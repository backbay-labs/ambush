#![allow(clippy::unwrap_used, clippy::expect_used)]
//! ADR 0018 "Verification": promote a finding, dismiss it, and assert the measurement is
//! attributable — strategy_id is not "unknown" and host_id is Some. Asserting only that a
//! measurement exists would pass with a useless one.
//!
//! An integration test on purpose: it sees only the public API, drives the engine
//! functions the routes call, and reads the SAME store the platform status route reads.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use swarm_core::config::{
    AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
    DetectorProfilesConfig, InvestigationConfig, OperatorAuthConfig, OperatorSurfaceConfig,
    PheromoneBackendConfig, PheromoneConfig, PolicyConfig, PolicyRuleConfig, PolicyRuleDecision,
    PromotionConfig, RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{ProvidenceFeedbackAction, Severity};
use swarm_ingest_runtime::ingest::IngestState;
use swarm_ingest_runtime::perch_ops::feedback::{FindingFeedbackRequest, record_finding_feedback};
use swarm_ingest_runtime::perch_ops::mint::{IncidentMintRequest, mint_incident};
use swarm_spine::IncidentStore;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A per-test root so every repo-relative store a Dismiss opens (the kitten
/// feedback store under `evolution.paths`) lands under the OS temp dir.
fn temp_root() -> PathBuf {
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "swarm-perch-walking-skeleton-{}-{}-{counter}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
    vec![PolicyRuleConfig {
        name: "operator-http-allow-execution".to_string(),
        decision: PolicyRuleDecision::Allow,
        threat_class: ThreatClass::Execution,
        actions: Vec::new(),
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: Some("operator surface tests allow execution responses".to_string()),
    }]
}

/// `http/tests.rs`'s `operator_config()`, with the evolution stores redirected
/// under `root` so a Dismiss never writes into the checked-out crate.
fn operator_config(root: &std::path::Path) -> SwarmConfig {
    let mut config = SwarmConfig {
        schema_version: 1,
        name: "operator-http".to_string(),
        description: "operator surface config".to_string(),
        runtime: RuntimeSettings {
            mode: swarm_runtime::RuntimeMode::DetectOnly,
            demo_mode: false,
            telemetry_sources: vec![TelemetrySourceConfig {
                name: "synthetic".to_string(),
                subject: "telemetry.synthetic".to_string(),
                bridge: None,
            }],
            threat_intel_feeds: vec![],
            max_in_flight_actions: 2,
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
            containment: Default::default(),
            response: Default::default(),
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
            rules: permissive_policy_rules(),
            ..PolicyConfig::default()
        },
        response_adapter: swarm_core::config::ResponseAdapterConfig::Sandbox,
        siem_forward: None,
        notification_channels: std::collections::BTreeMap::new(),
        notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
        audit: AuditConfig {
            bundle_store: BundleStoreConfig::Memory,
            recent_decisions_limit: 10,
        },
        investigation: InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 4,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        },
        correlation: CorrelationConfig {
            enabled: true,
            time_window_ms: 60_000,
            min_shared_keys: 1,
            candidate_limit: 8,
            incident_store: BundleStoreConfig::Memory,
        },
        canary: CanaryConfig::default(),
        promotion: PromotionConfig::default(),
        evolution: swarm_core::config::EvolutionConfig::default(),
        deception: swarm_core::config::DeceptionConfig::default(),
        memory: swarm_core::config::MemoryConfig::default(),
        identity: swarm_core::config::IdentityConfig::default(),
        platform_api: Default::default(),
        operator: OperatorSurfaceConfig {
            enabled: true,
            bind_addr: "127.0.0.1:7766".to_string(),
            runtime_base_url: "http://127.0.0.1:9090".to_string(),
            public_base_url: "http://127.0.0.1:7766".to_string(),
            allowed_embed_origins: Vec::new(),
            max_list_results: 2,
            widget_token_ttl_secs: 900,
            rate_limit: Default::default(),
            auth: OperatorAuthConfig {
                context_token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                principals: Vec::new(),
                operator_id: "local-operator".to_string(),
                token_env: "SWARM_OPERATOR_TEST_TOKEN".to_string(),
                token_expires_at_ms: None,
                nostr_pubkey: None,
            },
        },
        perch: swarm_core::config::PerchBridgeConfig::default(),
        tls: None,
    };
    config.evolution.paths.evolution_population_results_dir =
        root.join("evolution-population").display().to_string();
    config
}

#[tokio::test]
async fn a_promoted_then_dismissed_finding_leaves_an_attributable_measurement() {
    let root = temp_root();
    let state = IngestState::from_config(root.join("inline"), operator_config(&root)).unwrap();

    let minted = mint_incident(
        &state,
        IncidentMintRequest {
            finding_id: "f-1".into(),
            hunt_id: "hunt-evt-1".into(),
            event_id: "hunt-evt-1".into(),
            strategy_id: "suspicious_process_tree".into(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            created_at_ms: 1_700_000_000_000,
            summary: "Office-spawned encoded PowerShell".into(),
            host_id: Some("host-ops-1".into()),
            correlation_keys: vec![],
        },
        1,
    )
    .unwrap();
    assert!(minted.created);
    assert!(minted.degraded.is_empty());

    let fed = record_finding_feedback(
        &state,
        "local-operator",
        "f-1",
        FindingFeedbackRequest {
            action: ProvidenceFeedbackAction::Dismiss,
            incident_id: minted.incident_id.clone(),
            verdict_event_id: "ab".repeat(32),
            reason: Some("looked like the backup job".into()),
        },
        2,
    )
    .await
    .unwrap();
    assert!(fed.false_positive);
    assert!(!fed.replayed);
    assert_eq!(fed.analyst_id, "local-operator");
    assert_eq!(fed.incident_id, minted.incident_id);
    assert_eq!(fed.finding_id, "f-1");

    // The same store the platform status route reads, and the same fields the
    // tuning report attributes by.
    let lookup = state
        .current_incident_store()
        .load_by_incident_id(&minted.incident_id)
        .unwrap()
        .unwrap();
    let record = lookup.record;
    assert_eq!(record.false_positive_measurements.len(), 1);
    let measurement = &record.false_positive_measurements[0];
    assert_ne!(measurement.strategy_id, "unknown");
    assert_eq!(measurement.strategy_id, "suspicious_process_tree");
    assert_eq!(measurement.host_id.as_deref(), Some("host-ops-1"));
    assert_eq!(measurement.analyst_id, "local-operator");
    assert_eq!(measurement.finding_id, "f-1");
    assert_eq!(measurement.reviewed_at_ms, 2);
    assert!(measurement.false_positive);
    assert!(measurement.feedback_id.starts_with("perch-feedback:f-1:"));
    assert_eq!(measurement.feedback_id, fed.feedback_id);

    assert_eq!(record.feedback_audit_entries.len(), 1);
    let entry = &record.feedback_audit_entries[0];
    assert_eq!(entry.analyst_id, "local-operator");
    assert_eq!(entry.request_signature, "operator-bearer:local-operator");
    assert_eq!(entry.feedback_id, fed.feedback_id);
    assert!(
        entry.payload.get("analyst_id").is_none(),
        "the recorded payload is the body the operator sent, which carries no analyst_id"
    );
}
