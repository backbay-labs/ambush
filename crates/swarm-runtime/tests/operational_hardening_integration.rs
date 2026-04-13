//! Integration tests proving secret rotation and dead-letter journal rotation
//! work together in runtime conditions without losing data.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{
    AuditConfig, BundleStoreConfig, CanaryConfig, CircuitBreakerConfig, CorrelationConfig,
    DetectionConfig, DetectorProfilesConfig, HttpEdrConfig, InvestigationConfig,
    NotificationRoutingConfig, OperatorSurfaceConfig, PheromoneBackendConfig, PheromoneConfig,
    PolicyConfig, PromotionConfig, ResponseAdapterConfig, RetryConfig, RuntimeMode,
    RuntimeSettings, SwarmConfig, TelemetrySourceConfig,
};
use swarm_core::types::Severity;
use swarm_response::ExecutionMode;
use swarm_response::dead_letter::{DeadLetterEntry, DeadLetterJournal};
use swarm_runtime::ingest::IngestState;

fn unique_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn base_config() -> SwarmConfig {
    SwarmConfig {
        schema_version: 1,
        name: "hardening-integration".to_string(),
        description: "operational hardening integration test".to_string(),
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
        response_adapter: ResponseAdapterConfig::Sandbox,
        siem_forward: None,
        notification_channels: BTreeMap::new(),
        notification_routing: NotificationRoutingConfig::default(),
        audit: AuditConfig {
            bundle_store: BundleStoreConfig::Memory,
            recent_decisions_limit: 20,
        },
        investigation: InvestigationConfig::default(),
        correlation: CorrelationConfig::default(),
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

fn make_dead_letter_entry(index: usize) -> DeadLetterEntry {
    DeadLetterEntry {
        timestamp_ms: 1_700_000_000_000 + index as i64,
        receipt_id: format!("receipt-{index}"),
        action: "block_egress".to_string(),
        mode: ExecutionMode::Enforced,
        adapter: "http_edr".to_string(),
        attempts: 1,
        last_error: format!("simulated failure for entry {index}"),
        details: serde_json::json!({
            "target": "198.51.100.7",
            "reason": "integration test dead letter",
            "padding": "x".repeat(80),
        }),
    }
}

#[test]
fn secret_rotation_and_dead_letter_rotation_cycle_without_data_loss() {
    // ---- Setup: temp directories for secrets and dead-letter journals ----
    let suffix = unique_suffix();
    let secret_dir = std::env::temp_dir().join(format!("swarm-hardening-secrets-{suffix}"));
    let dl_dir = std::env::temp_dir().join(format!("swarm-hardening-deadletter-{suffix}"));
    fs::create_dir_all(&secret_dir).unwrap();
    fs::create_dir_all(&dl_dir).unwrap();

    let dead_letter_path = dl_dir.join("dispatch.jsonl");
    let config_path = std::env::temp_dir().join(format!("swarm-hardening-config-{suffix}.yaml"));

    // Write initial secret
    fs::write(secret_dir.join("edr-token"), "initial-token\n").unwrap();

    // Build config with @secret: reference and max_dead_letter_bytes
    let max_dead_letter_bytes: u64 = 500;
    let config = SwarmConfig {
        response_adapter: ResponseAdapterConfig::HttpEdr {
            config: HttpEdrConfig {
                endpoint: "https://edr.example".to_string(),
                auth_token: "@secret:edr-token".to_string(),
                timeout_ms: 1_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: dead_letter_path.display().to_string(),
            },
        },
        runtime: RuntimeSettings {
            secret_dir: Some(secret_dir.display().to_string()),
            max_dead_letter_bytes: Some(max_dead_letter_bytes),
            ..base_config().runtime
        },
        ..base_config()
    };

    // Build IngestState from synthetic config
    let state = IngestState::from_config(&config_path, config).unwrap();

    // ---- Phase 1: Verify initial secret resolution ----
    match state.current_response_adapter_config() {
        ResponseAdapterConfig::HttpEdr { config: edr } => {
            assert_eq!(
                edr.auth_token, "initial-token",
                "initial secret should be resolved on construction"
            );
        }
        other => panic!("expected HttpEdr, got {:?}", other),
    }

    // ---- Phase 2: Secret rotation cycle ----
    fs::write(secret_dir.join("edr-token"), "rotated-token\n").unwrap();
    state
        .reload_secrets_only()
        .expect("reload_secrets_only should succeed after secret rotation");

    match state.current_response_adapter_config() {
        ResponseAdapterConfig::HttpEdr { config: edr } => {
            assert_eq!(
                edr.auth_token, "rotated-token",
                "auth_token must reflect rotated secret after reload_secrets_only"
            );
        }
        other => panic!("expected HttpEdr after secret rotation, got {:?}", other),
    }

    // Detector strategy must be preserved through secret rotation
    assert_eq!(
        state.detector_strategy_name(),
        "suspicious_process_tree",
        "detector strategy must not change after secrets-only reload"
    );

    // ---- Phase 3: Dead-letter rotation cycle ----
    // Use DeadLetterJournal directly with the same max_bytes the runtime would configure.
    // Use a fresh path for the dead-letter rotation test so the file starts empty.
    let rotation_dl_path = dl_dir.join("rotation-test.jsonl");
    let journal = DeadLetterJournal::new(&rotation_dl_path, Some(max_dead_letter_bytes)).unwrap();

    // Write entries one at a time, tracking when rotation triggers.
    // rotation_if_needed runs at the start of write(), so the file grows
    // until a write sees size >= max_bytes and rotates before appending.
    let mut total_written = 0usize;
    let mut rotation_triggered = false;
    for i in 0..20 {
        journal.write(&make_dead_letter_entry(i)).unwrap();
        total_written += 1;

        // Check for rotated files after each write
        let rotated_count = fs::read_dir(&dl_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("rotation-test.jsonl.") && name != "rotation-test.jsonl"
            })
            .count();
        if rotated_count > 0 {
            rotation_triggered = true;
            break;
        }
    }

    assert!(
        rotation_triggered,
        "dead-letter rotation must trigger before 20 entries at max_bytes={max_dead_letter_bytes}"
    );

    // After the rotation-triggering write, the active journal should have exactly 1 entry
    let active_entries = journal.read_entries(None).unwrap();
    assert_eq!(
        active_entries.len(),
        1,
        "active journal should have exactly 1 entry after rotation"
    );
    assert_eq!(
        active_entries[0].receipt_id,
        format!("receipt-{}", total_written - 1),
        "the single active entry should be the post-rotation write"
    );

    // Collect all rotated files
    let rotated_files: Vec<_> = fs::read_dir(&dl_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("rotation-test.jsonl.") && name != "rotation-test.jsonl"
        })
        .collect();
    assert!(
        !rotated_files.is_empty(),
        "at least one rotated dead-letter file should exist"
    );

    // Read ALL rotated files and count total entries to verify no data was lost
    let mut all_rotated_entries = Vec::new();
    for rotated_file in &rotated_files {
        let content = fs::read_to_string(rotated_file.path()).unwrap();
        for line in content.lines() {
            if !line.trim().is_empty() {
                let entry: DeadLetterEntry = serde_json::from_str(line).unwrap();
                all_rotated_entries.push(entry);
            }
        }
    }

    // Total entries across rotated files + active journal must equal total_written
    let total_preserved = all_rotated_entries.len() + active_entries.len();
    assert_eq!(
        total_preserved,
        total_written,
        "no entries should be lost during rotation ({} rotated + {} active != {} written)",
        all_rotated_entries.len(),
        active_entries.len(),
        total_written,
    );

    // ---- Phase 4: Combined proof ----
    // After both rotations, verify secret is still the rotated value
    match state.current_response_adapter_config() {
        ResponseAdapterConfig::HttpEdr { config: edr } => {
            assert_eq!(
                edr.auth_token, "rotated-token",
                "secret rotation must persist after dead-letter rotation"
            );
        }
        other => panic!("expected HttpEdr at end of test, got {:?}", other),
    }

    // Dead-letter rotated files are still readable (no data lost)
    for rotated_file in &rotated_files {
        assert!(
            rotated_file.path().exists(),
            "rotated dead-letter file must still be readable: {:?}",
            rotated_file.path(),
        );
    }

    // ---- Cleanup ----
    let _ = fs::remove_dir_all(&secret_dir);
    let _ = fs::remove_dir_all(&dl_dir);
    let _ = fs::remove_file(&config_path);
}
