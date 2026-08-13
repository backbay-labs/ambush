use super::{
    AuditConfig, AuditdBridgeConfig, BundleStoreConfig, CanaryConfig, CloudTrailBridgeConfig,
    CorrelationConfig, DeceptionConfig, DeceptionMonitoringConfig, DeceptionPlacementStrategy,
    DeceptionPlaybookConfig, DeceptionPlaybookEntry, EvolutionAssuranceCoverageOverrideConfig,
    EvolutionConfig, EvolutionFitnessWeightsConfig, InvestigationConfig, JsonFileSourceConfig,
    NotificationChannelConfig, OperatorPrincipalConfig, OperatorScope, OperatorSurfaceConfig,
    PheromoneBackendConfig, PheromoneConfig, PlatformApiConfig, PlatformApiKeyConfig,
    PlatformApiScope, PolicyActionSelector, PolicyConfig, PolicyRuleConfig, PolicyRuleDecision,
    PolicyTimeWindowConfig, PromotionConfig, RequestSignatureConfig, ResponsePlaybookBranch,
    ResponsePlaybookCondition, ResponsePlaybookConfig, ResponsePlaybookRule,
    RuntimeAntiTamperConfig, RuntimeMode, RuntimeSettings, SecretString, SentinelBridgeConfig,
    SwarmConfig, SysmonBridgeConfig, TelemetryBridgeConfig, TelemetrySourceConfig,
    TemporalEventWindowConfig, WindowsEventLogBridgeConfig,
};
use crate::ThreatClass;
use crate::agent::SwarmMode;
use crate::types::{ResponseAction, Severity};
use zeroize::Zeroize;

fn valid_config(backend: PheromoneBackendConfig) -> SwarmConfig {
    SwarmConfig {
        schema_version: 1,
        name: "test".to_string(),
        description: "test config".to_string(),
        runtime: RuntimeSettings {
            mode: RuntimeMode::LiveResponse,
            demo_mode: false,
            telemetry_sources: vec![TelemetrySourceConfig {
                name: "synthetic".to_string(),
                subject: "telemetry.synthetic.process".to_string(),
                bridge: None,
            }],
            threat_intel_feeds: vec![],
            max_in_flight_actions: 4,
            drain_timeout_ms: 30_000,
            require_durable_live_response: true,
            max_heap_pressure: 0.90,
            secret_dir: None,
            anti_tamper: RuntimeAntiTamperConfig::default(),
            temporal_event_window: TemporalEventWindowConfig::default(),
            agent_tick_timeout_ms: 500,
            governance_degraded_tick_threshold: 3,
            partition_contingency_lease_ttl_ms: 300_000,
            partition_contingency_blast_radius_cap: 1,
            max_dead_letter_bytes: None,
            containment: Default::default(),
        },
        detection: super::DetectionConfig {
            strategy: "suspicious_process_tree".to_string(),
            strategies: Vec::new(),
            high_confidence_threshold: 0.9,
            medium_confidence_threshold: 0.7,
            profiles: super::DetectorProfilesConfig::default(),
        },
        pheromone: PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: ResponsePlaybookConfig::default(),
            backend,
        },
        policy: PolicyConfig::default(),
        response_adapter: Default::default(),
        siem_forward: None,
        notification_channels: std::collections::BTreeMap::new(),
        notification_routing: super::NotificationRoutingConfig::default(),
        audit: AuditConfig {
            bundle_store: BundleStoreConfig::Memory,
            recent_decisions_limit: 20,
        },
        investigation: InvestigationConfig::default(),
        correlation: CorrelationConfig::default(),
        canary: CanaryConfig::default(),
        promotion: PromotionConfig::default(),
        evolution: EvolutionConfig::default(),
        deception: DeceptionConfig::default(),
        memory: super::MemoryConfig::default(),
        identity: super::IdentityConfig::default(),
        platform_api: PlatformApiConfig::default(),
        operator: OperatorSurfaceConfig::default(),
        tls: None,
    }
}

#[test]
fn jet_stream_backend_is_durable_and_valid() {
    let config = valid_config(PheromoneBackendConfig::JetStream {
        url: "nats://127.0.0.1:4222".to_string(),
        connect_timeout_ms: 5_000,
        gc_page_size: 512,
    });

    assert!(config.pheromone.backend.is_durable());
    config.validate().unwrap();
}

#[test]
fn jet_stream_backend_requires_non_empty_url() {
    let config = valid_config(PheromoneBackendConfig::JetStream {
        url: "   ".to_string(),
        connect_timeout_ms: 5_000,
        gc_page_size: 512,
    });

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `pheromone.backend.url`: must not be empty"
    );
}

#[test]
fn jet_stream_backend_requires_positive_connect_timeout() {
    let config = valid_config(PheromoneBackendConfig::JetStream {
        url: "nats://127.0.0.1:4222".to_string(),
        connect_timeout_ms: 0,
        gc_page_size: 512,
    });

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `pheromone.backend.connect_timeout_ms`: must be greater than zero"
    );
}

#[test]
fn containment_lease_ttl_must_be_positive() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.containment.lease_ttl_ms = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.containment.lease_ttl_ms`: must be greater than zero; a \
         containment with no bound cannot be released automatically"
    );
}

#[test]
fn containment_sweep_interval_must_be_positive() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.containment.sweep_interval_ms = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.containment.sweep_interval_ms`: must be greater than zero"
    );
}

#[test]
fn containment_lease_store_path_must_not_be_blank_when_set() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.containment.lease_store_path = Some("   ".to_string());

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.containment.lease_store_path`: must not be empty when set; omit \
         the key for in-memory leases"
    );
}

/// The containment block is optional on the wire under `deny_unknown_fields`,
/// and its absence takes the shipped bounds rather than zeroes.
///
/// This matters because `rulesets/default.yaml` is digest-signed and carries no
/// containment block: if the keys were required the shipped ruleset would stop
/// loading, and if they defaulted to zero the validation above would reject it.
#[test]
fn a_runtime_block_with_no_containment_keys_loads_with_bounded_defaults() {
    let json = serde_json::json!({
        "mode": "detect_only",
        "telemetry_sources": [],
        "max_in_flight_actions": 4,
    });
    let settings: RuntimeSettings = serde_json::from_value(json).unwrap();
    assert_eq!(settings.containment.lease_ttl_ms, 900_000);
    assert_eq!(settings.containment.sweep_interval_ms, 30_000);
    assert_eq!(settings.containment.lease_store_path, None);
    assert!(settings.containment.lease_ttl_ms > 0);
}

#[test]
fn anti_tamper_requires_positive_check_interval_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.anti_tamper.check_interval_ms = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.anti_tamper.check_interval_ms`: must be greater than zero when anti-tamper monitoring is enabled"
    );
}

#[test]
fn anti_tamper_fail_closed_requires_monitoring_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.anti_tamper.enabled = false;
    config.runtime.anti_tamper.fail_closed_live_response = true;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.anti_tamper.fail_closed_live_response`: requires runtime.anti_tamper.enabled"
    );
}

#[test]
fn anti_tamper_rejects_empty_allowed_library_prefixes() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.anti_tamper.allowed_library_prefixes = vec![" ".to_string()];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.anti_tamper.allowed_library_prefixes`: entries must not be empty"
    );
}

#[test]
fn temporal_event_window_requires_positive_retention() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.temporal_event_window.retention_ms = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.temporal_event_window.retention_ms`: must be greater than zero"
    );
}

#[test]
fn temporal_event_window_match_span_cannot_exceed_retention() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.temporal_event_window.retention_ms = 30_000;
    config.runtime.temporal_event_window.max_match_span_ms = 60_000;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.temporal_event_window.max_match_span_ms`: must be less than or equal to retention_ms"
    );
}

#[test]
fn operator_surface_requires_http_runtime_base_url_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.runtime_base_url = "ws://127.0.0.1:9090".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.runtime_base_url`: must start with http:// or https://"
    );
}

#[test]
fn deception_enabled_requires_non_empty_playbook() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.deception.enabled = true;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `deception.playbook.entries`: must contain at least one entry when deception is enabled"
    );
}

#[test]
fn secret_string_zeroize_clears_plaintext() {
    let mut secret = SecretString::from("top-secret");

    secret.zeroize();

    assert!(secret.expose_secret().is_empty());
}

#[test]
fn secret_string_debug_redacts_plaintext() {
    let secret = SecretString::from("top-secret");

    assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
}

#[test]
fn deception_monitoring_confidence_must_be_high_fidelity() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.deception.enabled = true;
    config.deception.playbook = DeceptionPlaybookConfig {
        entries: vec![DeceptionPlaybookEntry {
            name: "finance-canary".to_string(),
            decoy_type: "canary_token".to_string(),
            target_zone: "finance".to_string(),
            host_profile: "linux-app".to_string(),
            placement_strategy: DeceptionPlacementStrategy::HighValuePath,
            monitoring: DeceptionMonitoringConfig {
                file_paths: vec!["/srv/finance/payroll.xlsx".to_string()],
                honeypot_ports: Vec::new(),
                canary_credentials: Vec::new(),
                threat_class: crate::pheromone::ThreatClass::InitialAccess,
                severity: Severity::High,
                confidence: 0.80,
            },
        }],
    };

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `deception.playbook.entries.monitoring.confidence`: must be between 0.95 and 1.0"
    );
}

#[test]
fn deception_requires_non_empty_lifecycle_results_dir_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.deception.enabled = true;
    config.deception.lifecycle_results_dir = " ".to_string();
    config.deception.playbook = DeceptionPlaybookConfig {
        entries: vec![DeceptionPlaybookEntry {
            name: "finance-canary".to_string(),
            decoy_type: "canary_token".to_string(),
            target_zone: "finance".to_string(),
            host_profile: "linux-app".to_string(),
            placement_strategy: DeceptionPlacementStrategy::HighValuePath,
            monitoring: DeceptionMonitoringConfig {
                file_paths: vec!["/srv/finance/payroll.xlsx".to_string()],
                honeypot_ports: Vec::new(),
                canary_credentials: Vec::new(),
                threat_class: crate::pheromone::ThreatClass::InitialAccess,
                severity: Severity::High,
                confidence: 0.99,
            },
        }],
    };

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `deception.lifecycle_results_dir`: must not be empty"
    );
}

#[test]
fn deception_requires_positive_rotation_interval_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.deception.enabled = true;
    config.deception.rotation_interval_secs = 0;
    config.deception.playbook = DeceptionPlaybookConfig {
        entries: vec![DeceptionPlaybookEntry {
            name: "finance-canary".to_string(),
            decoy_type: "canary_token".to_string(),
            target_zone: "finance".to_string(),
            host_profile: "linux-app".to_string(),
            placement_strategy: DeceptionPlacementStrategy::HighValuePath,
            monitoring: DeceptionMonitoringConfig {
                file_paths: vec!["/srv/finance/payroll.xlsx".to_string()],
                honeypot_ports: Vec::new(),
                canary_credentials: Vec::new(),
                threat_class: crate::pheromone::ThreatClass::InitialAccess,
                severity: Severity::High,
                confidence: 0.99,
            },
        }],
    };

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `deception.rotation_interval_secs`: must be greater than zero when deception is enabled"
    );
}

#[test]
fn operator_surface_requires_http_public_base_url_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.public_base_url = "ws://127.0.0.1:7766".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.public_base_url`: must start with http:// or https://"
    );
}

#[test]
fn operator_surface_requires_positive_widget_token_ttl_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.widget_token_ttl_secs = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.widget_token_ttl_secs`: must be greater than zero when operator surface is enabled"
    );
}

#[test]
fn operator_surface_rejects_invalid_embed_origin() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.allowed_embed_origins = vec!["ftp://providence.example".to_string()];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.allowed_embed_origins`: origin 0 must be 'self' or start with http:// or https://"
    );
}

#[test]
fn operator_surface_principals_require_scopes() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: "reader".to_string(),
        token_env: "SWARM_OPERATOR_READER_TOKEN".to_string(),
        token_expires_at_ms: None,
        scopes: Vec::new(),
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.auth.principals.scopes`: principal 0 must grant at least one scope"
    );
}

#[test]
fn operator_surface_rejects_duplicate_principal_token_envs() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: "reader".to_string(),
            token_env: "SWARM_OPERATOR_SHARED_TOKEN".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read],
        },
        OperatorPrincipalConfig {
            operator_id: "approver".to_string(),
            token_env: "SWARM_OPERATOR_SHARED_TOKEN".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
    ];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.auth.principals.token_env`: principal 1 reuses token_env `SWARM_OPERATOR_SHARED_TOKEN`; bearer secrets must map to one principal"
    );
}

#[test]
fn operator_surface_requires_read_scope_when_platform_api_is_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.platform_api.keys = vec![PlatformApiKeyConfig {
        name: "reader".to_string(),
        key_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        scopes: vec![PlatformApiScope::Read],
    }];
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: "maintainer".to_string(),
        token_env: "SWARM_OPERATOR_MAINTAINER_TOKEN".to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Maintenance],
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.auth.principals.scopes`: at least one principal must grant `read` scope"
    );
}

#[test]
fn platform_api_rejects_invalid_key_hash() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.platform_api.keys = vec![PlatformApiKeyConfig {
        name: "reader".to_string(),
        key_hash: "not-a-sha".to_string(),
        scopes: vec![PlatformApiScope::Read],
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `platform_api.keys.key_hash`: key 0 key_hash must be a 64-character SHA-256 hex digest"
    );
}

#[test]
fn operator_surface_rejects_non_positive_token_expiry() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: "reader".to_string(),
        token_env: "SWARM_OPERATOR_READER_TOKEN".to_string(),
        token_expires_at_ms: Some(0),
        scopes: vec![OperatorScope::Read],
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.auth.principals.token_expires_at_ms`: principal 0 token_expires_at_ms must be greater than zero when configured"
    );
}

#[test]
fn operator_surface_rejects_zero_burst_rate_limit_threshold() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.operator.enabled = true;
    config.operator.rate_limit.burst_max_requests = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `operator_surface.rate_limit.burst_max_requests`: must be greater than zero"
    );
}

#[test]
fn platform_api_rejects_sustained_window_smaller_than_burst_window() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.platform_api.rate_limit.burst_window_ms = 5_000;
    config.platform_api.rate_limit.sustained_window_ms = 1_000;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `platform_api.rate_limit.sustained_window_ms`: must be greater than or equal to burst_window_ms"
    );
}

#[test]
fn notification_request_signature_requires_non_empty_secret() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.notification_channels.insert(
        "providence_webhook".to_string(),
        NotificationChannelConfig {
            target_url: "https://providence.example/incidents".to_string(),
            auth_token: Some(SecretString::from("@secret:providence_api_token")),
            request_signature: Some(RequestSignatureConfig {
                header: "X-Swarm-Signature".to_string(),
                secret: SecretString::from("   "),
            }),
            timeout_ms: 5_000,
            rate_limit: super::NotificationRateLimitConfig::default(),
            quiet_hours: None,
            dead_letter_path: "./notification-providence.jsonl".to_string(),
        },
    );
    config.notification_routing.rules = vec![super::RoutingRule {
        min_severity: Some(Severity::High),
        threat_class: Some(ThreatClass::Execution),
        utc_start_hour: None,
        utc_end_hour: None,
        channels: vec!["providence_webhook".to_string()],
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `notification_channels.request_signature.secret`: must not be empty"
    );
}

#[test]
fn evolution_requires_non_zero_drift_threshold_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.drift_threshold_pct = 0.0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.drift_threshold_pct`: must be greater than 0.0 and less than or equal to 1.0"
    );
}

#[test]
fn evolution_requires_non_empty_results_paths_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.paths.evolution_validation_results_dir = " ".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.paths.evolution_validation_results_dir`: must not be empty"
    );
}

#[test]
fn evolution_requires_positive_hourly_proposal_limit_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.max_proposals_per_hour = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.max_proposals_per_hour`: must be greater than zero when evolution is enabled"
    );
}

/// Message updated, not just the expectation: "at least one weight" was accurate
/// while all four weights counted, and is now wrong in a way an operator would
/// act on. A config with `speed: 1.0` and everything else zero DOES have one
/// weight greater than zero and is still rejected -- see
/// `evolution_rejects_fitness_weights_carried_entirely_by_the_inert_speed_weight`.
/// The message has to name the weights that actually count.
#[test]
fn evolution_requires_non_zero_fitness_weight_total_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.fitness_weights.detection_rate = 0.0;
    config.evolution.fitness_weights.false_positive_cost = 0.0;
    config.evolution.fitness_weights.speed = 0.0;
    config.evolution.fitness_weights.threat_class_coverage = 0.0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.fitness_weights`: at least one of `detection_rate`, \
         `false_positive_cost` or `threat_class_coverage` must be greater than zero (`speed` is \
         accepted for compatibility but no longer contributes)"
    );
}

#[test]
fn evolution_requires_non_empty_safety_invariant_bundle_paths_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.safety_gate.invariant_bundle_paths.clear();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.safety_gate.invariant_bundle_paths`: must include at least one repo-owned invariant bundle when evolution is enabled"
    );
}

#[test]
fn evolution_requires_non_empty_canary_results_dir_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.paths.canary_results_dir = " ".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.paths.canary_results_dir`: must not be empty"
    );
}

#[test]
fn evolution_requires_probability_assurance_floor_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.assurance.min_detector_catch_rate = 1.5;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.assurance.min_detector_catch_rate`: must be between 0.0 and 1.0"
    );
}

#[test]
fn evolution_requires_non_empty_allowed_solver_statuses_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.assurance.allowed_solver_statuses.clear();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.assurance.allowed_solver_statuses`: must include at least one allowed solver outcome"
    );
}

#[test]
fn evolution_requires_non_empty_assurance_override_detector_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.assurance.coverage_overrides =
        vec![EvolutionAssuranceCoverageOverrideConfig {
            detector: " ".to_string(),
            min_catch_rate: 0.5,
        }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.assurance.coverage_overrides.detector`: entry 0 must not be empty"
    );
}

#[test]
fn evolution_requires_non_empty_assurance_harvest_results_dir_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.assurance.harvest.results_dir = " ".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.assurance.harvest.results_dir`: must not be empty"
    );
}

#[test]
fn evolution_requires_positive_assurance_waiver_ttl_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.assurance.waiver.max_ttl_secs = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.assurance.waiver.max_ttl_secs`: must be greater than zero"
    );
}

#[test]
fn evolution_requires_ed25519_assurance_waiver_operator_ids_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.assurance.waiver.allowed_operator_ids = vec!["local-operator".to_string()];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.assurance.waiver.allowed_operator_ids`: entry 0 must start with swarm:ed25519:"
    );
}

#[test]
fn memory_requires_non_empty_results_dir_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.memory.enabled = true;
    config.memory.knowledge_graph_results_dir = " ".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `memory.knowledge_graph_results_dir`: must not be empty"
    );
}

#[test]
fn memory_requires_positive_temporal_window_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.memory.enabled = true;
    config.memory.temporal_window_secs = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `memory.temporal_window_secs`: must be greater than zero when memory is enabled"
    );
}

#[test]
fn memory_requires_positive_retention_days_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.memory.enabled = true;
    config.memory.knowledge_retention_days = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `memory.knowledge_retention_days`: must be greater than zero when memory is enabled"
    );
}

#[test]
fn identity_requires_non_empty_agent_key_dir() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.identity.agent_key_dir = "   ".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `identity.agent_key_dir`: must not be empty"
    );
}

#[test]
fn identity_requires_non_empty_registry_dir() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.identity.registry_dir = "   ".to_string();

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `identity.registry_dir`: must not be empty"
    );
}

#[test]
fn sentinel_bridge_requires_http_endpoint() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.telemetry_sources = vec![TelemetrySourceConfig {
        name: "sentinel-primary".to_string(),
        subject: String::new(),
        bridge: Some(TelemetryBridgeConfig::Sentinel {
            config: Box::new(SentinelBridgeConfig {
                endpoint: "127.0.0.1:9100/metrics".to_string(),
                scrape_interval_ms: 5_000,
                scrape_timeout_ms: 3_000,
                thermal_anomaly_threshold_celsius: 60.0,
                memory_exhaustion_threshold_percent: 85.0,
                disk_exhaustion_threshold_percent: 90.0,
                max_consecutive_failures: 5,
            }),
        }),
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.telemetry_sources.bridge.endpoint`: must start with http:// or https://"
    );
}

#[test]
fn file_backed_bridge_variants_deserialize_and_validate() {
    for bridge in [
        serde_json::json!({
            "kind": "windows_event_log",
            "path": "/tmp/security.jsonl"
        }),
        serde_json::json!({
            "kind": "sysmon",
            "path": "/tmp/sysmon.jsonl"
        }),
        serde_json::json!({
            "kind": "auditd",
            "path": "/tmp/auditd.jsonl"
        }),
        serde_json::json!({
            "kind": "cloud_trail",
            "path": "/tmp/cloudtrail.jsonl"
        }),
    ] {
        let bridge: TelemetryBridgeConfig = serde_json::from_value(bridge).unwrap();
        let mut config = valid_config(PheromoneBackendConfig::InMemory);
        config.runtime.require_durable_live_response = false;
        config.runtime.telemetry_sources = vec![TelemetrySourceConfig {
            name: "bridge-primary".to_string(),
            subject: String::new(),
            bridge: Some(bridge),
        }];

        config.validate().unwrap();
    }
}

#[test]
fn windows_event_log_bridge_requires_non_empty_path() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.runtime.telemetry_sources = vec![TelemetrySourceConfig {
        name: "windows-security".to_string(),
        subject: String::new(),
        bridge: Some(TelemetryBridgeConfig::WindowsEventLog {
            config: Box::new(WindowsEventLogBridgeConfig {
                source: JsonFileSourceConfig {
                    path: "   ".to_string(),
                },
            }),
        }),
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `runtime.telemetry_sources.bridge.path`: must not be empty"
    );
}

#[test]
fn sysmon_and_auditd_bridge_configs_round_trip() {
    let sysmon = TelemetryBridgeConfig::Sysmon {
        config: Box::new(SysmonBridgeConfig {
            source: JsonFileSourceConfig {
                path: "/tmp/sysmon.jsonl".to_string(),
            },
        }),
    };
    let auditd = TelemetryBridgeConfig::Auditd {
        config: Box::new(AuditdBridgeConfig {
            source: JsonFileSourceConfig {
                path: "/tmp/auditd.jsonl".to_string(),
            },
        }),
    };
    let cloudtrail = TelemetryBridgeConfig::CloudTrail {
        config: Box::new(CloudTrailBridgeConfig {
            source: JsonFileSourceConfig {
                path: "/tmp/cloudtrail.jsonl".to_string(),
            },
        }),
    };

    let sysmon_round_trip: TelemetryBridgeConfig =
        serde_json::from_value(serde_json::to_value(&sysmon).unwrap()).unwrap();
    let auditd_round_trip: TelemetryBridgeConfig =
        serde_json::from_value(serde_json::to_value(&auditd).unwrap()).unwrap();
    let cloudtrail_round_trip: TelemetryBridgeConfig =
        serde_json::from_value(serde_json::to_value(&cloudtrail).unwrap()).unwrap();

    assert_eq!(sysmon_round_trip, sysmon);
    assert_eq!(auditd_round_trip, auditd);
    assert_eq!(cloudtrail_round_trip, cloudtrail);
}

#[test]
fn jet_stream_backend_requires_positive_gc_page_size() {
    let config = valid_config(PheromoneBackendConfig::JetStream {
        url: "nats://127.0.0.1:4222".to_string(),
        connect_timeout_ms: 5_000,
        gc_page_size: 0,
    });

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `pheromone.backend.gc_page_size`: must be greater than zero"
    );
}

#[test]
fn jet_stream_backend_deserializes_from_tagged_config() {
    let backend: PheromoneBackendConfig = serde_json::from_value(serde_json::json!({
        "kind": "jet_stream",
        "url": "nats://127.0.0.1:4222",
        "connect_timeout_ms": 2500,
        "gc_page_size": 64
    }))
    .unwrap();

    assert_eq!(
        backend,
        PheromoneBackendConfig::JetStream {
            url: "nats://127.0.0.1:4222".to_string(),
            connect_timeout_ms: 2_500,
            gc_page_size: 64,
        }
    );
}

#[test]
fn detection_config_active_strategies_uses_legacy_strategy_when_list_missing() {
    let config: super::DetectionConfig = serde_json::from_value(serde_json::json!({
        "strategy": "suspicious_process_tree",
        "high_confidence_threshold": 0.9,
        "medium_confidence_threshold": 0.7
    }))
    .unwrap();

    assert!(config.strategies.is_empty());
    assert_eq!(config.active_strategies(), vec!["suspicious_process_tree"]);
}

#[test]
fn detection_config_active_strategies_prefers_explicit_list() {
    let config: super::DetectionConfig = serde_json::from_value(serde_json::json!({
        "strategy": "suspicious_process_tree",
        "strategies": ["suspicious_process_tree", "dns_exfiltration"],
        "high_confidence_threshold": 0.9,
        "medium_confidence_threshold": 0.7
    }))
    .unwrap();

    assert_eq!(
        config.active_strategies(),
        vec![
            "suspicious_process_tree".to_string(),
            "dns_exfiltration".to_string()
        ]
    );
}

#[test]
fn rollout_scopes_remain_optional_for_single_strategy_configs() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.canary.enabled = true;
    config.promotion.enabled = true;

    config.validate().unwrap();
}

#[test]
fn multi_strategy_canary_requires_explicit_scope() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.detection.strategies = vec![
        "suspicious_process_tree".to_string(),
        "dns_exfiltration".to_string(),
    ];
    config.canary.enabled = true;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `canary.strategy_id`: is required when multiple detection.strategies are active: suspicious_process_tree, dns_exfiltration"
    );
}

#[test]
fn unknown_rollout_strategy_ids_are_rejected() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.detection.strategies = vec![
        "suspicious_process_tree".to_string(),
        "dns_exfiltration".to_string(),
    ];
    config.canary.enabled = true;
    config.canary.strategy_id = Some("unknown".to_string());

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `canary.strategy_id`: must match one of detection.active_strategies(): suspicious_process_tree, dns_exfiltration"
    );

    config.canary.strategy_id = Some("dns_exfiltration".to_string());
    config.promotion.strategy_id = Some("unknown".to_string());

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `promotion.strategy_id`: must match one of detection.active_strategies(): suspicious_process_tree, dns_exfiltration"
    );
}

#[test]
fn valid_rollout_scopes_parse_and_validate() {
    let config: SwarmConfig = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "name": "test",
        "description": "test config",
        "runtime": {
            "mode": "live_response",
            "demo_mode": false,
            "telemetry_sources": [
                {
                    "name": "synthetic",
                    "subject": "telemetry.synthetic.process"
                }
            ],
            "max_in_flight_actions": 4,
            "drain_timeout_ms": 30000,
            "require_durable_live_response": true,
            "max_heap_pressure": 0.90,
            "agent_tick_timeout_ms": 500,
            "governance_degraded_tick_threshold": 3
        },
        "detection": {
            "strategy": "suspicious_process_tree",
            "strategies": ["suspicious_process_tree", "dns_exfiltration"],
            "high_confidence_threshold": 0.9,
            "medium_confidence_threshold": 0.7
        },
        "pheromone": {
            "default_half_life_secs": 3600.0,
            "evaporation_threshold": 0.01,
            "min_sources_for_escalation": 2,
            "alert_threshold": 2.0,
            "incident_threshold": 5.0,
            "backend": {
                "kind": "local_journal",
                "path": "./journal.jsonl"
            }
        },
        "policy": {
            "human_gate_severity": "HIGH",
            "lease_ttl_ms": 60000
        },
        "canary": {
            "enabled": true,
            "slot_id": "canary-primary",
            "strategy_id": "dns_exfiltration",
            "observation_window_events": 2,
            "max_candidate_only_rate": 0.25,
            "max_baseline_miss_rate": 0.25,
            "max_detect_latency_us": 10000,
            "max_total_detections": 8
        },
        "promotion": {
            "enabled": true,
            "window_id": "production-primary",
            "strategy_id": "dns_exfiltration",
            "observation_window_events": 2,
            "max_promoted_only_rate": 0.20,
            "max_fallback_recovery_rate": 0.20,
            "max_detect_latency_us": 10000,
            "max_total_detections": 12
        }
    }))
    .unwrap();

    assert_eq!(
        config.canary.strategy_id.as_deref(),
        Some("dns_exfiltration")
    );
    assert_eq!(
        config.promotion.strategy_id.as_deref(),
        Some("dns_exfiltration")
    );
    config.validate().unwrap();
}

#[test]
fn duplicate_detection_strategy_ids_are_rejected() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.detection.strategies = vec![
        "suspicious_process_tree".to_string(),
        "dns_exfiltration".to_string(),
        "dns_exfiltration".to_string(),
    ];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `detection.strategies`: duplicate detector strategy `dns_exfiltration`"
    );
}

#[test]
fn empty_explicit_detection_strategy_ids_are_rejected() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.detection.strategies = vec!["  ".to_string()];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `detection.strategies`: entries must not be empty"
    );
}

#[test]
fn response_playbook_rules_validate_confidence_ranges() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.pheromone.response_playbook = ResponsePlaybookConfig {
        rules: vec![ResponsePlaybookRule {
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            min_confidence: 0.8,
            max_confidence: 0.5,
            actions: vec![ResponseAction::Escalate {
                summary: "review required".to_string(),
                urgency: Severity::High,
            }],
            branches: Vec::new(),
        }],
    };

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `pheromone.response_playbook`: rule 0 max_confidence must be greater than or equal to min_confidence"
    );
}

#[test]
fn response_playbook_branches_reject_empty_action_lists() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.pheromone.response_playbook = ResponsePlaybookConfig {
        rules: vec![ResponsePlaybookRule {
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            min_confidence: 0.8,
            max_confidence: 1.0,
            actions: Vec::new(),
            branches: vec![ResponsePlaybookBranch {
                name: Some("incident-only".to_string()),
                when: ResponsePlaybookCondition {
                    modes: vec![SwarmMode::Incident],
                    ..ResponsePlaybookCondition::default()
                },
                actions: Vec::new(),
            }],
        }],
    };

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `pheromone.response_playbook`: rule 0 branch 0 must declare at least one response action"
    );
}

#[test]
fn response_playbook_rules_deserialize_from_config_shape() {
    let config: SwarmConfig = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "name": "test",
        "description": "test config",
        "runtime": {
            "mode": "live_response",
            "demo_mode": false,
            "telemetry_sources": [
                {
                    "name": "synthetic",
                    "subject": "telemetry.synthetic.process"
                }
            ],
            "max_in_flight_actions": 4,
            "drain_timeout_ms": 30000,
            "require_durable_live_response": true,
            "max_heap_pressure": 0.90,
            "agent_tick_timeout_ms": 500,
            "governance_degraded_tick_threshold": 3
        },
        "detection": {
            "strategy": "suspicious_process_tree",
            "high_confidence_threshold": 0.9,
            "medium_confidence_threshold": 0.7
        },
        "pheromone": {
            "default_half_life_secs": 3600.0,
            "evaporation_threshold": 0.01,
            "min_sources_for_escalation": 2,
            "alert_threshold": 2.0,
            "incident_threshold": 5.0,
            "deescalation_cooldown_secs": 300,
            "response_playbook": {
                "rules": [
                    {
                        "threat_class": "execution",
                        "severity": "HIGH",
                        "min_confidence": 0.9,
                        "max_confidence": 1.0,
                        "actions": [
                            {
                                "type": "deploy_decoy",
                                "decoy_type": "honeypot",
                                "target_zone": "dmz"
                            },
                            {
                                "type": "escalate",
                                "summary": "execution spike requires review",
                                "urgency": "HIGH"
                            }
                        ]
                    }
                ]
            },
            "backend": {
                "kind": "local_journal",
                "path": "./journal.jsonl"
            }
        },
        "policy": {
            "human_gate_severity": "HIGH",
            "lease_ttl_ms": 60000,
            "max_actions_per_scope_per_minute": 4,
            "rules": [
                {
                    "name": "execution-after-hours-review",
                    "decision": "allow",
                    "threat_class": "execution",
                    "actions": ["deploy_decoy", "escalate"],
                    "min_severity": "HIGH",
                    "max_severity": "CRITICAL",
                    "time_window_utc": {
                        "start_hour_utc": 18,
                        "end_hour_utc": 24
                    },
                    "max_actions_per_agent_per_minute": 2,
                    "reason": "execution playbook enabled after hours"
                }
            ]
        }
    }))
    .unwrap();

    assert_eq!(config.pheromone.deescalation_cooldown_secs, 300);
    assert_eq!(config.pheromone.response_playbook.rules.len(), 1);
    assert_eq!(config.policy.max_actions_per_scope_per_minute, 4);
    assert_eq!(config.policy.rules.len(), 1);
    config.validate().unwrap();
}

#[test]
fn response_playbook_branches_deserialize_from_config_shape() {
    let config: SwarmConfig = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "name": "test",
        "description": "test config",
        "runtime": {
            "mode": "live_response",
            "demo_mode": false,
            "telemetry_sources": [
                {
                    "name": "synthetic",
                    "subject": "telemetry.synthetic.process"
                }
            ],
            "max_in_flight_actions": 4,
            "drain_timeout_ms": 30000,
            "require_durable_live_response": true,
            "max_heap_pressure": 0.90,
            "agent_tick_timeout_ms": 500,
            "governance_degraded_tick_threshold": 3
        },
        "detection": {
            "strategy": "suspicious_process_tree",
            "high_confidence_threshold": 0.9,
            "medium_confidence_threshold": 0.7
        },
        "pheromone": {
            "default_half_life_secs": 3600.0,
            "evaporation_threshold": 0.01,
            "min_sources_for_escalation": 2,
            "alert_threshold": 2.0,
            "incident_threshold": 5.0,
            "deescalation_cooldown_secs": 300,
            "response_playbook": {
                "rules": [
                    {
                        "threat_class": "execution",
                        "severity": "HIGH",
                        "min_confidence": 0.9,
                        "max_confidence": 1.0,
                        "actions": [
                            {
                                "type": "escalate",
                                "summary": "fallback review",
                                "urgency": "HIGH"
                            }
                        ],
                        "branches": [
                            {
                                "name": "incident_containment",
                                "when": {
                                    "min_confidence": 0.97,
                                    "modes": ["incident"]
                                },
                                "actions": [
                                    {
                                        "type": "block_egress",
                                        "target": "203.0.113.10"
                                    },
                                    {
                                        "type": "isolate_host",
                                        "host_id": "host-1"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            },
            "backend": {
                "kind": "local_journal",
                "path": "./journal.jsonl"
            }
        },
        "policy": {
            "human_gate_severity": "HIGH",
            "lease_ttl_ms": 60000
        }
    }))
    .unwrap();

    let rule = &config.pheromone.response_playbook.rules[0];
    assert_eq!(rule.branches.len(), 1);
    assert_eq!(
        rule.branches[0].name.as_deref(),
        Some("incident_containment")
    );
    assert_eq!(rule.branches[0].when.modes, vec![SwarmMode::Incident]);
    assert_eq!(rule.branches[0].actions.len(), 2);
    config.validate().unwrap();
}

#[test]
fn response_playbook_resolve_prefers_first_matching_branch_and_fallback() {
    let playbook = ResponsePlaybookConfig {
        rules: vec![ResponsePlaybookRule {
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            min_confidence: 0.9,
            max_confidence: 1.0,
            actions: vec![ResponseAction::Escalate {
                summary: "fallback review".to_string(),
                urgency: Severity::High,
            }],
            branches: vec![ResponsePlaybookBranch {
                name: Some("incident_containment".to_string()),
                when: ResponsePlaybookCondition {
                    min_confidence: Some(0.97),
                    modes: vec![SwarmMode::Incident],
                    ..ResponsePlaybookCondition::default()
                },
                actions: vec![
                    ResponseAction::BlockEgress {
                        target: "203.0.113.10".to_string(),
                    },
                    ResponseAction::IsolateHost {
                        host_id: "host-1".to_string(),
                    },
                ],
            }],
        }],
    };

    let incident = playbook
        .resolve(
            &ThreatClass::Execution,
            Severity::High,
            0.98,
            SwarmMode::Incident,
        )
        .unwrap();
    assert_eq!(
        incident.branch,
        Some(super::ResponsePlaybookBranchResolution {
            index: 0,
            name: Some("incident_containment".to_string()),
        })
    );
    assert_eq!(incident.actions.len(), 2);
    assert!(matches!(
        incident.actions[0],
        ResponseAction::BlockEgress { .. }
    ));

    let fallback = playbook
        .resolve(
            &ThreatClass::Execution,
            Severity::High,
            0.93,
            SwarmMode::Alert,
        )
        .unwrap();
    assert_eq!(fallback.branch, None);
    assert_eq!(
        fallback.actions,
        vec![ResponseAction::Escalate {
            summary: "fallback review".to_string(),
            urgency: Severity::High,
        }]
    );
}

#[test]
fn policy_rules_reject_zero_per_agent_limit() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.policy.rules = vec![PolicyRuleConfig {
        name: "deny-execution".to_string(),
        decision: PolicyRuleDecision::Deny,
        threat_class: ThreatClass::Execution,
        actions: vec![PolicyActionSelector::DeployDecoy],
        min_severity: Severity::Medium,
        max_severity: Severity::Critical,
        time_window_utc: Some(PolicyTimeWindowConfig {
            start_hour_utc: 18,
            end_hour_utc: 24,
        }),
        max_actions_per_agent_per_minute: Some(0),
        reason: None,
    }];

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `policy.rules`: rule 0 max_actions_per_agent_per_minute must be greater than zero"
    );
}

#[test]
fn investigation_requires_positive_starvation_boost_when_enabled() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.investigation.enabled = true;
    config
        .investigation
        .starvation_boost_per_second_basis_points = 0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `investigation.starvation_boost_per_second_basis_points`: must be greater than zero when investigation is enabled"
    );
}

#[test]
fn investigation_requires_ambiguity_margin_within_basis_point_range() {
    let mut config = valid_config(PheromoneBackendConfig::LocalJournal {
        path: "./journal.jsonl".to_string(),
    });
    config.investigation.enabled = true;
    config.investigation.ambiguity_margin_basis_points = 10_001;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `investigation.ambiguity_margin_basis_points`: must be between 1 and 10000 when investigation is enabled"
    );
}

/// `speed` used to satisfy the "at least one weight" check on its own. It no
/// longer contributes to fitness, so a weights block whose only non-zero entry
/// is `speed` now yields a fitness of exactly zero for every candidate: a total
/// tie in which survivor selection falls through to tie-breaks and the
/// operator's stated objective is never expressed anywhere.
///
/// A ranking that silently means nothing is worse than a config that refuses to
/// load, so this fails closed at validation.
#[test]
fn evolution_rejects_fitness_weights_carried_entirely_by_the_inert_speed_weight() {
    let mut config = valid_config(PheromoneBackendConfig::InMemory);
    config.runtime.require_durable_live_response = false;
    config.evolution.enabled = true;
    config.evolution.fitness_weights.detection_rate = 0.0;
    config.evolution.fitness_weights.false_positive_cost = 0.0;
    config.evolution.fitness_weights.speed = 1.0;
    config.evolution.fitness_weights.threat_class_coverage = 0.0;

    let error = config.validate().unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid field `evolution.fitness_weights`: at least one of `detection_rate`, \
         `false_positive_cost` or `threat_class_coverage` must be greater than zero (`speed` is \
         accepted for compatibility but no longer contributes)"
    );
}

/// Every ruleset already deployed carries a `speed:` entry in its weights block,
/// including this repository's own tracked `rulesets/default.yaml` (covered by
/// `mutation::tests_core::tracked_default_ruleset_still_loads_with_its_speed_weight`,
/// which parses that file). The struct is `deny_unknown_fields`, so deleting the
/// field would turn a config that loads today into a hard startup failure -- and
/// `rulesets/` is covered by the signed `rulesets/attestation.json`, whose
/// signing key is deliberately not in this repository, so the tracked ruleset
/// could not have been edited to drop the key either.
///
/// The weight is therefore still accepted and still validated. It just no longer
/// contributes.
#[test]
fn evolution_fitness_weights_still_accept_the_inert_speed_weight() {
    let raw = r#"{
        "detection_rate": 0.40,
        "false_positive_cost": 0.30,
        "speed": 0.15,
        "threat_class_coverage": 0.15
    }"#;
    let weights: EvolutionFitnessWeightsConfig = serde_json::from_str(raw).unwrap();
    assert_eq!(weights.speed, 0.15);

    // Redistributed, not dropped: the total the operator wrote is preserved and
    // only the split across the applied objectives changes.
    let applied = weights.applied();
    let configured_total = weights.detection_rate
        + weights.false_positive_cost
        + weights.speed
        + weights.threat_class_coverage;
    let applied_total =
        applied.detection_rate + applied.false_positive_cost + applied.threat_class_coverage;
    assert!((applied_total - configured_total).abs() < 1e-12);

    // The proportions between the applied objectives are exactly as configured.
    assert!(
        (applied.detection_rate / applied.false_positive_cost
            - weights.detection_rate / weights.false_positive_cost)
            .abs()
            < 1e-12
    );
}
