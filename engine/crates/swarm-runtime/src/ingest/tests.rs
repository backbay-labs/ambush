use super::health::{HeapPressureSnapshot, response_adapter_kind};
use super::platform_api::{
    PlatformApiEnvelope, PlatformAssetPosture, PlatformFindingSummary, PlatformIncidentSummary,
    PlatformRuntimeStatus,
};
use super::{
    DemoApprovalResumeRequest, DemoApprovalResumeResponse, DemoDashboardSnapshot, DemoProofPackage,
    DemoReplayRequest, DemoReplayResponse, IngestRequest, IngestRequestError, IngestResponse,
    IngestState, StrategyProposalRoute, detect_http_router, ingest_router, validate_and_parse,
};
use crate::StrategyProposalRouteError;
use crate::anti_tamper::AntiTamperReport;
use crate::approval::DefaultApprovalHarness;
use crate::bridge_runtime::{BridgeStatusSnapshot, SharedBridgeHealth};
use crate::config::{CURRENT_SCHEMA_VERSION, write_debug_test_config_signature};
use crate::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
use crate::evasion_coverage::EvasionCoverageSnapshot;
use crate::evolution::DefaultEvolutionProofHarness;
use crate::mutation::{
    DefaultEvolutionMutationHarness, EvolutionMutationProfileOverrides,
    EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
};
use crate::replay::{
    DefaultReplayHarness, ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata,
    ReplayScenarioStep,
};
use crate::runtime_events::{ReplayEventPhase, RuntimeEvent, RuntimeEventBroadcaster, now_ms};
use crate::startup_attestation::{StartupAttestationComponentReport, StartupAttestationReport};
use crate::strategy::DefaultStrategyScorecardHarness;
use crate::tom_agent::{GovernancePolicy, GovernancePolicyConfig};
use arc_swap::ArcSwap;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::routing::post;
use axum::{Json as AxumJson, Router};
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use swarm_core::ThreatClass;
use swarm_core::agent::AgentHealthEntry;
use swarm_core::agent::{AgentHealth, AgentRole, SwarmMode, SwarmModeState};
use swarm_core::config::{
    AuditConfig, BundleStoreConfig, CanaryConfig, CircuitBreakerConfig, CorrelationConfig,
    DetectionConfig, DetectorProfilesConfig, HttpEdrConfig, InvestigationConfig,
    NotificationChannelConfig, NotificationRateLimitConfig, NotificationRoutingConfig,
    OperatorPrincipalConfig, OperatorScope, OperatorSurfaceConfig, PheromoneBackendConfig,
    PheromoneConfig, PlatformApiConfig, PlatformApiKeyConfig, PlatformApiScope,
    PolicyActionSelector, PolicyConfig, PolicyRuleConfig, PolicyRuleDecision, PromotionConfig,
    ResponseAdapterConfig, RetryConfig, RoutingRule, RuntimeAntiTamperConfig, RuntimeMode,
    RuntimeSettings, SwarmConfig, TelemetrySourceConfig, WebhookConfig,
};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{
    AgentId, HuntId, ProvidenceIncidentReconciliation, ProvidenceIncidentStatus,
    ProvidenceReconciliationOutcome, ResponseAction, ResponseBlastRadiusImpact,
    ResponseBlastRadiusPreview, ResponseRehearsalPreview, ResponseRehearsalScopeKind,
    ResponseRollbackPreview, ResponseRollbackStep, ResponseRollbackStepKind, Severity,
};
use swarm_crypto::Ed25519Signer;
use swarm_pheromone::PheromoneSubstrate;
use swarm_response::SwarmFindingEnvelope;
use swarm_spine::{
    CorrelatedIncident, FalsePositiveMeasurement, IncidentStore, InvestigationBundle,
    InvestigationBundleStore, ReplayBundleStore,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};
use tower::ServiceExt;

fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
    vec![PolicyRuleConfig {
        name: "ingest-test-execution-allow".to_string(),
        decision: PolicyRuleDecision::Allow,
        threat_class: ThreatClass::Execution,
        actions: vec![PolicyActionSelector::Escalate],
        min_severity: Severity::Low,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: Some("ingest tests allow execution demo replays".to_string()),
    }]
}

fn test_config(strategy: &str) -> SwarmConfig {
    SwarmConfig {
        schema_version: 1,
        name: "ingest-test".to_string(),
        description: "ingest test config".to_string(),
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
            anti_tamper: RuntimeAntiTamperConfig::default(),
            temporal_event_window: swarm_core::config::TemporalEventWindowConfig::default(),
            agent_tick_timeout_ms: 500,
            governance_degraded_tick_threshold: 3,
            partition_contingency_lease_ttl_ms: 300_000,
            partition_contingency_blast_radius_cap: 1,
            max_dead_letter_bytes: None,
        },
        detection: DetectionConfig {
            strategy: strategy.to_string(),
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
        response_adapter: ResponseAdapterConfig::Sandbox,
        siem_forward: None,
        notification_channels: std::collections::BTreeMap::new(),
        notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
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
        platform_api: PlatformApiConfig::default(),
        operator: OperatorSurfaceConfig::default(),
        tls: None,
    }
}

const TEST_PLATFORM_API_KEY: &str = "platform-read-secret";
const TEST_PLATFORM_API_BEARER_TOKEN: &str = "platform-bearer-secret";
const TEST_PLATFORM_API_BEARER_TOKEN_ENV: &str = "SWARM_PLATFORM_API_TEST_TOKEN";

fn enable_platform_api(config: &mut SwarmConfig) {
    config.platform_api.keys = vec![PlatformApiKeyConfig {
        name: "test-reader".to_string(),
        key_hash: super::platform_api::platform_api_key_hash_hex(TEST_PLATFORM_API_KEY),
        scopes: vec![PlatformApiScope::Read],
    }];
    config.operator.auth.operator_id = "platform-api-test-operator".to_string();
    config.operator.auth.token_env = TEST_PLATFORM_API_BEARER_TOKEN_ENV.to_string();
    config.operator.auth.context_token_env = TEST_PLATFORM_API_BEARER_TOKEN_ENV.to_string();
    unsafe {
        std::env::set_var(
            TEST_PLATFORM_API_BEARER_TOKEN_ENV,
            TEST_PLATFORM_API_BEARER_TOKEN,
        );
    }
}

fn mint_platform_context_token(
    config: &SwarmConfig,
    scope: crate::providence::ProvidenceContextScope,
) -> String {
    crate::providence::mint_providence_context_token(&config.operator, scope, now_ms()).unwrap()
}

fn authorized_platform_api_request(
    method: &str,
    uri: impl Into<String>,
) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri.into())
        .header(
            header::AUTHORIZATION,
            format!("Bearer {TEST_PLATFORM_API_BEARER_TOKEN}"),
        )
        .header("x-api-key", TEST_PLATFORM_API_KEY)
}

fn process_event_json(event_id: &str, host_id: &str, timestamp: i64) -> Value {
    let mut event = valid_process_event_json();
    event["event_id"] = json!(event_id);
    event["host_id"] = json!(host_id);
    event["timestamp"] = json!(timestamp);
    event
}

fn seed_platform_replay_bundle(
    state: &IngestState,
    event_id: &str,
    host_id: &str,
    created_at_ms: i64,
) {
    let event = validate_and_parse(process_event_json(event_id, host_id, created_at_ms)).unwrap();
    let finding = swarm_whisker::DetectionFinding {
        finding_id: format!("finding-{event_id}"),
        event_id: event_id.to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::Critical,
        confidence: 0.98,
        evidence: json!({
            "host_id": host_id,
            "event_id": event_id,
        }),
        strategy_id: "suspicious_process_tree".to_string(),
    };
    let bundle = swarm_spine::ReplayBundle {
        bundle_id: format!("bundle-{event_id}"),
        event,
        findings: vec![finding.clone()],
        deposits: Vec::new(),
        action_request: swarm_policy::ActionRequest {
            hunt_id: swarm_core::types::HuntId(event_id.to_string()),
            requested_by: swarm_core::types::AgentId::new("whisker", "primary"),
            action: ResponseAction::Escalate {
                summary: format!("escalate {event_id}"),
                urgency: Severity::Critical,
            },
            severity: Severity::Critical,
            evidence: json!(swarm_response::SwarmFindingEnvelope::from(&finding)),
        },
        rehearsal: None,
        audit: swarm_spine::AuditTrail {
            trail_id: format!("trail-{event_id}"),
            hunt_id: event_id.to_string(),
            related_receipt_ids: vec![format!("receipt-{event_id}")],
            detection: finding,
            policy: swarm_spine::PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Allow,
                rule_name: "platform-test.allow".to_string(),
                reason: "platform API test fixture".to_string(),
                lease: None,
            },
            response: swarm_spine::AuditResponseRecord::Skipped {
                reason: "platform API fixture skips response execution".to_string(),
            },
            created_at_ms,
        },
    };

    state.current_replay_store().persist(&bundle).unwrap();
}

fn seed_platform_rehearsal_bundle(
    state: &IngestState,
    event_id: &str,
    host_id: &str,
    created_at_ms: i64,
) {
    let event = validate_and_parse(process_event_json(event_id, host_id, created_at_ms)).unwrap();
    let finding = swarm_whisker::DetectionFinding {
        finding_id: format!("finding-{event_id}"),
        event_id: event_id.to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::Critical,
        confidence: 0.98,
        evidence: json!({
            "host_id": host_id,
            "event_id": event_id,
        }),
        strategy_id: "suspicious_process_tree".to_string(),
    };
    let bundle = swarm_spine::ReplayBundle {
        bundle_id: format!("bundle:rehearsal:{event_id}:{created_at_ms}"),
        event,
        findings: vec![finding.clone()],
        deposits: Vec::new(),
        action_request: swarm_policy::ActionRequest {
            hunt_id: HuntId(event_id.to_string()),
            requested_by: swarm_core::types::AgentId::new("whisker", "primary"),
            action: ResponseAction::Escalate {
                summary: format!("escalate {event_id}"),
                urgency: Severity::Critical,
            },
            severity: Severity::Critical,
            evidence: json!(swarm_response::SwarmFindingEnvelope::from(&finding)),
        },
        rehearsal: Some(ResponseRehearsalPreview {
            rehearsal_id: format!("rehearsal:{event_id}"),
            source_bundle_id: format!("bundle:{event_id}"),
            prepared_at_ms: created_at_ms,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::Host,
                scope_value: host_id.to_string(),
                impact: ResponseBlastRadiusImpact::OperatorEscalationOnly,
                max_affected_scopes: 1,
                affected_capabilities: vec!["notify_operator".to_string()],
                summary: "Escalation remains dry-run only.".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: "Close the rehearsal escalation receipt.".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::CloseEscalation,
                    summary: "Close the rehearsal escalation receipt.".to_string(),
                }],
            },
        }),
        audit: swarm_spine::AuditTrail {
            trail_id: format!("trail-rehearsal-{event_id}"),
            hunt_id: event_id.to_string(),
            related_receipt_ids: vec![format!("receipt-rehearsal-{event_id}")],
            detection: finding,
            policy: swarm_spine::PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Allow,
                rule_name: "platform-test.rehearsal-allow".to_string(),
                reason: "platform API rehearsal fixture".to_string(),
                lease: None,
            },
            response: swarm_spine::AuditResponseRecord::Skipped {
                reason: "platform API rehearsal fixture skips live response execution".to_string(),
            },
            created_at_ms,
        },
    };

    state.current_replay_store().persist(&bundle).unwrap();
}

fn seed_measured_incident(
    state: &IngestState,
    incident_id: &str,
    hunt_id: &str,
    host_id: &str,
    strategy_id: &str,
    false_positive: bool,
    created_at_ms: i64,
) {
    state
        .current_incident_store()
        .persist(&CorrelatedIncident {
            incident_id: incident_id.to_string(),
            summary: format!("measured incident for {hunt_id}"),
            created_at_ms,
            window_start_ms: created_at_ms,
            window_end_ms: created_at_ms + 1,
            correlation_keys: vec![format!("host:{host_id}")],
            related_receipt_ids: vec![format!("receipt:{hunt_id}")],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: format!("investigation:{hunt_id}"),
                hunt_id: hunt_id.to_string(),
                finding_id: format!("finding:{hunt_id}"),
                reason: "measured incident fixture".to_string(),
                shared_keys: vec![format!("host:{host_id}")],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some(hunt_id.to_string()),
            trigger_finding_id: Some(format!("finding:{hunt_id}")),
            trigger_strategy_id: Some(strategy_id.to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::High),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: vec![FalsePositiveMeasurement {
                finding_id: format!("finding:{hunt_id}"),
                hunt_id: hunt_id.to_string(),
                strategy_id: strategy_id.to_string(),
                host_id: Some(host_id.to_string()),
                feedback_id: format!("feedback:{hunt_id}"),
                reviewed_at_ms: created_at_ms + 10,
                analyst_id: "analyst-platform".to_string(),
                action: if false_positive {
                    swarm_core::types::ProvidenceFeedbackAction::Dismiss
                } else {
                    swarm_core::types::ProvidenceFeedbackAction::Confirm
                },
                reason: Some("runtime status fixture".to_string()),
                false_positive,
            }],
        })
        .unwrap();
}

async fn seed_platform_host_deposit(
    state: &IngestState,
    signing_key: &ed25519_dalek::SigningKey,
    host_id: &str,
    threat_class: ThreatClass,
    confidence: f64,
    timestamp: i64,
) {
    let agent_id = swarm_core::types::AgentId::from_verifying_key(&signing_key.verifying_key());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: json!({
            "event_id": format!("evt-{agent_id}"),
            "host_id": host_id,
            "source": "synthetic",
            "evidence": {
                "host_metadata": {
                    "host_id": host_id,
                }
            }
        }),
        threat_class,
        severity: Severity::High,
        confidence,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: agent_id.clone(),
        agent_identity: agent_id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let payload = swarm_pheromone::DepositSigningPayload {
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
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let signature = signing_key.sign(&payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
    state.current_substrate().deposit(deposit).await.unwrap();
}

fn seed_platform_investigation_bundle(
    state: &IngestState,
    investigation_id: &str,
    hunt_id: &str,
    host_id: &str,
    status: swarm_spine::InvestigationStatus,
    queued_at_ms: i64,
) {
    state
        .current_investigation_store()
        .persist(&InvestigationBundle {
            investigation_id: investigation_id.to_string(),
            source_bundle_id: format!("bundle:{hunt_id}"),
            hunt_id: hunt_id.to_string(),
            trail_id: format!("trail:{hunt_id}"),
            event_id: format!("evt:{hunt_id}"),
            finding_id: format!("finding:{hunt_id}"),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            strategy_id: "suspicious_process_tree".to_string(),
            response_kind: "skipped".to_string(),
            related_receipt_ids: vec![format!("receipt:{hunt_id}")],
            host_id: Some(host_id.to_string()),
            user: Some("alice".to_string()),
            process_name: Some("powershell.exe".to_string()),
            queued_at_ms,
            started_at_ms: Some(queued_at_ms + 10),
            completed_at_ms: None,
            status,
            priority: swarm_spine::InvestigationPriority::default(),
            summary: Some(format!("investigation for {hunt_id}")),
            evidence_points: vec![format!("host_id={host_id}")],
            correlation_keys: vec![format!("host:{host_id}")],
            candidate_interpretations: Vec::new(),
            vote_lineage: Vec::new(),
            decision: swarm_spine::InvestigationDecision::default(),
            failure_reason: None,
        })
        .unwrap();
}

fn temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "swarm-runtime-ingest-{label}-{}-{nanos}.yaml",
        std::process::id()
    ))
}

fn write_config(path: &Path, strategy: &str) {
    fs::write(path, serde_yaml::to_string(&test_config(strategy)).unwrap()).unwrap();
    write_debug_test_config_signature(path).unwrap();
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn office_control_experiment() -> PathBuf {
    repo_root().join("experiments/office-baseline-control.yaml")
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "swarm-runtime-ingest-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn configure_evolution_paths(config: &mut SwarmConfig, root: &Path) {
    config.evolution.enabled = true;
    config.canary.enabled = true;
    config.evolution.paths.replay_results_dir = root.join("replay").display().to_string();
    config.evolution.paths.experiment_results_dir = root.join("experiments").display().to_string();
    config.evolution.paths.verification_results_dir =
        root.join("verifications").display().to_string();
    config.evolution.paths.shadow_results_dir = root.join("shadows").display().to_string();
    config.evolution.paths.strategy_memory_results_dir =
        root.join("strategy-memory").display().to_string();
    config.evolution.paths.strategy_scorecard_results_dir =
        root.join("strategy-scorecards").display().to_string();
    config.evolution.paths.evolution_proof_results_dir =
        root.join("evolution-proofs").display().to_string();
    config.evolution.paths.evolution_queue_results_dir =
        root.join("evolution-queue").display().to_string();
    config.evolution.paths.evolution_selection_results_dir =
        root.join("evolution-selections").display().to_string();
    config.evolution.paths.evolution_bridge_results_dir = root
        .join("evolution-selection-bridges")
        .display()
        .to_string();
    config.evolution.paths.evolution_handoff_results_dir =
        root.join("evolution-handoffs").display().to_string();
    config.evolution.paths.evolution_pressure_results_dir =
        root.join("evolution-pressures").display().to_string();
    config.evolution.paths.evolution_draft_results_dir =
        root.join("evolution-drafts").display().to_string();
    config.evolution.paths.evolution_draft_promotion_results_dir = root
        .join("evolution-draft-promotions")
        .display()
        .to_string();
    config.evolution.paths.evolution_materialization_results_dir = root
        .join("evolution-materializations")
        .display()
        .to_string();
    config.evolution.paths.evolution_validation_results_dir = root
        .join("evolution-validation-bundles")
        .display()
        .to_string();
    config.evolution.paths.evolution_reconciliation_results_dir =
        root.join("evolution-reconciliations").display().to_string();
    config.evolution.paths.evolution_mutation_results_dir =
        root.join("evolution-mutations").display().to_string();
    config
        .evolution
        .paths
        .evolution_mutation_materialization_batch_results_dir = root
        .join("evolution-mutation-materialization-batches")
        .display()
        .to_string();
    config
        .evolution
        .paths
        .evolution_mutation_validation_batch_results_dir = root
        .join("evolution-mutation-validation-batches")
        .display()
        .to_string();
    config.evolution.paths.evolution_ranking_results_dir =
        root.join("evolution-rankings").display().to_string();
    config.evolution.paths.evolution_population_results_dir =
        root.join("evolution-population").display().to_string();
    config.evolution.paths.canary_results_dir = root.join("canaries").display().to_string();
}

fn test_ingest_state() -> IngestState {
    IngestState::from_config(temp_path("inline"), test_config("suspicious_process_tree")).unwrap()
}

fn failed_startup_attestation_report() -> StartupAttestationReport {
    StartupAttestationReport {
        ready: false,
        evaluated_at_ms: 1_710_000_000_000,
        binary: StartupAttestationComponentReport {
            ready: false,
            subject: "binary".to_string(),
            statement_path: "swarm_detect.attestation.json".to_string(),
            status: "failed".to_string(),
            details: "binary digest mismatch".to_string(),
            key_id: Some("test-key".to_string()),
            expected_sha256: Some("expected".to_string()),
            observed_sha256: Some("observed".to_string()),
            verified_items: None,
        },
        rulesets: StartupAttestationComponentReport {
            ready: true,
            subject: "rulesets".to_string(),
            statement_path: "rulesets/attestation.json".to_string(),
            status: "verified".to_string(),
            details: "verified 3 repo-owned ruleset files".to_string(),
            key_id: Some("test-key".to_string()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: Some(3),
        },
    }
}

fn verified_startup_attestation_report() -> StartupAttestationReport {
    StartupAttestationReport {
        ready: true,
        evaluated_at_ms: 1_710_000_000_500,
        binary: StartupAttestationComponentReport {
            ready: true,
            subject: "binary".to_string(),
            statement_path: "swarm_detect.attestation.json".to_string(),
            status: "verified".to_string(),
            details: "binary digest verified".to_string(),
            key_id: Some("test-key".to_string()),
            expected_sha256: Some("expected".to_string()),
            observed_sha256: Some("expected".to_string()),
            verified_items: Some(1),
        },
        rulesets: StartupAttestationComponentReport {
            ready: true,
            subject: "rulesets".to_string(),
            statement_path: "rulesets/attestation.json".to_string(),
            status: "verified".to_string(),
            details: "verified 3 repo-owned ruleset files".to_string(),
            key_id: Some("test-key".to_string()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: Some(3),
        },
    }
}

fn tampered_anti_tamper_report(required: bool) -> AntiTamperReport {
    AntiTamperReport {
        enabled: true,
        supported: true,
        required,
        ready: false,
        checked_at_ms: 1_710_000_010_000,
        status: "tampered".to_string(),
        details: "debugger attached via TracerPid=77; 1 unexpected library load(s)".to_string(),
        debugger_attached: true,
        tracer_pid: Some(77),
        unexpected_library_loads: vec!["/tmp/rogue.so".to_string()],
        baseline_library_count: 12,
        fail_closed_live_response: required,
    }
}

fn degraded_ingest_state() -> IngestState {
    let state = test_ingest_state();
    state.detector_status.store(Arc::new(
        super::health::DetectorRuntimeStatus::reload_failed(
            "suspicious_process_tree".to_string(),
            "synthetic reload failure",
        ),
    ));
    state
}

fn live_response_config(strategy: &str) -> SwarmConfig {
    let mut config = test_config(strategy);
    config.runtime.mode = RuntimeMode::LiveResponse;
    config
}

#[tokio::test]
async fn strategy_proposal_router_admits_verified_kitten_candidate_into_canary_lane() {
    let root = temp_dir("strategy-router");
    let config_path = repo_root().join("rulesets/default.yaml");
    let mut config = test_config("suspicious_process_tree");
    configure_evolution_paths(&mut config, &root);
    let state = IngestState::from_config(&config_path, config.clone()).unwrap();
    let paths = super::resolve_strategy_proposal_paths(&config_path, &config);

    let replay = DefaultReplayHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.replay_results_dir,
    )
    .unwrap();
    let verification = replay
        .evaluate_verification_path(
            office_control_experiment(),
            &config.evolution.paths.verification_results_dir,
        )
        .await
        .unwrap();
    let scorecards = DefaultStrategyScorecardHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.strategy_memory_results_dir,
        &config.evolution.paths.strategy_scorecard_results_dir,
    )
    .unwrap();
    let scorecard = scorecards
        .create_scorecard(
            &replay,
            office_control_experiment(),
            &config.evolution.paths.experiment_results_dir,
            &config.evolution.paths.verification_results_dir,
            &verification.report.verification_id,
        )
        .await
        .unwrap();
    let drafting = DefaultEvolutionDraftingHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.evolution_pressure_results_dir,
        &config.evolution.paths.evolution_draft_results_dir,
        &config.evolution.paths.evolution_draft_promotion_results_dir,
        &config.evolution.paths.evolution_materialization_results_dir,
        &config.evolution.paths.evolution_validation_results_dir,
        &config.evolution.paths.evolution_reconciliation_results_dir,
    )
    .unwrap();
    let mutation = DefaultEvolutionMutationHarness::from_path(
        &config.evolution.paths.evolution_mutation_results_dir,
        &config
            .evolution
            .paths
            .evolution_mutation_materialization_batch_results_dir,
        &config
            .evolution
            .paths
            .evolution_mutation_validation_batch_results_dir,
        &config.evolution.paths.evolution_ranking_results_dir,
    )
    .unwrap();
    let proof_harness = DefaultEvolutionProofHarness::from_config(
        &config_path,
        config.clone(),
        &config.evolution.paths.evolution_proof_results_dir,
    )
    .unwrap();

    let pressure = drafting
        .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
        .unwrap();
    let draft = drafting
        .create_draft(EvolutionDraftCreateRequest {
            pressure_id: pressure.report.pressure_id.clone(),
            strategy_id: "ingest_router_candidate".to_string(),
            strategy_description: "Ingest router admission fixture".to_string(),
            mutation: "router_acceptance".to_string(),
            rationale: "exercise the runtime strategy proposal admission lane".to_string(),
        })
        .unwrap();
    let spec = mutation
        .create_mutation_spec(
            &drafting,
            EvolutionMutationSpecCreateRequest {
                draft_id: Some(draft.report.draft_id.clone()),
                materialization_id: None,
                base_experiment_path: Some(office_control_experiment()),
                rationale: "materialize a proposal-ready control candidate".to_string(),
            },
        )
        .unwrap();
    let spec = mutation
        .append_variant(
            &spec.report.mutation_spec_id,
            EvolutionMutationVariantCreateRequest {
                variant_id: Some("router-control".to_string()),
                strategy_id: "office_router_candidate".to_string(),
                strategy_description: "Runtime router control candidate".to_string(),
                mutation: "copy_control_profile".to_string(),
                rationale: "keep the verification-clean control profile".to_string(),
                overrides: EvolutionMutationProfileOverrides::default(),
            },
        )
        .unwrap();
    let batch = mutation
        .materialize_batch(&drafting, &spec.report.mutation_spec_id)
        .unwrap();
    let validation_batch = mutation
        .refresh_validation_batch(
            &drafting,
            &replay,
            &proof_harness,
            &scorecards,
            &config.evolution.paths.experiment_results_dir,
            &config.evolution.paths.verification_results_dir,
            &config.evolution.paths.shadow_results_dir,
            &batch.report.batch_id,
        )
        .await
        .unwrap();
    let ranking = mutation
        .rank_candidates(
            &config.evolution.paths.evolution_queue_results_dir,
            &validation_batch.report.validation_batch_id,
            1,
        )
        .unwrap();
    let population = mutation
        .refresh_population(
            &config.evolution.paths.evolution_population_results_dir,
            &drafting,
            &config.evolution.paths.experiment_results_dir,
            &config.evolution.paths.verification_results_dir,
            &ranking.report,
            config.evolution.population_size,
            config.evolution.pareto_tournament_size,
            &config.evolution.fitness_weights,
            None,
        )
        .unwrap();
    assert_eq!(population.members.len(), 1);

    mutation
        .mark_population_candidate_proposed(
            &config.evolution.paths.evolution_population_results_dir,
            "office_router_candidate",
            now_ms(),
        )
        .unwrap();

    let packet = ranking.report.review_packets.first().unwrap();
    let validation = drafting
        .load_validation_bundle(&packet.validation_bundle_id)
        .unwrap()
        .unwrap();
    let router = state.current_strategy_proposal_router();
    let report = router
        .route_proposal(StrategyProposalRoute {
            proposed_by: swarm_core::types::AgentId("kitten-primary".to_string()),
            strategy_id: "office_router_candidate".to_string(),
            strategy: json!({
                "source": "kitten_population_candidate",
                "ranking_id": ranking.report.ranking_id,
                "validation_bundle_id": packet.validation_bundle_id,
                "materialization_id": packet.materialization_id,
                "experiment_path": validation.report.experiment_path,
            }),
            fitness: population.members[0].fitness,
        })
        .await
        .unwrap();

    assert_eq!(report.outcome, super::StrategyProposalOutcome::Accepted);
    assert!(report.selection_id.is_some());
    assert!(report.bridge_id.is_some());
    assert!(report.handoff_id.is_some());
    assert!(report.canary_run_id.is_some());

    let stored_population = mutation
        .load_population(&config.evolution.paths.evolution_population_results_dir)
        .unwrap()
        .unwrap();
    let stored_candidate = stored_population
        .members
        .iter()
        .find(|candidate| candidate.strategy_id == "office_router_candidate")
        .unwrap();
    assert_eq!(
        stored_candidate.queue_review_state,
        Some(crate::evolution::EvolutionProposalReviewState::AcceptedForCanary)
    );
    assert!(!stored_candidate.ready_for_review);
    assert_eq!(paths.canary_results_dir, root.join("canaries"));
}

#[tokio::test]
async fn strategy_proposal_router_rejects_malformed_payload_with_typed_error() {
    let state = test_ingest_state();
    let router = state.current_strategy_proposal_router();
    let error = router
        .route_proposal(StrategyProposalRoute {
            proposed_by: AgentId("kitten-primary".to_string()),
            strategy_id: "office_router_candidate".to_string(),
            strategy: json!({
                "source": "kitten_population_candidate",
                "ranking_id": 7,
            }),
            fitness: 0.95,
        })
        .await
        .unwrap_err();

    assert!(matches!(
        &error,
        StrategyProposalRouteError::InvalidPayload(_)
    ));
    assert_eq!(error.boundary(), "payload");
}

fn demo_ingest_state() -> IngestState {
    let mut config = test_config("suspicious_process_tree");
    config.runtime.demo_mode = true;
    IngestState::from_config(temp_path("demo-inline"), config).unwrap()
}

fn live_demo_ingest_state() -> (IngestState, DefaultApprovalHarness) {
    let mut config = test_config("suspicious_process_tree");
    let operator_vote_signer = Ed25519Signer::from_secret_material("demo-operator-vote-key");
    config.runtime.demo_mode = true;
    config.runtime.mode = RuntimeMode::LiveResponse;
    config.policy.human_gate_severity = Severity::Low;
    config.investigation.enabled = true;
    config.correlation.enabled = true;
    config.operator.auth.operator_id =
        format!("swarm:ed25519:{}", operator_vote_signer.public_key_hex());
    let config_path = temp_path("demo-live-inline");
    let root = temp_path("demo-live-root");
    let harness = DefaultApprovalHarness::from_path(
        &config_path,
        root.join("approval-verdicts"),
        root.join("approval-receipt-packs"),
        root.join("approval-sets"),
        root.join("approval-ledgers"),
    )
    .unwrap();
    (
        IngestState::from_config(config_path, config)
            .unwrap()
            .with_approval_harness(harness.clone()),
        harness,
    )
}

fn bridge_health(entries: Vec<BridgeStatusSnapshot>) -> SharedBridgeHealth {
    Arc::new(std::sync::Mutex::new(entries))
}

#[derive(Clone, Default)]
struct NotificationCaptureState {
    payloads: Arc<AsyncMutex<Vec<Value>>>,
    auth: Arc<AsyncMutex<Option<String>>>,
    signature: Arc<AsyncMutex<Option<String>>>,
}

async fn notification_capture_handler(
    State(state): State<NotificationCaptureState>,
    headers: axum::http::HeaderMap,
    AxumJson(payload): AxumJson<Value>,
) -> (StatusCode, AxumJson<Value>) {
    state.payloads.lock().await.push(payload);
    *state.auth.lock().await = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    *state.signature.lock().await = headers
        .get("x-swarm-signature")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    (
        StatusCode::OK,
        AxumJson(json!({
            "id": "prov-test-1",
            "url": "http://127.0.0.1:3001/incidents/prov-test-1"
        })),
    )
}

async fn spawn_notification_capture_server() -> (
    String,
    NotificationCaptureState,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let state = NotificationCaptureState::default();
    let app = Router::new()
        .route("/", get(|| async { StatusCode::METHOD_NOT_ALLOWED }))
        .route(
            "/incidents",
            get(|| async { StatusCode::METHOD_NOT_ALLOWED }).post(notification_capture_handler),
        )
        .route(
            "/incidents/{id}",
            post(notification_capture_handler).put(notification_capture_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        let _ = server.await;
    });
    (format!("http://{address}/"), state, shutdown_tx, handle)
}

async fn spawn_providence_health_server(
    status: StatusCode,
) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/incidents",
        get(move || async move { status }).post(move || async move { status }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        let _ = server.await;
    });
    (format!("http://{address}/incidents"), shutdown_tx, handle)
}

fn valid_process_event_json() -> Value {
    json!({
        "source": "synthetic",
        "event_id": "evt-ingest-1",
        "timestamp": 1_700_000_000_000i64,
        "host_id": "host-1",
        "payload": {
            "kind": "process_start",
            "parent_process": "WINWORD",
            "process_name": "powershell",
            "command_line": "powershell.exe -enc AAA=",
            "user": "alice"
        }
    })
}

fn malformed_event_json() -> Value {
    json!({
        "source": "synthetic",
        "event_id": "evt-ingest-bad",
        "timestamp": 1_700_000_000_000i64,
        "host_id": "host-1"
    })
}

async fn parse_response(response: axum::response::Response) -> IngestResponse {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn parse_json<T: serde::de::DeserializeOwned>(response: axum::response::Response) -> T {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn query_value(url: &str, key: &str) -> Option<String> {
    url.split_once('?').and_then(|(_, query)| {
        query.split('&').find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let candidate = parts.next()?;
            if candidate == key {
                Some(parts.next().unwrap_or_default().to_string())
            } else {
                None
            }
        })
    })
}

fn demo_replay_request(path: &Path) -> DemoReplayRequest {
    DemoReplayRequest {
        scenario_path: path.display().to_string(),
        pace_ms: 0,
    }
}

async fn parse_demo_replay_response(response: axum::response::Response) -> DemoReplayResponse {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn parse_demo_dashboard_response(
    response: axum::response::Response,
) -> DemoDashboardSnapshot {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn parse_demo_approval_resume_response(
    response: axum::response::Response,
) -> DemoApprovalResumeResponse {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn parse_demo_proof_response(response: axum::response::Response) -> DemoProofPackage {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn write_demo_scenario(path: &Path) {
    let manifest = ReplayScenarioManifest {
        name: "demo replay".to_string(),
        description: "demo replay scenario".to_string(),
        seed_time_ms: 1_700_000_000_000,
        requested_by: "demo-runner".to_string(),
        receipt_chain: Vec::new(),
        metadata: ReplayScenarioMetadata::default(),
        input: ReplayScenarioInput::Events {
            events: vec![ReplayScenarioStep {
                action: ResponseAction::Escalate {
                    summary: "demo replay".to_string(),
                    urgency: Severity::High,
                },
                event: validate_and_parse(valid_process_event_json()).unwrap(),
            }],
        },
        expectations: Default::default(),
    };
    fs::write(path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
}

fn write_human_gate_demo_scenario(path: &Path) {
    let manifest = ReplayScenarioManifest {
        name: "human gate replay".to_string(),
        description: "approval gated demo replay scenario".to_string(),
        seed_time_ms: 1_700_000_100_000,
        requested_by: "demo-operator".to_string(),
        receipt_chain: Vec::new(),
        metadata: ReplayScenarioMetadata::default(),
        input: ReplayScenarioInput::Events {
            events: vec![ReplayScenarioStep {
                action: ResponseAction::IsolateHost {
                    host_id: "host-1".to_string(),
                },
                event: validate_and_parse(valid_process_event_json()).unwrap(),
            }],
        },
        expectations: Default::default(),
    };
    fs::write(path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
}

#[test]
fn valid_event_parses_successfully() {
    let event = validate_and_parse(valid_process_event_json()).unwrap();
    assert_eq!(event.event_id, "evt-ingest-1");
    assert_eq!(event.host_id.as_deref(), Some("host-1"));
}

#[test]
fn malformed_event_is_rejected() {
    let error = validate_and_parse(malformed_event_json()).unwrap_err();
    assert!(matches!(&error, IngestRequestError::InvalidPayload(_)));
    assert!(error.to_string().contains("payload"));
}

#[test]
fn completely_invalid_json_is_rejected() {
    let error = validate_and_parse(json!("not-an-object")).unwrap_err();
    assert!(matches!(&error, IngestRequestError::InvalidPayload(_)));
    assert!(error.to_string().contains("invalid type"));
}

#[test]
fn missing_payload_is_rejected() {
    let error = validate_and_parse(json!({
        "source": "synthetic",
        "event_id": "evt-missing-payload",
        "timestamp": 1_700_000_000_000i64,
        "host_id": "host-1"
    }))
    .unwrap_err();
    assert!(matches!(&error, IngestRequestError::InvalidPayload(_)));
    assert!(error.to_string().contains("payload"));
}

#[test]
fn resolve_demo_scope_rejects_requested_fields_outside_token_scope() {
    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.context_token_env = "SWARM_OPERATOR_SCOPE_TEST_TOKEN".to_string();
    unsafe {
        std::env::set_var(
            "SWARM_OPERATOR_SCOPE_TEST_TOKEN",
            "scope-test-secret-material",
        );
    }
    let token = crate::providence::mint_providence_context_token(
        &config.operator,
        crate::providence::ProvidenceContextScope {
            hunt_id: Some("evt-scope-1".to_string()),
            ..Default::default()
        },
        now_ms(),
    )
    .unwrap();

    let error = super::resolve_demo_scope(
        &config.operator,
        &super::demo::DemoScopeQuery {
            context_token: Some(token),
            hunt_id: Some("evt-scope-2".to_string()),
            ..Default::default()
        },
    )
    .unwrap_err();

    assert!(matches!(
        error,
        IngestRequestError::ContextScopeMismatch { field: "hunt_id" }
    ));
}

#[test]
fn ingest_state_from_config_succeeds() {
    let state = test_ingest_state();
    assert_eq!(state.detector_strategy_name(), "suspicious_process_tree");
    assert!(
        state
            .config_path()
            .display()
            .to_string()
            .contains("swarm-runtime-ingest-inline")
    );
}

#[test]
fn ingest_state_reload_updates_detector() {
    let state = test_ingest_state();
    state.reload(test_config("dns_exfiltration")).unwrap();
    assert_eq!(state.detector_strategy_name(), "dns_exfiltration");
}

#[test]
fn ingest_state_reload_from_missing_path_fails() {
    let config_path = temp_path("missing");
    let state =
        IngestState::from_config(&config_path, test_config("suspicious_process_tree")).unwrap();

    let error = state.reload_from_disk().unwrap_err();
    assert!(error.to_string().contains("failed to read config"));
}

#[test]
fn ingest_state_from_path_loads_written_config() {
    let config_path = temp_path("from-path");
    write_config(&config_path, "suspicious_process_tree");

    let state = IngestState::from_path(&config_path).unwrap();
    assert_eq!(state.detector_strategy_name(), "suspicious_process_tree");

    let _ = fs::remove_file(config_path);
}

#[tokio::test]
async fn handler_accepts_valid_batch() {
    let app = ingest_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_response(response).await;
    assert!(!body.correlation_id.is_empty());
    assert_eq!(body.accepted.len(), 1);
    assert!(body.rejected.is_empty());
}

#[tokio::test]
async fn handler_rejects_malformed_batch() {
    let app = ingest_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![malformed_event_json()])).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_response(response).await;
    assert!(!body.correlation_id.is_empty());
    assert!(body.accepted.is_empty());
    assert_eq!(body.rejected.len(), 1);
    assert_eq!(body.rejected[0].event_id.as_deref(), Some("evt-ingest-bad"));
}

#[tokio::test]
async fn handler_rejects_invalid_json_body() {
    let app = ingest_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from("{not-json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn handler_rejects_invalid_content_type() {
    let app = ingest_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "text/plain")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn handler_handles_empty_batch() {
    let app = ingest_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![])).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_response(response).await;
    assert!(!body.correlation_id.is_empty());
    assert!(body.accepted.is_empty());
    assert!(body.rejected.is_empty());
}

#[tokio::test]
async fn handler_handles_mixed_batch() {
    let app = ingest_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![
                        valid_process_event_json(),
                        malformed_event_json(),
                        valid_process_event_json(),
                    ]))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_response(response).await;
    assert!(!body.correlation_id.is_empty());
    assert_eq!(body.accepted.len(), 2);
    assert_eq!(body.rejected.len(), 1);
}

#[tokio::test]
async fn handler_generates_unique_correlation_ids_per_request() {
    let app = ingest_router(test_ingest_state());
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let first_body = parse_response(first).await;
    let second_body = parse_response(second).await;
    assert_ne!(first_body.correlation_id, second_body.correlation_id);
}

#[tokio::test]
async fn platform_api_routes_require_bearer_and_api_key_but_health_and_ingest_do_not() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let app =
        detect_http_router(IngestState::from_config(temp_path("platform-auth"), config).unwrap());

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let missing_api_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {TEST_PLATFORM_API_BEARER_TOKEN}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_api_key.status(), StatusCode::UNAUTHORIZED);

    let wrong_bearer = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(header::AUTHORIZATION, "Bearer wrong-token")
                .header("x-api-key", TEST_PLATFORM_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_bearer.status(), StatusCode::UNAUTHORIZED);

    let wrong_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {TEST_PLATFORM_API_BEARER_TOKEN}"),
                )
                .header("x-api-key", "wrong-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_key.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    let health = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let ingest = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ingest.status(), StatusCode::OK);
}

#[tokio::test]
async fn platform_api_bearer_requires_read_scoped_operator_principal() {
    const READ_ENV: &str = "SWARM_PLATFORM_API_READER_TOKEN";
    const MAINT_ENV: &str = "SWARM_PLATFORM_API_MAINT_TOKEN";
    const READ_TOKEN: &str = "platform-reader-token";
    const MAINT_TOKEN: &str = "platform-maint-token";

    unsafe {
        std::env::set_var(READ_ENV, READ_TOKEN);
        std::env::set_var(MAINT_ENV, MAINT_TOKEN);
    }

    let mut config = test_config("suspicious_process_tree");
    config.platform_api.keys = vec![PlatformApiKeyConfig {
        name: "test-reader".to_string(),
        key_hash: super::platform_api::platform_api_key_hash_hex(TEST_PLATFORM_API_KEY),
        scopes: vec![PlatformApiScope::Read],
    }];
    config.operator.auth.context_token_env = READ_ENV.to_string();
    config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: "reader-1".to_string(),
            token_env: READ_ENV.to_string(),
            scopes: vec![OperatorScope::Read],
        },
        OperatorPrincipalConfig {
            operator_id: "maintainer-1".to_string(),
            token_env: MAINT_ENV.to_string(),
            scopes: vec![OperatorScope::Maintenance],
        },
    ];
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-scope-auth"), config).unwrap(),
    );

    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(header::AUTHORIZATION, format!("Bearer {MAINT_TOKEN}"))
                .header("x-api-key", TEST_PLATFORM_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let allowed = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
                .header("x-api-key", TEST_PLATFORM_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn platform_api_read_routes_accept_context_token_for_scoped_queries() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let token = mint_platform_context_token(
        &config,
        crate::providence::ProvidenceContextScope {
            incident_id: None,
            hunt_id: Some("evt-platform-1".to_string()),
            finding_id: Some("finding-evt-platform-1".to_string()),
            strategy_id: Some("suspicious_process_tree".to_string()),
            threat_class: Some(ThreatClass::Execution),
        },
    );
    let state = IngestState::from_config(temp_path("platform-context-token"), config).unwrap();
    seed_platform_replay_bundle(&state, "evt-platform-1", "host-a", 1_700_000_000_001);
    let app = detect_http_router(state);

    let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/v2/api/findings?finding_id=finding-evt-platform-1&hunt_id=evt-platform-1&strategy_id=suspicious_process_tree&threat_class=execution&context_token={token}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let envelope: PlatformApiEnvelope<PlatformFindingSummary> = parse_json(response).await;
    assert_eq!(envelope.data.len(), 1);
    assert_eq!(
        envelope.data[0].finding.finding_id,
        "finding-evt-platform-1"
    );

    let forbidden = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/v2/api/findings?finding_id=finding-evt-platform-2&hunt_id=evt-platform-2&strategy_id=suspicious_process_tree&threat_class=execution&context_token={token}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn platform_evasion_coverage_endpoint_returns_filtered_snapshot() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let app = detect_http_router(
        IngestState::from_config(repo_root().join("rulesets/default.yaml"), config).unwrap(),
    );

    let response = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                "/api/v1/evasion/coverage?detector=fileless_execution",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let snapshot: EvasionCoverageSnapshot = parse_json(response).await;
    assert_eq!(snapshot.suite_name, "evasion_breadth_v1");
    assert_eq!(snapshot.detectors.len(), 1);
    assert_eq!(snapshot.detectors[0].detector, "fileless_execution");
    assert!(snapshot.detectors[0].total_payloads >= 10);
    assert!(!snapshot.detectors[0].intentionally_uncovered.is_empty());
}

#[tokio::test]
async fn platform_evasion_coverage_endpoint_rejects_unknown_detector() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let app = detect_http_router(
        IngestState::from_config(repo_root().join("rulesets/default.yaml"), config).unwrap(),
    );

    let response = app
        .oneshot(
            authorized_platform_api_request(
                "GET",
                "/api/v1/evasion/coverage?detector=totally_unknown",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = parse_json(response).await;
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|value| value.contains("unknown evasion detector"))
    );
}

#[tokio::test]
async fn platform_findings_endpoint_returns_filtered_cursor_paginated_envelope() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let state = IngestState::from_config(temp_path("platform-findings"), config).unwrap();
    for (event_id, host_id, timestamp) in [
        ("evt-platform-1", "host-a", 1_700_000_000_001i64),
        ("evt-platform-2", "host-b", 1_700_000_000_002i64),
        ("evt-platform-3", "host-c", 1_700_000_000_003i64),
    ] {
        seed_platform_replay_bundle(&state, event_id, host_id, timestamp);
    }
    let app = detect_http_router(state);

    let first_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/findings?page_size=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page: PlatformApiEnvelope<PlatformFindingSummary> = parse_json(first_page).await;
    assert_eq!(first_page.data.len(), 1);
    assert_eq!(first_page.data[0].finding.event_id, "evt-platform-3");
    assert!(first_page.cursor.is_some());

    let second_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!(
                    "/v2/api/findings?page_size=1&cursor={}",
                    first_page.cursor.as_deref().unwrap()
                ),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page: PlatformApiEnvelope<PlatformFindingSummary> = parse_json(second_page).await;
    assert_eq!(second_page.data.len(), 1);
    assert_eq!(second_page.data[0].finding.event_id, "evt-platform-2");

    let filtered = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/findings?host_id=host-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered: PlatformApiEnvelope<PlatformFindingSummary> = parse_json(filtered).await;
    assert_eq!(filtered.data.len(), 1);
    assert_eq!(filtered.data[0].host_id.as_deref(), Some("host-b"));
    assert_eq!(filtered.data[0].finding.event_id, "evt-platform-2");
}

#[tokio::test]
async fn platform_incidents_endpoint_returns_filtered_cursor_paginated_envelope() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let state = IngestState::from_config(temp_path("platform-incidents"), config).unwrap();
    state
        .current_incident_store()
        .persist(&CorrelatedIncident {
            incident_id: "incident-1".to_string(),
            summary: "first incident".to_string(),
            created_at_ms: 1_700_000_000_001,
            window_start_ms: 1_700_000_000_000,
            window_end_ms: 1_700_000_000_001,
            correlation_keys: vec!["host:host-a".to_string()],
            related_receipt_ids: vec!["receipt-a".to_string()],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: "investigation-a".to_string(),
                hunt_id: "hunt-a".to_string(),
                finding_id: "finding-a".to_string(),
                reason: "shared host".to_string(),
                shared_keys: vec!["host:host-a".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("hunt-a".to_string()),
            trigger_finding_id: Some("finding-a".to_string()),
            trigger_strategy_id: Some("summary_investigator".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::High),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        })
        .unwrap();
    state
        .current_incident_store()
        .persist(&CorrelatedIncident {
            incident_id: "incident-2".to_string(),
            summary: "second incident".to_string(),
            created_at_ms: 1_700_000_000_002,
            window_start_ms: 1_700_000_000_001,
            window_end_ms: 1_700_000_000_002,
            correlation_keys: vec!["host:host-b".to_string()],
            related_receipt_ids: vec!["receipt-b".to_string()],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: "investigation-b".to_string(),
                hunt_id: "hunt-b".to_string(),
                finding_id: "finding-b".to_string(),
                reason: "shared receipt".to_string(),
                shared_keys: vec!["host:host-b".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("hunt-b".to_string()),
            trigger_finding_id: Some("finding-b".to_string()),
            trigger_strategy_id: Some("summary_investigator".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::Critical),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        })
        .unwrap();
    let app = detect_http_router(state);

    let first_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/incidents?page_size=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page: PlatformApiEnvelope<PlatformIncidentSummary> = parse_json(first_page).await;
    assert_eq!(first_page.data.len(), 1);
    assert_eq!(first_page.data[0].incident_id, "incident-2");
    assert!(first_page.cursor.is_some());

    let second_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!(
                    "/v2/api/incidents?page_size=1&cursor={}",
                    first_page.cursor.as_deref().unwrap()
                ),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page: PlatformApiEnvelope<PlatformIncidentSummary> = parse_json(second_page).await;
    assert_eq!(second_page.data.len(), 1);
    assert_eq!(second_page.data[0].incident_id, "incident-1");

    let filtered = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/incidents?hunt_id=hunt-b")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered: PlatformApiEnvelope<PlatformIncidentSummary> = parse_json(filtered).await;
    assert_eq!(filtered.data.len(), 1);
    assert_eq!(filtered.data[0].incident_id, "incident-2");
}

#[tokio::test]
async fn platform_surfaces_join_latest_rehearsal_and_providence_reconciliation() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let state = IngestState::from_config(temp_path("platform-rehearsal-context"), config).unwrap();
    seed_platform_rehearsal_bundle(
        &state,
        "evt-platform-rehearsal",
        "host-r",
        1_700_000_000_010,
    );
    state
        .current_incident_store()
        .persist(&CorrelatedIncident {
            incident_id: "incident-rehearsal".to_string(),
            summary: "incident with rehearsal".to_string(),
            created_at_ms: 1_700_000_000_011,
            window_start_ms: 1_700_000_000_009,
            window_end_ms: 1_700_000_000_011,
            correlation_keys: vec!["host:host-r".to_string()],
            related_receipt_ids: vec!["receipt-rehearsal-evt-platform-rehearsal".to_string()],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: "investigation-rehearsal".to_string(),
                hunt_id: "evt-platform-rehearsal".to_string(),
                finding_id: "finding-evt-platform-rehearsal".to_string(),
                reason: "same host".to_string(),
                shared_keys: vec!["host:host-r".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("evt-platform-rehearsal".to_string()),
            trigger_finding_id: Some("finding-evt-platform-rehearsal".to_string()),
            trigger_strategy_id: Some("summary_investigator".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::Critical),
            external_references: Vec::new(),
            providence_reconciliation: Some(ProvidenceIncidentReconciliation {
                incident_key: "suspicious_process_tree:execution:finding-evt-platform-rehearsal"
                    .to_string(),
                remote_incident_id: "prov-rehearsal-1".to_string(),
                remote_incident_url: Some(
                    "https://providence.local/incidents/prov-rehearsal-1".to_string(),
                ),
                remote_status: ProvidenceIncidentStatus::Investigating,
                remote_severity: Severity::Critical,
                swarm_status: ProvidenceIncidentStatus::Open,
                swarm_severity: Severity::Critical,
                remote_updated_at_ms: 1_700_000_000_012,
                reconciled_at_ms: 1_700_000_000_013,
                outcome: ProvidenceReconciliationOutcome::ProvidenceAhead,
                needs_review: true,
                summary: "Providence status advanced beyond the local incident.".to_string(),
            }),
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        })
        .unwrap();
    let app = detect_http_router(state);

    let finding_response = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                "/v2/api/findings?hunt_id=evt-platform-rehearsal&finding_id=finding-evt-platform-rehearsal",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(finding_response.status(), StatusCode::OK);
    let finding_envelope: PlatformApiEnvelope<PlatformFindingSummary> =
        parse_json(finding_response).await;
    assert_eq!(finding_envelope.data.len(), 1);
    let finding = &finding_envelope.data[0];
    assert_eq!(
        finding.latest_rehearsal_bundle_id.as_deref(),
        Some("bundle:rehearsal:evt-platform-rehearsal:1700000000010")
    );
    assert_eq!(
        finding
            .latest_rehearsal
            .as_ref()
            .map(|preview| preview.rehearsal_id.as_str()),
        Some("rehearsal:evt-platform-rehearsal")
    );
    assert_eq!(
        finding.related_incident_id.as_deref(),
        Some("incident-rehearsal")
    );
    assert_eq!(
        finding
            .related_incident_providence_reconciliation
            .as_ref()
            .map(|reconciliation| reconciliation.outcome),
        Some(ProvidenceReconciliationOutcome::ProvidenceAhead)
    );

    let incident_response = app
        .oneshot(
            authorized_platform_api_request(
                "GET",
                "/v2/api/incidents?incident_id=incident-rehearsal&hunt_id=evt-platform-rehearsal",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(incident_response.status(), StatusCode::OK);
    let incident_envelope: PlatformApiEnvelope<PlatformIncidentSummary> =
        parse_json(incident_response).await;
    assert_eq!(incident_envelope.data.len(), 1);
    let incident = &incident_envelope.data[0];
    assert_eq!(
        incident.latest_rehearsal_hunt_id.as_deref(),
        Some("evt-platform-rehearsal")
    );
    assert_eq!(
        incident.latest_rehearsal_bundle_id.as_deref(),
        Some("bundle:rehearsal:evt-platform-rehearsal:1700000000010")
    );
    assert_eq!(
        incident
            .latest_rehearsal
            .as_ref()
            .map(|preview| preview.rollback.summary.as_str()),
        Some("Close the rehearsal escalation receipt.")
    );
}

#[tokio::test]
async fn platform_runtime_status_endpoint_returns_live_status_envelope() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    config.investigation.enabled = true;
    config.correlation.enabled = true;
    let agent_health = Arc::new(ArcSwap::from_pointee(vec![AgentHealthEntry {
        id: "whisker-primary".to_string(),
        role: AgentRole::Whisker,
        health: AgentHealth::Healthy,
    }]));
    let mut mode_state = SwarmModeState::new();
    mode_state.transition_to(
        SwarmMode::Alert,
        swarm_core::ThreatClass::Execution,
        1_700_000_000_000,
    );
    let mode_state = Arc::new(ArcSwap::from_pointee(mode_state));
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-status"), config)
            .unwrap()
            .with_agent_health(agent_health)
            .with_mode_state(mode_state),
    );

    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: PlatformApiEnvelope<PlatformRuntimeStatus> = parse_json(response).await;
    assert_eq!(body.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
    assert_eq!(body.data.len(), 1);
    assert!(body.cursor.is_none());
    assert_eq!(body.data[0].mode_state.current, SwarmMode::Alert);
    assert_eq!(body.data[0].degradation.level.as_str(), "detect_only");
    assert_eq!(body.data[0].agent_health.len(), 1);
    assert_eq!(body.data[0].detector.strategy, "suspicious_process_tree");
    assert!(body.data[0].anti_tamper.ready);
    assert!(body.data[0].async_lane.enabled);
    assert_eq!(body.data[0].async_lane.status.as_str(), "ok");
    assert!(body.data[0].async_lane.investigation_store_ready);
    assert!(body.data[0].async_lane.incident_store_ready);
}

#[tokio::test]
async fn platform_runtime_status_surfaces_anti_tamper_report() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-anti-tamper"), config)
            .unwrap()
            .with_anti_tamper_report(tampered_anti_tamper_report(false)),
    );

    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: PlatformApiEnvelope<PlatformRuntimeStatus> = parse_json(response).await;
    assert_eq!(body.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
    assert_eq!(body.data.len(), 1);
    assert_eq!(body.data[0].anti_tamper.status, "tampered");
    assert!(!body.data[0].anti_tamper.required);
    assert_eq!(
        body.data[0].anti_tamper.unexpected_library_loads,
        vec!["/tmp/rogue.so".to_string()]
    );
}

#[tokio::test]
async fn platform_runtime_status_surfaces_alert_tuning_recommendations() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let state = IngestState::from_config(temp_path("platform-alert-tuning"), config).unwrap();
    for (incident_id, hunt_id, host_id, false_positive, created_at_ms) in [
        (
            "incident-alert-a-1",
            "hunt-alert-a-1",
            "host-a",
            true,
            1_700_000_200_000,
        ),
        (
            "incident-alert-a-2",
            "hunt-alert-a-2",
            "host-a",
            true,
            1_700_000_200_100,
        ),
        (
            "incident-alert-b-1",
            "hunt-alert-b-1",
            "host-b",
            true,
            1_700_000_200_200,
        ),
        (
            "incident-alert-c-1",
            "hunt-alert-c-1",
            "host-c",
            false,
            1_700_000_200_300,
        ),
        (
            "incident-alert-d-1",
            "hunt-alert-d-1",
            "host-d",
            false,
            1_700_000_200_400,
        ),
    ] {
        seed_measured_incident(
            &state,
            incident_id,
            hunt_id,
            host_id,
            "suspicious_process_tree",
            false_positive,
            created_at_ms,
        );
    }
    let app = detect_http_router(state);

    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: PlatformApiEnvelope<PlatformRuntimeStatus> = parse_json(response).await;
    assert_eq!(body.schema_version, CURRENT_OPERATOR_API_SCHEMA_VERSION);
    let tuning = &body.data[0].alert_tuning;
    assert_eq!(tuning.recommendation_count, 2);
    assert!(tuning.recommendations.iter().any(|entry| {
        entry.host_id.as_deref() == Some("host-a") && entry.summary.contains("scoped exclusion")
    }));
    assert!(tuning.recommendations.iter().any(|entry| {
        entry.strategy_id.as_deref() == Some("suspicious_process_tree")
            && entry.summary.contains("thresholding")
    }));
}

#[tokio::test]
async fn platform_runtime_status_rejects_unsupported_schema_version_header() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-status-schema-version"), config).unwrap(),
    );

    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .header(crate::control::OPERATOR_API_SCHEMA_VERSION_HEADER, "99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = parse_json(response).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unsupported operator API schema version")
    );
}

#[tokio::test]
async fn platform_asset_posture_endpoint_returns_host_filtered_posture() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let state = IngestState::from_config(temp_path("platform-posture"), config).unwrap();

    let now = super::unix_timestamp_secs();
    let key_a = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let key_b = ed25519_dalek::SigningKey::from_bytes(&[43u8; 32]);
    let key_c = ed25519_dalek::SigningKey::from_bytes(&[44u8; 32]);
    seed_platform_host_deposit(&state, &key_a, "host-a", ThreatClass::Execution, 1.0, now).await;
    seed_platform_host_deposit(&state, &key_b, "host-a", ThreatClass::Execution, 1.0, now).await;
    seed_platform_host_deposit(&state, &key_c, "host-b", ThreatClass::Execution, 1.0, now).await;

    seed_platform_investigation_bundle(
        &state,
        "investigation:host-a",
        "hunt-host-a",
        "host-a",
        swarm_spine::InvestigationStatus::Running,
        1_700_000_000_100,
    );
    seed_platform_investigation_bundle(
        &state,
        "investigation:host-b",
        "hunt-host-b",
        "host-b",
        swarm_spine::InvestigationStatus::Queued,
        1_700_000_000_200,
    );

    seed_platform_replay_bundle(&state, "evt-host-a-1", "host-a", 1_700_000_000_001);
    seed_platform_replay_bundle(&state, "evt-host-b-1", "host-b", 1_700_000_000_002);

    let app = detect_http_router(state);
    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/assets/host-a/posture")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body: PlatformApiEnvelope<PlatformAssetPosture> = parse_json(response).await;
    assert_eq!(body.data.len(), 1);
    assert!(body.cursor.is_none());
    assert_eq!(body.data[0].host_id, "host-a");
    assert_eq!(body.data[0].escalation_level, SwarmMode::Alert);
    assert_eq!(body.data[0].active_investigations.len(), 1);
    assert_eq!(
        body.data[0].active_investigations[0].investigation_id,
        "investigation:host-a"
    );
    assert_eq!(body.data[0].recent_findings.len(), 1);
    assert_eq!(
        body.data[0].recent_findings[0].host_id.as_deref(),
        Some("host-a")
    );
    let execution = body.data[0]
        .threat_concentrations
        .iter()
        .find(|summary| summary.threat_class == ThreatClass::Execution)
        .unwrap();
    assert_eq!(execution.distinct_sources, 2);
    assert!(execution.total_strength >= 2.0);
}

#[tokio::test]
async fn demo_replay_endpoint_rejects_when_demo_mode_disabled() {
    let scenario_path = temp_path("demo-scenario-disabled");
    write_demo_scenario(&scenario_path);
    let app = detect_http_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/replay")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&demo_replay_request(&scenario_path)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let _ = fs::remove_file(scenario_path);
}

#[tokio::test]
async fn demo_replay_endpoint_injects_events_into_runtime_lane() {
    let scenario_path = temp_path("demo-scenario-live");
    write_demo_scenario(&scenario_path);
    let runtime_events = RuntimeEventBroadcaster::new(32);
    let mut runtime_rx = runtime_events.subscribe();
    let app = detect_http_router(demo_ingest_state().with_runtime_events(runtime_events));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/replay")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&demo_replay_request(&scenario_path)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_demo_replay_response(response).await;
    assert_eq!(body.scenario_name, "demo replay");
    assert_eq!(body.injected_events, 1);

    let mut observed = Vec::new();
    for _ in 0..8 {
        let event = tokio::time::timeout(Duration::from_millis(250), runtime_rx.recv())
            .await
            .unwrap()
            .unwrap();
        observed.push(event);
        let saw_started = observed.iter().any(|event| {
            matches!(
                event,
                RuntimeEvent::Replay {
                    phase: ReplayEventPhase::Started,
                    ..
                }
            )
        });
        let saw_completed = observed.iter().any(|event| {
            matches!(
                event,
                RuntimeEvent::Replay {
                    phase: ReplayEventPhase::Completed,
                    ..
                }
            )
        });
        let saw_ingest = observed.iter().any(|event| {
            matches!(
                event,
                RuntimeEvent::Ingest {
                    event_id,
                    accepted: true,
                    ..
                } if event_id == "evt-ingest-1"
            )
        });
        let saw_response = observed.iter().any(|event| {
            matches!(
                event,
                RuntimeEvent::ResponseExecution {
                    hunt_id,
                    response_kind,
                    ..
                } if hunt_id == "evt-ingest-1" && response_kind == "success"
            )
        });
        if saw_started && saw_completed && saw_ingest && saw_response {
            break;
        }
    }
    assert!(observed.iter().any(|event| matches!(
        event,
        RuntimeEvent::Replay {
            phase: ReplayEventPhase::Started,
            ..
        }
    )));
    assert!(observed.iter().any(|event| matches!(
        event,
        RuntimeEvent::Replay {
            phase: ReplayEventPhase::Completed,
            ..
        }
    )));
    assert!(observed.iter().any(|event| matches!(
        event,
        RuntimeEvent::Ingest {
            event_id,
            accepted: true,
            ..
        } if event_id == "evt-ingest-1"
    )));
    assert!(observed.iter().any(|event| matches!(
        event,
        RuntimeEvent::ResponseExecution {
            hunt_id,
            response_kind,
            ..
        } if hunt_id == "evt-ingest-1" && response_kind == "success"
    )));

    let _ = fs::remove_file(scenario_path);
}

#[tokio::test]
async fn human_gated_demo_replay_can_resume_and_export_proof() {
    unsafe {
        std::env::set_var("SWARM_EVIDENCE_SIGNING_KEY", "demo-proof-signing-key");
    }

    let scenario_path = temp_path("demo-scenario-human-gate");
    write_human_gate_demo_scenario(&scenario_path);
    let (state, harness) = live_demo_ingest_state();
    let operator_id = state.operator_id();
    let app = detect_http_router(state);

    let replay_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/demo/replay")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&demo_replay_request(&scenario_path)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay_body = parse_demo_replay_response(replay_response).await;

    let approval_sets = harness.list_approval_sets().unwrap();
    assert_eq!(approval_sets.total_count, 1);
    let approval_set_id = approval_sets.sets[0].set_id.clone();
    let approval_ledgers = harness.list_ledgers(Some(&approval_set_id)).unwrap();
    assert_eq!(approval_ledgers.total_count, 1);
    let approval_ledger_id = approval_ledgers.ledgers[0].ledger_id.clone();

    let voter = Ed25519Signer::from_secret_material("demo-operator-vote-key");
    let quorum = harness
        .append_vote(&approval_set_id, &operator_id, &voter)
        .unwrap();
    assert!(quorum.quorum_met);

    let verdict = harness
        .create_verdict(&approval_set_id, &approval_ledger_id)
        .unwrap();
    let receipt_pack = harness
        .export_receipt_pack(
            &verdict.report.verdict_id,
            "demo-proof-signer",
            "SWARM_EVIDENCE_SIGNING_KEY",
        )
        .unwrap();

    let resume_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/demo/approvals/{approval_set_id}/resume"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&DemoApprovalResumeRequest {
                        receipt_pack: receipt_pack.report.clone(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resume_response.status(), StatusCode::OK);
    let resume_body = parse_demo_approval_resume_response(resume_response).await;
    assert_eq!(resume_body.approval_set_id, approval_set_id);
    assert_eq!(resume_body.receipt_pack_id, receipt_pack.report.pack_id);
    assert_eq!(resume_body.response_kind, "success");

    let proof_response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/demo/proof?run_id={}", replay_body.run_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(proof_response.status(), StatusCode::OK);
    let proof = parse_demo_proof_response(proof_response).await;
    assert_eq!(proof.run_id, replay_body.run_id);
    assert_eq!(proof.signed_receipts.len(), 1);
    assert_eq!(
        proof.signed_receipts[0].pack_id,
        receipt_pack.report.pack_id
    );
    assert!(!proof.final_incident.incident_id.is_empty());
    assert!(
        proof
            .decision_timeline
            .iter()
            .any(|entry| entry.stage == "approval_paused")
    );
    assert!(
        proof
            .decision_timeline
            .iter()
            .any(|entry| entry.stage == "approval_resumed")
    );
    assert!(proof.merkle_leaves.len() >= 5);

    let _ = fs::remove_file(scenario_path);
}

#[tokio::test]
async fn demo_dashboard_snapshot_endpoint_reports_live_runtime_state() {
    let agent_health = Arc::new(ArcSwap::from_pointee(vec![AgentHealthEntry {
        id: "whisker-primary".to_string(),
        role: AgentRole::Whisker,
        health: AgentHealth::Healthy,
    }]));
    let mut mode_state = SwarmModeState::new();
    mode_state.transition_to(
        SwarmMode::Alert,
        swarm_core::ThreatClass::Execution,
        1_700_000,
    );
    let mode_state = Arc::new(ArcSwap::from_pointee(mode_state));

    let app = detect_http_router(
        demo_ingest_state()
            .with_agent_health(agent_health)
            .with_mode_state(mode_state),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/demo/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "*"
    );
    let body = parse_demo_dashboard_response(response).await;
    assert_eq!(body.mode_state.current, SwarmMode::Alert);
    assert_eq!(body.agent_health.len(), 1);
    assert_eq!(body.agent_health[0].id, "whisker-primary");
    assert_eq!(body.concentrations.len(), 12);
}

#[tokio::test]
async fn demo_widget_endpoint_sets_embed_headers_and_renders_scoped_context() {
    let mut config = test_config("suspicious_process_tree");
    config.runtime.demo_mode = true;
    config.operator.runtime_base_url = "http://127.0.0.1:9090".to_string();
    config.operator.allowed_embed_origins = vec!["https://providence.example".to_string()];
    config.operator.auth.context_token_env = "SWARM_OPERATOR_WIDGET_TEST_TOKEN".to_string();
    unsafe {
        std::env::set_var(
            "SWARM_OPERATOR_WIDGET_TEST_TOKEN",
            "widget-context-secret-material",
        );
    }
    let token = crate::providence::mint_providence_context_token(
        &config.operator,
        crate::providence::ProvidenceContextScope {
            incident_id: None,
            hunt_id: Some("evt-widget-1".to_string()),
            finding_id: Some("finding-evt-widget-1".to_string()),
            strategy_id: Some("suspicious_process_tree".to_string()),
            threat_class: Some(ThreatClass::Execution),
        },
        now_ms(),
    )
    .unwrap();
    let app =
        detect_http_router(IngestState::from_config(temp_path("demo-widget"), config).unwrap());
    let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/v1/demo/widget?context_token={token}&hunt_id=evt-widget-1&finding_id=finding-evt-widget-1&strategy_id=suspicious_process_tree&threat_class=execution"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap(),
        "frame-ancestors 'self' https://providence.example"
    );
    assert_eq!(
        response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
        "ALLOW-FROM https://providence.example"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("Providence Context Widget"));
    assert!(body.contains("/v1/demo/dashboard"));
    assert!(body.contains("/v1/events/stream"));
    assert!(body.contains(&token));
    assert!(body.contains(r#"huntId: "evt-widget-1""#));
    assert!(body.contains(r#"findingId: "finding-evt-widget-1""#));
    assert!(body.contains(r#"strategyId: "suspicious_process_tree""#));
    assert!(body.contains(r#"threatClass: "execution""#));
}

#[tokio::test]
async fn providence_webhook_payload_includes_runtime_context_and_links() {
    let (target_url, capture, shutdown_tx, handle) = spawn_notification_capture_server().await;
    let mut config = test_config("suspicious_process_tree");
    config.operator.runtime_base_url = "http://127.0.0.1:9090".to_string();
    config.operator.public_base_url = "http://127.0.0.1:7766".to_string();
    config.operator.auth.context_token_env = "SWARM_PROVIDENCE_LINK_TEST_TOKEN".to_string();
    unsafe {
        std::env::set_var(
            "SWARM_PROVIDENCE_LINK_TEST_TOKEN",
            "providence-link-secret-material",
        );
    }
    config.notification_channels.insert(
        "providence_webhook".to_string(),
        NotificationChannelConfig {
            target_url: format!("{target_url}incidents"),
            auth_token: Some("providence-api-bearer".to_string()),
            request_signature: Some(swarm_core::config::RequestSignatureConfig {
                header: "X-Swarm-Signature".to_string(),
                secret: "shared-providence-secret".to_string(),
            }),
            timeout_ms: 500,
            rate_limit: NotificationRateLimitConfig {
                max_notifications: 5,
                window_ms: 60_000,
            },
            quiet_hours: None,
            dead_letter_path: temp_path("providence-webhook-dead-letter")
                .display()
                .to_string(),
        },
    );
    config.notification_routing = NotificationRoutingConfig {
        dedup_window_ms: 1,
        rules: vec![RoutingRule {
            min_severity: Some(Severity::High),
            threat_class: Some(ThreatClass::Execution),
            utc_start_hour: None,
            utc_end_hour: None,
            channels: vec!["providence_webhook".to_string()],
        }],
    };

    let agent_health = Arc::new(ArcSwap::from_pointee(vec![
        AgentHealthEntry {
            id: "whisker-primary".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Healthy,
        },
        AgentHealthEntry {
            id: "tom-primary".to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Degraded,
        },
        AgentHealthEntry {
            id: "pounce-primary".to_string(),
            role: AgentRole::Pouncer,
            health: AgentHealth::Failed,
        },
    ]));
    let mut mode_state = SwarmModeState::new();
    mode_state.transition_to(SwarmMode::Alert, ThreatClass::Execution, 1_700_000_000_000);
    let mode_state = Arc::new(ArcSwap::from_pointee(mode_state));
    let bridge_health = bridge_health(vec![
        BridgeStatusSnapshot {
            name: "synthetic".to_string(),
            source_id: "bridge:synthetic".to_string(),
            ready: true,
            events_processed: 12,
            error_count: 0,
            lag_seconds: Some(0.2),
            last_error: None,
        },
        BridgeStatusSnapshot {
            name: "backup".to_string(),
            source_id: "bridge:backup".to_string(),
            ready: false,
            events_processed: 2,
            error_count: 1,
            lag_seconds: Some(5.0),
            last_error: Some("upstream timeout".to_string()),
        },
    ]);
    let (shutdown_watch_tx, _shutdown_watch_rx) = watch::channel(false);
    let state = IngestState::from_config(temp_path("providence-inline"), config)
        .unwrap()
        .with_agent_health(agent_health)
        .with_mode_state(mode_state)
        .with_bridge_health(bridge_health)
        .with_shutdown_channel(shutdown_watch_tx);
    state
        .current_incident_store()
        .persist(&CorrelatedIncident {
            incident_id: "incident-providence-1".to_string(),
            summary: "correlated Providence incident".to_string(),
            created_at_ms: 1_700_000_000_001,
            window_start_ms: 1_700_000_000_000,
            window_end_ms: 1_700_000_000_001,
            correlation_keys: vec!["host:host-a".to_string()],
            related_receipt_ids: vec!["receipt-a".to_string()],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: "investigation-a".to_string(),
                hunt_id: "evt-ingest-1".to_string(),
                finding_id: "finding-a".to_string(),
                reason: "shared host".to_string(),
                shared_keys: vec!["host:host-a".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("evt-ingest-1".to_string()),
            trigger_finding_id: Some("finding-a".to_string()),
            trigger_strategy_id: Some("suspicious_process_tree".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::Critical),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        })
        .unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;

    let payloads = capture.payloads.lock().await.clone();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["schema"], "swarm_providence_webhook");
    assert_eq!(payloads[0]["schema_version"], 1);
    assert_eq!(
        payloads[0]["finding"]["schema"],
        "swarm_correlated_incident"
    );
    assert_eq!(payloads[0]["create_incident"]["severity"], "CRITICAL");
    assert_eq!(
        payloads[0]["incident_key"],
        "suspicious_process_tree:execution:finding-a"
    );
    assert_eq!(payloads[0]["runtime"]["mode"], "alert");
    assert_eq!(payloads[0]["runtime"]["registered_agent_count"], 3);
    assert_eq!(payloads[0]["runtime"]["active_agent_count"], 2);
    assert_eq!(payloads[0]["runtime"]["degraded_agent_count"], 1);
    assert_eq!(payloads[0]["runtime"]["failed_agent_count"], 1);
    assert_eq!(
        payloads[0]["runtime"]["bridge_health"]["status"],
        "degraded"
    );
    let dashboard = payloads[0]["links"]["dashboard"].as_str().unwrap();
    assert!(dashboard.starts_with("http://127.0.0.1:9090/v1/demo/widget?"));
    assert_eq!(
        query_value(dashboard, "hunt_id").as_deref(),
        Some("evt-ingest-1")
    );
    assert_eq!(
        query_value(dashboard, "finding_id").as_deref(),
        Some("finding-a")
    );
    assert_eq!(
        query_value(dashboard, "strategy_id").as_deref(),
        Some("suspicious_process_tree")
    );
    assert_eq!(
        query_value(dashboard, "threat_class").as_deref(),
        Some("execution")
    );
    let dashboard_token = query_value(dashboard, "context_token").unwrap();
    let claims = crate::providence::verify_providence_context_token(
        "providence-link-secret-material",
        &dashboard_token,
        now_ms(),
    )
    .unwrap();
    assert_eq!(claims.scope.hunt_id.as_deref(), Some("evt-ingest-1"));
    assert_eq!(claims.scope.finding_id.as_deref(), Some("finding-a"));
    assert_eq!(
        claims.scope.strategy_id.as_deref(),
        Some("suspicious_process_tree")
    );
    assert_eq!(claims.scope.threat_class, Some(ThreatClass::Execution));
    let event_stream = payloads[0]["links"]["event_stream"].as_str().unwrap();
    assert!(event_stream.starts_with("http://127.0.0.1:9090/v1/events/stream?"));
    assert_eq!(
        query_value(event_stream, "types").as_deref(),
        Some(
            "agent_action,response_execution,concentration_snapshot,escalation,mode_transition,finding"
        )
    );
    assert_eq!(
        query_value(event_stream, "context_token").as_deref(),
        Some(dashboard_token.as_str())
    );
    let finding_drilldown = payloads[0]["links"]["finding_drilldown"].as_str().unwrap();
    assert!(finding_drilldown.starts_with("http://127.0.0.1:9090/v2/api/findings?"));
    assert_eq!(
        query_value(finding_drilldown, "context_token").as_deref(),
        Some(dashboard_token.as_str())
    );
    assert_eq!(
        query_value(finding_drilldown, "finding_id").as_deref(),
        Some("finding-a")
    );
    assert_eq!(
        query_value(finding_drilldown, "hunt_id").as_deref(),
        Some("evt-ingest-1")
    );
    assert_eq!(
        query_value(finding_drilldown, "strategy_id").as_deref(),
        Some("suspicious_process_tree")
    );
    assert_eq!(
        payloads[0]["links"]["replay_bundle"],
        "http://127.0.0.1:7766/v1/operator/replay?hunt_id=evt-ingest-1"
    );
    assert_eq!(
        payloads[0]["links"]["audit_trail"],
        "http://127.0.0.1:7766/v1/operator/review?hunt_id=evt-ingest-1&incident_id=incident-providence-1"
    );
    let incident = payloads[0]["links"]["incident"].as_str().unwrap();
    assert!(incident.starts_with("http://127.0.0.1:9090/v2/api/incidents?"));
    assert_eq!(
        query_value(incident, "context_token").as_deref(),
        Some(dashboard_token.as_str())
    );
    assert_eq!(
        query_value(incident, "hunt_id").as_deref(),
        Some("evt-ingest-1")
    );
    assert_eq!(
        payloads[0]["links"]["review_home"],
        "http://127.0.0.1:7766/v1/operator/review?hunt_id=evt-ingest-1&incident_id=incident-providence-1"
    );
    assert_eq!(
        capture.auth.lock().await.clone(),
        Some("Bearer providence-api-bearer".to_string())
    );
    assert_eq!(
        capture.signature.lock().await.clone(),
        Some(format!(
            "sha256={}",
            swarm_crypto::hmac_sha256_hex(
                b"shared-providence-secret",
                &swarm_crypto::canonical_json_bytes(&payloads[0]).unwrap()
            )
        ))
    );
    assert!(
        payloads[0]["create_incident"]["description"]
            .as_str()
            .unwrap()
            .contains("incident-providence-1")
    );

    let _ = shutdown_tx.send(());
    handle.abort();
}

#[tokio::test]
async fn events_stream_filters_scoped_runtime_events_for_widget_context() {
    let broadcaster = RuntimeEventBroadcaster::new(16);
    let publisher = broadcaster.clone();
    let app = detect_http_router(demo_ingest_state().with_runtime_events(broadcaster.clone()));
    let publish_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        publisher.publish(RuntimeEvent::AgentAction {
            emitted_at_ms: now_ms(),
            agent_id: "weaver-primary".to_string(),
            role: AgentRole::Weaver,
            action_kind: "publish_findings".to_string(),
            hunt_id: Some("evt-widget-1".to_string()),
            details: json!({"finding_count": 1, "strategy_id": "suspicious_process_tree"}),
        });
        publisher.publish(RuntimeEvent::AgentAction {
            emitted_at_ms: now_ms(),
            agent_id: "weaver-secondary".to_string(),
            role: AgentRole::Weaver,
            action_kind: "publish_findings".to_string(),
            hunt_id: Some("evt-widget-2".to_string()),
            details: json!({"finding_count": 1, "strategy_id": "suspicious_process_tree"}),
        });
        publisher.publish(RuntimeEvent::ResponseExecution {
            emitted_at_ms: now_ms(),
            agent_id: "pounce-primary".to_string(),
            hunt_id: "evt-widget-1".to_string(),
            action_kind: "block_egress".to_string(),
            response_kind: "success".to_string(),
            policy_verdict: swarm_policy::PolicyVerdict::Allow,
            rule_name: "demo.allow".to_string(),
            reason: "allowed".to_string(),
            receipt_id: Some("receipt-widget-1".to_string()),
            governing_agent_id: None,
            error: None,
        });
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/events/stream?types=agent_action,response_execution&hunt_id=evt-widget-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    drop(broadcaster);
    publish_task.await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = tokio::time::timeout(
        Duration::from_secs(1),
        to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .unwrap()
    .unwrap();
    let stream = String::from_utf8(body.to_vec()).unwrap();
    assert!(stream.contains("event: agent_action"));
    assert!(stream.contains("event: response_execution"));
    assert!(stream.contains("\"hunt_id\":\"evt-widget-1\""));
    assert!(!stream.contains("\"hunt_id\":\"evt-widget-2\""));
}

mod providence_callback {
    use super::*;
    use crate::providence::PROVIDENCE_CHANNEL;
    use swarm_core::types::{
        ProvidenceCallbackEvent, ProvidenceIncidentStatus, ProvidenceReconciliationOutcome,
        SwarmProvidenceCallbackRequest,
    };
    use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};

    const CALLBACK_SECRET: &str = "providence-callback-secret";
    const CALLBACK_HEADER: &str = "X-Swarm-Signature";

    fn configure_callback_channel(config: &mut SwarmConfig) {
        config.notification_channels.insert(
            PROVIDENCE_CHANNEL.to_string(),
            NotificationChannelConfig {
                target_url: "http://127.0.0.1:65535/incidents".to_string(),
                auth_token: None,
                request_signature: Some(swarm_core::config::RequestSignatureConfig {
                    header: CALLBACK_HEADER.to_string(),
                    secret: CALLBACK_SECRET.to_string(),
                }),
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: super::temp_path("providence-callback-dead")
                    .display()
                    .to_string(),
            },
        );
    }

    fn callback_signature(payload: &SwarmProvidenceCallbackRequest) -> String {
        let payload = serde_json::to_value(payload).unwrap();
        format!(
            "sha256={}",
            hmac_sha256_hex(
                CALLBACK_SECRET.as_bytes(),
                &canonical_json_bytes(&payload).unwrap()
            )
        )
    }

    fn signed_callback_request(payload: &SwarmProvidenceCallbackRequest) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/providence/callback")
            .header("content-type", "application/json")
            .header(CALLBACK_HEADER, callback_signature(payload))
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    fn seed_callback_incident(state: &IngestState, incident_id: &str) {
        state
            .current_incident_store()
            .persist(&CorrelatedIncident {
                incident_id: incident_id.to_string(),
                summary: "callback incident".to_string(),
                created_at_ms: 1_700_130_000_000,
                window_start_ms: 1_700_130_000_000,
                window_end_ms: 1_700_130_000_100,
                correlation_keys: vec!["host:host-callback".to_string()],
                related_receipt_ids: vec!["receipt-callback".to_string()],
                included_members: vec![swarm_spine::IncidentMemberDecision {
                    investigation_id: "investigation-callback".to_string(),
                    hunt_id: "evt-callback".to_string(),
                    finding_id: "finding-callback".to_string(),
                    reason: "callback fixture".to_string(),
                    shared_keys: vec!["host:host-callback".to_string()],
                    evidence_links: Vec::new(),
                    confidence_score: 1.0,
                }],
                rejected_members: Vec::new(),
                graph_dimensions: Vec::new(),
                confidence_score: 1.0,
                trigger_event_id: Some("evt-callback".to_string()),
                trigger_finding_id: Some("finding-callback".to_string()),
                trigger_strategy_id: Some("suspicious_process_tree".to_string()),
                threat_class: Some(ThreatClass::Execution),
                severity: Some(Severity::High),
                external_references: Vec::new(),
                providence_reconciliation: None,
                providence_callback_audit_entries: Vec::new(),
                feedback_audit_entries: Vec::new(),
                false_positive_measurements: Vec::new(),
            })
            .unwrap();
    }

    #[tokio::test]
    async fn callback_endpoint_persists_reconciliation_and_surfaces_it_in_platform_incidents() {
        let mut config = super::test_config("suspicious_process_tree");
        enable_platform_api(&mut config);
        configure_callback_channel(&mut config);
        let mode_state = Arc::new(ArcSwap::from_pointee({
            let mut state = SwarmModeState::new();
            state.current = SwarmMode::Alert;
            state.last_transition_at = Some(1_700_130_000_050);
            state.triggering_threat_class = Some(ThreatClass::Execution);
            state
        }));
        let state = IngestState::from_config(super::temp_path("providence-callback"), config)
            .unwrap()
            .with_mode_state(mode_state);
        seed_callback_incident(&state, "incident-callback");
        let app = detect_http_router(state.clone());

        let request = SwarmProvidenceCallbackRequest {
            event: ProvidenceCallbackEvent::Resolved,
            incident_key: "suspicious_process_tree:execution:finding-callback".to_string(),
            remote_incident_id: "prov-incident-1".to_string(),
            remote_incident_url: Some(
                "https://providence.example/incidents/prov-incident-1".to_string(),
            ),
            incident_id: Some("incident-callback".to_string()),
            status: ProvidenceIncidentStatus::Resolved,
            severity: Severity::High,
            updated_at_ms: 1_700_130_000_200,
            note: Some("resolved remotely".to_string()),
        };

        let response = app
            .clone()
            .oneshot(signed_callback_request(&request))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-callback")
            .unwrap()
            .unwrap();
        let reconciliation = lookup.incident.providence_reconciliation.unwrap();
        assert_eq!(
            reconciliation.outcome,
            ProvidenceReconciliationOutcome::ProvidenceAhead
        );
        assert!(reconciliation.needs_review);
        assert_eq!(reconciliation.remote_incident_id, "prov-incident-1");
        assert_eq!(lookup.incident.providence_callback_audit_entries.len(), 1);
        assert_eq!(lookup.incident.external_references[0].id, "prov-incident-1");

        let incidents = app
            .oneshot(
                authorized_platform_api_request(
                    "GET",
                    "/v2/api/incidents?incident_id=incident-callback",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(incidents.status(), StatusCode::OK);
        let incidents: PlatformApiEnvelope<PlatformIncidentSummary> = parse_json(incidents).await;
        assert_eq!(incidents.data.len(), 1);
        let surfaced = incidents.data[0]
            .providence_reconciliation
            .as_ref()
            .unwrap();
        assert_eq!(
            surfaced.outcome,
            ProvidenceReconciliationOutcome::ProvidenceAhead
        );
        assert!(surfaced.needs_review);
    }
}

mod providence_feedback {
    use super::*;
    use crate::drafting::EvolutionValidationBundleStatus;
    use crate::evolution::{EvolutionProposalProofStatus, EvolutionProposalReviewState};
    use crate::kitten_agent::load_feedback_signal_records;
    use crate::mutation::{
        EvolutionPopulationCandidate, EvolutionPopulationFitnessObjectives,
        EvolutionPopulationState, FileEvolutionPopulationStore,
    };
    use crate::providence::PROVIDENCE_CHANNEL;
    use swarm_core::types::{AgentId, ProvidenceFeedbackAction, SwarmProvidenceFeedbackRequest};
    use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};
    use swarm_pheromone::DepositSigningPayload;

    const FEEDBACK_SECRET: &str = "providence-feedback-secret";
    const FEEDBACK_HEADER: &str = "X-Swarm-Signature";

    fn temp_dir(label: &str) -> PathBuf {
        let dir = super::temp_path(label).with_extension("dir");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn configure_feedback_channel(config: &mut SwarmConfig) {
        config.notification_channels.insert(
            PROVIDENCE_CHANNEL.to_string(),
            NotificationChannelConfig {
                target_url: "http://127.0.0.1:65535/incidents".to_string(),
                auth_token: None,
                request_signature: Some(swarm_core::config::RequestSignatureConfig {
                    header: FEEDBACK_HEADER.to_string(),
                    secret: FEEDBACK_SECRET.to_string(),
                }),
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: super::temp_path("providence-feedback-dead")
                    .display()
                    .to_string(),
            },
        );
    }

    fn feedback_signature(payload: &SwarmProvidenceFeedbackRequest) -> String {
        let payload = serde_json::to_value(payload).unwrap();
        format!(
            "sha256={}",
            hmac_sha256_hex(
                FEEDBACK_SECRET.as_bytes(),
                &canonical_json_bytes(&payload).unwrap()
            )
        )
    }

    fn signed_feedback_request(payload: &SwarmProvidenceFeedbackRequest) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/providence/feedback")
            .header("content-type", "application/json")
            .header(FEEDBACK_HEADER, feedback_signature(payload))
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    fn seed_feedback_incident(
        state: &IngestState,
        incident_id: &str,
        event_id: &str,
        host_id: &str,
        strategy_id: &str,
        created_at_ms: i64,
    ) {
        state
            .current_incident_store()
            .persist(&CorrelatedIncident {
                incident_id: incident_id.to_string(),
                summary: format!("feedback incident for {event_id}"),
                created_at_ms,
                window_start_ms: created_at_ms,
                window_end_ms: created_at_ms + 1,
                correlation_keys: vec![format!("host:{host_id}")],
                related_receipt_ids: vec![format!("receipt-{event_id}")],
                included_members: vec![swarm_spine::IncidentMemberDecision {
                    investigation_id: format!("investigation-{event_id}"),
                    hunt_id: event_id.to_string(),
                    finding_id: format!("finding-{event_id}"),
                    reason: "feedback fixture".to_string(),
                    shared_keys: vec![format!("host:{host_id}")],
                    evidence_links: Vec::new(),
                    confidence_score: 1.0,
                }],
                rejected_members: Vec::new(),
                graph_dimensions: Vec::new(),
                confidence_score: 1.0,
                trigger_event_id: Some(event_id.to_string()),
                trigger_finding_id: Some(format!("finding-{event_id}")),
                trigger_strategy_id: Some(strategy_id.to_string()),
                threat_class: Some(ThreatClass::Execution),
                severity: Some(Severity::High),
                external_references: Vec::new(),
                providence_reconciliation: None,
                providence_callback_audit_entries: Vec::new(),
                feedback_audit_entries: Vec::new(),
                false_positive_measurements: Vec::new(),
            })
            .unwrap();
    }

    async fn seed_feedback_deposit(
        state: &IngestState,
        _agent_label: &str,
        event_id: &str,
        host_id: &str,
        confidence: f64,
        timestamp: i64,
    ) {
        let agent_id = AgentId::from_verifying_key(&state.signing_key.verifying_key());
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: json!({
                "event_id": event_id,
                "host_id": host_id,
                "source": "synthetic",
                "evidence": {
                    "host_metadata": {
                        "host_id": host_id,
                    }
                }
            }),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: agent_id.clone(),
            agent_identity: agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
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
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = state.signing_key.sign(&payload_bytes);
        deposit.signature = signature.to_bytes().to_vec();
        deposit.agent_key = state.signing_key.verifying_key().to_bytes().to_vec();
        state.current_substrate().deposit(deposit).await.unwrap();
    }

    fn persist_population_candidate(root: &Path, strategy_id: &str, fitness: f64) {
        let store = FileEvolutionPopulationStore::open(root).unwrap();
        store
            .persist(&EvolutionPopulationState {
                updated_at_ms: 1_800_900_000_000,
                ranking_id: "ranking-feedback".to_string(),
                validation_batch_id: "validation-feedback".to_string(),
                population_size: 4,
                pareto_tournament_size: 2,
                proposal_timestamps_ms: Vec::new(),
                members: vec![EvolutionPopulationCandidate {
                    generation: 1,
                    generation_created_at_ms: 1_800_900_000_000,
                    population_rank: 1,
                    pareto_front: 1,
                    ranking_id: "ranking-feedback".to_string(),
                    validation_batch_id: "validation-feedback".to_string(),
                    variant_id: "variant-feedback".to_string(),
                    strategy_id: strategy_id.to_string(),
                    materialization_id: "materialization-feedback".to_string(),
                    validation_bundle_id: "validation-feedback".to_string(),
                    experiment_id: "experiment-feedback".to_string(),
                    verification_id: "verification-feedback".to_string(),
                    ready_for_review: true,
                    status: EvolutionValidationBundleStatus::ReadyForQueue,
                    proof_status: EvolutionProposalProofStatus::Proved,
                    queue_review_state: Some(EvolutionProposalReviewState::PendingReview),
                    advisory_recommendation: None,
                    blocking_reason_names: Vec::new(),
                    ranking_score: fitness,
                    baseline_fitness: None,
                    fitness,
                    evasion_pressure: None,
                    autonomous_fitness: None,
                    proposed_at_ms: None,
                    objectives: EvolutionPopulationFitnessObjectives {
                        detection_rate: 0.95,
                        false_positive_cost: 0.05,
                        speed: 0.8,
                        threat_class_coverage: 1.0,
                    },
                    summary: "feedback candidate".to_string(),
                }],
            })
            .unwrap();
    }

    #[tokio::test]
    async fn signed_feedback_endpoint_persists_audit_entry() {
        let mut config = super::test_config("suspicious_process_tree");
        configure_feedback_channel(&mut config);
        let state = IngestState::from_config(super::temp_path("feedback-audit"), config).unwrap();
        super::seed_platform_replay_bundle(
            &state,
            "evt-feedback-audit",
            "host-feedback-audit",
            1_700_100_000_000,
        );
        seed_feedback_incident(
            &state,
            "incident-feedback-audit",
            "evt-feedback-audit",
            "host-feedback-audit",
            "suspicious_process_tree",
            1_700_100_000_000,
        );

        let app = detect_http_router(state.clone());
        let payload = SwarmProvidenceFeedbackRequest {
            action: ProvidenceFeedbackAction::Dismiss,
            incident_id: "incident-feedback-audit".to_string(),
            finding_id: Some("finding-evt-feedback-audit".to_string()),
            analyst_id: "analyst-a".to_string(),
            reason: Some("false positive".to_string()),
        };
        let response = app
            .oneshot(signed_feedback_request(&payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-feedback-audit")
            .unwrap()
            .unwrap();
        assert_eq!(lookup.incident.feedback_audit_entries.len(), 1);
        let entry = &lookup.incident.feedback_audit_entries[0];
        assert_eq!(entry.action, ProvidenceFeedbackAction::Dismiss);
        assert_eq!(entry.analyst_id, "analyst-a");
        assert_eq!(
            entry.finding_id.as_deref(),
            Some("finding-evt-feedback-audit")
        );
        assert_eq!(entry.request_signature, feedback_signature(&payload));
        assert_eq!(
            entry
                .evidence
                .as_ref()
                .map(|evidence| evidence.schema.as_str()),
            Some(swarm_core::types::SWARM_PROVIDENCE_FEEDBACK_SCHEMA)
        );
        assert!(
            entry
                .evidence
                .as_ref()
                .is_some_and(|evidence| !evidence.signature_hex.is_empty())
        );
        assert_eq!(entry.payload["incident_id"], "incident-feedback-audit");
        assert_eq!(entry.payload["analyst_id"], "analyst-a");
        assert_eq!(entry.outcome["substrate"]["status"], "suppressed");
        assert_eq!(entry.outcome["memory"]["disposition"], "audit_only");
        assert_eq!(entry.outcome["kitten"]["disposition"], "pending");
    }

    #[tokio::test]
    async fn feedback_actions_translate_into_runtime_side_effects() {
        let mut config = super::test_config("suspicious_process_tree");
        configure_feedback_channel(&mut config);
        config.investigation.enabled = true;
        let state = IngestState::from_config(super::temp_path("feedback-actions"), config).unwrap();

        super::seed_platform_replay_bundle(
            &state,
            "evt-feedback-confirm",
            "host-confirm",
            1_700_110_000_000,
        );
        super::seed_platform_replay_bundle(
            &state,
            "evt-feedback-dismiss",
            "host-dismiss",
            1_700_110_000_100,
        );
        super::seed_platform_replay_bundle(
            &state,
            "evt-feedback-investigate",
            "host-investigate",
            1_700_110_000_200,
        );
        seed_feedback_incident(
            &state,
            "incident-feedback-confirm",
            "evt-feedback-confirm",
            "host-confirm",
            "suspicious_process_tree",
            1_700_110_000_000,
        );
        seed_feedback_incident(
            &state,
            "incident-feedback-dismiss",
            "evt-feedback-dismiss",
            "host-dismiss",
            "suspicious_process_tree",
            1_700_110_000_100,
        );
        seed_feedback_incident(
            &state,
            "incident-feedback-investigate",
            "evt-feedback-investigate",
            "host-investigate",
            "suspicious_process_tree",
            1_700_110_000_200,
        );
        seed_feedback_deposit(
            &state,
            "seed-confirm",
            "evt-feedback-confirm",
            "host-confirm",
            0.40,
            1_700_110_000_000,
        )
        .await;
        seed_feedback_deposit(
            &state,
            "seed-dismiss",
            "evt-feedback-dismiss",
            "host-dismiss",
            0.90,
            1_700_110_000_100,
        )
        .await;

        let before_confirm = state
            .current_substrate()
            .query_concentration(&ThreatClass::Execution, super::now_ms())
            .await
            .unwrap()
            .total_strength;

        let app = detect_http_router(state.clone());
        let confirm = app
            .clone()
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Confirm,
                incident_id: "incident-feedback-confirm".to_string(),
                finding_id: Some("finding-evt-feedback-confirm".to_string()),
                analyst_id: "analyst-confirm".to_string(),
                reason: Some("confirmed malicious".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(confirm.status(), StatusCode::OK);

        let after_confirm = state
            .current_substrate()
            .query_concentration(&ThreatClass::Execution, super::now_ms())
            .await
            .unwrap()
            .total_strength;
        assert!(after_confirm > before_confirm);

        let dismiss = app
            .clone()
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident-feedback-dismiss".to_string(),
                finding_id: Some("finding-evt-feedback-dismiss".to_string()),
                analyst_id: "analyst-dismiss".to_string(),
                reason: Some("benign admin action".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(dismiss.status(), StatusCode::OK);

        let suppressed = state
            .current_substrate()
            .query_concentration(&ThreatClass::Execution, super::now_ms())
            .await
            .unwrap()
            .total_strength;
        assert!(suppressed < after_confirm);

        let investigate = app
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Investigate,
                incident_id: "incident-feedback-investigate".to_string(),
                finding_id: Some("finding-evt-feedback-investigate".to_string()),
                analyst_id: "analyst-investigate".to_string(),
                reason: Some("need deeper context".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(investigate.status(), StatusCode::OK);

        let lookup = state
            .current_investigation_store()
            .load_by_hunt_id("evt-feedback-investigate")
            .unwrap()
            .unwrap();
        assert_eq!(lookup.record.hunt_id, "evt-feedback-investigate");
    }

    #[tokio::test]
    async fn feedback_persists_false_positive_measurements_and_surfaces_runtime_rollups() {
        let mut config = super::test_config("suspicious_process_tree");
        enable_platform_api(&mut config);
        configure_feedback_channel(&mut config);
        let state =
            IngestState::from_config(super::temp_path("feedback-measurements"), config).unwrap();

        super::seed_platform_replay_bundle(
            &state,
            "evt-feedback-measure-dismiss",
            "host-dismiss",
            1_700_110_100_000,
        );
        super::seed_platform_replay_bundle(
            &state,
            "evt-feedback-measure-confirm",
            "host-confirm",
            1_700_110_100_100,
        );
        seed_feedback_incident(
            &state,
            "incident-feedback-measure-dismiss",
            "evt-feedback-measure-dismiss",
            "host-dismiss",
            "suspicious_process_tree",
            1_700_110_100_000,
        );
        seed_feedback_incident(
            &state,
            "incident-feedback-measure-confirm",
            "evt-feedback-measure-confirm",
            "host-confirm",
            "suspicious_process_tree",
            1_700_110_100_100,
        );

        let app = detect_http_router(state.clone());
        let dismiss = app
            .clone()
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident-feedback-measure-dismiss".to_string(),
                finding_id: Some("finding-evt-feedback-measure-dismiss".to_string()),
                analyst_id: "analyst-dismiss".to_string(),
                reason: Some("dismissed as benign".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(dismiss.status(), StatusCode::OK);

        let confirm = app
            .clone()
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Confirm,
                incident_id: "incident-feedback-measure-confirm".to_string(),
                finding_id: Some("finding-evt-feedback-measure-confirm".to_string()),
                analyst_id: "analyst-confirm".to_string(),
                reason: Some("confirmed malicious".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(confirm.status(), StatusCode::OK);

        let dismiss_lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-feedback-measure-dismiss")
            .unwrap()
            .unwrap();
        assert_eq!(dismiss_lookup.incident.false_positive_measurements.len(), 1);
        let dismiss_measurement = &dismiss_lookup.incident.false_positive_measurements[0];
        assert_eq!(dismiss_measurement.strategy_id, "suspicious_process_tree");
        assert_eq!(dismiss_measurement.host_id.as_deref(), Some("host-dismiss"));
        assert_eq!(
            dismiss_measurement.action,
            ProvidenceFeedbackAction::Dismiss
        );
        assert!(dismiss_measurement.false_positive);

        let confirm_lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-feedback-measure-confirm")
            .unwrap()
            .unwrap();
        assert_eq!(confirm_lookup.incident.false_positive_measurements.len(), 1);
        let confirm_measurement = &confirm_lookup.incident.false_positive_measurements[0];
        assert_eq!(confirm_measurement.host_id.as_deref(), Some("host-confirm"));
        assert_eq!(
            confirm_measurement.action,
            ProvidenceFeedbackAction::Confirm
        );
        assert!(!confirm_measurement.false_positive);

        let response = app
            .oneshot(
                authorized_platform_api_request("GET", "/v2/api/runtime/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: PlatformApiEnvelope<PlatformRuntimeStatus> = parse_json(response).await;
        let tracking = &body.data[0].false_positive_tracking;
        assert_eq!(tracking.reviewed_findings, 2);
        assert_eq!(tracking.false_positive_findings, 1);
        assert_eq!(tracking.false_positive_rate, 0.5);
        let detector = tracking
            .detectors
            .iter()
            .find(|entry| entry.strategy_id == "suspicious_process_tree")
            .unwrap();
        assert_eq!(detector.reviewed_findings, 2);
        assert_eq!(detector.false_positive_findings, 1);
        let dismiss_host = tracking
            .hosts
            .iter()
            .find(|entry| entry.host_id == "host-dismiss")
            .unwrap();
        assert_eq!(dismiss_host.reviewed_findings, 1);
        assert_eq!(dismiss_host.false_positive_findings, 1);
        let confirm_host = tracking
            .hosts
            .iter()
            .find(|entry| entry.host_id == "host-confirm")
            .unwrap();
        assert_eq!(confirm_host.reviewed_findings, 1);
        assert_eq!(confirm_host.false_positive_findings, 0);
    }

    #[tokio::test]
    async fn dismiss_feedback_reaches_kitten_or_pending_fallback() {
        let applied_root = temp_dir("feedback-applied");
        let mut applied_config = super::test_config("suspicious_process_tree");
        configure_feedback_channel(&mut applied_config);
        applied_config.evolution.enabled = true;
        applied_config
            .evolution
            .paths
            .evolution_population_results_dir =
            applied_root.join("population").display().to_string();
        let kitten_health = Arc::new(ArcSwap::from_pointee(vec![AgentHealthEntry {
            id: "kitten-primary".to_string(),
            role: AgentRole::Kitten,
            health: AgentHealth::Healthy,
        }]));
        let applied_state =
            IngestState::from_config(super::temp_path("feedback-applied"), applied_config)
                .unwrap()
                .with_agent_health(kitten_health);
        super::seed_platform_replay_bundle(
            &applied_state,
            "evt-feedback-applied",
            "host-applied",
            1_700_120_000_000,
        );
        seed_feedback_incident(
            &applied_state,
            "incident-feedback-applied",
            "evt-feedback-applied",
            "host-applied",
            "suspicious_process_tree",
            1_700_120_000_000,
        );
        persist_population_candidate(
            &applied_root.join("population"),
            "suspicious_process_tree",
            0.80,
        );

        let applied_app = detect_http_router(applied_state.clone());
        let applied_response = applied_app
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident-feedback-applied".to_string(),
                finding_id: Some("finding-evt-feedback-applied".to_string()),
                analyst_id: "analyst-applied".to_string(),
                reason: Some("known false positive".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(applied_response.status(), StatusCode::OK);
        let applied_json: Value = super::parse_json(applied_response).await;
        assert_eq!(applied_json["outcome"]["kitten"]["disposition"], "applied");

        let population = FileEvolutionPopulationStore::open(applied_root.join("population"))
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(population.members[0].fitness < 0.80);
        assert!(
            population.members[0]
                .blocking_reason_names
                .iter()
                .any(|reason| reason == "analyst_false_positive_feedback")
        );

        let pending_root = temp_dir("feedback-pending");
        let mut pending_config = super::test_config("suspicious_process_tree");
        configure_feedback_channel(&mut pending_config);
        pending_config.evolution.enabled = true;
        pending_config
            .evolution
            .paths
            .evolution_population_results_dir =
            pending_root.join("population").display().to_string();
        let pending_state =
            IngestState::from_config(super::temp_path("feedback-pending"), pending_config).unwrap();
        super::seed_platform_replay_bundle(
            &pending_state,
            "evt-feedback-pending",
            "host-pending",
            1_700_120_000_100,
        );
        seed_feedback_incident(
            &pending_state,
            "incident-feedback-pending",
            "evt-feedback-pending",
            "host-pending",
            "suspicious_process_tree",
            1_700_120_000_100,
        );

        let pending_app = detect_http_router(pending_state.clone());
        let pending_response = pending_app
            .oneshot(signed_feedback_request(&SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident-feedback-pending".to_string(),
                finding_id: Some("finding-evt-feedback-pending".to_string()),
                analyst_id: "analyst-pending".to_string(),
                reason: Some("kitten offline".to_string()),
            }))
            .await
            .unwrap();
        assert_eq!(pending_response.status(), StatusCode::OK);
        let pending_json: Value = super::parse_json(pending_response).await;
        assert_eq!(pending_json["outcome"]["kitten"]["disposition"], "pending");

        let pending_records =
            load_feedback_signal_records(pending_root.join("population")).unwrap();
        assert!(
            pending_records.iter().any(|record| record.disposition
                == crate::kitten_agent::FeedbackSignalDisposition::Pending)
        );
    }
}

#[tokio::test]
async fn process_runtime_event_publishes_finding_runtime_events() {
    let broadcaster = RuntimeEventBroadcaster::new(16);
    let mut receiver = broadcaster.subscribe();
    let state = test_ingest_state().with_runtime_events(broadcaster);
    let event = validate_and_parse(valid_process_event_json()).unwrap();

    super::process_runtime_event(
        &state,
        &swarm_core::types::AgentId("ingest".to_string()),
        "corr-findings",
        event,
    )
    .await
    .unwrap();

    let mut saw_finding = None;
    for _ in 0..3 {
        let event = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        if let RuntimeEvent::Finding {
            host_id, finding, ..
        } = event
        {
            saw_finding = Some((host_id, finding));
            break;
        }
    }

    let (host_id, finding) = saw_finding.expect("finding runtime event");
    assert_eq!(host_id.as_deref(), Some("host-1"));
    assert_eq!(finding.event_id, "evt-ingest-1");
    assert_eq!(finding.schema, "swarm_finding");
}

#[tokio::test]
async fn platform_findings_stream_endpoint_emits_canonical_finding_events() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let broadcaster = RuntimeEventBroadcaster::new(16);
    let publisher = broadcaster.clone();
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-stream"), config)
            .unwrap()
            .with_runtime_events(broadcaster.clone()),
    );
    let publish_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        publisher.publish(RuntimeEvent::AgentAction {
            emitted_at_ms: now_ms(),
            agent_id: "weaver-primary".to_string(),
            role: AgentRole::Weaver,
            action_kind: "publish_findings".to_string(),
            hunt_id: Some("evt-ingest-1".to_string()),
            details: json!({"finding_count": 1}),
        });
        publisher.publish(RuntimeEvent::Finding {
            emitted_at_ms: now_ms(),
            host_id: Some("host-stream".to_string()),
            finding: SwarmFindingEnvelope {
                schema: "swarm_finding".to_string(),
                finding_id: "finding-stream-1".to_string(),
                event_id: "evt-stream-1".to_string(),
                strategy_id: "suspicious_process_tree".to_string(),
                threat_class: ThreatClass::Execution,
                severity: Severity::Critical,
                confidence: 0.98,
                evidence: json!({"host_id": "host-stream"}),
            },
        });
    });
    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/stream/findings?host_id=host-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    drop(broadcaster);
    publish_task.await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let body = tokio::time::timeout(
        Duration::from_secs(1),
        to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .unwrap()
    .unwrap();
    let stream = String::from_utf8(body.to_vec()).unwrap();
    assert!(stream.contains("event: finding"));
    assert!(stream.contains("\"finding_id\":\"finding-stream-1\""));
    assert!(!stream.contains("event: agent_action"));
}

#[tokio::test]
async fn events_stream_filters_typed_runtime_events() {
    let broadcaster = RuntimeEventBroadcaster::new(16);
    let publisher = broadcaster.clone();
    let app = detect_http_router(test_ingest_state().with_runtime_events(broadcaster.clone()));
    let publish_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        publisher.publish(RuntimeEvent::ConcentrationSnapshot {
            emitted_at_ms: now_ms(),
            current_mode: SwarmMode::Normal,
            concentrations: vec![],
        });
        publisher.publish(RuntimeEvent::AgentAction {
            emitted_at_ms: now_ms(),
            agent_id: "weaver-primary".to_string(),
            role: AgentRole::Weaver,
            action_kind: "publish_findings".to_string(),
            hunt_id: Some("evt-ingest-1".to_string()),
            details: json!({"finding_count": 1}),
        });
        publisher.publish(RuntimeEvent::ResponseExecution {
            emitted_at_ms: now_ms(),
            agent_id: "pounce-primary".to_string(),
            hunt_id: "evt-ingest-1".to_string(),
            action_kind: "block_egress".to_string(),
            response_kind: "success".to_string(),
            policy_verdict: swarm_policy::PolicyVerdict::Allow,
            rule_name: "demo.allow".to_string(),
            reason: "allowed".to_string(),
            receipt_id: Some("receipt-1".to_string()),
            governing_agent_id: None,
            error: None,
        });
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/events/stream?types=agent_action")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    drop(broadcaster);
    publish_task.await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let body = tokio::time::timeout(
        Duration::from_secs(1),
        to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .unwrap()
    .unwrap();
    let stream = String::from_utf8(body.to_vec()).unwrap();
    assert!(stream.contains("event: agent_action"));
    assert!(stream.contains("\"action_kind\":\"publish_findings\""));
    assert!(!stream.contains("event: response_execution"));
}

#[tokio::test]
async fn events_stream_can_filter_evolution_status_events() {
    let broadcaster = RuntimeEventBroadcaster::new(16);
    let publisher = broadcaster.clone();
    let app = detect_http_router(test_ingest_state().with_runtime_events(broadcaster.clone()));
    let report = crate::evolution_status::DefaultEvolutionStatusHarness::from_config(
        "inline",
        test_config("suspicious_process_tree"),
    )
    .unwrap()
    .status()
    .unwrap();
    let publish_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(25)).await;
        publisher.publish(RuntimeEvent::EvolutionStatus {
            emitted_at_ms: now_ms(),
            source: "test".to_string(),
            status: report,
        });
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/events/stream?types=evolution_status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    drop(broadcaster);
    publish_task.await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = tokio::time::timeout(
        Duration::from_secs(1),
        to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .unwrap()
    .unwrap();
    let stream = String::from_utf8(body.to_vec()).unwrap();
    assert!(stream.contains("event: evolution_status"));
    assert!(stream.contains("\"generation_count\":0"));
    assert!(!stream.contains("event: agent_action"));
}

#[tokio::test]
async fn healthz_returns_ok_with_component_status() {
    let app = detect_http_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["components"]["response"]["adapter"], "sandbox");
}

#[tokio::test]
async fn handler_forwards_accepted_events_to_agent_buffer() {
    let (tx, mut rx) = mpsc::channel(4);
    let app = ingest_router(test_ingest_state().with_telemetry_channel(tx));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let forwarded = rx.recv().await.unwrap();
    assert_eq!(forwarded.event_id, "evt-ingest-1");
}

#[tokio::test]
async fn healthz_includes_agent_component_when_available() {
    let health = Arc::new(ArcSwap::from_pointee(vec![AgentHealthEntry {
        id: "whisker-primary".to_string(),
        role: AgentRole::Whisker,
        health: AgentHealth::Healthy,
    }]));
    let app = detect_http_router(test_ingest_state().with_agent_health(health));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["agents"]["status"], "ok");
    assert_eq!(
        json["components"]["agents"]["entries"][0]["id"],
        "whisker-primary"
    );
}

#[tokio::test]
async fn healthz_includes_async_lane_component_when_enabled() {
    let mut config = test_config("suspicious_process_tree");
    config.investigation.enabled = true;
    config.correlation.enabled = true;
    let app =
        detect_http_router(IngestState::from_config(temp_path("healthz-async"), config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["async_lane"]["status"], "ok");
    assert_eq!(json["components"]["async_lane"]["enabled"], true);
    assert_eq!(
        json["components"]["async_lane"]["investigation_enabled"],
        true
    );
    assert_eq!(
        json["components"]["async_lane"]["correlation_enabled"],
        true
    );
}

#[tokio::test]
async fn healthz_includes_governance_partition_component() {
    let governance_policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig {
        contingency_lease_ttl_ms: 60_000,
        contingency_blast_radius_cap: 1,
    }));
    governance_policy.register_governor(
        AgentId::new("tom", "primary"),
        ed25519_dalek::SigningKey::from_bytes(&[29; 32]),
    );
    governance_policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "tom-primary".to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }],
        1_700_000_000_000,
    );

    let app = detect_http_router(test_ingest_state().with_governance_policy(governance_policy));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["governance"]["status"], "partitioned");
    assert_eq!(json["components"]["governance"]["quorum_threshold"], 1);
    assert_eq!(
        json["components"]["governance"]["active_contingency_leases"],
        0
    );
}

#[tokio::test]
async fn healthz_includes_bridge_component_without_failing_core_readiness() {
    let bridges = bridge_health(vec![
        BridgeStatusSnapshot {
            name: "cloudtrail-primary".to_string(),
            source_id: "cloudtrail".to_string(),
            ready: true,
            events_processed: 2,
            error_count: 0,
            lag_seconds: Some(4.0),
            last_error: None,
        },
        BridgeStatusSnapshot {
            name: "tetragon-primary".to_string(),
            source_id: "tetragon".to_string(),
            ready: false,
            events_processed: 5,
            error_count: 1,
            lag_seconds: Some(12.0),
            last_error: Some("stream closed".to_string()),
        },
    ]);
    let app = detect_http_router(test_ingest_state().with_bridge_health(bridges));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["components"]["bridges"]["status"], "degraded");
    assert_eq!(json["components"]["bridges"]["configured"], 2);
    assert_eq!(json["components"]["bridges"]["degraded"], 1);
    assert_eq!(
        json["components"]["bridges"]["entries"][1]["name"],
        "tetragon-primary"
    );
}

#[tokio::test]
async fn healthz_includes_providence_component_when_configured() {
    let (target_url, shutdown_tx, handle) =
        spawn_providence_health_server(StatusCode::METHOD_NOT_ALLOWED).await;
    let mut config = test_config("suspicious_process_tree");
    config.notification_channels.insert(
        "providence_webhook".to_string(),
        NotificationChannelConfig {
            target_url,
            auth_token: Some("providence-api-bearer".to_string()),
            request_signature: None,
            timeout_ms: 500,
            rate_limit: NotificationRateLimitConfig::default(),
            quiet_hours: None,
            dead_letter_path: temp_path("providence-health").display().to_string(),
        },
    );
    let app = detect_http_router(
        IngestState::from_config(temp_path("providence-health"), config).unwrap(),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["providence"]["status"], "ok");
    assert_eq!(json["components"]["providence"]["authenticated"], true);
    assert_eq!(json["components"]["providence"]["accepting_writes"], true);

    let _ = shutdown_tx.send(());
    handle.abort();
}

#[tokio::test]
async fn readyz_reports_providence_auth_failure() {
    let (target_url, shutdown_tx, handle) =
        spawn_providence_health_server(StatusCode::UNAUTHORIZED).await;
    let mut config = test_config("suspicious_process_tree");
    config.notification_channels.insert(
        "providence_webhook".to_string(),
        NotificationChannelConfig {
            target_url,
            auth_token: Some("providence-api-bearer".to_string()),
            request_signature: None,
            timeout_ms: 500,
            rate_limit: NotificationRateLimitConfig::default(),
            quiet_hours: None,
            dead_letter_path: temp_path("providence-readyz").display().to_string(),
        },
    );
    let app = detect_http_router(
        IngestState::from_config(temp_path("providence-readyz"), config).unwrap(),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["providence"]["status"], "auth_failed");
    assert_eq!(json["components"]["providence"]["authenticated"], false);
    assert_eq!(json["components"]["providence"]["ready"], false);

    let _ = shutdown_tx.send(());
    handle.abort();
}

#[tokio::test]
async fn readyz_reports_jetstream_unreachable_detect_only_transition() {
    let mut config = live_response_config("suspicious_process_tree");
    config.pheromone.backend = PheromoneBackendConfig::JetStream {
        url: "nats://127.0.0.1:65535".to_string(),
        connect_timeout_ms: 10,
        gc_page_size: 64,
    };
    let app = detect_http_router(
        IngestState::from_config(temp_path("jetstream-down-readyz"), config)
            .unwrap()
            .with_startup_attestation(verified_startup_attestation_report()),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["components"]["substrate"]["backend"], "jetstream");
    assert_eq!(json["components"]["substrate"]["ready"], false);
    assert_eq!(json["components"]["degradation"]["level"], "detect_only");
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["allows_live_response"],
        false
    );
}

#[tokio::test]
async fn readyz_reports_replay_store_write_failure_read_only_transition() {
    let replay_root = temp_path("replay-store-read-only").with_extension("dir");
    let mut config = live_response_config("suspicious_process_tree");
    config.audit.bundle_store = BundleStoreConfig::LocalFiles {
        directory: replay_root.display().to_string(),
    };
    let state = IngestState::from_config(temp_path("replay-store-read-only-config"), config)
        .unwrap()
        .with_startup_attestation(verified_startup_attestation_report());
    let bundles_dir = replay_root.join("bundles");
    fs::remove_dir_all(&bundles_dir).unwrap();
    fs::write(&bundles_dir, b"blocked").unwrap();
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "degraded");
    assert_eq!(json["components"]["replay_store"]["ready"], false);
    assert_eq!(json["components"]["degradation"]["level"], "read_only");
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["accepts_ingest"],
        false
    );
}

#[tokio::test]
async fn replay_store_write_failure_rejects_new_ingest_requests() {
    let replay_root = temp_path("replay-store-ingest").with_extension("dir");
    let mut config = live_response_config("suspicious_process_tree");
    config.audit.bundle_store = BundleStoreConfig::LocalFiles {
        directory: replay_root.display().to_string(),
    };
    let state = IngestState::from_config(temp_path("replay-store-ingest-config"), config)
        .unwrap()
        .with_startup_attestation(verified_startup_attestation_report());
    let bundles_dir = replay_root.join("bundles");
    fs::remove_dir_all(&bundles_dir).unwrap();
    fs::write(&bundles_dir, b"blocked").unwrap();
    let app = ingest_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|value| value.contains("read_only"))
    );
}

#[tokio::test]
async fn readyz_reports_detector_degradation() {
    let app = detect_http_router(degraded_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "degraded");
    assert_eq!(json["components"]["detector"]["ready"], false);
    assert_eq!(json["components"]["degradation"]["level"], "read_only");
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["accepts_ingest"],
        false
    );
}

#[tokio::test]
async fn livez_returns_ok_when_detector_is_degraded() {
    let app = detect_http_router(degraded_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/livez")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["components"]["detector"]["ready"], false);
}

#[tokio::test]
async fn startupz_returns_ok_for_valid_state() {
    let app = detect_http_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/startupz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["checks"]["schema_version"]["loaded"], 1);
}

#[tokio::test]
async fn readyz_surfaces_telemetry_source_summary() {
    let app = detect_http_router(test_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["telemetry_sources"]["configured"], 1);
    assert_eq!(json["components"]["telemetry_sources"]["subject_backed"], 1);
    assert_eq!(json["components"]["telemetry_sources"]["bridge_backed"], 0);
    assert_eq!(
        json["components"]["telemetry_sources"]["status"],
        "configured"
    );
    assert_eq!(json["components"]["degradation"]["level"], "detect_only");
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["accepts_ingest"],
        true
    );
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["allows_live_response"],
        false
    );
}

#[tokio::test]
async fn startupz_surfaces_failed_attestation_without_blocking_detect_only() {
    let app = detect_http_router(
        test_ingest_state().with_startup_attestation(failed_startup_attestation_report()),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/startupz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["checks"]["startup_attestation"]["ready"], false);
    assert_eq!(json["checks"]["startup_attestation"]["required"], false);
    assert_eq!(
        json["checks"]["startup_attestation"]["effective_ready"],
        true
    );
}

#[tokio::test]
async fn startupz_reports_unsupported_schema_version() {
    let mut config = test_config("suspicious_process_tree");
    config.schema_version = CURRENT_SCHEMA_VERSION + 1;
    let app =
        detect_http_router(IngestState::from_config(temp_path("future-schema"), config).unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/startupz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["checks"]["schema_version"]["ready"], false);
}

#[tokio::test]
async fn readyz_requires_startup_attestation_for_live_response_mode() {
    let mut config = test_config("suspicious_process_tree");
    config.runtime.mode = RuntimeMode::LiveResponse;
    let state = IngestState::from_config(temp_path("attestation-readyz"), config)
        .unwrap()
        .with_startup_attestation(failed_startup_attestation_report());
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["startup_attestation"]["required"], true);
    assert_eq!(
        json["components"]["startup_attestation"]["effective_ready"],
        false
    );
    assert_eq!(
        json["components"]["startup_attestation"]["binary"]["status"],
        "failed"
    );
    assert_eq!(
        json["components"]["degradation"]["level"],
        "emergency_drain"
    );
}

#[tokio::test]
async fn readyz_requires_anti_tamper_when_live_response_fail_closed() {
    let mut config = test_config("suspicious_process_tree");
    config.runtime.mode = RuntimeMode::LiveResponse;
    config.runtime.anti_tamper.fail_closed_live_response = true;
    let state = IngestState::from_config(temp_path("anti-tamper-readyz"), config)
        .unwrap()
        .with_anti_tamper_report(tampered_anti_tamper_report(true));
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["anti_tamper"]["required"], true);
    assert_eq!(json["components"]["anti_tamper"]["effective_ready"], false);
    assert_eq!(json["components"]["anti_tamper"]["debugger_attached"], true);
    assert_eq!(json["components"]["anti_tamper"]["tracer_pid"], 77);
    assert_eq!(
        json["components"]["degradation"]["level"],
        "emergency_drain"
    );
}

#[tokio::test]
async fn readyz_reports_draining_state() {
    let state = test_ingest_state();
    state.begin_drain();
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "draining");
    assert_eq!(json["components"]["lifecycle"]["draining"], true);
    assert_eq!(
        json["components"]["degradation"]["level"],
        "emergency_drain"
    );
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["drains_ingest"],
        true
    );
}

#[tokio::test]
async fn draining_runtime_rejects_new_ingest_requests() {
    let state = test_ingest_state();
    state.begin_drain();
    let app = ingest_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|value| value.contains("draining"))
    );
}

#[tokio::test]
async fn read_only_degraded_runtime_rejects_new_ingest_requests() {
    let app = ingest_router(degraded_ingest_state());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![valid_process_event_json()]))
                        .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|value| value.contains("read_only"))
    );
}

#[tokio::test]
async fn prestop_waits_for_inflight_requests_and_requests_shutdown() {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let state = test_ingest_state().with_shutdown_channel(shutdown_tx);
    let guard = state.try_begin_ingest_request().unwrap();
    let app = detect_http_router(state);

    let releaser = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(guard);
    });

    let started = Instant::now();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/prestop")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    releaser.await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(started.elapsed() >= Duration::from_millis(40));
    shutdown_rx.changed().await.unwrap();
    assert!(*shutdown_rx.borrow());
}

#[tokio::test]
async fn readyz_reports_heap_pressure_degradation() {
    let app = detect_http_router(test_ingest_state().with_heap_snapshot_provider(|| {
        Some(HeapPressureSnapshot {
            bytes: 95,
            limit_bytes: 100,
            pressure_ratio: 0.95,
        })
    }));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["components"]["heap"]["ready"], false);
    assert_eq!(json["components"]["heap"]["pressure_ratio"], 0.95);
    assert_eq!(
        json["components"]["degradation"]["level"],
        "emergency_drain"
    );
}

#[tokio::test]
async fn readyz_reports_live_response_heap_pressure_emergency_drain_transition() {
    let state = IngestState::from_config(
        temp_path("heap-pressure-live-response"),
        live_response_config("suspicious_process_tree"),
    )
    .unwrap()
    .with_startup_attestation(verified_startup_attestation_report())
    .with_heap_snapshot_provider(|| {
        Some(HeapPressureSnapshot {
            bytes: 95,
            limit_bytes: 100,
            pressure_ratio: 0.95,
        })
    });
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "draining");
    assert_eq!(
        json["components"]["degradation"]["level"],
        "emergency_drain"
    );
    assert_eq!(
        json["components"]["degradation"]["capabilities"]["drains_ingest"],
        true
    );
}

#[tokio::test]
async fn metrics_include_heap_gauges() {
    let app = detect_http_router(test_ingest_state().with_heap_snapshot_provider(|| {
        Some(HeapPressureSnapshot {
            bytes: 4_096,
            limit_bytes: 8_192,
            pressure_ratio: 0.5,
        })
    }));
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let metrics = String::from_utf8(body.to_vec()).unwrap();
    assert!(metrics.contains("swarm_heap_bytes 4096"));
    assert!(metrics.contains("swarm_heap_pressure_ratio 0.5"));
}

#[tokio::test]
async fn metrics_include_evasion_coverage_gauges() {
    let app = detect_http_router(
        IngestState::from_config(
            repo_root().join("rulesets/default.yaml"),
            test_config("suspicious_process_tree"),
        )
        .unwrap(),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let metrics = String::from_utf8(body.to_vec()).unwrap();
    assert!(metrics.contains("swarm_evasion_catch_rate"));
    assert!(metrics.contains("suite=\"evasion_breadth_v1\""));
    assert!(metrics.contains("detector=\"fileless_execution\""));
    assert!(metrics.contains("threat_class=\"all\""));
}

fn test_config_with_secret_token(secret_dir: &Path) -> SwarmConfig {
    use swarm_core::config::{CircuitBreakerConfig, HttpEdrConfig, RetryConfig};
    SwarmConfig {
        response_adapter: ResponseAdapterConfig::HttpEdr {
            config: HttpEdrConfig {
                endpoint: "https://edr.example".to_string(),
                auth_token: "@secret:edr-token".to_string(),
                timeout_ms: 1_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        },
        runtime: swarm_core::config::RuntimeSettings {
            secret_dir: Some(secret_dir.display().to_string()),
            ..test_config("suspicious_process_tree").runtime
        },
        ..test_config("suspicious_process_tree")
    }
}

#[test]
fn reload_secrets_only_updates_auth_token() {
    let tmp = std::env::temp_dir().join(format!(
        "swarm-secrets-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("edr-token"), "initial-value\n").unwrap();

    // Pass the unresolved config — from_config resolves internally
    // and stores the template with @secret: references intact.
    let config_path = temp_path("secrets-reload");
    let config = test_config_with_secret_token(&tmp);
    let state = IngestState::from_config(&config_path, config).unwrap();

    // Verify initial value was resolved on construction
    let stack = state.stack.load_full();
    match &stack.service.config.response_adapter {
        ResponseAdapterConfig::HttpEdr { config: edr } => {
            assert_eq!(edr.auth_token, "initial-value");
        }
        other => panic!("expected HttpEdr, got {:?}", other),
    }
    drop(stack);

    // Rotate the secret on disk and reload secrets only
    fs::write(tmp.join("edr-token"), "rotated-value\n").unwrap();
    state.reload_secrets_only().unwrap();

    // Verify the rotated value is visible in the active stack
    let stack = state.stack.load_full();
    match &stack.service.config.response_adapter {
        ResponseAdapterConfig::HttpEdr { config: edr } => {
            assert_eq!(edr.auth_token, "rotated-value");
        }
        other => panic!("expected HttpEdr after reload, got {:?}", other),
    }

    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::remove_file(config_path);
}

#[test]
fn reload_secrets_only_preserves_detector_strategy() {
    let tmp = std::env::temp_dir().join(format!(
        "swarm-secrets-strategy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("edr-token"), "some-token\n").unwrap();

    let config_path = temp_path("secrets-strategy");
    let config = test_config_with_secret_token(&tmp);
    let state = IngestState::from_config(&config_path, config).unwrap();
    let strategy_before = state.detector_strategy_name();

    fs::write(tmp.join("edr-token"), "new-token\n").unwrap();
    state.reload_secrets_only().unwrap();

    let strategy_after = state.detector_strategy_name();
    assert_eq!(
        strategy_before, strategy_after,
        "detector strategy must not change after secrets-only reload"
    );

    let _ = fs::remove_dir_all(&tmp);
    let _ = fs::remove_file(config_path);
}

#[test]
fn reload_secrets_only_does_not_read_config_yaml() {
    // Build state with a config path that does NOT exist on disk.
    // reload_secrets_only must succeed because it should NOT try
    // to re-read the YAML file — only re-resolve secrets.
    let tmp = std::env::temp_dir().join(format!(
        "swarm-secrets-nofile-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("edr-token"), "the-token\n").unwrap();

    // Pass unresolved config — from_config stores the template
    let config_path = temp_path("secrets-nofile");
    let config = test_config_with_secret_token(&tmp);
    let state = IngestState::from_config(&config_path, config).unwrap();

    // The config YAML file was never actually written, so reload_from_disk
    // would fail. reload_secrets_only works because it uses the stored
    // config template — no YAML file is read.
    fs::write(tmp.join("edr-token"), "fresh-token\n").unwrap();
    state.reload_secrets_only().unwrap();

    let stack = state.stack.load_full();
    match &stack.service.config.response_adapter {
        ResponseAdapterConfig::HttpEdr { config: edr } => {
            assert_eq!(edr.auth_token, "fresh-token");
        }
        other => panic!("expected HttpEdr, got {:?}", other),
    }

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn response_adapter_kind_maps_variants() {
    assert_eq!(
        response_adapter_kind(&ResponseAdapterConfig::Sandbox),
        "sandbox"
    );
    assert_eq!(
        response_adapter_kind(&ResponseAdapterConfig::HttpEdr {
            config: HttpEdrConfig {
                endpoint: "https://edr.example".to_string(),
                auth_token: "secret".to_string(),
                timeout_ms: 1_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        }),
        "http_edr"
    );
    assert_eq!(
        response_adapter_kind(&ResponseAdapterConfig::Webhook {
            config: WebhookConfig {
                url: "https://hooks.example".to_string(),
                timeout_ms: 1_000,
                channel: Some("#alerts".to_string()),
                auth_token: None,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        }),
        "webhook"
    );
}
