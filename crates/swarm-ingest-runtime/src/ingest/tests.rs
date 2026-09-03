use super::health::{HeapPressureSnapshot, response_adapter_kind};
use super::platform_api::{
    PlatformApiEnvelope, PlatformAssetPosture, PlatformFindingSummary, PlatformIncidentSummary,
    PlatformRuntimeStatus,
};
use super::{
    DemoDashboardSnapshot, DemoProofPackage, DemoReplayRequest, DemoReplayResponse, IngestRequest,
    IngestRequestError, IngestResponse, IngestState, StrategyProposalRoute, detect_http_router,
    ingest_router, validate_and_parse,
};
use crate::anti_tamper::AntiTamperReport;
use crate::bridge_runtime::SharedBridgeHealth;
use crate::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use arc_swap::ArcSwap;
use async_trait::async_trait;
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
use swarm_agents::tom_agent::{GovernanceDecision, GovernancePolicy, GovernancePolicyConfig};
use swarm_core::BridgeStatusSnapshot;
use swarm_core::ThreatClass;
use swarm_core::agent::AgentHealthEntry;
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmMode, SwarmModeState,
};
use swarm_core::config::{
    AuditConfig, BundleStoreConfig, CanaryConfig, CircuitBreakerConfig, CorrelationConfig,
    DetectionConfig, DetectorProfilesConfig, HttpEdrConfig, InvestigationConfig,
    NotificationChannelConfig, NotificationRateLimitConfig, NotificationRoutingConfig,
    OperatorPrincipalConfig, OperatorScope, OperatorSurfaceConfig, PheromoneBackendConfig,
    PheromoneConfig, PlatformApiConfig, PlatformApiKeyConfig, PlatformApiScope,
    PolicyActionSelector, PolicyConfig, PolicyRuleConfig, PolicyRuleDecision, PromotionConfig,
    ResponseAdapterConfig, ResponsePlaybookRule, RetryConfig, RoutingRule, RuntimeAntiTamperConfig,
    RuntimeMode, RuntimeSettings, SecretString, SwarmConfig, TelemetrySourceConfig, WebhookConfig,
};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{
    AgentId, HuntId, ProvidenceIncidentReconciliation, ProvidenceIncidentStatus,
    ProvidenceReconciliationOutcome, ResponseAction, ResponseBlastRadiusImpact,
    ResponseBlastRadiusPreview, ResponseRehearsalPreview, ResponseRehearsalScopeKind,
    ResponseRollbackPreview, ResponseRollbackStep, ResponseRollbackStepKind, Severity, SwarmAction,
};
use swarm_crypto::Ed25519Signer;
use swarm_pheromone::PheromoneSubstrate;
use swarm_response::SwarmFindingEnvelope;
use swarm_runtime::StrategyProposalRouteError;
use swarm_runtime::approval::DefaultApprovalHarness;
use swarm_runtime::config::{CURRENT_SCHEMA_VERSION, write_debug_test_config_signature};
use swarm_runtime::dispatcher::{AgentDispatcher, AgentDispatcherConfig};
use swarm_runtime::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
use swarm_runtime::evasion_coverage::EvasionCoverageSnapshot;
use swarm_runtime::evolution::DefaultEvolutionProofHarness;
use swarm_runtime::mutation::{
    DefaultEvolutionMutationHarness, EvolutionMutationProfileOverrides,
    EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
};
use swarm_runtime::replay::{
    DefaultReplayHarness, ReplayScenarioClass, ReplayScenarioInput, ReplayScenarioManifest,
    ReplayScenarioMetadata, ReplayScenarioStep,
};
use swarm_runtime::runtime_events::{
    ReplayEventPhase, RuntimeEvent, RuntimeEventBroadcaster, now_ms,
};
use swarm_runtime::startup_attestation::{
    StartupAttestationComponentReport, StartupAttestationReport,
};
use swarm_runtime::strategy::DefaultStrategyScorecardHarness;
use swarm_spine::{
    CorrelatedIncident, FalsePositiveMeasurement, IncidentStore, InvestigationBundle,
    InvestigationBundleStore, ReplayBundleStore,
};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};
use tower::ServiceExt;

// Historical fixture timestamps remain deterministic while the configured runtime exercises the
// production, wall-clock-backed admission path. Keep their retention horizon long enough that the
// fixtures test ingest behavior instead of eventually expiring as the calendar advances.
const TEST_LIVE_HALF_LIFE_SECS: f64 = 3_153_600_000.0;

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

/// A throwaway store root for `test_config`.
///
/// Not created on disk: every harness that needs one calls `create_dir_all`
/// itself. Building the path lazily keeps `test_config` free of filesystem
/// side effects while still keeping the repo-relative defaults out of play.
fn test_config_store_root() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "swarm-runtime-ingest-config-{}-{nanos}",
        std::process::id()
    ))
}

fn test_config(strategy: &str) -> SwarmConfig {
    let mut config = SwarmConfig {
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
            threat_intel_feeds: vec![],
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
            containment: Default::default(),
        },
        detection: DetectionConfig {
            strategy: strategy.to_string(),
            strategies: Vec::new(),
            high_confidence_threshold: 0.9,
            medium_confidence_threshold: 0.7,
            profiles: DetectorProfilesConfig::default(),
        },
        pheromone: PheromoneConfig {
            default_half_life_secs: TEST_LIVE_HALF_LIFE_SECS,
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
        hypothesis_graph: Default::default(),
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
    };
    redirect_evolution_paths(&mut config, &test_config_store_root());
    config
}

const TEST_PLATFORM_API_KEY: &str = "platform-read-secret";
const TEST_PLATFORM_API_BEARER_TOKEN: &str = "platform-bearer-secret";
const TEST_PLATFORM_API_BEARER_TOKEN_ENV: &str = "SWARM_PLATFORM_API_TEST_TOKEN";
const TEST_PLATFORM_API_ROTATION_BEARER_TOKEN_ENV: &str = "SWARM_PLATFORM_API_ROTATION_TEST_TOKEN";

fn enable_platform_api(config: &mut SwarmConfig) {
    enable_platform_api_with_token_env(config, TEST_PLATFORM_API_BEARER_TOKEN_ENV);
}

fn enable_platform_api_with_token_env(config: &mut SwarmConfig, token_env: &str) {
    config.platform_api.keys = vec![PlatformApiKeyConfig {
        name: "test-reader".to_string(),
        key_hash: super::platform_api::platform_api_key_hash_hex(TEST_PLATFORM_API_KEY),
        scopes: vec![PlatformApiScope::Read],
    }];
    config.operator.auth.operator_id = "platform-api-test-operator".to_string();
    config.operator.auth.token_env = token_env.to_string();
    config.operator.auth.context_token_env = token_env.to_string();
    unsafe {
        std::env::set_var(token_env, TEST_PLATFORM_API_BEARER_TOKEN);
    }
}

fn enable_collective_hypothesis_graph(config: &mut SwarmConfig, directory: &Path) {
    config.investigation.enabled = true;
    config.correlation.enabled = true;
    config.audit.bundle_store = BundleStoreConfig::LocalFiles {
        directory: directory.join("replays").display().to_string(),
    };
    config.investigation.bundle_store = BundleStoreConfig::LocalFiles {
        directory: directory.join("investigations").display().to_string(),
    };
    config.correlation.incident_store = BundleStoreConfig::LocalFiles {
        directory: directory.join("incidents").display().to_string(),
    };
    config.hypothesis_graph.enabled = true;
    config.hypothesis_graph.state_store = BundleStoreConfig::LocalFiles {
        directory: directory.join("hypothesis-graph").display().to_string(),
    };
}

fn mint_platform_context_token(
    config: &SwarmConfig,
    scope: swarm_runtime::providence::ProvidenceContextScope,
) -> String {
    swarm_runtime::providence::mint_providence_context_token(&config.operator, scope, now_ms())
        .unwrap()
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

fn authorized_platform_api_request_from_source(
    method: &str,
    uri: impl Into<String>,
    source: &str,
) -> axum::http::request::Builder {
    let ip: std::net::IpAddr = source
        .parse()
        .expect("test source must parse as an IP address");
    let socket_addr = std::net::SocketAddr::new(ip, 0);
    authorized_platform_api_request(method, uri).extension(axum::extract::ConnectInfo(socket_addr))
}

fn process_event_json(event_id: &str, host_id: &str, timestamp: i64) -> Value {
    let mut event = valid_process_event_json();
    event["event_id"] = json!(event_id);
    event["host_id"] = json!(host_id);
    event["timestamp"] = json!(timestamp);
    event
}

fn platform_replay_bundle(
    event_id: &str,
    host_id: &str,
    created_at_ms: i64,
) -> swarm_spine::ReplayBundle {
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
    swarm_spine::ReplayBundle {
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
    }
}

fn seed_platform_replay_bundle(
    state: &IngestState,
    event_id: &str,
    host_id: &str,
    created_at_ms: i64,
) {
    let bundle = platform_replay_bundle(event_id, host_id, created_at_ms);
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
                soar_lineage: None,
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
        decay_half_life: TEST_LIVE_HALF_LIFE_SECS,
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
            graph_findings_published: false,
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

/// Copy an experiment manifest into `root`, rewriting its relative `../` corpus
/// and verification references to absolute paths in the checked-out tree.
///
/// Materialized mutation manifests are written NEXT TO their base experiment, so
/// a test that passes the checked-out `experiments/office-baseline-control.yaml`
/// as the base drops `mutation-*.yaml` into the repository's `experiments/`.
///
/// The corpora are ABSOLUTIZED rather than copied: `rulesets/safety/
/// office-detector-admission.yaml` pins the admission invariants to the
/// repository's `verifications/office-detector-safety-v1.yaml`, and a candidate
/// verified against a copy is rejected as a different corpus.
fn stage_experiment(root: &Path, source: &Path) -> PathBuf {
    let experiments_dir = root.join("experiments");
    fs::create_dir_all(&experiments_dir).unwrap();
    let destination = experiments_dir.join(source.file_name().unwrap());
    let source_dir = source.parent().unwrap();

    let raw = fs::read_to_string(source).unwrap();
    let mut manifest: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    for (section, key) in [("corpus", "suite"), ("verification", "corpus")] {
        let relative = manifest[section][key].as_str().unwrap().to_string();
        let absolute = source_dir.join(&relative).canonicalize().unwrap();
        manifest[section][key] = serde_yaml::Value::String(absolute.display().to_string());
    }
    fs::write(&destination, serde_yaml::to_string(&manifest).unwrap()).unwrap();
    destination
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
    redirect_evolution_paths(config, root);
}

/// Point every evolution store at `root`.
///
/// `EvolutionConfig::default()` leaves these on repo-relative `data/...`
/// defaults, and `resolve_repo_relative_path` degenerates those to cwd for an
/// inline config path -- i.e. the checked-out crate root. Any harness built
/// from such a config creates its store eagerly, so the default has to be
/// overwritten even by tests that never intend to read the store back.
fn redirect_evolution_paths(config: &mut SwarmConfig, root: &Path) {
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
    // The assurance harvest store is NOT under `evolution.paths`, so it is not
    // covered by the loop above. Left alone it resolves relative to the config
    // file -- which for a test pointed at the repo's own `rulesets/default.yaml`
    // means the harvester writes scenario YAML into `rulesets/data/`, dirtying the
    // working tree and breaking `repo_ruleset_attestation_matches_checked_in_files`.
    // The assurance harvest store is NOT under `evolution.paths`, so it is easy to
    // miss here; left on its repo-relative default it writes into the checked-out
    // crate root.
    config.evolution.assurance.harvest.results_dir =
        root.join("assurance-cases").display().to_string();
}

fn test_ingest_state() -> IngestState {
    IngestState::from_config(temp_path("inline"), test_config("suspicious_process_tree")).unwrap()
}

struct IngestOneShotGovernedRequestAgent {
    id: AgentId,
    verifying_key: ed25519_dalek::VerifyingKey,
    actions: Option<Vec<SwarmAction>>,
}

impl IngestOneShotGovernedRequestAgent {
    fn new(id: AgentId, actions: Vec<SwarmAction>) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[79; 32]);
        Self {
            id,
            verifying_key: signing_key.verifying_key(),
            actions: Some(actions),
        }
    }
}

#[async_trait]
impl SwarmAgent for IngestOneShotGovernedRequestAgent {
    fn identity(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        AgentRole::Pouncer
    }

    async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        Ok(self.actions.take().unwrap_or_default())
    }

    fn health(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}

fn governed_request_action(governance: &GovernancePolicy, suffix: &str) -> (AgentId, SwarmAction) {
    let pounce_id = AgentId::new("pounce", suffix);
    let hunt_id = HuntId(format!("hunt-governed-voter-{suffix}"));
    let action = ResponseAction::BlockEgress {
        target: format!("203.0.113.{}", suffix.len() + 10),
    };
    let mut evidence = json!({
        "lineage": {
            "hunt_id": hunt_id.0.clone(),
            "event_id": format!("event-governed-voter-{suffix}"),
        },
        "escalation": {
            "threat_class": ThreatClass::Execution,
            "severity": Severity::Critical,
            "confidence": 0.99,
        },
    });
    let request = swarm_policy::ActionRequest {
        hunt_id: hunt_id.clone(),
        requested_by: pounce_id.clone(),
        action: action.clone(),
        severity: Severity::Critical,
        evidence: evidence.clone(),
    };
    let GovernanceDecision::Authorize { receipt, .. } = governance.can_act(&request) else {
        panic!("healthy configured governance must authorize the exact request");
    };
    evidence["governance_receipt"] = serde_json::to_value(receipt).unwrap();
    (
        pounce_id,
        SwarmAction::RequestResponse {
            hunt_id,
            action,
            evidence,
        },
    )
}

#[test]
fn configured_approval_voters_use_effective_approve_principals_in_deterministic_order() {
    let legacy_signer = Ed25519Signer::from_secret_material("legacy-voter-must-not-widen");
    let first_signer = Ed25519Signer::from_secret_material("multi-principal-voter-first");
    let second_signer = Ed25519Signer::from_secret_material("multi-principal-voter-second");
    let legacy_id = format!("swarm:ed25519:{}", legacy_signer.public_key_hex());
    let first_id = format!("swarm:ed25519:{}", first_signer.public_key_hex());
    let second_id = format!("swarm:ed25519:{}", second_signer.public_key_hex());

    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.operator_id = legacy_id.clone();
    config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: second_id.clone(),
            token_env: "SWARM_APPROVAL_SECOND".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read, OperatorScope::Approve],
        },
        OperatorPrincipalConfig {
            operator_id: "read-only-principal".to_string(),
            token_env: "SWARM_APPROVAL_READ_ONLY".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read],
        },
        OperatorPrincipalConfig {
            operator_id: first_id.clone(),
            token_env: "SWARM_APPROVAL_FIRST".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
    ];

    let mut expected = vec![first_id, second_id];
    expected.sort();
    assert_eq!(
        super::configured_approval_voters(&config).unwrap(),
        expected
    );
    assert!(
        !super::configured_approval_voters(&config)
            .unwrap()
            .contains(&legacy_id)
    );
}

#[test]
fn configured_approval_voters_fail_closed_for_legacy_or_malformed_approvers() {
    let mut config = test_config("suspicious_process_tree");
    let legacy_signer = Ed25519Signer::from_secret_material("legacy-auth-id");
    let malformed_public_key_hex = "02".repeat(32);
    assert!(swarm_crypto::PublicKey::from_hex(&malformed_public_key_hex).is_err());
    config.operator.auth.operator_id = format!("swarm:ed25519:{}", legacy_signer.public_key_hex());
    config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: "operator-legacy-approver".to_string(),
            token_env: "SWARM_APPROVAL_LEGACY".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
        OperatorPrincipalConfig {
            operator_id: format!("swarm:ed25519:{malformed_public_key_hex}"),
            token_env: "SWARM_APPROVAL_MALFORMED".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
    ];

    assert!(matches!(
        super::configured_approval_voters(&config),
        Err(super::ApprovalVoterConfigError::NoEligibleApprover)
    ));
}

#[test]
fn configured_approval_voters_keep_canonical_legacy_fallback_when_principals_are_empty() {
    let signer = Ed25519Signer::from_secret_material("canonical-legacy-voter");
    let voter_id = format!("swarm:ed25519:{}", signer.public_key_hex());
    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.operator_id = voter_id.clone();
    config.operator.auth.principals.clear();

    assert_eq!(
        super::configured_approval_voters(&config).unwrap(),
        vec![voter_id]
    );
}

#[tokio::test]
async fn governed_router_uses_effective_voters_across_reload_and_fails_closed_without_one() {
    let root = temp_dir("governed-voter-router-reload");
    let config_path = root.join("swarm.yaml");
    let harness = DefaultApprovalHarness::from_path(
        &config_path,
        root.join("verdicts"),
        root.join("receipt-packs"),
        root.join("sets"),
        root.join("ledgers"),
    )
    .unwrap();
    let governance = Arc::new(
        GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            root.join("governance.json"),
            AgentId::new("tom", "governed-voter-router"),
            ed25519_dalek::SigningKey::from_bytes(&[91; 32]),
        )
        .unwrap(),
    );
    let governance_authority = governance
        .authority()
        .expect("healthy persisted governance should mint an authority");

    let legacy_signer = Ed25519Signer::from_secret_material("governed-voter-legacy");
    let first_signer = Ed25519Signer::from_secret_material("governed-voter-first");
    let second_signer = Ed25519Signer::from_secret_material("governed-voter-second");
    let first_id = format!("swarm:ed25519:{}", first_signer.public_key_hex());
    let second_id = format!("swarm:ed25519:{}", second_signer.public_key_hex());
    let legacy_id = format!("swarm:ed25519:{}", legacy_signer.public_key_hex());
    let mut initial_config = test_config("suspicious_process_tree");
    initial_config.runtime.mode = RuntimeMode::LiveResponse;
    initial_config.operator.auth.operator_id = legacy_id;
    initial_config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: second_id.clone(),
            token_env: "SWARM_GOVERNED_VOTER_SECOND".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read, OperatorScope::Approve],
        },
        OperatorPrincipalConfig {
            operator_id: "reader-only".to_string(),
            token_env: "SWARM_GOVERNED_VOTER_READER".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read],
        },
        OperatorPrincipalConfig {
            operator_id: first_id.clone(),
            token_env: "SWARM_GOVERNED_VOTER_FIRST".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
    ];
    let state = IngestState::from_config(&config_path, initial_config.clone())
        .unwrap()
        .with_approval_harness(harness.clone())
        .with_governance_authority(governance_authority.clone());
    let router = state.current_request_response_router();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        state.current_substrate(),
        Arc::new(ArcSwap::from_pointee(Vec::<AgentHealthEntry>::new())),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance_authority.clone());

    let (first_agent_id, first_action) = governed_request_action(&governance, "initial");
    dispatcher
        .register(Box::new(IngestOneShotGovernedRequestAgent::new(
            first_agent_id,
            vec![first_action],
        )))
        .unwrap();
    dispatcher.tick_once().await;

    let mut expected_initial = vec![first_id.clone(), second_id.clone()];
    expected_initial.sort();
    let initial_sets = harness.list_approval_sets().unwrap();
    assert_eq!(initial_sets.sets.len(), 1);
    let initial_report = harness
        .load_approval_set(&initial_sets.sets[0].set_id)
        .unwrap()
        .unwrap()
        .report;
    assert_eq!(initial_report.eligible_voters, expected_initial);
    assert_eq!(harness.list_ledgers(None).unwrap().total_count, 1);

    let rotated_signer = Ed25519Signer::from_secret_material("governed-voter-rotated");
    let rotated_id = format!("swarm:ed25519:{}", rotated_signer.public_key_hex());
    let rotated_legacy_signer =
        Ed25519Signer::from_secret_material("governed-voter-rotated-legacy");
    let mut rotated_config = initial_config;
    rotated_config.operator.auth.operator_id =
        format!("swarm:ed25519:{}", rotated_legacy_signer.public_key_hex());
    rotated_config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: rotated_id.clone(),
        token_env: "SWARM_GOVERNED_VOTER_ROTATED".to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Approve],
    }];
    state.reload(rotated_config.clone()).unwrap();

    let (rotated_agent_id, rotated_action) = governed_request_action(&governance, "rotated");
    dispatcher
        .register(Box::new(IngestOneShotGovernedRequestAgent::new(
            rotated_agent_id,
            vec![rotated_action],
        )))
        .unwrap();
    dispatcher.tick_once().await;

    let rotated_sets = harness.list_approval_sets().unwrap();
    assert_eq!(rotated_sets.sets.len(), 2);
    let rotated_reports = rotated_sets
        .sets
        .iter()
        .map(|record| {
            harness
                .load_approval_set(&record.set_id)
                .unwrap()
                .unwrap()
                .report
                .eligible_voters
        })
        .collect::<Vec<_>>();
    assert!(rotated_reports.contains(&expected_initial));
    assert!(rotated_reports.contains(&vec![rotated_id]));
    assert_eq!(harness.list_ledgers(None).unwrap().total_count, 2);

    let mut no_approver_config = rotated_config;
    no_approver_config.operator.auth.operator_id =
        format!("swarm:ed25519:{}", legacy_signer.public_key_hex());
    no_approver_config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: "legacy-approver-without-key".to_string(),
            token_env: "SWARM_GOVERNED_VOTER_INVALID_LEGACY".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
        OperatorPrincipalConfig {
            operator_id: format!("swarm:ed25519:{}", "02".repeat(32)),
            token_env: "SWARM_GOVERNED_VOTER_INVALID_KEY".to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
    ];
    state.reload(no_approver_config).unwrap();
    let (invalid_agent_id, invalid_action) = governed_request_action(&governance, "invalid");
    dispatcher
        .register(Box::new(IngestOneShotGovernedRequestAgent::new(
            invalid_agent_id,
            vec![invalid_action],
        )))
        .unwrap();
    dispatcher.tick_once().await;
    assert_eq!(harness.list_approval_sets().unwrap().sets.len(), 2);
    assert_eq!(harness.list_ledgers(None).unwrap().total_count, 2);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn configured_approval_voters_reject_noncanonical_public_key_identity() {
    let signer = Ed25519Signer::from_secret_material("uppercase-voter-id");
    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: format!(
            "swarm:ed25519:{}",
            signer.public_key_hex().to_ascii_uppercase()
        ),
        token_env: "SWARM_APPROVAL_UPPERCASE".to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Approve],
    }];

    assert!(matches!(
        super::configured_approval_voters(&config),
        Err(super::ApprovalVoterConfigError::NoEligibleApprover)
    ));
}

#[test]
fn demo_approval_keeps_legacy_operator_id_compatibility() {
    let mut config = test_config("suspicious_process_tree");
    config.runtime.demo_mode = true;
    config.operator.auth.operator_id = "demo-legacy-operator".to_string();
    let root = temp_dir("demo-legacy-approval-voter");
    let config_path = root.join("swarm.yaml");
    let harness = DefaultApprovalHarness::from_path(
        &config_path,
        root.join("verdicts"),
        root.join("receipt-packs"),
        root.join("sets"),
        root.join("ledgers"),
    )
    .unwrap();
    let state = IngestState::from_config(config_path, config)
        .unwrap()
        .with_approval_harness(harness.clone());
    state.begin_demo_run("demo-legacy-run", "demo", "inline", "operator", 0, 1);

    let finding = swarm_whisker::DetectionFinding {
        finding_id: "finding-demo-legacy".to_string(),
        event_id: "event-demo-legacy".to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.99,
        evidence: json!({"fixture": "demo-legacy-approval"}),
        strategy_id: "suspicious_process_tree".to_string(),
    };
    let request = swarm_policy::ActionRequest {
        hunt_id: HuntId("hunt-demo-legacy".to_string()),
        requested_by: AgentId::new("demo", "operator"),
        action: ResponseAction::IsolateHost {
            host_id: "host-demo-legacy".to_string(),
        },
        severity: Severity::High,
        evidence: json!({"fixture": "demo-legacy-approval"}),
    };
    let audit = swarm_spine::AuditTrail {
        trail_id: "trail-demo-legacy".to_string(),
        hunt_id: request.hunt_id.0.clone(),
        related_receipt_ids: Vec::new(),
        detection: finding,
        policy: swarm_spine::PolicyRecord {
            verdict: swarm_policy::PolicyVerdict::RequireHuman,
            rule_name: "demo.test.human".to_string(),
            reason: "demo compatibility fixture".to_string(),
            lease: None,
        },
        response: swarm_spine::AuditResponseRecord::Skipped {
            reason: "demo compatibility fixture".to_string(),
        },
        created_at_ms: 1_700_000_000_000,
    };

    state
        .register_pending_demo_approval("demo-legacy-run", 0, &request, &audit)
        .unwrap();
    let set_id = harness.list_approval_sets().unwrap().sets[0].set_id.clone();
    let set = harness.load_approval_set(&set_id).unwrap().unwrap().report;
    assert_eq!(set.eligible_voters, vec!["demo-legacy-operator"]);

    let _ = fs::remove_dir_all(root);
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
            details: "verified 4 repo-owned ruleset files".to_string(),
            key_id: Some("test-key".to_string()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: Some(4),
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
            details: "verified 4 repo-owned ruleset files".to_string(),
            key_id: Some("test-key".to_string()),
            expected_sha256: None,
            observed_sha256: None,
            verified_items: Some(4),
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

fn live_response_playbook_config(action: ResponseAction) -> SwarmConfig {
    let mut config = live_response_config("suspicious_process_tree");
    config.pheromone.response_playbook.rules = vec![ResponsePlaybookRule {
        threat_class: ThreatClass::Execution,
        severity: Severity::Critical,
        min_confidence: 0.90,
        max_confidence: 1.0,
        actions: vec![action],
        branches: Vec::new(),
    }];
    config
}

/// Everything the two `route_kitten_candidate` cases assert on.
struct RoutedKittenCandidate {
    report: super::StrategyProposalRouteReport,
    /// `queue_review_state` recorded against the population candidate.
    stored_review_state: Option<swarm_runtime::evolution::EvolutionProposalReviewState>,
    stored_ready_for_review: bool,
    canary_results_dir: PathBuf,
    expected_canary_results_dir: PathBuf,
    /// Assurance summary persisted on the queue proposal, if the route wrote one.
    queue_assurance: Option<swarm_runtime::evolution::EvolutionProposalAssuranceSummary>,
    queue_blocking_reasons: Vec<swarm_runtime::evolution::EvolutionProposalBlockingReason>,
}

/// Drive one kitten candidate through the whole automated admission lane.
///
/// `min_detector_catch_rate` is the ONLY knob: it is the assurance coverage floor
/// the candidate is judged against. The `office_baseline_control` candidate's
/// measured catch rate against the repo evasion corpus is ~0.143, so a floor above
/// that must block the route and a floor below it must not. Both cases run the
/// same code path; nothing about the gate is switched off.
async fn route_kitten_candidate(
    label: &str,
    min_detector_catch_rate: f64,
) -> RoutedKittenCandidate {
    let root = temp_dir(label);
    let config_path = repo_root().join("rulesets/default.yaml");
    let mut config = test_config("suspicious_process_tree");
    config.evolution.assurance.min_detector_catch_rate = min_detector_catch_rate;
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
        state.signing_key.clone(),
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
                base_experiment_path: Some(stage_experiment(&root, &office_control_experiment())),
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
                target_genome: None,
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

    let stored_population = mutation
        .load_population(&config.evolution.paths.evolution_population_results_dir)
        .unwrap()
        .unwrap();
    let stored_candidate = stored_population
        .members
        .iter()
        .find(|candidate| candidate.strategy_id == "office_router_candidate")
        .unwrap();

    let queue_proposal = bridge_queue_proposal(&paths, report.bridge_id.as_deref());

    RoutedKittenCandidate {
        stored_review_state: stored_candidate.queue_review_state,
        stored_ready_for_review: stored_candidate.ready_for_review,
        canary_results_dir: paths.canary_results_dir.clone(),
        expected_canary_results_dir: root.join("canaries"),
        queue_assurance: queue_proposal
            .as_ref()
            .and_then(|proposal| proposal.assurance.clone()),
        queue_blocking_reasons: queue_proposal
            .map(|proposal| proposal.blocking_reasons)
            .unwrap_or_default(),
        report,
    }
}

/// Load the queue proposal the bridge minted for this run, so a test can read the
/// assurance summary that was actually persisted rather than the one it expected.
fn bridge_queue_proposal(
    paths: &super::StrategyProposalPaths,
    bridge_id: Option<&str>,
) -> Option<swarm_runtime::evolution::EvolutionProposalReport> {
    bridge_id?;
    let store = swarm_runtime::evolution::FileEvolutionProposalStore::open(
        &paths.evolution_queue_results_dir,
    )
    .unwrap();
    let list = store.list(None, None).unwrap();
    let proposal_id = list.proposals.first()?.proposal_id.clone();
    store
        .load(&proposal_id)
        .unwrap()
        .map(|lookup| lookup.report)
}

#[tokio::test]
async fn strategy_proposal_router_admits_verified_kitten_candidate_into_canary_lane() {
    // Floor below the candidate's measured 0.143 catch rate: assurance genuinely
    // passes rather than being switched off.
    let routed = route_kitten_candidate("strategy-router", 0.10).await;

    assert_eq!(
        routed.report.outcome,
        super::StrategyProposalOutcome::Accepted
    );
    assert!(routed.report.selection_id.is_some());
    assert!(routed.report.bridge_id.is_some());
    assert!(routed.report.handoff_id.is_some());
    assert!(routed.report.canary_run_id.is_some());

    // The persisted assurance summary must come from the evaluator, not from the
    // route writing one down. This is the assertion the fabricated summary passed
    // while the gate had never run.
    let assurance = routed.queue_assurance.expect("route persisted assurance");
    assert_eq!(
        assurance.decision(),
        swarm_runtime::evolution::EvolutionProposalAssuranceDecision::Passed
    );
    assert_eq!(
        assurance.provenance().evaluated_by(),
        "evaluate_proposal_assurance"
    );
    // The fabrication reported no coverage evidence at all (`suite_name: None`,
    // `actual_catch_rate: None`); a real evaluation cannot.
    assert!(assurance.coverage.suite_name.is_some());
    assert!(assurance.coverage.actual_catch_rate.is_some());

    assert_eq!(
        routed.stored_review_state,
        Some(swarm_runtime::evolution::EvolutionProposalReviewState::AcceptedForCanary)
    );
    assert!(!routed.stored_ready_for_review);
    assert_eq!(
        routed.canary_results_dir,
        routed.expected_canary_results_dir
    );
}

#[tokio::test]
async fn strategy_proposal_router_blocks_candidate_that_fails_the_assurance_gate() {
    // Floor above the candidate's measured 0.143 catch rate. Everything else is
    // identical to the admitting case, so the only thing under test is whether the
    // assurance gate runs on this route at all.
    let routed = route_kitten_candidate("strategy-router-blocked", 0.25).await;

    assert_eq!(
        routed.report.outcome,
        super::StrategyProposalOutcome::Blocked
    );
    assert!(routed.report.handoff_id.is_none());
    assert!(routed.report.canary_run_id.is_none());

    let assurance = routed.queue_assurance.expect("route persisted assurance");
    assert_eq!(
        assurance.decision(),
        swarm_runtime::evolution::EvolutionProposalAssuranceDecision::Blocked
    );
    assert!(
        routed
            .queue_blocking_reasons
            .iter()
            .any(|reason| reason.source == "assurance" && reason.name == "coverage_floor_not_met"),
        "expected a coverage_floor_not_met reason, got {:?}",
        routed.queue_blocking_reasons
    );
    // The blocked verdict must be written through to the durable review state, or
    // the queue record still reads `accepted_for_canary` to any later reader.
    assert_eq!(
        routed.stored_review_state,
        Some(swarm_runtime::evolution::EvolutionProposalReviewState::Blocked)
    );
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

fn rehearsal_demo_ingest_state() -> (IngestState, DefaultApprovalHarness) {
    let (mut state, harness) = live_demo_ingest_state();
    let mut config = state.config_template.load_full().as_ref().clone();
    config.runtime.mode = RuntimeMode::DetectOnly;
    let config_path = temp_path("demo-rehearsal-inline");
    state = IngestState::from_config(config_path, config)
        .unwrap()
        .with_approval_harness(harness.clone());
    (state, harness)
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
        metadata: ReplayScenarioMetadata {
            // Explicit. `ReplayScenarioClass` has no `Default` any more, so an
            // unclassified scenario can no longer be produced by omission --
            // that default is what let a scenario sit exempt from every replay
            // safety invariant. WINWORD -> encoded powershell is adversarial.
            class: ReplayScenarioClass::Adversarial,
            threat_class: None,
            campaign: None,
            techniques: Vec::new(),
            tags: Vec::new(),
        },
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
        metadata: ReplayScenarioMetadata {
            // Explicit. `ReplayScenarioClass` has no `Default` any more, so an
            // unclassified scenario can no longer be produced by omission --
            // that default is what let a scenario sit exempt from every replay
            // safety invariant. WINWORD -> encoded powershell is adversarial.
            class: ReplayScenarioClass::Adversarial,
            threat_class: None,
            campaign: None,
            techniques: Vec::new(),
            tags: Vec::new(),
        },
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
    let token = swarm_runtime::providence::mint_providence_context_token(
        &config.operator,
        swarm_runtime::providence::ProvidenceContextScope {
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

#[tokio::test]
async fn ingest_state_rejects_hypothesis_graph_hot_reload() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("hypothesis-graph-reload-store");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let state =
        IngestState::from_config(temp_path("hypothesis-graph-reload"), config.clone()).unwrap();
    let mut changed = config.clone();
    changed.hypothesis_graph.max_tasks += 1;
    let error = state.reload(changed).unwrap_err();
    assert!(matches!(
        error,
        super::IngestBuildError::HypothesisGraphReload
    ));

    let dependent_stores = [
        ("audit", temp_path("hypothesis-graph-reload-audit")),
        (
            "investigation",
            temp_path("hypothesis-graph-reload-investigation"),
        ),
        (
            "correlation",
            temp_path("hypothesis-graph-reload-correlation"),
        ),
    ];
    for (kind, directory) in dependent_stores {
        let mut changed = config.clone();
        let store = BundleStoreConfig::LocalFiles {
            directory: directory.display().to_string(),
        };
        match kind {
            "audit" => changed.audit.bundle_store = store,
            "investigation" => changed.investigation.bundle_store = store,
            "correlation" => changed.correlation.incident_store = store,
            _ => unreachable!(),
        }
        assert!(matches!(
            state.reload(changed),
            Err(super::IngestBuildError::HypothesisGraphReload)
        ));
    }

    let mut changed = config.clone();
    changed.investigation.time_budget_ms += 1;
    assert!(matches!(
        state.reload(changed),
        Err(super::IngestBuildError::HypothesisGraphReload)
    ));

    let mut changed = config.clone();
    changed.correlation.time_window_ms += 1;
    assert!(matches!(
        state.reload(changed),
        Err(super::IngestBuildError::HypothesisGraphReload)
    ));

    let mut changed = config;
    changed.pheromone.default_half_life_secs += 1.0;
    assert!(matches!(
        state.reload(changed),
        Err(super::IngestBuildError::HypothesisGraphReload)
    ));
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

#[test]
fn live_ingest_timestamp_validation_handles_seconds_milliseconds_and_invalid_values() {
    assert_eq!(
        super::normalized_ingest_timestamp_ms(1_700_000_000).unwrap(),
        1_700_000_000_000
    );
    assert_eq!(
        super::normalized_ingest_timestamp_ms(1_700_000_000_000).unwrap(),
        1_700_000_000_000
    );
    assert!(matches!(
        super::normalized_ingest_timestamp_ms(-1),
        Err(super::IngestProcessingError::InvalidEventTimestamp { timestamp: -1 })
    ));
    assert!(matches!(
        super::validate_live_event_timestamp(1_800_000_301, 1_800_000_000_000),
        Err(super::IngestProcessingError::FutureEventTimestamp { .. })
    ));
}

#[tokio::test]
async fn handler_rejects_future_timestamp_before_detection_or_deposit() {
    let state = test_ingest_state();
    let app = ingest_router(state.clone());
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut event = valid_process_event_json();
    event["timestamp"] = json!(now_ms + 6 * 60 * 1_000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&IngestRequest(vec![event])).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = parse_response(response).await;
    assert!(body.accepted.is_empty());
    assert_eq!(body.rejected.len(), 1);
    assert!(matches!(
        body.rejected[0].status,
        super::IngestEventStatus::Rejected
    ));
    assert!(
        body.rejected[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("trusted ingest ceiling"))
    );
    assert!(
        state
            .current_substrate()
            .recent_deposits(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn handler_queues_durable_replay_without_graph_io_on_request_path() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("ingest-enabled-hypothesis-graph");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let admission_notify = Arc::new(tokio::sync::Notify::new());
    let state = IngestState::from_config(temp_path("ingest-enabled-graph-config"), config)
        .unwrap()
        .with_hypothesis_graph_admission_notify(Arc::clone(&admission_notify));
    state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[126; 32]),
        )
        .unwrap()
        .unwrap();
    state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[127; 32]),
        )
        .unwrap()
        .unwrap();
    let graph = state.current_hypothesis_graph().unwrap();
    let response = ingest_router(state.clone())
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
    assert_eq!(body.accepted.len(), 1);
    assert!(body.rejected.is_empty());
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        admission_notify.notified(),
    )
    .await
    .expect("durable replay should signal background graph admission");
    assert_eq!(state.current_replay_store().recent(10).unwrap().len(), 1);
    let request_path_summary = graph.summary().unwrap();
    assert_eq!(request_path_summary.evidence_count, 0);
    assert_eq!(request_path_summary.metrics.submissions, 0);

    let reconciliation = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(reconciliation.admitted, 1);
    assert_eq!(reconciliation.failures, 0);
    let summary = graph.summary().unwrap();
    assert_eq!(summary.evidence_count, 1);
    assert_eq!(summary.edge_count, 1);
    assert_eq!(summary.pending_task_count, 3);
    assert_eq!(summary.metrics.submissions, 1);
    drop(graph);
    drop(state);
    fs::remove_dir_all(graph_root).unwrap();
}

#[tokio::test]
async fn startup_reconciliation_recovers_durable_replays_missing_from_graph() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("reconcile-enabled-hypothesis-graph");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let state =
        IngestState::from_config(temp_path("reconcile-enabled-graph-config"), config).unwrap();
    seed_platform_replay_bundle(&state, "reconcile-older", "host-a", 1_700_000_030_000);
    seed_platform_replay_bundle(&state, "reconcile-newer", "host-b", 1_700_000_030_001);
    state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[128; 32]),
        )
        .unwrap()
        .unwrap();
    state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[129; 32]),
        )
        .unwrap()
        .unwrap();

    let first = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(first.examined, 2);
    assert_eq!(first.admitted, 2);
    assert_eq!(first.idempotent, 0);
    assert_eq!(first.failures, 0);
    let summary = state.current_hypothesis_graph().unwrap().summary().unwrap();
    assert_eq!(summary.evidence_count, 2);
    assert_eq!(summary.hypothesis_count, 4);
    assert_eq!(summary.pending_task_count, 6);

    let retry = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(retry.examined, 0);
    assert_eq!(retry.admitted, 0);
    assert_eq!(retry.idempotent, 0);
    assert_eq!(retry.failures, 0);
    drop(state);
    fs::remove_dir_all(graph_root).unwrap();
}

#[tokio::test]
async fn scheduler_budget_retries_share_each_reconciliation_tick_and_converge() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("reconcile-scheduler-budget-retry");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    config.hypothesis_graph.max_work_units_per_tick = 3;
    let state =
        IngestState::from_config(temp_path("reconcile-scheduler-budget-retry-config"), config)
            .unwrap();
    state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[168; 32]),
        )
        .unwrap()
        .unwrap();
    state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[169; 32]),
        )
        .unwrap()
        .unwrap();

    let created_at_ms = 1_700_000_130_000;
    seed_platform_replay_bundle(&state, "same-tick-first", "host-a", created_at_ms);
    seed_platform_replay_bundle(&state, "same-tick-second", "host-b", created_at_ms);
    seed_platform_replay_bundle(&state, "same-tick-third", "host-c", created_at_ms);
    let first = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(first.examined, 3);
    assert_eq!(first.admitted, 1);
    assert_eq!(first.retryable_failures, 2);
    assert_eq!(first.quarantined, 0);
    let checkpoint = state
        .current_replay_store()
        .hypothesis_graph_checkpoint()
        .unwrap();
    assert_eq!(checkpoint.cursor_sequence, 3);
    assert_eq!(checkpoint.retry_bundle_ids.len(), 2);

    let retry = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(retry.examined, 2);
    assert_eq!(retry.admitted, 1);
    assert_eq!(retry.retryable_failures, 1);
    assert_eq!(retry.quarantined, 0);
    assert_eq!(
        state
            .current_replay_store()
            .hypothesis_graph_checkpoint()
            .unwrap()
            .retry_bundle_ids
            .len(),
        1
    );
    assert_eq!(
        state
            .current_hypothesis_graph()
            .unwrap()
            .summary()
            .unwrap()
            .evidence_count,
        2
    );

    let final_retry = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(final_retry.examined, 1);
    assert_eq!(final_retry.admitted, 1);
    assert_eq!(final_retry.retryable_failures, 0);
    assert_eq!(final_retry.quarantined, 0);
    assert!(
        state
            .current_replay_store()
            .hypothesis_graph_checkpoint()
            .unwrap()
            .retry_bundle_ids
            .is_empty()
    );
    assert_eq!(
        state
            .current_hypothesis_graph()
            .unwrap()
            .summary()
            .unwrap()
            .evidence_count,
        3
    );
    drop(state);
    fs::remove_dir_all(graph_root).unwrap();
}

#[tokio::test]
async fn reconciliation_checkpoint_survives_restart_and_admits_lexically_earlier_bundle() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("reconcile-durable-sequence-cursor");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let config_path = temp_path("reconcile-durable-sequence-cursor-config");
    let runtime_signing_key = ed25519_dalek::SigningKey::from_bytes(&[133; 32]);
    let state = IngestState::from_config_with_signing_key(
        config_path.clone(),
        config.clone(),
        runtime_signing_key.clone(),
    )
    .unwrap();
    seed_platform_replay_bundle(&state, "z-first-persisted", "host-z", 1_700_000_031_000);
    state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[134; 32]),
        )
        .unwrap()
        .unwrap();
    state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[135; 32]),
        )
        .unwrap()
        .unwrap();
    let first = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(first.examined, 1);
    assert_eq!(first.admitted, 1);
    drop(state);

    let restarted =
        IngestState::from_config_with_signing_key(config_path, config, runtime_signing_key)
            .unwrap();
    restarted
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[134; 32]),
        )
        .unwrap()
        .unwrap();
    restarted
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[135; 32]),
        )
        .unwrap()
        .unwrap();
    seed_platform_replay_bundle(
        &restarted,
        "a-second-persisted",
        "host-a",
        1_700_000_031_001,
    );
    let second = restarted.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(second.examined, 1);
    assert_eq!(second.admitted, 1);
    assert_eq!(second.idempotent, 0);
    assert_eq!(second.failures, 0);
    assert_eq!(
        restarted
            .current_hypothesis_graph()
            .unwrap()
            .summary()
            .unwrap()
            .evidence_count,
        2
    );

    drop(restarted);
    fs::remove_dir_all(graph_root).unwrap();
}

#[tokio::test]
async fn reconciliation_resets_checkpoint_for_a_replacement_graph_identity() {
    let mut first_config = test_config("suspicious_process_tree");
    let root = temp_path("reconcile-replacement-graph-identity");
    enable_collective_hypothesis_graph(&mut first_config, &root);
    let config_path = temp_path("reconcile-replacement-graph-identity-config");
    let runtime_signing_key = ed25519_dalek::SigningKey::from_bytes(&[141; 32]);
    let first = IngestState::from_config_with_signing_key(
        config_path.clone(),
        first_config.clone(),
        runtime_signing_key.clone(),
    )
    .unwrap();
    seed_platform_replay_bundle(
        &first,
        "replacement-graph-replay",
        "host-a",
        1_700_000_032_000,
    );
    for (kinds, seed) in [
        (
            vec![
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            142,
        ),
        (
            vec![swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            143,
        ),
    ] {
        first
            .current_hypothesis_graph_worker(
                kinds,
                &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            )
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        first.reconcile_hypothesis_graph_replays().unwrap().admitted,
        1
    );
    let first_graph_id = first.current_hypothesis_graph().unwrap().graph_id();
    let first_consumer_id = first
        .current_hypothesis_graph()
        .unwrap()
        .replay_consumer_graph_id();
    drop(first);

    let mut replacement_config = first_config;
    replacement_config.hypothesis_graph.state_store = BundleStoreConfig::LocalFiles {
        directory: root
            .join("replacement-hypothesis-graph")
            .display()
            .to_string(),
    };
    let replacement = IngestState::from_config_with_signing_key(
        config_path,
        replacement_config,
        runtime_signing_key,
    )
    .unwrap();
    for (kinds, seed) in [
        (
            vec![
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            145,
        ),
        (
            vec![swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            146,
        ),
    ] {
        replacement
            .current_hypothesis_graph_worker(
                kinds,
                &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            )
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        replacement.current_hypothesis_graph().unwrap().graph_id(),
        first_graph_id
    );
    assert_ne!(
        replacement
            .current_hypothesis_graph()
            .unwrap()
            .replay_consumer_graph_id(),
        first_consumer_id
    );
    let replayed = replacement.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(replayed.examined, 1);
    assert_eq!(replayed.admitted, 1);
    assert_eq!(replayed.failures, 0);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replay_reconciliation_quarantines_only_replay_local_failures() {
    let invalid_replay = swarm_runtime::hypothesis_graph::service::GraphServiceError::Admission(
        swarm_core::hypothesis_graph::GraphAdmissionError::InvalidField {
            field: "replay".to_string(),
            reason: "invalid fixture".to_string(),
        },
    );
    assert!(!super::replay_submission_failure_is_retryable(
        &invalid_replay
    ));

    for resource in ["scheduler.work_units_per_tick", "scheduler.claims_per_tick"] {
        let exhausted_tick = swarm_runtime::hypothesis_graph::service::GraphServiceError::Admission(
            swarm_core::hypothesis_graph::GraphAdmissionError::ResourceLimitExceeded {
                resource: resource.to_string(),
                limit: 3,
            },
        );
        assert!(super::replay_submission_failure_is_retryable(
            &exhausted_tick
        ));
    }

    let oversized_replay = swarm_runtime::hypothesis_graph::service::GraphServiceError::Store(
        swarm_spine::GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: 1,
        },
    );
    assert!(!super::replay_submission_failure_is_retryable(
        &oversized_replay
    ));

    for operational_failure in [
        swarm_runtime::hypothesis_graph::service::GraphServiceError::Store(
            swarm_spine::GraphStoreError::LockContended {
                path: PathBuf::from("graph.lock"),
            },
        ),
        swarm_runtime::hypothesis_graph::service::GraphServiceError::Store(
            swarm_spine::GraphStoreError::InvalidState {
                reason: "operator repair required".to_string(),
            },
        ),
        swarm_runtime::hypothesis_graph::service::GraphServiceError::MissingWorkerRegistration(
            swarm_core::hypothesis_graph::TaskKind::ChallengeEdge,
        ),
    ] {
        assert!(super::replay_submission_failure_is_retryable(
            &operational_failure
        ));
    }
}

#[tokio::test]
async fn permanent_replay_failures_do_not_hide_later_valid_evidence() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("reconcile-quarantines-poison-replays");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let state = IngestState::from_config(
        temp_path("reconcile-quarantines-poison-replays-config"),
        config,
    )
    .unwrap();
    state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[147; 32]),
        )
        .unwrap()
        .unwrap();
    state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[148; 32]),
        )
        .unwrap()
        .unwrap();

    for index in 0..super::HYPOTHESIS_GRAPH_REPLAY_MAX_RETRIES {
        let hunt_id = format!("poison-replay-{index:03}");
        let mut poison =
            platform_replay_bundle(&hunt_id, "host-poison", 1_700_000_033_000 + index as i64);
        poison.audit.created_at_ms = -1;
        state.current_replay_store().persist(&poison).unwrap();
    }
    seed_platform_replay_bundle(
        &state,
        "valid-after-poison",
        "host-valid",
        1_700_000_034_000,
    );

    let first_page = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(
        first_page.examined,
        super::HYPOTHESIS_GRAPH_REPLAY_SCAN_PAGE_SIZE
    );
    assert_eq!(
        first_page.quarantined,
        super::HYPOTHESIS_GRAPH_REPLAY_MAX_RETRIES
    );
    assert_eq!(first_page.admitted, 0);
    assert_eq!(
        first_page.failures,
        super::HYPOTHESIS_GRAPH_REPLAY_MAX_RETRIES
    );
    assert!(first_page.continuation_pending);
    let first_checkpoint = state
        .current_replay_store()
        .hypothesis_graph_checkpoint()
        .unwrap();
    assert_eq!(first_checkpoint.cursor_sequence, 256);

    let final_page = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(final_page.examined, 1);
    assert_eq!(final_page.quarantined, 0);
    assert_eq!(final_page.admitted, 1);
    assert_eq!(final_page.failures, 0);
    assert!(!final_page.continuation_pending);
    let checkpoint = state
        .current_replay_store()
        .hypothesis_graph_checkpoint()
        .unwrap();
    assert_eq!(checkpoint.cursor_sequence, 257);
    assert!(checkpoint.retry_bundle_ids.is_empty());
    fs::remove_dir_all(graph_root).unwrap();
}

#[tokio::test]
async fn infrastructure_detector_replays_reach_enabled_collective_graph() {
    let mut config = test_config("infrastructure_anomaly");
    let graph_root = temp_path("infrastructure-replay-hypothesis-graph");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let state = IngestState::from_config(
        temp_path("infrastructure-replay-hypothesis-graph-config"),
        config,
    )
    .unwrap();
    state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[132; 32]),
        )
        .unwrap()
        .unwrap();
    state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[133; 32]),
        )
        .unwrap()
        .unwrap();

    let payloads = [
        (
            "infrastructure-health",
            swarm_core::TelemetryPayload::InfrastructureHealth(
                swarm_core::InfrastructureHealthEvent {
                    node_name: "node-health".to_string(),
                    cpu_usage_percent: 91.0,
                    cpu_frequency_mhz: 3_200.0,
                    load_average_1m: 8.0,
                    load_average_5m: 7.0,
                    load_average_15m: 6.0,
                    memory_usage_percent: 88.0,
                    memory_available_bytes: 1_024,
                    disk_usage_percent: 72.0,
                    disk_io_latency_ms: 45.0,
                    network_rx_bytes: 11,
                    network_tx_bytes: 12,
                    network_rx_errors: 2,
                    network_tx_errors: 3,
                    failure_probability: 0.9,
                    prediction_confidence: 0.95,
                    time_to_failure_secs: 120.0,
                    collection_duration_ms: 25.0,
                },
            ),
        ),
        (
            "thermal-anomaly",
            swarm_core::TelemetryPayload::ThermalAnomaly(swarm_core::ThermalAnomalyEvent {
                node_name: "node-thermal".to_string(),
                temperature_celsius: 96.0,
                cpu_throttled: true,
                trend_slope: 1.5,
                severity: swarm_core::ThermalSeverity::Critical,
                estimated_time_to_critical_secs: 30.0,
            }),
        ),
        (
            "resource-exhaustion",
            swarm_core::TelemetryPayload::ResourceExhaustion(swarm_core::ResourceExhaustionEvent {
                node_name: "node-resource".to_string(),
                resource_kind: swarm_core::ExhaustedResource::Memory,
                utilization_percent: 99.0,
                current_value: 990,
                capacity_value: 1_000,
                oom_kill_count: Some(4),
                swap_used_bytes: Some(512),
                is_new: true,
            }),
        ),
    ];
    for (offset, (hunt_id, payload)) in payloads.into_iter().enumerate() {
        let mut replay = platform_replay_bundle(
            hunt_id,
            "infrastructure-host",
            1_700_000_035_000 + offset as i64,
        );
        replay.event.source = "sentinel".to_string();
        replay.event.payload = payload;
        state.current_replay_store().persist(&replay).unwrap();
    }

    let reconciliation = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(reconciliation.examined, 3);
    assert_eq!(reconciliation.admitted, 3);
    assert_eq!(reconciliation.failures, 0);
    let summary = state.current_hypothesis_graph().unwrap().summary().unwrap();
    assert_eq!(summary.evidence_count, 3);
    assert_eq!(summary.pending_task_count, 9);
    let projection = state
        .current_hypothesis_graph()
        .unwrap()
        .operator_projection()
        .unwrap();
    // Each infrastructure adapter supplies its own normalized event and asset;
    // fallback observation reuses those exact identities instead of adding a
    // redundant replay event and host alias.
    assert_eq!(projection.graph.nodes.len(), 6);
    assert_eq!(projection.graph.edges.len(), 3);
    assert!(projection.graph.edges.values().all(|edge| {
        edge.relation == swarm_core::hypothesis_graph::CausalRelation::ObservedIn
            && projection.graph.nodes.contains_key(&edge.from)
            && projection.graph.nodes.contains_key(&edge.to)
    }));
    for evidence in projection.graph.evidence.values() {
        for entity_id in evidence.entity_ids() {
            assert!(
                projection.graph.nodes.contains_key(&entity_id),
                "fallback evidence entity {entity_id} must be navigable"
            );
        }
    }

    drop(state);
    fs::remove_dir_all(graph_root).unwrap();
}

#[tokio::test]
async fn reconciliation_retries_old_failed_replays_beyond_graph_task_capacity() {
    let mut config = test_config("suspicious_process_tree");
    let graph_root = temp_path("reconcile-all-replays-beyond-task-capacity");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    config.hypothesis_graph.max_tasks = 3;
    let state = IngestState::from_config(
        temp_path("reconcile-all-replays-beyond-task-capacity-config"),
        config,
    )
    .unwrap();
    let stalker = state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[130; 32]),
        )
        .unwrap()
        .unwrap();
    let weaver = state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[131; 32]),
        )
        .unwrap()
        .unwrap();

    let created_at_ms = 1_700_000_040_000;
    seed_platform_replay_bundle(&state, "a-active", "host-a", created_at_ms);
    let first = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(first.examined, 1);
    assert_eq!(first.admitted, 1);

    for (offset, event_id) in ["b-old-failed", "c-newer", "d-newer", "e-newest"]
        .into_iter()
        .enumerate()
    {
        seed_platform_replay_bundle(
            &state,
            event_id,
            "host-pending",
            created_at_ms + offset as i64 + 1,
        );
    }
    let blocked = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(blocked.examined, 4);
    assert_eq!(blocked.idempotent, 0);
    assert_eq!(blocked.admitted, 0);
    assert_eq!(blocked.failures, 4);

    stalker
        .complete_stalker_hunt(
            "a-active",
            swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 10),
            9_800,
            false,
            true,
        )
        .unwrap();
    let challenge = weaver
        .next_challenge_context(swarm_core::hypothesis_graph::GraphLogicalTime::new(
            created_at_ms + 11,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(challenge.hunt_id, "a-active");
    assert!(
        weaver
            .complete_challenge(
                &challenge.task_id,
                swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 12),
            )
            .unwrap()
    );

    let retried = state.reconcile_hypothesis_graph_replays().unwrap();
    assert_eq!(retried.examined, 4);
    assert_eq!(retried.idempotent, 0);
    assert_eq!(retried.admitted, 1);
    assert_eq!(retried.failures, 3);
    let old_failed_replay = state
        .current_replay_store()
        .load_by_hunt_id("b-old-failed")
        .unwrap()
        .unwrap();
    assert!(
        state
            .current_hypothesis_graph()
            .unwrap()
            .submit_replay(&old_failed_replay.bundle)
            .unwrap()
            .idempotent
    );

    drop(state);
    fs::remove_dir_all(graph_root).unwrap();
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
async fn governed_resume_requires_approve_bearer_and_fails_closed_without_pack_store() {
    const TOKEN_ENV: &str = "SWARM_GOVERNED_RESUME_AUTH_TEST_TOKEN";
    const TOKEN: &str = "governed-resume-auth-test-secret";
    const READ_TOKEN_ENV: &str = "SWARM_GOVERNED_RESUME_READ_TEST_TOKEN";
    const READ_TOKEN: &str = "governed-resume-read-test-secret";
    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.context_token_env = TOKEN_ENV.to_string();
    config.operator.auth.operator_id = "governed-resume-auth-operator".to_string();
    config.operator.auth.token_env = TOKEN_ENV.to_string();
    config.operator.auth.principals = vec![
        OperatorPrincipalConfig {
            operator_id: "governed-resume-auth-operator".to_string(),
            token_env: TOKEN_ENV.to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
        },
        OperatorPrincipalConfig {
            operator_id: "governed-resume-read-operator".to_string(),
            token_env: READ_TOKEN_ENV.to_string(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read],
        },
    ];
    unsafe {
        std::env::set_var(TOKEN_ENV, TOKEN);
        std::env::set_var(READ_TOKEN_ENV, READ_TOKEN);
    }
    let state = IngestState::from_config(temp_path("governed-resume-auth"), config).unwrap();
    let app = detect_http_router(state);
    let uri = "/v1/governance/approvals/approval-set:missing/resume";
    let body = json!({"receipt_pack_id": "approval-receipt-pack:missing"}).to_string();

    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let caller_selected_time = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "receipt_pack_id": "approval-receipt-pack:missing",
                        "now_ms": 0,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        caller_selected_time.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let unavailable = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    unsafe {
        std::env::remove_var(TOKEN_ENV);
        std::env::remove_var(READ_TOKEN_ENV);
    }
}

#[tokio::test]
async fn governed_resume_fails_closed_when_receipt_pack_store_is_not_configured() {
    const TOKEN_ENV: &str = "SWARM_GOVERNED_RESUME_STORE_TEST_TOKEN";
    const TOKEN: &str = "governed-resume-store-test-secret";
    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.context_token_env = TOKEN_ENV.to_string();
    config.operator.auth.operator_id = "governed-resume-store-operator".to_string();
    config.operator.auth.token_env = TOKEN_ENV.to_string();
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: "governed-resume-store-operator".to_string(),
        token_env: TOKEN_ENV.to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Approve],
    }];
    unsafe { std::env::set_var(TOKEN_ENV, TOKEN) };
    let root = temp_path("governed-resume-two-stores");
    let harness = DefaultApprovalHarness::from_paths(root.join("sets"), root.join("ledgers"))
        .expect("two-store compatibility harness should open");
    let state = IngestState::from_config(temp_path("governed-resume-two-store-config"), config)
        .unwrap()
        .with_approval_harness(harness);
    let response = detect_http_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/governance/approvals/approval-set:missing/resume")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"receipt_pack_id": "approval-receipt-pack:missing"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    unsafe { std::env::remove_var(TOKEN_ENV) };
}

#[tokio::test]
async fn governed_resume_fails_closed_when_persisted_pack_is_missing() {
    const TOKEN_ENV: &str = "SWARM_GOVERNED_RESUME_MISSING_PACK_TEST_TOKEN";
    const TOKEN: &str = "governed-resume-missing-pack-test-secret";
    let mut config = test_config("suspicious_process_tree");
    config.operator.auth.context_token_env = TOKEN_ENV.to_string();
    config.operator.auth.operator_id = "governed-resume-missing-pack-operator".to_string();
    config.operator.auth.token_env = TOKEN_ENV.to_string();
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: "governed-resume-missing-pack-operator".to_string(),
        token_env: TOKEN_ENV.to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Approve],
    }];
    unsafe { std::env::set_var(TOKEN_ENV, TOKEN) };
    let root = temp_path("governed-resume-four-stores");
    let harness = DefaultApprovalHarness::from_path(
        root.join("config.yaml"),
        root.join("verdicts"),
        root.join("receipt-packs"),
        root.join("sets"),
        root.join("ledgers"),
    )
    .expect("four-store approval harness should open");
    let state = IngestState::from_config(temp_path("governed-resume-four-store-config"), config)
        .unwrap()
        .with_approval_harness(harness);
    let response = detect_http_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/governance/approvals/approval-set:missing/resume")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"receipt_pack_id": "approval-receipt-pack:missing"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    unsafe { std::env::remove_var(TOKEN_ENV) };
}

#[tokio::test]
async fn platform_api_routes_reload_rotated_bearer_token_without_restart() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api_with_token_env(&mut config, TEST_PLATFORM_API_ROTATION_BEARER_TOKEN_ENV);
    // This test mutates its bearer secret mid-flight. Keep that mutation out of
    // the shared helper env so it cannot invalidate another platform API test
    // running in parallel.
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-auth-rotation"), config).unwrap(),
    );

    let initial = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);

    unsafe {
        std::env::set_var(
            TEST_PLATFORM_API_ROTATION_BEARER_TOKEN_ENV,
            "platform-bearer-rotated",
        );
    }

    let stale = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {TEST_PLATFORM_API_BEARER_TOKEN}"),
                )
                .header("x-api-key", TEST_PLATFORM_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    let rotated = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(header::AUTHORIZATION, "Bearer platform-bearer-rotated")
                .header("x-api-key", TEST_PLATFORM_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
}

#[tokio::test]
async fn platform_api_routes_reload_rotated_api_key_without_restart() {
    const ROTATED_KEY: &str = "platform-read-rotated";

    let mut config_a = test_config("suspicious_process_tree");
    enable_platform_api(&mut config_a);
    let state =
        IngestState::from_config(temp_path("platform-key-rotation"), config_a.clone()).unwrap();
    let app = detect_http_router(state.clone());

    let initial = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);

    let mut config_b = test_config("suspicious_process_tree");
    enable_platform_api(&mut config_b);
    config_b.platform_api.keys = vec![PlatformApiKeyConfig {
        name: "test-reader-rotated".to_string(),
        key_hash: super::platform_api::platform_api_key_hash_hex(ROTATED_KEY),
        scopes: vec![PlatformApiScope::Read],
    }];
    state.reload(config_b).unwrap();

    let stale = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {TEST_PLATFORM_API_BEARER_TOKEN}"),
                )
                .header("x-api-key", TEST_PLATFORM_API_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    let rotated = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v2/api/runtime/status")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {TEST_PLATFORM_API_BEARER_TOKEN}"),
                )
                .header("x-api-key", ROTATED_KEY)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
}

#[tokio::test]
async fn platform_api_routes_reject_expired_bearer_token_with_context() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    config.operator.auth.token_expires_at_ms = Some(1);
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-auth-expiry"), config).unwrap(),
    );

    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("expired at"),
        "expected expiry context in platform API auth error: {json:?}"
    );
}

#[tokio::test]
async fn platform_api_routes_reject_sustained_rate_limit_and_report_recent_violation() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    config.platform_api.rate_limit.burst_max_requests = 10;
    config.platform_api.rate_limit.burst_window_ms = 10;
    config.platform_api.rate_limit.sustained_max_requests = 2;
    config.platform_api.rate_limit.sustained_window_ms = 1_000;
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-rate-limit"), config).unwrap(),
    );

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(
                authorized_platform_api_request_from_source(
                    "GET",
                    "/v2/api/runtime/status",
                    "203.0.113.50",
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let rejected = app
        .clone()
        .oneshot(
            authorized_platform_api_request_from_source(
                "GET",
                "/v2/api/runtime/status",
                "203.0.113.50",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers().get(header::RETRY_AFTER).unwrap(), "1");
    let body = to_bytes(rejected.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("sustained rate limit exceeded"),
        "expected sustained limiter rejection context: {json:?}"
    );

    let audit = app
        .oneshot(
            authorized_platform_api_request_from_source(
                "GET",
                "/v2/api/runtime/status",
                "203.0.113.51",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(audit.status(), StatusCode::OK);
    let body = to_bytes(audit.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["data"][0]["rate_limit"]["recent_violations"][0]["source"],
        "203.0.113.50"
    );
    assert_eq!(
        json["data"][0]["rate_limit"]["recent_violations"][0]["threshold"],
        "sustained"
    );
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
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Read],
        },
        OperatorPrincipalConfig {
            operator_id: "maintainer-1".to_string(),
            token_env: MAINT_ENV.to_string(),
            token_expires_at_ms: None,
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
        swarm_runtime::providence::ProvidenceContextScope {
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
            .clone()
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

    // Context tokens MUST NOT grant access to /runtime/status — that would
    // expose runtime health, bridge state, and bearer-token metadata to any
    // operator following a scoped Providence finding link.
    let runtime_status_blocked = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v2/api/runtime/status?context_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        matches!(
            runtime_status_blocked.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "context token must not authorize /runtime/status; got {}",
        runtime_status_blocked.status()
    );
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
async fn platform_hypothesis_graph_endpoints_surface_durable_state() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let graph_root = temp_path("platform-hypothesis-graph-store");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    config.hypothesis_graph.max_hypotheses = 4;
    let state = IngestState::from_config(temp_path("platform-hypothesis-graph"), config).unwrap();
    let hunt_id = "evt-platform-hypothesis-graph";
    let created_at_ms = 1_700_000_020_000;
    seed_platform_replay_bundle(&state, hunt_id, "host-graph", created_at_ms);
    let replay = state
        .current_replay_store()
        .load_by_hunt_id(hunt_id)
        .unwrap()
        .unwrap()
        .bundle;
    let graph = state.current_hypothesis_graph().unwrap();
    let stalker_key = ed25519_dalek::SigningKey::from_bytes(&[123; 32]);
    let worker = state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &stalker_key,
        )
        .unwrap()
        .unwrap();
    let weaver = state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[124; 32]),
        )
        .unwrap()
        .unwrap();
    graph.submit_replay(&replay).unwrap();
    let completion = worker
        .complete_stalker_hunt(
            hunt_id,
            swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 1),
            9_800,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 1);
    let first_challenge = weaver
        .next_challenge_context(swarm_core::hypothesis_graph::GraphLogicalTime::new(
            created_at_ms + 2,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(first_challenge.hunt_id, hunt_id);
    assert!(
        weaver
            .complete_challenge(
                &first_challenge.task_id,
                swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 3),
            )
            .unwrap()
    );
    let graph_id = graph.graph_id().to_string();
    let app = detect_http_router(state.clone());

    let summaries = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/hypothesis-graphs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(summaries.status(), StatusCode::OK);
    let summaries: Value = parse_json(summaries).await;
    assert_eq!(summaries["data"].as_array().unwrap().len(), 1);
    assert_eq!(summaries["data"][0]["graph_id"], graph_id);
    assert_eq!(summaries["data"][0]["memory_count"], 1);

    let detail = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", format!("/v2/api/hypothesis-graphs/{graph_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail.status(), StatusCode::OK);
    let detail: Value = parse_json(detail).await;
    assert_eq!(
        detail["data"][0]["graph"]["evidence"]
            .as_object()
            .unwrap()
            .len(),
        1
    );

    let tasks = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs/{graph_id}/tasks"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tasks.status(), StatusCode::OK);
    let tasks: Value = parse_json(tasks).await;
    assert_eq!(tasks["data"].as_array().unwrap().len(), 3);

    let first_task_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs/{graph_id}/tasks?page_size=2"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_task_page.status(), StatusCode::OK);
    let first_task_page: Value = parse_json(first_task_page).await;
    assert_eq!(first_task_page["data"].as_array().unwrap().len(), 2);
    let task_cursor = first_task_page["cursor"].as_str().unwrap();
    let second_task_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!(
                    "/v2/api/hypothesis-graphs/{graph_id}/tasks?page_size=2&cursor={task_cursor}"
                ),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_task_page.status(), StatusCode::OK);
    let second_task_page: Value = parse_json(second_task_page).await;
    assert_eq!(second_task_page["data"].as_array().unwrap().len(), 1);
    assert!(second_task_page.get("cursor").is_none());

    let memory = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs/{graph_id}/memory"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(memory.status(), StatusCode::OK);
    let memory: Value = parse_json(memory).await;
    assert_eq!(memory["data"].as_array().unwrap().len(), 1);

    let second_hunt_id = "evt-platform-hypothesis-graph-second";
    seed_platform_replay_bundle(&state, second_hunt_id, "host-graph", created_at_ms + 10);
    let second_replay = state
        .current_replay_store()
        .load_by_hunt_id(second_hunt_id)
        .unwrap()
        .unwrap()
        .bundle;
    graph.submit_replay(&second_replay).unwrap();
    let second_completion = worker
        .complete_stalker_hunt(
            second_hunt_id,
            swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 11),
            9_700,
            false,
            true,
        )
        .unwrap();
    assert_eq!(second_completion.memory_records_projected, 1);
    let second_challenge = weaver
        .next_challenge_context(swarm_core::hypothesis_graph::GraphLogicalTime::new(
            created_at_ms + 12,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(second_challenge.hunt_id, second_hunt_id);
    assert!(
        weaver
            .complete_challenge(
                &second_challenge.task_id,
                swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 13),
            )
            .unwrap()
    );

    let first_memory_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs/{graph_id}/memory?page_size=1"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_memory_page.status(), StatusCode::OK);
    let first_memory_page: Value = parse_json(first_memory_page).await;
    assert_eq!(first_memory_page["data"].as_array().unwrap().len(), 1);
    let memory_cursor = first_memory_page["cursor"].as_str().unwrap();
    let first_memory_id = first_memory_page["data"][0]["memory"]["memory_id"]
        .as_str()
        .unwrap();
    let second_memory_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!(
                    "/v2/api/hypothesis-graphs/{graph_id}/memory?page_size=1&cursor={memory_cursor}"
                ),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_memory_page.status(), StatusCode::OK);
    let second_memory_page: Value = parse_json(second_memory_page).await;
    assert_eq!(second_memory_page["data"].as_array().unwrap().len(), 1);
    assert_ne!(
        second_memory_page["data"][0]["memory"]["memory_id"]
            .as_str()
            .unwrap(),
        first_memory_id
    );
    assert!(second_memory_page.get("cursor").is_none());

    let third_hunt_id = "evt-platform-hypothesis-graph-third";
    seed_platform_replay_bundle(&state, third_hunt_id, "host-graph", created_at_ms + 20);
    let third_replay = state
        .current_replay_store()
        .load_by_hunt_id(third_hunt_id)
        .unwrap()
        .unwrap()
        .bundle;
    let third_submission = graph.submit_replay(&third_replay).unwrap();
    assert_ne!(third_submission.graph_id.to_string(), graph_id);
    let rotated_summaries = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/hypothesis-graphs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated_summaries.status(), StatusCode::OK);
    let rotated_summaries: Value = parse_json(rotated_summaries).await;
    assert_eq!(rotated_summaries["data"].as_array().unwrap().len(), 2);
    assert_eq!(
        rotated_summaries["data"][0]["graph_id"],
        third_submission.graph_id.to_string()
    );
    assert_eq!(rotated_summaries["data"][1]["graph_id"], graph_id);

    let first_summary_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/hypothesis-graphs?page_size=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first_summary_page.status(), StatusCode::OK);
    let first_summary_page: Value = parse_json(first_summary_page).await;
    assert_eq!(first_summary_page["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        first_summary_page["data"][0]["graph_id"],
        third_submission.graph_id.to_string()
    );
    let summary_cursor = first_summary_page["cursor"].as_str().unwrap();
    let second_summary_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs?page_size=1&cursor={summary_cursor}"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second_summary_page.status(), StatusCode::OK);
    let second_summary_page: Value = parse_json(second_summary_page).await;
    assert_eq!(second_summary_page["data"].as_array().unwrap().len(), 1);
    assert_eq!(second_summary_page["data"][0]["graph_id"], graph_id);
    assert!(second_summary_page.get("cursor").is_none());
    let forged_summary_cursor = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                "/v2/api/hypothesis-graphs?page_size=1&cursor=0:graph:forged",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forged_summary_cursor.status(), StatusCode::BAD_REQUEST);

    let invalid_page = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs/{graph_id}/tasks?page_size=0"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_page.status(), StatusCode::BAD_REQUEST);

    let missing = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/hypothesis-graphs/graph:missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn platform_task_cursor_remains_complete_while_unreturned_tasks_transition() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let graph_root = temp_path("platform-hypothesis-task-stable-cursor-store");
    enable_collective_hypothesis_graph(&mut config, &graph_root);
    let state =
        IngestState::from_config(temp_path("platform-hypothesis-task-stable-cursor"), config)
            .unwrap();
    let hunt_id = "evt-platform-hypothesis-task-stable-cursor";
    let created_at_ms = 1_700_000_030_000;
    seed_platform_replay_bundle(&state, hunt_id, "host-graph", created_at_ms);
    let replay = state
        .current_replay_store()
        .load_by_hunt_id(hunt_id)
        .unwrap()
        .unwrap()
        .bundle;
    let graph = state.current_hypothesis_graph().unwrap();
    let stalker = state
        .current_hypothesis_graph_worker(
            [
                swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
                swarm_core::hypothesis_graph::TaskKind::FalsifyHypothesis,
            ],
            &ed25519_dalek::SigningKey::from_bytes(&[133; 32]),
        )
        .unwrap()
        .unwrap();
    let weaver = state
        .current_hypothesis_graph_worker(
            [swarm_core::hypothesis_graph::TaskKind::ChallengeEdge],
            &ed25519_dalek::SigningKey::from_bytes(&[134; 32]),
        )
        .unwrap()
        .unwrap();
    let submission = graph.submit_replay(&replay).unwrap();
    let graph_id = submission.graph_id.to_string();
    let expected = submission
        .task_ids
        .iter()
        .map(ToString::to_string)
        .collect::<std::collections::BTreeSet<_>>();
    let app = detect_http_router(state);

    let first = app
        .clone()
        .oneshot(
            authorized_platform_api_request(
                "GET",
                format!("/v2/api/hypothesis-graphs/{graph_id}/tasks?page_size=1"),
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first: Value = parse_json(first).await;
    let mut observed = std::collections::BTreeSet::from([first["data"][0]["request"]["task_id"]
        .as_str()
        .unwrap()
        .to_string()]);
    let mut cursor = first["cursor"].as_str().unwrap().to_string();

    stalker
        .complete_stalker_hunt(
            hunt_id,
            swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 1),
            9_000,
            false,
            true,
        )
        .unwrap();
    let challenge = weaver
        .next_challenge_context(swarm_core::hypothesis_graph::GraphLogicalTime::new(
            created_at_ms + 2,
        ))
        .unwrap()
        .unwrap();
    assert!(
        weaver
            .complete_challenge(
                &challenge.task_id,
                swarm_core::hypothesis_graph::GraphLogicalTime::new(created_at_ms + 3),
            )
            .unwrap()
    );

    loop {
        let response = app
            .clone()
            .oneshot(
                authorized_platform_api_request(
                    "GET",
                    format!(
                        "/v2/api/hypothesis-graphs/{graph_id}/tasks?page_size=1&cursor={cursor}"
                    ),
                )
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page: Value = parse_json(response).await;
        let task_id = page["data"][0]["request"]["task_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            observed.insert(task_id),
            "task pagination duplicated an item"
        );
        let Some(next) = page.get("cursor").and_then(Value::as_str) else {
            break;
        };
        cursor = next.to_string();
    }

    assert_eq!(observed, expected);
}

#[tokio::test]
async fn platform_hypothesis_graph_collection_is_empty_when_disabled() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let app = detect_http_router(
        IngestState::from_config(temp_path("platform-hypothesis-disabled"), config).unwrap(),
    );
    let response = app
        .oneshot(
            authorized_platform_api_request("GET", "/v2/api/hypothesis-graphs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = parse_json(response).await;
    assert!(body["data"].as_array().unwrap().is_empty());
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
    // The shipped alert_threshold is 2.0 and this test seeds exactly two sources at
    // confidence 1.0, so `total_strength >= alert_threshold` was a knife-edge float
    // equality that held ONLY while the handler's clock read landed in the same second
    // as the seeding. `strength_at` decays as confidence * 0.5^(elapsed / 3600), so one
    // second of elapsed time gives 1.999615 and the endpoint reports Normal instead of
    // Alert. Measured: 2 failures in 150 unforced local runs, and forcing `now - 1`
    // reproduces CI run 31725573487's failure exactly (same assert, Normal vs Alert).
    //
    // Lowering the threshold for this test restores a margin decay cannot cross inside a
    // test run (2.0 -> 1.5 survives ~1490s), while keeping what the test is actually
    // about: two DISTINCT sources at min_sources_for_escalation clearing the alert
    // threshold, and not reaching incident_threshold. Do not raise it back to a value
    // the seeded strength meets exactly -- that is what made this flaky.
    config.pheromone.alert_threshold = 1.5;
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
    // Two deposits at confidence 1.0 sum to 2.0 at zero elapsed and decay from there, so
    // this is bounded on both sides rather than asserted at the boundary: `>= 2.0` was
    // the second wall-clock-decided assertion in this test and failed for the same
    // reason as the escalation_level one above. The lower bound is the alert threshold
    // this test configures; the upper bound still catches a double-count.
    assert!(
        execution.total_strength > 1.5 && execution.total_strength <= 2.0,
        "expected two decaying full-strength sources above the alert threshold, got {}",
        execution.total_strength
    );
}

#[tokio::test]
async fn generated_python_client_smoke_tests_live_platform_router() {
    let mut config = test_config("suspicious_process_tree");
    enable_platform_api(&mut config);
    let state = IngestState::from_config(temp_path("platform-python-client"), config).unwrap();
    seed_platform_replay_bundle(
        &state,
        "evt-platform-python",
        "host-python",
        1_700_210_000_000,
    );
    state
        .current_incident_store()
        .persist(&CorrelatedIncident {
            incident_id: "incident-platform-python".to_string(),
            summary: "platform python smoke incident".to_string(),
            created_at_ms: 1_700_210_000_000,
            window_start_ms: 1_700_210_000_000,
            window_end_ms: 1_700_210_000_001,
            correlation_keys: vec!["host:host-python".to_string()],
            related_receipt_ids: vec!["receipt:evt-platform-python".to_string()],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: "investigation:evt-platform-python".to_string(),
                hunt_id: "evt-platform-python".to_string(),
                finding_id: "finding-evt-platform-python".to_string(),
                reason: "platform python smoke fixture".to_string(),
                shared_keys: vec!["host:host-python".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("evt-platform-python".to_string()),
            trigger_finding_id: Some("finding-evt-platform-python".to_string()),
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

    let app = detect_http_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        let _ = server.await;
    });

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let script_path = repo_root.join("clients/python/smoke_platform_client.py");
    let base_url = format!("http://{address}");
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("uv")
            // The script imports the generated client package from
            // `clients/python/swarm-platform-client/` IN THE CHECKED-OUT TREE,
            // and CPython writes a `__pycache__/` directory next to every module
            // it imports. Gitignored, so `git status --porcelain` never showed
            // it -- but it is still the suite writing into the repository.
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .arg("run")
            .arg("--isolated")
            .arg("--no-project")
            .arg("--no-config")
            .arg("--with")
            .arg("httpx>=0.23.0,<0.29.0")
            .arg("--with")
            .arg("attrs>=22.2.0")
            .arg("--with")
            .arg("python-dateutil>=2.8.0,<3")
            .arg("--python")
            .arg("python3")
            .arg("python")
            .arg(script_path)
            .arg("--base-url")
            .arg(base_url)
            .arg("--bearer-token")
            .arg(TEST_PLATFORM_API_BEARER_TOKEN)
            .arg("--api-key")
            .arg(TEST_PLATFORM_API_KEY)
            .arg("--schema-version")
            .arg(CURRENT_OPERATOR_API_SCHEMA_VERSION.to_string())
            .arg("--expected-hunt-id")
            .arg("evt-platform-python")
            .arg("--expected-finding-id")
            .arg("finding-evt-platform-python")
            .arg("--expected-incident-id")
            .arg("incident-platform-python")
            .arg("--expected-host-id")
            .arg("host-python")
            .output()
    })
    .await
    .unwrap()
    .expect(
        "`uv` must be on PATH for the generated python client smoke test. CI installs it in \
         the test job; locally see https://docs.astral.sh/uv/. Without this message the \
         absence surfaced as a bare NotFound naming neither the tool nor the reason.",
    );

    let _ = shutdown_tx.send(());
    let _ = server.await;

    assert!(
        output.status.success(),
        "python client smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["finding_id"], "finding-evt-platform-python");
    assert_eq!(summary["incident_id"], "incident-platform-python");
    assert_eq!(summary["host_id"], "host-python");
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
async fn detect_only_governed_demo_produces_rehearsal_proof_without_live_approval() {
    let scenario_path = temp_path("demo-scenario-detect-only-governed");
    write_human_gate_demo_scenario(&scenario_path);
    let (state, harness) = rehearsal_demo_ingest_state();
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

    assert_eq!(harness.list_approval_sets().unwrap().total_count, 0);

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
    assert!(proof.signed_receipts.is_empty());
    assert!(!proof.final_incident.incident_id.is_empty());
    assert!(
        proof
            .decision_timeline
            .iter()
            .any(|entry| entry.stage == "replay_step_decision")
    );
    assert!(
        proof
            .decision_timeline
            .iter()
            .all(|entry| entry.stage != "governance_deferred")
    );
    assert!(proof.merkle_leaves.len() >= 2);

    let _ = fs::remove_file(scenario_path);
}

#[tokio::test]
async fn live_governed_demo_defers_without_creating_human_approval() {
    let scenario_path = temp_path("demo-scenario-governance-deferred");
    write_human_gate_demo_scenario(&scenario_path);
    let (state, harness) = live_demo_ingest_state();
    let app = detect_http_router(state.clone());

    let replay_response = app
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
    let replay = parse_demo_replay_response(replay_response).await;
    assert_eq!(harness.list_approval_sets().unwrap().total_count, 0);
    let run = state.load_demo_run(&replay.run_id).unwrap();
    assert!(
        run.timeline
            .iter()
            .any(|entry| entry.stage == "governance_deferred")
    );
    assert!(run.approvals.is_empty());

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
    let token = swarm_runtime::providence::mint_providence_context_token(
        &config.operator,
        swarm_runtime::providence::ProvidenceContextScope {
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
            auth_token: Some("providence-api-bearer".into()),
            request_signature: Some(swarm_core::config::RequestSignatureConfig {
                header: "X-Swarm-Signature".to_string(),
                secret: "shared-providence-secret".into(),
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
    let claims = swarm_runtime::providence::verify_providence_context_token(
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
    use swarm_core::types::{
        ProvidenceCallbackEvent, ProvidenceIncidentStatus, ProvidenceReconciliationOutcome,
        SwarmProvidenceCallbackRequest,
    };
    use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};
    use swarm_runtime::providence::PROVIDENCE_CHANNEL;

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
                    secret: CALLBACK_SECRET.into(),
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
    use swarm_core::types::{
        AgentId, ProvidenceFeedbackAction, SwarmFeedbackSignal, SwarmProvidenceFeedbackRequest,
    };
    use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};
    use swarm_pheromone::DepositSigningPayload;
    use swarm_runtime::drafting::EvolutionValidationBundleStatus;
    use swarm_runtime::evolution::{EvolutionProposalProofStatus, EvolutionProposalReviewState};
    use swarm_runtime::kitten_agent::{KittenFeedbackSignalRecord, route_feedback_signal};
    use swarm_runtime::mutation::{
        EvolutionPopulationCandidate, EvolutionPopulationFitnessObjectives,
        EvolutionPopulationState, FileEvolutionPopulationStore,
    };
    use swarm_runtime::providence::PROVIDENCE_CHANNEL;

    const FEEDBACK_SECRET: &str = "providence-feedback-secret";
    const FEEDBACK_HEADER: &str = "X-Swarm-Signature";
    const FEEDBACK_SIGNALS_FILE: &str = "feedback-signals.jsonl";

    /// Reads back what `kitten_agent::route_feedback_signal` appended.
    ///
    /// The writer half (`FileKittenFeedbackStore::append`) is production code;
    /// the read half exists only for this assertion, so it lives here rather
    /// than on `swarm_runtime::kitten_agent`. A `#[cfg(test)]` item on the root is
    /// unreachable from `swarm-ingest-runtime`, which depends on the root
    /// normally and therefore links its non-test build (SPLIT-05).
    fn load_feedback_signal_records(
        root: impl AsRef<Path>,
    ) -> Result<Vec<KittenFeedbackSignalRecord>, String> {
        let path = root.as_ref().join(FEEDBACK_SIGNALS_FILE);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&path)
            .map_err(|error| format!("failed to read kitten feedback store: {error}"))?;
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("failed to parse kitten feedback signal: {error}"))
            })
            .collect()
    }

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
                    secret: FEEDBACK_SECRET.into(),
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

    #[tokio::test]
    async fn feedback_clock_is_strictly_monotonic_across_state_clones() {
        let state = IngestState::from_config(
            super::temp_path("feedback-monotonic-clock"),
            super::test_config("suspicious_process_tree"),
        )
        .unwrap();
        let clone = state.clone();
        let first = state.next_providence_feedback_timestamp_ms().await.unwrap();
        let second = clone.next_providence_feedback_timestamp_ms().await.unwrap();
        assert!(second > first);
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

    #[tokio::test]
    async fn feedback_clock_reservation_survives_partial_commit_and_restart() {
        let incident_root = temp_dir("feedback-durable-clock");
        let mut config = super::test_config("suspicious_process_tree");
        config.correlation.incident_store = BundleStoreConfig::LocalFiles {
            directory: incident_root.display().to_string(),
        };
        config.pheromone.backend = PheromoneBackendConfig::LocalJournal {
            path: incident_root
                .join("pheromone-feedback.jsonl")
                .display()
                .to_string(),
        };
        let config_path = super::temp_path("feedback-durable-clock-config");
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let state = IngestState::from_config_with_signing_key(
            config_path.clone(),
            config.clone(),
            signing_key.clone(),
        )
        .unwrap();
        seed_feedback_incident(
            &state,
            "incident-durable-clock",
            "event-durable-clock",
            "host-durable-clock",
            "suspicious_process_tree",
            1_700_000_000_000,
        );
        let durable_high_water = now_ms().saturating_add(60_000);
        let mut incident = state
            .current_incident_store()
            .load_by_incident_id("incident-durable-clock")
            .unwrap()
            .unwrap()
            .incident;
        incident
            .feedback_audit_entries
            .push(swarm_spine::AnalystFeedbackAuditEntry {
                feedback_id: "durable-feedback".to_string(),
                received_at_ms: durable_high_water,
                action: ProvidenceFeedbackAction::Confirm,
                analyst_id: "analyst-durable".to_string(),
                incident_id: incident.incident_id.clone(),
                finding_id: Some("finding-event-durable-clock".to_string()),
                reason: None,
                request_signature: "sha256=durable".to_string(),
                evidence: None,
                soar_lineage: None,
                payload: json!({"source": "durable-clock-test"}),
                outcome: json!({"status": "recorded"}),
                soar_claim_lease: None,
            });
        state.current_incident_store().persist(&incident).unwrap();
        let reserved_high_water = state.next_providence_feedback_timestamp_ms().await.unwrap();
        assert!(reserved_high_water > durable_high_water);
        crate::ingest::providence_handlers::apply_providence_feedback(
            &state,
            &SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Confirm,
                incident_id: "incident-durable-clock".to_string(),
                finding_id: Some("finding-event-durable-clock".to_string()),
                analyst_id: "analyst-partial-commit".to_string(),
                reason: Some("durable substrate before audit".to_string()),
            },
            &swarm_runtime::providence::ProvidenceFeedbackTarget {
                incident_id: "incident-durable-clock".to_string(),
                finding_id: "finding-event-durable-clock".to_string(),
                hunt_id: "event-durable-clock".to_string(),
                event_id: "event-durable-clock".to_string(),
                replay_bundle_id: None,
                replay_bundle_digest: None,
                evidence_timestamp: None,
                host_id: Some("host-durable-clock".to_string()),
                strategy_id: Some("suspicious_process_tree".to_string()),
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
            },
            "partial-commit-feedback",
            reserved_high_water,
        )
        .await
        .unwrap();
        drop(state);

        let reopened =
            IngestState::from_config_with_signing_key(config_path, config, signing_key).unwrap();
        assert!(
            reopened
                .next_providence_feedback_timestamp_ms()
                .await
                .unwrap()
                > reserved_high_water,
            "a restarted process must advance beyond a reservation whose substrate write completed before its audit"
        );
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
            timestamp: timestamp.div_euclid(1_000),
            decay_half_life: TEST_LIVE_HALF_LIFE_SECS,
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

    fn persist_population_candidate(
        root: &Path,
        strategy_id: &str,
        fitness: f64,
        signing_key: &ed25519_dalek::SigningKey,
    ) {
        let signer_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let store =
            FileEvolutionPopulationStore::open_signed(root, signer_agent_id, signing_key.clone())
                .unwrap();
        store
            .persist(&EvolutionPopulationState {
                updated_at_ms: 1_800_900_000_000,
                ranking_id: "ranking-feedback".to_string(),
                validation_batch_id: "validation-feedback".to_string(),
                population_size: 4,
                pareto_tournament_size: 2,
                proposal_timestamps_ms: Vec::new(),
                applied_feedback_operations: Default::default(),
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
                        threat_class_coverage: 1.0,
                    },
                    observations: None,
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
        let feedback_deposit = state
            .current_substrate()
            .recent_deposits(10)
            .await
            .unwrap()
            .into_iter()
            .find(|deposit| {
                deposit.indicator["feedback_id"]
                    == serde_json::Value::String(entry.feedback_id.clone())
            })
            .unwrap();
        assert_eq!(
            feedback_deposit.indicator["governed_evidence_timestamp"],
            serde_json::json!(1_700_100_000)
        );
    }

    #[tokio::test]
    async fn feedback_target_event_id_is_bound_to_the_selected_replay_bundle() {
        let state = IngestState::from_config(
            super::temp_path("feedback-selected-replay-event"),
            super::test_config("suspicious_process_tree"),
        )
        .unwrap();
        super::seed_platform_replay_bundle(
            &state,
            "evt-selected-replay",
            "host-selected-replay",
            1_700_105_000_000,
        );
        seed_feedback_incident(
            &state,
            "incident-selected-replay",
            "evt-trigger",
            "host-trigger",
            "trigger-strategy",
            1_700_105_000_000,
        );
        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-selected-replay")
            .unwrap()
            .unwrap();
        let target = swarm_runtime::providence::ProvidenceFeedbackTarget {
            incident_id: lookup.incident.incident_id.clone(),
            finding_id: "finding-evt-selected-replay".to_string(),
            hunt_id: "evt-selected-replay".to_string(),
            event_id: "evt-trigger".to_string(),
            replay_bundle_id: None,
            replay_bundle_digest: None,
            evidence_timestamp: None,
            host_id: None,
            strategy_id: None,
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
        };
        let enriched =
            crate::ingest::providence_handlers::enrich_feedback_target(&state, &lookup, &target)
                .unwrap();
        assert_eq!(enriched.event_id, "evt-selected-replay");
        assert_eq!(enriched.host_id.as_deref(), Some("host-selected-replay"));
        assert_eq!(
            enriched.replay_bundle_id.as_deref(),
            Some("bundle-evt-selected-replay")
        );
        assert!(
            enriched
                .replay_bundle_digest
                .as_ref()
                .is_some_and(|digest| digest.len() == 64)
        );
    }

    #[tokio::test]
    async fn investigation_feedback_uses_the_replay_bundle_frozen_in_its_target() {
        let mut config = super::test_config("suspicious_process_tree");
        config.investigation.enabled = true;
        let state =
            IngestState::from_config(super::temp_path("feedback-frozen-replay-bundle"), config)
                .unwrap();
        super::seed_platform_replay_bundle(
            &state,
            "evt-frozen-replay",
            "host-original",
            1_700_106_000_000,
        );
        seed_feedback_incident(
            &state,
            "incident-frozen-replay",
            "evt-frozen-replay",
            "host-original",
            "suspicious_process_tree",
            1_700_106_000_000,
        );
        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-frozen-replay")
            .unwrap()
            .unwrap();
        let unresolved = swarm_runtime::providence::resolve_feedback_target(
            &lookup,
            Some("finding-evt-frozen-replay"),
        )
        .unwrap();
        let frozen = crate::ingest::providence_handlers::enrich_feedback_target(
            &state,
            &lookup,
            &unresolved,
        )
        .unwrap();
        let frozen_bundle_id = frozen.replay_bundle_id.clone().unwrap();

        let mut newer = state
            .current_replay_store()
            .load_by_bundle_id(&frozen_bundle_id)
            .unwrap()
            .unwrap()
            .bundle;
        newer.bundle_id = "bundle-newer-same-hunt".to_string();
        newer.audit.created_at_ms += 1_000;
        newer.event.host_id = Some("host-newer".to_string());
        state.current_replay_store().persist(&newer).unwrap();
        assert_eq!(
            state
                .current_replay_store()
                .load_by_hunt_id("evt-frozen-replay")
                .unwrap()
                .unwrap()
                .record
                .bundle_id,
            "bundle-newer-same-hunt"
        );

        crate::ingest::providence_handlers::apply_providence_feedback(
            &state,
            &SwarmProvidenceFeedbackRequest {
                action: ProvidenceFeedbackAction::Investigate,
                incident_id: "incident-frozen-replay".to_string(),
                finding_id: Some("finding-evt-frozen-replay".to_string()),
                analyst_id: "analyst-frozen-replay".to_string(),
                reason: Some("freeze exact replay".to_string()),
            },
            &frozen,
            "feedback-frozen-replay",
            1_700_106_001_000,
        )
        .await
        .unwrap();
        let investigation = state
            .current_investigation()
            .load_by_hunt_id("evt-frozen-replay")
            .unwrap()
            .unwrap();
        assert_eq!(investigation.bundle.source_bundle_id, frozen_bundle_id);
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
            .query_concentration(&ThreatClass::Execution, super::now_ms().div_euclid(1_000))
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
            .query_concentration(&ThreatClass::Execution, super::now_ms().div_euclid(1_000))
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
            .query_concentration(&ThreatClass::Execution, super::now_ms().div_euclid(1_000))
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
        // Pin the agent key directory into this test's own root. `route_feedback_signal`
        // resolves Kitten's identity through `resolve_agent_key_dir`, so the fixture and
        // the handler must agree on where that key lives; without this they would share
        // the process-wide default under the config path's parent.
        applied_config.identity.agent_key_dir =
            applied_root.join("agent-keys").display().to_string();
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
        // Sign the population fixture with the identity the handler verifies against.
        // `route_feedback_signal` loads Kitten/primary from `identity.agent_key_dir` and
        // calls `load_trusted(&kitten_identity.id)`; signing with the ingest key makes
        // `SignedStateEnvelope::verify` return `SignerMismatch` -> `InvalidSignature` ->
        // HTTP 500. That signer pinning is a deliberate product property (966bae0), so
        // the fixture is what has to change.
        let kitten_identity =
            swarm_runtime::agent_identity::FileAgentKeyStore::open(applied_root.join("agent-keys"))
                .unwrap()
                .load_or_create(AgentRole::Kitten, "primary")
                .unwrap();
        persist_population_candidate(
            &applied_root.join("population"),
            "suspicious_process_tree",
            0.80,
            &kitten_identity.signing_key,
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
        let feedback_id = applied_json["feedback_id"].as_str().unwrap().to_string();

        let population_store =
            FileEvolutionPopulationStore::open(applied_root.join("population")).unwrap();
        let population = population_store.load().unwrap().unwrap();
        let penalized_fitness = population.members[0].fitness;
        assert!(penalized_fitness < 0.80);
        assert!(
            population.members[0]
                .blocking_reason_names
                .iter()
                .any(|reason| reason == "analyst_false_positive_feedback")
        );
        assert_eq!(population.applied_feedback_operations.len(), 1);

        // Simulate a crash after the signed population transaction committed but
        // before the append-only audit record became durable. The operation
        // ledger must make the retry repair the audit without applying a second
        // fitness penalty.
        let applied_record = load_feedback_signal_records(applied_root.join("population"))
            .unwrap()
            .into_iter()
            .find(|record| {
                record.disposition
                    == swarm_runtime::kitten_agent::FeedbackSignalDisposition::Applied
            })
            .unwrap();
        fs::remove_file(applied_root.join("population").join(FEEDBACK_SIGNALS_FILE)).unwrap();
        fs::remove_dir_all(applied_root.join("population").join("feedback-operations")).unwrap();
        let stack = applied_state.stack.load_full();
        let retried = route_feedback_signal(
            applied_state.config_path(),
            &stack.service.config,
            true,
            &SwarmFeedbackSignal {
                operation_id: Some(feedback_id),
                action: applied_record.action,
                incident_id: applied_record.incident_id.clone(),
                finding_id: applied_record.finding_id.clone(),
                strategy_id: applied_record.strategy_id.clone(),
                threat_class: applied_record.threat_class.clone(),
                analyst_id: applied_record.analyst_id.clone(),
                reason: applied_record.reason.clone(),
                recorded_at_ms: applied_record.recorded_at_ms,
            },
        )
        .unwrap();
        assert_eq!(
            retried.disposition,
            swarm_runtime::kitten_agent::FeedbackSignalDisposition::Applied
        );
        let retried_population = population_store.load().unwrap().unwrap();
        assert_eq!(retried_population.applied_feedback_operations.len(), 1);
        assert!((retried_population.members[0].fitness - penalized_fitness).abs() < f64::EPSILON);
        assert_eq!(
            load_feedback_signal_records(applied_root.join("population"))
                .unwrap()
                .len(),
            1
        );

        // Fill the signed population cache to its exact bound. The oldest
        // marker has an independently durable applied audit record, so the
        // next valid operation must roll that cache entry instead of imposing
        // a lifetime service ceiling.
        let signed_population_store = FileEvolutionPopulationStore::open_signed(
            applied_root.join("population"),
            kitten_identity.id.clone(),
            kitten_identity.signing_key.clone(),
        )
        .unwrap();
        let oldest_marker = retried_population
            .applied_feedback_operations
            .keys()
            .next()
            .unwrap()
            .clone();
        signed_population_store
            .update_trusted(&kitten_identity.id, |state| {
                for index in 1..swarm_runtime::mutation::MAX_EVOLUTION_APPLIED_FEEDBACK_OPERATIONS {
                    state.applied_feedback_operations.insert(
                        format!("{index:064x}"),
                        swarm_runtime::mutation::EvolutionAppliedFeedbackOperation {
                            operation_digest: format!("{:064x}", index + 1),
                            strategy_id: "suspicious_process_tree".to_string(),
                            penalty: 0.20,
                            applied_at_ms: applied_record.recorded_at_ms + index as i64,
                        },
                    );
                }
                Ok(true)
            })
            .unwrap();
        let rolled = route_feedback_signal(
            applied_state.config_path(),
            &stack.service.config,
            true,
            &SwarmFeedbackSignal {
                operation_id: Some("feedback-rollover-operation".to_string()),
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident-feedback-applied".to_string(),
                finding_id: Some("finding-evt-feedback-applied".to_string()),
                strategy_id: Some("suspicious_process_tree".to_string()),
                threat_class: Some(ThreatClass::Execution),
                analyst_id: "analyst-rollover".to_string(),
                reason: Some("exercise bounded rollover".to_string()),
                recorded_at_ms: applied_record.recorded_at_ms
                    + swarm_runtime::mutation::MAX_EVOLUTION_APPLIED_FEEDBACK_OPERATIONS as i64,
            },
        )
        .unwrap();
        assert_eq!(
            rolled.disposition,
            swarm_runtime::kitten_agent::FeedbackSignalDisposition::Applied
        );
        let rolled_population = population_store.load().unwrap().unwrap();
        assert_eq!(
            rolled_population.applied_feedback_operations.len(),
            swarm_runtime::mutation::MAX_EVOLUTION_APPLIED_FEEDBACK_OPERATIONS
        );
        assert!(
            !rolled_population
                .applied_feedback_operations
                .contains_key(&oldest_marker)
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
        assert!(pending_records.iter().any(|record| record.disposition
            == swarm_runtime::kitten_agent::FeedbackSignalDisposition::Pending));
    }
}

mod soar_verdict_sync {
    use super::*;
    use crate::ingest::soar_verdict_handlers::SOAR_VERDICT_CHANNEL;
    use swarm_core::types::{ProvidenceFeedbackAction, SoarSourceSystem, SwarmSoarVerdictRequest};
    use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};

    const SOAR_SECRET: &str = "soar-verdict-secret";
    const SOAR_HEADER: &str = "X-Swarm-Signature";

    fn configure_soar_channel(config: &mut SwarmConfig) {
        config.notification_channels.insert(
            SOAR_VERDICT_CHANNEL.to_string(),
            NotificationChannelConfig {
                target_url: "http://127.0.0.1:65535/verdicts".to_string(),
                auth_token: None,
                request_signature: Some(swarm_core::config::RequestSignatureConfig {
                    header: SOAR_HEADER.to_string(),
                    secret: SOAR_SECRET.into(),
                }),
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: super::temp_path("soar-verdict-dead").display().to_string(),
            },
        );
    }

    fn soar_signature(payload: &SwarmSoarVerdictRequest) -> String {
        let payload = serde_json::to_value(payload).unwrap();
        format!(
            "sha256={}",
            hmac_sha256_hex(
                SOAR_SECRET.as_bytes(),
                &canonical_json_bytes(&payload).unwrap()
            )
        )
    }

    fn signed_soar_request(payload: &SwarmSoarVerdictRequest) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/soar/verdicts")
            .header("content-type", "application/json")
            .header(SOAR_HEADER, soar_signature(payload))
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    fn seed_soar_incident(
        state: &IngestState,
        incident_id: &str,
        event_id: &str,
        host_id: &str,
        strategy_id: &str,
        created_at_ms: i64,
    ) {
        state
            .current_incident_store()
            .persist(&soar_incident(
                incident_id,
                event_id,
                host_id,
                strategy_id,
                created_at_ms,
            ))
            .unwrap();
    }

    fn soar_incident(
        incident_id: &str,
        event_id: &str,
        host_id: &str,
        strategy_id: &str,
        created_at_ms: i64,
    ) -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: incident_id.to_string(),
            summary: format!("soar incident for {event_id}"),
            created_at_ms,
            window_start_ms: created_at_ms,
            window_end_ms: created_at_ms + 1,
            correlation_keys: vec![format!("host:{host_id}")],
            related_receipt_ids: vec![format!("receipt-{event_id}")],
            included_members: vec![swarm_spine::IncidentMemberDecision {
                investigation_id: format!("investigation-{event_id}"),
                hunt_id: event_id.to_string(),
                finding_id: format!("finding-{event_id}"),
                reason: "soar fixture".to_string(),
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
        }
    }

    #[tokio::test]
    async fn inbound_soar_verdicts_apply_existing_feedback_paths_and_persist_lineage() {
        let mut config = super::test_config("suspicious_process_tree");
        enable_platform_api(&mut config);
        configure_soar_channel(&mut config);
        config.investigation.enabled = true;
        let state =
            IngestState::from_config(super::temp_path("soar-verdict-apply"), config).unwrap();
        for (event_id, host_id, incident_id, created_at_ms) in [
            (
                "evt-soar-splunk",
                "host-splunk",
                "incident-soar-splunk",
                1_700_130_000_000,
            ),
            (
                "evt-soar-sentinel",
                "host-sentinel",
                "incident-soar-sentinel",
                1_700_130_000_100,
            ),
            (
                "evt-soar-chronicle",
                "host-chronicle",
                "incident-soar-chronicle",
                1_700_130_000_200,
            ),
        ] {
            super::seed_platform_replay_bundle(&state, event_id, host_id, created_at_ms);
            seed_soar_incident(
                &state,
                incident_id,
                event_id,
                host_id,
                "suspicious_process_tree",
                created_at_ms,
            );
        }

        let app = detect_http_router(state.clone());
        for payload in [
            SwarmSoarVerdictRequest {
                source_system: SoarSourceSystem::SplunkSoar,
                source_verdict_id: "splunk-verdict-1".to_string(),
                verdict_at_ms: 1_700_130_001_000,
                action: ProvidenceFeedbackAction::Dismiss,
                incident_id: "incident-soar-splunk".to_string(),
                finding_id: Some("finding-evt-soar-splunk".to_string()),
                analyst_id: "splunk-analyst".to_string(),
                reason: Some("known false positive".to_string()),
                source_case_id: Some("splunk-case-42".to_string()),
                source_case_url: Some("https://splunk.example/cases/42".to_string()),
            },
            SwarmSoarVerdictRequest {
                source_system: SoarSourceSystem::SentinelSoar,
                source_verdict_id: "sentinel-verdict-1".to_string(),
                verdict_at_ms: 1_700_130_001_100,
                action: ProvidenceFeedbackAction::Confirm,
                incident_id: "incident-soar-sentinel".to_string(),
                finding_id: Some("finding-evt-soar-sentinel".to_string()),
                analyst_id: "sentinel-analyst".to_string(),
                reason: Some("confirmed malicious".to_string()),
                source_case_id: Some("sentinel-case-99".to_string()),
                source_case_url: None,
            },
            SwarmSoarVerdictRequest {
                source_system: SoarSourceSystem::ChronicleSoar,
                source_verdict_id: "chronicle-verdict-1".to_string(),
                verdict_at_ms: 1_700_130_001_200,
                action: ProvidenceFeedbackAction::Investigate,
                incident_id: "incident-soar-chronicle".to_string(),
                finding_id: Some("finding-evt-soar-chronicle".to_string()),
                analyst_id: "chronicle-analyst".to_string(),
                reason: Some("need deeper triage".to_string()),
                source_case_id: Some("chronicle-case-7".to_string()),
                source_case_url: Some("https://chronicle.example/cases/7".to_string()),
            },
        ] {
            let response = app
                .clone()
                .oneshot(signed_soar_request(&payload))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let splunk_lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-splunk")
            .unwrap()
            .unwrap();
        assert_eq!(splunk_lookup.incident.feedback_audit_entries.len(), 1);
        assert_eq!(splunk_lookup.incident.false_positive_measurements.len(), 1);
        let splunk_audit = &splunk_lookup.incident.feedback_audit_entries[0];
        let splunk_lineage = splunk_audit.soar_lineage.as_ref().unwrap();
        assert_eq!(splunk_lineage.source_system, SoarSourceSystem::SplunkSoar);
        assert_eq!(splunk_lineage.source_verdict_id, "splunk-verdict-1");
        assert_eq!(
            splunk_lookup.incident.false_positive_measurements[0]
                .soar_lineage
                .as_ref()
                .unwrap()
                .source_case_id
                .as_deref(),
            Some("splunk-case-42")
        );
        assert!(splunk_lookup.incident.false_positive_measurements[0].false_positive);

        let sentinel_lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-sentinel")
            .unwrap()
            .unwrap();
        assert_eq!(
            sentinel_lookup.incident.feedback_audit_entries[0]
                .soar_lineage
                .as_ref()
                .unwrap()
                .source_system,
            SoarSourceSystem::SentinelSoar
        );
        assert!(!sentinel_lookup.incident.false_positive_measurements[0].false_positive);

        let chronicle_lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-chronicle")
            .unwrap()
            .unwrap();
        assert_eq!(
            chronicle_lookup.incident.feedback_audit_entries[0]
                .soar_lineage
                .as_ref()
                .unwrap()
                .source_system,
            SoarSourceSystem::ChronicleSoar
        );
        assert_eq!(
            chronicle_lookup.incident.feedback_audit_entries[0].outcome["investigation"]["hunt_id"],
            "evt-soar-chronicle"
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
        let body: PlatformApiEnvelope<PlatformRuntimeStatus> = super::parse_json(response).await;
        let tracking = &body.data[0].false_positive_tracking;
        assert_eq!(tracking.reviewed_findings, 3);
        assert_eq!(tracking.false_positive_findings, 1);
    }

    #[tokio::test]
    async fn concurrent_exact_soar_retries_apply_once_and_conflicting_reuse_fails_closed() {
        let mut config = super::test_config("suspicious_process_tree");
        configure_soar_channel(&mut config);
        let state =
            IngestState::from_config(super::temp_path("soar-verdict-duplicate"), config).unwrap();
        super::seed_platform_replay_bundle(
            &state,
            "evt-soar-duplicate",
            "host-duplicate",
            1_700_130_100_000,
        );
        seed_soar_incident(
            &state,
            "incident-soar-duplicate",
            "evt-soar-duplicate",
            "host-duplicate",
            "suspicious_process_tree",
            1_700_130_100_000,
        );

        let payload = SwarmSoarVerdictRequest {
            source_system: SoarSourceSystem::SplunkSoar,
            source_verdict_id: "splunk-duplicate-1".to_string(),
            verdict_at_ms: 1_700_130_101_000,
            action: ProvidenceFeedbackAction::Dismiss,
            incident_id: "incident-soar-duplicate".to_string(),
            finding_id: Some("finding-evt-soar-duplicate".to_string()),
            analyst_id: "duplicate-analyst".to_string(),
            reason: Some("known duplicate".to_string()),
            source_case_id: Some("splunk-case-duplicate".to_string()),
            source_case_url: None,
        };

        let app = detect_http_router(state.clone());
        let (first, second) = tokio::join!(
            app.clone().oneshot(signed_soar_request(&payload)),
            app.clone().oneshot(signed_soar_request(&payload))
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        let first: Value = super::parse_json(first).await;
        let second: Value = super::parse_json(second).await;
        assert_eq!(first["feedback_id"], second["feedback_id"]);
        assert_eq!(first["outcome"], second["outcome"]);

        let mut completed_incident = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-duplicate")
            .unwrap()
            .unwrap()
            .incident;
        completed_incident.included_members.clear();
        completed_incident.trigger_finding_id = None;
        completed_incident.trigger_event_id = None;
        state
            .current_incident_store()
            .persist(&completed_incident)
            .unwrap();
        let retry_after_target_removal = app
            .clone()
            .oneshot(signed_soar_request(&payload))
            .await
            .unwrap();
        assert_eq!(retry_after_target_removal.status(), StatusCode::OK);

        let mut conflicting = payload.clone();
        conflicting.reason = Some("different verdict payload".to_string());
        let conflict = app
            .oneshot(signed_soar_request(&conflicting))
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);

        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-duplicate")
            .unwrap()
            .unwrap();
        assert_eq!(lookup.incident.false_positive_measurements.len(), 1);
        assert_eq!(lookup.incident.feedback_audit_entries.len(), 1);
        assert!(lookup.incident.feedback_audit_entries[0].evidence.is_some());
    }

    #[tokio::test]
    async fn rolling_upgrade_retry_preserves_the_durable_legacy_feedback_id() {
        let mut config = super::test_config("suspicious_process_tree");
        configure_soar_channel(&mut config);
        let state =
            IngestState::from_config(super::temp_path("soar-verdict-legacy-id"), config).unwrap();
        super::seed_platform_replay_bundle(
            &state,
            "evt-soar-legacy-id",
            "host-legacy-id",
            1_700_130_150_000,
        );
        let payload = SwarmSoarVerdictRequest {
            source_system: SoarSourceSystem::SplunkSoar,
            source_verdict_id: "legacy/case?42".to_string(),
            verdict_at_ms: 1_700_130_151_000,
            action: ProvidenceFeedbackAction::Dismiss,
            incident_id: "incident-soar-legacy-id".to_string(),
            finding_id: Some("finding-evt-soar-legacy-id".to_string()),
            analyst_id: "legacy-analyst".to_string(),
            reason: Some("rolling upgrade retry".to_string()),
            source_case_id: Some("legacy-case-42".to_string()),
            source_case_url: None,
        };
        let legacy_feedback_id = "soar-verdict:splunk_soar:legacy_case_42";
        let mut incident = soar_incident(
            "incident-soar-legacy-id",
            "evt-soar-legacy-id",
            "host-legacy-id",
            "suspicious_process_tree",
            1_700_130_150_000,
        );
        incident
            .feedback_audit_entries
            .push(swarm_spine::AnalystFeedbackAuditEntry {
                feedback_id: legacy_feedback_id.to_string(),
                received_at_ms: 1_700_130_151_100,
                action: payload.action,
                analyst_id: payload.analyst_id.clone(),
                incident_id: payload.incident_id.clone(),
                finding_id: payload.finding_id.clone(),
                reason: payload.reason.clone(),
                request_signature: soar_signature(&payload),
                evidence: None,
                soar_lineage: Some(swarm_core::types::SoarVerdictLineage {
                    source_system: payload.source_system,
                    source_verdict_id: payload.source_verdict_id.clone(),
                    verdict_at_ms: payload.verdict_at_ms,
                    source_case_id: payload.source_case_id.clone(),
                    source_case_url: payload.source_case_url.clone(),
                }),
                payload: serde_json::to_value(&payload).unwrap(),
                outcome: serde_json::json!({
                    "status": "recorded",
                    "target": {
                        "incident_id": "incident-soar-legacy-id",
                        "finding_id": "finding-evt-soar-legacy-id",
                        "hunt_id": "evt-soar-legacy-id",
                        "event_id": "evt-soar-legacy-id",
                        "evidence_timestamp": 1_700_130_150,
                        "host_id": "host-legacy-id",
                        "strategy_id": "suspicious_process_tree",
                        "threat_class": "execution",
                        "severity": "HIGH"
                    }
                }),
                soar_claim_lease: Some(swarm_spine::SoarVerdictClaimLease {
                    token: "pre-upgrade-expired-lease".to_string(),
                    issued_at_ms: None,
                    expires_at_ms: 1_700_130_151_101,
                }),
            });
        state.current_incident_store().persist(&incident).unwrap();

        let app = detect_http_router(state.clone());
        let retry = app.oneshot(signed_soar_request(&payload)).await.unwrap();
        let retry_status = retry.status();
        let retry: Value = super::parse_json(retry).await;
        assert_eq!(retry_status, StatusCode::OK, "retry response: {retry}");
        assert_eq!(retry["feedback_id"], legacy_feedback_id);
        let retained = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-legacy-id")
            .unwrap()
            .unwrap();
        assert_eq!(retained.incident.feedback_audit_entries.len(), 1);
        assert!(
            retained.incident.feedback_audit_entries[0]
                .evidence
                .is_some()
        );
        assert_eq!(retained.incident.false_positive_measurements.len(), 1);
    }

    #[tokio::test]
    async fn incomplete_soar_verdicts_fail_closed_and_persist_rejection_audit() {
        let mut config = super::test_config("suspicious_process_tree");
        configure_soar_channel(&mut config);
        let state =
            IngestState::from_config(super::temp_path("soar-verdict-incomplete"), config).unwrap();
        super::seed_platform_replay_bundle(
            &state,
            "evt-soar-incomplete",
            "host-incomplete",
            1_700_130_200_000,
        );
        seed_soar_incident(
            &state,
            "incident-soar-incomplete",
            "evt-soar-incomplete",
            "host-incomplete",
            "suspicious_process_tree",
            1_700_130_200_000,
        );

        let payload = SwarmSoarVerdictRequest {
            source_system: SoarSourceSystem::SentinelSoar,
            source_verdict_id: "".to_string(),
            verdict_at_ms: 1_700_130_201_000,
            action: ProvidenceFeedbackAction::Confirm,
            incident_id: "incident-soar-incomplete".to_string(),
            finding_id: Some("finding-evt-soar-incomplete".to_string()),
            analyst_id: "incomplete-analyst".to_string(),
            reason: Some("missing upstream verdict id".to_string()),
            source_case_id: Some("sentinel-case-incomplete".to_string()),
            source_case_url: None,
        };

        let app = detect_http_router(state.clone());
        let response = app
            .clone()
            .oneshot(signed_soar_request(&payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-incomplete")
            .unwrap()
            .unwrap();
        assert!(lookup.incident.false_positive_measurements.is_empty());
        assert_eq!(lookup.incident.feedback_audit_entries.len(), 1);
        let rejected = &lookup.incident.feedback_audit_entries[0];
        assert_eq!(rejected.outcome["status"], "rejected");
        assert_eq!(
            rejected.outcome["reason"],
            "source_verdict_id must not be empty"
        );
        assert_eq!(
            rejected.soar_lineage.as_ref().unwrap().source_system,
            SoarSourceSystem::SentinelSoar
        );

        let mut corrected = payload;
        corrected.source_verdict_id = "sentinel-corrected-redelivery".to_string();
        corrected.analyst_id.clear();
        let rejected = app
            .clone()
            .oneshot(signed_soar_request(&corrected))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        corrected.analyst_id = "corrected-analyst".to_string();
        let accepted = app.oneshot(signed_soar_request(&corrected)).await.unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);

        let lookup = state
            .current_incident_store()
            .load_by_incident_id("incident-soar-incomplete")
            .unwrap()
            .unwrap();
        assert_eq!(
            lookup
                .incident
                .feedback_audit_entries
                .iter()
                .filter(|entry| {
                    entry.soar_lineage.as_ref().is_some_and(|lineage| {
                        lineage.source_verdict_id == "sentinel-corrected-redelivery"
                    })
                })
                .count(),
            2,
            "the rejected audit is retained while corrected redelivery completes"
        );
        assert_eq!(lookup.incident.false_positive_measurements.len(), 1);
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
    let report = swarm_runtime::evolution_status::DefaultEvolutionStatusHarness::from_config(
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
async fn live_ingest_defers_governed_playbook_action_but_deposits_and_forwards() {
    let mut config = live_response_playbook_config(ResponseAction::BlockEgress {
        target: "203.0.113.25".to_string(),
    });
    config.policy.rules = vec![PolicyRuleConfig {
        name: "would-execute-without-governance-boundary".to_string(),
        decision: PolicyRuleDecision::Allow,
        threat_class: ThreatClass::Execution,
        actions: vec![PolicyActionSelector::BlockEgress],
        min_severity: Severity::Critical,
        max_severity: Severity::Critical,
        time_window_utc: None,
        max_actions_per_agent_per_minute: None,
        reason: Some("security regression fixture".to_string()),
    }];
    let (tx, mut rx) = mpsc::channel(4);
    let state = IngestState::from_config(temp_path("governed-live-ingest"), config)
        .unwrap()
        .with_startup_attestation(verified_startup_attestation_report())
        .with_telemetry_channel(tx);
    let app = ingest_router(state.clone());

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
    assert_eq!(rx.recv().await.unwrap().event_id, "evt-ingest-1");
    let deposits = state.current_substrate().recent_deposits(10).await.unwrap();
    assert_eq!(deposits.len(), 1, "the finding must still be deposited");
    assert_eq!(deposits[0].indicator["event_id"], "evt-ingest-1");
    assert!(
        state.current_replay_store().recent(10).unwrap().is_empty(),
        "direct ingest must not propose or execute a governed action"
    );
}

#[tokio::test]
async fn live_ingest_still_executes_non_governed_playbook_action() {
    let config = live_response_playbook_config(ResponseAction::Escalate {
        summary: "notify the response team".to_string(),
        urgency: Severity::Critical,
    });
    let state = IngestState::from_config(temp_path("non-governed-live-ingest"), config)
        .unwrap()
        .with_startup_attestation(verified_startup_attestation_report());
    let app = ingest_router(state.clone());

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
    let decisions = state.current_replay_store().recent(10).unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].action_kind, "escalate");
    assert_eq!(decisions[0].response_kind, "success");
}

#[tokio::test]
async fn bridge_ingest_defers_governed_playbook_action_and_forwards_to_agents() {
    let config = live_response_playbook_config(ResponseAction::IsolateHost {
        host_id: "host-1".to_string(),
    });
    let (tx, mut rx) = mpsc::channel(4);
    let state = IngestState::from_config(temp_path("governed-bridge-ingest"), config)
        .unwrap()
        .with_startup_attestation(verified_startup_attestation_report())
        .with_telemetry_channel(tx);
    let event = validate_and_parse(valid_process_event_json()).unwrap();

    state.process_bridge_event(event).await.unwrap();

    assert_eq!(rx.recv().await.unwrap().event_id, "evt-ingest-1");
    assert_eq!(
        state
            .current_substrate()
            .recent_deposits(10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(state.current_replay_store().recent(10).unwrap().is_empty());
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
    let governance_root = temp_dir("healthz-governance");
    let governance_policy = Arc::new(
        GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig {
                contingency_lease_ttl_ms: 60_000,
                contingency_blast_radius_cap: 1,
            },
            governance_root.join("governance.json"),
            AgentId::new("tom", "primary"),
            ed25519_dalek::SigningKey::from_bytes(&[29; 32]),
        )
        .expect("test governance should initialize signed persistence"),
    );
    let governance_authority = governance_policy
        .authority()
        .expect("persisted test governance should mint authority");
    governance_policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "tom-primary".to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }],
        1_700_000_000_000,
    );

    let app =
        detect_http_router(test_ingest_state().with_governance_authority(governance_authority));
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
    drop(governance_policy);
    let _ = fs::remove_dir_all(governance_root);
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
            auth_token: Some("providence-api-bearer".into()),
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
            auth_token: Some("providence-api-bearer".into()),
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

/// Narrowness guard for the tolerant `query_escalations` branch in
/// `RuntimeService::operator_status`. Tolerating a substrate escalation-read
/// failure must not disable async-lane gating in general: a genuine async-lane
/// fault still has to fail `/readyz`.
#[tokio::test]
async fn readyz_still_fails_for_a_genuine_async_lane_store_fault() {
    let investigation_root = temp_path("async-lane-store-fault").with_extension("dir");
    let mut config = live_response_config("suspicious_process_tree");
    config.investigation.enabled = true;
    config.investigation.bundle_store = BundleStoreConfig::LocalFiles {
        directory: investigation_root.display().to_string(),
    };
    let state = IngestState::from_config(temp_path("async-lane-store-fault-config"), config)
        .unwrap()
        .with_startup_attestation(verified_startup_attestation_report());
    let bundles_dir = investigation_root.join("bundles");
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
    assert_eq!(json["components"]["async_lane"]["ready"], false);
    assert_eq!(json["components"]["async_lane"]["status"], "degraded");
    assert!(
        json["components"]["async_lane"]["details"]
            .as_str()
            .unwrap_or_default()
            .contains("investigation store"),
        "async lane must name the investigation store fault: {}",
        json["components"]["async_lane"]
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
                auth_token: "@secret:edr-token".into(),
                timeout_ms: 1_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                // Live adapter config: the cwd-relative default would append to
                // the checked-out `crates/swarm-runtime/dead-letter.jsonl`.
                dead_letter_path: temp_path("http-edr-dead-letter").display().to_string(),
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
            assert_eq!(edr.auth_token.expose_secret(), "initial-value");
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
            assert_eq!(edr.auth_token.expose_secret(), "rotated-value");
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
            assert_eq!(edr.auth_token.expose_secret(), "fresh-token");
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
                auth_token: SecretString::from("secret"),
                timeout_ms: 1_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        }),
        "http_edr"
    );
    assert_eq!(
        response_adapter_kind(&ResponseAdapterConfig::CrowdStrikeRtr {
            config: swarm_core::config::CrowdStrikeRtrConfig {
                base_url: "https://api.crowdstrike.example".to_string(),
                client_id: SecretString::from("client-id"),
                client_secret: SecretString::from("client-secret"),
                timeout_ms: 1_000,
                retry: RetryConfig::default(),
                circuit_breaker: CircuitBreakerConfig::default(),
                dead_letter_path: "./dead-letter.jsonl".to_string(),
            },
        }),
        "crowdstrike_rtr"
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
