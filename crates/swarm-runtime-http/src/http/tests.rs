#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::LocalOperatorSurface;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::post;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use swarm_agents::tom_agent::{GovernanceDecision, GovernancePolicy, GovernancePolicyConfig};
use swarm_core::agent::{
    AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError,
};
use swarm_core::config::{
    AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
    DetectorProfilesConfig, InvestigationConfig, NotificationChannelConfig,
    NotificationRateLimitConfig, NotificationRoutingConfig, OperatorAuthConfig,
    OperatorPrincipalConfig, OperatorScope, OperatorSurfaceConfig, OperatorSurfacePaths,
    PheromoneBackendConfig, PheromoneConfig, PolicyActionSelector, PolicyConfig, PolicyRuleConfig,
    PolicyRuleDecision, PromotionConfig, QuietHoursConfig, RoutingRule, RuntimeSettings,
    SwarmConfig, TelemetrySourceConfig,
};
use swarm_core::pheromone::{
    ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::types::{
    AgentId, HuntId, ProvidenceIncidentReconciliation, ProvidenceIncidentStatus,
    ProvidenceReconciliationOutcome, ResponseAction, ResponseBlastRadiusImpact,
    ResponseBlastRadiusPreview, ResponseRehearsalPreview, ResponseRehearsalScopeKind,
    ResponseRollbackPreview, ResponseRollbackStep, ResponseRollbackStepKind, Severity, SwarmAction,
};
use swarm_crypto::{Ed25519Signer, canonical_json_bytes};
use swarm_evolution::evidence::{
    EvidenceBundle, EvidenceRelatedRef, EvidenceSignature, EvidenceSubjectKind,
    EvidenceSubjectMetadata, EvidenceVerificationReport, EvidenceVerificationStatus,
    FileEvidenceBundleStore, FileEvidenceVerificationStore, FilePromotionEvidencePacketStore,
    PromotionEvidenceAttachment, PromotionEvidencePacket, PromotionEvidenceRecommendation,
};
use swarm_ingest_runtime::control::{
    CURRENT_OPERATOR_API_SCHEMA_VERSION, OPERATOR_API_SCHEMA_VERSION_HEADER,
};
use swarm_ingest_runtime::ingest::{IngestState, detect_http_router};
use swarm_policy::{ActionRequest, ApprovalContext};
use swarm_response::SwarmFindingEnvelope;
use swarm_runtime::approval::{DefaultApprovalHarness, ThresholdRule};
use swarm_runtime::dispatcher::{AgentDispatcher, AgentDispatcherConfig};
use swarm_runtime::replay::{
    ExperimentLineage, ReplayScenarioClass, ReplayScenarioInput, ReplayScenarioManifest,
    ReplayScenarioMetadata, ReplayScenarioStep,
};
use swarm_runtime::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
use swarm_runtime::service::EventExecutionContext;
use swarm_spine::{
    AuditResponseRecord, AuditTrail, CorrelatedIncident, IncidentMemberDecision, IncidentStore,
    PolicyRecord, ReplayBundle, ReplayBundleStore,
};
use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};
use tower::ServiceExt;

use swarm_evolution::governance_prep::{
    EvolutionGovernancePacketSetEntryReport, EvolutionGovernancePacketSetReport,
    EvolutionPortfolioHistoryCohortSummary, EvolutionPortfolioHistoryEntryReport,
    EvolutionPortfolioHistoryOutcomeCounts, EvolutionPortfolioHistoryOutcomeKind,
    EvolutionPortfolioHistoryReport, EvolutionPortfolioHistoryReviewDebtKind,
    FileEvolutionGovernancePacketSetStore, FileEvolutionPortfolioHistoryStore,
};
use swarm_evolution::portfolio::{
    EvolutionGovernanceReviewPacketReport, EvolutionPortfolioDecisionRecord,
    EvolutionPortfolioEntryReport, EvolutionPortfolioEntryReviewState, EvolutionPortfolioReport,
    FileEvolutionGovernanceReviewPacketStore, FileEvolutionPortfolioStore,
};
use swarm_runtime::drafting::EvolutionValidationBundleStatus;
use swarm_runtime::evolution::{
    EvolutionProposalBlockingReason, EvolutionProposalProofStatus, EvolutionProposalProofSummary,
    EvolutionProposalReviewState,
};
use swarm_runtime_workbench::review_workbench::DefaultReviewWorkbenchHarness;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

struct OneShotGovernedRequestAgent {
    id: AgentId,
    verifying_key: ed25519_dalek::VerifyingKey,
    actions: Option<Vec<SwarmAction>>,
}

impl OneShotGovernedRequestAgent {
    fn new(id: AgentId, actions: Vec<SwarmAction>) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        Self {
            id,
            verifying_key: signing_key.verifying_key(),
            actions: Some(actions),
        }
    }
}

#[async_trait]
impl SwarmAgent for OneShotGovernedRequestAgent {
    fn identity(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        AgentRole::Pouncer
    }

    fn observe_event(&mut self, _event: &swarm_core::agent::SwarmEvent) -> Result<(), SwarmError> {
        Ok(())
    }

    async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        Ok(self.actions.take().unwrap_or_default())
    }

    fn health(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
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

fn operator_config() -> SwarmConfig {
    SwarmConfig {
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
            human_gate_severity: swarm_core::types::Severity::High,
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
            },
        },
        tls: None,
    }
}

fn scoped_operator_config(
    context_token_env: &str,
    principals: Vec<OperatorPrincipalConfig>,
) -> SwarmConfig {
    let mut config = operator_config();
    config.operator.auth.context_token_env = context_token_env.to_string();
    config.operator.auth.principals = principals;
    config
}

fn unique_temp_dir(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.push(format!(
        "swarm-team-six-operator-http-{}-{}-{}",
        label,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        counter
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn event(event_id: &str, command_line: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "synthetic".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host-1".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "winword".to_string(),
            process_name: "powershell".to_string(),
            command_line: command_line.to_string(),
            user: Some("alice".to_string()),
            executable_path: None,
            signer: None,
            signature_valid: None,
        }),
    }
}

fn approval_context(now_ms: i64) -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
        correlation_id: None,
        now_ms,
    }
}

#[derive(Clone, Default)]
struct NotificationCaptureState {
    payloads: Arc<AsyncMutex<Vec<Value>>>,
    auth_headers: Arc<AsyncMutex<Vec<Option<String>>>>,
    replay_headers: Arc<AsyncMutex<Vec<Option<String>>>>,
}

async fn notification_capture_handler(
    State(state): State<NotificationCaptureState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    {
        let mut payloads = state.payloads.lock().await;
        payloads.push(payload);
    }
    {
        let mut auth_headers = state.auth_headers.lock().await;
        auth_headers.push(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string),
        );
    }
    {
        let mut replay_headers = state.replay_headers.lock().await;
        replay_headers.push(
            headers
                .get("x-swarm-replay")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string),
        );
    }
    (StatusCode::OK, Json(json!({"ok": true})))
}

async fn spawn_notification_capture_server() -> (
    String,
    NotificationCaptureState,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let state = NotificationCaptureState::default();
    let app = Router::new()
        .route("/", post(notification_capture_handler))
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

#[derive(Clone, Default)]
struct ApprovalResumeCaptureState {
    requests: Arc<AsyncMutex<Vec<(String, Value)>>>,
}

async fn approval_resume_capture_handler(
    State(state): State<ApprovalResumeCaptureState>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state
        .requests
        .lock()
        .await
        .push((uri.path().to_string(), body));
    (StatusCode::OK, Json(json!({"ok": true})))
}

async fn spawn_approval_resume_capture_server() -> (
    String,
    ApprovalResumeCaptureState,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let state = ApprovalResumeCaptureState::default();
    let app = Router::new()
        .route("/{*path}", post(approval_resume_capture_handler))
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
    (format!("http://{address}"), state, shutdown_tx, handle)
}

fn notification_operator_config(target_url: String, dead_letter_path: String) -> SwarmConfig {
    let mut config = operator_config();
    config.notification_channels.insert(
        "pager".to_string(),
        NotificationChannelConfig {
            target_url,
            auth_token: Some("notify-secret".into()),
            request_signature: None,
            timeout_ms: 500,
            rate_limit: NotificationRateLimitConfig {
                max_notifications: 5,
                window_ms: 60_000,
            },
            quiet_hours: Some(QuietHoursConfig {
                start_hour_utc: 0,
                end_hour_utc: 0,
            }),
            dead_letter_path,
        },
    );
    config.notification_routing = NotificationRoutingConfig {
        dedup_window_ms: 1,
        rules: vec![RoutingRule {
            min_severity: Some(Severity::High),
            threat_class: Some(ThreatClass::Execution),
            utc_start_hour: None,
            utc_end_hour: None,
            channels: vec!["pager".to_string()],
        }],
    };
    config
}

fn sample_lineage(strategy_id: &str) -> ExperimentLineage {
    ExperimentLineage {
        parent_strategy_id: "office_baseline_control".to_string(),
        mutation: format!("mutation_for_{strategy_id}"),
        rationale: format!("rationale for {strategy_id}"),
    }
}

fn sample_governance_packet(
    packet_id: &str,
    strategy_id: &str,
    cohort: &str,
    ready_for_governance: bool,
) -> EvolutionGovernanceReviewPacketReport {
    let blocking_reasons = if ready_for_governance {
        Vec::new()
    } else {
        vec![EvolutionProposalBlockingReason {
            source: "governance_packet".to_string(),
            name: "candidate_blocked".to_string(),
            details: "candidate remained blocked during governance packet preparation".to_string(),
            references: vec![packet_id.to_string()],
        }]
    };
    EvolutionGovernanceReviewPacketReport {
        packet_id: packet_id.to_string(),
        portfolio_id: format!("portfolio:{cohort}"),
        portfolio_name: format!("portfolio {cohort}"),
        entry_id: format!("entry:{packet_id}"),
        selection_id: format!("selection:{strategy_id}"),
        ranking_id: format!("ranking:{strategy_id}"),
        validation_batch_id: format!("validation_batch:{strategy_id}"),
        mutation_spec_id: format!("mutation_spec:{strategy_id}"),
        created_at_ms: 1_710_000_000_000,
        cohort: cohort.to_string(),
        rank: 1,
        strategy_id: strategy_id.to_string(),
        strategy_description: format!("strategy {strategy_id}"),
        score: 0.91,
        summary: format!("summary for {strategy_id}"),
        materialization_id: format!("materialization:{strategy_id}"),
        validation_bundle_id: format!("validation_bundle:{strategy_id}"),
        experiment_id: format!("experiment:{strategy_id}"),
        experiment_name: format!("experiment {strategy_id}"),
        experiment_path: format!("/tmp/{strategy_id}.yaml"),
        lineage: sample_lineage(strategy_id),
        manifest_sha256: format!("manifest_sha_for_{strategy_id}"),
        lineage_sha256: format!("lineage_sha_for_{strategy_id}"),
        verification_id: format!("verification:{strategy_id}"),
        verification_passed: ready_for_governance,
        proof_status: if ready_for_governance {
            EvolutionProposalProofStatus::Proved
        } else {
            EvolutionProposalProofStatus::Missing
        },
        proof: ready_for_governance.then(|| EvolutionProposalProofSummary {
            proof_id: format!("proof:{strategy_id}"),
            proof_system: "repo_owned".to_string(),
            attestation_sha256: format!("attestation_sha_for_{strategy_id}"),
            invariant_count: 4,
        }),
        advisory: None,
        shadow_id: format!("shadow:{strategy_id}"),
        shadow_passed: ready_for_governance,
        validation_status: if ready_for_governance {
            EvolutionValidationBundleStatus::ReadyForQueue
        } else {
            EvolutionValidationBundleStatus::Blocked
        },
        parent_queue_proposal_id: Some(format!("proposal:{strategy_id}")),
        parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
        selection_review_state: if ready_for_governance {
            EvolutionProposalReviewState::AcceptedForCanary
        } else {
            EvolutionProposalReviewState::Blocked
        },
        portfolio_review_state: if ready_for_governance {
            EvolutionPortfolioEntryReviewState::Included
        } else {
            EvolutionPortfolioEntryReviewState::Blocked
        },
        operator_reason: "prepare for governance-prep review".to_string(),
        ready_for_governance,
        blocking_reasons,
    }
}

fn sample_portfolio_report() -> EvolutionPortfolioReport {
    EvolutionPortfolioReport {
        portfolio_id: "portfolio:red".to_string(),
        portfolio_name: "red portfolio".to_string(),
        operator_rationale: "review red cohort".to_string(),
        created_at_ms: 1_710_000_000_100,
        entries: vec![EvolutionPortfolioEntryReport {
            entry_id: "entry:packet:red:ready".to_string(),
            selection_id: "selection:office_red_ready_v1".to_string(),
            ranking_id: "ranking:office_red_ready_v1".to_string(),
            validation_batch_id: "validation_batch:office_red_ready_v1".to_string(),
            mutation_spec_id: "mutation_spec:office_red_ready_v1".to_string(),
            cohort: "red".to_string(),
            rank: 1,
            strategy_id: "office_red_ready_v1".to_string(),
            strategy_description: "strategy office_red_ready_v1".to_string(),
            score: 0.91,
            summary: "summary for office_red_ready_v1".to_string(),
            materialization_id: "materialization:office_red_ready_v1".to_string(),
            validation_bundle_id: "validation_bundle:office_red_ready_v1".to_string(),
            experiment_id: "experiment:office_red_ready_v1".to_string(),
            experiment_name: "experiment office_red_ready_v1".to_string(),
            experiment_path: "/tmp/office_red_ready_v1.yaml".to_string(),
            lineage: sample_lineage("office_red_ready_v1"),
            manifest_sha256: "manifest_sha_for_office_red_ready_v1".to_string(),
            lineage_sha256: "lineage_sha_for_office_red_ready_v1".to_string(),
            verification_id: "verification:office_red_ready_v1".to_string(),
            verification_passed: true,
            proof_status: EvolutionProposalProofStatus::Proved,
            proof: Some(EvolutionProposalProofSummary {
                proof_id: "proof:office_red_ready_v1".to_string(),
                proof_system: "repo_owned".to_string(),
                attestation_sha256: "attestation_sha_for_office_red_ready_v1".to_string(),
                invariant_count: 4,
            }),
            advisory: None,
            shadow_id: "shadow:office_red_ready_v1".to_string(),
            shadow_passed: true,
            validation_status: EvolutionValidationBundleStatus::ReadyForQueue,
            parent_queue_proposal_id: Some("proposal:office_red_ready_v1".to_string()),
            parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
            selection_review_state: EvolutionProposalReviewState::AcceptedForCanary,
            portfolio_review_state: EvolutionPortfolioEntryReviewState::Included,
            blocking_reasons: Vec::new(),
            decision_history: vec![EvolutionPortfolioDecisionRecord {
                decided_at_ms: 1_710_000_000_120,
                action: swarm_evolution::portfolio::EvolutionPortfolioDecisionAction::Include,
                reason: "include the ready portfolio entry".to_string(),
            }],
        }],
    }
}

fn sample_packet_set_report() -> EvolutionGovernancePacketSetReport {
    EvolutionGovernancePacketSetReport {
        packet_set_id: "packet_set:red:1".to_string(),
        packet_set_name: "red review set".to_string(),
        operator_rationale: "group red governance packets".to_string(),
        created_at_ms: 1_710_000_000_200,
        parent_packet_set_id: None,
        entries: vec![EvolutionGovernancePacketSetEntryReport {
            packet_set_entry_id: "packet_set_entry:packet:red:ready:0".to_string(),
            source_packet_set_entry_id: None,
            packet_id: "packet:red:ready".to_string(),
            source_packet_created_at_ms: 1_710_000_000_000,
            operator_reason: "prepare for governance-prep review".to_string(),
            portfolio_id: "portfolio:red".to_string(),
            portfolio_name: "red portfolio".to_string(),
            portfolio_entry_id: "entry:packet:red:ready".to_string(),
            selection_id: "selection:office_red_ready_v1".to_string(),
            ranking_id: "ranking:office_red_ready_v1".to_string(),
            validation_batch_id: "validation_batch:office_red_ready_v1".to_string(),
            mutation_spec_id: "mutation_spec:office_red_ready_v1".to_string(),
            cohort: "red".to_string(),
            rank: 1,
            strategy_id: "office_red_ready_v1".to_string(),
            strategy_description: "strategy office_red_ready_v1".to_string(),
            score: 0.91,
            summary: "summary for office_red_ready_v1".to_string(),
            materialization_id: "materialization:office_red_ready_v1".to_string(),
            validation_bundle_id: "validation_bundle:office_red_ready_v1".to_string(),
            experiment_id: "experiment:office_red_ready_v1".to_string(),
            experiment_name: "experiment office_red_ready_v1".to_string(),
            experiment_path: "/tmp/office_red_ready_v1.yaml".to_string(),
            lineage: sample_lineage("office_red_ready_v1"),
            manifest_sha256: "manifest_sha_for_office_red_ready_v1".to_string(),
            lineage_sha256: "lineage_sha_for_office_red_ready_v1".to_string(),
            verification_id: "verification:office_red_ready_v1".to_string(),
            verification_passed: true,
            proof_status: EvolutionProposalProofStatus::Proved,
            proof: Some(EvolutionProposalProofSummary {
                proof_id: "proof:office_red_ready_v1".to_string(),
                proof_system: "repo_owned".to_string(),
                attestation_sha256: "attestation_sha_for_office_red_ready_v1".to_string(),
                invariant_count: 4,
            }),
            advisory: None,
            shadow_id: "shadow:office_red_ready_v1".to_string(),
            shadow_passed: true,
            validation_status: EvolutionValidationBundleStatus::ReadyForQueue,
            parent_queue_proposal_id: Some("proposal:office_red_ready_v1".to_string()),
            parent_queue_review_state: Some(EvolutionProposalReviewState::AcceptedForCanary),
            selection_review_state: EvolutionProposalReviewState::AcceptedForCanary,
            portfolio_review_state: EvolutionPortfolioEntryReviewState::Included,
            ready_for_governance: true,
            blocking_reasons: Vec::new(),
        }],
    }
}

fn sample_portfolio_history_report() -> EvolutionPortfolioHistoryReport {
    EvolutionPortfolioHistoryReport {
        history_id: "portfolio_history:red:1".to_string(),
        packet_set_id: "packet_set:red:1".to_string(),
        packet_set_name: "red review set".to_string(),
        created_at_ms: 1_710_000_000_300,
        outcomes: EvolutionPortfolioHistoryOutcomeCounts {
            entry_count: 1,
            survived_count: 1,
            stable_count: 1,
            ready_for_promotion_review_count: 0,
            blocked_count: 0,
            halted_count: 0,
            unobserved_count: 0,
            review_debt_count: 0,
        },
        cohorts: vec![EvolutionPortfolioHistoryCohortSummary {
            cohort: "red".to_string(),
            entry_count: 1,
            survived_count: 1,
            stable_count: 1,
            blocked_count: 0,
            halted_count: 0,
            unobserved_count: 0,
            review_debt_count: 0,
        }],
        entries: vec![EvolutionPortfolioHistoryEntryReport {
            packet_set_entry_id: "packet_set_entry:packet:red:ready:0".to_string(),
            packet_id: "packet:red:ready".to_string(),
            portfolio_id: "portfolio:red".to_string(),
            portfolio_name: "red portfolio".to_string(),
            portfolio_entry_id: "entry:packet:red:ready".to_string(),
            cohort: "red".to_string(),
            strategy_id: "office_red_ready_v1".to_string(),
            strategy_description: "strategy office_red_ready_v1".to_string(),
            ready_for_governance: true,
            blocking_reasons: Vec::new(),
            memory_ids: vec!["memory:office_red_ready_v1:1".to_string()],
            latest_rollout_state: Some(swarm_runtime::strategy::StrategyRolloutStateSummary {
                source_kind: swarm_runtime::strategy::StrategyMemorySourceKind::Promotion,
                source_artifact_id: "promotion:office_red_ready_v1".to_string(),
                outcome_kind:
                    swarm_runtime::strategy::StrategyMemoryOutcomeKind::StableInProduction,
                observed_at_ms: 1_710_000_000_250,
            }),
            outcome: EvolutionPortfolioHistoryOutcomeKind::StableInProduction,
            survived_live_rollout: true,
            review_debt: Some(EvolutionPortfolioHistoryReviewDebtKind::AwaitingStableOutcome),
        }],
    }
}

fn sample_subject_evidence_bundle(
    kind: EvidenceSubjectKind,
    stable_id: &str,
    payload_sha256: &str,
    canonical_payload: &str,
    related_refs: Vec<EvidenceRelatedRef>,
) -> EvidenceBundle {
    EvidenceBundle {
        bundle_id: format!(
            "evidence:{}:{}:local-evidence-signer",
            kind.as_str(),
            stable_id
        ),
        schema_version: "v1".to_string(),
        config_name: "operator-http".to_string(),
        exported_at_ms: 1_710_000_000_500,
        subject: EvidenceSubjectMetadata {
            kind,
            stable_id: stable_id.to_string(),
            display_name: format!("{} {stable_id}", kind.as_str()),
            source_created_at_ms: 1_710_000_000_000,
            receipt_chain_refs: vec![],
            related_refs,
        },
        payload_sha256: payload_sha256.to_string(),
        canonical_payload: canonical_payload.to_string(),
        signature: EvidenceSignature {
            signer_id: "local-evidence-signer".to_string(),
            algorithm: "ed25519".to_string(),
            key_id: "key:red".to_string(),
            public_key_hex: "11".repeat(32),
            signature_hex: "22".repeat(64),
        },
    }
}

fn sample_evidence_bundle() -> EvidenceBundle {
    sample_subject_evidence_bundle(
        EvidenceSubjectKind::ProductionPromotion,
        "promotion:red",
        "abcd1234",
        r#"{"promotion_id":"promotion:red","status":"completed"}"#,
        vec![EvidenceRelatedRef {
            kind: "canary_run".to_string(),
            id: "canary:red".to_string(),
        }],
    )
}

fn sample_canary_evidence_bundle() -> EvidenceBundle {
    sample_subject_evidence_bundle(
        EvidenceSubjectKind::CanaryRun,
        "canary:red",
        "beefcafe",
        r#"{"run_id":"canary:red","status":"completed"}"#,
        vec![EvidenceRelatedRef {
            kind: "promotion_review".to_string(),
            id: "review:red".to_string(),
        }],
    )
}

fn sample_promotion_review_evidence_bundle() -> EvidenceBundle {
    sample_subject_evidence_bundle(
        EvidenceSubjectKind::PromotionReview,
        "review:red",
        "facefeed",
        r#"{"review_id":"review:red","recommendation":"ready_for_manual_review"}"#,
        vec![
            EvidenceRelatedRef {
                kind: "verification".to_string(),
                id: "verification:red".to_string(),
            },
            EvidenceRelatedRef {
                kind: "shadow".to_string(),
                id: "shadow:red".to_string(),
            },
        ],
    )
}

fn sample_subject_verification_report(
    kind: EvidenceSubjectKind,
    stable_id: &str,
    bundle_id: &str,
) -> EvidenceVerificationReport {
    EvidenceVerificationReport {
        verification_id: format!("evidence_verification:{bundle_id}"),
        bundle_id: bundle_id.to_string(),
        subject_kind: kind,
        subject_id: stable_id.to_string(),
        verified_at_ms: 1_710_000_000_800,
        status: EvidenceVerificationStatus::Passed,
        signer_id: "local-evidence-signer".to_string(),
        signer_key_id: "key:red".to_string(),
        expected_key_id: Some("key:red".to_string()),
        checks: vec![swarm_evolution::evidence::EvidenceVerificationCheck {
            name: "canonical_payload".to_string(),
            passed: true,
            details: "canonical payload bytes normalized cleanly".to_string(),
        }],
    }
}

fn sample_promotion_evidence_packet() -> PromotionEvidencePacket {
    PromotionEvidencePacket {
            packet_id: "promotion_evidence:promotion:red".to_string(),
            promotion_id: "promotion:red".to_string(),
            created_at_ms: 1_710_000_000_900,
            window_id: "production-primary".to_string(),
            promotion_status: swarm_runtime::promotion::ProductionPromotionStatus::Completed,
            promoted_strategy_id: "office_red_ready_v1".to_string(),
            fallback_strategy_id: "office_control_v1".to_string(),
            canary_run_id: "canary:red".to_string(),
            verification_id:
                "evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer"
                    .to_string(),
            shadow_id: "shadow:red".to_string(),
            supporting_evidence: vec![PromotionEvidenceAttachment {
                subject_kind: EvidenceSubjectKind::ProductionPromotion,
                subject_id: "promotion:red".to_string(),
                bundle_id: Some(
                    "evidence:production_promotion:promotion:red:local-evidence-signer"
                        .to_string(),
                ),
                verification_id: Some(
                    "evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer"
                        .to_string(),
                ),
                verification_status: Some(EvidenceVerificationStatus::Passed),
                details: "production promotion evidence".to_string(),
            }],
            blocking_reasons: vec![],
            recommendation: PromotionEvidenceRecommendation::ReadyForExternalReview,
            advisory_only: true,
        }
}

fn surface_paths(root: &std::path::Path) -> OperatorSurfacePaths {
    OperatorSurfacePaths {
        evidence_signer_id: "local-evidence-signer".to_string(),
        evidence_signing_key_env: "SWARM_EVIDENCE_SIGNING_KEY".to_string(),
        verification_results_dir: root.join("detector-verifications"),
        shadow_results_dir: root.join("strategy-shadows"),
        promotion_review_results_dir: root.join("promotion-reviews"),
        canary_results_dir: root.join("canary-runs"),
        promotion_results_dir: root.join("promotions"),
        evolution_ranking_results_dir: root.join("rankings"),
        evolution_selection_results_dir: root.join("selections"),
        evolution_portfolio_results_dir: root.join("portfolios"),
        evolution_governance_review_packet_results_dir: root.join("governance-packets"),
        evolution_packet_set_results_dir: root.join("packet-sets"),
        strategy_memory_results_dir: root.join("strategy-memory"),
        evolution_portfolio_history_results_dir: root.join("portfolio-history"),
        operator_maintenance_results_dir: root.join("operator-maintenance-actions"),
        evidence_results_dir: root.join("evidence-bundles"),
        evidence_verification_results_dir: root.join("evidence-verifications"),
        promotion_evidence_results_dir: root.join("promotion-evidence-packets"),
        review_session_results_dir: root.join("review-sessions"),
        review_session_export_results_dir: root.join("review-session-exports"),
        review_session_readiness_results_dir: root.join("review-session-readiness"),
        review_session_handoff_results_dir: root.join("review-session-handoffs"),
        review_capsule_results_dir: root.join("review-capsules"),
        review_capsule_import_results_dir: root.join("review-capsule-imports"),
        review_delegation_results_dir: root.join("review-delegations"),
        approval_set_results_dir: root.join("approval-sets"),
        approval_ledger_results_dir: root.join("approval-ledgers"),
        approval_verdict_results_dir: root.join("approval-verdicts"),
        approval_receipt_pack_results_dir: root.join("approval-receipt-packs"),
    }
}

fn seed_evolution_artifacts(root: &std::path::Path) {
    let paths = surface_paths(root);
    FileEvolutionPortfolioStore::open(&paths.evolution_portfolio_results_dir)
        .unwrap()
        .persist(&sample_portfolio_report())
        .unwrap();
    FileEvolutionGovernanceReviewPacketStore::open(
        &paths.evolution_governance_review_packet_results_dir,
    )
    .unwrap()
    .persist(&sample_governance_packet(
        "packet:red:ready",
        "office_red_ready_v1",
        "red",
        true,
    ))
    .unwrap();
    FileEvolutionGovernancePacketSetStore::open(&paths.evolution_packet_set_results_dir)
        .unwrap()
        .persist(&sample_packet_set_report())
        .unwrap();
    FileEvolutionPortfolioHistoryStore::open(&paths.evolution_portfolio_history_results_dir)
        .unwrap()
        .persist(&sample_portfolio_history_report())
        .unwrap();
}

fn seed_evidence_artifacts(root: &std::path::Path) {
    let paths = surface_paths(root);
    let packet = sample_promotion_evidence_packet();

    let bundle_store = FileEvidenceBundleStore::open(&paths.evidence_results_dir).unwrap();
    let verification_store =
        FileEvidenceVerificationStore::open(&paths.evidence_verification_results_dir).unwrap();
    for bundle in [
        sample_evidence_bundle(),
        sample_canary_evidence_bundle(),
        sample_promotion_review_evidence_bundle(),
    ] {
        let bundle_lookup = bundle_store.persist(&bundle).unwrap();
        let verification_lookup = verification_store
            .persist(&sample_subject_verification_report(
                bundle.subject.kind,
                &bundle.subject.stable_id,
                &bundle_lookup.record.bundle_id,
            ))
            .unwrap();
        bundle_store
            .attach_verification(&verification_lookup.record, &bundle_lookup.record.bundle_id)
            .unwrap();
    }
    FilePromotionEvidencePacketStore::open(&paths.promotion_evidence_results_dir)
        .unwrap()
        .persist(&packet)
        .unwrap();
}

fn sample_review_scope_rehearsal_bundle() -> ReplayBundle {
    let finding = DetectionFinding {
        finding_id: "finding-hunt-review".to_string(),
        event_id: "hunt-review".to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.99,
        evidence: json!({
            "host_id": "host-1",
            "event_id": "hunt-review",
        }),
        strategy_id: "suspicious_process_tree".to_string(),
    };
    ReplayBundle {
        bundle_id: "bundle:rehearsal:hunt-review:1700000000002".to_string(),
        event: event("hunt-review", "powershell -enc review"),
        findings: vec![finding.clone()],
        deposits: Vec::new(),
        action_request: swarm_policy::ActionRequest {
            hunt_id: HuntId("hunt-review".to_string()),
            requested_by: AgentId::new("whisker", "primary"),
            action: ResponseAction::Escalate {
                summary: "escalate hunt-review".to_string(),
                urgency: Severity::High,
            },
            severity: Severity::High,
            evidence: json!(SwarmFindingEnvelope::from(&finding)),
        },
        rehearsal: Some(ResponseRehearsalPreview {
            rehearsal_id: "rehearsal:hunt-review".to_string(),
            source_bundle_id: "bundle:source:hunt-review".to_string(),
            prepared_at_ms: 1_700_000_000_002,
            simulated_only: true,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::Host,
                scope_value: "host-1".to_string(),
                impact: ResponseBlastRadiusImpact::OperatorEscalationOnly,
                max_affected_scopes: 1,
                affected_capabilities: vec!["notify_operator".to_string()],
                summary: "Escalation stays on the operator lane.".to_string(),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: "Close the rehearsal escalation if operators accept it.".to_string(),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::CloseEscalation,
                    summary: "Close the dry-run escalation receipt.".to_string(),
                }],
            },
        }),
        audit: AuditTrail {
            trail_id: "trail-hunt-review".to_string(),
            hunt_id: "hunt-review".to_string(),
            related_receipt_ids: vec!["receipt-hunt-review".to_string()],
            detection: finding,
            policy: PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Allow,
                rule_name: "review-surface.allow".to_string(),
                reason: "review surface rehearsal test".to_string(),
                lease: None,
            },
            response: AuditResponseRecord::Skipped {
                reason: "review surface fixture records persisted dry-run proof only".to_string(),
            },
            created_at_ms: 1_700_000_000_002,
        },
    }
}

fn sample_review_scope_incident() -> CorrelatedIncident {
    CorrelatedIncident {
        incident_id: "incident-review".to_string(),
        summary: "Review scope incident".to_string(),
        created_at_ms: 1_700_000_000_003,
        window_start_ms: 1_700_000_000_000,
        window_end_ms: 1_700_000_000_003,
        correlation_keys: vec!["host:host-1".to_string()],
        related_receipt_ids: vec!["receipt-hunt-review".to_string()],
        included_members: vec![IncidentMemberDecision {
            investigation_id: "investigation-review".to_string(),
            hunt_id: "hunt-review".to_string(),
            finding_id: "finding-hunt-review".to_string(),
            reason: "same review hunt".to_string(),
            shared_keys: vec!["host:host-1".to_string()],
            evidence_links: Vec::new(),
            confidence_score: 1.0,
        }],
        rejected_members: Vec::new(),
        graph_dimensions: Vec::new(),
        confidence_score: 1.0,
        trigger_event_id: Some("hunt-review".to_string()),
        trigger_finding_id: Some("finding-hunt-review".to_string()),
        trigger_strategy_id: Some("summary_investigator".to_string()),
        threat_class: Some(ThreatClass::Execution),
        severity: Some(Severity::High),
        external_references: Vec::new(),
        providence_reconciliation: Some(ProvidenceIncidentReconciliation {
            incident_key: "suspicious_process_tree:execution:finding-hunt-review".to_string(),
            remote_incident_id: "prov-review-1".to_string(),
            remote_incident_url: Some(
                "https://providence.local/incidents/prov-review-1".to_string(),
            ),
            remote_status: ProvidenceIncidentStatus::Investigating,
            remote_severity: Severity::High,
            swarm_status: ProvidenceIncidentStatus::Open,
            swarm_severity: Severity::High,
            remote_updated_at_ms: 1_700_000_000_004,
            reconciled_at_ms: 1_700_000_000_005,
            outcome: ProvidenceReconciliationOutcome::ProvidenceAhead,
            needs_review: true,
            summary: "Providence status advanced while Swarm stayed open.".to_string(),
        }),
        providence_callback_audit_entries: Vec::new(),
        feedback_audit_entries: Vec::new(),
        false_positive_measurements: Vec::new(),
    }
}

#[tokio::test]
async fn status_route_requires_bearer_token() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
    let app = surface.router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_route_allows_configured_burst_before_rate_limit_rejection() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let mut config = operator_config();
    config.operator.rate_limit.burst_max_requests = 2;
    config.operator.rate_limit.burst_window_ms = 1_000;
    config.operator.rate_limit.sustained_max_requests = 10;
    config.operator.rate_limit.sustained_window_ms = 60_000;
    config.operator.rate_limit.trust_forwarded_headers = true;
    let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
    let app = surface.router();

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/status")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .header("x-forwarded-for", "198.51.100.10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let rejected = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header("x-forwarded-for", "198.51.100.10")
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
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("burst rate limit exceeded"),
        "expected burst limiter rejection context: {json:?}"
    );
}

#[tokio::test]
async fn status_route_recovers_after_rate_limit_window_refills() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let mut config = operator_config();
    config.operator.rate_limit.burst_max_requests = 1;
    config.operator.rate_limit.burst_window_ms = 20;
    config.operator.rate_limit.sustained_max_requests = 10;
    config.operator.rate_limit.sustained_window_ms = 1_000;
    config.operator.rate_limit.trust_forwarded_headers = true;
    let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
    let app = surface.router();

    let initial = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header("x-forwarded-for", "198.51.100.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);

    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header("x-forwarded-for", "198.51.100.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);

    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    let recovered = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header("x-forwarded-for", "198.51.100.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
}

#[tokio::test]
async fn status_route_reloads_rotated_bearer_token_without_rebuild() {
    let token_env = "SWARM_OPERATOR_ROTATION_TEST_TOKEN";
    unsafe {
        std::env::set_var(token_env, "initial-token");
    }
    let mut config = operator_config();
    config.operator.auth.token_env = token_env.to_string();
    config.operator.auth.context_token_env = token_env.to_string();
    let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
    let app = surface.router();

    let initial = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer initial-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);

    unsafe {
        std::env::set_var(token_env, "rotated-token");
    }

    let stale = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer initial-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

    let rotated = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer rotated-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);
}

#[tokio::test]
async fn status_route_rejects_expired_bearer_token_with_context() {
    let token_env = "SWARM_OPERATOR_EXPIRED_TEST_TOKEN";
    unsafe {
        std::env::set_var(token_env, "expired-token");
    }
    let mut config = operator_config();
    config.operator.auth.token_env = token_env.to_string();
    config.operator.auth.context_token_env = token_env.to_string();
    config.operator.auth.token_expires_at_ms = Some(1);
    let surface = LocalOperatorSurface::from_config("inline", config).unwrap();
    let app = surface.router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer expired-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("expired at"),
        "expected expiry context in operator auth error: {json:?}"
    );
}

#[tokio::test]
async fn status_route_returns_json_when_authorized() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
    let app = surface.router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["schema_version"], CURRENT_OPERATOR_API_SCHEMA_VERSION);
    assert_eq!(json["origin"], "live_runtime_status");
    assert_eq!(json["config_name"], "operator-http");
}

#[tokio::test]
async fn status_route_rejects_unsupported_schema_version_header() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
    let app = surface.router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header(OPERATOR_API_SCHEMA_VERSION_HEADER, "99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["message"]
            .as_str()
            .unwrap_or_default()
            .contains("unsupported operator API schema version")
    );
}

#[tokio::test]
async fn threat_class_config_routes_store_and_list_configs() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
    let app = surface.router();

    let request = serde_json::to_vec(&ThreatClassConfig {
        threat_class: ThreatClass::Execution,
        half_life_secs: 180.0,
        evaporation_threshold: 0.05,
        alert_threshold: 1.4,
        incident_threshold: 3.6,
    })
    .unwrap();
    let store_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/pheromone/threat-class-configs")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(request))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(store_response.status(), StatusCode::OK);
    let store_body = to_bytes(store_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let store_json: Value = serde_json::from_slice(&store_body).unwrap();
    assert_eq!(store_json["data"]["threat_class"], "execution");
    assert_eq!(store_json["data"]["half_life_secs"], 180.0);

    let list_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/pheromone/threat-class-configs")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    assert_eq!(list_json["data"][0]["threat_class"], "execution");
    assert_eq!(list_json["data"][0]["alert_threshold"], 1.4);
}

#[tokio::test]
async fn threat_intel_routes_store_and_query_entries() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
    let app = surface.router();

    let request = serde_json::to_vec(&ThreatIntelEntry {
        indicator_type: ThreatIntelIndicatorType::Domain,
        value: " Example.COM. ".to_string(),
        source: "operator".to_string(),
        indicator_id: None,
        confidence: 0.91,
        expires_at: 1_700_000_000_100,
    })
    .unwrap();
    let store_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/threat-intel/entries")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(request))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(store_response.status(), StatusCode::OK);
    let store_body = to_bytes(store_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let store_json: Value = serde_json::from_slice(&store_body).unwrap();
    assert_eq!(store_json["data"]["indicator_type"], "domain");
    assert_eq!(store_json["data"]["value"], " Example.COM. ");

    let lookup_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/threat-intel/entries?indicator_type=domain&value=example.com&now=1700000000000")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(lookup_response.status(), StatusCode::OK);
    let lookup_body = to_bytes(lookup_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let lookup_json: Value = serde_json::from_slice(&lookup_body).unwrap();
    assert_eq!(lookup_json["data"]["value"], "example.com");
    assert_eq!(lookup_json["data"]["confidence"], 0.91);

    let expired_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/threat-intel/entries?indicator_type=domain&value=EXAMPLE.COM.&now=1700000000100")
                    .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(expired_response.status(), StatusCode::OK);
    let expired_body = to_bytes(expired_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let expired_json: Value = serde_json::from_slice(&expired_body).unwrap();
    assert!(expired_json["data"].is_null());
}

#[tokio::test]
async fn notification_dead_letter_routes_list_and_replay_entries() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let (target_url, capture, shutdown_tx, handle) = spawn_notification_capture_server().await;
    let root = unique_temp_dir("notification-dead-letter");
    let dead_letter_path = root.join("pager.jsonl");
    let surface = LocalOperatorSurface::from_config(
        "inline",
        notification_operator_config(target_url, dead_letter_path.display().to_string()),
    )
    .unwrap();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let _ = surface
        .state
        .control
        .stack
        .process_event(
            &swarm_whisker::SuspiciousProcessTreeDetector::default(),
            &event("evt-http-notify-1", "powershell.exe -enc AAA="),
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval_context(1_700_000_000_010),
                signing_key: &signing_key,
            },
            |_finding| {
                Some(swarm_core::types::ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                })
            },
        )
        .await
        .unwrap()
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(capture.payloads.lock().await.is_empty());

    let app = surface.router();
    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/notifications/dead-letter/pager?limit=5")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    assert_eq!(list_json["data"][0]["adapter"], "notification:pager");
    assert_eq!(list_json["data"][0]["details"]["channel"], "pager");
    let receipt_id = list_json["data"][0]["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();

    let replay_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/notifications/dead-letter/pager")
                .header(axum::http::header::AUTHORIZATION, "Bearer secret-token")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "receipt_ids": [receipt_id] }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay_body = to_bytes(replay_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let replay_json: Value = serde_json::from_slice(&replay_body).unwrap();
    assert_eq!(replay_json["data"][0]["status"], "replayed");

    let payloads = capture.payloads.lock().await.clone();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["schema"], "swarm_notification");
    assert_eq!(
        payloads[0]["sample_finding"]["event_id"],
        "evt-http-notify-1"
    );
    assert_eq!(
        payloads[0]["sample_finding"]["evidence"]["host_metadata"]["host_id"],
        "host-1"
    );
    let auth_headers = capture.auth_headers.lock().await.clone();
    assert_eq!(auth_headers[0].as_deref(), Some("Bearer notify-secret"));
    let replay_headers = capture.replay_headers.lock().await.clone();
    assert_eq!(replay_headers[0].as_deref(), Some("true"));

    let _ = shutdown_tx.send(());
    handle.abort();
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn metrics_route_returns_openmetrics_without_auth() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }
    let surface = LocalOperatorSurface::from_config("inline", operator_config()).unwrap();
    let app = surface.router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "application/openmetrics-text; version=1.0.0; charset=utf-8"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("swarm_detect_latency_microseconds"));
    assert!(text.contains("swarm_policy_latency_microseconds"));
    assert!(text.contains("swarm_response_latency_microseconds"));
}

#[tokio::test]
async fn read_endpoints_return_runtime_and_governance_artifacts() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }

    let root = unique_temp_dir("read-endpoints");
    seed_evolution_artifacts(&root);
    let paths = surface_paths(&root);
    let surface =
        LocalOperatorSurface::from_config_and_paths("inline", operator_config(), paths).unwrap();

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let processed = surface
        .state
        .control
        .stack
        .process_event(
            &swarm_whisker::SuspiciousProcessTreeDetector::default(),
            &event("evt-http-1", "powershell.exe -enc AAA="),
            EventExecutionContext {
                agent_id: &agent_id,
                approval: &approval_context(1_700_000_000_001),
                signing_key: &signing_key,
            },
            |_finding| {
                Some(swarm_core::types::ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                })
            },
        )
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let _ = surface
        .state
        .control
        .stack
        .correlate_hunt("evt-http-1")
        .unwrap();

    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");

    let replay_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/operator/replay?receipt_id={}",
                    processed
                        .replay
                        .record
                        .response_receipt_id
                        .as_deref()
                        .unwrap()
                ))
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay_response.status(), StatusCode::OK);
    let replay_body = to_bytes(replay_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let replay_json: Value = serde_json::from_slice(&replay_body).unwrap();
    assert_eq!(replay_json["data"]["record"]["hunt_id"], "evt-http-1");

    let portfolio_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/evolution/portfolios/portfolio:red")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(portfolio_response.status(), StatusCode::OK);
    let portfolio_body = to_bytes(portfolio_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let portfolio_json: Value = serde_json::from_slice(&portfolio_body).unwrap();
    assert_eq!(portfolio_json["portfolio_id"], "portfolio:red");

    let packet_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/evolution/governance-packets/packet:red:ready")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(packet_response.status(), StatusCode::OK);

    let packet_set_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/evolution/packet-sets?cohort=red&limit=1")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(packet_set_response.status(), StatusCode::OK);
    let packet_set_body = to_bytes(packet_set_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let packet_set_json: Value = serde_json::from_slice(&packet_set_body).unwrap();
    assert_eq!(packet_set_json["total_count"], 1);
    assert_eq!(
        packet_set_json["packet_sets"][0]["packet_set_id"],
        "packet_set:red:1"
    );

    let history_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/evolution/portfolio-histories/portfolio_history:red:1")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(history_response.status(), StatusCode::OK);
    let history_body = to_bytes(history_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let history_json: Value = serde_json::from_slice(&history_body).unwrap();
    assert_eq!(history_json["history_id"], "portfolio_history:red:1");
}

#[tokio::test]
async fn evidence_endpoints_return_signed_bundle_views() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }

    let root = unique_temp_dir("evidence-endpoints");
    seed_evolution_artifacts(&root);
    seed_evidence_artifacts(&root);
    let paths = surface_paths(&root);
    let surface =
        LocalOperatorSurface::from_config_and_paths("inline", operator_config(), paths).unwrap();
    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/evidence/bundles?subject_kind=production_promotion&limit=5")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_json: Value = serde_json::from_slice(&list_body).unwrap();
    assert_eq!(list_json["total_count"], 1);
    assert_eq!(
        list_json["bundles"][0]["latest_verification_status"],
        "passed"
    );

    let bundle_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(
                        "/v1/operator/evidence/bundles/evidence:production_promotion:promotion:red:local-evidence-signer",
                    )
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(bundle_response.status(), StatusCode::OK);
    let bundle_body = to_bytes(bundle_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let bundle_json: Value = serde_json::from_slice(&bundle_body).unwrap();
    assert_eq!(bundle_json["subject"]["stable_id"], "promotion:red");

    let verification_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(
                        "/v1/operator/evidence/verifications/evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer",
                    )
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(verification_response.status(), StatusCode::OK);
    let verification_body = to_bytes(verification_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verification_json: Value = serde_json::from_slice(&verification_body).unwrap();
    assert_eq!(verification_json["status"], "passed");

    let packet_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/evidence/promotion-packets/promotion_evidence:promotion:red")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(packet_response.status(), StatusCode::OK);
    let packet_body = to_bytes(packet_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let packet_json: Value = serde_json::from_slice(&packet_body).unwrap();
    assert_eq!(packet_json["recommendation"], "ready_for_external_review");
}

#[tokio::test]
async fn live_governed_demo_cannot_be_resumed_by_human_approval() {
    let root = unique_temp_dir("approval-resume");
    let runtime_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime_addr = runtime_listener.local_addr().unwrap();
    let runtime_base_url = format!("http://{}", runtime_addr);

    let runtime_config_path = root.join("runtime-config.yaml");
    let mut runtime_config = operator_config();
    runtime_config.runtime.mode = swarm_runtime::RuntimeMode::LiveResponse;
    runtime_config.runtime.demo_mode = true;
    runtime_config.policy.human_gate_severity = swarm_core::types::Severity::Low;
    // Even a config that would otherwise hold the action for human review must
    // defer a live governed demo action to Pouncer and dispatcher governance.
    for rule in &mut runtime_config.policy.rules {
        rule.actions = vec![swarm_core::config::PolicyActionSelector::Escalate];
    }
    runtime_config.operator.runtime_base_url = runtime_base_url.clone();
    let runtime_harness = DefaultApprovalHarness::from_path(
        &runtime_config_path,
        root.join("approval-verdicts"),
        root.join("approval-receipt-packs"),
        root.join("approval-sets"),
        root.join("approval-ledgers"),
    )
    .unwrap();
    let runtime_state = IngestState::from_config(runtime_config_path, runtime_config)
        .unwrap()
        .with_approval_harness(runtime_harness.clone());
    let runtime_server = tokio::spawn(async move {
        axum::serve(runtime_listener, detect_http_router(runtime_state))
            .await
            .unwrap();
    });

    let scenario_path = root.join("human-gate-demo.yaml");
    let manifest = ReplayScenarioManifest {
        name: "operator approval replay".to_string(),
        description: "operator approval replay scenario".to_string(),
        seed_time_ms: 1_700_000_200_000,
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
                event: event("evt-approval-1", "powershell.exe -enc AAA="),
            }],
        },
        expectations: Default::default(),
    };
    fs::write(&scenario_path, serde_yaml::to_string(&manifest).unwrap()).unwrap();

    let replay_response = reqwest::Client::new()
        .post(format!("{runtime_base_url}/v1/demo/replay"))
        .json(&json!({
            "scenario_path": scenario_path.display().to_string(),
            "pace_ms": 0,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(replay_response.status(), reqwest::StatusCode::OK);
    let replay_json: Value = replay_response.json().await.unwrap();
    let run_id = replay_json["run_id"].as_str().unwrap().to_string();

    let approval_sets = runtime_harness.list_approval_sets().unwrap();
    assert_eq!(approval_sets.total_count, 0);

    let proof_response = reqwest::Client::new()
        .get(format!("{runtime_base_url}/v1/demo/proof"))
        .query(&[("run_id", run_id.clone())])
        .send()
        .await
        .unwrap();
    assert_eq!(proof_response.status(), reqwest::StatusCode::CONFLICT);
    assert!(
        proof_response
            .text()
            .await
            .unwrap()
            .contains("does not have a correlated incident")
    );

    runtime_server.abort();
}

#[tokio::test]
async fn review_surface_renders_html_shell_and_evidence_pages() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }

    let root = unique_temp_dir("review-html-evidence");
    seed_evolution_artifacts(&root);
    seed_evidence_artifacts(&root);
    let surface = LocalOperatorSurface::from_config_and_paths(
        "inline",
        operator_config(),
        surface_paths(&root),
    )
    .unwrap();
    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/review")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(home_response.status(), StatusCode::OK);
    assert_eq!(
        home_response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap(),
        "text/html; charset=utf-8"
    );
    let home_body = to_bytes(home_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let home_html = String::from_utf8(home_body.to_vec()).unwrap();
    assert!(home_html.contains("Local Evidence Review"));
    assert!(home_html.contains("Live Demo Dashboard"));
    assert!(home_html.contains("/v1/demo/dashboard"));
    assert!(home_html.contains("/v1/events/stream"));
    assert!(home_html.contains("/v1/operator/review/evidence"));
    assert!(home_html.contains("promotion_evidence:promotion:red"));

    let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/evidence?subject_kind=production_promotion&verification_status=passed&limit=5")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_html = String::from_utf8(list_body.to_vec()).unwrap();
    assert!(list_html.contains("Evidence Inspection"));
    assert!(list_html.contains("production_promotion"));
    assert!(
        list_html.contains("evidence:production_promotion:promotion:red:local-evidence-signer")
    );

    let bundle_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/evidence/evidence:production_promotion:promotion:red:local-evidence-signer")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(bundle_response.status(), StatusCode::OK);
    let bundle_body = to_bytes(bundle_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let bundle_html = String::from_utf8(bundle_body.to_vec()).unwrap();
    assert!(bundle_html.contains("Evidence Bundle Detail"));
    assert!(bundle_html.contains("promotion:red"));
    assert!(bundle_html.contains("canonical payload"));

    let verification_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/review/verifications/evidence_verification:evidence:production_promotion:promotion:red:local-evidence-signer")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(verification_response.status(), StatusCode::OK);
    let verification_body = to_bytes(verification_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verification_html = String::from_utf8(verification_body.to_vec()).unwrap();
    assert!(verification_html.contains("Evidence Verification Detail"));
    assert!(verification_html.contains("canonical_payload"));
    assert!(verification_html.contains("canonical payload bytes normalized cleanly"));
}

#[tokio::test]
async fn review_surface_scoped_context_renders_rehearsal_and_exports_signed_proof() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        std::env::set_var(
            "SWARM_EVIDENCE_SIGNING_KEY",
            "review-evidence-export-secret-material",
        );
    }

    let root = unique_temp_dir("review-scoped-rehearsal");
    seed_evolution_artifacts(&root);
    seed_evidence_artifacts(&root);
    let surface = LocalOperatorSurface::from_config_and_paths(
        "inline",
        operator_config(),
        surface_paths(&root),
    )
    .unwrap();
    surface
        .state
        .control
        .stack
        .replay_store
        .persist(&sample_review_scope_rehearsal_bundle())
        .unwrap();
    surface
        .state
        .control
        .stack
        .incident_store
        .persist(&sample_review_scope_incident())
        .unwrap();
    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");

    let home_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/review?hunt_id=hunt-review&incident_id=incident-review")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(home_response.status(), StatusCode::OK);
    let home_body = to_bytes(home_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let home_html = String::from_utf8(home_body.to_vec()).unwrap();
    assert!(home_html.contains("Latest Rehearsal Proof"));
    assert!(home_html.contains("Providence Reconciliation"));
    assert!(home_html.contains("Providence status advanced while Swarm stayed open."));
    assert!(home_html.contains("bundle:rehearsal:hunt-review:1700000000002"));
    assert!(home_html.contains(
        "/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export"
    ));

    let export_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export")
                    .header(auth.0, auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(export_response.status(), StatusCode::SEE_OTHER);
    let location = export_response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        location,
        "/v1/operator/review/evidence/evidence:replay_bundle:bundle:rehearsal:hunt-review:1700000000002:local-evidence-signer"
    );

    let exported = surface
        .state
        .evidence
        .as_ref()
        .unwrap()
        .find_bundle_by_subject(
            EvidenceSubjectKind::ReplayBundle,
            "bundle:rehearsal:hunt-review:1700000000002",
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        exported.bundle.subject.stable_id,
        "bundle:rehearsal:hunt-review:1700000000002"
    );
    assert_eq!(exported.bundle.signature.signer_id, "local-evidence-signer");

    let refreshed_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/review?hunt_id=hunt-review&incident_id=incident-review")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed_response.status(), StatusCode::OK);
    let refreshed_body = to_bytes(refreshed_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let refreshed_html = String::from_utf8(refreshed_body.to_vec()).unwrap();
    assert!(refreshed_html.contains("Open signed rehearsal proof"));
    assert!(refreshed_html.contains(&location));
}

#[tokio::test]
async fn review_surface_renders_promotion_packet_pages() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }

    let root = unique_temp_dir("review-html-packets");
    seed_evolution_artifacts(&root);
    seed_evidence_artifacts(&root);
    let surface = LocalOperatorSurface::from_config_and_paths(
        "inline",
        operator_config(),
        surface_paths(&root),
    )
    .unwrap();
    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/review/promotion-packets?recommendation=ready&limit=5")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_html = String::from_utf8(list_body.to_vec()).unwrap();
    assert!(list_html.contains("Promotion Evidence Review"));
    assert!(list_html.contains("promotion_evidence:promotion:red"));
    assert!(list_html.contains("ready_for_external_review"));

    let detail_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/review/promotion-packets/promotion_evidence:promotion:red")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail_body = to_bytes(detail_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let detail_html = String::from_utf8(detail_body.to_vec()).unwrap();
    assert!(detail_html.contains("Promotion Evidence Packet Detail"));
    assert!(detail_html.contains("office_red_ready_v1"));
    assert!(detail_html.contains("office_control_v1"));
    assert!(detail_html.contains("advisory"));
}

#[tokio::test]
async fn maintenance_endpoints_persist_audit_records() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
    }

    let root = unique_temp_dir("maintenance-endpoints");
    seed_evolution_artifacts(&root);
    let paths = surface_paths(&root);
    let surface =
        LocalOperatorSurface::from_config_and_paths("inline", operator_config(), paths).unwrap();
    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");

    let applied_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/maintenance/actions")
                .header(auth.0, auth.1)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "action": "refresh_portfolio_history",
                        "packet_set_id": "packet_set:red:1",
                        "reason": "refresh local review snapshot"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(applied_response.status(), StatusCode::OK);
    let applied_body = to_bytes(applied_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let applied_json: Value = serde_json::from_slice(&applied_body).unwrap();
    let applied_action_id = applied_json["action_id"].as_str().unwrap().to_string();
    assert_eq!(applied_json["actor"], "local-operator");
    assert_eq!(applied_json["status"], "applied");
    assert_eq!(applied_json["reason"], "refresh local review snapshot");
    assert_eq!(applied_json["artifacts"][0]["kind"], "portfolio_history");

    let blocked_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/maintenance/actions")
                .header(auth.0, auth.1)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "action": "packet_set_split",
                        "parent_packet_set_id": "packet_set:red:1",
                        "name": "red subset",
                        "packet_ids": ["packet:missing"],
                        "reason": "test blocked maintenance flow"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked_response.status(), StatusCode::CONFLICT);
    let blocked_body = to_bytes(blocked_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let blocked_json: Value = serde_json::from_slice(&blocked_body).unwrap();
    let blocked_action_id = blocked_json["action_id"].as_str().unwrap().to_string();
    assert_eq!(blocked_json["status"], "blocked");
    assert_eq!(blocked_json["target_kind"], "packet_set");
    assert!(
        blocked_json["summary"]
            .as_str()
            .unwrap()
            .contains("packet:missing")
    );

    let lookup_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/operator/maintenance/actions/{blocked_action_id}"
                ))
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lookup_response.status(), StatusCode::OK);
    let lookup_body = to_bytes(lookup_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let lookup_json: Value = serde_json::from_slice(&lookup_body).unwrap();
    assert_eq!(lookup_json["action_id"], blocked_action_id);
    assert_eq!(lookup_json["status"], "blocked");

    let blocked_list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/maintenance/actions?status=blocked&limit=5")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked_list_response.status(), StatusCode::OK);
    let blocked_list_body = to_bytes(blocked_list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let blocked_list_json: Value = serde_json::from_slice(&blocked_list_body).unwrap();
    assert_eq!(blocked_list_json["total_count"], 1);
    assert_eq!(
        blocked_list_json["actions"][0]["action_id"],
        blocked_action_id
    );

    let all_actions_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/maintenance/actions?limit=5")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(all_actions_response.status(), StatusCode::OK);
    let all_actions_body = to_bytes(all_actions_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let all_actions_json: Value = serde_json::from_slice(&all_actions_body).unwrap();
    assert_eq!(all_actions_json["total_count"], 2);
    let action_ids = all_actions_json["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["action_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(action_ids.contains(&applied_action_id));
    assert!(action_ids.contains(&blocked_action_id));
}

#[tokio::test]
async fn scoped_operator_principals_gate_actions_and_preserve_actor_identity() {
    const READ_ENV: &str = "SWARM_OPERATOR_SCOPE_READ_TOKEN";
    const REHEARSE_ENV: &str = "SWARM_OPERATOR_SCOPE_REHEARSE_TOKEN";
    const APPROVE_ENV: &str = "SWARM_OPERATOR_SCOPE_APPROVE_TOKEN";
    const APPROVE2_ENV: &str = "SWARM_OPERATOR_SCOPE_APPROVE2_TOKEN";
    const MAINT_ENV: &str = "SWARM_OPERATOR_SCOPE_MAINT_TOKEN";
    const READ_TOKEN: &str = "scope-read-secret";
    const REHEARSE_TOKEN: &str = "scope-rehearse-secret";
    const APPROVE_TOKEN: &str = "scope-approve-secret";
    const APPROVE2_TOKEN: &str = "scope-approve-secret-2";
    const MAINT_TOKEN: &str = "scope-maint-secret";

    unsafe {
        std::env::set_var(READ_ENV, READ_TOKEN);
        std::env::set_var(REHEARSE_ENV, REHEARSE_TOKEN);
        std::env::set_var(APPROVE_ENV, APPROVE_TOKEN);
        std::env::set_var(APPROVE2_ENV, APPROVE2_TOKEN);
        std::env::set_var(MAINT_ENV, MAINT_TOKEN);
        std::env::set_var("SWARM_EVIDENCE_SIGNING_KEY", "scope-evidence-signing-key");
    }

    let approve_signer = Ed25519Signer::from_secret_material("scope-approve-voter-key");
    let approver_id = format!("swarm:ed25519:{}", approve_signer.public_key_hex());
    let second_approver_id = "approver-2".to_string();
    let maintainer_id = "maintainer-1".to_string();
    let config = scoped_operator_config(
        READ_ENV,
        vec![
            OperatorPrincipalConfig {
                operator_id: "reader-1".to_string(),
                token_env: READ_ENV.to_string(),
                token_expires_at_ms: None,
                scopes: vec![OperatorScope::Read],
            },
            OperatorPrincipalConfig {
                operator_id: "rehearser-1".to_string(),
                token_env: REHEARSE_ENV.to_string(),
                token_expires_at_ms: None,
                scopes: vec![OperatorScope::Rehearse],
            },
            OperatorPrincipalConfig {
                operator_id: approver_id.clone(),
                token_env: APPROVE_ENV.to_string(),
                token_expires_at_ms: None,
                scopes: vec![OperatorScope::Approve],
            },
            OperatorPrincipalConfig {
                operator_id: second_approver_id.clone(),
                token_env: APPROVE2_ENV.to_string(),
                token_expires_at_ms: None,
                scopes: vec![OperatorScope::Approve],
            },
            OperatorPrincipalConfig {
                operator_id: maintainer_id.clone(),
                token_env: MAINT_ENV.to_string(),
                token_expires_at_ms: None,
                scopes: vec![OperatorScope::Maintenance],
            },
        ],
    );

    let root = unique_temp_dir("scoped-operator-principals");
    seed_evolution_artifacts(&root);
    let surface =
        LocalOperatorSurface::from_config_and_paths("inline", config, surface_paths(&root))
            .unwrap();
    surface
        .state
        .control
        .stack
        .replay_store
        .persist(&sample_review_scope_rehearsal_bundle())
        .unwrap();
    let app = surface.router();

    let read_status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/status")
                .header("authorization", format!("Bearer {READ_TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_status.status(), StatusCode::OK);

    let read_maintenance = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/maintenance/actions")
                .header("authorization", format!("Bearer {READ_TOKEN}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "action": "refresh_portfolio_history",
                        "packet_set_id": "packet_set:red:1",
                        "reason": "reader should not be allowed"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_maintenance.status(), StatusCode::FORBIDDEN);

    let read_rehearsal_export = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export")
                    .header("authorization", format!("Bearer {READ_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(read_rehearsal_export.status(), StatusCode::FORBIDDEN);

    let rehearse_export = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/review/rehearsals/bundle:rehearsal:hunt-review:1700000000002/export")
                    .header("authorization", format!("Bearer {REHEARSE_TOKEN}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    assert_eq!(rehearse_export.status(), StatusCode::SEE_OTHER);

    let invalid_set_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/approval-sets")
                .header("authorization", format!("Bearer {APPROVE_TOKEN}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "eligible_voters": ["reader-1"],
                        "threshold_required": 1,
                        "promotion_evidence_ref": "promotion_evidence:promotion:red"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_set_response.status(), StatusCode::BAD_REQUEST);

    let create_set_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/approval-sets")
                .header("authorization", format!("Bearer {APPROVE_TOKEN}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "eligible_voters": [approver_id.clone(), second_approver_id.clone()],
                        "threshold_required": 2,
                        "promotion_evidence_ref": "promotion_evidence:promotion:red"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_set_response.status(), StatusCode::CREATED);
    let create_set_body = to_bytes(create_set_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let create_set_json: Value = serde_json::from_slice(&create_set_body).unwrap();
    let approval_set_id = create_set_json["set_id"].as_str().unwrap().to_string();

    let ledgers = surface
        .state
        .approval
        .as_ref()
        .unwrap()
        .list_ledgers(Some(&approval_set_id))
        .unwrap();
    let approval_ledger_id = ledgers.ledgers[0].ledger_id.clone();
    let vote_signature = approve_signer.sign(
        &canonical_json_bytes(&json!({
            "approval_set_id": approval_set_id,
            "ledger_id": approval_ledger_id,
            "voter_id": approver_id,
        }))
        .unwrap(),
    );

    let maintenance_vote = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/approval-ledgers/{approval_ledger_id}/vote"
                ))
                .header("authorization", format!("Bearer {MAINT_TOKEN}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "voter_id": approver_id,
                        "signature": vote_signature.clone(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(maintenance_vote.status(), StatusCode::FORBIDDEN);

    let approval_vote = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/approval-ledgers/{approval_ledger_id}/vote"
                ))
                .header("authorization", format!("Bearer {APPROVE_TOKEN}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "voter_id": approver_id,
                        "signature": vote_signature,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(approval_vote.status(), StatusCode::OK);
    let approval_vote_body = to_bytes(approval_vote.into_body(), usize::MAX)
        .await
        .unwrap();
    let approval_vote_json: Value = serde_json::from_slice(&approval_vote_body).unwrap();
    assert_eq!(
        approval_vote_json["report"]["entries"][0]["voter_id"],
        approver_id.as_str()
    );

    let maintenance_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/maintenance/actions")
                .header("authorization", format!("Bearer {MAINT_TOKEN}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "action": "refresh_portfolio_history",
                        "packet_set_id": "packet_set:red:1",
                        "reason": "maintainer refresh"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(maintenance_response.status(), StatusCode::OK);
    let maintenance_body = to_bytes(maintenance_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let maintenance_json: Value = serde_json::from_slice(&maintenance_body).unwrap();
    assert_eq!(maintenance_json["actor"], maintainer_id);
}

#[tokio::test]
async fn review_workbench_routes_create_export_and_handoff_sessions() {
    unsafe {
        std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        std::env::set_var("SWARM_EVIDENCE_SIGNING_KEY", "review-workbench-test-key");
    }

    let root = unique_temp_dir("review-workbench");
    seed_evolution_artifacts(&root);
    seed_evidence_artifacts(&root);
    let surface = LocalOperatorSurface::from_config_and_paths(
        "inline",
        operator_config(),
        surface_paths(&root),
    )
    .unwrap();
    let app = surface.router();
    let auth = ("authorization", "Bearer secret-token");
    let create_body =
            "title=red+lane+review&notes=compare+promotion+lanes&artifact_refs=promotion_review%3Areview%3Ared%0Acanary_run%3Acanary%3Ared%0Aproduction_promotion%3Apromotion%3Ared"
                .to_string();
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/review/sessions")
                .header(auth.0, auth.1)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(create_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::SEE_OTHER);
    let session_location = create_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(session_location.starts_with("/v1/operator/review/sessions/review_session:"));
    let session_id = session_location
        .trim_start_matches("/v1/operator/review/sessions/")
        .to_string();

    let session_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&session_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);
    let session_body = to_bytes(session_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let session_html = String::from_utf8(session_body.to_vec()).unwrap();
    assert!(session_html.contains("Review Session Detail"));
    assert!(session_html.contains("Cross-Lane Summary"));
    assert!(session_html.contains("Portable Capsules"));
    assert!(session_html.contains("Governance Prep"));
    assert!(session_html.contains("Canary"));
    assert!(session_html.contains("Production"));
    assert!(session_html.contains("review:red"));
    assert!(session_html.contains("canary:red"));
    assert!(session_html.contains("promotion:red"));

    let export_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/operator/review/sessions/{session_id}/export"))
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_response.status(), StatusCode::SEE_OTHER);
    let export_location = export_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(export_location.starts_with("/v1/operator/review/exports/review_session_export:"));
    let export_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&export_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(export_page.status(), StatusCode::OK);
    let export_body = to_bytes(export_page.into_body(), usize::MAX).await.unwrap();
    let export_html = String::from_utf8(export_body.to_vec()).unwrap();
    assert!(export_html.contains("Review Session Export"));
    assert!(export_html.contains("abcd1234"));
    assert!(export_html.contains("Cross-Lane Summary"));

    let capsule_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/review/sessions/{session_id}/capsules"
                ))
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capsule_response.status(), StatusCode::SEE_OTHER);
    let capsule_location = capsule_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(capsule_location.starts_with("/v1/operator/review/capsules/review_capsule:"));
    let capsule_id = capsule_location
        .trim_start_matches("/v1/operator/review/capsules/")
        .to_string();
    let capsule_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&capsule_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(capsule_page.status(), StatusCode::OK);
    let capsule_body = to_bytes(capsule_page.into_body(), usize::MAX)
        .await
        .unwrap();
    let capsule_html = String::from_utf8(capsule_body.to_vec()).unwrap();
    assert!(capsule_html.contains("Portable Review Capsule"));
    assert!(capsule_html.contains("Create Delegation Packet"));

    let readiness_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/review/sessions/{session_id}/promotion-readiness"
                ))
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(readiness_response.status(), StatusCode::SEE_OTHER);
    let readiness_location = readiness_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        readiness_location
            .starts_with("/v1/operator/review/promotion-readiness/review_session_readiness:")
    );
    let readiness_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&readiness_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(readiness_page.status(), StatusCode::OK);
    let readiness_body = to_bytes(readiness_page.into_body(), usize::MAX)
        .await
        .unwrap();
    let readiness_html = String::from_utf8(readiness_body.to_vec()).unwrap();
    assert!(readiness_html.contains("Promotion Readiness Review"));
    assert!(readiness_html.contains("ready_for_advisory_promotion_review"));

    let readiness_capsule_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/review/promotion-readiness/{}/capsules",
                    readiness_location
                        .trim_start_matches("/v1/operator/review/promotion-readiness/")
                ))
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(readiness_capsule_response.status(), StatusCode::SEE_OTHER);

    let workbench = DefaultReviewWorkbenchHarness::from_paths(&surface_paths(&root)).unwrap();
    let capsule_lookup = workbench.load_capsule(&capsule_id).unwrap().unwrap();
    let import_body = format!("source_path={}", capsule_lookup.record.bundle_path);
    let import_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/review/capsule-imports")
                .header(auth.0, auth.1)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(import_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(import_response.status(), StatusCode::SEE_OTHER);
    let import_location = import_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        import_location.starts_with("/v1/operator/review/capsule-imports/review_capsule_import:")
    );
    let import_id = import_location
        .trim_start_matches("/v1/operator/review/capsule-imports/")
        .to_string();
    let import_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&import_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(import_page.status(), StatusCode::OK);
    let import_body = to_bytes(import_page.into_body(), usize::MAX).await.unwrap();
    let import_html = String::from_utf8(import_body.to_vec()).unwrap();
    assert!(import_html.contains("Imported Review Capsule"));
    assert!(import_html.contains("trusted"));

    let delegation_body = "reason=preserve+review+continuity+for+external+inspection&delegate_label=remote+review+board";
    let delegation_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/review/capsule-imports/{import_id}/delegations"
                ))
                .header(auth.0, auth.1)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(delegation_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delegation_response.status(), StatusCode::SEE_OTHER);
    let delegation_location = delegation_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(delegation_location.starts_with("/v1/operator/review/delegations/review_delegation:"));
    let delegation_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&delegation_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delegation_page.status(), StatusCode::OK);
    let delegation_body = to_bytes(delegation_page.into_body(), usize::MAX)
        .await
        .unwrap();
    let delegation_html = String::from_utf8(delegation_body.to_vec()).unwrap();
    assert!(delegation_html.contains("Review Delegation Packet"));
    assert!(delegation_html.contains("remote review board"));

    let handoff_body = "reason=re-verify+selected+evidence+from+review&selected_artifact_refs=production_promotion%3Apromotion%3Ared".to_string();
    let handoff_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/v1/operator/review/sessions/{session_id}/handoffs/reverify"
                ))
                .header(auth.0, auth.1)
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(Body::from(handoff_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(handoff_response.status(), StatusCode::SEE_OTHER);
    let handoff_location = handoff_response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(handoff_location.starts_with("/v1/operator/review/handoffs/review_handoff:"));
    let handoff_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&handoff_location)
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(handoff_page.status(), StatusCode::OK);
    let handoff_body = to_bytes(handoff_page.into_body(), usize::MAX)
        .await
        .unwrap();
    let handoff_html = String::from_utf8(handoff_body.to_vec()).unwrap();
    assert!(handoff_html.contains("Review Session Handoff"));
    assert!(handoff_html.contains("blocked"));
    assert!(handoff_html.contains("/v1/operator/maintenance/actions/"));

    let maintenance_response = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/maintenance/actions?status=blocked&limit=10")
                .header(auth.0, auth.1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(maintenance_response.status(), StatusCode::OK);
    let maintenance_body = to_bytes(maintenance_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let maintenance_json: Value = serde_json::from_slice(&maintenance_body).unwrap();
    assert_eq!(maintenance_json["total_count"], 1);
    assert_eq!(
        maintenance_json["actions"][0]["target_kind"],
        "evidence_bundle"
    );
}

#[tokio::test]
async fn ordinary_operator_vote_keeps_the_demo_resume_contract() {
    const TOKEN_ENV: &str = "SWARM_ORDINARY_APPROVAL_ROUTE_TOKEN";
    const EVIDENCE_KEY_ENV: &str = "SWARM_ORDINARY_APPROVAL_ROUTE_EVIDENCE_KEY";
    const TOKEN: &str = "ordinary-approval-route-token";
    unsafe {
        std::env::set_var(TOKEN_ENV, TOKEN);
        std::env::set_var(EVIDENCE_KEY_ENV, "ordinary-approval-route-evidence-key");
    }
    let (runtime_base_url, capture, shutdown_tx, server) =
        spawn_approval_resume_capture_server().await;
    let signer = Ed25519Signer::from_secret_material("ordinary-approval-route-voter");
    let voter_id = format!("swarm:ed25519:{}", signer.public_key_hex());
    let mut config = operator_config();
    config.operator.runtime_base_url = runtime_base_url;
    config.operator.auth.context_token_env = TOKEN_ENV.to_string();
    config.operator.auth.operator_id = voter_id.clone();
    config.operator.auth.token_env = TOKEN_ENV.to_string();
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: voter_id.clone(),
        token_env: TOKEN_ENV.to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Approve],
    }];
    let root = unique_temp_dir("ordinary-approval-route");
    let mut paths = surface_paths(&root);
    paths.evidence_signing_key_env = EVIDENCE_KEY_ENV.to_string();
    let surface = LocalOperatorSurface::from_config_and_paths("inline", config, paths).unwrap();
    let harness = surface.state.approval.as_ref().unwrap();
    let set = harness
        .create_approval_set(
            vec![voter_id.clone()],
            ThresholdRule::AtLeast { required: 1 },
            "promotion_evidence:ordinary-demo-approval",
        )
        .unwrap();
    let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
        .ledger_id
        .clone();
    let signature = signer.sign(
        &canonical_json_bytes(&json!({
            "approval_set_id": set.set_id.clone(),
            "ledger_id": ledger_id.clone(),
            "voter_id": voter_id.clone(),
        }))
        .unwrap(),
    );
    let response = surface
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/operator/approval-ledgers/{ledger_id}/vote"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"voter_id": voter_id, "signature": signature}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let requests = capture.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].0,
        format!("/v1/demo/approvals/{}/resume", set.set_id)
    );
    assert!(requests[0].1.get("receipt_pack").is_some());
    assert!(requests[0].1.get("receipt_pack_id").is_none());
    drop(requests);
    let _ = shutdown_tx.send(());
    let _ = server.await;
    unsafe {
        std::env::remove_var(TOKEN_ENV);
        std::env::remove_var(EVIDENCE_KEY_ENV);
    }
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn governed_operator_vote_resumes_persisted_hold_once_through_authenticated_runtime_route() {
    const TOKEN_ENV: &str = "SWARM_GOVERNED_RESUME_E2E_TOKEN";
    const EVIDENCE_KEY_ENV: &str = "SWARM_GOVERNED_RESUME_E2E_EVIDENCE_KEY";
    const TOKEN: &str = "governed-resume-e2e-bearer";
    unsafe {
        std::env::set_var(TOKEN_ENV, TOKEN);
        std::env::set_var(EVIDENCE_KEY_ENV, "governed-resume-e2e-evidence-key");
    }

    let root = unique_temp_dir("governed-resume-production-composition");
    let mut paths = surface_paths(&root);
    paths.evidence_signing_key_env = EVIDENCE_KEY_ENV.to_string();
    paths.evidence_signer_id = "governed-resume-e2e-signer".to_string();
    let harness = DefaultApprovalHarness::from_path(
        "inline",
        &paths.approval_verdict_results_dir,
        &paths.approval_receipt_pack_results_dir,
        &paths.approval_set_results_dir,
        &paths.approval_ledger_results_dir,
    )
    .unwrap();

    let operator_signer = Ed25519Signer::from_secret_material("governed-resume-e2e-voter");
    let operator_id = format!("swarm:ed25519:{}", operator_signer.public_key_hex());
    let runtime_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime_address = runtime_listener.local_addr().unwrap();
    let mut config = operator_config();
    config.runtime.mode = swarm_core::config::RuntimeMode::LiveResponse;
    config.policy.human_gate_severity = Severity::Low;
    for rule in &mut config.policy.rules {
        rule.actions = vec![PolicyActionSelector::Escalate];
    }
    config.operator.runtime_base_url = format!("http://{runtime_address}");
    config.operator.auth.context_token_env = TOKEN_ENV.to_string();
    config.operator.auth.operator_id = operator_id.clone();
    config.operator.auth.token_env = TOKEN_ENV.to_string();
    config.operator.auth.principals = vec![OperatorPrincipalConfig {
        operator_id: operator_id.clone(),
        token_env: TOKEN_ENV.to_string(),
        token_expires_at_ms: None,
        scopes: vec![OperatorScope::Approve],
    }];

    let governance = Arc::new(
        GovernancePolicy::with_persistence(
            GovernancePolicyConfig::default(),
            root.join("governance-authorizations.json"),
        )
        .unwrap(),
    );
    governance
        .register_governor(
            AgentId::new("tom", "governed-resume-e2e"),
            ed25519_dalek::SigningKey::from_bytes(&[91; 32]),
        )
        .unwrap();
    let runtime_events = RuntimeEventBroadcaster::new(32);
    let mut runtime_rx = runtime_events.subscribe();
    let state = IngestState::from_config(root.join("swarm.yaml"), config.clone())
        .unwrap()
        .with_approval_harness(harness.clone())
        .with_governance_policy(Arc::clone(&governance))
        .with_runtime_events(runtime_events.clone());

    let pounce_id = AgentId::new("pounce", "governed-resume-e2e");
    let hunt_id = HuntId("hunt-governed-resume-e2e".to_string());
    let response_action = ResponseAction::BlockEgress {
        target: "203.0.113.211".to_string(),
    };
    let mut evidence = json!({
        "lineage": {
            "hunt_id": hunt_id.0.clone(),
            "event_id": "evt-governed-resume-e2e",
            "indicator": {"host_id": "host-governed-resume-e2e"}
        },
        "escalation": {
            "mode": "alert",
            "mode_transition_at": 1_700_000_000,
            "timestamp": 1_700_000_010,
            "threat_class": ThreatClass::Execution,
            "severity": Severity::Critical,
            "confidence": 0.99
        },
        "playbook_match": {
            "threat_class": ThreatClass::Execution,
            "severity": Severity::Critical,
            "min_confidence": 0.90,
            "max_confidence": 1.0
        }
    });
    let request = ActionRequest {
        hunt_id: hunt_id.clone(),
        requested_by: pounce_id.clone(),
        action: response_action.clone(),
        severity: Severity::Critical,
        evidence: evidence.clone(),
    };
    let GovernanceDecision::Authorize { receipt, .. } = governance.can_act(&request) else {
        panic!("healthy configured governance must authorize the exact request");
    };
    evidence["governance_receipt"] = serde_json::to_value(receipt).unwrap();

    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        state.current_substrate(),
        Arc::new(ArcSwap::from_pointee(Vec::<AgentHealthEntry>::new())),
    )
    .with_request_response_router(state.current_request_response_router())
    .with_governance_policy(Arc::clone(&governance))
    .with_runtime_events(runtime_events);
    dispatcher
        .register(Box::new(OneShotGovernedRequestAgent::new(
            pounce_id,
            vec![SwarmAction::RequestResponse {
                hunt_id,
                action: response_action,
                evidence,
            }],
        )))
        .unwrap();
    dispatcher.tick_once().await;

    let approval_sets = harness.list_approval_sets().unwrap();
    assert_eq!(approval_sets.sets.len(), 1);
    let approval_set_id = approval_sets.sets[0].set_id.clone();
    governance
        .pending_human_authorization(&approval_set_id)
        .expect("dispatcher must leave governance pending while it waits for a human");
    while let Ok(event) = runtime_rx.try_recv() {
        if let RuntimeEvent::ResponseExecution { response_kind, .. } = event {
            assert_ne!(
                response_kind, "success",
                "the initial hold must not execute"
            );
        }
    }

    let runtime_server = tokio::spawn(async move {
        axum::serve(runtime_listener, detect_http_router(state))
            .await
            .unwrap();
    });
    let surface = LocalOperatorSurface::from_config_and_paths("inline", config, paths).unwrap();
    let operator_app = surface.router();
    let ledgers = harness.list_ledgers(Some(&approval_set_id)).unwrap();
    assert_eq!(ledgers.ledgers.len(), 1);
    let ledger_id = ledgers.ledgers[0].ledger_id.clone();
    let signature = operator_signer.sign(
        &canonical_json_bytes(&json!({
            "approval_set_id": approval_set_id.clone(),
            "ledger_id": ledger_id.clone(),
            "voter_id": operator_id.clone(),
        }))
        .unwrap(),
    );
    let trusted_before_ms = swarm_runtime::runtime_events::now_ms();
    let vote_response = operator_app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/operator/approval-ledgers/{ledger_id}/vote"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "voter_id": operator_id.clone(),
                        "signature": signature,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let trusted_after_ms = swarm_runtime::runtime_events::now_ms();
    assert_eq!(vote_response.status(), StatusCode::OK);

    let receipt_packs = harness.list_receipt_packs().unwrap();
    assert_eq!(receipt_packs.packs.len(), 1);
    let receipt_pack_id = receipt_packs.packs[0].pack_id.clone();
    assert!(
        governance
            .pending_human_authorization(&approval_set_id)
            .is_err()
    );

    let mut successful_executions = 0;
    while let Ok(event) = runtime_rx.try_recv() {
        if let RuntimeEvent::ResponseExecution {
            response_kind,
            emitted_at_ms,
            ..
        } = event
            && response_kind == "success"
        {
            successful_executions += 1;
            assert!(emitted_at_ms >= trusted_before_ms && emitted_at_ms <= trusted_after_ms);
        }
    }
    assert_eq!(successful_executions, 1);

    let duplicate_vote = operator_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/operator/approval-ledgers/{ledger_id}/vote"))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "voter_id": operator_id.clone(),
                        "signature": operator_signer.sign(
                            &canonical_json_bytes(&json!({
                                "approval_set_id": approval_set_id.clone(),
                                "ledger_id": ledger_id.clone(),
                                "voter_id": operator_id.clone(),
                            }))
                            .unwrap(),
                        ),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!duplicate_vote.status().is_success());

    let replay = reqwest::Client::new()
        .post(format!(
            "http://{runtime_address}/v1/governance/approvals/{approval_set_id}/resume"
        ))
        .bearer_auth(TOKEN)
        .json(&json!({"receipt_pack_id": receipt_pack_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), reqwest::StatusCode::CONFLICT);
    tokio::task::yield_now().await;
    while let Ok(event) = runtime_rx.try_recv() {
        if let RuntimeEvent::ResponseExecution { response_kind, .. } = event {
            assert_ne!(response_kind, "success", "a retry must not execute again");
        }
    }

    runtime_server.abort();
    unsafe {
        std::env::remove_var(TOKEN_ENV);
        std::env::remove_var(EVIDENCE_KEY_ENV);
    }
    let _ = fs::remove_dir_all(root);
}

// --- QRT-04: operator-driven containment release ---------------------------
//
// These tests drive the routes in `super::containment` against a REAL
// `swarm_agents::tom_agent::GovernancePolicy`, because the requirement's phrase
// is "through the same governance signing path" and a fake signer would prove
// nothing about that path. `swarm-runtime-http` is the lowest crate that can
// name both the governance agent and the HTTP surface, which is why they live
// here rather than in `swarm-runtime`'s own tests.
//
// NO WALL CLOCK GATES ANY ASSERTION BELOW. Every instant is a literal handed to
// the release body, the list query, or `sweep(now_ms)`. `1c4d728` records a
// `thread::sleep(2000)` against a 1000ms TTL as this repo's anti-pattern and
// the containment module's own doc says the clock is a parameter everywhere;
// an expiry test that could only be exercised by sleeping would be untestable
// in exactly the same way.

mod qrt_04 {
    use super::*;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use swarm_agents::tom_agent::{GovernancePolicy, GovernancePolicyConfig};
    use swarm_consensus::{
        ConsensusCommit, ConsensusCommittee, ConsensusGovernanceReceipt, ConsensusProposal,
        GovernanceReceiptDecision,
    };
    use swarm_crypto::sha256_hex;
    use swarm_response::containment::{
        ContainmentLease, ContainmentLeaseStore, ContainmentTtl, MemoryContainmentLeaseStore,
    };
    use swarm_response::rollback::{
        RollbackExecutor, RollbackReceipt, RollbackStepOutcome, RollbackStepStatus, RollbackTrigger,
    };
    use swarm_response::{ExecutionMode, ResponseError, ResponseStatus};
    use swarm_runtime::containment::{
        ContainmentSweep, ReleaseAttestationError, verify_release_attestation,
    };

    /// A world with hosts in it. The point of the integration test is that the
    /// containment had an EFFECT and the rollback removed it, so something has
    /// to hold that effect; a receipt asserting restoration with nothing behind
    /// it is the failure mode this lane exists to remove.
    #[derive(Debug, Default)]
    struct World {
        isolated_hosts: Mutex<BTreeSet<String>>,
    }

    impl World {
        fn isolate(&self, host_id: &str) {
            self.isolated_hosts
                .lock()
                .unwrap()
                .insert(host_id.to_string());
        }

        fn is_isolated(&self, host_id: &str) -> bool {
            self.isolated_hosts.lock().unwrap().contains(host_id)
        }
    }

    /// Executes the inverse against [`World`] for real, so `Reversed` on the
    /// receipt corresponds to an observable change.
    #[derive(Debug)]
    struct WorldRollbackExecutor {
        world: Arc<World>,
    }

    #[async_trait]
    impl RollbackExecutor for WorldRollbackExecutor {
        async fn rollback(
            &self,
            lease: &ContainmentLease,
            trigger: RollbackTrigger,
            mode: ExecutionMode,
            completed_at_ms: i64,
        ) -> Result<RollbackReceipt, ResponseError> {
            let host_id = lease.blast_radius().scope_value.clone();
            let restored = self.world.isolated_hosts.lock().unwrap().remove(&host_id);
            Ok(RollbackReceipt::from_steps(
                lease,
                trigger,
                mode,
                completed_at_ms,
                vec![RollbackStepOutcome {
                    kind: ResponseRollbackStepKind::RestoreHostConnectivity,
                    status: if restored {
                        RollbackStepStatus::Reversed
                    } else {
                        RollbackStepStatus::Failed
                    },
                    detail: format!("restored connectivity for `{host_id}`"),
                }],
            ))
        }
    }

    fn isolate_preview(host_id: &str) -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: format!("rehearsal:{host_id}"),
            source_bundle_id: format!("bundle:{host_id}"),
            prepared_at_ms: 1_000,
            simulated_only: false,
            blast_radius: ResponseBlastRadiusPreview {
                scope_kind: ResponseRehearsalScopeKind::Host,
                scope_value: host_id.to_string(),
                impact: ResponseBlastRadiusImpact::HostConnectivityIsolated,
                max_affected_scopes: 1,
                affected_capabilities: vec!["network_connectivity".to_string()],
                summary: format!("isolates {host_id}"),
            },
            rollback: ResponseRollbackPreview {
                required: true,
                summary: format!("restore connectivity for {host_id}"),
                steps: vec![ResponseRollbackStep {
                    kind: ResponseRollbackStepKind::RestoreHostConnectivity,
                    summary: format!("restore {host_id}"),
                }],
            },
        }
    }

    fn open_containment(
        world: &World,
        store: &dyn ContainmentLeaseStore,
        lease_id: &str,
        host_id: &str,
        issued_at_ms: i64,
        ttl_ms: i64,
    ) -> ContainmentLease {
        world.isolate(host_id);
        let lease = ContainmentLease::open(
            lease_id,
            ResponseAction::IsolateHost {
                host_id: host_id.to_string(),
            },
            format!("resp:{lease_id}"),
            Some(format!("gov:{lease_id}")),
            &isolate_preview(host_id),
            issued_at_ms,
            ContainmentTtl::from_config_ms(ttl_ms).unwrap(),
        )
        .unwrap();
        store.open_lease(&lease).unwrap();
        lease
    }

    fn governance_with_one_governor() -> Arc<GovernancePolicy> {
        let policy = Arc::new(GovernancePolicy::new(GovernancePolicyConfig::default()));
        // `register_governor` became fallible in BFT-03 -- it refuses a SECOND
        // distinct signing key -- so the Result is handled rather than dropped.
        policy
            .register_governor(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[41; 32]),
            )
            .expect("the first governor key must register");
        policy
    }

    fn attestation_of(receipt: &RollbackReceipt) -> ConsensusGovernanceReceipt {
        serde_json::from_value(
            receipt
                .governance_attestation
                .clone()
                .expect("release should be attested"),
        )
        .expect("attestation should deserialize as a governance receipt")
    }

    struct Harness {
        world: Arc<World>,
        store: Arc<MemoryContainmentLeaseStore>,
        sweep: Arc<ContainmentSweep>,
        app: Router,
    }

    fn harness() -> Harness {
        unsafe {
            std::env::set_var("SWARM_OPERATOR_TEST_TOKEN", "secret-token");
        }
        let world = Arc::new(World::default());
        let store = Arc::new(MemoryContainmentLeaseStore::new());
        let sweep = Arc::new(
            ContainmentSweep::new(
                store.clone(),
                Arc::new(WorldRollbackExecutor {
                    world: Arc::clone(&world),
                }),
                ExecutionMode::Enforced,
            )
            .with_governance(governance_with_one_governor()),
        );
        // ONE sweep object, and the router is handed the same `Arc` the TTL
        // task would get in `swarm_detect`. That sharing is the thing under
        // test: the manual release below and the `sweep(now_ms)` call after it
        // reach `swarm_runtime::containment::release_lease` through the same
        // store, executor, mode and governance authority.
        let app = super::super::containment::containment_operator_router(
            &operator_config(),
            Arc::clone(&sweep),
        )
        .unwrap();
        Harness {
            world,
            store,
            sweep,
            app,
        }
    }

    fn bearer() -> (&'static str, &'static str) {
        ("authorization", "Bearer secret-token")
    }

    #[tokio::test]
    async fn qrt_04_containment_is_released_manually_and_by_ttl_through_one_path() {
        let harness = harness();
        // Two containments take effect at t=1_000. One will be released early
        // by an operator, the other left to its TTL.
        let manual = open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-manual",
            "host-manual",
            1_000,
            60_000,
        );
        let expiring = open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-ttl",
            "host-ttl",
            1_000,
            5_000,
        );
        assert_eq!(manual.expires_at_ms(), 61_000);
        assert_eq!(expiring.expires_at_ms(), 6_000);

        // 1. THE CONTAINMENT HAD AN EFFECT.
        assert!(harness.world.is_isolated("host-manual"));
        assert!(harness.world.is_isolated("host-ttl"));

        // 2. The operator listing shows both, against a STATED instant.
        let listed = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/containment/leases?now_ms=2000")
                    .header(bearer().0, bearer().1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed: Value =
            serde_json::from_slice(&to_bytes(listed.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(listed["observed_at_ms"], 2_000);
        assert_eq!(listed["open_leases"].as_array().unwrap().len(), 2);
        // Sorted by expiry: the TTL lease first.
        assert_eq!(listed["open_leases"][0]["lease"]["lease_id"], "lease-ttl");
        assert_eq!(listed["open_leases"][0]["remaining_ms"], 4_000);
        assert_eq!(listed["open_leases"][0]["expired"], false);
        assert_eq!(
            listed["open_leases"][1]["lease"]["lease_id"],
            "lease-manual"
        );
        assert_eq!(listed["open_leases"][1]["remaining_ms"], 59_000);

        // 3. MANUAL EARLY RELEASE, over the authenticated operator route, at a
        //    stated instant well before the lease's own expiry.
        let released = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/containment/leases/lease-manual/release")
                    .header(bearer().0, bearer().1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "now_ms": 3_000 }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(released.status(), StatusCode::OK);
        let released: Value =
            serde_json::from_slice(&to_bytes(released.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(released["lease_closed"], true);
        assert_eq!(released["fully_reversed"], true);
        assert_eq!(released["attestation_verified"], true);
        assert_eq!(released["receipt"]["trigger"], "manual");
        assert_eq!(released["receipt"]["completed_at_ms"], 3_000);
        assert_eq!(
            released["receipt"]["governance_receipt_id"],
            "gov:lease-manual"
        );
        // The effect is gone from the world, not merely from the receipt.
        assert!(!harness.world.is_isolated("host-manual"));
        // The other containment is untouched.
        assert!(harness.world.is_isolated("host-ttl"));

        // 4. TTL RELEASE, driven by the instant the sweep is told to act at
        //    rather than by elapsed wall clock.
        let before_expiry = harness.sweep.sweep(5_999).await;
        assert_eq!(
            before_expiry.expired, 0,
            "a lease expiring at 6_000 must not be swept at 5_999"
        );
        assert!(harness.world.is_isolated("host-ttl"));

        let after_expiry = harness.sweep.sweep(6_001).await;
        assert_eq!(after_expiry.expired, 1);
        assert_eq!(after_expiry.restored(), 1);
        assert!(after_expiry.failures.is_empty());
        assert!(!harness.world.is_isolated("host-ttl"));

        // 5. BOTH RECEIPTS ARE DURABLE, AND BOTH VERIFY.
        let closed = harness.store.closed_receipts().unwrap();
        assert_eq!(closed.len(), 2);
        let manual_receipt = closed
            .iter()
            .find(|receipt| receipt.lease_id == "lease-manual")
            .unwrap();
        let ttl_receipt = closed
            .iter()
            .find(|receipt| receipt.lease_id == "lease-ttl")
            .unwrap();
        assert_eq!(manual_receipt.trigger, RollbackTrigger::Manual);
        assert_eq!(ttl_receipt.trigger, RollbackTrigger::Expiry);
        verify_release_attestation(manual_receipt, harness.sweep.governance())
            .expect("manual release should verify");
        verify_release_attestation(ttl_receipt, harness.sweep.governance())
            .expect("ttl release should verify");

        // 6. MANUAL AND AUTOMATIC RELEASE DID NOT DIVERGE. Everything a
        //    reviewer would compare is equal except the trigger, the subject
        //    and the instant -- because both went through `release_lease` on
        //    the one `ContainmentSweep` that carries the store, the executor,
        //    the mode and the governance authority.
        assert_eq!(manual_receipt.status, ttl_receipt.status);
        assert_eq!(manual_receipt.status, ResponseStatus::Executed);
        assert_eq!(manual_receipt.mode, ttl_receipt.mode);
        assert_eq!(manual_receipt.mode, ExecutionMode::Enforced);
        assert!(manual_receipt.fully_reversed() && ttl_receipt.fully_reversed());
        assert_eq!(
            manual_receipt.steps.len(),
            ttl_receipt.steps.len(),
            "one release path means one step shape"
        );
        assert!(
            manual_receipt.governance_attestation.is_some()
                && ttl_receipt.governance_attestation.is_some(),
            "if only one trigger were attested the two paths would have diverged"
        );

        // 7. THE TWO ATTESTATIONS SIT ON ONE CHAIN. The manual release was
        //    attested first, so the TTL release's attestation must name the
        //    manual one's commit as its predecessor. A second signer, or a
        //    second chain, could not produce this.
        let manual_attestation = attestation_of(manual_receipt);
        let ttl_attestation = attestation_of(ttl_receipt);
        assert_eq!(
            ttl_attestation.payload.previous_commit_hash, manual_attestation.payload.commit_hash,
            "the TTL release must extend the chain the manual release advanced"
        );
        assert_eq!(
            manual_attestation.payload.issued_by,
            ttl_attestation.payload.issued_by
        );
    }

    #[tokio::test]
    async fn a_tampered_rollback_receipt_fails_verification() {
        let harness = harness();
        open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-tamper",
            "host-tamper",
            1_000,
            60_000,
        );
        let receipt = harness.sweep.release("lease-tamper", 2_000).await.unwrap();
        verify_release_attestation(&receipt, harness.sweep.governance())
            .expect("the untampered receipt must verify");

        // (a) MUTATE THE BODY. An auditor reading `fully_reversed` acts on it,
        //     so rewriting a `Failed` step into a `Reversed` one is the lie
        //     that matters most. The signature still checks out -- it covers a
        //     governance commit, not a rollback -- and the SUBJECT binding is
        //     what catches it.
        let mut rewritten = receipt.clone();
        rewritten.steps[0].status = RollbackStepStatus::Failed;
        let error = verify_release_attestation(&rewritten, harness.sweep.governance()).unwrap_err();
        assert!(
            matches!(error, ReleaseAttestationError::SubjectMismatch { .. }),
            "expected a subject mismatch, got {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("the signature does not cover this body"),
            "unexpected diagnostic: {error}"
        );

        // Every other field is covered too, not just the one above.
        for mutate in [
            (|r: &mut RollbackReceipt| r.summary.push_str(" (edited)")) as fn(&mut RollbackReceipt),
            |r: &mut RollbackReceipt| r.completed_at_ms += 1,
            |r: &mut RollbackReceipt| r.lease_id = "lease-other".to_string(),
            |r: &mut RollbackReceipt| r.rollback_id = "rollback:other".to_string(),
            |r: &mut RollbackReceipt| r.trigger = RollbackTrigger::Expiry,
            |r: &mut RollbackReceipt| r.origin_receipt_id = "resp:other".to_string(),
            |r: &mut RollbackReceipt| r.governance_receipt_id = Some("gov:other".to_string()),
            |r: &mut RollbackReceipt| r.status = ResponseStatus::Failed,
            |r: &mut RollbackReceipt| r.mode = ExecutionMode::DryRun,
        ] {
            let mut tampered = receipt.clone();
            mutate(&mut tampered);
            assert!(
                matches!(
                    verify_release_attestation(&tampered, harness.sweep.governance()),
                    Err(ReleaseAttestationError::SubjectMismatch { .. })
                ),
                "a mutated receipt must not verify: {tampered:?}"
            );
        }

        // (b) MUTATE THE ATTESTATION. `ConsensusGovernanceReceipt::verify`
        //     re-canonicalizes the payload and checks the detached signature,
        //     so this fails at the signature rather than at the binding.
        let mut forged = receipt.clone();
        let mut attestation = attestation_of(&receipt);
        attestation.payload.issued_at_ms += 1;
        forged.governance_attestation = Some(serde_json::to_value(&attestation).unwrap());
        let error = verify_release_attestation(&forged, harness.sweep.governance()).unwrap_err();
        assert!(
            matches!(error, ReleaseAttestationError::Signature { .. }),
            "expected a signature failure, got {error:?}"
        );

        // (c) STRIP THE ATTESTATION. A verifier that answered "fine" here
        //     would be reporting success over a region it never inspected.
        let mut stripped = receipt.clone();
        stripped.governance_attestation = None;
        let error = verify_release_attestation(&stripped, harness.sweep.governance()).unwrap_err();
        assert!(
            matches!(error, ReleaseAttestationError::Unattested { .. }),
            "expected an unattested refusal, got {error:?}"
        );

        // (d) LIFT A VALID ATTESTATION ONTO A DIFFERENT RELEASE. The signature
        //     is genuine and verifies; only the subject binding refuses it.
        open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-second",
            "host-second",
            1_000,
            60_000,
        );
        let second = harness.sweep.release("lease-second", 2_500).await.unwrap();
        let mut lifted = second.clone();
        lifted.governance_attestation = receipt.governance_attestation.clone();
        attestation_of(&lifted)
            .verify()
            .expect("the lifted signature is genuine, which is the point");
        assert!(
            matches!(
                verify_release_attestation(&lifted, harness.sweep.governance()),
                Err(ReleaseAttestationError::SubjectMismatch { .. })
            ),
            "a genuine signature over a different release must not verify this one"
        );
    }

    /// Re-attest `receipt` end to end with `signing_key`: a fresh commit whose
    /// `proposal_id` is the digest of the canonical receipt-minus-attestation,
    /// signed by whoever holds the key.
    ///
    /// This is the attacker's whole job, and it is eight lines. Every input is
    /// public: the subject is the receipt itself, and the binding rule is
    /// documented on `GovernanceAuthority::attest_release`.
    fn re_attest(receipt: &RollbackReceipt, signing_key: &SigningKey) -> Value {
        let mut subject = receipt.clone();
        subject.governance_attestation = None;
        let subject_id = sha256_hex(&canonical_json_bytes(&subject).unwrap());
        let issued_by = AgentId::from_verifying_key(&signing_key.verifying_key());
        let committee = ConsensusCommittee::new(vec![issued_by.clone()], 0).unwrap();
        let commit = ConsensusCommit {
            height: 1,
            round: 0,
            committee_id: committee.committee_id().to_string(),
            proposal: ConsensusProposal {
                proposal_id: subject_id,
                payload: json!({ "forged": true }),
            },
            prevote_tally: 1,
            precommit_tally: 1,
            commit_hash: "forged-commit-hash".to_string(),
        };
        serde_json::to_value(
            ConsensusGovernanceReceipt::issue(
                &commit,
                "forged-previous-commit-hash",
                &committee,
                GovernanceReceiptDecision::Approve,
                issued_by,
                signing_key,
                9_999,
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// A FULL RE-ATTESTATION BY A KEY NO GOVERNOR EVER HELD.
    ///
    /// The tamper test above covers PARTIAL rewrites -- body edited with the
    /// attestation left alone, or a genuine attestation lifted from another
    /// release. This is the case it did not cover: the attacker rewrites the
    /// body AND mints a fresh keypair AND recomputes `proposal_id` over the
    /// rewritten subject AND signs it. Both of the checks that shipped with
    /// QRT-04 pass on that input, because both are self-referential -- the
    /// signature is checked against a public key carried inside the receipt,
    /// and the subject digest against the body the attacker wrote.
    #[tokio::test]
    async fn a_fully_re_attested_receipt_is_refused() {
        let harness = harness();
        open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-forge",
            "host-forge",
            1_000,
            60_000,
        );
        let receipt = harness.sweep.release("lease-forge", 2_000).await.unwrap();
        verify_release_attestation(&receipt, harness.sweep.governance())
            .expect("the genuine receipt must verify");

        // The lie an auditor would act on: a release that did NOT restore the
        // host, rewritten to say it did -- and then re-signed end to end.
        let mut forged = receipt.clone();
        forged.steps[0].status = RollbackStepStatus::Failed;
        forged.summary = "forged by a key no governor ever held".to_string();
        let attacker = SigningKey::from_bytes(&[251; 32]);
        forged.governance_attestation = Some(re_attest(&forged, &attacker));

        // The forged attestation is signed by a DIFFERENT key than the genuine
        // one, which is what makes this a trust-anchor question rather than a
        // signature question.
        let attacker_id = AgentId::from_verifying_key(&attacker.verifying_key());
        assert_ne!(attestation_of(&receipt).payload.issued_by, attacker_id);
        // Both shipped checks pass on the forgery, individually.
        attestation_of(&forged)
            .verify()
            .expect("the forged signature is internally consistent, which is the point");

        let error = verify_release_attestation(&forged, harness.sweep.governance())
            .expect_err("a receipt re-attested by an unknown key must be refused");
        assert!(
            matches!(error, ReleaseAttestationError::UntrustedSigner { .. }),
            "expected an untrusted-signer refusal, got {error:?}"
        );
        // The diagnostic names the key that actually signed, so an operator can
        // tell a forgery from a governor rotation they forgot about.
        assert!(
            error.to_string().contains(&attacker_id.0),
            "the refusal should name the untrusted signer: {error}"
        );

        // FAIL CLOSED WITH NO ANCHOR. The same GENUINE receipt that verified
        // above is refused when there is no authority to check it against --
        // not accepted on the strength of the key it carries.
        let error = verify_release_attestation(&receipt, None)
            .expect_err("with no governor set, a verifier knows nothing and must say so");
        assert!(
            matches!(error, ReleaseAttestationError::UntrustedSigner { .. }),
            "expected a refusal with no trust anchor, got {error:?}"
        );
        assert!(
            error.to_string().contains("no governor public keys"),
            "the refusal should name the missing anchor: {error}"
        );
    }

    #[tokio::test]
    async fn release_route_refuses_unauthenticated_and_unscoped_callers() {
        let harness = harness();
        open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-auth",
            "host-auth",
            1_000,
            60_000,
        );

        let anonymous = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/containment/leases/lease-auth/release")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        assert!(
            harness.world.is_isolated("host-auth"),
            "a rejected request must not have released anything"
        );

        // A principal with every scope EXCEPT maintenance.
        unsafe {
            std::env::set_var("SWARM_OPERATOR_READONLY_TOKEN", "readonly-token");
        }
        let readonly = super::super::containment::containment_operator_router(
            &scoped_operator_config(
                "SWARM_OPERATOR_READONLY_TOKEN",
                vec![OperatorPrincipalConfig {
                    operator_id: "readonly-operator".to_string(),
                    token_env: "SWARM_OPERATOR_READONLY_TOKEN".to_string(),
                    token_expires_at_ms: None,
                    scopes: vec![
                        OperatorScope::Read,
                        OperatorScope::Rehearse,
                        OperatorScope::Approve,
                    ],
                }],
            ),
            Arc::clone(&harness.sweep),
        )
        .unwrap();
        let forbidden = readonly
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/containment/leases/lease-auth/release")
                    .header("authorization", "Bearer readonly-token")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        assert!(
            harness.world.is_isolated("host-auth"),
            "a forbidden request must not have released anything"
        );

        // The same principal may still LIST: reading which hosts are contained
        // is not the destructive act.
        let listed = readonly
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/containment/leases?now_ms=2000")
                    .header("authorization", "Bearer readonly-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn releasing_an_unknown_lease_is_a_404_and_changes_nothing() {
        let harness = harness();
        open_containment(
            &harness.world,
            harness.store.as_ref(),
            "lease-known",
            "host-known",
            1_000,
            60_000,
        );
        let response = harness
            .app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/containment/leases/lease-typo/release")
                    .header(bearer().0, bearer().1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("no open containment lease `lease-typo`"),
            "unexpected body: {body:?}"
        );
        assert!(harness.world.is_isolated("host-known"));
        assert_eq!(harness.store.open_leases().unwrap().len(), 1);
        assert!(harness.store.closed_receipts().unwrap().is_empty());
    }

    /// A release the world refused is NOT a release, and neither the lease nor
    /// the chain may pretend otherwise.
    #[tokio::test]
    async fn a_release_whose_inverse_failed_keeps_the_lease_open_and_is_not_attested() {
        let harness = harness();
        // Open a lease over a host the world never isolated, so the executor's
        // `remove` returns false and it reports a `Failed` step -- the shape
        // `HttpEdrRollbackExecutor` produces against an unreachable endpoint.
        let lease = ContainmentLease::open(
            "lease-unreachable",
            ResponseAction::IsolateHost {
                host_id: "host-unreachable".to_string(),
            },
            "resp:lease-unreachable".to_string(),
            Some("gov:lease-unreachable".to_string()),
            &isolate_preview("host-unreachable"),
            1_000,
            ContainmentTtl::from_config_ms(60_000).unwrap(),
        )
        .unwrap();
        harness.store.open_lease(&lease).unwrap();

        let response = harness
            .app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/operator/containment/leases/lease-unreachable/release")
                    .header(bearer().0, bearer().1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({ "now_ms": 2_000 }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["lease_closed"], false);
        assert_eq!(body["fully_reversed"], false);
        assert_eq!(body["attestation_verified"], false);
        assert!(
            body["attestation_error"]
                .as_str()
                .unwrap_or_default()
                .contains("carries no governance attestation"),
            "unexpected attestation error: {body:?}"
        );
        assert_eq!(
            harness.store.open_leases().unwrap().len(),
            1,
            "a failed inverse must leave the lease open for the next sweep"
        );
        assert!(harness.store.closed_receipts().unwrap().is_empty());
    }
}
