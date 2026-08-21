    use super::{
        ConfiguredRuntimeStack, EventExecutionContext, ReadinessError, RehearsalPreviewError,
        ResponsePlaybookPreviewRequest, ResponsePlaybookPreviewStatus, RuntimeService,
        ServiceError,
    };
    use swarm_core::{BridgeStatusReport, BridgeStatusSnapshot};
    use crate::correlation::CorrelationEngine;
    use crate::detection::metrics::{CriticalPathMetrics, encode_metrics};
    use crate::investigation::{InvestigationOutcome, InvestigationStrategy};
    use crate::{RuntimeMode, SwarmRuntime};
    use async_trait::async_trait;
    use axum::body::to_bytes;
    use axum::extract::{Request, State};
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CircuitBreakerConfig, CorrelationConfig,
        InvestigationConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
        PolicyRuleConfig, PolicyRuleDecision, PromotionConfig, ResponsePlaybookBranch,
        ResponsePlaybookCondition, ResponsePlaybookConfig, ResponsePlaybookRule, RetryConfig,
        RuntimeSettings, SiemForwardConfig, SwarmConfig, TelemetrySourceConfig,
        TemporalEventWindowConfig,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{
        AgentId, HuntId, ResponseAction, ResponseBlastRadiusImpact, ResponseRehearsalScopeKind,
        ResponseRollbackStepKind, Severity,
    };
    use swarm_guard::{
        Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
    };
    use swarm_pheromone::{InMemoryPheromoneSubstrate, LocalJournalPheromoneSubstrate};
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_policy::{ActionRequest, ApprovalContext, CapabilityLease, PolicyVerdict};
    use swarm_response::adapters::SandboxExecutor;
    use swarm_response::{
        ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
    };
    use swarm_spine::{
        AuditResponseRecord, FileReplayBundleStore, InvestigationBundleStore, MemoryIncidentStore,
        MemoryInvestigationBundleStore, MemoryReplayBundleStore, ReplayBundle, ReplayBundleStore,
    };
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent, TelemetryEventPredicate,
        TelemetryPayload,
    };
    use tokio::sync::{Mutex as AsyncMutex, oneshot};

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_agent_id() -> AgentId {
        AgentId::from_verifying_key(&test_signing_key().verifying_key())
    }

    fn service_config(
        mode: RuntimeMode,
        backend: PheromoneBackendConfig,
        require_durable: bool,
    ) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "test".to_string(),
            description: "test config".to_string(),
            runtime: RuntimeSettings {
                mode,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                threat_intel_feeds: vec![],
                max_in_flight_actions: 4,
                drain_timeout_ms: 30_000,
                require_durable_live_response: require_durable,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: Default::default(),
                temporal_event_window: TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
                containment: Default::default(),
            },
            detection: swarm_core::config::DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: swarm_core::config::DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: Default::default(),
                backend,
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
            investigation: InvestigationConfig::default(),
            hypothesis_graph: Default::default(),
            correlation: CorrelationConfig::default(),
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: swarm_core::config::OperatorSurfaceConfig::default(),
            tls: None,
        }
    }

    fn runtime_service() -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        )
    }

    fn runtime_service_with_prometheus() -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        runtime_service().with_prometheus(CriticalPathMetrics::new())
    }

    fn permissive_policy_rules() -> Vec<PolicyRuleConfig> {
        vec![PolicyRuleConfig {
            name: "service-preview-allow-execution".to_string(),
            decision: PolicyRuleDecision::Allow,
            threat_class: ThreatClass::Execution,
            actions: Vec::new(),
            min_severity: Severity::Low,
            max_severity: Severity::Critical,
            time_window_utc: None,
            max_actions_per_agent_per_minute: None,
            reason: Some("service preview tests allow execution responses".to_string()),
        }]
    }

    fn branching_playbook() -> ResponsePlaybookConfig {
        ResponsePlaybookConfig {
            rules: vec![ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.90,
                max_confidence: 1.0,
                actions: vec![ResponseAction::Escalate {
                    summary: "fallback execution review".to_string(),
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
        }
    }

    fn runtime_service_with_branching_playbook()
    -> RuntimeService<StaticApprovalGate, SandboxExecutor> {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.policy.rules = permissive_policy_rules();
        config.pheromone.response_playbook = branching_playbook();
        RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        )
    }

    fn suspicious_event(event_id: &str, command_line: &str) -> TelemetryEvent {
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

    fn approval_context(now_ms: i64, correlation_id: &str) -> ApprovalContext {
        ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: Some(correlation_id.to_string()),
            now_ms,
        }
    }

    fn preview_request(action: ResponseAction) -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-preview".to_string()),
            requested_by: test_agent_id(),
            action,
            severity: Severity::High,
            evidence: json!({
                "test": "phase_213_preview"
            }),
        }
    }

    #[derive(Clone, Default)]
    struct ForwardCaptureState {
        auth: std::sync::Arc<AsyncMutex<Option<String>>>,
        payloads: std::sync::Arc<AsyncMutex<Vec<Value>>>,
    }

    async fn forward_capture_handler(
        State(state): State<ForwardCaptureState>,
        headers: HeaderMap,
        request: Request,
    ) -> (StatusCode, Json<Value>) {
        {
            let mut auth = state.auth.lock().await;
            *auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
        }
        let body = to_bytes(request.into_body(), usize::MAX).await.unwrap();
        let rendered = String::from_utf8(body.to_vec()).unwrap();
        let payloads = if let Ok(value) = serde_json::from_str::<Value>(&rendered) {
            vec![value]
        } else {
            rendered
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>()
        };
        {
            let mut captured = state.payloads.lock().await;
            captured.extend(payloads);
        }
        (StatusCode::OK, Json(json!({"ok": true})))
    }

    async fn spawn_forward_capture_server() -> (
        String,
        ForwardCaptureState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = ForwardCaptureState::default();
        let app = Router::new()
            .route("/", post(forward_capture_handler))
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

    fn temp_jsonl_path(label: &str) -> String {
        std::env::temp_dir()
            .join(format!(
                "swarm-runtime-{label}-{}-{}.jsonl",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .display()
            .to_string()
    }

    struct BlockingGuard;

    impl Guard for BlockingGuard {
        fn name(&self) -> &str {
            "test_guard"
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            GuardResult::block("test_guard", GuardSeverity::Critical, "blocked in test")
        }
    }

    #[derive(Clone)]
    struct TimeoutExecutor;

    #[async_trait]
    impl ResponseExecutor for TimeoutExecutor {
        async fn execute(
            &self,
            request: &ActionRequest,
            _lease: &CapabilityLease,
            mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            Ok(ResponseReceipt {
                receipt_id: format!("timeout:{}", request.hunt_id.0),
                action: request.action.kind().to_string(),
                mode,
                status: ResponseStatus::Timeout,
                summary: "timed out in test".to_string(),
                details: serde_json::json!({
                    "adapter": "timeout_test",
                    "status": "timeout",
                }),
                audit: Default::default(),
            })
        }
    }

    #[derive(Clone, Default)]
    struct RecordingModeExecutor {
        modes: std::sync::Arc<AsyncMutex<Vec<ExecutionMode>>>,
    }

    #[async_trait]
    impl ResponseExecutor for RecordingModeExecutor {
        async fn execute(
            &self,
            request: &ActionRequest,
            _lease: &CapabilityLease,
            mode: ExecutionMode,
        ) -> Result<ResponseReceipt, ResponseError> {
            self.modes.lock().await.push(mode);
            Ok(ResponseReceipt {
                receipt_id: format!("recorded:{}", request.hunt_id.0),
                action: request.action.kind().to_string(),
                mode,
                status: if mode == ExecutionMode::DryRun {
                    ResponseStatus::Simulated
                } else {
                    ResponseStatus::Executed
                },
                summary: "recorded execution".to_string(),
                details: serde_json::json!({
                    "adapter": "recording_mode_executor",
                }),
                audit: Default::default(),
            })
        }
    }

    fn runtime_service_with_recording_modes() -> (
        RuntimeService<StaticApprovalGate, RecordingModeExecutor>,
        std::sync::Arc<AsyncMutex<Vec<ExecutionMode>>>,
    ) {
        let executor = RecordingModeExecutor::default();
        let modes = executor.modes.clone();
        (
            RuntimeService::new(
                service_config(
                    RuntimeMode::DetectOnly,
                    PheromoneBackendConfig::InMemory,
                    false,
                ),
                SwarmRuntime::new(
                    RuntimeMode::DetectOnly,
                    StaticApprovalGate::default(),
                    executor,
                ),
            ),
            modes,
        )
    }

    #[derive(Debug, Clone)]
    struct SlowInvestigator {
        delay_ms: u64,
    }

    #[async_trait]
    impl InvestigationStrategy for SlowInvestigator {
        fn id(&self) -> &str {
            "slow_service_test_investigator"
        }

        async fn investigate(&self, replay: &ReplayBundle) -> Result<InvestigationOutcome, String> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(InvestigationOutcome {
                summary: format!("investigated {}", replay.audit.hunt_id),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec!["host:host-1".to_string()],
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
            })
        }
    }
