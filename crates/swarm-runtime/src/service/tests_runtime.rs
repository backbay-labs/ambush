    #[tokio::test]
    async fn process_event_creates_and_replays_bundle() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
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
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_000,
        };
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
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

        match &bundle.audit.response {
            AuditResponseRecord::Success(receipt) => {
                assert_eq!(receipt.status, ResponseStatus::Executed);
            }
            other => panic!("expected successful response record, got {other:?}"),
        }

        let path = std::env::temp_dir().join("swarm-runtime-replay-bundle.json");
        service.save_replay_bundle(&bundle, &path).unwrap();
        let replayed = service.load_replay_bundle(&path).unwrap();

        assert_eq!(replayed.audit.trail_id, bundle.audit.trail_id);
        assert_eq!(replayed.findings.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_event_records_temporal_window_state_without_findings() {
        let mut config = service_config(
            RuntimeMode::DetectOnly,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.runtime.temporal_event_window = TemporalEventWindowConfig {
            retention_ms: 120_000,
            max_events: 4,
            max_match_span_ms: 120_000,
            max_predicates_per_match: 4,
        };
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::DetectOnly,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let agent_id = test_agent_id();
        let first_event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-seq-a".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "explorer".to_string(),
                process_name: "cmd".to_string(),
                command_line: "cmd.exe /c whoami".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let second_event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-seq-b".to_string(),
            timestamp: 1_700_000_030,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "cmd".to_string(),
                process_name: "whoami".to_string(),
                command_line: "whoami".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let first_context = ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["receipt-seq-a".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_000,
        };
        let second_context = ApprovalContext {
            live_mode: false,
            receipt_chain: vec!["receipt-seq-b".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_030_000,
        };

        assert!(
            service
                .process_event(
                    &detector,
                    &substrate,
                    &first_event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &first_context,
                        signing_key: &test_signing_key(),
                    },
                    |_finding| None,
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .process_event(
                    &detector,
                    &substrate,
                    &second_event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &second_context,
                        signing_key: &test_signing_key(),
                    },
                    |_finding| None,
                )
                .await
                .unwrap()
                .is_none()
        );

        let snapshot = service.runtime.temporal_event_window_snapshot();
        assert_eq!(snapshot.retained_events, 2);

        let first_step = |event: &TelemetryEvent| event.event_id == "evt-seq-a";
        let second_step = |event: &TelemetryEvent| event.event_id == "evt-seq-b";
        let predicates: [&dyn TelemetryEventPredicate; 2] = [&first_step, &second_step];
        let matched = service
            .runtime
            .match_temporal_sequence(&predicates, Some(60_000))
            .unwrap()
            .unwrap();
        assert_eq!(matched.matched_events.len(), 2);
        assert_eq!(matched.matched_events[0].event_id, "evt-seq-a");
        assert_eq!(matched.matched_events[1].event_id, "evt-seq-b");
    }

    #[tokio::test]
    async fn process_event_preserves_stable_identity_in_request_and_receipt() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-stable-identity".to_string(),
            timestamp: 1_700_000_111,
            host_id: Some("host-identity".to_string()),
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
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-identity-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_111_000,
        };
        let agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
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

        assert_eq!(bundle.action_request.requested_by, agent_id);
        let AuditResponseRecord::Success(receipt) = &bundle.audit.response else {
            panic!(
                "expected successful response record, got {:?}",
                bundle.audit.response
            );
        };
        assert_eq!(receipt.details["requested_by"], serde_json::json!(agent_id));
    }

    #[tokio::test]
    async fn process_event_enriches_findings_before_bundle_persistence() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-enrichment-1", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_005, "corr-enrichment");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        let evidence = &bundle.findings[0].evidence;
        assert_eq!(
            evidence["parent_process_ancestry"],
            json!(["winword", "powershell"])
        );
        assert_eq!(evidence["host_metadata"]["source"], "synthetic");
        assert_eq!(evidence["host_metadata"]["host_id"], "host-1");
        assert_eq!(evidence["host_metadata"]["event_id"], "evt-enrichment-1");
        assert_eq!(evidence["host_metadata"]["event_timestamp"], 1_700_000_000);
        assert!(evidence["time_to_detect_ms"].as_i64().unwrap() >= 0);
        assert_eq!(evidence["escalation"]["threat_class"], "execution");
        assert_eq!(evidence["escalation"]["severity"], "CRITICAL");
        assert_eq!(evidence["escalation"]["strategy_id"], "suspicious_process_tree");
    }

    #[tokio::test]
    async fn process_event_forwards_enriched_findings_to_siem() {
        let (endpoint, state, shutdown_tx, handle) = spawn_forward_capture_server().await;
        let dead_letter_path = temp_jsonl_path("siem-forward");
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.siem_forward = Some(SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token: "splunk-secret".into(),
            timeout_ms: 500,
            batch_max_events: 32,
            batch_max_bytes: 131_072,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: dead_letter_path.clone(),
        });
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-siem-1", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_021, "corr-siem");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| None,
            )
            .await
            .unwrap();

        assert!(bundle.is_none());
        assert_eq!(
            state.auth.lock().await.clone().as_deref(),
            Some("Splunk splunk-secret")
        );
        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["source"], "swarm-team-six");
        assert_eq!(payloads[0]["sourcetype"], "swarm:finding");
        assert_eq!(payloads[0]["event"]["event_id"], "evt-siem-1");
        assert_eq!(payloads[0]["event"]["signature"], "suspicious_process_tree");
        assert_eq!(payloads[0]["event"]["severity"], "CRITICAL");
        assert_eq!(
            payloads[0]["event"]["raw_evidence"]["parent_process_ancestry"],
            json!(["winword", "powershell"])
        );
        assert_eq!(
            payloads[0]["event"]["raw_evidence"]["escalation"]["threat_class"],
            "execution"
        );
        assert_eq!(
            payloads[0]["event"]["raw_evidence"]["host_metadata"]["host_id"],
            "host-1"
        );
        assert!(
            payloads[0]["event"]["raw_evidence"]["time_to_detect_ms"]
                .as_i64()
                .unwrap()
                >= 0
        );

        let _ = shutdown_tx.send(());
        handle.abort();
        let _ = std::fs::remove_file(dead_letter_path);
    }

    /// The durability half of the SIEM forward contract, and the reason
    /// `join_siem_forward` exists rather than a bare `tokio::spawn`.
    ///
    /// A dropped `JoinHandle` is not fire-and-forget: tokio aborts the task when the
    /// runtime shuts down. `swarm_detect` in scenario mode is a one-shot CLI, so a
    /// detached forward is cancelled mid-POST on exit with no dead-letter entry, no
    /// receipt and no counter. This drives `process_event` on a runtime that is
    /// dropped the instant it returns, and asserts the forward already landed.
    ///
    /// The capture server deliberately lives on a SEPARATE runtime so that dropping
    /// the service runtime models process shutdown without also killing the sink.
    #[test]
    fn process_event_completes_the_siem_forward_before_its_runtime_shuts_down() {
        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (endpoint, state, shutdown_tx, handle) =
            server_runtime.block_on(spawn_forward_capture_server());
        let dead_letter_path = temp_jsonl_path("siem-forward-shutdown");
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.siem_forward = Some(SiemForwardConfig::SplunkHec {
            endpoint,
            auth_token: "splunk-secret".into(),
            timeout_ms: 500,
            batch_max_events: 32,
            batch_max_bytes: 131_072,
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            dead_letter_path: dead_letter_path.clone(),
        });
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );

        let service_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        service_runtime.block_on(async {
            let detector = SuspiciousProcessTreeDetector::default();
            let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
            let event = suspicious_event("evt-siem-shutdown-1", "powershell.exe -enc AAA=");
            let context = approval_context(1_700_000_000_031, "corr-siem-shutdown");
            let agent_id = test_agent_id();
            service
                .process_event(
                    &detector,
                    &substrate,
                    &event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &context,
                        signing_key: &test_signing_key(),
                    },
                    |_finding| None,
                )
                .await
                .unwrap()
        });
        // Process shutdown. Anything still detached dies here.
        drop(service_runtime);

        let payloads = server_runtime.block_on(async { state.payloads.lock().await.clone() });
        assert_eq!(
            payloads.len(),
            1,
            "SIEM forward must complete before process_event returns, not race runtime shutdown"
        );
        assert_eq!(payloads[0]["event"]["event_id"], "evt-siem-shutdown-1");

        let _ = shutdown_tx.send(());
        handle.abort();
        let _ = std::fs::remove_file(dead_letter_path);
    }

    #[tokio::test]
    async fn process_event_records_success_metrics_in_prometheus() {
        let service = runtime_service_with_prometheus();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-success", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_010, "corr-success");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(bundle.audit.policy.verdict, PolicyVerdict::Allow);
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"success\"} 1"));
        assert!(
            encoded.contains(
                "swarm_findings_total{detector=\"suspicious_process_tree\",threat_class=\"execution\"} 1"
            ) || encoded.contains(
                "swarm_findings_total{threat_class=\"execution\",detector=\"suspicious_process_tree\"} 1"
            )
        );
    }

    #[tokio::test]
    async fn process_event_records_guard_rejection_metrics_in_prometheus() {
        let runtime = SwarmRuntime::new(
            RuntimeMode::LiveResponse,
            StaticApprovalGate::default(),
            SandboxExecutor,
        )
        .with_guard_pipeline(GuardPipeline::new(vec![Box::new(BlockingGuard)]));
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            runtime,
        )
        .with_prometheus(CriticalPathMetrics::new());
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-guard", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_011, "corr-guard");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            bundle.audit.response,
            AuditResponseRecord::GuardRejected { .. }
        ));
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_guard_rejections_total{guard_name=\"test_guard\"} 1"));
    }

    #[tokio::test]
    async fn process_event_records_timeout_metrics_in_prometheus() {
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                TimeoutExecutor,
            ),
        )
        .with_prometheus(CriticalPathMetrics::new());
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-timeout", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_012, "corr-timeout");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            bundle.audit.response,
            AuditResponseRecord::Failure(_)
        ));
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"timeout\"} 1"));
    }

    #[tokio::test]
    async fn process_event_records_require_human_metrics_in_prometheus() {
        let service = runtime_service_with_prometheus();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-metrics-human", "powershell.exe -enc AAA=");
        let context = approval_context(1_700_000_000_013, "corr-human");
        let agent_id = test_agent_id();

        let bundle = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::BlockEgress {
                        target: "203.0.113.10".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(bundle.audit.policy.verdict, PolicyVerdict::RequireHuman);
        assert!(matches!(
            bundle.audit.response,
            AuditResponseRecord::Skipped { .. }
        ));
        let encoded = encode_metrics(service.prometheus_metrics().unwrap());
        assert!(encoded.contains("swarm_verdict_total{verdict=\"require_human\"} 1"));
    }

    #[tokio::test]
    async fn live_response_requires_durable_substrate_when_enabled() {
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                true,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());

        let error = service
            .ensure_substrate_ready(&substrate)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ServiceError::Readiness {
                component: "substrate",
                source: ReadinessError::SubstrateNotDurable { .. },
            }
        ));
    }

    #[tokio::test]
    async fn local_journal_satisfies_durable_live_response_readiness() {
        let path = std::env::temp_dir().join("swarm-runtime-durable-substrate.jsonl");
        let service = RuntimeService::new(
            service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::LocalJournal {
                    path: path.display().to_string(),
                },
                true,
            ),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let substrate =
            LocalJournalPheromoneSubstrate::open(service.config.pheromone.clone(), &path).unwrap();

        let health = service.ensure_substrate_ready(&substrate).await.unwrap();
        assert!(health.ready);
        assert!(health.durable);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn process_event_with_store_persists_and_loads_by_receipt_id() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let store_root = std::env::temp_dir().join("swarm-runtime-file-store");
        let _ = std::fs::remove_dir_all(&store_root);
        let store = FileReplayBundleStore::open(&store_root).unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-store-1".to_string(),
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
        let context = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_001,
        };
        let agent_id = test_agent_id();

        let persisted = service
            .process_event_with_store(
                &detector,
                &substrate,
                &store,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context,
                    signing_key: &test_signing_key(),
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

        let response_receipt_id = persisted
            .record
            .response_receipt_id
            .clone()
            .expect("response receipt id");
        let loaded = service
            .load_persisted_bundle_by_receipt_id(&store, &response_receipt_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.record.bundle_id, persisted.record.bundle_id);

        let preview = service.replay_preview(&loaded.bundle);
        assert_eq!(preview.bundle_id, persisted.record.bundle_id);
        assert!(
            preview
                .note
                .contains("no live response action was re-executed")
        );

        let _ = std::fs::remove_dir_all(store_root);
    }

    #[tokio::test]
    async fn rehearse_bundle_persists_typed_preview_and_forces_dry_run() {
        let (service, modes) = runtime_service_with_recording_modes();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-rehearsal-1", "powershell.exe -enc AAA=");
        let source_context = approval_context(1_700_000_000_100, "corr-rehearsal-source");
        let agent_id = test_agent_id();

        let source = service
            .process_event(
                &detector,
                &substrate,
                &event,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &source_context,
                    signing_key: &test_signing_key(),
                },
                |_finding| {
                    Some(ResponseAction::BlockEgress {
                        target: "203.0.113.10".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            source.audit.response,
            AuditResponseRecord::Skipped { .. }
        ));
        assert!(modes.lock().await.is_empty());

        let store = MemoryReplayBundleStore::default();
        let rehearsal_context = approval_context(1_700_000_000_200, "corr-rehearsal-run");
        let persisted = service
            .rehearse_bundle_with_store(&store, &source, &rehearsal_context)
            .await
            .unwrap();

        assert_eq!(&*modes.lock().await, &[ExecutionMode::DryRun]);
        assert!(persisted.record.is_rehearsal);
        assert!(persisted.record.bundle_id.contains("rehearsal"));
        let rehearsal = persisted
            .bundle
            .rehearsal
            .as_ref()
            .expect("rehearsal preview");
        assert_eq!(rehearsal.source_bundle_id, source.bundle_id);
        assert!(rehearsal.simulated_only);
        assert_eq!(
            rehearsal.blast_radius.scope_kind,
            ResponseRehearsalScopeKind::NetworkTarget
        );
        assert_eq!(
            rehearsal.rollback.steps[0].kind,
            ResponseRollbackStepKind::RemoveNetworkBlock
        );
        let AuditResponseRecord::Success(receipt) = &persisted.bundle.audit.response else {
            panic!(
                "expected successful rehearsal response, got {:?}",
                persisted.bundle.audit.response
            );
        };
        assert_eq!(
            persisted.bundle.audit.policy.verdict,
            PolicyVerdict::RequireHuman
        );
        assert_eq!(receipt.mode, ExecutionMode::DryRun);
        assert_eq!(receipt.status, ResponseStatus::Simulated);

        let loaded = service
            .load_persisted_bundle_by_bundle_id(&store, &persisted.record.bundle_id)
            .unwrap()
            .unwrap();
        let preview = service.replay_preview(&loaded.bundle);
        assert!(preview.rehearsal.is_some());
        assert!(preview.note.contains("dry-run receipt"));
    }
