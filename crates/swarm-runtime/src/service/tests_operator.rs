    #[tokio::test]
    async fn operator_status_reports_metrics_and_recent_decisions() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::replay(service.config.pheromone.clone());
        let store_root = std::env::temp_dir().join("swarm-runtime-operator-store");
        let _ = std::fs::remove_dir_all(&store_root);
        let store = FileReplayBundleStore::open(&store_root).unwrap();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-status-1".to_string(),
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
            receipt_chain: vec!["receipt-upstream-2".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_002,
        };
        let agent_id = test_agent_id();

        let _ = service
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

        let status = service
            .operator_status(&detector, &substrate, &store)
            .await
            .unwrap();
        assert_eq!(status.mode, RuntimeMode::LiveResponse);
        assert_eq!(
            status.detector.details,
            "strategy `suspicious_process_tree`"
        );
        assert_eq!(status.replay_store.durable, Some(true));
        assert_eq!(status.recent_decisions.len(), 1);
        assert_eq!(status.metrics.detect.successes, 1);
        assert_eq!(status.metrics.policy.successes, 1);
        assert_eq!(status.metrics.persist.successes, 1);
        assert_eq!(status.metrics.response.successes, 1);
        assert!(status.bridges.is_none());
        assert!(status.warnings.is_empty());

        let recent = store.recent(1).unwrap();
        assert_eq!(recent.len(), 1);

        let _ = std::fs::remove_dir_all(store_root);
    }

    #[tokio::test]
    async fn operator_status_with_bridges_surfaces_bridge_report_and_warning() {
        let config = service_config(
            RuntimeMode::DetectOnly,
            PheromoneBackendConfig::InMemory,
            false,
        );
        let service = RuntimeService::new(
            config,
            SwarmRuntime::new(
                RuntimeMode::DetectOnly,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::replay(service.config.pheromone.clone());
        let store = swarm_spine::MemoryReplayBundleStore::default();

        let bridges = BridgeStatusReport::from_entries(vec![
            BridgeStatusSnapshot {
                name: "cloudtrail-primary".to_string(),
                source_id: "cloudtrail".to_string(),
                ready: true,
                events_processed: 4,
                error_count: 0,
                lag_seconds: Some(1.5),
                last_error: None,
            },
            BridgeStatusSnapshot {
                name: "tetragon-primary".to_string(),
                source_id: "tetragon".to_string(),
                ready: false,
                events_processed: 9,
                error_count: 2,
                lag_seconds: Some(8.0),
                last_error: Some("stream closed".to_string()),
            },
        ]);

        let status = service
            .operator_status_with_bridges(&detector, &substrate, &store, bridges)
            .await
            .unwrap();

        assert_eq!(
            status.bridges.as_ref().map(|report| report.configured),
            Some(2)
        );
        assert!(
            status
                .warnings
                .iter()
                .any(|warning| warning.contains("telemetry bridge"))
        );
    }

    #[tokio::test]
    async fn process_event_with_investigation_stays_nonblocking_and_persists_bundle() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 2,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::replay(service.config.pheromone.clone());
        let replay_store_root =
            std::env::temp_dir().join("swarm-runtime-investigation-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let investigation_completed =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            SlowInvestigator {
                delay_ms: 75,
                completed: Some(std::sync::Arc::clone(&investigation_completed)),
            },
            investigation_store.clone(),
        );
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-investigation-1".to_string(),
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
            receipt_chain: vec!["receipt-upstream-3".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_003,
        };
        let agent_id = test_agent_id();

        let persisted = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
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

        assert!(
            !investigation_completed.load(std::sync::atomic::Ordering::Acquire),
            "expected nonblocking path to return before the background investigation completed"
        );
        let investigation = persisted.investigation.expect("queued investigation");
        assert_eq!(
            investigation.status,
            swarm_spine::InvestigationStatus::Queued
        );

        tokio::time::sleep(std::time::Duration::from_millis(125)).await;

        let by_hunt = service
            .load_persisted_investigation_by_hunt_id(&investigation_store, "evt-investigation-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            by_hunt.bundle.status,
            swarm_spine::InvestigationStatus::Completed
        );

        let receipt_id = persisted
            .replay
            .record
            .response_receipt_id
            .clone()
            .expect("response receipt id");
        let by_receipt = service
            .load_persisted_investigation_by_receipt_id(&investigation_store, &receipt_id)
            .unwrap()
            .unwrap();
        assert_eq!(by_receipt.bundle.hunt_id, "evt-investigation-1");
        assert!(coordinator.snapshot().completed_jobs >= 1);

        let _ = std::fs::remove_dir_all(replay_store_root);
    }

    #[tokio::test]
    async fn correlate_hunt_persists_incident_with_rejected_candidates() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 4,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        config.correlation = CorrelationConfig {
            enabled: true,
            time_window_ms: 5_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let investigation_store = MemoryInvestigationBundleStore::default();
        let incident_store = MemoryIncidentStore::default();
        let engine = CorrelationEngine::new(config.correlation.clone());

        let completed = |investigation_id: &str,
                         hunt_id: &str,
                         queued_at_ms: i64,
                         correlation_keys: &[&str]| {
            swarm_spine::InvestigationBundle {
                investigation_id: investigation_id.to_string(),
                source_bundle_id: format!("bundle:{hunt_id}:1"),
                hunt_id: hunt_id.to_string(),
                trail_id: format!("trail:{hunt_id}:1"),
                event_id: format!("evt:{hunt_id}"),
                finding_id: format!("finding:{hunt_id}"),
                threat_class: swarm_core::pheromone::ThreatClass::Execution,
                severity: Severity::Critical,
                strategy_id: "summary_investigator".to_string(),
                response_kind: "success".to_string(),
                related_receipt_ids: vec![format!("receipt:{hunt_id}")],
                host_id: Some("host-1".to_string()),
                user: Some("alice".to_string()),
                process_name: Some("powershell".to_string()),
                queued_at_ms,
                started_at_ms: Some(queued_at_ms + 10),
                completed_at_ms: Some(queued_at_ms + 100),
                status: swarm_spine::InvestigationStatus::Completed,
                priority: swarm_spine::InvestigationPriority::default(),
                summary: Some(format!("summary for {hunt_id}")),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: correlation_keys.iter().map(|key| key.to_string()).collect(),
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
                decision: swarm_spine::InvestigationDecision::default(),
                failure_reason: None,
                graph_findings_published: false,
            }
        };

        investigation_store
            .persist(&completed(
                "investigation:hunt-1:1",
                "hunt-1",
                1_700_000_000_000,
                &["host:host-1", "user:alice", "strategy:summary"],
            ))
            .unwrap();
        investigation_store
            .persist(&completed(
                "investigation:hunt-2:1",
                "hunt-2",
                1_700_000_003_000,
                &["host:host-1", "user:alice"],
            ))
            .unwrap();
        investigation_store
            .persist(&completed(
                "investigation:hunt-3:1",
                "hunt-3",
                1_700_000_010_500,
                &["host:host-1"],
            ))
            .unwrap();

        let outcome = service
            .correlate_hunt(&engine, &investigation_store, &incident_store, "hunt-1")
            .unwrap()
            .unwrap();
        assert_eq!(outcome.incident.included_members.len(), 2);
        assert_eq!(outcome.incident.rejected_members.len(), 1);
        assert!(
            outcome
                .incident
                .rejected_members
                .first()
                .unwrap()
                .reason
                .contains("outside correlation time window")
        );

        let loaded = service
            .load_incident_by_hunt_id(&incident_store, "hunt-2")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.record.incident_id, outcome.record.incident_id);
    }

    #[tokio::test]
    async fn operator_review_status_surfaces_async_context_and_freshness() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 1,
            time_budget_ms: 500,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        config.correlation = CorrelationConfig {
            enabled: true,
            time_window_ms: 5_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            ),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::replay(service.config.pheromone.clone());
        let replay_store_root = std::env::temp_dir().join("swarm-runtime-review-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let incident_store = MemoryIncidentStore::default();
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            SlowInvestigator {
                delay_ms: 100,
                completed: None,
            },
            investigation_store.clone(),
        );
        let event_one = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-review-1".to_string(),
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
        let event_two = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-review-queue-fail".to_string(),
            timestamp: 1_700_000_001,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe -enc BBB=".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        let context_one = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-review-1".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_010,
        };
        let context_two = ApprovalContext {
            live_mode: true,
            receipt_chain: vec!["receipt-upstream-review-2".to_string()],
            correlation_id: None,
            now_ms: 1_700_000_000_020,
        };
        let agent_id = test_agent_id();

        let _ = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &event_one,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context_one,
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
        let _ = service
            .process_event_with_store_and_investigation(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &event_two,
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &context_two,
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

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        investigation_store
            .persist(&swarm_spine::InvestigationBundle {
                investigation_id: "investigation:hunt-2:1".to_string(),
                source_bundle_id: "bundle:hunt-2:1".to_string(),
                hunt_id: "hunt-2".to_string(),
                trail_id: "trail:hunt-2:1".to_string(),
                event_id: "evt:hunt-2".to_string(),
                finding_id: "finding:hunt-2".to_string(),
                threat_class: swarm_core::pheromone::ThreatClass::Execution,
                severity: Severity::Critical,
                strategy_id: "summary_investigator".to_string(),
                response_kind: "success".to_string(),
                related_receipt_ids: vec!["receipt:hunt-2".to_string()],
                host_id: Some("host-1".to_string()),
                user: Some("alice".to_string()),
                process_name: Some("powershell".to_string()),
                queued_at_ms: 1_700_000_003_000,
                started_at_ms: Some(1_700_000_003_010),
                completed_at_ms: Some(1_700_000_003_100),
                status: swarm_spine::InvestigationStatus::Completed,
                priority: swarm_spine::InvestigationPriority::default(),
                summary: Some("summary for hunt-2".to_string()),
                evidence_points: vec!["host_id=host-1".to_string()],
                correlation_keys: vec![
                    "host:host-1".to_string(),
                    "user:alice".to_string(),
                    "strategy:summary_investigator".to_string(),
                ],
                candidate_interpretations: Vec::new(),
                vote_lineage: Vec::new(),
                decision: swarm_spine::InvestigationDecision::default(),
                failure_reason: None,
                graph_findings_published: false,
            })
            .unwrap();

        let engine = CorrelationEngine::new(config.correlation.clone());
        let _ = service
            .correlate_hunt(
                &engine,
                &investigation_store,
                &incident_store,
                "evt-review-1",
            )
            .unwrap()
            .unwrap();

        let status = service
            .operator_review_status(
                &detector,
                &substrate,
                &replay_store,
                &coordinator,
                &incident_store,
            )
            .await
            .unwrap();

        assert_eq!(status.recent_decisions.len(), 2);
        assert!(status.investigation_review.is_some());
        assert!(status.incident_review.is_some());
        assert!(status.async_lane.enabled);
        assert!(status.freshness.latest_hot_path_decision_at_ms.is_some());
        assert!(status.freshness.latest_investigation_update_at_ms.is_some());
        assert!(status.freshness.latest_incident_at_ms.is_some());

        let investigation_review = status.investigation_review.unwrap();
        assert!(investigation_review.recent.len() >= 2);
        assert!(investigation_review.queue.last_failure_reason.is_some());

        let incident_review = status.incident_review.unwrap();
        assert_eq!(incident_review.recent.len(), 1);
        assert_eq!(
            status.async_lane.status,
            super::AsyncLaneStatusLevel::Degraded
        );
        assert!(status.async_lane.recent_investigations >= 2);
        assert_eq!(status.async_lane.recent_incidents, 1);
        assert!(
            status
                .async_lane
                .latest_incident_confidence_score
                .is_some_and(|value| value > 0.0)
        );
        assert!(
            status
                .async_lane
                .warnings
                .iter()
                .any(|warning| warning.contains("recent investigation failure"))
        );
        assert!(
            status
                .warnings
                .iter()
                .any(|warning| warning.contains("investigation queue reported recent failure"))
        );

        let _ = std::fs::remove_dir_all(replay_store_root);
    }

    #[tokio::test]
    async fn configured_runtime_stack_builds_async_layers_from_config() {
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.audit.bundle_store = BundleStoreConfig::Memory;
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 4,
            time_budget_ms: 250,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        config.correlation = CorrelationConfig {
            enabled: true,
            time_window_ms: 10_000,
            min_shared_keys: 1,
            candidate_limit: 16,
            incident_store: BundleStoreConfig::Memory,
        };

        let stack = ConfiguredRuntimeStack::from_components(
            config,
            StaticApprovalGate::default(),
            SandboxExecutor,
            SlowInvestigator {
                delay_ms: 50,
                completed: None,
            },
        )
        .unwrap();
        let detector = SuspiciousProcessTreeDetector::default();
        let agent_id = test_agent_id();
        let live_now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        let make_event = |event_id: &str, command_line: &str| TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: live_now,
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
        };
        let make_context = |now_ms| ApprovalContext {
            live_mode: true,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: None,
            now_ms,
        };

        let first = stack
            .process_event(
                &detector,
                &make_event("evt-stack-1", "powershell.exe -enc AAA="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &make_context(live_now.saturating_mul(1_000).saturating_add(100)),
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
        let second = stack
            .process_event(
                &detector,
                &make_event("evt-stack-2", "powershell.exe -enc BBB="),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &make_context(live_now.saturating_mul(1_000).saturating_add(200)),
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

        assert!(first.investigation.is_some());
        assert!(second.investigation.is_some());

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let incident = stack.correlate_hunt("evt-stack-1").unwrap().unwrap();
        assert_eq!(incident.incident.included_members.len(), 2);

        let report = stack.operator_review_status(&detector).await.unwrap();
        let investigation_review = report.investigation_review.expect("investigation review");
        let incident_review = report.incident_review.expect("incident review");
        assert!(investigation_review.queue.completed_jobs >= 2);
        assert_eq!(incident_review.recent.len(), 1);
        assert_eq!(
            incident_review.recent[0].incident_id,
            incident.record.incident_id
        );
        assert_eq!(
            report.freshness.latest_incident_at_ms,
            Some(incident.record.created_at_ms)
        );
    }
