    #[tokio::test]
    async fn operator_status_reports_metrics_and_recent_decisions() {
        let service = runtime_service();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
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
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
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
        #[derive(Clone)]
        struct GatedInvestigator {
            started: std::sync::Arc<tokio::sync::Notify>,
            release: std::sync::Arc<tokio::sync::Notify>,
        }

        #[async_trait]
        impl InvestigationStrategy for GatedInvestigator {
            fn id(&self) -> &str {
                "gated_service_test_investigator"
            }

            async fn investigate(
                &self,
                replay: &ReplayBundle,
            ) -> Result<InvestigationOutcome, String> {
                self.started.notify_one();
                self.release.notified().await;
                Ok(InvestigationOutcome {
                    summary: format!("investigated {}", replay.audit.hunt_id),
                    evidence_points: vec!["host_id=host-1".to_string()],
                    correlation_keys: vec!["host:host-1".to_string()],
                    candidate_interpretations: Vec::new(),
                    vote_lineage: Vec::new(),
                })
            }
        }

        let investigation_started = std::sync::Arc::new(tokio::sync::Notify::new());
        let release_investigation = std::sync::Arc::new(tokio::sync::Notify::new());
        let watchdog = std::time::Duration::from_secs(5);
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.investigation = InvestigationConfig {
            enabled: true,
            worker_count: 1,
            max_pending_jobs: 2,
            // The worker deadline must not release the latch during the watchdog.
            time_budget_ms: 30_000,
            bundle_store: BundleStoreConfig::Memory,
            ..InvestigationConfig::default()
        };
        let service = RuntimeService::new(
            config.clone(),
            SwarmRuntime::new(
                RuntimeMode::LiveResponse,
                StaticApprovalGate::default(),
                SandboxExecutor,
            )
            .with_dispatch_journal(service_dispatch_journal()),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let replay_store_root =
            std::env::temp_dir().join("swarm-runtime-investigation-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            GatedInvestigator {
                started: investigation_started.clone(),
                release: release_investigation.clone(),
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

        let persisted = tokio::time::timeout(
            watchdog,
            service.process_event_with_store_and_investigation(
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
            ),
        )
        .await
        .expect("event processing must return while investigation is held at its latch")
        .unwrap()
        .unwrap();
        let investigation = persisted.investigation.expect("queued investigation");
        assert_eq!(
            investigation.status,
            swarm_spine::InvestigationStatus::Queued
        );

        tokio::time::timeout(watchdog, investigation_started.notified())
            .await
            .expect("queued investigation must start");
        let pending = service
            .load_persisted_investigation_by_hunt_id(&investigation_store, "evt-investigation-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.bundle.status,
            swarm_spine::InvestigationStatus::Running
        );
        let snapshot = coordinator.snapshot();
        assert_eq!(snapshot.running_jobs, 1);
        assert_eq!(snapshot.completed_jobs, 0);
        assert_eq!(snapshot.timed_out_jobs, 0);

        // Only release the investigator after the service has returned and its
        // persisted result is demonstrably still pending.
        release_investigation.notify_one();
        let by_hunt = tokio::time::timeout(watchdog, async {
            loop {
                let by_hunt = service
                    .load_persisted_investigation_by_hunt_id(
                        &investigation_store,
                        "evt-investigation-1",
                    )
                    .unwrap()
                    .unwrap();
                match by_hunt.bundle.status {
                    swarm_spine::InvestigationStatus::Completed => return by_hunt,
                    swarm_spine::InvestigationStatus::Running => tokio::task::yield_now().await,
                    status => panic!("expected running or completed investigation, got {status:?}"),
                }
            }
        })
        .await
        .expect("released investigation must persist its completed result");
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
            )
            .with_dispatch_journal(service_dispatch_journal()),
        );
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let replay_store_root = std::env::temp_dir().join("swarm-runtime-review-replay-store");
        let _ = std::fs::remove_dir_all(&replay_store_root);
        let replay_store = FileReplayBundleStore::open(&replay_store_root).unwrap();
        let investigation_store = MemoryInvestigationBundleStore::default();
        let incident_store = MemoryIncidentStore::default();
        let coordinator = crate::investigation::InvestigationCoordinator::new(
            config.investigation.clone(),
            SlowInvestigator { delay_ms: 100 },
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
        let audit_directory = std::env::temp_dir()
            .join(format!("swarm-service-stack-audit-{}", uuid::Uuid::new_v4()));
        let mut config = service_config(
            RuntimeMode::LiveResponse,
            PheromoneBackendConfig::InMemory,
            false,
        );
        config.audit.bundle_store = BundleStoreConfig::LocalFiles {
            directory: audit_directory.display().to_string(),
        };
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
            SlowInvestigator { delay_ms: 50 },
        )
        .unwrap();
        let detector = SuspiciousProcessTreeDetector::default();
        let agent_id = test_agent_id();

        let make_event = |event_id: &str, command_line: &str| TelemetryEvent {
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
                    approval: &make_context(1_700_000_000_100),
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
                    approval: &make_context(1_700_000_000_200),
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
        drop(stack);
        std::fs::remove_dir_all(audit_directory).unwrap();
    }

    /// XHUNT-03: the optional correlation + memory lanes must never gate the
    /// critical path. This drives the SAME two telemetry events through two
    /// otherwise-identical stacks -- one with `correlation.enabled = true`
    /// AND `memory.enabled = true` (and this arm genuinely EXERCISES both: a
    /// real `SphinxAgent` tick persists a knowledge-graph snapshot built from
    /// the arm's own pheromone deposits, and `correlate_hunt_with_persisted_graph`
    /// then runs the graph-native cross-hunt decision against that snapshot --
    /// confirmed below by asserting a `graph_path` was recorded on the
    /// resulting incident, i.e. the Phase 298 graph-native path ran, not the
    /// pre-298 string-overlap fallback), the other with both `false` -- and
    /// asserts the policy/response decision captured from `process_event`
    /// (captured BEFORE the enabled arm's correlation/memory exercise runs)
    /// is identical between the two arms.
    ///
    /// `SwarmRuntime::authorize_and_execute` (`crates/swarm-runtime/src/lib.rs`)
    /// has zero references to correlation/sphinx/memory; this test pins that
    /// structural decoupling against regression, and does so for a
    /// configuration where the optional lanes actually run rather than one
    /// where they are simply unreachable.
    #[tokio::test]
    async fn optional_correlation_and_memory_lanes_never_perturb_policy_decision() {
        use crate::sphinx_agent::{FileKnowledgeGraphStore, SphinxAgent};
        use swarm_core::agent::{SwarmAgent, SwarmEnvironment};
        use swarm_pheromone::ConfiguredPheromoneSubstrate;

        /// The decision-relevant projection of one handled event's audit
        /// trail: the policy verdict/rule/reason and the lease terms that
        /// gated execution, plus the response's disposition (kind, status,
        /// action, mode). Deliberately excludes bookkeeping identifiers that
        /// are incidental to the decision itself (`trail_id`, `bundle_id`,
        /// `receipt_id`) even though, in this fixture, they are ALSO fully
        /// deterministic (formatted from `hunt_id` plus the fixed `now_ms`
        /// used by both arms, never random or wall-clock derived) -- the
        /// assertion below is about the decision, not about ids that happen
        /// to match too.
        #[derive(Debug, PartialEq)]
        struct DecisionSnapshot {
            verdict: PolicyVerdict,
            rule_name: String,
            reason: String,
            lease: Option<(String, String, Option<String>, i64)>,
            response_kind: &'static str,
            response_status: Option<ResponseStatus>,
            response_action: Option<String>,
            response_mode: Option<ExecutionMode>,
            response_disposition: Option<String>,
        }

        fn decision_snapshot(audit: &swarm_spine::AuditTrail) -> DecisionSnapshot {
            let (response_kind, response_status, response_action, response_mode, response_disposition) =
                match &audit.response {
                    AuditResponseRecord::Success(receipt) => (
                        "success",
                        Some(receipt.status),
                        Some(receipt.action.clone()),
                        Some(receipt.mode),
                        None,
                    ),
                    AuditResponseRecord::Failure(failure) => (
                        "failure",
                        None,
                        Some(failure.action.clone()),
                        Some(failure.mode),
                        Some(failure.message.clone()),
                    ),
                    AuditResponseRecord::Skipped { reason } => {
                        ("skipped", None, None, None, Some(reason.clone()))
                    }
                    AuditResponseRecord::GuardRejected { guard_name, reason } => (
                        "guard_rejected",
                        None,
                        None,
                        None,
                        Some(format!("{guard_name}: {reason}")),
                    ),
                };
            DecisionSnapshot {
                verdict: audit.policy.verdict,
                rule_name: audit.policy.rule_name.clone(),
                reason: audit.policy.reason.clone(),
                lease: audit.policy.lease.as_ref().map(|lease| {
                    (
                        lease.capability_id.clone(),
                        lease.action.clone(),
                        lease.scope.clone(),
                        lease.expires_at_ms,
                    )
                }),
                response_kind,
                response_status,
                response_action,
                response_mode,
                response_disposition,
            }
        }

        fn build_config(
            audit_dir: &std::path::Path,
            memory_dir: &std::path::Path,
            lanes_enabled: bool,
        ) -> SwarmConfig {
            let mut config = service_config(
                RuntimeMode::LiveResponse,
                PheromoneBackendConfig::InMemory,
                false,
            );
            config.audit.bundle_store = BundleStoreConfig::LocalFiles {
                directory: audit_dir.display().to_string(),
            };
            config.investigation = InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 4,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::Memory,
                ..InvestigationConfig::default()
            };
            config.correlation = CorrelationConfig {
                enabled: lanes_enabled,
                time_window_ms: 10_000,
                min_shared_keys: 1,
                candidate_limit: 16,
                incident_store: BundleStoreConfig::Memory,
            };
            config.memory = swarm_core::config::MemoryConfig {
                enabled: lanes_enabled,
                knowledge_graph_results_dir: memory_dir.display().to_string(),
                ..swarm_core::config::MemoryConfig::default()
            };
            config
        }

        async fn drive_two_events(
            stack: &ConfiguredRuntimeStack<StaticApprovalGate, SandboxExecutor, SlowInvestigator>,
            detector: &SuspiciousProcessTreeDetector,
            agent_id: &AgentId,
        ) -> (
            swarm_spine::AuditTrail,
            swarm_spine::AuditTrail,
            Vec<swarm_core::pheromone::PheromoneDeposit>,
        ) {
            let first = stack
                .process_event(
                    detector,
                    &suspicious_event("evt-xhunt-1", "powershell.exe -enc AAA="),
                    EventExecutionContext {
                        agent_id,
                        approval: &approval_context(1_700_000_100_000, "xhunt-corr-1"),
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
                    detector,
                    &suspicious_event("evt-xhunt-2", "powershell.exe -enc BBB="),
                    EventExecutionContext {
                        agent_id,
                        approval: &approval_context(1_700_000_100_500, "xhunt-corr-2"),
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

            let mut deposits = first.replay.bundle.deposits.clone();
            deposits.extend(second.replay.bundle.deposits.clone());

            (
                first.replay.bundle.audit.clone(),
                second.replay.bundle.audit.clone(),
                deposits,
            )
        }

        let agent_id = test_agent_id();
        let detector = SuspiciousProcessTreeDetector::default();

        // Arm A: correlation + memory ENABLED, and genuinely exercised below.
        let audit_dir_enabled = std::env::temp_dir().join(format!(
            "swarm-runtime-xhunt03-audit-enabled-{}",
            uuid::Uuid::new_v4()
        ));
        let memory_dir = std::env::temp_dir().join(format!(
            "swarm-runtime-xhunt03-memory-{}",
            uuid::Uuid::new_v4()
        ));
        let config_enabled = build_config(&audit_dir_enabled, &memory_dir, true);
        let stack_enabled = ConfiguredRuntimeStack::from_components(
            config_enabled.clone(),
            StaticApprovalGate::default(),
            SandboxExecutor,
            SlowInvestigator { delay_ms: 50 },
        )
        .unwrap();
        let (audit_enabled_1, audit_enabled_2, deposits_enabled) =
            drive_two_events(&stack_enabled, &detector, &agent_id).await;

        // Arm B: correlation + memory DISABLED.
        let audit_dir_disabled = std::env::temp_dir().join(format!(
            "swarm-runtime-xhunt03-audit-disabled-{}",
            uuid::Uuid::new_v4()
        ));
        let unused_memory_dir = std::env::temp_dir().join(format!(
            "swarm-runtime-xhunt03-memory-unused-{}",
            uuid::Uuid::new_v4()
        ));
        let config_disabled = build_config(&audit_dir_disabled, &unused_memory_dir, false);
        let stack_disabled = ConfiguredRuntimeStack::from_components(
            config_disabled,
            StaticApprovalGate::default(),
            SandboxExecutor,
            SlowInvestigator { delay_ms: 50 },
        )
        .unwrap();
        let (audit_disabled_1, audit_disabled_2, _deposits_disabled) =
            drive_two_events(&stack_disabled, &detector, &agent_id).await;

        // The policy/response decision must be identical whether or not the
        // optional lanes are enabled -- this is the core XHUNT-03 assertion.
        let snapshot_enabled_1 = decision_snapshot(&audit_enabled_1);
        let snapshot_disabled_1 = decision_snapshot(&audit_disabled_1);
        let snapshot_enabled_2 = decision_snapshot(&audit_enabled_2);
        let snapshot_disabled_2 = decision_snapshot(&audit_disabled_2);
        assert_eq!(
            snapshot_enabled_1, snapshot_disabled_1,
            "event 1's policy/response decision must not depend on correlation/memory config"
        );
        assert_eq!(
            snapshot_enabled_2, snapshot_disabled_2,
            "event 2's policy/response decision must not depend on correlation/memory config"
        );
        // Both arms allowed the DeployDecoy response and actually executed
        // it, so the equality above is not vacuously comparing two denials.
        assert_eq!(snapshot_enabled_1.verdict, PolicyVerdict::Allow);
        assert_eq!(snapshot_enabled_1.response_kind, "success");

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Disabled arm: the disabled lanes must be a clean no-op, not merely
        // unreachable from the critical path.
        assert!(
            stack_disabled
                .correlate_hunt("evt-xhunt-1")
                .unwrap()
                .is_none(),
            "correlation.enabled = false must produce no incident"
        );
        assert!(
            stack_disabled
                .correlate_hunt_with_persisted_graph(
                    &unused_memory_dir.join("config-placeholder.yaml"),
                    None,
                    "evt-xhunt-1",
                )
                .unwrap()
                .is_none(),
            "memory.enabled = false must skip the graph-correlation lane entirely"
        );

        // Now GENUINELY exercise the enabled arm's correlation + memory
        // lanes -- AFTER the decision comparison above -- proving they ran
        // without perturbing the already-final decision, per this module's
        // decoupling ruling (XHUNT-03).
        //
        // Run a real Sphinx memory tick over the enabled arm's own deposits,
        // persisting a typed knowledge-graph snapshot to `memory_dir`. This
        // is the actual memory lane, not a stand-in for it.
        let sphinx_signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let sphinx_substrate =
            ConfiguredPheromoneSubstrate::from_config(&config_enabled.pheromone).unwrap();
        let mut sphinx_agent = SphinxAgent::new_with_signing_key(
            AgentId::new("sphinx", "xhunt03-test"),
            sphinx_signing_key,
            memory_dir.join("config-placeholder.yaml"),
            config_enabled.clone(),
            sphinx_substrate,
        )
        .unwrap();
        sphinx_agent
            .tick(&SwarmEnvironment {
                pheromones: deposits_enabled,
                mode: SwarmMode::Alert,
                mode_transition_at: Some(1_700_000_100),
                now: 1_700_000_101,
                peer_findings: Vec::new(),
                agent_health: Vec::new(),
            })
            .await
            .unwrap();
        let persisted_snapshot = FileKnowledgeGraphStore::open(&memory_dir)
            .unwrap()
            .load_snapshot()
            .unwrap()
            .expect("sphinx tick should have persisted a knowledge-graph snapshot");
        assert!(
            !persisted_snapshot.nodes.is_empty(),
            "the memory lane should have genuinely built graph state"
        );

        // Run the real graph-native cross-hunt correlation decision against
        // that persisted snapshot -- the actual correlation lane.
        let outcome = stack_enabled
            .correlate_hunt_with_persisted_graph(
                &memory_dir.join("config-placeholder.yaml"),
                None,
                "evt-xhunt-1",
            )
            .unwrap()
            .expect("correlation should assemble an incident from the persisted graph");
        assert_eq!(
            outcome.incident.included_members.len(),
            2,
            "both engagements should bridge via the shared host-1 entity node"
        );
        let bridged_member = outcome
            .incident
            .included_members
            .iter()
            .find(|member| !member.evidence_links.is_empty())
            .expect("the non-seed member should carry graph evidence links");
        assert!(
            bridged_member
                .evidence_links
                .iter()
                .any(|link| link.graph_path.is_some()),
            "a populated graph_path proves the Phase 298 graph-native decision path ran, \
             not the pre-298 string-overlap fallback -- i.e. memory was genuinely exercised"
        );

        drop(stack_enabled);
        drop(stack_disabled);
        std::fs::remove_dir_all(audit_dir_enabled).unwrap();
        std::fs::remove_dir_all(audit_dir_disabled).unwrap();
        std::fs::remove_dir_all(memory_dir).unwrap();
    }
