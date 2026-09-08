#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod dispatch_journal_composition {
    use super::*;
    use swarm_policy::configurable_gate::ConfigurableApprovalGate;
    use swarm_response::DispatchingExecutor;
    use swarm_runtime::RuntimeError;
    use swarm_runtime::investigation::SummaryInvestigator;
    use swarm_runtime::service::{ConfiguredRuntimeStack, ServiceError};

    fn durable_config(mode: RuntimeMode) -> SwarmConfig {
        let mut config = test_config("suspicious_process_tree");
        config.runtime.mode = mode;
        config.runtime.require_durable_live_response = false;
        config.audit.bundle_store = BundleStoreConfig::LocalFiles {
            directory: temp_path("dispatch-journal-audit")
                .with_extension("dir")
                .display()
                .to_string(),
        };
        config
    }

    #[test]
    fn memory_storage_cannot_enable_live_dispatch_even_when_durability_flag_is_off() {
        let mut config = test_config("suspicious_process_tree");
        config.runtime.mode = RuntimeMode::LiveResponse;
        config.runtime.require_durable_live_response = false;
        let result = IngestState::from_config(temp_path("dispatch-memory-refused"), config);
        assert!(matches!(
            result,
            Err(super::super::IngestBuildError::Service(
                ServiceError::Runtime(RuntimeError::DispatchRefused { .. })
            ))
        ));
    }

    #[test]
    fn detect_only_memory_remains_available_and_live_reload_fails_closed() {
        let config = test_config("suspicious_process_tree");
        let state =
            IngestState::from_config(temp_path("dispatch-memory-detect"), config.clone()).unwrap();
        let original_runtime = state.request_runtime.load_full();
        assert!(original_runtime.dispatch_journal().is_none());
        let mut live = config;
        live.runtime.mode = RuntimeMode::LiveResponse;
        live.runtime.require_durable_live_response = false;
        assert!(state.reload(live).is_err());
        assert_eq!(state.current_runtime_mode(), RuntimeMode::DetectOnly);
        assert!(Arc::ptr_eq(
            &original_runtime,
            &state.request_runtime.load_full()
        ));
        assert!(!state.detector_status().ready);
    }

    #[test]
    fn durable_detect_stack_and_request_runtime_share_one_exclusive_journal() {
        let config = durable_config(RuntimeMode::DetectOnly);
        let state =
            IngestState::from_config(temp_path("dispatch-durable-detect"), config.clone()).unwrap();
        let stack = state.stack.load_full();
        let runtime = state.request_runtime.load_full();
        assert!(Arc::ptr_eq(&stack.service.runtime, &runtime));
        let journal = runtime.dispatch_journal().unwrap();
        assert!(Arc::ptr_eq(
            journal,
            stack.service.runtime.dispatch_journal().unwrap()
        ));
        assert!(journal.directory().is_dir());
        let competing = IngestState::from_config(temp_path("dispatch-second-writer"), config);
        assert!(matches!(
            competing,
            Err(super::super::IngestBuildError::Service(
                ServiceError::Runtime(RuntimeError::DispatchJournal(_))
            ))
        ));
    }

    #[test]
    fn detect_live_policy_reload_retains_journal_while_old_snapshots_are_alive() {
        let config = durable_config(RuntimeMode::DetectOnly);
        let state = IngestState::from_config(temp_path("dispatch-reload"), config.clone()).unwrap();
        let old_stack = state.stack.load_full();
        let old_runtime = state.request_runtime.load_full();
        let journal = Arc::clone(old_runtime.dispatch_journal().unwrap());

        let mut live = config;
        live.runtime.mode = RuntimeMode::LiveResponse;
        state.reload(live.clone()).unwrap();
        assert_eq!(state.current_runtime_mode(), RuntimeMode::LiveResponse);
        let live_runtime = state.request_runtime.load_full();
        assert!(!Arc::ptr_eq(&old_runtime, &live_runtime));
        assert!(Arc::ptr_eq(
            &journal,
            live_runtime.dispatch_journal().unwrap()
        ));
        assert!(Arc::ptr_eq(
            &state.stack.load_full().service.runtime,
            &live_runtime
        ));

        live.policy.lease_ttl_ms += 1_000;
        state.reload(live.clone()).unwrap();
        assert!(Arc::ptr_eq(
            &journal,
            state
                .request_runtime
                .load_full()
                .dispatch_journal()
                .unwrap()
        ));
        live.runtime.mode = RuntimeMode::DetectOnly;
        state.reload(live).unwrap();
        assert_eq!(state.current_runtime_mode(), RuntimeMode::DetectOnly);
        assert!(Arc::ptr_eq(
            &journal,
            state
                .request_runtime
                .load_full()
                .dispatch_journal()
                .unwrap()
        ));
        assert!(Arc::ptr_eq(
            &journal,
            old_stack.service.runtime.dispatch_journal().unwrap()
        ));
    }

    #[test]
    fn memory_detect_to_durable_live_reload_initializes_journal_before_mode_flip() {
        let state = IngestState::from_config(
            temp_path("dispatch-memory-to-local"),
            test_config("suspicious_process_tree"),
        )
        .unwrap();
        let old_runtime = state.request_runtime.load_full();
        assert!(old_runtime.dispatch_journal().is_none());
        state
            .reload(durable_config(RuntimeMode::LiveResponse))
            .unwrap();
        assert_eq!(state.current_runtime_mode(), RuntimeMode::LiveResponse);
        assert!(
            state
                .request_runtime
                .load_full()
                .dispatch_journal()
                .is_some()
        );
    }

    #[test]
    fn reload_cannot_reset_durable_dispatch_history_by_rebinding_storage() {
        let config = durable_config(RuntimeMode::LiveResponse);
        let state =
            IngestState::from_config(temp_path("dispatch-rebinding"), config.clone()).unwrap();
        let original = state.request_runtime.load_full();
        let replacement = durable_config(RuntimeMode::LiveResponse);
        let error = state.reload(replacement).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot change durable audit storage")
        );
        assert!(Arc::ptr_eq(&original, &state.request_runtime.load_full()));

        let mut memory = config;
        memory.runtime.mode = RuntimeMode::DetectOnly;
        memory.audit.bundle_store = BundleStoreConfig::Memory;
        assert!(state.reload(memory).is_err());
        assert!(Arc::ptr_eq(&original, &state.request_runtime.load_full()));
        assert_eq!(state.current_runtime_mode(), RuntimeMode::LiveResponse);
    }

    #[test]
    fn concurrent_first_live_reloads_cannot_publish_different_dispatch_histories() {
        // Independent target directories would both open successfully; the reload
        // transaction itself must ensure only the first becomes durable state.
        let state = IngestState::from_config(
            temp_path("dispatch-concurrent-first-live"),
            test_config("suspicious_process_tree"),
        )
        .unwrap();
        let start = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let state = state.clone();
            let start = Arc::clone(&start);
            let config = durable_config(RuntimeMode::LiveResponse);
            workers.push(std::thread::spawn(move || {
                start.wait();
                state.reload(config)
            }));
        }
        start.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let rejection = results.into_iter().find_map(Result::err).unwrap();
        assert!(
            rejection
                .to_string()
                .contains("cannot change durable audit storage")
        );
        let active = state.request_runtime.load_full();
        assert_eq!(active.mode(), RuntimeMode::LiveResponse);
        assert!(active.dispatch_journal().is_some());
        assert!(Arc::ptr_eq(
            &active,
            &state.stack.load_full().service.runtime
        ));
    }

    #[test]
    fn configured_stack_cannot_accept_a_journal_from_different_audit_storage() {
        let first = ConfiguredRuntimeStack::from_config(
            durable_config(RuntimeMode::LiveResponse),
            SummaryInvestigator,
        )
        .unwrap();
        let second_config = durable_config(RuntimeMode::LiveResponse);
        let BundleStoreConfig::LocalFiles { directory } = &second_config.audit.bundle_store else {
            panic!("durable fixture");
        };
        fs::create_dir_all(Path::new(directory).join(".dispatch-journal")).unwrap();
        let result = ConfiguredRuntimeStack::from_config_with_dispatch_journal(
            second_config,
            SummaryInvestigator,
            first.service.runtime.dispatch_journal().cloned(),
        );
        assert!(matches!(
            result,
            Err(ServiceError::Runtime(RuntimeError::DispatchRefused { .. }))
        ));
    }

    #[tokio::test]
    async fn operator_view_reads_beside_live_writer_but_cannot_dispatch() {
        let config = durable_config(RuntimeMode::LiveResponse);
        let config_path = temp_path("dispatch-operator-view");
        let daemon = IngestState::from_config(&config_path, config.clone()).unwrap();
        let view = crate::control::DefaultControlPlane::from_config(&config_path, config).unwrap();
        assert_eq!(view.stack.service.mode(), RuntimeMode::LiveResponse);
        assert!(view.stack.service.runtime.dispatch_journal().is_none());
        assert!(
            daemon
                .request_runtime
                .load_full()
                .dispatch_journal()
                .is_some()
        );
        let status = view.status().await.unwrap();
        assert_eq!(status.data.mode, RuntimeMode::LiveResponse);

        let request = swarm_policy::ActionRequest {
            hunt_id: HuntId("operator-view-must-not-dispatch".to_string()),
            requested_by: AgentId::new("whisker", "operator-view"),
            action: ResponseAction::Escalate {
                summary: "view cannot execute".to_string(),
                urgency: Severity::Medium,
            },
            severity: Severity::Medium,
            evidence: json!({"threat_class": ThreatClass::Execution}),
        };
        let error = view
            .stack
            .service
            .runtime
            .authorize_and_execute(
                &request,
                &swarm_policy::ApprovalContext {
                    live_mode: true,
                    receipt_chain: Vec::new(),
                    correlation_id: None,
                    now_ms: now_ms(),
                },
            )
            .await
            .unwrap_err();
        let RuntimeError::Response(error) = error else {
            panic!("operator view must refuse enforced dispatch");
        };
        assert_eq!(error.failure.details["status"], "dispatch_refused");
        assert_eq!(error.failure.details["response_attempted"], false);
        assert_eq!(error.failure.details["retry_permitted"], false);
    }

    #[tokio::test]
    async fn request_dispatch_history_survives_policy_reload_and_process_reconstruction() {
        let config = durable_config(RuntimeMode::LiveResponse);
        let config_path = temp_path("dispatch-durable-request");
        let mut request = swarm_policy::ActionRequest {
            hunt_id: HuntId("dispatch-journal-restart-hunt".to_string()),
            requested_by: AgentId::new("whisker", "dispatch-journal-test"),
            action: ResponseAction::Escalate {
                summary: "durable request dispatch".to_string(),
                urgency: Severity::Medium,
            },
            severity: Severity::Medium,
            evidence: json!({"threat_class": ThreatClass::Execution}),
        };
        {
            let state = IngestState::from_config(&config_path, config.clone()).unwrap();
            let old_runtime = state.request_runtime.load_full();
            let router = state.current_request_response_router();
            let first = router.route_request(request.clone()).await.unwrap();
            assert!(matches!(
                first.response,
                swarm_spine::AuditResponseRecord::Success(_)
            ));

            let mut changed_policy = config.clone();
            changed_policy.policy.lease_ttl_ms += 1_000;
            state.reload(changed_policy).unwrap();
            request.severity = Severity::Low;
            request.evidence["updated_evidence"] = json!(true);
            let duplicate = router.route_request(request.clone()).await.unwrap();
            assert_duplicate_refused(&duplicate);
            assert!(Arc::ptr_eq(
                old_runtime.dispatch_journal().unwrap(),
                state
                    .request_runtime
                    .load_full()
                    .dispatch_journal()
                    .unwrap()
            ));
        }
        // Every previous runtime, router, and journal Arc has been dropped.
        // Reopening the same configured storage must recover the consumed intent.
        let restarted = IngestState::from_config(&config_path, config).unwrap();
        let duplicate = restarted
            .current_request_response_router()
            .route_request(request)
            .await
            .unwrap();
        assert_duplicate_refused(&duplicate);
    }

    fn assert_duplicate_refused(audit: &swarm_spine::AuditTrail) {
        let swarm_spine::AuditResponseRecord::Failure(failure) = &audit.response else {
            panic!(
                "duplicate dispatch must return an audited refusal: {:?}",
                audit.response
            );
        };
        assert_eq!(failure.details["status"], "dispatch_refused");
        assert_eq!(failure.details["prior_reservation"], true);
        assert_eq!(failure.details["response_attempted"], false);
        assert_eq!(failure.details["retry_permitted"], false);
    }

    #[test]
    fn from_runtime_checks_actual_live_mode_with_memory_config() {
        let config = test_config("suspicious_process_tree");
        let policy = ConfigurableApprovalGate::from_config(&config.policy);
        let executor =
            DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None).unwrap();
        let runtime = swarm_runtime::SwarmRuntime::new(RuntimeMode::LiveResponse, policy, executor);
        let result = ConfiguredRuntimeStack::from_runtime(config, runtime, SummaryInvestigator);
        assert!(matches!(
            result,
            Err(ServiceError::Runtime(RuntimeError::DispatchRefused { .. }))
        ));
    }
}
