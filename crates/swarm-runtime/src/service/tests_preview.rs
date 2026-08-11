    #[test]
    fn rehearsal_preview_covers_expanded_response_action_catalog() {
        let service = runtime_service();
        let source_bundle_id = "bundle-expanded-catalog";
        let prepared_at_ms = 1_700_000_000_250;
        let cases = vec![
            (
                ResponseAction::SinkholeDns {
                    domain: "sinkhole.example".to_string(),
                },
                ResponseRehearsalScopeKind::NetworkTarget,
                "sinkhole.example".to_string(),
                ResponseBlastRadiusImpact::DnsResolutionSinkholed,
                true,
                ResponseRollbackStepKind::RemoveDnsSinkhole,
            ),
            (
                ResponseAction::TerminateUserSession {
                    host_id: "host-77".to_string(),
                    session_id: "session-9".to_string(),
                },
                ResponseRehearsalScopeKind::UserSession,
                "host-77:session-9".to_string(),
                ResponseBlastRadiusImpact::UserSessionTerminated,
                false,
                ResponseRollbackStepKind::ReauthenticateUserSession,
            ),
            (
                ResponseAction::TriggerEdrScan {
                    host_id: "host-22".to_string(),
                    scan_profile: "memory_quick".to_string(),
                },
                ResponseRehearsalScopeKind::Host,
                "host-22".to_string(),
                ResponseBlastRadiusImpact::HostScanTriggered,
                false,
                ResponseRollbackStepKind::CancelHostScan,
            ),
            (
                ResponseAction::InjectFirewallRule {
                    host_id: "host-44".to_string(),
                    rule_name: "deny-c2".to_string(),
                    direction: "egress".to_string(),
                    cidr: "203.0.113.0/24".to_string(),
                    port: Some(443),
                },
                ResponseRehearsalScopeKind::Host,
                "host-44".to_string(),
                ResponseBlastRadiusImpact::HostFirewallPolicyChanged,
                true,
                ResponseRollbackStepKind::RemoveFirewallRule,
            ),
            (
                ResponseAction::QuarantineFile {
                    host_id: "host-55".to_string(),
                    file_path: "/tmp/payload.exe".to_string(),
                },
                ResponseRehearsalScopeKind::File,
                "host-55:/tmp/payload.exe".to_string(),
                ResponseBlastRadiusImpact::FileQuarantined,
                true,
                ResponseRollbackStepKind::ReleaseQuarantinedFile,
            ),
            (
                ResponseAction::KillProcess {
                    host_id: "host-88".to_string(),
                    process_name: "powershell.exe".to_string(),
                },
                ResponseRehearsalScopeKind::Process,
                "host-88:powershell.exe".to_string(),
                ResponseBlastRadiusImpact::ProcessTerminated,
                false,
                ResponseRollbackStepKind::RestartProcess,
            ),
            (
                ResponseAction::SuspendProcess {
                    host_id: "host-99".to_string(),
                    process_name: "cmd.exe".to_string(),
                },
                ResponseRehearsalScopeKind::Process,
                "host-99:cmd.exe".to_string(),
                ResponseBlastRadiusImpact::ProcessSuspended,
                true,
                ResponseRollbackStepKind::ResumeProcess,
            ),
            (
                ResponseAction::DisableUserAccount {
                    user_id: "alice@example.com".to_string(),
                },
                ResponseRehearsalScopeKind::UserAccount,
                "alice@example.com".to_string(),
                ResponseBlastRadiusImpact::UserAccountDisabled,
                true,
                ResponseRollbackStepKind::ReenableUserAccount,
            ),
            (
                ResponseAction::ForcePasswordReset {
                    user_id: "bob@example.com".to_string(),
                },
                ResponseRehearsalScopeKind::UserAccount,
                "bob@example.com".to_string(),
                ResponseBlastRadiusImpact::PasswordResetEnforced,
                true,
                ResponseRollbackStepKind::ClearPasswordResetRequirement,
            ),
            (
                ResponseAction::RemoveScheduledTask {
                    host_id: "host-66".to_string(),
                    task_name: "DailyUpdater".to_string(),
                },
                ResponseRehearsalScopeKind::ScheduledTask,
                "host-66:DailyUpdater".to_string(),
                ResponseBlastRadiusImpact::ScheduledTaskRemoved,
                true,
                ResponseRollbackStepKind::RestoreScheduledTask,
            ),
        ];

        for (
            action,
            expected_scope_kind,
            expected_scope_value,
            expected_impact,
            expected_rollback_required,
            expected_step_kind,
        ) in cases
        {
            let preview = service
                .rehearsal_preview(&preview_request(action), source_bundle_id, prepared_at_ms)
                .expect("expanded action preview");
            assert_eq!(preview.source_bundle_id, source_bundle_id);
            assert!(preview.simulated_only);
            assert_eq!(preview.blast_radius.scope_kind, expected_scope_kind);
            assert_eq!(preview.blast_radius.scope_value, expected_scope_value);
            assert_eq!(preview.blast_radius.impact, expected_impact);
            assert_eq!(preview.rollback.required, expected_rollback_required);
            assert_eq!(preview.rollback.steps.len(), 1);
            assert_eq!(preview.rollback.steps[0].kind, expected_step_kind);
        }
    }

    #[tokio::test]
    async fn rehearse_bundle_supports_expanded_firewall_action_preview() {
        let (service, modes) = runtime_service_with_recording_modes();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-rehearsal-firewall", "powershell.exe -enc AAA=");
        let source_context = approval_context(1_700_000_000_320, "corr-rehearsal-firewall");
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
                    Some(ResponseAction::InjectFirewallRule {
                        host_id: "host-22".to_string(),
                        rule_name: "deny-c2".to_string(),
                        direction: "egress".to_string(),
                        cidr: "203.0.113.0/24".to_string(),
                        port: Some(443),
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
        let rehearsal_context = approval_context(1_700_000_000_321, "corr-rehearsal-run");
        let persisted = service
            .rehearse_bundle_with_store(&store, &source, &rehearsal_context)
            .await
            .unwrap();

        assert_eq!(&*modes.lock().await, &[ExecutionMode::DryRun]);
        let rehearsal = persisted
            .bundle
            .rehearsal
            .as_ref()
            .expect("rehearsal preview");
        assert_eq!(
            rehearsal.blast_radius.scope_kind,
            ResponseRehearsalScopeKind::Host
        );
        assert_eq!(
            rehearsal.blast_radius.impact,
            ResponseBlastRadiusImpact::HostFirewallPolicyChanged
        );
        assert_eq!(
            rehearsal.rollback.steps[0].kind,
            ResponseRollbackStepKind::RemoveFirewallRule
        );
    }

    #[tokio::test]
    async fn rehearse_bundle_fails_closed_before_executor_when_scope_metadata_is_missing() {
        let (service, modes) = runtime_service_with_recording_modes();
        let detector = SuspiciousProcessTreeDetector::default();
        let substrate = InMemoryPheromoneSubstrate::new(service.config.pheromone.clone());
        let event = suspicious_event("evt-rehearsal-invalid", "powershell.exe -enc AAA=");
        let source_context = approval_context(1_700_000_000_300, "corr-rehearsal-invalid");
        let agent_id = test_agent_id();

        let mut source = service
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
        source.action_request.action = ResponseAction::BlockEgress {
            target: "   ".to_string(),
        };

        let store = MemoryReplayBundleStore::default();
        let rehearsal_context = approval_context(1_700_000_000_301, "corr-rehearsal-preview");
        let error = service
            .rehearse_bundle_with_store(&store, &source, &rehearsal_context)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            ServiceError::RehearsalPreview(RehearsalPreviewError::EmptyValue {
                label: "block target"
            })
        ));
        assert!(modes.lock().await.is_empty());
        assert!(store.recent(10).unwrap().is_empty());
    }

    #[test]
    fn playbook_preview_matches_branch_and_projects_policy_requirements() {
        let service = runtime_service_with_branching_playbook();

        let report = service
            .playbook_preview(
                ResponsePlaybookPreviewRequest {
                    threat_class: ThreatClass::Execution,
                    severity: Severity::High,
                    confidence: 0.98,
                    mode: SwarmMode::Incident,
                },
                1_700_000_000_777,
            )
            .expect("playbook preview");

        assert_eq!(report.status, ResponsePlaybookPreviewStatus::Matched);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.approval_summary.allow_count, 2);
        let matched = report.matched_rule.expect("matched rule");
        assert_eq!(matched.rule_index, 0);
        assert_eq!(
            matched
                .branch
                .as_ref()
                .and_then(|branch| branch.name.as_deref()),
            Some("incident_containment")
        );
        assert!(matches!(
            report.actions[0].action,
            ResponseAction::BlockEgress { .. }
        ));
        assert_eq!(
            report.actions[0].rehearsal.blast_radius.scope_kind,
            ResponseRehearsalScopeKind::NetworkTarget
        );
        assert_eq!(report.actions[0].policy.verdict, PolicyVerdict::Allow);
        assert!(report.actions[0].policy.lease_scope.is_some());
    }

    #[test]
    fn playbook_preview_uses_fallback_actions_when_no_branch_matches() {
        let service = runtime_service_with_branching_playbook();

        let report = service
            .playbook_preview(
                ResponsePlaybookPreviewRequest {
                    threat_class: ThreatClass::Execution,
                    severity: Severity::High,
                    confidence: 0.93,
                    mode: SwarmMode::Alert,
                },
                1_700_000_000_778,
            )
            .expect("playbook preview");

        assert_eq!(report.status, ResponsePlaybookPreviewStatus::Matched);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.approval_summary.allow_count, 1);
        assert_eq!(report.matched_rule.expect("matched rule").branch, None);
        assert!(matches!(
            report.actions[0].action,
            ResponseAction::Escalate { .. }
        ));
    }

    #[test]
    fn playbook_action_for_finding_rejects_multi_action_rule() {
        // Regression: live executor is single-action; silently dropping the
        // tail of an isolate->scan->escalate sequence would skip configured
        // containment steps. Fail closed instead.
        let service = runtime_service_with_branching_playbook();
        let multi_action_finding = DetectionFinding {
            finding_id: "f1".to_string(),
            event_id: "evt-1".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.98,
            evidence: serde_json::json!({}),
            strategy_id: "test".to_string(),
        };
        let action =
            service.playbook_action_for_finding(&multi_action_finding, SwarmMode::Incident);
        assert!(
            action.is_none(),
            "multi-action playbook rule must not produce a single ActionRequest; got {action:?}"
        );

        // Single-action fallback rule still resolves normally.
        let single_action_finding = DetectionFinding {
            finding_id: "f2".to_string(),
            event_id: "evt-2".to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.93,
            evidence: serde_json::json!({}),
            strategy_id: "test".to_string(),
        };
        let fallback =
            service.playbook_action_for_finding(&single_action_finding, SwarmMode::Alert);
        assert!(matches!(fallback, Some(ResponseAction::Escalate { .. })));
    }

