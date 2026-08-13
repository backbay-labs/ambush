use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct FindingEnrichmentService;

impl FindingEnrichmentService {
    pub(super) fn enrich(
        &self,
        event: &TelemetryEvent,
        findings: Vec<DetectionFinding>,
        detected_at_ms: i64,
    ) -> Vec<DetectionFinding> {
        findings
            .into_iter()
            .map(|finding| {
                let evidence = enrich_finding_evidence(event, &finding, detected_at_ms);
                DetectionFinding {
                    evidence,
                    ..finding
                }
            })
            .collect()
    }
}

pub(super) fn approval_correlation_id(context: &ApprovalContext) -> &str {
    context.correlation_id.as_deref().unwrap_or("unknown")
}

pub(super) fn threat_class_label(threat_class: &ThreatClass) -> &str {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement",
        ThreatClass::DataExfiltration => "data_exfiltration",
        ThreatClass::PrivilegeEscalation => "privilege_escalation",
        ThreatClass::CommandAndControl => "command_and_control",
        ThreatClass::InitialAccess => "initial_access",
        ThreatClass::Persistence => "persistence",
        ThreatClass::SupplyChain => "supply_chain",
        ThreatClass::DefenseEvasion => "defense_evasion",
        ThreatClass::CredentialAccess => "credential_access",
        ThreatClass::Discovery => "discovery",
        ThreatClass::Execution => "execution",
        ThreatClass::Impact => "impact",
        ThreatClass::Custom(value) => value.as_str(),
    }
}

pub(super) fn verdict_label(verdict: PolicyVerdict) -> &'static str {
    match verdict {
        PolicyVerdict::Deny => "deny",
        PolicyVerdict::Allow => "allow",
        PolicyVerdict::RequireHuman => "require_human",
    }
}

pub(super) fn adapter_outcome_label(response: &AuditResponseRecord) -> Option<&'static str> {
    match response {
        AuditResponseRecord::Success(_) => Some("success"),
        AuditResponseRecord::Failure(failure) => {
            let is_timeout = failure
                .details
                .get("status")
                .and_then(serde_json::Value::as_str)
                == Some("timeout");
            Some(if is_timeout { "timeout" } else { "failure" })
        }
        AuditResponseRecord::Skipped { .. } | AuditResponseRecord::GuardRejected { .. } => None,
    }
}

pub(super) fn merge_rehearsal_receipt_chain(
    approval: &ApprovalContext,
    source: &ReplayBundle,
) -> ApprovalContext {
    let mut receipt_chain = approval.receipt_chain.clone();
    for receipt_id in source.audit.all_receipt_ids() {
        if !receipt_chain.iter().any(|existing| existing == &receipt_id) {
            receipt_chain.push(receipt_id);
        }
    }
    ApprovalContext {
        receipt_chain,
        ..approval.clone()
    }
}

pub(crate) fn build_rehearsal_preview(
    request: &ActionRequest,
    source_bundle_id: &str,
    prepared_at_ms: i64,
) -> Result<ResponseRehearsalPreview, ServiceError> {
    fn require_value(label: &'static str, value: &str) -> Result<String, RehearsalPreviewError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(RehearsalPreviewError::EmptyValue { label });
        }
        Ok(trimmed.to_string())
    }

    fn preview(
        rehearsal_id: &str,
        source_bundle_id: &str,
        prepared_at_ms: i64,
        blast_radius: ResponseBlastRadiusPreview,
        rollback: ResponseRollbackPreview,
    ) -> ResponseRehearsalPreview {
        ResponseRehearsalPreview {
            rehearsal_id: rehearsal_id.to_string(),
            source_bundle_id: source_bundle_id.to_string(),
            prepared_at_ms,
            simulated_only: true,
            blast_radius,
            rollback,
        }
    }

    fn rollback_step(
        kind: ResponseRollbackStepKind,
        summary: impl Into<String>,
    ) -> ResponseRollbackStep {
        ResponseRollbackStep {
            kind,
            summary: summary.into(),
        }
    }

    let rehearsal_id = format!("rehearsal:{}:{}", request.hunt_id.0, prepared_at_ms);

    let preview = match &request.action {
        ResponseAction::BlockEgress { .. } => {
            let scope_value = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "block_egress",
                },
            )?;
            let target = require_value("block target", &scope_value)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::NetworkTarget,
                    scope_value: target.clone(),
                    impact: ResponseBlastRadiusImpact::NetworkEgressBlocked,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["egress_connectivity".to_string()],
                    summary: format!(
                        "Blocks outbound connectivity to the scoped network target `{target}`"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Remove the temporary egress deny rule for `{target}` to restore traffic"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RemoveNetworkBlock,
                        format!(
                            "Remove the egress deny rule for `{target}` and confirm traffic flows normally"
                        ),
                    )],
                },
            )
        }
        ResponseAction::IsolateHost { .. } => {
            let scope_value = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "isolate_host",
                },
            )?;
            let host_id = require_value("host_id", &scope_value)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: host_id.clone(),
                    impact: ResponseBlastRadiusImpact::HostConnectivityIsolated,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "network_connectivity".to_string(),
                        "remote_management".to_string(),
                    ],
                    summary: format!(
                        "Cuts the scoped host `{host_id}` off from normal network communication"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Restore normal connectivity for the isolated host `{host_id}`"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestoreHostConnectivity,
                        format!(
                            "Remove the isolation policy for `{host_id}` and verify host reachability"
                        ),
                    )],
                },
            )
        }
        ResponseAction::RevokeCredential { .. } => {
            let scope_value = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "revoke_credential",
                },
            )?;
            let credential_id = require_value("credential_id", &scope_value)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Credential,
                    scope_value: credential_id.clone(),
                    impact: ResponseBlastRadiusImpact::CredentialAccessRevoked,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["credential_authentication".to_string()],
                    summary: format!(
                        "Removes the scoped credential `{credential_id}` from future authentication attempts"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Restore or rotate the revoked credential `{credential_id}` with bounded access"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestoreCredential,
                        format!(
                            "Reissue or restore `{credential_id}` after validation of the owning principal"
                        ),
                    )],
                },
            )
        }
        ResponseAction::SinkholeDns { domain } => {
            let domain = require_value("domain", domain)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::NetworkTarget,
                    scope_value: domain.clone(),
                    impact: ResponseBlastRadiusImpact::DnsResolutionSinkholed,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "dns_resolution".to_string(),
                        "domain_reachability".to_string(),
                    ],
                    summary: format!(
                        "Redirects name resolution for the scoped domain `{domain}` to a controlled sinkhole target"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Remove the sinkhole override for `{domain}` to restore normal DNS answers"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RemoveDnsSinkhole,
                        format!(
                            "Delete the sinkhole record for `{domain}` and confirm DNS responses return to baseline"
                        ),
                    )],
                },
            )
        }
        ResponseAction::TerminateUserSession {
            host_id,
            session_id,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let session_id = require_value("session_id", session_id)?;
            let scope_value = format!("{host_id}:{session_id}");
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::UserSession,
                    scope_value: scope_value.clone(),
                    impact: ResponseBlastRadiusImpact::UserSessionTerminated,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "interactive_session".to_string(),
                        "session_bound_credentials".to_string(),
                    ],
                    summary: format!(
                        "Ends the scoped session `{session_id}` on host `{host_id}` and forces that principal to reconnect"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary: format!(
                        "The terminated session `{session_id}` cannot be resumed; if this was a false positive, the user must establish a fresh session on `{host_id}`"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ReauthenticateUserSession,
                        format!(
                            "After validation, allow the principal tied to `{session_id}` to authenticate again on `{host_id}`"
                        ),
                    )],
                },
            )
        }
        ResponseAction::TriggerEdrScan {
            host_id,
            scan_profile,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let scan_profile = require_value("scan_profile", scan_profile)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: host_id.clone(),
                    impact: ResponseBlastRadiusImpact::HostScanTriggered,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "endpoint_scan_capacity".to_string(),
                        "cpu_headroom".to_string(),
                    ],
                    summary: format!(
                        "Starts the EDR scan profile `{scan_profile}` on host `{host_id}`, consuming bounded endpoint inspection capacity"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary: format!(
                        "The scan job is non-destructive; cancel the `{scan_profile}` scan on `{host_id}` only if it was launched in error"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::CancelHostScan,
                        format!(
                            "Cancel the active `{scan_profile}` EDR scan on `{host_id}` or allow it to complete if the load is acceptable"
                        ),
                    )],
                },
            )
        }
        ResponseAction::InjectFirewallRule {
            host_id,
            rule_name,
            direction,
            cidr,
            port,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let rule_name = require_value("rule_name", rule_name)?;
            let direction = require_value("direction", direction)?;
            let cidr = require_value("cidr", cidr)?;
            let port_clause = port
                .map(|value| format!(" on port `{value}`"))
                .unwrap_or_default();
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Host,
                    scope_value: host_id.clone(),
                    impact: ResponseBlastRadiusImpact::HostFirewallPolicyChanged,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "host_network_connectivity".to_string(),
                        "firewall_policy".to_string(),
                    ],
                    summary: format!(
                        "Adds firewall rule `{rule_name}` on host `{host_id}` for {direction} traffic matching `{cidr}`{port_clause}"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Remove firewall rule `{rule_name}` from `{host_id}` to restore the pre-action policy"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RemoveFirewallRule,
                        format!(
                            "Delete firewall rule `{rule_name}` from `{host_id}` and verify expected traffic resumes"
                        ),
                    )],
                },
            )
        }
        ResponseAction::QuarantineFile { host_id, file_path } => {
            let host_id = require_value("host_id", host_id)?;
            let file_path = require_value("file_path", file_path)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::File,
                    scope_value: format!("{host_id}:{file_path}"),
                    impact: ResponseBlastRadiusImpact::FileQuarantined,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "file_access".to_string(),
                        "file_execution".to_string(),
                    ],
                    summary: format!(
                        "Moves the scoped file `{file_path}` on host `{host_id}` into quarantine, blocking normal access and execution"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Release `{file_path}` from quarantine on `{host_id}` only after validating it is benign"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ReleaseQuarantinedFile,
                        format!(
                            "Restore `{file_path}` to its original location on `{host_id}` and confirm the file hash matches the approved baseline"
                        ),
                    )],
                },
            )
        }
        ResponseAction::KillProcess {
            host_id,
            process_name,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let process_name = require_value("process_name", process_name)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Process,
                    scope_value: format!("{host_id}:{process_name}"),
                    impact: ResponseBlastRadiusImpact::ProcessTerminated,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "process_execution".to_string(),
                        "task_continuity".to_string(),
                    ],
                    summary: format!(
                        "Terminates process `{process_name}` on host `{host_id}`, immediately interrupting that workload"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary: format!(
                        "The terminated process `{process_name}` does not resume automatically; restart it only if post-review confirms the workload is benign"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestartProcess,
                        format!(
                            "Relaunch the approved `{process_name}` workload on `{host_id}` with normal supervision if business impact warrants recovery"
                        ),
                    )],
                },
            )
        }
        ResponseAction::SuspendProcess {
            host_id,
            process_name,
        } => {
            let host_id = require_value("host_id", host_id)?;
            let process_name = require_value("process_name", process_name)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Process,
                    scope_value: format!("{host_id}:{process_name}"),
                    impact: ResponseBlastRadiusImpact::ProcessSuspended,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "process_execution".to_string(),
                        "interactive_task_progress".to_string(),
                    ],
                    summary: format!(
                        "Suspends process `{process_name}` on host `{host_id}`, pausing its execution without removing it from memory"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Resume suspended process `{process_name}` on `{host_id}` if the action is later judged unnecessary"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ResumeProcess,
                        format!(
                            "Resume process `{process_name}` on `{host_id}` and confirm it returns to the expected execution state"
                        ),
                    )],
                },
            )
        }
        ResponseAction::DisableUserAccount { user_id } => {
            let user_id = require_value("user_id", user_id)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::UserAccount,
                    scope_value: user_id.clone(),
                    impact: ResponseBlastRadiusImpact::UserAccountDisabled,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "interactive_authentication".to_string(),
                        "privileged_access".to_string(),
                    ],
                    summary: format!(
                        "Disables user account `{user_id}`, blocking new authentication and inherited access"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Re-enable account `{user_id}` only after identity validation and scope review"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ReenableUserAccount,
                        format!(
                            "Restore account `{user_id}` and confirm its expected group membership and MFA state before the next login"
                        ),
                    )],
                },
            )
        }
        ResponseAction::ForcePasswordReset { user_id } => {
            let user_id = require_value("user_id", user_id)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::UserAccount,
                    scope_value: user_id.clone(),
                    impact: ResponseBlastRadiusImpact::PasswordResetEnforced,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "interactive_authentication".to_string(),
                        "credential_rotation".to_string(),
                    ],
                    summary: format!(
                        "Marks account `{user_id}` for password reset before the next successful login"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Clear the forced-reset requirement for `{user_id}` only if the reset was queued in error"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::ClearPasswordResetRequirement,
                        format!(
                            "Remove the forced-reset flag for `{user_id}` or issue a controlled temporary credential after validation"
                        ),
                    )],
                },
            )
        }
        ResponseAction::RemoveScheduledTask { host_id, task_name } => {
            let host_id = require_value("host_id", host_id)?;
            let task_name = require_value("task_name", task_name)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::ScheduledTask,
                    scope_value: format!("{host_id}:{task_name}"),
                    impact: ResponseBlastRadiusImpact::ScheduledTaskRemoved,
                    max_affected_scopes: 1,
                    affected_capabilities: vec![
                        "scheduled_automation".to_string(),
                        "task_execution".to_string(),
                    ],
                    summary: format!(
                        "Deletes scheduled task `{task_name}` from host `{host_id}`, preventing future automated execution"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Recreate scheduled task `{task_name}` on `{host_id}` if the removal was not justified"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::RestoreScheduledTask,
                        format!(
                            "Restore scheduled task `{task_name}` on `{host_id}` with its approved trigger and command definition"
                        ),
                    )],
                },
            )
        }
        ResponseAction::DeployDecoy { decoy_type, .. } => {
            let decoy_type = require_value("decoy_type", decoy_type)?;
            let zone = scope_for_response_action(&request.action).ok_or(
                RehearsalPreviewError::MissingScopeTarget {
                    action: "deploy_decoy",
                },
            )?;
            let zone = require_value("target_zone", &zone)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::Zone,
                    scope_value: zone.clone(),
                    impact: ResponseBlastRadiusImpact::DeceptionCoverageChanged,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["deception_coverage".to_string()],
                    summary: format!(
                        "Adds a `{decoy_type}` deception asset inside the bounded zone `{zone}`"
                    ),
                },
                ResponseRollbackPreview {
                    required: true,
                    summary: format!(
                        "Withdraw the rehearsal-scoped `{decoy_type}` decoy from zone `{zone}` if it is promoted"
                    ),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::WithdrawDecoy,
                        format!(
                            "Remove the `{decoy_type}` decoy from `{zone}` and confirm sensors return to baseline"
                        ),
                    )],
                },
            )
        }
        ResponseAction::Escalate { summary, .. } => {
            let summary = require_value("summary", summary)?;
            preview(
                &rehearsal_id,
                source_bundle_id,
                prepared_at_ms,
                ResponseBlastRadiusPreview {
                    scope_kind: ResponseRehearsalScopeKind::OperatorQueue,
                    scope_value: "human_review".to_string(),
                    impact: ResponseBlastRadiusImpact::OperatorEscalationOnly,
                    max_affected_scopes: 1,
                    affected_capabilities: vec!["operator_review_queue".to_string()],
                    summary: format!(
                        "Queues one bounded operator review using the escalation summary `{summary}`"
                    ),
                },
                ResponseRollbackPreview {
                    required: false,
                    summary:
                        "No containment rollback is required; only the queued escalation note may need closure"
                            .to_string(),
                    steps: vec![rollback_step(
                        ResponseRollbackStepKind::CloseEscalation,
                        "Close or supersede the rehearsal-only escalation note after review",
                    )],
                },
            )
        }
    };

    Ok(preview)
}

pub(super) fn playbook_preview_approval_context(
    prepared_at_ms: i64,
    live_mode: bool,
) -> ApprovalContext {
    ApprovalContext {
        live_mode,
        receipt_chain: vec![format!("playbook-preview:{prepared_at_ms}")],
        correlation_id: Some(format!("playbook-preview-{prepared_at_ms}")),
        now_ms: prepared_at_ms,
    }
}

pub(super) fn playbook_preview_hunt_id(prepared_at_ms: i64) -> swarm_core::types::HuntId {
    swarm_core::types::HuntId(format!("playbook-preview-{prepared_at_ms}"))
}

pub(super) fn playbook_preview_evidence(
    request: &ResponsePlaybookPreviewRequest,
    resolution: &ResponsePlaybookRuleResolution,
) -> serde_json::Value {
    json!({
        "preview": true,
        "escalation": {
            "threat_class": request.threat_class,
            "severity": request.severity,
            "confidence": request.confidence,
            "mode": request.mode,
        },
        "playbook_match": {
            "rule_index": resolution.rule_index,
            "threat_class": resolution.threat_class,
            "severity": resolution.severity,
            "min_confidence": resolution.min_confidence,
            "max_confidence": resolution.max_confidence,
            "branch": resolution.branch.as_ref().map(|branch| json!({
                "index": branch.index,
                "name": branch.name,
            })),
        }
    })
}

fn enrich_finding_evidence(
    event: &TelemetryEvent,
    finding: &DetectionFinding,
    detected_at_ms: i64,
) -> serde_json::Value {
    let ancestry = parent_process_ancestry(event);
    let host_metadata = json!({
        "source": event.source,
        "host_id": event.host_id,
        "event_id": event.event_id,
        "event_timestamp": event.timestamp,
    });
    let time_to_detect_ms = (detected_at_ms - normalized_timestamp_ms(event.timestamp)).max(0);
    let escalation = serde_json::json!({
        "threat_class": finding.threat_class,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "strategy_id": finding.strategy_id,
    });

    match finding.evidence.clone() {
        serde_json::Value::Object(mut object) => {
            object.insert(
                "parent_process_ancestry".to_string(),
                serde_json::json!(ancestry),
            );
            object.insert("host_metadata".to_string(), host_metadata);
            object.insert(
                "time_to_detect_ms".to_string(),
                serde_json::json!(time_to_detect_ms),
            );
            object.insert("escalation".to_string(), escalation);
            serde_json::Value::Object(object)
        }
        other => serde_json::json!({
            "evidence": other,
            "escalation": escalation,
            "parent_process_ancestry": ancestry,
            "host_metadata": host_metadata,
            "time_to_detect_ms": time_to_detect_ms,
        }),
    }
}

fn parent_process_ancestry(event: &TelemetryEvent) -> Vec<String> {
    match &event.payload {
        TelemetryPayload::ProcessStart(process) => {
            vec![process.parent_process.clone(), process.process_name.clone()]
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect()
        }
        TelemetryPayload::ProcessMemoryAccess(access) => {
            vec![access.source_process.clone(), access.target_process.clone()]
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect()
        }
        TelemetryPayload::NetworkConnect(connection) => vec![connection.process_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::DnsQuery(dns) => dns
            .process_name
            .clone()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::CloudTrail(event) => event
            .principal_name
            .clone()
            .or_else(|| event.principal_arn.clone())
            .into_iter()
            .chain(std::iter::once(event.event_name.clone()))
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::KubernetesAudit(event) => event
            .username
            .clone()
            .into_iter()
            .chain(std::iter::once(event.resource.clone()))
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::RegistryAccess(registry) => {
            let mut ancestry = vec![registry.process_name.clone()];
            if let Some(target_process) = &registry.target_process {
                ancestry.push(target_process.clone());
            }
            ancestry
                .into_iter()
                .filter(|value| !value.trim().is_empty())
                .collect()
        }
        TelemetryPayload::RegistryPersistence(registry) => vec![registry.process_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::FilePersistence(file) => vec![file.process_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::AuthenticationEvent(authentication) => authentication
            .process_name
            .clone()
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::InfrastructureHealth(health) => vec![health.node_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::ThermalAnomaly(thermal) => vec![thermal.node_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
        TelemetryPayload::ResourceExhaustion(exhaustion) => vec![exhaustion.node_name.clone()]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect(),
    }
}

fn normalized_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp.abs() < 100_000_000_000 {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    }
}

pub(super) fn notification_config_without_providence(
    config: &SwarmConfig,
) -> (
    BTreeMap<String, swarm_core::config::NotificationChannelConfig>,
    swarm_core::config::NotificationRoutingConfig,
) {
    let mut channels = config.notification_channels.clone();
    channels.remove(PROVIDENCE_CHANNEL);
    let mut routing = config.notification_routing.clone();
    for rule in &mut routing.rules {
        rule.channels
            .retain(|channel| channel != PROVIDENCE_CHANNEL);
    }
    routing.rules.retain(|rule| !rule.channels.is_empty());
    (channels, routing)
}
