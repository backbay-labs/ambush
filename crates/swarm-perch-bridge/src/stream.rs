//! Stream classification, redaction, and the engine-domain → wire conversions.
//!
//! "Stream" is `APPENDIX-NORMATIVE.md` section 7's ruled word: one of the bridge's four transport
//! classes. It never means a threat-class channel (that is a *lane*) and never means one of The
//! Watch's inbox categories (that is a *queue*).
//!
//! The conversions at the bottom of this module are where the engine's domain types become
//! the wire-owned DTOs of `swarm-perch-wire` (00-DECISIONS W3-27). They live here, never in the
//! wire crate, so a field added upstream becomes a compile error at the conversion site rather
//! than a silently absent key on the wire.

use swarm_core::agent::AgentRole;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{
    ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
    ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
    ResponseRollbackStep, ResponseRollbackStepKind, Severity,
};
use swarm_crypto::DetachedSignature;
use swarm_perch_wire::{
    Decision as WireDecision, EscalationLevel as WireEscalationLevel,
    HoldDecisionRecord as WireHoldDecisionRecord, HoldRationale as WireHoldRationale,
    HoldState as WireHoldState, WireActionRequest, WireAgentRole, WireBlastRadiusImpact,
    WireBlastRadiusPreview, WireDetachedSignature, WireFindingEnvelope, WirePolicyDecision,
    WirePolicyVerdict, WireRehearsalPreview, WireRehearsalScopeKind, WireResponseAction,
    WireResponseActionKind, WireRollbackPreview, WireRollbackStep, WireRollbackStepKind,
    WireSeverity, WireThreatClass,
};
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};
use swarm_response::SwarmFindingEnvelope;
use swarm_runtime::held_action::{HoldDecision, HoldDecisionRecord, HoldRationale, HoldState};
use swarm_runtime::runtime_events::{
    EscalationLevel as RuntimeEscalationLevel, RuntimeEvent, RuntimeThreatConcentration,
};

use crate::error::BridgeError;

/// The four transport classes. Each `RuntimeEvent` variant maps to exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Stream {
    /// Durable `kind:9` marker cards into a lane or case channel. Disk-spooled, coalesced,
    /// shed oldest-first with accounting.
    Evidence,
    /// Ephemeral `26000`-`26005` frames, global, no `h` -- deliberately, because none of the six
    /// carries a `p` tag and p-gating them would make them undeliverable (ADR 0017). Memory-spooled
    /// at depth 1 per key; last-wins is lossless in meaning so dropping an older frame is not loss.
    Telemetry,
    /// `kind:46010` plus the ephemeral `26006`/`26003`/`26005` nudges, and case-channel
    /// provisioning on `CasePromoted`. Disk-spooled, **never coalesced, never shed**.
    Alarm,
    /// Carries no domain fact. Counts, ranges, and the `26000` ingest-rate gauge. Not spooled;
    /// its `GapSlot` is persisted inside the sibling streams' cursors so a crash between a loss
    /// and the next card does not lose the knowledge that the loss happened.
    DroppedAtSource,
}

impl Stream {
    /// Whether this stream keeps a segmented on-disk log.
    ///
    /// `Telemetry` is deliberately false — a replayed ephemeral is a lie about "now", the relay
    /// never stores ephemerals anyway, and last-wins at depth 1 is already lossless in meaning.
    pub const fn is_disk_spooled(self) -> bool {
        matches!(self, Self::Evidence | Self::Alarm)
    }

    /// Metric label value. Stable; dashboards key on it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Telemetry => "telemetry",
            Self::Alarm => "alarm",
            Self::DroppedAtSource => "dropped_at_source",
        }
    }

    /// The byte the segment header carries for a disk-spooled stream: `1` evidence, `3` alarm.
    /// `2` is reserved for telemetry, which never lands on disk.
    pub const fn disk_code(self) -> u8 {
        match self {
            Self::Evidence => 1,
            Self::Telemetry => 2,
            Self::Alarm => 3,
            Self::DroppedAtSource => 0,
        }
    }
}

/// Maps a `RuntimeEvent` to its **scheduling** stream.
///
/// EXHAUSTIVE, WITH NO `_` ARM, ON PURPOSE. `RuntimeEvent` has twelve variants today, and each
/// time one is added this function fails to compile and somebody must decide which stream the
/// new fact belongs to. That is the point.
///
/// `ModeTransition` and `TamperAlert` are dual-routed on the wire: they are `Alarm` for
/// scheduling — never coalesced, never shed — and the alarm publisher *additionally* emits their
/// telemetry ephemeral once those producers land. This function returns the scheduling class,
/// which is the one that governs backpressure.
pub fn classify(event: &RuntimeEvent) -> Stream {
    match event {
        // --- Alarm -------------------------------------------------------------------------
        // `CasePromoted` is Alarm, not Evidence, for one reason: it is the only trigger that
        // creates a case channel on the manual-promotion clause, which ADR 0018 C4 enables
        // FIRST. Coalescing or shedding it would leave a daemon incident record whose `case_id`
        // names a channel that does not exist. It carries no `26006` frame -- a promotion is not
        // a held action and must not alarm the shift -- so it costs one `kind:9007` and one
        // `kind:9000` per operator.
        RuntimeEvent::CasePromoted { .. } => Stream::Alarm,
        // `ResponseHeld` is Alarm and bypasses the pacer: a held destructive
        // action is exactly the event an operator is waiting on, and the
        // 26006 frame it drives must never be coalesced or shed (R-1).
        RuntimeEvent::ResponseHeld { .. } => Stream::Alarm,
        // B1c. A rollback receipt is durable evidence: never coalesced,
        // spooled to disk, and the only record that a containment was undone.
        RuntimeEvent::ContainmentReleased { .. } => Stream::Evidence,
        RuntimeEvent::ModeTransition { .. } => Stream::Alarm,
        RuntimeEvent::TamperAlert { .. } => Stream::Alarm,

        // --- Evidence ----------------------------------------------------------------------
        RuntimeEvent::Escalation { .. } => Stream::Evidence,
        RuntimeEvent::Finding { .. } => Stream::Evidence,
        RuntimeEvent::ResponseExecution { .. } => Stream::Evidence,

        // --- Telemetry ---------------------------------------------------------------------
        RuntimeEvent::ConcentrationSnapshot { .. } => Stream::Telemetry,
        RuntimeEvent::AgentHealth { .. } => Stream::Telemetry,
        RuntimeEvent::AgentAction { .. } => Stream::Telemetry,

        // --- Dropped at source -------------------------------------------------------------
        // `Ingest` is published once per accepted telemetry event and is reduced, deliberately,
        // to the 1 Hz `26000` gauge. One relay event per ingested event exceeds the relay quota
        // by ~1,800x, and the record already exists in the `ReplayBundle`.
        RuntimeEvent::Ingest { .. } => Stream::DroppedAtSource,
        // `Replay` and `EvolutionStatus` are not published at all. The Watchfloor and `/tuning`
        // read the daemon.
        RuntimeEvent::Replay { .. } => Stream::DroppedAtSource,
        RuntimeEvent::EvolutionStatus { .. } => Stream::DroppedAtSource,
    }
}

/// Fields stripped at classification time, before the record ever reaches the spool.
///
/// Two of these are security obligations rather than size optimizations:
///
/// - `AgentAction.details` is `serde_json::to_value(action)` over the entire `SwarmAction`,
///   i.e. adversary-influenced content, and there is no route that serves it. Dropped; a tally
///   is published instead.
/// - `TamperAlert.unexpected_library_loads` is reduced to its `.len()`. The `26000` block's
///   payload rule is counts, not paths.
///
/// Returns the number of library paths stripped so the receive loop can count them. The
/// wildcard arm is acceptable here and only here: redaction is an allow-list of fields to
/// strip, and a new variant must default to "strip nothing" — the opposite of [`classify`],
/// whose exhaustiveness is the point.
pub fn redact_in_place(event: &mut RuntimeEvent) -> usize {
    match event {
        RuntimeEvent::AgentAction { details, .. } => {
            *details = serde_json::Value::Null;
            0
        }
        RuntimeEvent::TamperAlert {
            unexpected_library_loads,
            ..
        } => {
            let count = unexpected_library_loads.len();
            unexpected_library_loads.clear();
            count
        }
        _ => 0,
    }
}

// ═══════════════════════════════════════════ engine domain → wire DTO (W3-27)

/// The wire threat class for an engine threat class. Exhaustive over the taxonomy.
pub fn threat_class_to_wire(class: &ThreatClass) -> WireThreatClass {
    match class {
        ThreatClass::LateralMovement => WireThreatClass::LateralMovement,
        ThreatClass::DataExfiltration => WireThreatClass::DataExfiltration,
        ThreatClass::PrivilegeEscalation => WireThreatClass::PrivilegeEscalation,
        ThreatClass::CommandAndControl => WireThreatClass::CommandAndControl,
        ThreatClass::InitialAccess => WireThreatClass::InitialAccess,
        ThreatClass::Persistence => WireThreatClass::Persistence,
        ThreatClass::SupplyChain => WireThreatClass::SupplyChain,
        ThreatClass::DefenseEvasion => WireThreatClass::DefenseEvasion,
        ThreatClass::CredentialAccess => WireThreatClass::CredentialAccess,
        ThreatClass::Discovery => WireThreatClass::Discovery,
        ThreatClass::Execution => WireThreatClass::Execution,
        ThreatClass::Impact => WireThreatClass::Impact,
        ThreatClass::Custom(name) => WireThreatClass::Custom(name.clone()),
    }
}

/// The `t`-tag slug of an engine threat class: the snake_case name, or `custom`.
pub fn threat_class_slug(class: &ThreatClass) -> String {
    swarm_perch_wire::threat_class_slug(&threat_class_to_wire(class)).to_string()
}

/// The wire severity for an engine severity. Exhaustive.
pub fn severity_to_wire(severity: Severity) -> WireSeverity {
    match severity {
        Severity::Low => WireSeverity::Low,
        Severity::Medium => WireSeverity::Medium,
        Severity::High => WireSeverity::High,
        Severity::Critical => WireSeverity::Critical,
    }
}

/// The `l`-tag label of an engine severity, SCREAMING_SNAKE.
pub fn severity_label(severity: Severity) -> &'static str {
    swarm_perch_wire::severity_label(severity_to_wire(severity))
}

/// The wire agent role for an engine agent role. Exhaustive over the eight roles.
pub fn agent_role_to_wire(role: AgentRole) -> WireAgentRole {
    match role {
        AgentRole::Whisker => WireAgentRole::Whisker,
        AgentRole::Stalker => WireAgentRole::Stalker,
        AgentRole::Weaver => WireAgentRole::Weaver,
        AgentRole::Pouncer => WireAgentRole::Pouncer,
        AgentRole::Tom => WireAgentRole::Tom,
        AgentRole::Kitten => WireAgentRole::Kitten,
        AgentRole::Sphinx => WireAgentRole::Sphinx,
        AgentRole::Calico => WireAgentRole::Calico,
    }
}

/// The wire action kind of an engine response action. Exhaustive over the fifteen actions.
pub fn response_action_kind_to_wire(action: &ResponseAction) -> WireResponseActionKind {
    match action {
        ResponseAction::BlockEgress { .. } => WireResponseActionKind::BlockEgress,
        ResponseAction::IsolateHost { .. } => WireResponseActionKind::IsolateHost,
        ResponseAction::RevokeCredential { .. } => WireResponseActionKind::RevokeCredential,
        ResponseAction::SinkholeDns { .. } => WireResponseActionKind::SinkholeDns,
        ResponseAction::TerminateUserSession { .. } => WireResponseActionKind::TerminateUserSession,
        ResponseAction::TriggerEdrScan { .. } => WireResponseActionKind::TriggerEdrScan,
        ResponseAction::InjectFirewallRule { .. } => WireResponseActionKind::InjectFirewallRule,
        ResponseAction::QuarantineFile { .. } => WireResponseActionKind::QuarantineFile,
        ResponseAction::KillProcess { .. } => WireResponseActionKind::KillProcess,
        ResponseAction::SuspendProcess { .. } => WireResponseActionKind::SuspendProcess,
        ResponseAction::DisableUserAccount { .. } => WireResponseActionKind::DisableUserAccount,
        ResponseAction::ForcePasswordReset { .. } => WireResponseActionKind::ForcePasswordReset,
        ResponseAction::RemoveScheduledTask { .. } => WireResponseActionKind::RemoveScheduledTask,
        ResponseAction::DeployDecoy { .. } => WireResponseActionKind::DeployDecoy,
        ResponseAction::Escalate { .. } => WireResponseActionKind::Escalate,
    }
}

/// The wire form of a `SwarmFindingEnvelope`: every field copied, nothing redacted.
///
/// Redaction is the separate step above; evidence truncation is the card builder's, because it
/// depends on the serialized size of the whole card.
pub fn finding_to_wire(finding: &SwarmFindingEnvelope) -> WireFindingEnvelope {
    let SwarmFindingEnvelope {
        schema,
        finding_id,
        event_id,
        strategy_id,
        threat_class,
        severity,
        confidence,
        evidence,
    } = finding;
    WireFindingEnvelope {
        schema: schema.clone(),
        finding_id: finding_id.clone(),
        event_id: event_id.clone(),
        strategy_id: strategy_id.clone(),
        threat_class: threat_class_to_wire(threat_class),
        severity: severity_to_wire(*severity),
        confidence: *confidence,
        evidence: evidence.clone(),
    }
}

// ────────────────────────────────────────────────── the hold record, projected

/// The wire policy verdict for an engine one. Exhaustive.
pub fn policy_verdict_to_wire(verdict: PolicyVerdict) -> WirePolicyVerdict {
    match verdict {
        PolicyVerdict::Deny => WirePolicyVerdict::Deny,
        PolicyVerdict::Allow => WirePolicyVerdict::Allow,
        PolicyVerdict::RequireHuman => WirePolicyVerdict::RequireHuman,
    }
}

/// The wire form of a `PolicyDecision`: three fields, destructured so a fourth is a compile
/// error here rather than an absent key on the wire.
pub fn policy_decision_to_wire(decision: &PolicyDecision) -> WirePolicyDecision {
    let PolicyDecision {
        verdict,
        rule_name,
        reason,
    } = decision;
    WirePolicyDecision {
        verdict: policy_verdict_to_wire(*verdict),
        rule_name: rule_name.clone(),
        reason: reason.clone(),
    }
}

/// The wire form of a `ResponseAction`.
///
/// The kind comes from [`response_action_kind_to_wire`], which is exhaustive over the fifteen
/// variants and therefore compile-checked. The PAYLOAD is carried verbatim through the action's
/// own serde form, which is what
/// [`swarm_perch_wire::WireResponseAction`]'s `#[serde(flatten)]` map is for: Perch is a reader
/// of the action and never an author, and the schema is `additionalProperties: true`.
/// `every_action_kind_round_trips_through_the_wire_action` asserts the two halves reassemble
/// into the engine's own bytes for all fifteen.
///
/// # Errors
///
/// [`BridgeError::Encode`] when the action does not serialize to a JSON object — which would
/// mean the engine had stopped tagging `ResponseAction` internally on `type`.
pub fn response_action_to_wire(action: &ResponseAction) -> Result<WireResponseAction, BridgeError> {
    let value =
        serde_json::to_value(action).map_err(|error| BridgeError::Encode(error.to_string()))?;
    let serde_json::Value::Object(map) = value else {
        return Err(BridgeError::Encode(
            "ResponseAction did not serialize to a JSON object".to_string(),
        ));
    };
    Ok(WireResponseAction {
        kind: response_action_kind_to_wire(action),
        fields: map.into_iter().filter(|(key, _)| key != "type").collect(),
    })
}

/// The wire form of an `ActionRequest`. Carried VERBATIM, including `evidence`, which is
/// adversary-shaped: the card is channel-compartmented and the hold pane has to show the
/// operator what the requesting agent actually claimed.
///
/// # Errors
///
/// [`BridgeError::Encode`] from [`response_action_to_wire`].
pub fn action_request_to_wire(request: &ActionRequest) -> Result<WireActionRequest, BridgeError> {
    let ActionRequest {
        hunt_id,
        requested_by,
        action,
        severity,
        evidence,
    } = request;
    Ok(WireActionRequest {
        hunt_id: hunt_id.0.clone(),
        requested_by: requested_by.0.clone(),
        action: response_action_to_wire(action)?,
        severity: severity_to_wire(*severity),
        evidence: evidence.clone(),
    })
}

/// The wire form of a runtime threat concentration.
pub fn concentration_to_wire(
    concentration: &RuntimeThreatConcentration,
) -> swarm_perch_wire::ThreatConcentration {
    let RuntimeThreatConcentration {
        threat_class,
        total_strength,
        distinct_sources,
        peak_confidence,
    } = concentration;
    swarm_perch_wire::ThreatConcentration {
        threat_class: threat_class_to_wire(threat_class),
        total_strength: *total_strength,
        distinct_sources: *distinct_sources,
        peak_confidence: *peak_confidence,
    }
}

/// The wire escalation level for a runtime one. Exhaustive.
pub fn escalation_level_to_wire(level: RuntimeEscalationLevel) -> WireEscalationLevel {
    match level {
        RuntimeEscalationLevel::Alert => WireEscalationLevel::Alert,
        RuntimeEscalationLevel::Incident => WireEscalationLevel::Incident,
    }
}

/// The wire form of the hold's rationale — render law 1's WHY WE ARE ASKING slot.
pub fn hold_rationale_to_wire(rationale: &HoldRationale) -> WireHoldRationale {
    let HoldRationale {
        rule_name,
        reason,
        threat_class,
        severity,
        request_carried_fields,
        concentration_at_hold,
        escalation_level,
        governance_receipt_present,
    } = rationale;
    WireHoldRationale {
        rule_name: rule_name.clone(),
        reason: reason.clone(),
        threat_class: threat_class_to_wire(threat_class),
        severity: severity_to_wire(*severity),
        request_carried_fields: request_carried_fields.clone(),
        concentration_at_hold: concentration_at_hold.as_ref().map(concentration_to_wire),
        escalation_level: escalation_level.map(escalation_level_to_wire),
        governance_receipt_present: *governance_receipt_present,
    }
}

/// The wire rehearsal scope kind. Exhaustive over the ten.
pub fn rehearsal_scope_kind_to_wire(kind: ResponseRehearsalScopeKind) -> WireRehearsalScopeKind {
    match kind {
        ResponseRehearsalScopeKind::NetworkTarget => WireRehearsalScopeKind::NetworkTarget,
        ResponseRehearsalScopeKind::Host => WireRehearsalScopeKind::Host,
        ResponseRehearsalScopeKind::Credential => WireRehearsalScopeKind::Credential,
        ResponseRehearsalScopeKind::UserSession => WireRehearsalScopeKind::UserSession,
        ResponseRehearsalScopeKind::File => WireRehearsalScopeKind::File,
        ResponseRehearsalScopeKind::Process => WireRehearsalScopeKind::Process,
        ResponseRehearsalScopeKind::UserAccount => WireRehearsalScopeKind::UserAccount,
        ResponseRehearsalScopeKind::ScheduledTask => WireRehearsalScopeKind::ScheduledTask,
        ResponseRehearsalScopeKind::Zone => WireRehearsalScopeKind::Zone,
        ResponseRehearsalScopeKind::OperatorQueue => WireRehearsalScopeKind::OperatorQueue,
    }
}

/// The wire blast-radius impact. Exhaustive over the fifteen, one per action.
pub fn blast_radius_impact_to_wire(impact: ResponseBlastRadiusImpact) -> WireBlastRadiusImpact {
    match impact {
        ResponseBlastRadiusImpact::NetworkEgressBlocked => {
            WireBlastRadiusImpact::NetworkEgressBlocked
        }
        ResponseBlastRadiusImpact::HostConnectivityIsolated => {
            WireBlastRadiusImpact::HostConnectivityIsolated
        }
        ResponseBlastRadiusImpact::CredentialAccessRevoked => {
            WireBlastRadiusImpact::CredentialAccessRevoked
        }
        ResponseBlastRadiusImpact::DnsResolutionSinkholed => {
            WireBlastRadiusImpact::DnsResolutionSinkholed
        }
        ResponseBlastRadiusImpact::UserSessionTerminated => {
            WireBlastRadiusImpact::UserSessionTerminated
        }
        ResponseBlastRadiusImpact::HostScanTriggered => WireBlastRadiusImpact::HostScanTriggered,
        ResponseBlastRadiusImpact::HostFirewallPolicyChanged => {
            WireBlastRadiusImpact::HostFirewallPolicyChanged
        }
        ResponseBlastRadiusImpact::FileQuarantined => WireBlastRadiusImpact::FileQuarantined,
        ResponseBlastRadiusImpact::ProcessTerminated => WireBlastRadiusImpact::ProcessTerminated,
        ResponseBlastRadiusImpact::ProcessSuspended => WireBlastRadiusImpact::ProcessSuspended,
        ResponseBlastRadiusImpact::UserAccountDisabled => {
            WireBlastRadiusImpact::UserAccountDisabled
        }
        ResponseBlastRadiusImpact::PasswordResetEnforced => {
            WireBlastRadiusImpact::PasswordResetEnforced
        }
        ResponseBlastRadiusImpact::ScheduledTaskRemoved => {
            WireBlastRadiusImpact::ScheduledTaskRemoved
        }
        ResponseBlastRadiusImpact::DeceptionCoverageChanged => {
            WireBlastRadiusImpact::DeceptionCoverageChanged
        }
        ResponseBlastRadiusImpact::OperatorEscalationOnly => {
            WireBlastRadiusImpact::OperatorEscalationOnly
        }
    }
}

/// The wire rollback step kind. Exhaustive over the fifteen.
pub fn rollback_step_kind_to_wire(kind: ResponseRollbackStepKind) -> WireRollbackStepKind {
    match kind {
        ResponseRollbackStepKind::RemoveNetworkBlock => WireRollbackStepKind::RemoveNetworkBlock,
        ResponseRollbackStepKind::RestoreHostConnectivity => {
            WireRollbackStepKind::RestoreHostConnectivity
        }
        ResponseRollbackStepKind::RestoreCredential => WireRollbackStepKind::RestoreCredential,
        ResponseRollbackStepKind::RemoveDnsSinkhole => WireRollbackStepKind::RemoveDnsSinkhole,
        ResponseRollbackStepKind::ReauthenticateUserSession => {
            WireRollbackStepKind::ReauthenticateUserSession
        }
        ResponseRollbackStepKind::CancelHostScan => WireRollbackStepKind::CancelHostScan,
        ResponseRollbackStepKind::RemoveFirewallRule => WireRollbackStepKind::RemoveFirewallRule,
        ResponseRollbackStepKind::ReleaseQuarantinedFile => {
            WireRollbackStepKind::ReleaseQuarantinedFile
        }
        ResponseRollbackStepKind::RestartProcess => WireRollbackStepKind::RestartProcess,
        ResponseRollbackStepKind::ResumeProcess => WireRollbackStepKind::ResumeProcess,
        ResponseRollbackStepKind::ReenableUserAccount => WireRollbackStepKind::ReenableUserAccount,
        ResponseRollbackStepKind::ClearPasswordResetRequirement => {
            WireRollbackStepKind::ClearPasswordResetRequirement
        }
        ResponseRollbackStepKind::RestoreScheduledTask => {
            WireRollbackStepKind::RestoreScheduledTask
        }
        ResponseRollbackStepKind::WithdrawDecoy => WireRollbackStepKind::WithdrawDecoy,
        ResponseRollbackStepKind::CloseEscalation => WireRollbackStepKind::CloseEscalation,
    }
}

/// The wire form of the daemon's rehearsal preview — render law 1's BLAST RADIUS and IF YOU
/// UNDO slots.
pub fn rehearsal_to_wire(preview: &ResponseRehearsalPreview) -> WireRehearsalPreview {
    let ResponseRehearsalPreview {
        rehearsal_id,
        source_bundle_id,
        prepared_at_ms,
        simulated_only,
        blast_radius,
        rollback,
    } = preview;
    let ResponseBlastRadiusPreview {
        scope_kind,
        scope_value,
        impact,
        max_affected_scopes,
        affected_capabilities,
        summary: blast_summary,
    } = blast_radius;
    let ResponseRollbackPreview {
        required,
        summary: rollback_summary,
        steps,
    } = rollback;
    WireRehearsalPreview {
        rehearsal_id: rehearsal_id.clone(),
        source_bundle_id: source_bundle_id.clone(),
        prepared_at_ms: *prepared_at_ms,
        simulated_only: *simulated_only,
        blast_radius: WireBlastRadiusPreview {
            scope_kind: rehearsal_scope_kind_to_wire(*scope_kind),
            scope_value: scope_value.clone(),
            impact: blast_radius_impact_to_wire(*impact),
            max_affected_scopes: *max_affected_scopes,
            affected_capabilities: affected_capabilities.clone(),
            summary: blast_summary.clone(),
        },
        rollback: WireRollbackPreview {
            required: *required,
            summary: rollback_summary.clone(),
            steps: steps
                .iter()
                .map(|step| {
                    let ResponseRollbackStep { kind, summary } = step;
                    WireRollbackStep {
                        kind: rollback_step_kind_to_wire(*kind),
                        summary: summary.clone(),
                    }
                })
                .collect(),
        },
    }
}

/// The wire hold state. Exhaustive over the nine.
pub fn hold_state_to_wire(state: HoldState) -> WireHoldState {
    match state {
        HoldState::Created => WireHoldState::Created,
        HoldState::Notified => WireHoldState::Notified,
        HoldState::Armed => WireHoldState::Armed,
        HoldState::Deciding => WireHoldState::Deciding,
        HoldState::Granted => WireHoldState::Granted,
        HoldState::Refused => WireHoldState::Refused,
        HoldState::Expired => WireHoldState::Expired,
        HoldState::Executed => WireHoldState::Executed,
        HoldState::Failed => WireHoldState::Failed,
    }
}

/// The wire form of a detached Ed25519 signature.
pub fn detached_signature_to_wire(signature: &DetachedSignature) -> WireDetachedSignature {
    let DetachedSignature {
        algorithm,
        key_id,
        public_key_hex,
        signature_hex,
    } = signature;
    WireDetachedSignature {
        algorithm: algorithm.clone(),
        key_id: key_id.clone(),
        public_key_hex: public_key_hex.clone(),
        signature_hex: signature_hex.clone(),
    }
}

/// The wire operator decision word. Exhaustive; NEVER `deny`.
pub fn hold_decision_to_wire(decision: HoldDecision) -> WireDecision {
    match decision {
        HoldDecision::Grant => WireDecision::Grant,
        HoldDecision::Refuse => WireDecision::Refuse,
    }
}

/// The engine's partition state on the wire.
///
/// A total match, not a string round trip: the two enums are the same four
/// states and a new one on either side must fail to compile here rather than
/// serialize as something the console does not know how to render (INV-08).
pub fn partition_state_to_wire(
    state: swarm_policy::governance::PartitionState,
) -> swarm_perch_wire::cards::WirePartitionState {
    use swarm_perch_wire::cards::WirePartitionState as Wire;
    use swarm_policy::governance::PartitionState as Engine;
    match state {
        Engine::Healthy => Wire::Healthy,
        Engine::Degraded => Wire::Degraded,
        Engine::Partitioned => Wire::Partitioned,
        Engine::Healing => Wire::Healing,
    }
}

/// The wire form of a stored decision.
///
/// NARROWING, and every dropped field is a daemon-side fact with no place on a card that
/// reaches an operator's timeline: `voter_id` and `rationale_sha256` belong to the decide
/// route's signature check, `hold_notice_published` and `governance_clearance` are the
/// daemon's own account of what it re-derived, and `audit_trail_id` names a record no console
/// can fetch. The card carries what a human reads: who, when, what happened, and why not.
pub fn hold_decision_record_to_wire(record: &HoldDecisionRecord) -> WireHoldDecisionRecord {
    let HoldDecisionRecord {
        decision,
        operator_id,
        voter_id: _,
        rationale_sha256: _,
        hold_notice_published: _,
        governance_clearance: _,
        decided_at_ms,
        nostr_intent_event_id,
        signature,
        rationale,
        outcome,
        dispatched,
        receipt_id,
        audit_trail_id: _,
        refusal,
        partition_state_at_execution,
    } = record;
    WireHoldDecisionRecord {
        partition_state_at_execution: partition_state_at_execution.map(partition_state_to_wire),
        decision: hold_decision_to_wire(*decision),
        operator_id: operator_id.clone(),
        decided_at_ms: *decided_at_ms,
        nostr_intent_event_id: nostr_intent_event_id.clone(),
        signature: signature.as_ref().map(detached_signature_to_wire),
        rationale: rationale.clone(),
        outcome: serde_json::to_value(outcome)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string()),
        dispatched: *dispatched,
        receipt_id: receipt_id.clone(),
        refusal: refusal
            .as_ref()
            .and_then(|refusal| serde_json::to_value(refusal).ok()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn event(json: serde_json::Value) -> RuntimeEvent {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn a_finding_is_evidence_and_a_mode_transition_is_alarm() {
        let finding = event(serde_json::json!({
            "event_type": "finding", "emitted_at_ms": 1, "host_id": "web-04",
            "finding": {"schema": "swarm_finding", "finding_id": "f1", "event_id": "e1",
                        "strategy_id": "dns_exfil_beaconing", "threat_class": "data_exfiltration",
                        "severity": "HIGH", "confidence": 0.82, "evidence": {}}
        }));
        assert_eq!(classify(&finding), Stream::Evidence);
        let mode = event(serde_json::json!({
            "event_type": "mode_transition", "emitted_at_ms": 1, "from": "normal", "to": "incident",
            "triggering_threat_class": null, "reason": "test"
        }));
        assert_eq!(classify(&mode), Stream::Alarm);
        assert!(Stream::Evidence.is_disk_spooled() && Stream::Alarm.is_disk_spooled());
        assert!(!Stream::Telemetry.is_disk_spooled() && !Stream::DroppedAtSource.is_disk_spooled());
    }

    #[test]
    fn a_case_promotion_is_alarm_class() {
        let promoted = event(serde_json::json!({
            "event_type": "case_promoted", "emitted_at_ms": 1, "hunt_id": "hunt-1",
            "case_id": "9499a6e2-8872-453b-80d9-dafc6fc7fc69", "clause": "manual",
            "incident_id": "incident:perch-case:9499a6e2-8872-453b-80d9-dafc6fc7fc69",
            "finding_id": "f-1", "threat_class": "execution", "severity": "HIGH",
            "summary": "promoted"
        }));
        assert_eq!(classify(&promoted), Stream::Alarm);
    }

    /// A release is EVIDENCE, not an alarm.
    ///
    /// The compiler forces an arm to exist; this pins which one. An alarm
    /// bypasses the pacer and is never shed, which is right for a hold waiting
    /// on a human and wrong for a receipt that records something already done.
    #[test]
    fn a_containment_release_is_durable_evidence_and_not_an_alarm() {
        let released = event(serde_json::json!({
            "event_type": "containment_released",
            "emitted_at_ms": 7,
            "lease_id": "cl_test",
            "trigger": "expiry",
            "receipt": {
                "rollback_id": "rb_test",
                "lease_id": "cl_test",
                "origin_receipt_id": "resp_test",
                "governance_receipt_id": null,
                "trigger": "expiry",
                "mode": "enforced",
                "status": "executed",
                "steps": [],
                "completed_at_ms": 7,
                "summary": "0 of 0 steps reversed",
                "governance_attestation": null
            },
            "lease_closed": true,
            "attestation_verified": false,
            "attestation_error": "unattested",
            "partition_state_at_execution": "healthy"
        }));
        assert_eq!(classify(&released), Stream::Evidence);
    }

    #[test]
    fn classify_has_no_wildcard_arm() {
        // The compile-time guarantee, made greppable: a `_ =>` inside classify would
        // let a new RuntimeEvent variant land in a stream nobody chose.
        let src = include_str!("stream.rs");
        let body = src
            .split("pub fn classify")
            .nth(1)
            .unwrap()
            .split("pub fn redact_in_place")
            .next()
            .unwrap();
        assert!(!body.contains("_ =>"), "classify must stay exhaustive");
    }

    #[test]
    fn redaction_strips_library_paths_and_reports_the_count() {
        let mut tamper = event(serde_json::json!({
            "event_type": "tamper_alert", "emitted_at_ms": 1, "debugger_attached": false,
            "tracer_pid": null, "unexpected_library_loads": ["/tmp/a.so", "/tmp/b.so"],
            "fail_closed": true, "details": "two unexpected loads"
        }));
        assert_eq!(redact_in_place(&mut tamper), 2);
        assert!(matches!(
            tamper,
            RuntimeEvent::TamperAlert { ref unexpected_library_loads, .. }
                if unexpected_library_loads.is_empty()
        ));
        let mut action = event(serde_json::json!({
            "event_type": "agent_action", "emitted_at_ms": 1, "agent_id": "whisker-1",
            "role": "whisker", "action_kind": "deposit", "hunt_id": null,
            "details": {"payload": "adversary-shaped"}
        }));
        assert_eq!(redact_in_place(&mut action), 0);
        assert!(matches!(
            action,
            RuntimeEvent::AgentAction { ref details, .. } if details.is_null()
        ));
    }

    #[test]
    fn every_threat_class_converts_to_its_exact_wire_spelling() {
        let standard = [
            (ThreatClass::LateralMovement, "lateral_movement"),
            (ThreatClass::DataExfiltration, "data_exfiltration"),
            (ThreatClass::PrivilegeEscalation, "privilege_escalation"),
            (ThreatClass::CommandAndControl, "command_and_control"),
            (ThreatClass::InitialAccess, "initial_access"),
            (ThreatClass::Persistence, "persistence"),
            (ThreatClass::SupplyChain, "supply_chain"),
            (ThreatClass::DefenseEvasion, "defense_evasion"),
            (ThreatClass::CredentialAccess, "credential_access"),
            (ThreatClass::Discovery, "discovery"),
            (ThreatClass::Execution, "execution"),
            (ThreatClass::Impact, "impact"),
        ];
        for (class, spelling) in standard {
            let wire = threat_class_to_wire(&class);
            assert_eq!(serde_json::to_value(&wire).unwrap(), spelling);
            assert_eq!(
                serde_json::to_value(&wire).unwrap(),
                serde_json::to_value(&class).unwrap(),
                "the wire and the engine must serialize identically"
            );
            assert_eq!(threat_class_slug(&class), spelling);
        }
        let custom = ThreatClass::Custom("vendor_class".into());
        let wire = threat_class_to_wire(&custom);
        assert_eq!(
            serde_json::to_value(&wire).unwrap(),
            serde_json::json!({"custom": "vendor_class"})
        );
        assert_eq!(
            serde_json::to_value(&wire).unwrap(),
            serde_json::to_value(&custom).unwrap()
        );
        assert_eq!(threat_class_slug(&custom), "custom");
    }

    #[test]
    fn severities_roles_and_actions_keep_their_engine_spelling() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(
                serde_json::to_value(severity_to_wire(severity)).unwrap(),
                serde_json::to_value(severity).unwrap()
            );
            assert_eq!(
                severity_label(severity),
                serde_json::to_value(severity).unwrap().as_str().unwrap()
            );
        }
        for role in [
            AgentRole::Whisker,
            AgentRole::Stalker,
            AgentRole::Weaver,
            AgentRole::Pouncer,
            AgentRole::Tom,
            AgentRole::Kitten,
            AgentRole::Sphinx,
            AgentRole::Calico,
        ] {
            assert_eq!(
                serde_json::to_value(agent_role_to_wire(role)).unwrap(),
                serde_json::to_value(role).unwrap()
            );
        }
        let action = ResponseAction::IsolateHost {
            host_id: "web-04".into(),
        };
        assert_eq!(
            response_action_kind_to_wire(&action).as_str(),
            action.kind()
        );
    }

    #[test]
    fn a_finding_envelope_converts_field_for_field_with_nothing_redacted() {
        let finding = SwarmFindingEnvelope {
            schema: "swarm_finding".into(),
            finding_id: "f2c9a1b4".into(),
            event_id: "tel-8831".into(),
            strategy_id: "dns_exfil_beaconing".into(),
            threat_class: ThreatClass::DataExfiltration,
            severity: Severity::High,
            confidence: 0.82,
            evidence: serde_json::json!({"entropy": 4.7, "query_count": 411}),
        };
        let wire = finding_to_wire(&finding);
        assert_eq!(
            serde_json::to_value(&wire).unwrap(),
            serde_json::to_value(&finding).unwrap()
        );
    }
}
