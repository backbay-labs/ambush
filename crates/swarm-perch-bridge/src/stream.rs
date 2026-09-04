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
use swarm_core::types::{ResponseAction, Severity};
use swarm_perch_wire::{
    WireAgentRole, WireFindingEnvelope, WireResponseActionKind, WireSeverity, WireThreatClass,
};
use swarm_response::SwarmFindingEnvelope;
use swarm_runtime::runtime_events::RuntimeEvent;

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
