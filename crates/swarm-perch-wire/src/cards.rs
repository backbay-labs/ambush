//! The seven card bodies, and the wire-owned vocabulary they are built from.
//!
//! Every type in this module is a SERIALIZED CONTRACT owned by this crate
//! (`00-DECISIONS.md` W3-27). Where a field mirrors an engine domain type —
//! `SwarmFindingEnvelope`, `ActionRequest`, `AuditTrail`, `ContainmentLease`,
//! `RollbackReceipt` and the enums they carry — the `Wire*` type re-declares the
//! field set, field for field, in the same serde representation the engine
//! emits, and the JSON Schema under `docs/plans/ambush-ui/build/schemas/` is the
//! normative statement of that field set. Nothing here is an alias of an engine
//! type and this crate names no `swarm-*` package. The conversion from the
//! engine's types into these lives in `swarm-perch-bridge`, which is where a
//! field added upstream becomes a compile error at the conversion site rather
//! than a silently absent key on the wire.
//!
//! Where a wire type deliberately NARROWS a domain type, the narrowing is named
//! at the field with the reason.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::envelope::{FactIssuer, OperatorFactIssuer};
use crate::frames::{EscalationLevel, ThreatConcentration};
use crate::marker::CardKind;

// ═══════════════════════════════════════════════════════ wire vocabulary
//
// Closed enums, each with an explicit `as_str` so a human line never recovers
// a spelling by importing an engine type. Every one mirrors a `$def` in
// `common.schema.json`, whose `x-source` names the engine type and the serde
// attribute that fixes the wire form.

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident, $rename_all:literal {
            $( $variant:ident => $wire:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = $rename_all)]
        pub enum $name {
            $(
                #[doc = concat!("`", $wire, "`")]
                $variant,
            )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The exact wire spelling of this variant.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

/// The standard threat classes in taxonomy order.
///
/// Twelve unit variants plus `Custom(String)`, EXTERNALLY tagged exactly as the
/// engine's `ThreatClass` is (`common.schema.json#/$defs/ThreatClass`): serde
/// emits a bare string for the twelve and the single-key object
/// `{"custom": "..."}` for the thirteenth. Two production agents mint `Custom`
/// classes, so the object form is reachable, not theoretical.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireThreatClass {
    /// `lateral_movement`
    LateralMovement,
    /// `data_exfiltration`
    DataExfiltration,
    /// `privilege_escalation`
    PrivilegeEscalation,
    /// `command_and_control`
    CommandAndControl,
    /// `initial_access`
    InitialAccess,
    /// `persistence`
    Persistence,
    /// `supply_chain`
    SupplyChain,
    /// `defense_evasion`
    DefenseEvasion,
    /// `credential_access`
    CredentialAccess,
    /// `discovery`
    Discovery,
    /// `execution`
    Execution,
    /// `impact`
    Impact,
    /// A class outside the standard taxonomy. `{"custom": "<name>"}` on the
    /// wire; `custom` as the `t` tag slug, with the name carried in the body.
    Custom(String),
}

impl WireThreatClass {
    /// The twelve standard classes, in taxonomy order.
    pub const STANDARD: [Self; 12] = [
        Self::LateralMovement,
        Self::DataExfiltration,
        Self::PrivilegeEscalation,
        Self::CommandAndControl,
        Self::InitialAccess,
        Self::Persistence,
        Self::SupplyChain,
        Self::DefenseEvasion,
        Self::CredentialAccess,
        Self::Discovery,
        Self::Execution,
        Self::Impact,
    ];

    /// The `t`-tag slug: the wire spelling for a standard class, the literal
    /// `custom` for a custom one. See [`threat_class_slug`].
    #[must_use]
    pub fn slug(&self) -> &'static str {
        threat_class_slug(self)
    }
}

impl fmt::Display for WireThreatClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(name) => write!(f, "custom:{name}"),
            standard => f.write_str(standard.slug()),
        }
    }
}

/// A wire threat class as its `t`-tag slug.
///
/// `custom` for a custom class — `APPENDIX-NORMATIVE.md` §3's ruling, and the
/// only one of the three in-tree conventions that keeps an operator-supplied
/// string out of an indexed tag. The class name travels in the body instead.
#[must_use]
pub fn threat_class_slug(class: &WireThreatClass) -> &'static str {
    match class {
        WireThreatClass::LateralMovement => "lateral_movement",
        WireThreatClass::DataExfiltration => "data_exfiltration",
        WireThreatClass::PrivilegeEscalation => "privilege_escalation",
        WireThreatClass::CommandAndControl => "command_and_control",
        WireThreatClass::InitialAccess => "initial_access",
        WireThreatClass::Persistence => "persistence",
        WireThreatClass::SupplyChain => "supply_chain",
        WireThreatClass::DefenseEvasion => "defense_evasion",
        WireThreatClass::CredentialAccess => "credential_access",
        WireThreatClass::Discovery => "discovery",
        WireThreatClass::Execution => "execution",
        WireThreatClass::Impact => "impact",
        WireThreatClass::Custom(_) => "custom",
    }
}

wire_enum! {
    /// Severity, SCREAMING_SNAKE on the wire.
    ///
    /// The engine's `Severity` is the ONLY enum in its workspace with
    /// `rename_all = "SCREAMING_SNAKE_CASE"`; roughly forty siblings are
    /// snake_case, so any codegen that lowercases uniformly breaks exactly this
    /// field. It is also the value of the `l` tag.
    WireSeverity, "SCREAMING_SNAKE_CASE" {
        Low => "LOW",
        Medium => "MEDIUM",
        High => "HIGH",
        Critical => "CRITICAL",
    }
}

/// A wire severity as its `l`-tag label.
#[must_use]
pub fn severity_label(severity: WireSeverity) -> &'static str {
    severity.as_str()
}

wire_enum! {
    /// The eight swarm agent roles (`common.schema.json#/$defs/AgentRole`).
    ///
    /// A closed enum of SWARM agents with no human member. `tom` is
    /// "Governance — enforces policy, manages lifecycle": the VETO actor, and
    /// never a fact issuer for a human decision — see
    /// [`crate::envelope::OperatorFactIssuer`].
    WireAgentRole, "snake_case" {
        Whisker => "whisker",
        Stalker => "stalker",
        Weaver => "weaver",
        Pouncer => "pouncer",
        Tom => "tom",
        Kitten => "kitten",
        Sphinx => "sphinx",
        Calico => "calico",
    }
}

wire_enum! {
    /// Agent liveness (`common.schema.json#/$defs/AgentHealth`).
    WireAgentHealth, "snake_case" {
        Healthy => "healthy",
        Degraded => "degraded",
        Failed => "failed",
    }
}

wire_enum! {
    /// The swarm mode (`common.schema.json#/$defs/SwarmMode`).
    ///
    /// NOT MONOTONIC: the engine's `transition_down` exists beside
    /// `transition_to`, so every surface must render de-escalation.
    WireSwarmMode, "snake_case" {
        Normal => "normal",
        Alert => "alert",
        Incident => "incident",
    }
}

wire_enum! {
    /// A policy verdict (`common.schema.json#/$defs/PolicyVerdict`).
    ///
    /// `require_human` is the only verdict a hold can carry.
    WirePolicyVerdict, "snake_case" {
        Deny => "deny",
        Allow => "allow",
        RequireHuman => "require_human",
    }
}

wire_enum! {
    /// Whether a response adapter acted or simulated
    /// (`common.schema.json#/$defs/ExecutionMode`).
    WireExecutionMode, "snake_case" {
        DryRun => "dry_run",
        Enforced => "enforced",
    }
}

wire_enum! {
    /// Normalized response status (`common.schema.json#/$defs/ResponseStatus`).
    WireResponseStatus, "snake_case" {
        Simulated => "simulated",
        Executed => "executed",
        Timeout => "timeout",
        Failed => "failed",
    }
}

wire_enum! {
    /// `ResponseAction::kind()` (`common.schema.json#/$defs/ResponseActionKind`).
    ///
    /// Fifteen values. Twelve are destructive and human-gated; of those twelve
    /// only FOUR are containment actions and therefore ever mint a containment
    /// lease; of those four only THREE have an executable inverse. 12 → 4 → 3.
    WireResponseActionKind, "snake_case" {
        BlockEgress => "block_egress",
        IsolateHost => "isolate_host",
        RevokeCredential => "revoke_credential",
        SinkholeDns => "sinkhole_dns",
        TerminateUserSession => "terminate_user_session",
        TriggerEdrScan => "trigger_edr_scan",
        InjectFirewallRule => "inject_firewall_rule",
        QuarantineFile => "quarantine_file",
        KillProcess => "kill_process",
        SuspendProcess => "suspend_process",
        DisableUserAccount => "disable_user_account",
        ForcePasswordReset => "force_password_reset",
        RemoveScheduledTask => "remove_scheduled_task",
        DeployDecoy => "deploy_decoy",
        Escalate => "escalate",
    }
}

impl WireResponseActionKind {
    /// The four kinds that mint a containment lease
    /// (`common.schema.json#/$defs/ContainmentActionKind`). A hold card for
    /// any other kind renders NO pending containment-lease slot.
    pub const CONTAINMENT: [Self; 4] = [
        Self::QuarantineFile,
        Self::SuspendProcess,
        Self::IsolateHost,
        Self::TerminateUserSession,
    ];

    /// Whether this kind mints a containment lease.
    #[must_use]
    pub fn leases_a_containment(self) -> bool {
        Self::CONTAINMENT.contains(&self)
    }
}

wire_enum! {
    /// What a rehearsal's blast radius is scoped to
    /// (`common.schema.json#/$defs/ResponseRehearsalScopeKind`).
    WireRehearsalScopeKind, "snake_case" {
        NetworkTarget => "network_target",
        Host => "host",
        Credential => "credential",
        UserSession => "user_session",
        File => "file",
        Process => "process",
        UserAccount => "user_account",
        ScheduledTask => "scheduled_task",
        Zone => "zone",
        OperatorQueue => "operator_queue",
    }
}

wire_enum! {
    /// One impact per response action
    /// (`common.schema.json#/$defs/ResponseBlastRadiusImpact`).
    WireBlastRadiusImpact, "snake_case" {
        NetworkEgressBlocked => "network_egress_blocked",
        HostConnectivityIsolated => "host_connectivity_isolated",
        CredentialAccessRevoked => "credential_access_revoked",
        DnsResolutionSinkholed => "dns_resolution_sinkholed",
        UserSessionTerminated => "user_session_terminated",
        HostScanTriggered => "host_scan_triggered",
        HostFirewallPolicyChanged => "host_firewall_policy_changed",
        FileQuarantined => "file_quarantined",
        ProcessTerminated => "process_terminated",
        ProcessSuspended => "process_suspended",
        UserAccountDisabled => "user_account_disabled",
        PasswordResetEnforced => "password_reset_enforced",
        ScheduledTaskRemoved => "scheduled_task_removed",
        DeceptionCoverageChanged => "deception_coverage_changed",
        OperatorEscalationOnly => "operator_escalation_only",
    }
}

wire_enum! {
    /// One inverse step per response action
    /// (`common.schema.json#/$defs/ResponseRollbackStepKind`).
    WireRollbackStepKind, "snake_case" {
        RemoveNetworkBlock => "remove_network_block",
        RestoreHostConnectivity => "restore_host_connectivity",
        RestoreCredential => "restore_credential",
        RemoveDnsSinkhole => "remove_dns_sinkhole",
        ReauthenticateUserSession => "reauthenticate_user_session",
        CancelHostScan => "cancel_host_scan",
        RemoveFirewallRule => "remove_firewall_rule",
        ReleaseQuarantinedFile => "release_quarantined_file",
        RestartProcess => "restart_process",
        ResumeProcess => "resume_process",
        ReenableUserAccount => "reenable_user_account",
        ClearPasswordResetRequirement => "clear_password_reset_requirement",
        RestoreScheduledTask => "restore_scheduled_task",
        WithdrawDecoy => "withdraw_decoy",
        CloseEscalation => "close_escalation",
    }
}

wire_enum! {
    /// Terminal state of one inverse step
    /// (`common.schema.json#/$defs/RollbackStepStatus`). Exactly five.
    ///
    /// Only `reversed` restored anything: a simulated step touched no target
    /// and an irreversible step never will, which is why a rollback's human
    /// line counts `k of n steps reversed` rather than "nothing errored".
    WireRollbackStepStatus, "snake_case" {
        Reversed => "reversed",
        Simulated => "simulated",
        Irreversible => "irreversible",
        Unsupported => "unsupported",
        Failed => "failed",
    }
}

impl WireRollbackStepStatus {
    /// Whether this step actually restored the pre-containment state.
    #[must_use]
    pub const fn restored(self) -> bool {
        matches!(self, Self::Reversed)
    }
}

wire_enum! {
    /// Why a rollback ran (`common.schema.json#/$defs/RollbackTrigger`).
    ///
    /// `manual` is an operator releasing early; `expiry` is the TTL sweep,
    /// which has no HTTP request and therefore no `release_response`.
    WireRollbackTrigger, "snake_case" {
        Manual => "manual",
        Expiry => "expiry",
    }
}

wire_enum! {
    /// Where the governance quorum sits on the partition/heal path
    /// (`common.schema.json#/$defs/PartitionState`). Exactly four.
    WirePartitionState, "snake_case" {
        Healthy => "healthy",
        Degraded => "degraded",
        Partitioned => "partitioned",
        Healing => "healing",
    }
}

// ═══════════════════════════════════════════════════ structural wire types

/// Detached Ed25519 signature metadata
/// (`common.schema.json#/$defs/DetachedSignature`).
///
/// This is the Ed25519 chain, NOT the secp256k1 Schnorr signature the relay
/// verified over the transport event; a surface that renders either must name
/// which chain it checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDetachedSignature {
    /// The algorithm name, `ed25519` today.
    pub algorithm: String,
    /// Which key signed.
    pub key_id: String,
    /// The signer's public key, hex.
    pub public_key_hex: String,
    /// The signature, hex.
    pub signature_hex: String,
}

/// The outcome of evaluating a live response request
/// (`common.schema.json#/$defs/PolicyDecision`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePolicyDecision {
    /// The verdict.
    pub verdict: WirePolicyVerdict,
    /// Stable rule identifier responsible for the final verdict.
    pub rule_name: String,
    /// Human-readable explanation for audit logs and operators.
    pub reason: String,
}

/// A short-lived authorization lease attached to a live response request
/// (`common.schema.json#/$defs/CapabilityLease`).
///
/// Its `expires_at_ms` is the CAPABILITY lease's authorization window
/// (`policy.lease_ttl_ms`, 60 seconds by default). It is NOT the countdown an
/// operator watches on a containment lease, whose default TTL is 900 seconds;
/// rendering one beside the other is wrong by 15x.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCapabilityLease {
    /// Opaque capability identifier.
    pub capability_id: String,
    /// Expiration time for the lease in unix milliseconds.
    pub expires_at_ms: i64,
    /// Response action authorized by the lease.
    pub action: String,
    /// Optional target scope, such as a host or network segment.
    pub scope: Option<String>,
}

/// A response action, INTERNALLY tagged on `type`
/// (`common.schema.json#/$defs/ResponseAction`).
///
/// `{"type":"isolate_host","host_id":"web-04"}`, never
/// `{"isolate_host":{...}}`. The variant payload sits beside the tag, which is
/// why this type is open rather than fifteen shapes: Perch is a reader of the
/// action and never an author, and the schema itself is `additionalProperties:
/// true`. The payload fields are carried verbatim in `fields`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireResponseAction {
    /// The action kind. The `type` key on the wire.
    #[serde(rename = "type")]
    pub kind: WireResponseActionKind,
    /// The variant's own fields, beside the tag.
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

/// Render law 1's BLAST RADIUS slot
/// (`common.schema.json#/$defs/ResponseBlastRadiusPreview`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireBlastRadiusPreview {
    /// What the scope value names.
    pub scope_kind: WireRehearsalScopeKind,
    /// The scope itself: a host, a credential, a zone.
    pub scope_value: String,
    /// One of fifteen, one per action.
    pub impact: WireBlastRadiusImpact,
    /// Upper bound on scopes affected.
    pub max_affected_scopes: usize,
    /// Capabilities the action removes.
    pub affected_capabilities: Vec<String>,
    /// One sentence.
    pub summary: String,
}

/// One planned inverse step (`common.schema.json#/$defs/ResponseRollbackStep`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRollbackStep {
    /// The inverse.
    pub kind: WireRollbackStepKind,
    /// One sentence.
    pub summary: String,
}

/// Render law 1's IF YOU UNDO slot
/// (`common.schema.json#/$defs/ResponseRollbackPreview`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRollbackPreview {
    /// Whether undoing is required at all.
    pub required: bool,
    /// One sentence.
    pub summary: String,
    /// The steps, in order.
    pub steps: Vec<WireRollbackStep>,
}

/// A rehearsal preview (`common.schema.json#/$defs/ResponseRehearsalPreview`).
///
/// `simulated_only` is hardcoded `true` on every preview the daemon builds; the
/// schema pins it as a `const` and the console must refuse a card claiming a
/// rehearsal that ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRehearsalPreview {
    /// The rehearsal.
    pub rehearsal_id: String,
    /// The replay bundle it was prepared from.
    pub source_bundle_id: String,
    /// When it was prepared.
    pub prepared_at_ms: i64,
    /// Always `true`.
    pub simulated_only: bool,
    /// Render law 1's BLAST RADIUS.
    pub blast_radius: WireBlastRadiusPreview,
    /// Render law 1's IF YOU UNDO.
    pub rollback: WireRollbackPreview,
}

/// A response request as the detection runtime emitted it
/// (`card-swarm-hold-v1.schema.json` `hold.action_request`).
///
/// `severity` and the threat class inside `evidence` are set by the REQUESTING
/// AGENT and read back by the configurable gate's selector, so an agent
/// influences which rule judges its own destructive action. The WHY WE ARE
/// ASKING slot must mark both request-carried.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireActionRequest {
    /// Investigation or correlation context.
    pub hunt_id: String,
    /// An Ambush agent id. NOT a Nostr pubkey, and there is no mapping to one.
    pub requested_by: String,
    /// The action to authorize.
    pub action: WireResponseAction,
    /// REQUEST-CARRIED severity.
    pub severity: WireSeverity,
    /// Evidence bundle carried with the request. Adversary-shaped.
    pub evidence: Value,
}

/// `SwarmFindingEnvelope` on the wire
/// (`card-swarm-finding-v1.schema.json` `finding`): eight fields, unsigned,
/// with `schema` hardcoded to `swarm_finding` by the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireFindingEnvelope {
    /// Always `swarm_finding`.
    pub schema: String,
    /// The finding.
    pub finding_id: String,
    /// The TELEMETRY event id.
    pub event_id: String,
    /// The detector that produced it.
    pub strategy_id: String,
    /// The class.
    pub threat_class: WireThreatClass,
    /// The severity.
    pub severity: WireSeverity,
    /// `0.0..=1.0`.
    pub confidence: f64,
    /// Unconstrained, DERIVED FROM TELEMETRY AN ADVERSARY CAN SHAPE. Every
    /// string reached from here must render through the adversary-string
    /// wrapper (INV-14).
    pub evidence: Value,
}

/// `DetectionFinding` on the wire (`card-swarm-receipt-v1.schema.json`
/// `audit_trail.detection`): seven fields, no schema constant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireDetectionFinding {
    /// The finding.
    pub finding_id: String,
    /// The TELEMETRY event id.
    pub event_id: String,
    /// The class.
    pub threat_class: WireThreatClass,
    /// The severity.
    pub severity: WireSeverity,
    /// `0.0..=1.0`.
    pub confidence: f64,
    /// Adversary-shaped. INV-14 applies.
    pub evidence: Value,
    /// The detector that produced it.
    pub strategy_id: String,
}

/// The policy step captured in an audit trail
/// (`card-swarm-receipt-v1.schema.json` `audit_trail.policy`).
///
/// A DIFFERENT type from [`WirePolicyDecision`]: it carries one more field,
/// the capability lease the gate minted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePolicyRecord {
    /// The verdict.
    pub verdict: WirePolicyVerdict,
    /// Stable rule identifier responsible for the final verdict.
    pub rule_name: String,
    /// Human-readable explanation.
    pub reason: String,
    /// The capability lease, when the gate minted one.
    #[serde(default)]
    pub lease: Option<WireCapabilityLease>,
}

/// Policy attribution captured on a successful response receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireResponsePolicyAudit {
    /// The verdict.
    pub verdict: WirePolicyVerdict,
    /// The rule.
    pub rule_name: String,
    /// The reason.
    pub reason: String,
}

/// Governance attribution captured on response receipts and synthetic veto
/// receipts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireResponseGovernanceAudit {
    /// The governing agent id.
    pub governing_agent_id: String,
    /// The reason.
    pub reason: String,
    /// A serialized governance receipt, when one was attached. Opaque here;
    /// it is the one nested object on a receipt card that can be tier 1, and
    /// the badge scopes to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<Value>,
}

/// Runtime-owned audit metadata layered on top of adapter output.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WireResponseReceiptAudit {
    /// Policy attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<WireResponsePolicyAudit>,
    /// Governance attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<WireResponseGovernanceAudit>,
}

/// A receipt emitted by a response adapter: the seven fields that sit beside
/// the `kind: success` tag of [`WireAuditResponseRecord`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireResponseReceipt {
    /// Stable receipt identifier for audit reconstruction.
    pub receipt_id: String,
    /// Stable action name for audit and replay.
    pub action: String,
    /// Whether the adapter simulated or executed the action.
    pub mode: WireExecutionMode,
    /// Normalized result status.
    pub status: WireResponseStatus,
    /// Human-readable outcome summary.
    pub summary: String,
    /// Adapter-specific evidence, status, or metadata.
    pub details: Value,
    /// Runtime-owned audit metadata.
    #[serde(default)]
    pub audit: WireResponseReceiptAudit,
}

/// A normalized failure record: the fields beside the `kind: failure` tag of
/// [`WireAuditResponseRecord`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireResponseFailure {
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Stable action name.
    pub action: String,
    /// Whether the adapter simulated or executed the action.
    pub mode: WireExecutionMode,
    /// What went wrong.
    pub message: String,
    /// Adapter-specific detail.
    pub details: Value,
}

/// The response step captured in an audit trail
/// (`card-swarm-receipt-v1.schema.json` `audit_trail.response`).
///
/// `#[serde(tag = "kind")]` over four variants, two of them NEWTYPE variants
/// whose inner struct's fields sit BESIDE the tag: a success arm is
/// `{"kind":"success", ...the seven receipt fields}`, not
/// `{"kind":"success","0":{...}}` and not `{"success":{...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireAuditResponseRecord {
    /// The adapter produced a receipt.
    Success(WireResponseReceipt),
    /// The adapter failed.
    Failure(WireResponseFailure),
    /// No response was attempted.
    Skipped {
        /// Why.
        reason: String,
    },
    /// A guard refused the response before it ran.
    GuardRejected {
        /// The guard.
        guard_name: String,
        /// Why.
        reason: String,
    },
}

impl WireAuditResponseRecord {
    /// The wire spelling of the `kind` tag.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Success(_) => "success",
            Self::Failure(_) => "failure",
            Self::Skipped { .. } => "skipped",
            Self::GuardRejected { .. } => "guard_rejected",
        }
    }

    /// The response receipt id, `Some` for the `success` and `failure` arms.
    #[must_use]
    pub fn receipt_id(&self) -> Option<&str> {
        match self {
            Self::Success(receipt) => Some(receipt.receipt_id.as_str()),
            Self::Failure(failure) => Some(failure.receipt_id.as_str()),
            Self::Skipped { .. } | Self::GuardRejected { .. } => None,
        }
    }
}

/// The auditable trail for one handled event
/// (`card-swarm-receipt-v1.schema.json` `audit_trail`): seven fields, unsigned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireAuditTrail {
    /// The trail.
    pub trail_id: String,
    /// The hunt.
    pub hunt_id: String,
    /// Other receipts this trail relates to.
    pub related_receipt_ids: Vec<String>,
    /// The detection that started it.
    pub detection: WireDetectionFinding,
    /// The policy step.
    pub policy: WirePolicyRecord,
    /// The response step.
    pub response: WireAuditResponseRecord,
    /// When the trail was written.
    pub created_at_ms: i64,
}

/// A containment lease as persisted
/// (`card-swarm-lease-v1.schema.json` `lease`): the engine's private
/// `ContainmentLeaseRecord`, NOT its `ContainmentLeaseView`.
///
/// `remaining_ms` and `expired` are not here. They are computed against an
/// observation instant and a card is immutable; the console recomputes both
/// from `expires_at_ms` and renders them as two separate elements (INV-06).
/// `deny_unknown_fields` mirrors the engine's record: a stored lease with a
/// field the reader does not know is a parse error, not a lease that silently
/// means something else.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireContainmentLease {
    /// The record's schema version.
    pub schema_version: u32,
    /// The lease.
    pub lease_id: String,
    /// The TYPED action, not its name: the concrete host, file, process or
    /// session an inverse has to act on can only come from the action itself.
    pub action: WireResponseAction,
    /// The response receipt that made the containment.
    pub origin_receipt_id: String,
    /// The governance receipt that authorized it, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_receipt_id: Option<String>,
    /// What the containment touched.
    pub blast_radius: WireBlastRadiusPreview,
    /// The plan that undoes it.
    pub rollback: WireRollbackPreview,
    /// When it was issued.
    pub issued_at_ms: i64,
    /// When it lapses. Mandatory at the wire: a lease with no expiry is a parse
    /// error, not a lease that expires at the epoch.
    pub expires_at_ms: i64,
}

/// Outcome of one inverse step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRollbackStepOutcome {
    /// The inverse that ran.
    pub kind: WireRollbackStepKind,
    /// What happened.
    pub status: WireRollbackStepStatus,
    /// One line of detail.
    pub detail: String,
}

/// A receipt proving what a rollback did, chained to the receipt that made the
/// containment (`card-swarm-rollback-v1.schema.json` `rollback_receipt`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireRollbackReceipt {
    /// The rollback.
    pub rollback_id: String,
    /// The lease it closed.
    pub lease_id: String,
    /// Chain link back to the containment receipt this undoes.
    pub origin_receipt_id: String,
    /// Chain link back to the GOVERNANCE receipt that authorized the
    /// containment, carried from the lease. `None` when the lease was minted
    /// outside a governed path.
    #[serde(default)]
    pub governance_receipt_id: Option<String>,
    /// Why it ran.
    pub trigger: WireRollbackTrigger,
    /// Acted or simulated.
    pub mode: WireExecutionMode,
    /// Overall status.
    pub status: WireResponseStatus,
    /// Per-step outcomes.
    pub steps: Vec<WireRollbackStepOutcome>,
    /// When it finished.
    pub completed_at_ms: i64,
    /// One line.
    pub summary: String,
    /// The governance attestation over this receipt, if one was produced.
    /// OPAQUE: only the runtime's `verify_release_attestation` may decide
    /// whether it is valid, and `None` means UNATTESTED, never "fine".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_attestation: Option<Value>,
}

impl WireRollbackReceipt {
    /// How many steps actually restored the pre-containment state.
    #[must_use]
    pub fn reversed_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|step| step.status.restored())
            .count()
    }

    /// Whether every step restored state. DELIBERATELY STRICTER than "nothing
    /// errored": a simulated step restored nothing and an irreversible step
    /// never will.
    #[must_use]
    pub fn fully_reversed(&self) -> bool {
        !self.steps.is_empty() && self.reversed_steps() == self.steps.len()
    }
}

// ═══════════════════════════════════════════════════════════════ the cards

/// One of the seven card bodies, tagged by its own `schema` field.
///
/// `#[serde(tag = "schema")]` is internal tagging on a field every variant
/// already carries, so the wire form is exactly what the JSON Schemas describe
/// and there is no extra nesting level.
///
/// Every variant is boxed: a hold card is over a kilobyte while a finding is a
/// fraction of that, and a `Card` is built once per event at admission, so the
/// one allocation buys a uniform, small enum rather than one sized for its
/// largest member. Serde is transparent over `Box`, so the wire form is
/// unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "schema")]
pub enum Card {
    /// `swarm:finding:v1`
    #[serde(rename = "swarm.perch.finding.v1")]
    Finding(Box<FindingCard>),
    /// `swarm:escalation:v1`
    #[serde(rename = "swarm.perch.escalation.v1")]
    Escalation(Box<EscalationCard>),
    /// `swarm:hold:v1`
    #[serde(rename = "swarm.perch.hold.v1")]
    Hold(Box<HoldCard>),
    /// `swarm:verdict:v1`
    #[serde(rename = "swarm.perch.verdict.v1")]
    Verdict(Box<VerdictCard>),
    /// `swarm:receipt:v1`
    #[serde(rename = "swarm.perch.receipt.v1")]
    Receipt(Box<ReceiptCard>),
    /// `swarm:lease:v1`
    #[serde(rename = "swarm.perch.lease.v1")]
    Lease(Box<LeaseCard>),
    /// `swarm:rollback:v1`
    #[serde(rename = "swarm.perch.rollback.v1")]
    Rollback(Box<RollbackCard>),
}

impl Card {
    /// Which marker this card must ship under.
    #[must_use]
    pub const fn kind(&self) -> CardKind {
        match self {
            Self::Finding(_) => CardKind::Finding,
            Self::Escalation(_) => CardKind::Escalation,
            Self::Hold(_) => CardKind::Hold,
            Self::Verdict(_) => CardKind::Verdict,
            Self::Receipt(_) => CardKind::Receipt,
            Self::Lease(_) => CardKind::Lease,
            Self::Rollback(_) => CardKind::Rollback,
        }
    }

    /// The domain instant: THE SORT KEY for every Perch surface.
    #[must_use]
    pub const fn emitted_at_ms(&self) -> i64 {
        match self {
            Self::Finding(c) => c.emitted_at_ms,
            Self::Escalation(c) => c.emitted_at_ms,
            Self::Hold(c) => c.emitted_at_ms,
            Self::Verdict(c) => c.emitted_at_ms,
            Self::Receipt(c) => c.emitted_at_ms,
            Self::Lease(c) => c.emitted_at_ms,
            Self::Rollback(c) => c.emitted_at_ms,
        }
    }

    /// The one-line human fallback. THE DEGRADATION CONTRACT.
    ///
    /// This string is what the Flutter app renders, what an FTS snippet shows,
    /// and what `ambush --format compact messages thread` returns — that command
    /// projects an event to exactly `{id, content, created_at}` and drops `kind`,
    /// `pubkey` and `tags`. So it must name the identifiers a human needs to go
    /// find the real thing, on its own, with no tags and no kind.
    ///
    /// The seven grammars are `13-WIRE-SCHEMAS.md` §7.1. Voice law L5: every
    /// number carries its denominator and its unit. Appendix §7:
    /// `SCREAMING_SNAKE` only for a severity or a level, `lower_snake_case` for
    /// anything that is a literal action kind or wire field.
    #[must_use]
    pub fn human_line(&self) -> String {
        match self {
            Self::Finding(c) => c.human_line(),
            Self::Escalation(c) => c.human_line(),
            Self::Hold(c) => c.human_line(),
            Self::Verdict(c) => c.human_line(),
            Self::Receipt(c) => c.human_line(),
            Self::Lease(c) => c.human_line(),
            Self::Rollback(c) => c.human_line(),
        }
    }
}

/// Separator between fields of a human fallback line: U+00B7 with a space either
/// side. Not a hyphen — a hyphen is a lexeme boundary in Postgres's `simple`
/// text-search configuration, so `web-04` would already contribute `web` and
/// `04` and a hyphen separator makes an FTS query for a field value ambiguous.
pub const HUMAN_SEP: &str = " · ";

/// A unix-millisecond instant as RFC 3339 at second precision with a `Z`
/// suffix — the same spelling the envelope's `issued_at` uses. An instant chrono
/// cannot represent falls back to the raw millisecond count with its unit, so
/// the line still says what it knows.
fn iso_seconds(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("{ms}ms"))
}

/// The `M agents` half of render law 2, derived from strategy-scoped ids by
/// dropping the last `:`-segment of each and counting the distinct remainder.
/// Correct ONLY under [`SourceCountMechanism::StrategyScopedAgentId`], which is
/// why the mechanism travels on the wire beside the ids.
fn agents_of(source_ids: &[String]) -> usize {
    source_ids
        .iter()
        .map(|id| id.rsplit_once(':').map_or(id.as_str(), |(head, _)| head))
        .collect::<BTreeSet<_>>()
        .len()
}

// ───────────────────────────────────────────────────────────── finding

/// `swarm:finding:v1` — one detection finding, in a lane channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingCard {
    /// Who produced it.
    pub issuer: FactIssuer,
    /// `RuntimeEvent::Finding.emitted_at_ms` unchanged.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: FindingLocator,
    /// The finding envelope, field for field: eight fields, unsigned, with
    /// `schema` hardcoded to `swarm_finding` by the engine.
    pub finding: WireFindingEnvelope,
    /// Present only when the bridge replaced `finding.evidence`.
    ///
    /// NARROWING, conditional. The evidence is built from telemetry an
    /// adversary can shape, and it is the only unbounded field in the whole
    /// registry. When the serialized card would exceed
    /// `CARD_CONTENT_MAX_BYTES` the bridge replaces it with a byte count and a
    /// hash, so the card renders an explicit absence rather than a silently
    /// smaller evidence blob. At the CARD level, not inside `finding`: the
    /// envelope is carried by type and cannot grow a field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_truncated: Option<EvidenceTruncated>,
    /// Loss observed before this card. Absent on a normal card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap: Option<GapBlock>,
}

/// Join keys for a finding card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingLocator {
    /// `DetectionFinding.finding_id`.
    pub finding_id: String,
    /// The TELEMETRY event id. Half of the feedback-suppression key
    /// `FeedbackSuppressionKey{threat_class, event_id}`, which the substrate
    /// applies to drop every matching deposit at or before a Dismiss marker —
    /// reaching detectors the operator never reviewed. Carried in the locator,
    /// not only in `finding`, because the Dismiss preview arithmetic needs it
    /// without parsing the envelope.
    pub event_id: String,
    /// `DetectionFinding.strategy_id`.
    pub strategy_id: String,
    /// From the `RuntimeEvent::Finding` WRAPPER, not from the envelope: the
    /// finding envelope has eight fields and none of them is a host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    /// The lane channel this was published into.
    pub lane_channel: String,
}

/// Replacement for an oversized evidence blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceTruncated {
    /// Serialized size of the omitted value.
    pub bytes: usize,
    /// `0x`-prefixed sha256 of its canonical form.
    pub sha256: String,
}

/// Loss the bridge observed before this card, carried inside the same signed
/// envelope so it cannot be lost independently of the card (11-BRIDGE-CRATE §3.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapBlock {
    /// Why content is missing.
    pub cause: GapBlockCause,
    /// Present for `broadcast_lagged` only: the bridge never saw the events and has no seq for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// Present for the three spool causes: an exact `seq` range, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_seq: Option<u64>,
    /// The inclusive end of that range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_seq: Option<u64>,
    /// When the bridge first recorded the loss, daemon clock.
    pub noticed_at_ms: i64,
}

/// Exactly four causes. A coalesce is not a gap and never appears here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapBlockCause {
    /// The daemon's broadcast channel lagged and the bridge never saw the events.
    BroadcastLagged,
    /// The spool evicted a segment before it drained.
    SpoolEvicted,
    /// A spool segment ended in a torn record.
    SpoolTornTail,
    /// A spooled card aged past the relay's timestamp window before it published.
    PublishWindowExpired,
}

impl GapBlockCause {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BroadcastLagged => "broadcast_lagged",
            Self::SpoolEvicted => "spool_evicted",
            Self::SpoolTornTail => "spool_torn_tail",
            Self::PublishWindowExpired => "publish_window_expired",
        }
    }
}

impl FindingCard {
    /// `{Agent}-{short} · {threat_class} · {SEVERITY} · confidence {0.00} · host {host_id|unknown} · finding {finding_id}`
    ///
    /// The confidence carries two decimals AND the word, because a bare 0.82
    /// beside a bare 2.41 is two different quantities that read the same.
    #[must_use]
    pub fn human_line(&self) -> String {
        [
            self.issuer.swarm_agent_id.clone(),
            threat_class_slug(&self.finding.threat_class).to_string(),
            severity_label(self.finding.severity).to_string(),
            format!("confidence {:.2}", self.finding.confidence),
            format!(
                "host {}",
                self.locator.host_id.as_deref().unwrap_or("unknown")
            ),
            format!("finding {}", self.locator.finding_id),
        ]
        .join(HUMAN_SEP)
    }
}

// ────────────────────────────────────────────────────────── escalation

/// `swarm:escalation:v1` — one of three daemon events, in a lane channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationCard {
    /// Who produced it.
    pub issuer: FactIssuer,
    /// The source event's `emitted_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: EscalationLocator,
    /// Which of the three, and its payload.
    pub escalation: EscalationBody,
}

/// Join keys for an escalation card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationLocator {
    /// The lane channel.
    pub lane_channel: String,
    /// Set when this escalation promoted a case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_channel: Option<String>,
}

/// Which daemon event this escalation card carries.
///
/// APPENDIX-NORMATIVE §3 collapses three `RuntimeEvent` variants onto one
/// marker. They are kept separable here so a renderer never guesses which shape
/// it holds, and so an exhaustive `match` fails to compile if a fourth is added.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum EscalationBody {
    /// `RuntimeEvent::Escalation`.
    ConcentrationCrossing(ConcentrationCrossing),
    /// `RuntimeEvent::ModeTransition`, published only for a transition INTO
    /// `incident`. Every direction reaches the ephemeral `26003`; only this one
    /// earns a durable card, because a de-escalation is not evidence about an
    /// attack.
    ModeTransition(ModeTransitionBody),
    /// `RuntimeEvent::TamperAlert`, published only when `fail_closed` is true.
    TamperFailClosed(TamperFailClosed),
}

/// A concentration crossing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConcentrationCrossing {
    /// The class that crossed.
    pub threat_class: WireThreatClass,
    /// `alert` or `incident`.
    pub level: EscalationLevel,
    /// Post-evaporation, post-suppression sum at the crossing instant.
    pub total_strength: f64,
    /// **Never render this bare.** See `distinct_sources_counts` for the unit
    /// and `source_ids_absent_reason` for why the other half of render law 2 is
    /// not derivable in Phase 1.
    pub distinct_sources: usize,
    /// The counting unit, carried so no surface has to assume it.
    pub distinct_sources_counts: SourceCountMechanism,
    /// The strategy-scoped ids themselves, or `None` with a NAMED reason.
    ///
    /// `None` on every Phase-1 card. The absence is carried as a named state in
    /// `source_ids_absent_reason` rather than left as a bare `None`, because
    /// render law 2's `M agents` half has no other source: `RuntimeEvent::Escalation`
    /// carries `distinct_sources: usize` and nothing else, and the bridge takes
    /// a `broadcast::Receiver` with no substrate handle. Only **B4** can serve
    /// them, and B4 is Phase 2.
    ///
    /// When B4 lands, a consumer derives the agent half by dropping the last
    /// colon-separated segment of each id and counting the distinct remainder —
    /// a derivation that is correct ONLY under the strategy-scoped mechanism,
    /// which is why the mechanism travels beside the ids.
    #[serde(default)]
    pub source_ids: Option<Vec<String>>,
    /// Why `source_ids` is `None`. Exactly one of this and `source_ids` is
    /// `Some`; [`ConcentrationCrossing::assert_source_shape`] checks it.
    pub source_ids_absent_reason: Option<SourceIdsAbsentReason>,
    /// Highest deposit confidence in the sum.
    pub peak_confidence: f64,
    /// Whether this crossing moved the swarm mode.
    pub mode_changed: bool,
    /// Mode after the crossing.
    pub current_mode: WireSwarmMode,
    /// `{threat_class_slug}:{level}:{unix_seconds}`.
    ///
    /// The monitor is LEVEL-triggered at 10 Hz and its evaluation is a pure
    /// level comparison with no memory, so it re-emits on every tick while over
    /// threshold — up to 120 events/second for twelve classes, against a
    /// 120/min per-pubkey relay quota. Its `now` is unix seconds, so all ten
    /// ticks in a second are byte-identical and this key dedupes them for
    /// free. The bridge then EDGE-TRIGGERS on a level change. Both steps are
    /// mandatory.
    pub dedupe_key: String,
}

impl ConcentrationCrossing {
    /// `Ok(())` iff exactly one of `source_ids` and `source_ids_absent_reason`
    /// is present. Both-absent is an unnamed absence a component would
    /// improvise around; both-present is a claim with no reason to exist.
    pub fn assert_source_shape(&self) -> Result<(), &'static str> {
        match (
            self.source_ids.is_some(),
            self.source_ids_absent_reason.is_some(),
        ) {
            (true, false) | (false, true) => Ok(()),
            (false, false) => Err("escalation.source_ids is null with no source_ids_absent_reason"),
            (true, true) => {
                Err("escalation.source_ids is present beside a source_ids_absent_reason")
            }
        }
    }
}

/// What `distinct_sources` counts: the STRATEGY-SCOPED agent id.
///
/// Deliberately ONE variant. A closed single-variant enum makes the wrong
/// mechanism unrepresentable rather than merely undocumented, and a second
/// counting unit would be a wire change with its own argument, not a value a
/// producer picks.
///
/// THE PRODUCTION PATH, hop by hop, all inside `swarm_detect --serve`: the
/// Whisker builds an instance-scoped base id (`{derived_identity}:{agent_id}`),
/// the deposit resolver appends `:{strategy_id}` to every deposit's agent id,
/// and the concentration query counts those strings. So one Whisker running two
/// detectors is TWO sources / ONE agent, and clears
/// `min_sources_for_escalation: 2` on its own.
///
/// CONSEQUENCE FOR COPY: `APPENDIX-NORMATIVE.md` §8 render law 2 stands exactly
/// as written. `N sources / M agents` is two genuinely different numbers and the
/// expansion does not collapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCountMechanism {
    /// `{derived_identity}:{agent_id}:{strategy_id}` — one id per (agent
    /// instance, detector) pair.
    StrategyScopedAgentId,
}

/// Why `source_ids` is absent, as a value rather than an implication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceIdsAbsentReason {
    /// `RuntimeEvent::Escalation` carries a count and no ids, and the bridge
    /// holds no substrate handle with which to resolve them. Only B4
    /// (`GET /v1/operator/pheromone/deposits`, Phase 2) can serve them.
    ///
    /// A component renders THIS REASON. It never renders a fabricated agent
    /// count and it never renders a spinner: nothing is loading.
    NotCarriedByRuntimeEvent,
}

/// A transition into `incident`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeTransitionBody {
    /// Mode before.
    pub from: WireSwarmMode,
    /// Always `incident` on a durable card.
    pub to: WireSwarmMode,
    /// `None` on a de-escalation, because the engine clears it on the way down;
    /// always `Some` here, because a transition up requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggering_threat_class: Option<WireThreatClass>,
    /// The runtime's own reason string.
    pub reason: String,
}

/// A fail-closed tamper alert.
///
/// UNLIKE the `26005` frame, this DURABLE card carries the paths and the detail
/// string. The aggregates-only rule is scoped to the community-global ephemeral
/// block; a lane channel is membership-gated, and an operator investigating a
/// tamper alert needs the library paths. The frame carries only a count and a
/// hash so two alarms can be compared for identity without disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperFailClosed {
    /// `RuntimeEvent::TamperAlert.debugger_attached`.
    pub debugger_attached: bool,
    /// `RuntimeEvent::TamperAlert.tracer_pid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracer_pid: Option<u32>,
    /// `unexpected_library_loads.len()`.
    pub unexpected_library_count: usize,
    /// `0x`-prefixed sha256 over the newline-joined, lexicographically sorted
    /// path list. Present on BOTH the card and the frame, so the two can be
    /// joined without the frame carrying paths.
    pub unexpected_library_sha256: String,
    /// The paths themselves. Card only, never on `26005`.
    pub unexpected_library_loads: Vec<String>,
    /// Always `true` on a durable card.
    pub fail_closed: bool,
    /// `RuntimeEvent::TamperAlert.details`. Card only.
    pub details: String,
}

impl EscalationCard {
    /// Three grammars, one per cause (`13-WIRE-SCHEMAS.md` §7.1):
    ///
    /// - crossing: `{threat_class} · {LEVEL} · strength {0.00} · {n} sources / {m} agents · mode {mode}`,
    ///   or `{n} sources / agents not yet resolved` while the ids are absent (§7.2.1);
    /// - mode: `mode {from} → incident · {triggering_threat_class|none} · {reason}`;
    /// - tamper: `tamper fail-closed · {n} unexpected library loads · debugger {attached|not attached}`.
    #[must_use]
    pub fn human_line(&self) -> String {
        match &self.escalation {
            EscalationBody::ConcentrationCrossing(crossing) => {
                let sources = match &crossing.source_ids {
                    Some(ids) => format!(
                        "{} sources / {} agents",
                        crossing.distinct_sources,
                        agents_of(ids)
                    ),
                    None => format!(
                        "{} sources / agents not yet resolved",
                        crossing.distinct_sources
                    ),
                };
                [
                    threat_class_slug(&crossing.threat_class).to_string(),
                    crossing.level.label().to_string(),
                    format!("strength {:.2}", crossing.total_strength),
                    sources,
                    format!("mode {}", crossing.current_mode.as_str()),
                ]
                .join(HUMAN_SEP)
            }
            EscalationBody::ModeTransition(transition) => [
                format!("mode {} → incident", transition.from.as_str()),
                transition
                    .triggering_threat_class
                    .as_ref()
                    .map_or("none", threat_class_slug)
                    .to_string(),
                transition.reason.clone(),
            ]
            .join(HUMAN_SEP),
            EscalationBody::TamperFailClosed(tamper) => [
                "tamper fail-closed".to_string(),
                format!(
                    "{} unexpected library loads",
                    tamper.unexpected_library_count
                ),
                if tamper.debugger_attached {
                    "debugger attached".to_string()
                } else {
                    "debugger not attached".to_string()
                },
            ]
            .join(HUMAN_SEP),
        }
    }
}

// ──────────────────────────────────────────────────────────────── hold

/// `swarm:hold:v1` — one held destructive action, in a case channel.
///
/// One hold produces two or more cards: an OPEN card (`state` in
/// `created|notified|armed|deciding`) and exactly one TERMINAL card (`state` in
/// `granted|refused|expired|executed|failed`) published as a NIP-10 reply to it.
/// The terminal card is the appendix's "also the expiry record". Both carry the
/// whole hold, because a card is immutable and a timeline must read top to
/// bottom without a join.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldCard {
    /// Who produced it — the requesting agent.
    pub issuer: FactIssuer,
    /// When the hold was created, or when it reached its terminal state.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: HoldLocator,
    /// The hold.
    pub hold: HeldAction,
}

/// Join keys for a hold card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldLocator {
    /// An OPAQUE RANDOM TOKEN, never `hold:{hunt_id}:{held_at_ms}`: `hunt_id` is
    /// the telemetry event id, a join key into detection data, and `hold_id`
    /// travels in a `26006` frame — the widest-audience object in the registry.
    /// The shape is pinned by `schemas/common.schema.json#/$defs/HoldId`
    /// (`^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`) and by [`crate::tags::HoldId`]:
    /// URL-safe because it is a path parameter on
    /// `POST /v1/response/holds/{hold_id}/decide`, and COLON-FREE so the
    /// forbidden derived form is unrepresentable rather than merely warned about.
    pub hold_id: String,
    /// The case channel UUID. In Perch's vocabulary the case id IS the channel
    /// UUID; a `CorrelatedIncident` is a different, recomputed object.
    pub case_channel: String,
    /// `ActionRequest.hunt_id`.
    pub hunt_id: String,
    /// Nostr event id of the `swarm:finding:v1` card this answers, when one
    /// exists. Also the `e` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_card_id: Option<String>,
}

/// `HeldActionView` minus its two clock-derived fields.
///
/// Field-for-field the same object as
/// `build/openapi/perch-operator-v1.yaml#/components/schemas/HeldActionView`,
/// which is normative for the HTTP shape while this is normative for the wire
/// shape; `tools/check-perch-wire-parity.sh` holds them together.
///
/// NARROWING: `remaining_ms` and `expired` are NOT here. They are computed
/// against an observation instant and this card is immutable, so baking them in
/// would freeze a countdown at its publish value forever. The console recomputes
/// both from `expires_at_ms` and renders them as two separate elements
/// (`INV-06`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeldAction {
    /// The opaque id, repeated inside the body so a copied JSON blob is
    /// self-describing.
    pub hold_id: String,
    /// The state machine. `12-BACKEND-BILL-API.md` §3.3 owns the transitions.
    pub state: HoldState,
    /// `ResponseAction::kind()`.
    pub action_kind: WireResponseActionKind,
    /// `ActionRequest.severity`. REQUEST-CARRIED — see `rationale`.
    pub severity: WireSeverity,
    /// When the daemon created the hold.
    pub held_at_ms: i64,
    /// `held_at_ms + PERCH_HOLD_TTL_MS` by default.
    pub expires_at_ms: i64,
    /// The request VERBATIM. `severity` and the threat class inside `evidence`
    /// are set by the REQUESTING AGENT and read back by the configurable gate's
    /// selector, so an agent influences which rule judges its own destructive
    /// action.
    pub action_request: WireActionRequest,
    /// The gate's verdict VERBATIM. Today this is one constant pair for all
    /// twelve action kinds, which is why `rationale` exists.
    pub policy_decision: WirePolicyDecision,
    /// NEW IN B1. The differentiating context, captured at hold time.
    pub rationale: HoldRationale,
    /// `is_containment_action(action)`. FALSE for eight of the twelve
    /// destructive kinds, and a false means the card renders NO pending
    /// containment-lease slot rather than an empty one.
    pub leases_a_containment: bool,
    /// The daemon's rehearsal preview, when it built one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehearsal: Option<WireRehearsalPreview>,
    /// DERIVED, NOT SERVED. One entry per rollback step, from the engine's
    /// `resolve_inverse`. Render law 4 requires the console to name that
    /// function beside the row.
    #[serde(default)]
    pub inverse_resolution: Vec<InverseResolution>,
    /// `None` on the open card, `Some` on the terminal card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<HoldDecisionRecord>,
}

/// The hold state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum HoldState {
    Created,
    Notified,
    Armed,
    Deciding,
    Granted,
    Refused,
    Expired,
    Executed,
    Failed,
}

impl HoldState {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Notified => "notified",
            Self::Armed => "armed",
            Self::Deciding => "deciding",
            Self::Granted => "granted",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Executed => "executed",
            Self::Failed => "failed",
        }
    }

    /// Whether this is one of the five terminal states.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Granted | Self::Refused | Self::Expired | Self::Executed | Self::Failed
        )
    }
}

/// Why THIS action was held, as distinct from why holds exist.
///
/// Every hold today carries `rule_name = "static.human_gate"` and
/// `reason = "authorized but held for human approval"`, because the static gate
/// is the only production `RequireHuman` producer. Render law 1's WHY WE ARE
/// ASKING slot would otherwise print the same 42 characters on all twelve
/// action kinds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldRationale {
    /// Copied from `policy_decision`.
    pub rule_name: String,
    /// Copied from `policy_decision`.
    pub reason: String,
    /// From `request.evidence["escalation"]["threat_class"]`, falling back to
    /// `request.evidence["threat_class"]` — the same two keys the configurable
    /// gate reads.
    pub threat_class: WireThreatClass,
    /// `ActionRequest.severity`.
    pub severity: WireSeverity,
    /// Which fields on this rationale came from the requesting agent rather than
    /// the runtime. Always contains at least `severity` and `threat_class`.
    pub request_carried_fields: Vec<String>,
    /// The class concentration when the hold was created, or `None` when no
    /// escalation context rode in the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concentration_at_hold: Option<ThreatConcentration>,
    /// `alert` or `incident`, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation_level: Option<EscalationLevel>,
    /// Whether `evidence["governance_receipt"]` was present at HOLD time. NOT a
    /// verification result: B2g verifies at DECISION time and the answer can
    /// differ.
    pub governance_receipt_present: bool,
}

/// Per-step inverse resolution. DERIVED.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InverseResolution {
    /// The step this answers.
    pub step_kind: WireRollbackStepKind,
    /// `executable` | `irreversible` | `unmapped`.
    pub verdict: InverseVerdict,
    /// Quotable for `irreversible`; the shipped one reads "a terminated session
    /// cannot be resumed; the principal can only establish a fresh session".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Outcome of `resolve_inverse` for one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum InverseVerdict {
    Executable,
    Irreversible,
    Unmapped,
}

/// The stored outcome of a decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldDecisionRecord {
    /// `grant` or `refuse`. NEVER `deny`: appendix §7 rules `refuse` to the
    /// operator, `deny` to the policy and `veto` to governance, and a body that
    /// says `deny` puts the policy's word in a human's mouth in the one record
    /// meant to keep them apart.
    pub decision: Decision,
    /// From the authenticated operator principal, never from a body.
    pub operator_id: String,
    /// The instant the hold store's compare-and-set succeeded, not the instant
    /// the operator's client claimed. Both the capability lease and the
    /// containment lease are minted from this.
    pub decided_at_ms: i64,
    /// 64-hex Nostr event id of the leg-1 card. The idempotency key.
    pub nostr_intent_event_id: String,
    /// The operator's Ed25519 signature, when the decide route recorded one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<WireDetachedSignature>,
    /// Free text the operator typed. Never parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// The daemon's outcome label.
    pub outcome: String,
    /// Whether the runtime attempted the response at all. False for every
    /// refusal and for a late refusal.
    pub dispatched: bool,
    /// Set only when the runtime produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// The named check that refused late, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Value>,
}

/// The operator's two verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Record my decision and send it to the daemon.
    Grant,
    /// Refuse. One keypress, no dialog, no undo.
    Refuse,
}

impl Decision {
    /// The wire spelling, which is also the human-line word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Refuse => "refuse",
        }
    }
}

impl HoldCard {
    /// `hold {hold_id} · {action_kind} · {SEVERITY} · {scope_kind} {scope_value} · expires {ISO}`
    ///
    /// The scope comes from the rehearsal's blast radius; a hold with no
    /// rehearsal says `scope unresolved` rather than guessing one from the
    /// action payload.
    #[must_use]
    pub fn human_line(&self) -> String {
        let scope = self.hold.rehearsal.as_ref().map_or_else(
            || "scope unresolved".to_string(),
            |rehearsal| {
                format!(
                    "{} {}",
                    rehearsal.blast_radius.scope_kind.as_str(),
                    rehearsal.blast_radius.scope_value
                )
            },
        );
        [
            format!("hold {}", self.hold.hold_id),
            self.hold.action_kind.as_str().to_string(),
            severity_label(self.hold.severity).to_string(),
            scope,
            format!("expires {}", iso_seconds(self.hold.expires_at_ms)),
        ]
        .join(HUMAN_SEP)
    }
}

// ───────────────────────────────────────────────────────────── verdict

/// `swarm:verdict:v1` — LEG 1 OF THE TWO-LEGGED WRITE.
///
/// A signed human intent record, published by the OPERATOR'S OWN Nostr key. It
/// is not an authorization and no daemon reads it as one: leg 2 is a separate
/// POST across a process boundary and the daemon re-derives authority from
/// scratch. This is the only card the operator publishes and the only one whose
/// envelope `issuer` is not the bridge's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictCard {
    /// The operator, as an `OperatorFactIssuer` — a SEPARATE type from
    /// `FactIssuer` whose `role` is structurally `null`.
    ///
    /// This is not a style choice. The agent-role enum is a closed set of SWARM
    /// agents with no human member, and `tom` is "Governance — enforces policy,
    /// manages lifecycle": the veto actor. Stamping `tom` on an operator's own
    /// decision conflates the human's *refuse* with governance's *veto*, which
    /// `APPENDIX-NORMATIVE.md` §7 forbids and `adr/0016` spends a document
    /// keeping apart. A separate type makes the conflation a compile error.
    pub issuer: OperatorFactIssuer,
    /// `decided_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: VerdictLocator,
    /// What was decided.
    pub decision: VerdictDecision,
    /// Ed25519 over the RFC 8785 canonical form of
    /// `{decided_at_ms, decision, hold_id, rationale_sha256}` — EXACTLY the
    /// preimage the decide route requires (W3-16), so ONE signature serves both
    /// legs and a reviewer diffing them checks one thing. `rationale` and
    /// `operator_id` are deliberately outside the preimage: rationale is bound
    /// by its digest, and `operator_id` is re-derived from `public_key_hex`.
    pub signature: WireDetachedSignature,
    /// The console's own record of what leg 2 did, published as an UPDATE card
    /// replying to the first. `INV-33` forbids optimistic UI: three distinct
    /// states, none of them offering an undo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leg2: Option<Leg2State>,
}

/// Join keys for a verdict card, discriminated by what was decided (D-FC-3).
///
/// One marker carries verdicts on two different subjects because the registry
/// is closed at seven and an eighth is not an option. The `subject` tag is on
/// the wire, so a reader never has to guess which join keys a card carries.
///
/// Each arm is a named struct rather than an inline variant body: the wire
/// bytes are identical (serde's internal tagging flattens a newtype variant
/// beside its tag), and `tools/check-perch-wire-parity.sh` reads `pub field:`
/// declarations, which an inline variant body does not produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum VerdictLocator {
    /// A verdict on a held action.
    Hold(VerdictHoldLocator),
    /// A verdict on a finding: confirm, dismiss or investigate (B3).
    Finding(VerdictFindingLocator),
}

/// Join keys for a verdict on a held action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictHoldLocator {
    /// The hold.
    pub hold_id: String,
    /// The case channel. `INV-12` asserts it equals the `h` tag; `INV-13`
    /// asserts a mismatch refuses to render.
    pub case_channel: String,
    /// Nostr event id of the open `swarm:hold:v1` card.
    pub hold_card_id: String,
}

/// Join keys for a verdict on a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictFindingLocator {
    /// The finding the daemon knows by this id, read out of the admitted
    /// finding card's own body and never from a renderer-supplied copy.
    pub finding_id: String,
    /// Nostr event id of the admitted `swarm:finding:v1` card, 64 lowercase
    /// hex. THE JOIN, and deliberately not an `e` tag: the finding card lives
    /// in a lane channel and this card in a case channel, so an `e` would make
    /// the relay's NIP-10 thread resolver mutate a lane card's `reply_count`
    /// from a case.
    pub finding_card_id: String,
    /// The case channel. `INV-12` asserts it equals the `h` tag.
    pub case_channel: String,
    /// The incident the daemon minted for this case (B3i).
    pub incident_id: String,
}

/// The decision itself, discriminated by subject. The signing preimage is a
/// subset of the arm that carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum VerdictDecision {
    /// `grant` | `refuse`, on a held action.
    Hold(VerdictHoldDecision),
    /// `confirm` | `dismiss` | `investigate`, on a finding.
    Finding(VerdictFindingDecision),
}

/// What was decided about a held action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictHoldDecision {
    /// The operator's verb.
    pub decision: Decision,
    /// The hold.
    pub hold_id: String,
    /// When the operator signed.
    pub decided_at_ms: i64,
    /// The configured operator principal id. The console asserts it equals
    /// the id derived from `signature.public_key_hex` before publishing,
    /// because the decide route will.
    pub operator_id: String,
    /// SHA-256 of the UTF-8 rationale, or JSON `null` when absent.
    pub rationale_sha256: Option<String>,
    /// Free text. Never parsed by anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// What was decided about a finding.
///
/// The Ed25519 preimage for this arm is the RFC 8785 form of
/// `{decided_at_ms, decision, finding_id, rationale_sha256}` — W3-16's
/// four-member shape with `finding_id` in `hold_id`'s place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerdictFindingDecision {
    /// The operator's verb.
    pub decision: FindingVerdictWord,
    /// The finding.
    pub finding_id: String,
    /// When the operator signed.
    pub decided_at_ms: i64,
    /// The configured operator principal id.
    pub operator_id: String,
    /// SHA-256 of the UTF-8 rationale, or JSON `null` when absent.
    pub rationale_sha256: Option<String>,
    /// Free text. Never parsed by anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// The operator's three verbs on a finding (B3).
///
/// A separate enum from [`Decision`] on purpose: `grant` authorizes an action
/// the daemon is holding, `confirm` records that a detection was true. Sharing
/// one enum would let a grant be written where a confirm belongs, and the two
/// go to different daemon routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingVerdictWord {
    /// A true detection. Feeds the daemon's tuning as a confirmed finding.
    Confirm,
    /// A false positive. Feeds the daemon's false-positive tracking.
    Dismiss,
    /// Neither yet: keep the case open and say so on the record.
    Investigate,
}

impl FindingVerdictWord {
    /// The wire spelling, which is also the human-line word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Dismiss => "dismiss",
            Self::Investigate => "investigate",
        }
    }
}

/// What leg 2 did.
///
/// TWO OPERATORS, ONE HOLD. `APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags EVERY
/// Approve-scoped principal, so two consoles can legitimately hold the same
/// open hold. Leg 1 is published to the relay BEFORE leg 2 is POSTed, the relay
/// has no compare-and-set, and a `kind:9` event is immutable — so both signed
/// verdict cards land in the case channel and stay there forever.
/// `12-BACKEND-BILL-API.md` §4.4 resolves the DAEMON side
/// (`409 hold_already_deciding` / `409 hold_already_decided`); `Superseded` is
/// the relay side of the same event.
///
/// It has to be the losing CONSOLE that publishes it: the daemon never saw the
/// losing leg-1 card, and the console is the only party holding both its own
/// card's event id and the 409 body naming the winner's. A verdict card with no
/// matching daemon decision record renders as not-the-decision, whatever its
/// `leg2` says (`13-WIRE-SCHEMAS.md` §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leg2State {
    /// The outcome.
    pub state: Leg2Outcome,
    /// Set once the daemon returns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// The named check that refused, verbatim from the daemon. A late refusal is
    /// a NORMAL OUTCOME naming a rule, never a client error (`INV-28`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_check: Option<String>,
    /// The WINNING leg-1 card's Nostr event id — the `nostr_intent_event_id` the
    /// daemon recorded as the decision, read out of the 409 body.
    /// `Some` iff `state == Superseded`, asserted by
    /// [`Leg2State::assert_superseded_shape`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// When THIS console learned it had lost — its own clock at the 409, not the
    /// winner's `decided_at_ms`, which it never observes. `Some` iff
    /// `state == Superseded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at_ms: Option<i64>,
}

/// The five leg-2 outcomes. Closed; a sixth is a wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Leg2Outcome {
    /// Leg 1 is published; leg 2 has not answered.
    Sending,
    /// The daemon recorded the decision.
    Recorded,
    /// A receipt id came back.
    Acknowledged,
    /// The daemon refused AFTER leg 1 was signed and published. The intent
    /// record stands; the action did not run.
    RefusedLate,
    /// ANOTHER operator's decision was the one the daemon executed. This card is
    /// a human intent record that did not become the decision, and no surface
    /// may render it as one.
    Superseded,
}

impl Leg2State {
    /// `Ok(())` iff exactly the `Superseded` state carries a winner.
    ///
    /// Not a `Result` for ceremony: without it a `superseded` card with no
    /// `superseded_by` is a dead end for the reconciler, and a `recorded` card
    /// carrying one is a claim the console cannot have observed.
    pub fn assert_superseded_shape(&self) -> Result<(), &'static str> {
        let s = matches!(self.state, Leg2Outcome::Superseded);
        match (
            s,
            self.superseded_by.is_some(),
            self.superseded_at_ms.is_some(),
        ) {
            (true, true, true) | (false, false, false) => Ok(()),
            (true, _, _) => Err("leg2.superseded requires superseded_by and superseded_at_ms"),
            (false, _, _) => Err("only leg2.superseded may carry superseded_by/superseded_at_ms"),
        }
    }
}

impl VerdictCard {
    /// `{grant|refuse} · hold {hold_id} · by {operator_id} · {ISO}` for a held
    /// action, and
    /// `{confirm|dismiss|investigate} · finding {finding_id} · by {operator_id} · {ISO}`
    /// for a finding.
    #[must_use]
    pub fn human_line(&self) -> String {
        let (verb, subject, operator_id, decided_at_ms) = match &self.decision {
            VerdictDecision::Hold(d) => (
                d.decision.as_str(),
                format!("hold {}", d.hold_id),
                &d.operator_id,
                d.decided_at_ms,
            ),
            VerdictDecision::Finding(d) => (
                d.decision.as_str(),
                format!("finding {}", d.finding_id),
                &d.operator_id,
                d.decided_at_ms,
            ),
        };
        [
            verb.to_string(),
            subject,
            format!("by {operator_id}"),
            iso_seconds(decided_at_ms),
        ]
        .join(HUMAN_SEP)
    }
}

// ───────────────────────────────────────────────────────────── receipt

/// `swarm:receipt:v1` — one audit trail, in a case channel.
///
/// NARROWING: carries the `AuditTrail` ONLY, not the trail plus a separate
/// `ResponseReceipt`. APPENDIX-NORMATIVE §3 says both; the trail's `success`
/// response record already embeds the whole receipt, so carrying both puts a
/// byte-for-byte duplicate in a card that `INV-26` then has to reconcile
/// against the daemon's stored body. See `13-WIRE-SCHEMAS.md` §9 amendment W-5.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptCard {
    /// Who executed.
    pub issuer: FactIssuer,
    /// `AuditTrail.created_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: ReceiptLocator,
    /// The trail VERBATIM: seven fields, unsigned.
    pub audit_trail: WireAuditTrail,
}

/// Join keys for a receipt card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptLocator {
    /// `AuditTrail.trail_id`.
    pub trail_id: String,
    /// `AuditTrail.hunt_id`.
    pub hunt_id: String,
    /// The case channel.
    pub case_channel: String,
    /// `AuditTrail::response_receipt_id()`: `Some` for the `success` and
    /// `failure` arms, `None` for `skipped` and `guard_rejected`. Lifted into
    /// the locator so a search finds a receipt without parsing the trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Set when this receipt followed a human grant. Also the `e` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_card_id: Option<String>,
}

impl ReceiptCard {
    /// `receipt {receipt_id|none} · {action} · {status} · {mode} · trail {trail_id}`
    ///
    /// The action, status and mode come from the trail's response record. The
    /// `skipped` and `guard_rejected` arms carry no action and no mode, so the
    /// line says `none` for each and names the arm as the status rather than
    /// inventing values the record does not hold.
    #[must_use]
    pub fn human_line(&self) -> String {
        let (action, status, mode) = match &self.audit_trail.response {
            WireAuditResponseRecord::Success(receipt) => (
                receipt.action.clone(),
                receipt.status.as_str(),
                receipt.mode.as_str(),
            ),
            WireAuditResponseRecord::Failure(failure) => (
                failure.action.clone(),
                self.audit_trail.response.kind(),
                failure.mode.as_str(),
            ),
            WireAuditResponseRecord::Skipped { .. }
            | WireAuditResponseRecord::GuardRejected { .. } => {
                ("none".to_string(), self.audit_trail.response.kind(), "none")
            }
        };
        let receipt_id = self
            .locator
            .receipt_id
            .as_deref()
            .or_else(|| self.audit_trail.response.receipt_id())
            .unwrap_or("none");
        [
            format!("receipt {receipt_id}"),
            action,
            status.to_string(),
            mode.to_string(),
            format!("trail {}", self.locator.trail_id),
        ]
        .join(HUMAN_SEP)
    }
}

// ─────────────────────────────────────────────────────────────── lease

/// `swarm:lease:v1` — one containment lease on open, in a case channel.
///
/// NARROWING: carries the persisted lease record, NOT the daemon's
/// `ContainmentLeaseView`. The View's `remaining_ms` and `expired` are computed
/// against an observation instant and this card is immutable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaseCard {
    /// Who opened it.
    pub issuer: FactIssuer,
    /// `lease.issued_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: LeaseLocator,
    /// The containment lease VERBATIM.
    pub lease: WireContainmentLease,
    /// Which config key the TTL came from, carried so no surface renders the
    /// wrong one. A containment lease's default TTL is 900_000 ms; the 60_000
    /// `policy.lease_ttl_ms` is the CAPABILITY lease's authorization window,
    /// and rendering it beside a containment lease is wrong by 15x.
    pub ttl_source: TtlSource,
}

/// Where a rendered TTL came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TtlSource {
    /// `runtime.containment.lease_ttl_ms`, default 900_000.
    #[serde(rename = "runtime.containment.lease_ttl_ms")]
    ContainmentLeaseTtlMs,
}

/// Join keys for a lease card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseLocator {
    /// `ContainmentLease::lease_id`.
    pub lease_id: String,
    /// The case channel.
    pub case_channel: String,
    /// The response receipt that made the containment.
    pub origin_receipt_id: String,
    /// Nostr event id of the `swarm:receipt:v1` card. Also the `e` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_card_id: Option<String>,
}

impl LeaseCard {
    /// `containment lease {lease_id} · {action_kind} · issued {ISO} · expires {ISO} · origin receipt {receipt_id}`
    #[must_use]
    pub fn human_line(&self) -> String {
        [
            format!("containment lease {}", self.lease.lease_id),
            self.lease.action.kind.as_str().to_string(),
            format!("issued {}", iso_seconds(self.lease.issued_at_ms)),
            format!("expires {}", iso_seconds(self.lease.expires_at_ms)),
            format!("origin receipt {}", self.lease.origin_receipt_id),
        ]
        .join(HUMAN_SEP)
    }
}

// ──────────────────────────────────────────────────────────── rollback

/// `swarm:rollback:v1` — one rollback receipt, replying to its lease card.
///
/// THE ONLY CARD THAT CAN REACH TIER 1 TODAY. `rollback_receipt.governance_attestation`
/// holds a serialized governance receipt over this receipt's canonical form
/// with THAT FIELD CLEARED, and the runtime's `verify_release_attestation`
/// checks the signature AND the subject binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackCard {
    /// Who ran it — the sweep, or the operator's release.
    pub issuer: FactIssuer,
    /// `rollback_receipt.completed_at_ms`.
    pub emitted_at_ms: i64,
    /// Join keys.
    pub locator: RollbackLocator,
    /// The receipt VERBATIM.
    pub rollback_receipt: WireRollbackReceipt,
    /// `ContainmentReleaseResponse` minus its receipt and schema_version.
    ///
    /// PRESENT ONLY for `trigger = manual`. An expiry-triggered rollback comes
    /// from the TTL sweep with no HTTP request and therefore no such body.
    /// `lease_closed: false` on an HTTP 200 means the release attempted the
    /// inverse, it failed, and the containment lease was deliberately kept open
    /// for the next sweep — a host is STILL contained. `INV-05` forbids reading
    /// the status code instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_response: Option<ReleaseOutcome>,
    /// Which of the two UNATTESTED renderings applies (`INV-08`).
    /// `partitioned` or `healing` means `UNATTESTED — BY DESIGN`. `None` means
    /// the console could not establish it and must say so rather than assume
    /// healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_state_at_execution: Option<WirePartitionState>,
}

/// The four booleans a release returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseOutcome {
    /// Read this, never the HTTP status.
    pub lease_closed: bool,
    /// Deliberately stricter than "nothing errored": a simulated step did not
    /// restore anything and an irreversible step never will.
    pub fully_reversed: bool,
    /// From `verify_release_attestation`.
    pub attestation_verified: bool,
    /// Why it did not, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_error: Option<String>,
}

/// Join keys for a rollback card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackLocator {
    /// `RollbackReceipt.rollback_id`.
    pub rollback_id: String,
    /// The containment lease this closed.
    pub lease_id: String,
    /// The case channel.
    pub case_channel: String,
    /// Nostr event id of the `swarm:lease:v1` card. Also the `e` tag.
    pub lease_card_id: String,
}

impl RollbackCard {
    /// `rollback {rollback_id} · containment lease {lease_id} · {trigger} · {status} · {k} of {n} steps reversed`
    ///
    /// `k` counts steps whose status is `reversed` — voice law L5, every number
    /// carries its denominator.
    #[must_use]
    pub fn human_line(&self) -> String {
        let receipt = &self.rollback_receipt;
        [
            format!("rollback {}", receipt.rollback_id),
            format!("containment lease {}", receipt.lease_id),
            receipt.trigger.as_str().to_string(),
            receipt.status.as_str().to_string(),
            format!(
                "{} of {} steps reversed",
                receipt.reversed_steps(),
                receipt.steps.len()
            ),
        ]
        .join(HUMAN_SEP)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wire_form<T: Serialize>(value: &T) -> Value {
        serde_json::to_value(value).expect("serializes")
    }

    #[test]
    fn every_closed_enum_serializes_to_its_as_str() {
        fn check<T: Serialize + Copy + fmt::Display>(all: &[T], as_str: fn(T) -> &'static str) {
            for v in all {
                assert_eq!(wire_form(v), json!(as_str(*v)));
                assert_eq!(v.to_string(), as_str(*v));
            }
        }
        check(WireSeverity::ALL, WireSeverity::as_str);
        check(WireAgentRole::ALL, WireAgentRole::as_str);
        check(WireAgentHealth::ALL, WireAgentHealth::as_str);
        check(WireSwarmMode::ALL, WireSwarmMode::as_str);
        check(WirePolicyVerdict::ALL, WirePolicyVerdict::as_str);
        check(WireExecutionMode::ALL, WireExecutionMode::as_str);
        check(WireResponseStatus::ALL, WireResponseStatus::as_str);
        check(WireResponseActionKind::ALL, WireResponseActionKind::as_str);
        check(WireRehearsalScopeKind::ALL, WireRehearsalScopeKind::as_str);
        check(WireBlastRadiusImpact::ALL, WireBlastRadiusImpact::as_str);
        check(WireRollbackStepKind::ALL, WireRollbackStepKind::as_str);
        check(WireRollbackStepStatus::ALL, WireRollbackStepStatus::as_str);
        check(WireRollbackTrigger::ALL, WireRollbackTrigger::as_str);
        check(WirePartitionState::ALL, WirePartitionState::as_str);
    }

    #[test]
    fn the_vocabulary_has_the_schema_cardinalities() {
        assert_eq!(WireThreatClass::STANDARD.len(), 12);
        assert_eq!(WireSeverity::ALL.len(), 4);
        assert_eq!(WireAgentRole::ALL.len(), 8);
        assert_eq!(WireResponseActionKind::ALL.len(), 15);
        assert_eq!(WireRehearsalScopeKind::ALL.len(), 10);
        assert_eq!(WireBlastRadiusImpact::ALL.len(), 15);
        assert_eq!(WireRollbackStepKind::ALL.len(), 15);
        assert_eq!(WireRollbackStepStatus::ALL.len(), 5);
        assert_eq!(WirePartitionState::ALL.len(), 4);
        assert_eq!(WireResponseActionKind::CONTAINMENT.len(), 4);
        assert!(WireResponseActionKind::IsolateHost.leases_a_containment());
        assert!(!WireResponseActionKind::BlockEgress.leases_a_containment());
    }

    #[test]
    fn severity_is_screaming_snake_and_nothing_else_is() {
        assert_eq!(wire_form(&WireSeverity::High), json!("HIGH"));
        assert!(serde_json::from_value::<WireSeverity>(json!("high")).is_err());
        assert_eq!(wire_form(&WireSwarmMode::Alert), json!("alert"));
        assert_eq!(severity_label(WireSeverity::Critical), "CRITICAL");
    }

    #[test]
    fn threat_class_is_a_bare_string_for_the_twelve_and_an_object_for_custom() {
        for class in &WireThreatClass::STANDARD {
            assert_eq!(wire_form(class), json!(threat_class_slug(class)));
        }
        let custom = WireThreatClass::Custom("sphinx_memory".into());
        assert_eq!(wire_form(&custom), json!({ "custom": "sphinx_memory" }));
        assert_eq!(threat_class_slug(&custom), "custom");
        assert_eq!(custom.to_string(), "custom:sphinx_memory");
        // A bare "custom" string is not a threat class.
        assert!(serde_json::from_value::<WireThreatClass>(json!("custom")).is_err());
        let round: WireThreatClass =
            serde_json::from_value(json!({ "custom": "sphinx_memory" })).unwrap();
        assert_eq!(round, custom);
    }

    #[test]
    fn a_response_action_is_internally_tagged_on_type() {
        let action: WireResponseAction =
            serde_json::from_value(json!({ "type": "isolate_host", "host_id": "web-04" })).unwrap();
        assert_eq!(action.kind, WireResponseActionKind::IsolateHost);
        assert_eq!(action.fields.get("host_id"), Some(&json!("web-04")));
        assert_eq!(
            wire_form(&action),
            json!({ "type": "isolate_host", "host_id": "web-04" })
        );
        // The externally tagged shape is the wrong shape.
        assert!(
            serde_json::from_value::<WireResponseAction>(
                json!({ "isolate_host": { "host_id": "web-04" } })
            )
            .is_err()
        );
    }

    #[test]
    fn an_audit_response_record_flattens_the_receipt_beside_its_kind() {
        let record: WireAuditResponseRecord = serde_json::from_value(json!({
            "kind": "success",
            "receipt_id": "resp-1",
            "action": "isolate_host",
            "mode": "enforced",
            "status": "executed",
            "summary": "host web-04 isolated",
            "details": {},
        }))
        .unwrap();
        assert_eq!(record.kind(), "success");
        assert_eq!(record.receipt_id(), Some("resp-1"));
        let back = wire_form(&record);
        assert_eq!(back["kind"], "success");
        assert_eq!(back["receipt_id"], "resp-1");
        assert_eq!(back["audit"], json!({}));
        assert!(back.get("success").is_none());

        let skipped: WireAuditResponseRecord =
            serde_json::from_value(json!({ "kind": "skipped", "reason": "dry run" })).unwrap();
        assert_eq!(skipped.receipt_id(), None);
        assert_eq!(skipped.kind(), "skipped");
    }

    #[test]
    fn a_containment_lease_refuses_unknown_fields_like_the_engine_record() {
        let lease = json!({
            "schema_version": 1,
            "lease_id": "cl_1",
            "action": { "type": "isolate_host", "host_id": "web-04" },
            "origin_receipt_id": "resp-1",
            "blast_radius": {
                "scope_kind": "host",
                "scope_value": "web-04",
                "impact": "host_connectivity_isolated",
                "max_affected_scopes": 1,
                "affected_capabilities": [],
                "summary": "one host"
            },
            "rollback": { "required": true, "summary": "restore", "steps": [] },
            "issued_at_ms": 1,
            "expires_at_ms": 2
        });
        let parsed: WireContainmentLease = serde_json::from_value(lease.clone()).unwrap();
        assert_eq!(parsed.governance_receipt_id, None);
        // Serialization mirrors the engine: an absent governance receipt id is omitted.
        assert!(wire_form(&parsed).get("governance_receipt_id").is_none());
        let mut widened = lease;
        widened["remaining_ms"] = json!(5);
        assert!(serde_json::from_value::<WireContainmentLease>(widened).is_err());
    }

    #[test]
    fn agents_are_derived_by_dropping_the_strategy_segment() {
        let ids = [
            "w:1:spt".to_string(),
            "w:1:scr".to_string(),
            "w:2:spt".to_string(),
        ];
        assert_eq!(agents_of(&ids), 2);
        assert_eq!(agents_of(&["bare".to_string()]), 1);
        assert_eq!(agents_of(&[]), 0);
    }

    #[test]
    fn iso_seconds_is_rfc3339_at_second_precision_with_z() {
        assert_eq!(iso_seconds(1_773_742_482_600), "2026-03-17T10:14:42Z");
        assert_eq!(iso_seconds(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_seconds(i64::MAX), format!("{}ms", i64::MAX));
    }

    #[test]
    fn the_source_shape_is_exactly_one_of_two() {
        let mut crossing = ConcentrationCrossing {
            threat_class: WireThreatClass::Execution,
            level: EscalationLevel::Alert,
            total_strength: 2.7,
            distinct_sources: 2,
            distinct_sources_counts: SourceCountMechanism::StrategyScopedAgentId,
            source_ids: None,
            source_ids_absent_reason: Some(SourceIdsAbsentReason::NotCarriedByRuntimeEvent),
            peak_confidence: 0.9,
            mode_changed: true,
            current_mode: WireSwarmMode::Alert,
            dedupe_key: "execution:alert:1".into(),
        };
        assert!(crossing.assert_source_shape().is_ok());
        crossing.source_ids = Some(vec!["w:1:spt".into()]);
        assert!(crossing.assert_source_shape().is_err());
        crossing.source_ids_absent_reason = None;
        assert!(crossing.assert_source_shape().is_ok());
        crossing.source_ids = None;
        assert!(crossing.assert_source_shape().is_err());
    }

    #[test]
    fn a_superseded_leg2_carries_its_winner_and_nothing_else_may() {
        let winner = Leg2State {
            state: Leg2Outcome::Superseded,
            receipt_id: None,
            refusal_check: None,
            superseded_by: Some("d".repeat(64)),
            superseded_at_ms: Some(1),
        };
        assert!(winner.assert_superseded_shape().is_ok());
        let dead_end = Leg2State {
            superseded_by: None,
            ..winner.clone()
        };
        assert!(dead_end.assert_superseded_shape().is_err());
        let claim = Leg2State {
            state: Leg2Outcome::Recorded,
            ..winner
        };
        assert!(claim.assert_superseded_shape().is_err());
    }

    #[test]
    fn a_rollback_counts_only_reversed_steps() {
        let step = |status| WireRollbackStepOutcome {
            kind: WireRollbackStepKind::RestoreHostConnectivity,
            status,
            detail: String::new(),
        };
        let receipt = WireRollbackReceipt {
            rollback_id: "rb".into(),
            lease_id: "cl".into(),
            origin_receipt_id: "resp".into(),
            governance_receipt_id: None,
            trigger: WireRollbackTrigger::Expiry,
            mode: WireExecutionMode::Enforced,
            status: WireResponseStatus::Executed,
            steps: vec![
                step(WireRollbackStepStatus::Reversed),
                step(WireRollbackStepStatus::Simulated),
                step(WireRollbackStepStatus::Irreversible),
            ],
            completed_at_ms: 1,
            summary: String::new(),
            governance_attestation: None,
        };
        assert_eq!(receipt.reversed_steps(), 1);
        assert!(!receipt.fully_reversed());
        // Serialization mirrors the engine: the attestation is excluded from
        // its own subject by omission, and the governance receipt id is null.
        let form = wire_form(&receipt);
        assert!(form.get("governance_attestation").is_none());
        assert_eq!(form["governance_receipt_id"], Value::Null);
    }

    #[test]
    fn a_card_round_trips_through_its_schema_tag() {
        let fact = json!({
            "schema": "swarm.perch.escalation.v1",
            "issuer": { "swarm_agent_id": "concentration-monitor", "role": null },
            "emitted_at_ms": 1,
            "locator": { "lane_channel": "b8240a37-88b1-4a9f-8b77-5cc005891115" },
            "escalation": {
                "cause": "mode_transition",
                "from": "alert",
                "to": "incident",
                "triggering_threat_class": { "custom": "sphinx_memory" },
                "reason": "concentration crossed incident_threshold"
            }
        });
        let card: Card = serde_json::from_value(fact.clone()).unwrap();
        assert_eq!(card.kind(), CardKind::Escalation);
        assert_eq!(card.emitted_at_ms(), 1);
        assert_eq!(
            card.human_line(),
            "mode alert → incident · custom · concentration crossed incident_threshold"
        );
        assert_eq!(wire_form(&card), fact);
    }

    #[test]
    fn the_tamper_grammar_names_the_debugger_state() {
        let card = EscalationCard {
            issuer: FactIssuer {
                swarm_agent_id: "guard".into(),
                role: None,
                nostr_pubkey: None,
            },
            emitted_at_ms: 1,
            locator: EscalationLocator {
                lane_channel: "lane".into(),
                case_channel: None,
            },
            escalation: EscalationBody::TamperFailClosed(TamperFailClosed {
                debugger_attached: true,
                tracer_pid: Some(7),
                unexpected_library_count: 2,
                unexpected_library_sha256: "0x7d".into(),
                unexpected_library_loads: vec!["/tmp/a.so".into(), "/tmp/b.so".into()],
                fail_closed: true,
                details: "x".into(),
            }),
        };
        assert_eq!(
            card.human_line(),
            "tamper fail-closed · 2 unexpected library loads · debugger attached"
        );
    }
}
