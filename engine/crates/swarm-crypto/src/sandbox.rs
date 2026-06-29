//! Sandbox attestation types for receipt integration.
//!
//! Harvested into Ambush from the upstream ClawdStrike `sandbox::attestation`
//! module (Apache-2.0). These types capture the OS-level sandbox enforcement
//! state so that a signed [`Receipt`] can *claim* kernel-enforced isolation:
//! they serialize into the receipt `metadata["sandbox"]` slot that
//! [`crate::receipt::SignedReceipt::is_kernel_enforced`] already reads.
//!
//! The upstream OS-binding constructors (which read live kernel state through
//! the `nono` sandbox crate — `nono::CapabilitySet`, `nono::Sandbox::support_info`,
//! `nono::SignalMode`, etc.) are intentionally **dropped**. What remains is pure,
//! serializable type shapes plus cfg-derived (compile-time only) classification
//! logic, so the crate stays dependency-light and platform-agnostic.

use chrono::Utc;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JsonValue;

use crate::error::Result;
use crate::receipt::Receipt;

/// Complete sandbox attestation for receipt metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAttestation {
    pub enforced: bool,
    pub enforcement_level: EnforcementLevel,
    pub platform: PlatformInfo,
    pub runtime: SandboxRuntimeState,
    pub capabilities: CapabilitySnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<SupervisorStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denials: Vec<TimestampedDenial>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<AuditEntry>,
}

impl SandboxAttestation {
    /// Build an attestation from already-captured platform/runtime/capability
    /// snapshots, then derive `enforced` + `enforcement_level` from the runtime
    /// state. This is the pure replacement for the upstream `build_attestation`
    /// helper (which read live `nono::CapabilitySet` accessors).
    #[must_use]
    pub fn new(
        platform: PlatformInfo,
        runtime: SandboxRuntimeState,
        capabilities: CapabilitySnapshot,
    ) -> Self {
        let mut attestation = Self {
            enforced: false,
            enforcement_level: EnforcementLevel::None,
            platform,
            runtime,
            capabilities,
            supervisor: None,
            denials: Vec::new(),
            audit: Vec::new(),
        };
        attestation.recompute_status();
        attestation
    }

    /// Recompute `platform.mechanisms`, `enforcement_level`, and `enforced`
    /// from the current runtime state.
    pub fn recompute_status(&mut self) {
        self.platform.mechanisms = platform_mechanisms(&self.runtime);
        self.enforcement_level = effective_enforcement_level(&self.runtime);
        self.enforced = matches!(
            self.enforcement_level,
            EnforcementLevel::Kernel | EnforcementLevel::KernelSupervised
        );
    }

    /// Whether this attestation claims kernel-level (OS-sandbox) enforcement.
    ///
    /// True only when the attestation is flagged `enforced` *and* the
    /// enforcement level is kernel-backed (`Kernel` or `KernelSupervised`).
    #[must_use]
    pub fn is_kernel_enforced(&self) -> bool {
        self.enforced
            && matches!(
                self.enforcement_level,
                EnforcementLevel::Kernel | EnforcementLevel::KernelSupervised
            )
    }

    /// Serialize this attestation into the JSON value stored at the receipt
    /// `metadata["sandbox"]` slot.
    pub fn to_metadata_value(&self) -> Result<JsonValue> {
        Ok(serde_json::to_value(self)?)
    }

    /// Deserialize an attestation from the value held in a receipt's
    /// `metadata["sandbox"]` slot.
    pub fn from_metadata_value(value: &JsonValue) -> Result<Self> {
        Ok(serde_json::from_value(value.clone())?)
    }
}

/// Attach `attestation` into `receipt`'s `metadata["sandbox"]` slot.
///
/// Uses the receipt's deep metadata merge so any sibling metadata keys are
/// preserved. The serialized shape is exactly what
/// [`crate::receipt::SignedReceipt::is_kernel_enforced`] and
/// [`crate::receipt::SignedReceipt::enforcement_level`] consume.
pub fn attach_sandbox_attestation(
    receipt: Receipt,
    attestation: &SandboxAttestation,
) -> Result<Receipt> {
    let value = attestation.to_metadata_value()?;
    Ok(receipt.merge_metadata(serde_json::json!({ "sandbox": value })))
}

/// Read the [`SandboxAttestation`] stored in `receipt`'s `metadata["sandbox"]`
/// slot, if present and well-formed.
#[must_use]
pub fn read_sandbox_attestation(receipt: &Receipt) -> Option<SandboxAttestation> {
    let sandbox = receipt.metadata.as_ref()?.get("sandbox")?;
    serde_json::from_value(sandbox.clone()).ok()
}

/// Enforcement mechanism.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    None,
    Kernel,
    KernelSupervised,
    Degraded,
}

impl std::fmt::Display for EnforcementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforcementLevel::None => write!(f, "none"),
            EnforcementLevel::Kernel => write!(f, "kernel"),
            EnforcementLevel::KernelSupervised => write!(f, "kernel_supervised"),
            EnforcementLevel::Degraded => write!(f, "degraded"),
        }
    }
}

impl std::str::FromStr for EnforcementLevel {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "none" => Ok(EnforcementLevel::None),
            "kernel" => Ok(EnforcementLevel::Kernel),
            "kernel_supervised" => Ok(EnforcementLevel::KernelSupervised),
            "degraded" => Ok(EnforcementLevel::Degraded),
            _ => Err(format!("unknown enforcement level: {s}")),
        }
    }
}

/// Platform sandbox information.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub name: String,
    pub mechanisms: Vec<String>,
    pub abi_version: Option<u32>,
    pub details: String,
}

impl Serialize for PlatformInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count =
            3 + usize::from(self.abi_version.is_some()) + usize::from(!self.mechanisms.is_empty());
        let mut state = serializer.serialize_struct("PlatformInfo", field_count)?;
        state.serialize_field("name", &self.name)?;
        if let Some(mechanism) = self.mechanisms.first() {
            state.serialize_field("mechanism", mechanism)?;
        }
        state.serialize_field("mechanisms", &self.mechanisms)?;
        if let Some(abi_version) = self.abi_version {
            state.serialize_field("abi_version", &abi_version)?;
        }
        state.serialize_field("details", &self.details)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PlatformInfo {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PlatformInfoFields {
            name: String,
            #[serde(default)]
            mechanism: Option<String>,
            #[serde(default)]
            mechanisms: Vec<String>,
            abi_version: Option<u32>,
            details: String,
        }

        let fields = PlatformInfoFields::deserialize(deserializer)?;
        let mut mechanisms = fields.mechanisms;
        if mechanisms.is_empty() {
            if let Some(mechanism) = fields.mechanism {
                mechanisms.push(mechanism);
            }
        } else if let Some(mechanism) = fields.mechanism
            && !mechanisms.iter().any(|value| value == &mechanism)
        {
            mechanisms.insert(0, mechanism);
        }

        Ok(Self {
            name: fields.name,
            mechanisms,
            abi_version: fields.abi_version,
            details: fields.details,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderApprovalStatus {
    NotRequired,
    Approved,
    Blocked,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAvailability {
    Unavailable,
    Inactive,
    Active,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderState {
    pub provider: String,
    pub installed: bool,
    pub approval_status: ProviderApprovalStatus,
    pub active: bool,
    pub healthy: bool,
    pub availability: ProviderAvailability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_healthy_timestamp: Option<String>,
}

impl ProviderState {
    #[must_use]
    pub fn active(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some(Utc::now().to_rfc3339()),
        }
    }

    #[must_use]
    pub fn active_without_approval(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::NotRequired,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some(Utc::now().to_rfc3339()),
        }
    }

    #[must_use]
    pub fn unavailable(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: false,
            approval_status: ProviderApprovalStatus::Unknown,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn unavailable_without_approval(
        provider: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            installed: false,
            approval_status: ProviderApprovalStatus::NotRequired,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn unknown(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: false,
            approval_status: ProviderApprovalStatus::Unknown,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn degraded(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: false,
            availability: ProviderAvailability::Degraded,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }
}

/// Runtime enforcement state captured after execution completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRuntimeState {
    pub supported: bool,
    pub applied: bool,
    pub supervised_requested: bool,
    pub supervised_active: bool,
    #[serde(default = "legacy_contract_default")]
    pub contract: String,
    #[serde(default = "legacy_authorization_model_default")]
    pub authorization_model: String,
    #[serde(default)]
    pub fd_injection_equivalent: bool,
    #[serde(default)]
    pub fail_open_possible: bool,
    #[serde(default)]
    pub deadline_miss_count: u64,
    #[serde(default)]
    pub dropped_event_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_states: Vec<ProviderState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl SandboxRuntimeState {
    /// Static (unsupervised) kernel-sandbox runtime state.
    ///
    /// `supported` is supplied by the caller rather than read from the live
    /// `nono` sandbox support probe (the upstream OS binding is dropped here).
    #[must_use]
    pub fn static_mode(supported: bool, applied: bool, failure_reason: Option<String>) -> Self {
        let mut state = Self {
            supported,
            applied,
            supervised_requested: false,
            supervised_active: false,
            contract: "static_kernel_sandbox".to_string(),
            authorization_model: "none".to_string(),
            fd_injection_equivalent: false,
            fail_open_possible: false,
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: Vec::new(),
            provider_states: default_provider_states(applied),
            failure_reason,
        };
        if !state.applied {
            state
                .degraded_reasons
                .push("sandbox_apply_failed".to_string());
        }
        state
    }

    /// Supervised kernel-sandbox runtime state.
    #[must_use]
    pub fn supervised_mode(
        supported: bool,
        applied: bool,
        supervised_active: bool,
        failure_reason: Option<String>,
    ) -> Self {
        let mut state = Self {
            supported,
            applied,
            supervised_requested: true,
            supervised_active,
            contract: supervised_contract_name().to_string(),
            authorization_model: supervised_authorization_model().to_string(),
            fd_injection_equivalent: cfg!(target_os = "linux"),
            fail_open_possible: cfg!(target_os = "macos"),
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: Vec::new(),
            provider_states: default_provider_states(applied),
            failure_reason,
        };

        if !applied {
            state
                .degraded_reasons
                .push("sandbox_apply_failed".to_string());
        }
        if !supervised_active {
            state
                .degraded_reasons
                .push(supervised_unavailable_reason().to_string());
        }
        state
    }

    /// Supervised launch refused during preflight (no live authorization provider).
    #[must_use]
    pub fn supervised_preflight_refused(
        supported: bool,
        failure_reason: impl Into<String>,
    ) -> Self {
        Self {
            supported,
            applied: false,
            supervised_requested: true,
            supervised_active: false,
            contract: unavailable_supervised_contract_name().to_string(),
            authorization_model: "none".to_string(),
            fd_injection_equivalent: false,
            fail_open_possible: false,
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: vec![
                supervised_unavailable_reason().to_string(),
                "supervised_launch_refused_without_live_authorization_provider".to_string(),
            ],
            provider_states: default_provider_states(false),
            failure_reason: Some(failure_reason.into()),
        }
    }

    #[must_use]
    pub fn with_degraded_reason(mut self, reason: impl Into<String>) -> Self {
        self.degraded_reasons.push(reason.into());
        self
    }

    #[must_use]
    pub fn with_deadline_miss_count(mut self, deadline_miss_count: u64) -> Self {
        self.deadline_miss_count = deadline_miss_count;
        if deadline_miss_count > 0 {
            self.degraded_reasons
                .push("authorization_deadline_missed".to_string());
        }
        self
    }

    #[must_use]
    pub fn with_dropped_event_count(mut self, dropped_event_count: u64) -> Self {
        self.dropped_event_count = dropped_event_count;
        if dropped_event_count > 0 {
            self.degraded_reasons
                .push("dropped_enforcement_events".to_string());
        }
        self
    }

    pub fn set_dropped_event_count(&mut self, dropped_event_count: u64) {
        self.dropped_event_count = dropped_event_count;
        if dropped_event_count > 0
            && !self
                .degraded_reasons
                .iter()
                .any(|reason| reason == "dropped_enforcement_events")
        {
            self.degraded_reasons
                .push("dropped_enforcement_events".to_string());
        }
    }

    #[must_use]
    pub fn with_provider_states(mut self, provider_states: Vec<ProviderState>) -> Self {
        self.provider_states = provider_states;
        self
    }
}

/// Snapshot of filesystem and network capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub fs: Vec<FsCapSnapshot>,
    pub network_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation_backend_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    pub signal_mode: String,
    pub blocked_commands: Vec<String>,
    pub extensions_enabled: bool,
}

/// Serialized filesystem capability entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapSnapshot {
    pub original: String,
    pub resolved: String,
    pub access: String,
    pub is_file: bool,
}

/// A denial with timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedDenial {
    pub path: String,
    pub access: String,
    pub reason: String,
    pub timestamp: String,
}

/// Supervisor enforcement statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupervisorStats {
    pub enabled: bool,
    pub backend: String,
    pub requests_total: u64,
    pub requests_granted: u64,
    pub requests_denied: u64,
    #[serde(default)]
    pub deadline_miss_count: u64,
    #[serde(default)]
    pub dropped_event_count: u64,
    pub never_grant_blocks: u64,
    pub rate_limit_blocks: u64,
}

/// Audit trail entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub path: String,
    pub access: String,
    pub decision: String,
    pub backend: String,
    pub duration_ms: u64,
}

fn legacy_contract_default() -> String {
    "legacy_attestation".to_string()
}

fn legacy_authorization_model_default() -> String {
    "unknown".to_string()
}

fn platform_mechanisms(runtime: &SandboxRuntimeState) -> Vec<String> {
    if cfg!(target_os = "macos") {
        let mut mechanisms = vec!["seatbelt".to_string()];
        for provider in runtime
            .provider_states
            .iter()
            .filter(|provider| provider.active)
        {
            match provider.provider.as_str() {
                "endpoint_security" => {
                    push_unique_mechanism(&mut mechanisms, "endpoint_security_contract")
                }
                "network_extension" => {
                    push_unique_mechanism(&mut mechanisms, "network_extension_contract")
                }
                _ => {}
            }
        }
        mechanisms
    } else if cfg!(target_os = "linux") {
        let mut mechanisms = vec!["landlock".to_string()];
        if runtime.supervised_active {
            mechanisms.push("seccomp_notify".to_string());
        }
        mechanisms
    } else {
        vec!["none".to_string()]
    }
}

fn push_unique_mechanism(mechanisms: &mut Vec<String>, mechanism: &str) {
    if !mechanisms.iter().any(|existing| existing == mechanism) {
        mechanisms.push(mechanism.to_string());
    }
}

fn effective_enforcement_level(runtime: &SandboxRuntimeState) -> EnforcementLevel {
    if !runtime.applied {
        return EnforcementLevel::None;
    }

    let has_degraded_runtime = !runtime.degraded_reasons.is_empty()
        || runtime.deadline_miss_count > 0
        || runtime.dropped_event_count > 0;
    let has_degraded_provider = runtime.provider_states.iter().any(|provider| {
        !provider.active || !provider.healthy || !provider.degraded_reasons.is_empty()
    });
    if has_degraded_runtime || has_degraded_provider {
        return EnforcementLevel::Degraded;
    }

    if runtime.supervised_requested && !runtime.supervised_active {
        return EnforcementLevel::Degraded;
    }

    if runtime.supervised_requested && runtime.supervised_active {
        EnforcementLevel::KernelSupervised
    } else {
        EnforcementLevel::Kernel
    }
}

fn default_provider_states(applied: bool) -> Vec<ProviderState> {
    if cfg!(target_os = "macos") {
        vec![if applied {
            ProviderState::active_without_approval("seatbelt")
        } else {
            ProviderState::unavailable_without_approval("seatbelt", "sandbox_apply_failed")
        }]
    } else {
        Vec::new()
    }
}

fn supervised_contract_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos_endpoint_security_auth_contract"
    } else if cfg!(target_os = "linux") {
        "linux_seccomp_notify_fd_injection"
    } else {
        "supervised_contract_unavailable"
    }
}

fn unavailable_supervised_contract_name() -> &'static str {
    "supervised_contract_unavailable"
}

fn supervised_unavailable_reason() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos_authorization_contract_unavailable"
    } else {
        "supervised_interception_inactive"
    }
}

fn supervised_authorization_model() -> &'static str {
    if cfg!(target_os = "macos") {
        "auth_open_point_in_time"
    } else if cfg!(target_os = "linux") {
        "fd_injection"
    } else {
        "none"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hashing::Hash;
    use crate::receipt::{Receipt, SignedReceipt, Verdict};
    use crate::signing::Keypair;

    fn sample_capabilities() -> CapabilitySnapshot {
        CapabilitySnapshot {
            fs: vec![FsCapSnapshot {
                original: "/work".to_string(),
                resolved: "/work".to_string(),
                access: "read_write".to_string(),
                is_file: false,
            }],
            network_mode: "blocked".to_string(),
            mediation_backend_hint: None,
            proxy_port: Some(8080),
            signal_mode: "isolated".to_string(),
            blocked_commands: vec!["rm".to_string()],
            extensions_enabled: false,
        }
    }

    fn sample_platform() -> PlatformInfo {
        PlatformInfo {
            name: "test_os".to_string(),
            mechanisms: vec!["seatbelt".to_string()],
            abi_version: None,
            details: "test sandbox".to_string(),
        }
    }

    fn sample_attestation(applied: bool) -> SandboxAttestation {
        SandboxAttestation::new(
            sample_platform(),
            SandboxRuntimeState::static_mode(true, applied, None),
            sample_capabilities(),
        )
    }

    #[test]
    fn test_new_static_mode_is_kernel_enforced() {
        let attestation = sample_attestation(true);
        assert_eq!(attestation.enforcement_level, EnforcementLevel::Kernel);
        assert!(attestation.enforced);
        assert!(attestation.is_kernel_enforced());
    }

    #[test]
    fn test_failed_apply_is_not_enforced() {
        let attestation = SandboxAttestation::new(
            sample_platform(),
            SandboxRuntimeState::static_mode(true, false, Some("apply failed".to_string())),
            sample_capabilities(),
        );
        assert_eq!(attestation.enforcement_level, EnforcementLevel::None);
        assert!(!attestation.enforced);
        assert!(!attestation.is_kernel_enforced());
        assert_eq!(
            attestation.runtime.failure_reason.as_deref(),
            Some("apply failed")
        );
    }

    #[test]
    fn test_supervised_mode_is_kernel_supervised() {
        let attestation = SandboxAttestation::new(
            sample_platform(),
            SandboxRuntimeState::supervised_mode(true, true, true, None),
            sample_capabilities(),
        );
        assert_eq!(
            attestation.enforcement_level,
            EnforcementLevel::KernelSupervised
        );
        assert!(attestation.is_kernel_enforced());
    }

    #[test]
    fn test_dropped_events_degrade_attestation() {
        let mut attestation = sample_attestation(true);
        attestation.runtime.set_dropped_event_count(3);
        attestation.recompute_status();

        assert_eq!(attestation.enforcement_level, EnforcementLevel::Degraded);
        assert!(!attestation.enforced);
        assert!(!attestation.is_kernel_enforced());
        assert_eq!(attestation.runtime.dropped_event_count, 3);
    }

    #[test]
    fn test_serde_round_trip() {
        let attestation = sample_attestation(true);
        let json = serde_json::to_value(&attestation).unwrap();

        // Lands in the shape the receipt reader consumes.
        assert!(json["enforced"].as_bool().unwrap());
        assert_eq!(json["enforcement_level"].as_str(), Some("kernel"));
        assert_eq!(json["capabilities"]["proxy_port"].as_u64(), Some(8080));
        assert!(json["platform"]["mechanisms"].is_array());

        let restored: SandboxAttestation = serde_json::from_value(json).unwrap();
        assert_eq!(restored.enforcement_level, attestation.enforcement_level);
        assert_eq!(restored.enforced, attestation.enforced);
        assert_eq!(
            restored.capabilities.proxy_port,
            attestation.capabilities.proxy_port
        );
    }

    #[test]
    fn test_enforcement_level_string_round_trip() {
        for level in [
            EnforcementLevel::None,
            EnforcementLevel::Kernel,
            EnforcementLevel::KernelSupervised,
            EnforcementLevel::Degraded,
        ] {
            let parsed: EnforcementLevel = level.to_string().parse().unwrap();
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn test_platform_info_deserializes_legacy_mechanism_only() {
        let parsed: PlatformInfo = serde_json::from_value(serde_json::json!({
            "name": "macos",
            "mechanism": "seatbelt",
            "details": "legacy seatbelt sandbox"
        }))
        .unwrap();
        assert_eq!(parsed.mechanisms, vec!["seatbelt".to_string()]);
    }

    #[test]
    fn test_attach_and_read_round_trips_through_receipt() {
        let attestation = sample_attestation(true);
        let receipt = attach_sandbox_attestation(
            Receipt::new(Hash::zero(), Verdict::pass()),
            &attestation,
        )
        .unwrap();

        let read = read_sandbox_attestation(&receipt).expect("sandbox slot present");
        assert!(read.is_kernel_enforced());
        assert_eq!(read.enforcement_level, EnforcementLevel::Kernel);
    }

    #[test]
    fn test_attach_preserves_sibling_metadata() {
        let attestation = sample_attestation(true);
        let receipt = Receipt::new(Hash::zero(), Verdict::pass())
            .with_metadata(serde_json::json!({ "ambush": { "ruleset": "code-agent" } }));
        let receipt = attach_sandbox_attestation(receipt, &attestation).unwrap();

        let metadata = receipt.metadata.as_ref().unwrap();
        assert_eq!(
            metadata.pointer("/ambush/ruleset"),
            Some(&serde_json::json!("code-agent"))
        );
        assert!(metadata.pointer("/sandbox/enforced").unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_signed_receipt_reader_sees_kernel_enforcement() {
        // Proves serialization lands in the metadata["sandbox"] slot the
        // pre-existing SignedReceipt::is_kernel_enforced reader consumes.
        let keypair = Keypair::generate();

        let enforced = attach_sandbox_attestation(
            Receipt::new(Hash::zero(), Verdict::pass()),
            &sample_attestation(true),
        )
        .unwrap();
        let signed = SignedReceipt::sign(enforced, &keypair).unwrap();
        assert!(signed.is_kernel_enforced());
        assert_eq!(signed.enforcement_level(), Some("kernel".to_string()));

        let not_enforced = attach_sandbox_attestation(
            Receipt::new(Hash::zero(), Verdict::pass()),
            &sample_attestation(false),
        )
        .unwrap();
        let signed = SignedReceipt::sign(not_enforced, &keypair).unwrap();
        assert!(!signed.is_kernel_enforced());
        assert_eq!(signed.enforcement_level(), Some("none".to_string()));
    }

    #[test]
    fn test_no_sandbox_slot_reads_none() {
        let receipt = Receipt::new(Hash::zero(), Verdict::pass());
        assert!(read_sandbox_attestation(&receipt).is_none());
    }
}
