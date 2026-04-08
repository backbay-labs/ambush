//! Whisker agents — streaming detection on the hot path.
//!
//! Whiskers are long-running, stateful stream processors.
//! They consume telemetry (eBPF syscalls, network flows, tool invocations),
//! apply fast Rust-native detection (embedding similarity, rule matching,
//! statistical anomaly), and deposit pheromones on detection.
//!
//! No LLM per signal. LLM only for ambiguous signals routed to Stalkers.

pub mod composite;
pub mod credential_access;
pub mod detector;
pub mod dns_exfiltration;
pub mod lateral_movement;
pub mod persistence;
pub mod stream;
pub mod supply_chain;
pub mod suspicious_scripting;

#[derive(Debug, Clone)]
pub struct ProfileValidationError {
    pub profile: &'static str,
    pub field: &'static str,
    pub reason: String,
}

impl std::fmt::Display for ProfileValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{} {}", self.profile, self.field, self.reason)
    }
}

impl std::error::Error for ProfileValidationError {}

pub(crate) fn validate_confidence_thresholds(
    profile: &'static str,
    high: f64,
    medium: f64,
) -> Result<(), ProfileValidationError> {
    if !(0.0..=1.0).contains(&high) {
        return Err(ProfileValidationError {
            profile,
            field: "high_confidence_threshold",
            reason: "must be between 0.0 and 1.0".to_string(),
        });
    }
    if !(0.0..=1.0).contains(&medium) {
        return Err(ProfileValidationError {
            profile,
            field: "medium_confidence_threshold",
            reason: "must be between 0.0 and 1.0".to_string(),
        });
    }
    if high < medium {
        return Err(ProfileValidationError {
            profile,
            field: "high_confidence_threshold",
            reason: "must be greater than or equal to medium_confidence_threshold".to_string(),
        });
    }
    Ok(())
}

pub use composite::CompositeDetector;
pub use credential_access::{CredentialAccessDetector, CredentialAccessProfile};
pub use detector::{
    AuthenticationEventData, DetectionFinding, DetectionStrategy, DnsQueryEvent,
    FilePersistenceEvent, NetworkConnectEvent, ProcessStartEvent, RegistryAccessEvent,
    RegistryPersistenceEvent, SuspiciousProcessTreeDetector, SuspiciousProcessTreeProfile,
    TelemetryEvent, TelemetryPayload,
};
pub use dns_exfiltration::{DnsExfiltrationDetector, DnsExfiltrationProfile};
pub use lateral_movement::{LateralMovementDetector, LateralMovementProfile};
pub use persistence::{PersistenceDetector, PersistenceProfile};
pub use supply_chain::{SupplyChainDetector, SupplyChainProfile};
pub use suspicious_scripting::{SuspiciousScriptingDetector, SuspiciousScriptingProfile};
