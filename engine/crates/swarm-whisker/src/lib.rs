//! Whisker agents — streaming detection on the hot path.
//!
//! Whiskers are long-running, stateful stream processors.
//! They consume telemetry (eBPF syscalls, network flows, tool invocations),
//! apply fast Rust-native detection (embedding similarity, rule matching,
//! statistical anomaly), and deposit pheromones on detection.
//!
//! No LLM per signal. LLM only for ambiguous signals routed to Stalkers.

pub mod behavioral_anomaly;
pub mod composite;
pub mod credential_access;
pub mod detector;
pub mod dns_exfiltration;
pub mod fileless_execution;
pub mod infrastructure_anomaly;
pub mod lateral_movement;
pub mod network_connect;
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

pub use behavioral_anomaly::{BehavioralAnomalyDetector, BehavioralAnomalyProfile};
pub use composite::CompositeDetector;
pub use credential_access::{CredentialAccessDetector, CredentialAccessProfile};
pub use detector::{
    AuthenticationEventData, DetectionFinding, DetectionStrategy, DnsQueryEvent, ExhaustedResource,
    FilePersistenceEvent, InfrastructureHealthEvent, NetworkConnectEvent, ProcessMemoryAccessEvent,
    ProcessStartEvent, RegistryAccessEvent, RegistryPersistenceEvent, ResourceExhaustionEvent,
    SuspiciousProcessTreeDetector, SuspiciousProcessTreeProfile, TelemetryEvent,
    TelemetryEventPredicate, TelemetryPayload, ThermalAnomalyEvent, ThermalSeverity,
};
pub use dns_exfiltration::{DnsExfiltrationDetector, DnsExfiltrationProfile};
pub use fileless_execution::{FilelessExecutionDetector, FilelessExecutionProfile};
pub use infrastructure_anomaly::{InfrastructureAnomalyDetector, InfrastructureAnomalyProfile};
pub use lateral_movement::{LateralMovementDetector, LateralMovementProfile};
pub use network_connect::{NetworkConnectDetector, NetworkConnectProfile};
pub use persistence::{PersistenceDetector, PersistenceProfile};
pub use supply_chain::{SupplyChainDetector, SupplyChainProfile};
pub use suspicious_scripting::{SuspiciousScriptingDetector, SuspiciousScriptingProfile};

#[cfg(test)]
mod tests {
    use super::{
        BehavioralAnomalyDetector, CredentialAccessDetector, DnsExfiltrationDetector,
        FilelessExecutionDetector, InfrastructureAnomalyDetector, LateralMovementDetector,
        NetworkConnectDetector, PersistenceDetector, SupplyChainDetector,
        SuspiciousProcessTreeDetector, SuspiciousScriptingDetector,
    };

    #[test]
    fn default_detectors_construct_without_panic() {
        let _ = SuspiciousProcessTreeDetector::default();
        let _ = DnsExfiltrationDetector::default();
        let _ = FilelessExecutionDetector::default();
        let _ = BehavioralAnomalyDetector::default();
        let _ = LateralMovementDetector::default();
        let _ = CredentialAccessDetector::default();
        let _ = SuspiciousScriptingDetector::default();
        let _ = PersistenceDetector::default();
        let _ = SupplyChainDetector::default();
        let _ = NetworkConnectDetector::default();
        let _ = InfrastructureAnomalyDetector::default();
    }
}
