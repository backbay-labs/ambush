#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod cloudtrail;
pub mod generic_json;
pub mod source;

pub use cloudtrail::CloudTrailBridge;
pub use generic_json::GenericJsonBridge;
pub use source::{JsonRecordSource, JsonRecordSourceError};

use swarm_core::{BridgeHealth, TelemetryBridgeError, TelemetryEvent, TelemetryPayload};

#[derive(Debug, thiserror::Error)]
pub enum JsonBridgeConfigError {
    #[error(transparent)]
    Source(#[from] JsonRecordSourceError),

    #[error(transparent)]
    Bridge(#[from] TelemetryBridgeError),
}

fn validate_event_schema(event: &TelemetryEvent, source_id: &str) -> bool {
    if event.source != source_id {
        return false;
    }
    if event.event_id.trim().is_empty() || event.timestamp <= 0 {
        return false;
    }

    match &event.payload {
        TelemetryPayload::ProcessStart(process) => {
            !process.parent_process.trim().is_empty()
                && !process.process_name.trim().is_empty()
                && !process.command_line.trim().is_empty()
        }
        TelemetryPayload::ProcessMemoryAccess(access) => {
            !access.source_process.trim().is_empty()
                && !access.target_process.trim().is_empty()
                && !access.allocation_type.trim().is_empty()
                && !access.protection_flags.is_empty()
                && access.region_size > 0
        }
        TelemetryPayload::NetworkConnect(connect) => {
            !connect.process_name.trim().is_empty()
                && !connect.destination_ip.trim().is_empty()
                && !connect.protocol.trim().is_empty()
        }
        TelemetryPayload::DnsQuery(query) => {
            !query.query_name.trim().is_empty() && !query.query_type.trim().is_empty()
        }
        TelemetryPayload::RegistryAccess(access) => {
            !access.process_name.trim().is_empty()
                && !access.registry_path.trim().is_empty()
                && !access.access_type.trim().is_empty()
        }
        TelemetryPayload::RegistryPersistence(persistence) => {
            !persistence.process_name.trim().is_empty()
                && !persistence.registry_path.trim().is_empty()
                && !persistence.access_type.trim().is_empty()
        }
        TelemetryPayload::FilePersistence(file) => {
            !file.file_path.trim().is_empty()
                && !file.operation.trim().is_empty()
                && !file.process_name.trim().is_empty()
        }
        TelemetryPayload::AuthenticationEvent(auth) => !auth.auth_type.trim().is_empty(),
        TelemetryPayload::InfrastructureHealth(_)
        | TelemetryPayload::ThermalAnomaly(_)
        | TelemetryPayload::ResourceExhaustion(_) => false,
    }
}

fn record_error(health: &mut BridgeHealth, message: impl Into<String>) -> TelemetryBridgeError {
    let message = message.into();
    health.record_error(message.clone());
    TelemetryBridgeError::Mapping(message)
}
