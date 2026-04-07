use swarm_core::TelemetryBridgeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("gRPC error: {0}")]
    Grpc(String),

    #[error("failed to map Tetragon event: {0}")]
    MappingFailed(String),

    #[error("output channel closed")]
    ChannelClosed,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<TelemetryBridgeError> for Error {
    fn from(value: TelemetryBridgeError) -> Self {
        match value {
            TelemetryBridgeError::Connection(message) => Self::Grpc(message),
            TelemetryBridgeError::Mapping(message) => Self::MappingFailed(message),
            TelemetryBridgeError::Schema(message) => Self::MappingFailed(message),
            TelemetryBridgeError::Unavailable(message) => Self::Grpc(message),
        }
    }
}
