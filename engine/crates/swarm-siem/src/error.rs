//! Error types for swarm-siem transform and export operations.

use thiserror::Error;

/// Errors that can occur while transforming or exporting receipts.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SiemError {
    /// A receipt (or a mapped event) could not be serialized to its wire form.
    #[error("SIEM serialization error: {0}")]
    Serialization(String),

    /// The control-plane sink rejected or failed to deliver a payload.
    #[error("SIEM sink delivery failed: {0}")]
    Sink(String),
}

impl From<serde_json::Error> for SiemError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

/// Result type for swarm-siem operations.
pub type SiemResult<T> = std::result::Result<T, SiemError>;
