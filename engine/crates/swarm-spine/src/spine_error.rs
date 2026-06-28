//! Error types for spine envelope and checkpoint operations.

use thiserror::Error;

/// Errors that can occur during spine operations.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SpineError {
    #[error("invalid issuer string: {0}")]
    InvalidIssuer(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("invalid witness signature")]
    InvalidWitnessSignature,

    #[error("envelope hash mismatch: expected {expected}, computed {computed}")]
    HashMismatch { expected: String, computed: String },

    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    #[error("chain integrity violation for issuer {issuer}: {reason}")]
    ChainIntegrityViolation { issuer: String, reason: String },

    #[error("JSON error: {0}")]
    Json(String),

    #[error(transparent)]
    Crypto(#[from] swarm_crypto::CryptoError),
}

impl From<serde_json::Error> for SpineError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

/// Result type for spine operations.
pub type SpineResult<T> = std::result::Result<T, SpineError>;
