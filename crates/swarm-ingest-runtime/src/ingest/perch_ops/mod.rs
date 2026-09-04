//! Engine operations behind the first-card operator routes — the daemon half of
//! B3r (`reviewed`); B3i (`mint`) and B3 (`feedback`) join as their real modules
//! land (12-PLAN-FIRST-CARD.md Tasks 10–12, 12-BACKEND-BILL-API.md §8–§10).
//!
//! Every function here takes the live [`IngestState`] and reads the SAME
//! incident store the platform status route reads, so a measurement written
//! through these routes is visible to the tuning report by construction.

pub mod feedback;
pub mod holds;
pub mod mint;
pub mod reviewed;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test_support;

use super::providence_handlers::ProvidenceFeedbackError;
use axum::http::StatusCode;
use swarm_spine::IncidentStoreError;

/// Failure of a perch engine operation, in the three classes the HTTP layer
/// maps to status codes (`not_found`, `bad_request`, `internal`).
#[derive(Debug, thiserror::Error)]
pub enum PerchOpsError {
    /// The incident or the finding inside it does not exist — the
    /// "not yet correlated" wall the console renders as a disabled row.
    #[error("{0}")]
    NotFound(String),
    /// The request violated the minting or feedback contract.
    #[error("{0}")]
    BadRequest(String),
    /// A store or substrate failure the caller cannot repair by editing the request.
    #[error("{0}")]
    Internal(String),
}

impl From<IncidentStoreError> for PerchOpsError {
    fn from(error: IncidentStoreError) -> Self {
        Self::Internal(error.to_string())
    }
}

impl From<serde_json::Error> for PerchOpsError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

/// The webhook path's typed failure, by status: its `not_found` (an incident,
/// a member, or the replay bundle `investigate` re-queues) stays a not-found,
/// its `bad_request` stays a bad request, everything else is internal.
impl From<ProvidenceFeedbackError> for PerchOpsError {
    fn from(error: ProvidenceFeedbackError) -> Self {
        match error.status {
            StatusCode::NOT_FOUND => Self::NotFound(error.error),
            StatusCode::BAD_REQUEST => Self::BadRequest(error.error),
            _ => Self::Internal(error.error),
        }
    }
}
