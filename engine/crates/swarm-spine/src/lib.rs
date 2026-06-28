//! Typed audit and replay records for the v1 runtime slice.
//!
//! The first milestone does not need the full upstream envelope or
//! checkpoint machinery. It needs a small, serializable record format
//! that captures what happened in the critical lane and can be replayed.

pub mod chain;
pub mod checkpoint;
pub mod envelope;
pub mod incident;
pub mod investigation;
pub mod spine_error;
pub mod store;

use serde::{Deserialize, Serialize};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::ResponseRehearsalPreview;
use swarm_policy::{ActionRequest, CapabilityLease, PolicyVerdict};
use swarm_response::{ResponseFailure, ResponseReceipt};
use swarm_whisker::{DetectionFinding, TelemetryEvent};

pub use chain::{ChainLinkVerdict, IssuerChainHead, chain_head_from_envelope, verify_chain_link};
pub use checkpoint::{
    CHECKPOINT_STATEMENT_SCHEMA_V1, checkpoint_hash, checkpoint_statement,
    checkpoint_witness_message, sign_checkpoint_statement, verify_witness_signature,
};
pub use envelope::{
    ENVELOPE_SCHEMA_V1, build_signed_envelope, compute_envelope_hash, compute_envelope_hash_hex,
    envelope_signing_bytes, extract_envelope_hash, issuer_from_keypair, now_rfc3339,
    parse_issuer_pubkey_hex, sign_envelope, verify_envelope,
};
pub use incident::{
    AnalystFeedbackAuditEntry, ConfiguredIncidentStore, CorrelatedIncident, ExternalReference,
    FalsePositiveDetectorSummary, FalsePositiveHostSummary, FalsePositiveMeasurement,
    FalsePositiveMeasurementReport, FileIncidentStore, IncidentEvidenceLink,
    IncidentGraphDimension, IncidentLookup, IncidentMemberDecision, IncidentRecord, IncidentStore,
    IncidentStoreError, IncidentStoreHealth, MemoryIncidentStore,
    summarize_false_positive_measurements,
};
pub use investigation::{
    ConfiguredInvestigationBundleStore, FileInvestigationBundleStore, InvestigationBundle,
    InvestigationBundleLookup, InvestigationBundleRecord, InvestigationBundleStore,
    InvestigationDecision, InvestigationInterpretation, InvestigationPriority,
    InvestigationPriorityClass, InvestigationStatus, InvestigationStoreError,
    InvestigationStoreHealth, InvestigationVote, MemoryInvestigationBundleStore,
};
pub use spine_error::{SpineError, SpineResult};
pub use store::{
    ConfiguredReplayBundleStore, FileReplayBundleStore, MemoryReplayBundleStore,
    ReplayBundleLookup, ReplayBundleRecord, ReplayBundleStore, ReplayPreview, ReplayStoreError,
    ReplayStoreHealth,
};

/// Policy step captured in an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub verdict: PolicyVerdict,
    pub rule_name: String,
    pub reason: String,
    pub lease: Option<CapabilityLease>,
}

/// Response step captured in an audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditResponseRecord {
    Success(ResponseReceipt),
    Failure(ResponseFailure),
    Skipped { reason: String },
    GuardRejected { guard_name: String, reason: String },
}

/// Minimal auditable trail for one handled event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    pub trail_id: String,
    pub hunt_id: String,
    pub related_receipt_ids: Vec<String>,
    pub detection: DetectionFinding,
    pub policy: PolicyRecord,
    pub response: AuditResponseRecord,
    pub created_at_ms: i64,
}

/// File-backed bundle that can replay the critical path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBundle {
    pub bundle_id: String,
    pub event: TelemetryEvent,
    pub findings: Vec<DetectionFinding>,
    pub deposits: Vec<PheromoneDeposit>,
    pub action_request: ActionRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehearsal: Option<ResponseRehearsalPreview>,
    pub audit: AuditTrail,
}

impl AuditTrail {
    pub fn response_receipt_id(&self) -> Option<&str> {
        match &self.response {
            AuditResponseRecord::Success(receipt) => Some(&receipt.receipt_id),
            AuditResponseRecord::Failure(failure) => Some(&failure.receipt_id),
            AuditResponseRecord::Skipped { .. } => None,
            AuditResponseRecord::GuardRejected { .. } => None,
        }
    }

    pub fn response_kind(&self) -> &'static str {
        match &self.response {
            AuditResponseRecord::Success(_) => "success",
            AuditResponseRecord::Failure(_) => "failure",
            AuditResponseRecord::Skipped { .. } => "skipped",
            AuditResponseRecord::GuardRejected { .. } => "guard_rejected",
        }
    }

    pub fn all_receipt_ids(&self) -> Vec<String> {
        let mut receipt_ids = self.related_receipt_ids.clone();
        if let Some(receipt_id) = self.response_receipt_id()
            && !receipt_ids.iter().any(|existing| existing == receipt_id)
        {
            receipt_ids.push(receipt_id.to_string());
        }
        receipt_ids
    }
}

impl ReplayBundle {
    pub fn action_kind(&self) -> &'static str {
        self.action_request.action.kind()
    }

    pub fn is_rehearsal(&self) -> bool {
        self.rehearsal.is_some()
    }

    pub fn rehearsal_id(&self) -> Option<&str> {
        self.rehearsal
            .as_ref()
            .map(|preview| preview.rehearsal_id.as_str())
    }
}
