//! Typed audit and replay records for the v1 runtime slice.
//!
//! The first milestone does not need the full upstream envelope or
//! checkpoint machinery. It needs a small, serializable record format
//! that captures what happened in the critical lane and can be replayed.
//!
//! ## Owns
//!
//! - The signed envelope format and its verification ([`envelope`]), the
//!   issuer chain ([`chain`]) and the witnessed checkpoints over it
//!   ([`checkpoint`]). These decide what "this happened and has not been
//!   altered" means for the whole system.
//! - The audit record shapes for one handled event: [`PolicyRecord`],
//!   [`AuditResponseRecord`] and the replay bundle store ([`store`]).
//! - Durable incident and investigation records ([`incident`],
//!   [`investigation`]) — the persisted evidence, not the analysis that
//!   produces it.
//!
//! ## Does not own
//!
//! - Deciding anything. It records verdicts from `swarm-policy` and receipts
//!   from `swarm-response`; it does not authorize, execute, or re-rank.
//! - Correlation. `CorrelatedIncident` is a record type defined here and
//!   *assembled* by `swarm-runtime`'s correlation module, which depends on this
//!   crate and not the other way round.
//! - Cryptographic primitives, which are `swarm-crypto`'s.
//! - Transport. This crate is in the trusted computing base (ADR 0009) and must
//!   never name `axum`, `clap`, `hyper` or `reqwest` in any dependency section,
//!   in any dependency kind.
//! - Anything downstream of the TCB: `swarm-runtime`, `swarm-runtime-http`,
//!   `swarm-cli`, `swarm-pheromone`, `swarm-agents` and the ingest crates all
//!   sit above this one, dev-dependencies included.
//!
//! ONE MEASURED DEVIATION, recorded rather than hidden: this crate declares
//! `swarm-response` (its envelopes embed `ResponseReceipt` and
//! `ResponseFailure`), and `swarm-response` declares `reqwest` for the HTTP EDR
//! adapter, so `cargo tree -p swarm-spine -i reqwest -e normal` prints a path
//! today and the TCB reaches `reqwest` and `hyper` on its resolved normal
//! graph. Those two edges are on the accepted baseline in
//! `tools/check-workspace-layering.sh`; a third fails the build. ADR 0009 says
//! what closes them.
//!
//! The bans above are enforced by `tools/check-workspace-layering.sh`, which
//! runs in CI and carries a fixture proving it fails when they are broken.

pub mod chain;
pub mod checkpoint;
pub mod envelope;
pub mod hypothesis_graph_store;
pub mod incident;
pub mod investigation;
pub mod spine_error;
pub mod store;
pub mod strategy_memory;

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
pub use hypothesis_graph_store::{
    ConfiguredHypothesisGraphStore, DurableTaskRecord, FileHypothesisGraphStore, GraphStoreError,
    GraphStoreRevision, GraphStoreSnapshot, GraphStoreState, HypothesisGraphStore,
    MemoryHypothesisGraphStore, TaskClaimResult, TaskFailure, TaskMutationResult, TaskStore,
    TaskTerminalResult, validate_task_logical_identity, validate_task_terminal_envelope,
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
pub use strategy_memory::{
    FileStrategyMemoryStore, MemoryStrategyMemoryStore, RetrievedStrategyMemory,
    StrategyMemoryAppendResult, StrategyMemoryExpiryRecord, StrategyMemoryRecord,
    StrategyMemoryStore, StrategyMemoryStoreError, applicable_strategy_memory,
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
