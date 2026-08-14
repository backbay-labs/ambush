//! The governance authority the dispatcher authorizes partition-time actions through.
//!
//! # Why this exists (SPLIT-03, phase 282)
//!
//! `dispatcher.rs` -- the composition root's agent loop -- used to hold an
//! `Arc<crate::tom_agent::GovernancePolicy>` and match on
//! `crate::tom_agent::GovernanceRuntimeEvent`, while `tom_agent` imports back into
//! the runtime. That coupling is bidirectional, so no extraction order resolves it;
//! the root has to stop naming the concrete governance agent.
//!
//! # Why this trait lives in `swarm-policy` and not `swarm_core::agent`
//!
//! [`GovernanceAuthority::authorize_partition_request`] must be handed the whole
//! [`ActionRequest`] -- the Tom implementation records the rejected request in its
//! partition activity log, not just the action kind -- and `ActionRequest` is defined
//! here, in a crate that already depends on `swarm-core` rather than the other way
//! round. Putting the trait in `swarm-core` would mean moving `ActionRequest` down
//! with it, which is a far larger change than breaking one cycle. `swarm-policy` is
//! the lowest crate that can name both `ActionRequest` and `AgentRole`, both the
//! dispatcher and the governance agent already depend on it, and authorizing a
//! destructive action during a partition is a policy decision by any reading.

use serde::{Deserialize, Serialize};
use swarm_core::agent::AgentRole;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};

use crate::{ActionRequest, static_gate::scope_for_response_action};

pub const GOVERNANCE_ACTION_REQUEST_SUBJECT_SCHEMA_VERSION: u32 = 1;
pub const GOVERNANCE_ACTION_REQUEST_SUBJECT_DOMAIN: &str =
    "swarm.governance.action-request.authorization.v1";

/// Canonical subject governed for one response request.
///
/// The two bearer artifacts are deliberately not part of the subject: the receipt
/// cannot hash itself, and the partition lease is verified through its own path.
/// Every other evidence field is retained. The domain and schema prevent this digest
/// from being confused with a release attestation, contingency lease, or later schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceActionRequestSubjectV1 {
    pub domain: String,
    pub schema_version: u32,
    pub hunt_id: HuntId,
    pub requested_by: AgentId,
    pub action: ResponseAction,
    pub scope: Option<String>,
    pub severity: Severity,
    pub evidence: serde_json::Value,
}

impl GovernanceActionRequestSubjectV1 {
    pub fn from_request(request: &ActionRequest) -> Self {
        let mut evidence = request.evidence.clone();
        if let Some(object) = evidence.as_object_mut() {
            object.remove("governance_receipt");
            object.remove("contingency_lease");
        }
        Self {
            domain: GOVERNANCE_ACTION_REQUEST_SUBJECT_DOMAIN.to_string(),
            schema_version: GOVERNANCE_ACTION_REQUEST_SUBJECT_SCHEMA_VERSION,
            hunt_id: request.hunt_id.clone(),
            requested_by: request.requested_by.clone(),
            action: request.action.clone(),
            scope: scope_for_response_action(&request.action),
            severity: request.severity,
            evidence,
        }
    }
}

/// One governance-originated runtime event, flattened to what the dispatcher publishes.
///
/// The concrete event enum stays private to the governance agent. Everything the
/// dispatcher ever read out of it -- the governing agent, the action-kind label, and
/// the serialized body -- is carried here, so the agent owns the mapping and the
/// dispatcher owns only the publishing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRuntimeEventRecord {
    /// Identifier of the governor that emitted the event.
    pub governing_agent_id: String,
    /// Role to attribute the event to on the runtime event bus.
    pub role: AgentRole,
    /// Stable action-kind label for the emitted runtime event.
    pub action_kind: String,
    /// Serialized event body.
    pub details: serde_json::Value,
}

/// Where the governance quorum currently sits on the partition/heal path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionState {
    Healthy,
    Degraded,
    Partitioned,
    Healing,
}

/// The governance authority's own account of itself, as operators read it.
///
/// Moved down here from the concrete governance agent in SPLIT-05, so
/// [`GovernanceAuthority::status_report`] can name its own return type. The ingest
/// health surface renders these eight fields into `/healthz` and reads nothing else
/// off the authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceStatusReport {
    pub partition_state: PartitionState,
    pub total_governors: usize,
    pub healthy_governors: usize,
    pub quorum_threshold: usize,
    pub active_contingency_leases: usize,
    pub unauthorized_partition_actions: usize,
    pub last_transition_at_ms: Option<i64>,
    pub last_reconciliation_report_id: Option<String>,
}

/// Not public API. Seals [`GovernanceAuthority`]; see the note on that trait.
#[doc(hidden)]
pub mod sealed {
    /// Supertrait of [`super::GovernanceAuthority`], carrying no contract of its own.
    ///
    /// Its only job is to make implementing `GovernanceAuthority` require naming a
    /// `#[doc(hidden)]` item, so the set of types that can authorize a destructive
    /// action during a governance partition stays enumerable and every addition is
    /// explicit.
    pub trait SealedGovernanceAuthority {}
}

/// Partition-time authorization and event drain, as the dispatcher needs them.
///
/// Deliberately narrow. Its authorization methods separate normal action approval,
/// governance veto, and partition contingency so no caller can use a generic
/// "accept either decision" verifier. [`GovernanceAuthority::status_report`] is the
/// read-only surface the ingest health endpoint uses.
///
/// # What the trait widened, and why it is sealed
///
/// This is a security-relevant extension point, and it did not exist before SPLIT-03.
/// The dispatcher used to install one concrete type, `tom_agent::GovernancePolicy`
/// (`swarm_runtime::` then, `swarm_agents::` since SPLIT-03 moved the role out), whose
/// enforcement logic is the only thing that could answer
/// [`GovernanceAuthority::authorize_partition_request`]. Returning a verified lease
/// is what lets a destructive action proceed while the governance quorum is
/// partitioned, so an arbitrary implementation installed through
/// `AgentDispatcher::with_governance_policy` could otherwise approve every
/// partition-time request without minting a contingency lease.
///
/// The trait is therefore sealed: it requires
/// [`sealed::SealedGovernanceAuthority`], which lives in a `#[doc(hidden)]` module and
/// is not part of the documented API. An implementer must write that impl too, so
/// every type that can render this verdict stays enumerable with
/// `grep -rn SealedGovernanceAuthority`, and adding one is a deliberate, reviewable
/// act rather than a side effect of depending on this crate.
///
/// The seal is a deliberate-act barrier, not a capability boundary. Rust cannot
/// restrict an impl to a named set of crates, and this trait must stay implementable
/// from whichever crate the governance agent is extracted into (that is the entire
/// point of SPLIT-03), so a determined downstream crate can still name the hidden
/// module. What the seal buys is that it cannot happen by accident or unnoticed.
///
/// # The second widening: [`GovernanceAuthority::attest_release`] (QRT-04, ADR 0010)
///
/// The paragraph above says widening beyond what a named consumer already called
/// re-imports the coupling this trait exists to remove. `attest_release` is widened
/// past that bar deliberately, and this is the record of why.
///
/// QRT-04 requires a manual containment release to go "through the same governance
/// signing path" as the rest of the audit chain. The signing path is the governor
/// keyring plus the `previous_commit_hash` chain, and both live inside the concrete
/// governance agent's `Mutex<GovernanceState>` -- reachable only from a type that
/// implements this trait. The release path is `swarm_runtime::containment`, and
/// `swarm-agents` depends on `swarm-runtime`, so the runtime cannot name
/// `GovernancePolicy`. Either the release goes unsigned, or a second signer and a
/// second chain appear beside the governance one, or this trait carries the request.
/// A second chain over the same subject is the split-brain hazard QRT-04's own
/// blocker note describes, so the trait carries it.
///
/// It is a *narrow* widening on purpose:
///
/// - It takes an opaque `serde_json::Value` subject and returns an opaque
///   `serde_json::Value` receipt. `swarm-policy` is trusted-computing-base
///   (`docs/decisions/0009-*`, `tools/check-workspace-layering.sh`) and its declared
///   workspace dependencies are allow-listed down to `{swarm-core}`; naming
///   `swarm_consensus::ConsensusGovernanceReceipt` here would add a TCB edge for a
///   type this crate never inspects. `GovernanceRuntimeEventRecord::details` already
///   carries governance receipts across this boundary the same way, and
///   `swarm_runtime::dispatcher` already deserializes one out of a `Value`.
/// - It renders no authorization verdict. `Ok(true)` from
///   [`GovernanceAuthority::authorize_partition_request`] lets a destructive action
///   proceed; the worst an implementation of `attest_release` can do is refuse to
///   attest (`None`) or attest something. It cannot cause a containment, and it
///   cannot prevent one being undone -- release proceeds either way, and an
///   unattested release is recorded as unattested rather than silently equated with
///   an attested one.
///
/// # The third widening: [`GovernanceAuthority::governor_public_keys`] (ADR 0011)
///
/// `attest_release` above says a verifier can prove the signature covers *this* body.
/// It could not prove WHO signed it, and that was a hole rather than a nuance.
/// `ConsensusGovernanceReceipt::verify` checks a detached signature against
/// `signature.public_key_hex` CARRIED INSIDE THE RECEIPT, so both checks the QRT-04
/// release path performed were closed over attacker-writable data: anyone able to
/// rewrite a stored receipt could mint a keypair, recompute the subject digest over
/// the rewritten body, sign it, and verification returned `Ok`. Measured, before this
/// method existed, in `swarm-runtime-http`'s
/// `a_fully_re_attested_receipt_is_refused`.
///
/// Closing it needs the governor public keys where the verification happens, and the
/// verification happens in `swarm_runtime` -- [`crate::governance`] has no path to
/// `GovernancePolicy` (`swarm-agents` depends on `swarm-runtime`) and
/// [`GovernanceStatusReport`] carries counts, not identities. So the trust anchor
/// travels on this trait, for the same structural reason `attest_release` does.
///
/// It is narrower than either method above:
///
/// - **PUBLIC HALVES ONLY, AND IT CANNOT BE OTHERWISE.** It returns `AgentId`s, and a
///   governor's `AgentId` is `swarm:ed25519:<public-key-hex>` --
///   `AgentId::from_verifying_key` renders the 32 bytes of an
///   `ed25519_dalek::VerifyingKey` and nothing else. The local governor's is computed
///   once at registration by `SigningKey::verifying_key()`; recovering the private
///   half from it is the discrete-log problem ed25519 rests on, which is the same
///   protection every signature this system publishes already relies on. There is no
///   `SigningKey` in the return type, the private half never leaves
///   `LocalGovernorKey` -- which by construction exposes no accessor returning one
///   (BFT-03, `tools/check-single-governor-key.sh`) -- and peer governors were never
///   held as keys at all. The exact bytes returned are already published in plaintext
///   inside every receipt this authority signs, as `payload.issued_by` and
///   `signature.public_key_hex`, so a caller learns nothing it could not read off an
///   artifact it already holds.
/// - **It renders no verdict and takes no argument.** It reports a set. Every
///   decision made from it is made by the caller, in the open.
/// - **It grants no capability the implementer lacks.** An implementation could
///   return an attacker's key and admit forged receipts -- but only a type that
///   already implements this trait can, and that type already answers
///   [`GovernanceAuthority::authorize_partition_request`] and already holds the
///   signing key. This adds nothing to what a hostile implementer could do; the seal,
///   as ever, is what keeps that set enumerable.
///
/// It returns identities rather than `ed25519_dalek::VerifyingKey` deliberately:
/// `swarm-policy` is trusted computing base whose declared workspace dependencies are
/// allow-listed down to `{swarm-core}` (ADR 0009), `AgentId` is already the currency
/// of receipts, and the encoding is lossless -- so the check is exactly a public-key
/// comparison, spelled in a type this crate may name.
pub trait GovernanceAuthority: sealed::SealedGovernanceAuthority + Send + Sync {
    /// Whether `request` may proceed while the governance quorum is partitioned.
    ///
    /// `Ok(Some(receipt))` means a contingency lease was verified and durably
    /// redeemed for this exact request, `Ok(None)` that no partition-time
    /// authorization was required, and `Err` that the request was rejected.
    fn authorize_partition_request(
        &self,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<Option<serde_json::Value>, String>;

    /// Verify and durably consume one approval issued for this exact request.
    fn verify_and_consume_action_authorization(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String>;

    /// Verify and durably consume one veto issued for this exact request.
    fn verify_and_consume_veto(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String>;

    /// Whether the governance quorum is currently partitioned.
    fn is_partitioned(&self) -> bool;

    /// Record that `request` was vetoed while the quorum was partitioned.
    ///
    /// A no-op unless the quorum is actually partitioned.
    fn note_partition_veto(&self, request: &ActionRequest, reason: &str, now_ms: i64);

    /// Take the governance events queued since the last drain.
    fn drain_runtime_events(&self) -> Vec<GovernanceRuntimeEventRecord>;

    /// Snapshot of quorum health, for the operator-facing health surface.
    ///
    /// Read-only and verdict-free: it reports what the authority already decided and
    /// authorizes nothing. It is on this trait rather than a second one because the
    /// ingest surface holds the same authority object the dispatcher does, and one
    /// sealed governance trait keeps the enumerable-implementers property in one place.
    fn status_report(&self) -> GovernanceStatusReport;

    /// Sign `subject` on the governance receipt chain and return the receipt.
    ///
    /// `subject` is the canonical body being attested -- for QRT-04, a containment
    /// rollback receipt with its own attestation field cleared. The returned value is
    /// a serialized `swarm_consensus::ConsensusGovernanceReceipt`; see the trait doc
    /// for why the types are opaque here.
    ///
    /// THE BINDING IS THE CALLER'S TO CHECK, AND IT IS CHECKABLE. An implementation
    /// must set the attested commit's `proposal_id` to the sha256 of the canonical
    /// `subject`, so a verifier that re-canonicalizes the subject can prove the
    /// signature covers *this* body and not some other one. A verifier that only
    /// checked the signature would accept a receipt lifted from a different release.
    ///
    /// `None` means no attestation was produced -- no governors are registered, or the
    /// commit could not be built. It is NOT an authorization failure and callers must
    /// not read it as one: the caller records the release as unattested, which is a
    /// true statement, rather than treating absence as proof.
    fn attest_release(&self, subject: &serde_json::Value, now_ms: i64)
    -> Option<serde_json::Value>;

    /// The public key of every governor this authority recognises, as the consensus
    /// identity derived from it.
    ///
    /// This is the TRUST ANCHOR a verifier checks a governance receipt's signer
    /// against. Each element is `swarm:ed25519:<public-key-hex>` -- the 32 public key
    /// bytes, hex-encoded, untruncated and unhashed -- so membership here is exactly
    /// public-key equality, and nothing in the return value is derived from a private
    /// key. See the trait doc for why that is structural rather than a convention.
    ///
    /// AN EMPTY SET MEANS "I CANNOT NAME A GOVERNOR", AND CALLERS MUST REFUSE.
    /// It is the same situation `GovernancePolicy::can_act` fails closed on with no
    /// registered governor key (b4bf119): the only remaining key is the one the
    /// receipt carries itself, and trusting that is the defect this method exists to
    /// close. `ConsensusGovernanceReceipt::verify_signed_by` refuses an empty anchor
    /// outright so no caller has to remember.
    fn governor_public_keys(&self) -> std::collections::BTreeSet<swarm_core::types::AgentId>;
}
