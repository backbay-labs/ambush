//! Authenticated governance persistence, consensus authority, and the Tom role.
//!
//! ## Owns
//!
//! - The only concrete implementation that can mint a governance authority handle.
//! - Signed governance state, its permanent process lock, and one-shot ledgers.
//! - Governance consensus/contingency behavior and the Tom health role.
//!
//! ## Does not own
//!
//! - Runtime dispatch, ingest, containment execution, HTTP, or CLI composition.
//! - The admitted Tom identity or key-store lifecycle supplied by the daemon.
//! - Ordinary response policy or cryptographic primitives defined below this crate.

use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_consensus::{
    ConsensusCommittee, ConsensusConfig, ConsensusError, ConsensusGovernanceReceipt, ConsensusNode,
    ConsensusProposal, ConsensusTransport, GovernanceReceiptDecision, SoloGovernorTransport,
    drive_round, proposal_id_for_payload, recommended_max_faulty,
};
use swarm_core::agent::{
    AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError,
};
use swarm_core::signed_state::{
    SIGNED_STATE_SCHEMA_VERSION, SignedStateEnvelope, SignedStateError, SignedStateExpectation,
};
use swarm_core::types::{AgentId, ResponseAction, SwarmAction};
use swarm_crypto::{canonical_json_bytes, sha256_hex};
use swarm_policy::governance::{
    ConsumedGovernedHumanAuthorization, GovernanceActionRequestSubjectV1,
    GovernanceRuntimeEventRecord, GovernedHumanAuthorizationHold,
};
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};
// Both types are declared in `swarm-policy` as of SPLIT-05. Re-exported rather than
// merely imported, because the
// paths `swarm_agents::tom_agent::{PartitionState, GovernanceStatusReport}` are what
// this module's callers and integration tests already spell.
pub use swarm_policy::governance::{GovernanceStatusReport, PartitionState};
use swarm_policy::static_gate::scope_for_response_action;

pub mod persistence_protocol;
pub mod witness_engine;
pub mod witness_service;

const DEFAULT_CONTINGENCY_LEASE_TTL_MS: i64 = 300_000;
const DEFAULT_CONTINGENCY_BLAST_RADIUS_CAP: usize = 1;
const CONTINGENCY_LEASE_SCHEMA_VERSION: u32 = 1;
const MAX_RECONCILIATION_REPORTS: usize = 16;
const MAX_PENDING_AUTHORIZATIONS: usize = 1_024;
const MAX_CONSUMED_AUTHORIZATIONS: usize = 1_024;
const MAX_PENDING_HUMAN_AUTHORIZATIONS: usize = 1_024;
const MAX_AUTHORIZATION_AGE_MS: i64 = 300_000;
const MAX_AUTHORIZATION_FUTURE_SKEW_MS: i64 = 30_000;
const GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS: i64 = 1_000;
const GOVERNANCE_STATE_KIND: &str = "swarm.governance.policy-state.v1";
const GOVERNANCE_CHECKPOINT_KIND: &str = "swarm.governance.policy-checkpoint.v1";
const GOVERNANCE_STATE_STREAM: &str = "tom-primary";
const GOVERNANCE_LOCK_RECORD_SCHEMA_VERSION: u32 = 1;
const GOVERNANCE_LOCK_GENERATION_BYTES: usize = 32;
const MAX_GOVERNANCE_LOCK_RECORD_BYTES: u64 = 4_096;
const GOVERNANCE_CLEANUP_POOL_DIR_NAME: &str = ".governance-cleanup-pool";
const GOVERNANCE_CLEANUP_POOL_LOCK_NAME: &str = "lock";
const GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME: &str = "journal";
const GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME: &str = "candidate";
const GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME: &str = "quarantine";
const GOVERNANCE_CLEANUP_POOL_BINDING_NAME: &str = "binding.json";
const GOVERNANCE_CLEANUP_POOL_SLOT_COUNT: usize = 64;
const CLEANUP_POOL_BINDING_SCHEMA_VERSION: u32 = 1;
const CLEANUP_POOL_BINDING_KIND: &str = "swarm.governance.cleanup-pool-binding.v1";
const CLEANUP_POOL_BINDING_STREAM: &str = "tom-primary-cleanup-pool";
const GOVERNANCE_CLEANUP_POOL_MAINTENANCE_JOURNAL_NAME: &str = "maintenance.json";
const CLEANUP_POOL_MAINTENANCE_SCHEMA_VERSION: u32 = 1;
const CLEANUP_POOL_MAINTENANCE_KIND: &str = "swarm.governance.cleanup-pool-maintenance.v1";
const CLEANUP_POOL_MAINTENANCE_STREAM: &str = "tom-primary-cleanup-pool-maintenance";

static AUTHORITY_CLEANUP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContingencyLease {
    pub schema_version: u32,
    pub lease_id: String,
    pub action_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub blast_radius_cap: usize,
    pub max_duration_ms: i64,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    #[serde(default)]
    pub redeemed_scopes: Vec<String>,
    #[serde(default)]
    pub redeemed_request_subjects: Vec<String>,
    pub governance_receipt: ConsensusGovernanceReceipt,
}

impl ContingencyLease {
    pub fn verify(&self, governor_public_keys: &BTreeSet<AgentId>) -> Result<(), String> {
        if self.schema_version != CONTINGENCY_LEASE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported contingency lease schema_version `{}`",
                self.schema_version
            ));
        }
        if self.blast_radius_cap == 0 {
            return Err("contingency lease blast radius cap must be positive".to_string());
        }
        if self.max_duration_ms <= 0 {
            return Err("contingency lease duration must be positive".to_string());
        }
        if self.expires_at_ms <= self.issued_at_ms {
            return Err("contingency lease expiry must be after issuance".to_string());
        }
        let receipt = &self.governance_receipt;
        receipt
            .verify_signed_by(governor_public_keys)
            .map_err(|error| format!("invalid contingency lease receipt: {error}"))?;
        let proposal = build_contingency_lease_proposal(
            &self.lease_id,
            &self.action_kind,
            self.scope.as_deref(),
            self.blast_radius_cap,
            self.max_duration_ms,
            self.issued_at_ms,
            self.expires_at_ms,
        )
        .map_err(|error| format!("failed to rebuild contingency lease proposal: {error}"))?;
        receipt
            .verify_internal_consistency(&proposal.payload, GovernanceReceiptDecision::Approve)
            .map_err(|error| format!("invalid contingency lease receipt: {error}"))?;
        Ok(())
    }

    fn matches_committee(&self, committee: &ConsensusCommittee) -> bool {
        let receipt = &self.governance_receipt.payload;
        receipt.committee_id == committee.committee_id()
            && receipt.committee_members.as_slice() == committee.members()
            && receipt.threshold == committee.threshold()
    }

    fn verify_for_committee(
        &self,
        governor_public_keys: &BTreeSet<AgentId>,
        committee: &ConsensusCommittee,
    ) -> Result<(), String> {
        self.verify(governor_public_keys)?;
        if !self.matches_committee(committee) {
            return Err(format!(
                "contingency lease `{}` was staged for governance committee `{}`, not current committee `{}`",
                self.lease_id,
                self.governance_receipt.payload.committee_id,
                committee.committee_id()
            ));
        }
        Ok(())
    }

    fn matches_action(&self, action: &ResponseAction) -> bool {
        self.action_kind == action.kind()
            && self.scope.as_ref().is_none_or(|scope| {
                scope_for_response_action(action).as_deref() == Some(scope.as_str())
            })
    }

    fn scope_key(&self, action: &ResponseAction) -> String {
        scope_for_response_action(action).unwrap_or_else(|| format!("unscoped:{}", action.kind()))
    }

    fn can_redeem(&self, request: &ActionRequest, now_ms: i64) -> bool {
        if !self.matches_action(&request.action) || self.expires_at_ms <= now_ms {
            return false;
        }
        let Ok(subject_digest) = governance_request_subject_digest(request) else {
            return false;
        };
        if self
            .redeemed_request_subjects
            .iter()
            .any(|existing| existing == &subject_digest)
        {
            return false;
        }
        let scope = self.scope_key(&request.action);
        !self
            .redeemed_scopes
            .iter()
            .any(|existing| existing == &scope)
            && self.redeemed_scopes.len() < self.blast_radius_cap
    }

    fn redeem(&mut self, request: &ActionRequest, now_ms: i64) -> Result<(), String> {
        let action = &request.action;
        if !self.matches_action(action) {
            return Err(format!(
                "contingency lease `{}` does not cover action `{}`",
                self.lease_id,
                action.kind()
            ));
        }
        if self.expires_at_ms <= now_ms {
            return Err("contingency lease expired".to_string());
        }
        let subject_digest = governance_request_subject_digest(request)?;
        if self
            .redeemed_request_subjects
            .iter()
            .any(|existing| existing == &subject_digest)
        {
            return Err(format!(
                "contingency lease `{}` was already redeemed for this exact request",
                self.lease_id
            ));
        }
        let scope = self.scope_key(action);
        let scope_was_redeemed = self
            .redeemed_scopes
            .iter()
            .any(|existing| existing == &scope);
        if scope_was_redeemed {
            return Err(format!(
                "contingency lease `{}` was already redeemed for scope `{scope}`",
                self.lease_id
            ));
        }
        if self.redeemed_scopes.len() >= self.blast_radius_cap {
            return Err(format!(
                "contingency lease `{}` exceeded blast radius cap {}",
                self.lease_id, self.blast_radius_cap
            ));
        }
        self.redeemed_scopes.push(scope);
        self.redeemed_request_subjects.push(subject_digest);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartitionActionRecord {
    pub recorded_at_ms: i64,
    pub hunt_id: String,
    pub requested_by: String,
    pub action_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub authorized: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartitionReconciliationReport {
    pub report_id: String,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_started_at_ms: Option<i64>,
    pub healed_at_ms: i64,
    pub authorized_actions: Vec<PartitionActionRecord>,
    pub unauthorized_actions: Vec<PartitionActionRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GovernanceRuntimeEvent {
    PartitionStateTransition {
        emitted_at_ms: i64,
        governing_agent_id: AgentId,
        from: PartitionState,
        to: PartitionState,
        healthy_governors: usize,
        total_governors: usize,
        quorum_threshold: usize,
        reason: String,
    },
    PartitionReconciliation {
        emitted_at_ms: i64,
        governing_agent_id: AgentId,
        report: PartitionReconciliationReport,
    },
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum GovernanceDecision {
    NotRequired,
    Authorize {
        receipt: ConsensusGovernanceReceipt,
        contingency_lease: Option<ContingencyLease>,
    },
    Veto {
        governing_agent_id: AgentId,
        reason: String,
        receipt: Option<ConsensusGovernanceReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PendingGovernanceAuthorization {
    receipt_id: String,
    subject_digest: String,
    decision: GovernanceReceiptDecision,
    issued_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ConsumedGovernanceAuthorization {
    receipt_id: String,
    subject_digest: String,
    decision: GovernanceReceiptDecision,
    consumed_at_ms: i64,
}

/// The one governor signing key this process is allowed to hold (BFT-03).
///
/// Before this type, `GovernanceState` held `governors: BTreeMap<AgentId,
/// SigningKey>` and `simulate_governance_commit` built one `ConsensusNode` per
/// entry -- so the type permitted a process to speak, and sign, for every
/// member of its own committee. Nothing in the tree ever put two keys in that
/// map (measured: all 13 `register_governor` call sites register exactly one
/// key per policy), but "nobody does it" is a property of today's callers, not
/// of the code. This type makes it a property of the code.
///
/// There is deliberately NO accessor returning the `SigningKey`. Everything
/// that needs to sign does so through a method here, so a future
/// `issue_*`-shaped function cannot clone a key back out into a collection.
/// See `tools/check-single-governor-key.sh` for what that does and does not
/// catch.
struct LocalGovernorKey {
    consensus_agent_id: AgentId,
    signing_key: SigningKey,
}

impl std::fmt::Debug for LocalGovernorKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the private half, not even in a panic message.
        formatter
            .debug_struct("LocalGovernorKey")
            .field("consensus_agent_id", &self.consensus_agent_id)
            .finish_non_exhaustive()
    }
}

impl LocalGovernorKey {
    fn new(signing_key: SigningKey) -> Self {
        Self {
            consensus_agent_id: AgentId::from_verifying_key(&signing_key.verifying_key()),
            signing_key,
        }
    }

    fn consensus_agent_id(&self) -> &AgentId {
        &self.consensus_agent_id
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Build the ONE consensus node this process drives.
    ///
    /// The key is cloned exactly here, into the node that owns it for the
    /// duration of a round. `ConsensusNode` exposes no key accessor either --
    /// it signs its own outbound envelopes through `sign_outbound`.
    fn consensus_node(
        &self,
        committee: ConsensusCommittee,
        config: ConsensusConfig,
        previous_commit_hash: &str,
        now_ms: i64,
    ) -> Result<ConsensusNode, ConsensusError> {
        ConsensusNode::new_with_signing_key(
            self.consensus_agent_id.clone(),
            self.signing_key.clone(),
            committee,
            config,
            previous_commit_hash.to_string(),
            now_ms,
        )
    }

    fn issue_receipt(
        &self,
        commit: &swarm_consensus::ConsensusCommit,
        previous_commit_hash: &str,
        committee: &ConsensusCommittee,
        decision: GovernanceReceiptDecision,
        issued_at_ms: i64,
    ) -> Result<ConsensusGovernanceReceipt, ConsensusError> {
        ConsensusGovernanceReceipt::issue(
            commit,
            previous_commit_hash,
            committee,
            decision,
            self.consensus_agent_id.clone(),
            &self.signing_key,
            issued_at_ms,
        )
    }

    fn sign_persisted_state(
        &self,
        sequence: u64,
        payload: PersistedGovernanceState,
    ) -> Result<SignedStateEnvelope<PersistedGovernanceState>, SignedStateError> {
        SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            self.consensus_agent_id.clone(),
            sequence,
            payload,
            &self.signing_key,
        )
    }

    fn sign_checkpoint(
        &self,
        sequence: u64,
        payload: GovernanceSequenceCheckpoint,
    ) -> Result<SignedStateEnvelope<GovernanceSequenceCheckpoint>, SignedStateError> {
        SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            self.consensus_agent_id.clone(),
            sequence,
            payload,
            &self.signing_key,
        )
    }
}

/// Refusal reasons for [`GovernancePolicy::register_governor`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceKeyError {
    #[error(
        "governance policy already holds the signing key for governor `{existing}`; refusing to \
         also hold `{offered}` (no process may hold more than one governor signing key)"
    )]
    SecondSigningKey { existing: AgentId, offered: AgentId },

    #[error("governor key was not registered because persistence failed: {reason}")]
    Persistence { reason: String },
}

#[derive(Debug)]
struct GovernanceState {
    governing_agent_id: Option<AgentId>,
    display_governors: BTreeMap<AgentId, AgentId>,
    /// The single key this process holds, if any.
    local_governor: Option<LocalGovernorKey>,
    /// Peer governors, by consensus identity only. No key, ever.
    peer_governors: BTreeSet<AgentId>,
    unhealthy_agents: Vec<AgentHealthEntry>,
    previous_commit_hash: String,
    receipt_counter: u64,
    partition_state: PartitionState,
    partition_started_at_ms: Option<i64>,
    last_transition_at_ms: Option<i64>,
    last_healthy_governors: usize,
    last_quorum_threshold: usize,
    active_contingency_leases: Vec<ContingencyLease>,
    pending_authorizations: VecDeque<PendingGovernanceAuthorization>,
    consumed_authorizations: VecDeque<ConsumedGovernanceAuthorization>,
    pending_human_authorizations: VecDeque<GovernedHumanAuthorizationHold>,
    partition_activity: Vec<PartitionActionRecord>,
    reconciliation_reports: Vec<PartitionReconciliationReport>,
    pending_events: VecDeque<GovernanceRuntimeEvent>,
    /// Transient marker: the state envelope committed but its signed high-water
    /// checkpoint did not. Never serialized into the state it describes.
    checkpoint_lagging: Option<GovernanceCheckpointLag>,
    /// Transient health-tick retry deadline for a failed checkpoint repair.
    /// Governed effects deliberately bypass this backoff and attempt repair
    /// immediately before their external effect.
    checkpoint_repair_backoff: Option<GovernanceCheckpointRepairBackoff>,
    /// A health observation that arrived while checkpoint repair was deferred.
    /// Governed authority remains fail-closed until a later health tick can
    /// persist the observation against a repaired checkpoint. This is the
    /// latest in-memory observation; the signed `durable_pending_health_observation`
    /// below is the checkpoint-repair anchor when observations oscillate during
    /// the retry window.
    pending_health_observation: Option<PendingHealthObservation>,
    /// The first pending observation committed into the signed state envelope.
    /// Keeping this anchor separate from the latest in-memory observation means
    /// checkpoint repair can authenticate the durable envelope even when health
    /// snapshots change repeatedly before the retry deadline.
    durable_pending_health_observation: Option<PendingHealthObservation>,
    /// The exact signed envelope sequence this in-memory snapshot was loaded
    /// from or last committed as. Never serialized into its own payload.
    persistence_sequence: Option<u64>,
    /// Digest of the exact verified signed statement at
    /// `persistence_sequence`. Paired with the sequence for transaction CAS.
    persistence_digest: Option<String>,
}

impl GovernanceState {
    /// Every governor this policy knows about: the local one plus admitted peers.
    fn governor_count(&self) -> usize {
        self.committee_member_ids().len()
    }

    fn committee_member_ids(&self) -> BTreeSet<AgentId> {
        let mut members = self.peer_governors.clone();
        if let Some(local) = self.local_governor.as_ref() {
            members.insert(local.consensus_agent_id().clone());
        }
        members
    }

    /// Resolve unhealthy runtime identities to the consensus identities that
    /// define committee membership. The runtime may report the local Tom by its
    /// display identity or its key-derived consensus identity; both are one
    /// governor. Peers have only admitted consensus identities.
    fn unhealthy_governor_ids(&self, entries: &[AgentHealthEntry]) -> BTreeSet<AgentId> {
        entries
            .iter()
            .filter(|entry| entry.role == AgentRole::Tom && entry.health != AgentHealth::Healthy)
            .filter_map(|entry| {
                let observed_id = AgentId(entry.id.clone());
                self.display_governors
                    .get(&observed_id)
                    .cloned()
                    .or_else(|| {
                        (self
                            .display_governors
                            .values()
                            .any(|consensus_id| consensus_id == &observed_id)
                            || self.peer_governors.contains(&observed_id))
                        .then_some(observed_id)
                    })
            })
            .collect()
    }

    /// The committee for a round, by consensus identity. Contains no keys.
    fn committee(&self) -> Result<ConsensusCommittee, ConsensusError> {
        let members = self.committee_member_ids().into_iter().collect::<Vec<_>>();
        let size = members.len();
        ConsensusCommittee::new(members, recommended_max_faulty(size))
    }
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            governing_agent_id: None,
            display_governors: BTreeMap::new(),
            local_governor: None,
            peer_governors: BTreeSet::new(),
            unhealthy_agents: Vec::new(),
            previous_commit_hash: "governance-bootstrap".to_string(),
            receipt_counter: 0,
            partition_state: PartitionState::Healthy,
            partition_started_at_ms: None,
            last_transition_at_ms: None,
            last_healthy_governors: 0,
            last_quorum_threshold: 0,
            active_contingency_leases: Vec::new(),
            pending_authorizations: VecDeque::new(),
            consumed_authorizations: VecDeque::new(),
            pending_human_authorizations: VecDeque::new(),
            partition_activity: Vec::new(),
            reconciliation_reports: Vec::new(),
            pending_events: VecDeque::new(),
            checkpoint_lagging: None,
            checkpoint_repair_backoff: None,
            pending_health_observation: None,
            durable_pending_health_observation: None,
            persistence_sequence: None,
            persistence_digest: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GovernancePolicyConfig {
    pub contingency_lease_ttl_ms: i64,
    pub contingency_blast_radius_cap: usize,
}

impl Default for GovernancePolicyConfig {
    fn default() -> Self {
        Self {
            contingency_lease_ttl_ms: DEFAULT_CONTINGENCY_LEASE_TTL_MS,
            contingency_blast_radius_cap: DEFAULT_CONTINGENCY_BLAST_RADIUS_CAP,
        }
    }
}

#[cfg(test)]
type GovernanceLoaderBarrier = (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[derive(Debug)]
struct CleanupPoolContext {
    pool_path: PathBuf,
    binding_path: PathBuf,
    parent_identity: GovernanceArtifactIdentity,
    pool_file: fs::File,
    pool_identity: GovernanceArtifactIdentity,
    lock_file: fs::File,
    lock_identity: GovernanceArtifactIdentity,
    binding_file: fs::File,
    binding_identity: GovernanceArtifactIdentity,
    binding: CleanupPoolBinding,
    signed: bool,
}

impl CleanupPoolContext {
    #[cfg(test)]
    fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            pool_path: self.pool_path.clone(),
            binding_path: self.binding_path.clone(),
            parent_identity: self.parent_identity,
            pool_file: self.pool_file.try_clone()?,
            pool_identity: self.pool_identity,
            lock_file: self.lock_file.try_clone()?,
            lock_identity: self.lock_identity,
            binding_file: self.binding_file.try_clone()?,
            binding_identity: self.binding_identity,
            binding: self.binding.clone(),
            signed: self.signed,
        })
    }
}

#[derive(Debug)]
struct GovernancePersistence {
    path: PathBuf,
    sequence_path: PathBuf,
    parent_directory: fs::File,
    parent_directory_identity: GovernanceArtifactIdentity,
    no_replace_initial_publication: Mutex<bool>,
    lock_path: PathBuf,
    authority_lock_path: PathBuf,
    lock_binding: GovernanceLockBinding,
    expected_signer_agent_id: AgentId,
    /// Exclusive OS advisory lock held for the full policy lifetime. The lock
    /// file may remain after exit; ownership comes only from this live handle,
    /// never from file existence.
    lock_file: fs::File,
    /// Process-lifetime exclusion shared by current and legacy authority paths.
    authority_lock_file: fs::File,
    authority_lock_identity: GovernanceAuthorityLockIdentity,
    cleanup_pool_context: Mutex<Option<CleanupPoolContext>>,
    /// Exact identities written by the current initialization transaction.
    /// Rollback consumes this journal and never removes a state/sequence path
    /// based only on its name or on the unrelated stream lock.
    new_stream_artifacts: Mutex<Vec<(PathBuf, GovernanceArtifactIdentity)>>,
    /// Active reinitialization journal context.  Write paths publish an
    /// authenticated content intent before their atomic rename.
    reinitialization_journal_path: Mutex<Option<PathBuf>>,
    reinitialization_journal_signing_key: Mutex<Option<SigningKey>>,
    #[cfg(test)]
    test_pre_write_barrier: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
    #[cfg(test)]
    test_loader_barrier: Mutex<Option<GovernanceLoaderBarrier>>,
}

impl Drop for GovernancePersistence {
    fn drop(&mut self) {
        // Release explicitly before the descriptor is closed. Relying only on
        // close-on-drop made an immediate same-process reopen observably race on
        // Linux after the cross-process exclusivity probe.
        let _ = self.lock_file.unlock();
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GovernanceLockIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GovernanceLockIdentity;

/// Stable filesystem identity of the process-lifetime governance authority
/// sidecar. Runtime path-selection code uses this opaque value to require the
/// current and legacy authority paths to be hard links to one inode before it
/// selects either stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceAuthorityLockIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceLockBinding {
    device: u64,
    inode: u64,
    generation_id: String,
}

impl GovernanceLockBinding {
    fn unbound() -> Self {
        Self {
            device: 0,
            inode: 0,
            generation_id: String::new(),
        }
    }

    #[cfg(unix)]
    fn identity(&self) -> GovernanceLockIdentity {
        GovernanceLockIdentity {
            device: self.device,
            inode: self.inode,
        }
    }

    #[cfg(not(unix))]
    fn identity(&self) -> GovernanceLockIdentity {
        GovernanceLockIdentity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernanceLockRecord {
    schema_version: u32,
    generation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GovernanceLockOpenMode {
    Existing,
    Initialize,
    Reinitialize,
    Migrate,
}

#[derive(Debug)]
enum GovernancePersistenceOutcome {
    Committed,
    /// The signed state envelope is the durable commit point. The checkpoint is
    /// only a signed high-water anchor and did not advance after that commit.
    StateCommittedCheckpointLagging {
        sequence: u64,
        reason: String,
    },
}

#[derive(Debug)]
enum AtomicWriteOutcome {
    Synced(GovernanceArtifactIdentity),
    /// The rename (the state commit point) succeeded, but syncing its parent
    /// directory did not. Callers must treat the new file as committed in this
    /// process even though crash durability is not yet proven.
    RenamedDirectorySyncFailed(GovernancePersistenceError, GovernanceArtifactIdentity),
}

/// Identity captured from the freshly fsynced temporary file before its
/// atomic rename.  Reinitialization rollback uses this identity, rather than a
/// pathname or a lock check, when deciding whether a partial new stream may be
/// quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceArtifactIdentity {
    device: u64,
    inode: u64,
}

/// A no-follow, byte-authenticated snapshot of one persistence artifact.
///
/// The inode alone is not sufficient for reinitialization rollback: a hard
/// link would make the supposed archive an alias of the live source, so a
/// later in-place write could mutate both.  Reinitialization therefore binds
/// the source identity to the exact copied bytes and length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GovernanceArtifactSnapshot {
    identity: GovernanceArtifactIdentity,
    content_digest: String,
    byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPoolBinding {
    schema_version: u32,
    parent_identity: GovernanceArtifactIdentity,
    pool_identity: GovernanceArtifactIdentity,
    lock_identity: GovernanceArtifactIdentity,
    generation_id: String,
    slot_count: usize,
    pool_name: String,
    lock_name: String,
    binding_name: String,
    journal_name: String,
    candidate_name: String,
    quarantine_name: String,
    slot_names: Vec<String>,
}

impl CleanupPoolBinding {
    fn unbound() -> Self {
        Self {
            schema_version: CLEANUP_POOL_BINDING_SCHEMA_VERSION,
            parent_identity: GovernanceArtifactIdentity {
                device: 0,
                inode: 0,
            },
            pool_identity: GovernanceArtifactIdentity {
                device: 0,
                inode: 0,
            },
            lock_identity: GovernanceArtifactIdentity {
                device: 0,
                inode: 0,
            },
            generation_id: String::new(),
            slot_count: GOVERNANCE_CLEANUP_POOL_SLOT_COUNT,
            pool_name: GOVERNANCE_CLEANUP_POOL_DIR_NAME.to_string(),
            lock_name: GOVERNANCE_CLEANUP_POOL_LOCK_NAME.to_string(),
            binding_name: GOVERNANCE_CLEANUP_POOL_BINDING_NAME.to_string(),
            journal_name: GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME.to_string(),
            candidate_name: GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME.to_string(),
            quarantine_name: GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME.to_string(),
            slot_names: Vec::new(),
        }
    }

    fn new(
        parent_identity: GovernanceArtifactIdentity,
        pool_identity: GovernanceArtifactIdentity,
        lock_identity: GovernanceArtifactIdentity,
    ) -> Self {
        let mut generation = [0_u8; 32];
        OsRng.fill_bytes(&mut generation);
        Self {
            schema_version: CLEANUP_POOL_BINDING_SCHEMA_VERSION,
            parent_identity,
            pool_identity,
            lock_identity,
            generation_id: hex::encode(generation),
            slot_count: GOVERNANCE_CLEANUP_POOL_SLOT_COUNT,
            pool_name: GOVERNANCE_CLEANUP_POOL_DIR_NAME.to_string(),
            lock_name: GOVERNANCE_CLEANUP_POOL_LOCK_NAME.to_string(),
            binding_name: GOVERNANCE_CLEANUP_POOL_BINDING_NAME.to_string(),
            journal_name: GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME.to_string(),
            candidate_name: GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME.to_string(),
            quarantine_name: GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME.to_string(),
            slot_names: (0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT)
                .map(|index| cleanup_pool_slot_name(index).to_string_lossy().into_owned())
                .collect(),
        }
    }

    fn validate_namespace(
        &self,
        parent_identity: GovernanceArtifactIdentity,
        pool_identity: GovernanceArtifactIdentity,
        lock_identity: GovernanceArtifactIdentity,
    ) -> Result<(), String> {
        let expected = Self {
            schema_version: CLEANUP_POOL_BINDING_SCHEMA_VERSION,
            parent_identity,
            pool_identity,
            lock_identity,
            generation_id: self.generation_id.clone(),
            slot_count: GOVERNANCE_CLEANUP_POOL_SLOT_COUNT,
            pool_name: GOVERNANCE_CLEANUP_POOL_DIR_NAME.to_string(),
            lock_name: GOVERNANCE_CLEANUP_POOL_LOCK_NAME.to_string(),
            binding_name: GOVERNANCE_CLEANUP_POOL_BINDING_NAME.to_string(),
            journal_name: GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME.to_string(),
            candidate_name: GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME.to_string(),
            quarantine_name: GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME.to_string(),
            slot_names: (0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT)
                .map(|index| cleanup_pool_slot_name(index).to_string_lossy().into_owned())
                .collect(),
        };
        if self.schema_version != expected.schema_version
            || self.parent_identity != expected.parent_identity
            || self.pool_identity != expected.pool_identity
            || self.lock_identity != expected.lock_identity
            || self.generation_id.len() != 64
            || self.slot_count != expected.slot_count
            || self.pool_name != expected.pool_name
            || self.lock_name != expected.lock_name
            || self.binding_name != expected.binding_name
            || self.journal_name != expected.journal_name
            || self.candidate_name != expected.candidate_name
            || self.quarantine_name != expected.quarantine_name
            || self.slot_names != expected.slot_names
        {
            return Err("cleanup pool binding does not describe the fixed namespace".to_string());
        }
        if !self
            .generation_id
            .as_bytes()
            .iter()
            .all(u8::is_ascii_hexdigit)
        {
            return Err("cleanup pool binding generation is not hexadecimal".to_string());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn governance_artifact_identity(metadata: &fs::Metadata) -> Option<GovernanceArtifactIdentity> {
    use std::os::unix::fs::MetadataExt;
    metadata
        .file_type()
        .is_file()
        .then_some(GovernanceArtifactIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
}

#[cfg(not(unix))]
fn governance_artifact_identity(_metadata: &fs::Metadata) -> Option<GovernanceArtifactIdentity> {
    None
}

#[cfg(unix)]
fn governance_directory_identity(metadata: &fs::Metadata) -> Option<GovernanceArtifactIdentity> {
    use std::os::unix::fs::MetadataExt;
    metadata
        .file_type()
        .is_dir()
        .then_some(GovernanceArtifactIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
}

#[cfg(not(unix))]
fn governance_directory_identity(_metadata: &fs::Metadata) -> Option<GovernanceArtifactIdentity> {
    None
}

fn read_governance_artifact_identity(
    path: &Path,
) -> Result<Option<GovernanceArtifactIdentity>, std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(governance_artifact_identity(&metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

const CLEANUP_POOL_RECORD_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CleanupPoolPhase {
    Reserved,
    SourceMoved,
    QuarantineMoved,
    ForeignPreserved,
    Retained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum CleanupPoolMaintenanceJournalPhase {
    Prepared,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPoolMaintenanceJournal {
    schema_version: u32,
    operation_id: String,
    mode: GovernanceCleanupPoolMaintenanceMode,
    binding: CleanupPoolBinding,
    archive_name: String,
    archive_identity: GovernanceArtifactIdentity,
    selected_slots: Vec<String>,
    slot_proofs: BTreeMap<String, CleanupPoolMaintenanceSlotProof>,
    moved_slots: Vec<String>,
    opaque_slots: Vec<String>,
    phase: CleanupPoolMaintenanceJournalPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPoolMaintenanceSlotProof {
    identity: GovernanceArtifactIdentity,
    content_digest: String,
    byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPoolEntryRecord {
    target_component: Vec<u8>,
    identity: GovernanceArtifactIdentity,
    content_digest: String,
    byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupPoolRecord {
    schema_version: u32,
    transaction_id: String,
    parent_identity: GovernanceArtifactIdentity,
    pool_identity: GovernanceArtifactIdentity,
    lock_identity: GovernanceArtifactIdentity,
    slot_identity: GovernanceArtifactIdentity,
    target_component: Vec<u8>,
    entries: Vec<CleanupPoolEntryRecord>,
    previous_digest: Option<String>,
    phase: CleanupPoolPhase,
    record_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuarantineOutcome {
    NotVerified,
    Retained,
    ForeignPreserved,
    PoolExhausted,
    Uncertain,
}

impl QuarantineOutcome {
    fn is_semantic_success(self) -> bool {
        // A foreign replacement being preserved is deliberately not success
        // for the caller that expected to retire its own artifact.  It is a
        // safe outcome for a drop path, but result-returning paths must retain
        // their higher-level rollback material and report uncertainty.
        matches!(self, Self::Retained)
    }

    fn maintenance_reason(self) -> &'static str {
        match self {
            Self::NotVerified => "cleanup precondition was not verified",
            Self::Retained => "entry is semantically quarantined in a retained pool slot",
            Self::ForeignPreserved => "foreign replacement was preserved in a retained slot",
            Self::PoolExhausted => "all 64 cleanup pool slots are occupied",
            Self::Uncertain => "cleanup transaction is uncertain and requires maintenance",
        }
    }
}

/// A fixed-cardinality cleanup slot.  The pool and lock descriptors remain
/// live for the complete quarantine transaction; every slot operation is
/// relative to these descriptors, never a pathname re-open.
struct AuthorityCleanupRetirement {
    path: PathBuf,
    pool_path: PathBuf,
    /// The fixed pool entry name is part of the capability.  Holding the slot
    /// directory alone is insufficient: a same-UID writer can rename that
    /// entry away and leave the descriptor orphaned while the name is reused
    /// for a different transaction.
    slot_name: OsString,
    parent_file: fs::File,
    parent_identity: GovernanceArtifactIdentity,
    pool_file: fs::File,
    pool_identity: GovernanceArtifactIdentity,
    lock_file: fs::File,
    lock_identity: GovernanceArtifactIdentity,
    file: fs::File,
    identity: GovernanceArtifactIdentity,
    transaction_id: String,
    target_component: Vec<u8>,
    previous_record_digest: Option<String>,
    journal_file: Option<fs::File>,
    journal_identity: Option<GovernanceArtifactIdentity>,
    journal_expected_bytes: Vec<u8>,
    journal_expected_len: u64,
    journal_expected_digest: String,
    journal_last_phase: Option<CleanupPoolPhase>,
}

/// Stable handle to the original parent directory of a cleanup entry. Every
/// restore/publication operation is relative to this descriptor; the
/// pathname is only an observation and may be replaced by a foreign
/// directory while cleanup is in flight.
#[derive(Debug)]
struct AuthorityCleanupParent {
    file: fs::File,
    identity: GovernanceArtifactIdentity,
}

fn cleanup_pool_record_digest(record: &CleanupPoolRecord) -> Result<String, std::io::Error> {
    let mut unsigned = record.clone();
    unsigned.record_digest.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|error| {
        std::io::Error::other(format!("cleanup journal encoding failed: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

fn cleanup_pool_record_line(record: &CleanupPoolRecord) -> Result<Vec<u8>, std::io::Error> {
    let mut record = record.clone();
    record.record_digest = cleanup_pool_record_digest(&record)?;
    let mut bytes = serde_json::to_vec(&record).map_err(|error| {
        std::io::Error::other(format!("cleanup journal encoding failed: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn cleanup_pool_phase_rank(phase: CleanupPoolPhase) -> u8 {
    match phase {
        CleanupPoolPhase::Reserved => 0,
        CleanupPoolPhase::SourceMoved => 1,
        CleanupPoolPhase::QuarantineMoved => 2,
        CleanupPoolPhase::ForeignPreserved => 3,
        CleanupPoolPhase::Retained => 4,
    }
}

fn cleanup_pool_journal_error(
    slot: &AuthorityCleanupRetirement,
    reason: impl Into<String>,
) -> GovernancePersistenceError {
    cleanup_pool_error(&slot.path, reason)
}

fn validate_cleanup_pool_journal_bytes(
    slot: &AuthorityCleanupRetirement,
    bytes: &[u8],
    expected_bytes: &[u8],
    expected_len: u64,
    expected_digest: &str,
) -> Result<(Option<String>, Option<CleanupPoolPhase>), GovernancePersistenceError> {
    if bytes.len() as u64 != expected_len
        || bytes != expected_bytes
        || sha256_hex(bytes) != expected_digest
    {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal bytes changed from the held authenticated chain",
        ));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal is not newline terminated",
        ));
    }

    let mut previous_digest = None;
    let mut previous_phase = None;
    let mut lines = bytes.split(|byte| *byte == b'\n').peekable();
    while let Some(line) = lines.next() {
        if line.is_empty() {
            if lines.peek().is_none() {
                break;
            }
            return Err(cleanup_pool_journal_error(
                slot,
                "cleanup slot journal contains an empty record",
            ));
        }
        let record: CleanupPoolRecord = serde_json::from_slice(line).map_err(|error| {
            cleanup_pool_journal_error(
                slot,
                format!("cleanup slot journal record is malformed: {error}"),
            )
        })?;
        if record.schema_version != CLEANUP_POOL_RECORD_SCHEMA_VERSION
            || record.transaction_id != slot.transaction_id
            || record.parent_identity != slot.parent_identity
            || record.pool_identity != slot.pool_identity
            || record.lock_identity != slot.lock_identity
            || record.slot_identity != slot.identity
            || record.target_component != slot.target_component
        {
            return Err(cleanup_pool_journal_error(
                slot,
                "cleanup slot journal record metadata is not bound to this slot",
            ));
        }
        if record.previous_digest != previous_digest {
            return Err(cleanup_pool_journal_error(
                slot,
                "cleanup slot journal previous digest does not match its predecessor",
            ));
        }
        if let Some(previous_phase) = previous_phase {
            if matches!(
                previous_phase,
                CleanupPoolPhase::ForeignPreserved | CleanupPoolPhase::Retained
            ) || cleanup_pool_phase_rank(record.phase) < cleanup_pool_phase_rank(previous_phase)
            {
                return Err(cleanup_pool_journal_error(
                    slot,
                    "cleanup slot journal phase is not a legal monotonic transition",
                ));
            }
        } else if record.phase != CleanupPoolPhase::Reserved {
            return Err(cleanup_pool_journal_error(
                slot,
                "cleanup slot journal does not begin with Reserved",
            ));
        }
        for entry in &record.entries {
            if entry.target_component != slot.target_component
                || entry.content_digest.len() != 64
                || !entry
                    .content_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(cleanup_pool_journal_error(
                    slot,
                    "cleanup slot journal entry metadata is invalid",
                ));
            }
        }
        let recomputed = cleanup_pool_record_digest(&record).map_err(|error| {
            cleanup_pool_journal_error(
                slot,
                format!("cleanup slot journal digest could not be recomputed: {error}"),
            )
        })?;
        if record.record_digest != recomputed {
            return Err(cleanup_pool_journal_error(
                slot,
                "cleanup slot journal record digest is forged",
            ));
        }
        previous_digest = Some(record.record_digest);
        previous_phase = Some(record.phase);
    }
    Ok((previous_digest, previous_phase))
}

#[derive(Debug)]
struct CleanupPoolMaintenanceSlot {
    phase: Option<CleanupPoolPhase>,
    opaque: bool,
}

fn cleanup_maintenance_journal_path(pool_path: &Path) -> PathBuf {
    pool_path.join(GOVERNANCE_CLEANUP_POOL_MAINTENANCE_JOURNAL_NAME)
}

fn cleanup_maintenance_error(path: &Path, reason: impl Into<String>) -> GovernancePersistenceError {
    GovernancePersistenceError::CleanupMaintenanceJournal {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn cleanup_maintenance_archive_error(
    path: &Path,
    reason: impl Into<String>,
) -> GovernancePersistenceError {
    GovernancePersistenceError::CleanupMaintenanceArchive {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn map_cleanup_maintenance_contention(
    error: GovernancePersistenceError,
) -> GovernancePersistenceError {
    match error {
        GovernancePersistenceError::StateLocked { path } => {
            GovernancePersistenceError::MaintenanceBusy {
                path,
                resource: "governance state lock".to_string(),
            }
        }
        GovernancePersistenceError::CleanupPoolNamespaceChanged { path, reason }
            if reason.contains("held by another writer")
                || reason.contains("could not lock cleanup pool")
                || reason.contains("cleanup pool lock could not be acquired") =>
        {
            GovernancePersistenceError::MaintenanceBusy {
                path,
                resource: "cleanup pool lock".to_string(),
            }
        }
        other => other,
    }
}

fn valid_cleanup_archive_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && Path::new(name).file_name().and_then(|value| value.to_str()) == Some(name)
}

fn cleanup_pool_slot_name_set(binding: &CleanupPoolBinding) -> BTreeSet<OsString> {
    binding.slot_names.iter().map(OsString::from).collect()
}

fn validate_cleanup_pool_directory_namespace(
    pool: &fs::File,
    binding: &CleanupPoolBinding,
    pool_path: &Path,
) -> Result<(), GovernancePersistenceError> {
    let fixed_slots = cleanup_pool_slot_name_set(binding);
    let fixed_names = [
        OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
        OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
        OsStr::new(GOVERNANCE_CLEANUP_POOL_MAINTENANCE_JOURNAL_NAME),
    ];
    for name in directory_entry_names(pool).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("could not enumerate fixed pool: {source}"),
        )
    })? {
        if fixed_slots.contains(&name) || fixed_names.contains(&name.as_os_str()) {
            continue;
        }
        return Err(cleanup_maintenance_error(
            pool_path,
            format!(
                "unknown cleanup-pool entry `{}` is present",
                name.to_string_lossy()
            ),
        ));
    }
    Ok(())
}

fn inspect_cleanup_pool_slot(
    parent: &AuthorityCleanupParent,
    pool: &fs::File,
    lock: &fs::File,
    binding: &CleanupPoolBinding,
    pool_path: &Path,
    name: &OsStr,
) -> Result<CleanupPoolMaintenanceSlot, GovernancePersistenceError> {
    let identity = directory_entry_identity_at(pool, name)
        .map_err(|source| cleanup_maintenance_error(pool_path, source.to_string()))?
        .ok_or_else(|| cleanup_maintenance_error(pool_path, "cleanup slot disappeared"))?;
    let slot = open_directory_at(pool, name).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!(
                "slot `{}` is not an openable directory: {source}",
                name.to_string_lossy()
            ),
        )
    })?;
    let journal_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
    let journal = open_regular_entry_at(&slot, journal_name).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!(
                "slot `{}` has no regular journal: {source}",
                name.to_string_lossy()
            ),
        )
    })?;
    let journal_identity = journal
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| cleanup_maintenance_error(pool_path, "slot journal is not regular"))?;
    let mut reader = journal.try_clone().map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("slot journal could not be cloned: {source}"),
        )
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("slot journal could not be read: {source}"),
        )
    })?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("slot journal could not be read: {source}"),
        )
    })?;
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())
        .ok_or_else(|| cleanup_maintenance_error(pool_path, "slot journal is empty"))?;
    let first_record: CleanupPoolRecord = serde_json::from_slice(first_line).map_err(|error| {
        cleanup_maintenance_error(pool_path, format!("slot journal is malformed: {error}"))
    })?;
    let target_component = first_record.target_component.clone();
    let transaction_id = first_record.transaction_id.clone();
    let retirement = AuthorityCleanupRetirement {
        path: pool_path.join(name),
        pool_path: pool_path.to_path_buf(),
        slot_name: name.to_os_string(),
        parent_file: parent.file.try_clone().map_err(|source| {
            cleanup_maintenance_error(
                pool_path,
                format!("parent descriptor could not clone: {source}"),
            )
        })?,
        parent_identity: parent.identity,
        pool_file: pool.try_clone().map_err(|source| {
            cleanup_maintenance_error(
                pool_path,
                format!("pool descriptor could not clone: {source}"),
            )
        })?,
        pool_identity: binding.pool_identity,
        lock_file: lock.try_clone().map_err(|source| {
            cleanup_maintenance_error(
                pool_path,
                format!("pool lock descriptor could not clone: {source}"),
            )
        })?,
        lock_identity: binding.lock_identity,
        file: slot,
        identity,
        transaction_id,
        target_component,
        previous_record_digest: None,
        journal_file: Some(journal),
        journal_identity: Some(journal_identity),
        journal_expected_bytes: bytes.clone(),
        journal_expected_len: bytes.len() as u64,
        journal_expected_digest: sha256_hex(&bytes),
        journal_last_phase: None,
    };
    let (_, phase) = validate_cleanup_pool_journal_bytes(
        &retirement,
        &bytes,
        &bytes,
        bytes.len() as u64,
        &sha256_hex(&bytes),
    )?;
    if retirement.parent_identity != binding.parent_identity
        || retirement.pool_identity != binding.pool_identity
        || retirement.lock_identity != binding.lock_identity
    {
        return Err(cleanup_maintenance_error(
            pool_path,
            "slot journal namespace does not match authenticated cleanup binding",
        ));
    }
    let allowed = [
        OsStr::new(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME),
        OsStr::new(GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME),
        OsStr::new(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME),
        OsStr::new(std::str::from_utf8(&retirement.target_component).unwrap_or("")),
    ];
    for entry in directory_entry_names(&retirement.file).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("slot directory could not enumerate: {source}"),
        )
    })? {
        if !allowed.contains(&entry.as_os_str()) {
            return Err(cleanup_maintenance_error(
                pool_path,
                format!(
                    "slot `{}` contains unknown entry `{}`",
                    name.to_string_lossy(),
                    entry.to_string_lossy()
                ),
            ));
        }
    }
    Ok(CleanupPoolMaintenanceSlot {
        phase,
        opaque: matches!(phase, Some(CleanupPoolPhase::ForeignPreserved)),
    })
}

/// Snapshot the fixed slot's direct namespace through its held parent fd.  The
/// maintenance journal binds this proof together with the slot inode; a
/// same-inode content mutation therefore cannot make resume accept an
/// unproven source/archive pair.
fn cleanup_pool_slot_content_proof(
    pool: &fs::File,
    name: &OsStr,
) -> Result<(String, u64), std::io::Error> {
    let slot = open_directory_at(pool, name)?;
    let mut entries = Vec::new();
    let mut byte_len = 0_u64;
    for entry in directory_entry_names(&slot)? {
        let identity = directory_entry_identity_at(&slot, &entry)?;
        let (digest, len) = match open_regular_entry_at(&slot, &entry) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                byte_len = byte_len.saturating_add(bytes.len() as u64);
                (sha256_hex(&bytes), bytes.len() as u64)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), 0),
            Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => (String::new(), 0),
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;
        #[cfg(unix)]
        let entry_bytes = entry.as_bytes().to_vec();
        #[cfg(not(unix))]
        let entry_bytes = entry.to_string_lossy().as_bytes().to_vec();
        entries.push((entry_bytes, identity, digest, len));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let encoded = serde_json::to_vec(&entries).map_err(std::io::Error::other)?;
    Ok((sha256_hex(&encoded), byte_len))
}

#[derive(Debug)]
struct CleanupPoolMaintenanceJournalHandle {
    file: fs::File,
    identity: GovernanceArtifactIdentity,
}

fn open_cleanup_pool_maintenance_journal(
    pool: &fs::File,
    pool_path: &Path,
    create: bool,
) -> Result<Option<CleanupPoolMaintenanceJournalHandle>, GovernancePersistenceError> {
    let name = OsStr::new(GOVERNANCE_CLEANUP_POOL_MAINTENANCE_JOURNAL_NAME);
    let file = match open_writable_entry_at(pool, name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
            create_regular_file_at(pool, name).map_err(|source| {
                cleanup_maintenance_error(
                    &cleanup_maintenance_journal_path(pool_path),
                    format!("could not create maintenance journal: {source}"),
                )
            })?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(cleanup_maintenance_error(
                &cleanup_maintenance_journal_path(pool_path),
                format!("could not open maintenance journal: {source}"),
            ));
        }
    };
    let identity = file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| {
            cleanup_maintenance_error(
                &cleanup_maintenance_journal_path(pool_path),
                "maintenance journal is not a regular file",
            )
        })?;
    Ok(Some(CleanupPoolMaintenanceJournalHandle { file, identity }))
}

fn validate_cleanup_pool_maintenance_journal(
    journal: &CleanupPoolMaintenanceJournal,
    binding: &CleanupPoolBinding,
    path: &Path,
) -> Result<(), GovernancePersistenceError> {
    if journal.schema_version != CLEANUP_POOL_MAINTENANCE_SCHEMA_VERSION
        || journal.operation_id.is_empty()
        || !valid_cleanup_archive_name(&journal.archive_name)
        || journal.binding != *binding
    {
        return Err(cleanup_maintenance_error(
            path,
            "maintenance journal schema, operation, archive, or namespace binding is invalid",
        ));
    }
    let slots = cleanup_pool_slot_name_set(binding);
    let selected = journal
        .selected_slots
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let moved = journal
        .moved_slots
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let opaque = journal
        .opaque_slots
        .iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let mut sorted_selected = selected.clone();
    let mut sorted_moved = moved.clone();
    let mut sorted_opaque = opaque.clone();
    sorted_selected.sort();
    sorted_moved.sort();
    sorted_opaque.sort();
    if selected != sorted_selected
        || moved != sorted_moved
        || opaque != sorted_opaque
        || selected.windows(2).any(|pair| pair[0] == pair[1])
        || moved.windows(2).any(|pair| pair[0] == pair[1])
        || opaque.windows(2).any(|pair| pair[0] == pair[1])
        || selected.iter().any(|slot| !slots.contains(slot))
        || moved.iter().any(|slot| !selected.contains(slot))
        || opaque.iter().any(|slot| !selected.contains(slot))
    {
        return Err(cleanup_maintenance_error(
            path,
            "maintenance journal slot selection is not a sorted fixed-pool subset",
        ));
    }
    let selected_set = selected.iter().map(OsString::from).collect::<BTreeSet<_>>();
    let proof_set = journal
        .slot_proofs
        .keys()
        .map(OsString::from)
        .collect::<BTreeSet<_>>();
    if proof_set != selected_set
        || journal.slot_proofs.values().any(|proof| {
            proof.content_digest.len() != 64
                || !proof
                    .content_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(cleanup_maintenance_error(
            path,
            "maintenance journal slot proofs are not an exact authenticated selection",
        ));
    }
    match journal.phase {
        CleanupPoolMaintenanceJournalPhase::Prepared if !moved.is_empty() => {
            return Err(cleanup_maintenance_error(
                path,
                "Prepared maintenance journal already records moved slots",
            ));
        }
        CleanupPoolMaintenanceJournalPhase::Completed if moved.len() != selected.len() => {
            return Err(cleanup_maintenance_error(
                path,
                "Completed maintenance journal does not record every selected slot",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn read_cleanup_pool_maintenance_journal(
    handle: &mut CleanupPoolMaintenanceJournalHandle,
    pool: &fs::File,
    pool_path: &Path,
    binding: &CleanupPoolBinding,
    expected_signer: &AgentId,
) -> Result<CleanupPoolMaintenanceJournal, GovernancePersistenceError> {
    let path = cleanup_maintenance_journal_path(pool_path);
    let named_identity = open_regular_entry_at(
        pool,
        OsStr::new(GOVERNANCE_CLEANUP_POOL_MAINTENANCE_JOURNAL_NAME),
    )
    .ok()
    .and_then(|file| file.metadata().ok())
    .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_identity != Some(handle.identity) {
        return Err(cleanup_maintenance_error(
            &path,
            "maintenance journal name is not bound to the held descriptor",
        ));
    }
    let mut reader = handle.file.try_clone().map_err(|source| {
        cleanup_maintenance_error(
            &path,
            format!("maintenance journal could not clone: {source}"),
        )
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|source| {
        cleanup_maintenance_error(
            &path,
            format!("maintenance journal could not seek: {source}"),
        )
    })?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|source| {
        cleanup_maintenance_error(
            &path,
            format!("maintenance journal could not read: {source}"),
        )
    })?;
    let envelope: SignedStateEnvelope<CleanupPoolMaintenanceJournal> =
        serde_json::from_slice(&bytes).map_err(|error| {
            cleanup_maintenance_error(&path, format!("maintenance journal is malformed: {error}"))
        })?;
    let verified = envelope
        .verify(SignedStateExpectation {
            state_kind: CLEANUP_POOL_MAINTENANCE_KIND,
            stream_id: CLEANUP_POOL_MAINTENANCE_STREAM,
            expected_signer_agent_id: Some(expected_signer),
            accepted_sequence: Some(1),
        })
        .map_err(|error| {
            cleanup_maintenance_error(&path, format!("maintenance authentication failed: {error}"))
        })?;
    if verified.schema_version != SIGNED_STATE_SCHEMA_VERSION {
        return Err(cleanup_maintenance_error(
            &path,
            "maintenance envelope schema is unsupported",
        ));
    }
    validate_cleanup_pool_maintenance_journal(&verified.payload, binding, &path)?;
    Ok(verified.payload)
}

struct CleanupPoolMaintenanceJournalWriteContext<'a> {
    handle: &'a mut CleanupPoolMaintenanceJournalHandle,
    pool: &'a fs::File,
    parent: &'a fs::File,
    archive: &'a fs::File,
    pool_path: &'a Path,
    binding: &'a CleanupPoolBinding,
    expected_signer: &'a AgentId,
    signing_key: &'a SigningKey,
}

fn write_cleanup_pool_maintenance_journal(
    context: CleanupPoolMaintenanceJournalWriteContext<'_>,
    journal: &CleanupPoolMaintenanceJournal,
) -> Result<(), GovernancePersistenceError> {
    let CleanupPoolMaintenanceJournalWriteContext {
        handle,
        pool,
        parent,
        archive,
        pool_path,
        binding,
        expected_signer,
        signing_key,
    } = context;
    let path = cleanup_maintenance_journal_path(pool_path);
    validate_cleanup_pool_maintenance_journal(journal, binding, &path)?;
    let envelope = SignedStateEnvelope::sign(
        CLEANUP_POOL_MAINTENANCE_KIND,
        CLEANUP_POOL_MAINTENANCE_STREAM,
        expected_signer.clone(),
        1,
        journal,
        signing_key,
    )
    .map_err(|error| {
        cleanup_maintenance_error(&path, format!("maintenance signing failed: {error}"))
    })?;
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|error| {
        cleanup_maintenance_error(&path, format!("maintenance serialization failed: {error}"))
    })?;
    let held_identity = handle
        .file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata));
    if held_identity != Some(handle.identity) {
        return Err(cleanup_maintenance_error(
            &path,
            "maintenance journal descriptor identity changed before write",
        ));
    }
    handle
        .file
        .set_len(0)
        .and_then(|()| handle.file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| handle.file.write_all(&bytes))
        .and_then(|()| handle.file.sync_all())
        .map_err(|source| {
            cleanup_maintenance_error(&path, format!("maintenance journal write failed: {source}"))
        })?;
    let named_identity = open_regular_entry_at(
        pool,
        OsStr::new(GOVERNANCE_CLEANUP_POOL_MAINTENANCE_JOURNAL_NAME),
    )
    .ok()
    .and_then(|file| file.metadata().ok())
    .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_identity != Some(handle.identity) {
        return Err(cleanup_maintenance_error(
            &path,
            "maintenance journal name changed during write",
        ));
    }
    pool.sync_all()
        .and_then(|()| archive.sync_all())
        .and_then(|()| parent.sync_all())
        .map_err(|source| {
            cleanup_maintenance_error(
                &path,
                format!("maintenance durability sync failed: {source}"),
            )
        })?;
    Ok(())
}

fn read_cleanup_pool_journal(
    slot: &AuthorityCleanupRetirement,
) -> Result<Vec<u8>, GovernancePersistenceError> {
    let journal = slot.journal_file.as_ref().ok_or_else(|| {
        cleanup_pool_journal_error(slot, "cleanup slot journal descriptor is missing")
    })?;
    let identity = journal
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata));
    if identity != slot.journal_identity {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal descriptor identity changed",
        ));
    }
    let mut reader = journal.try_clone().map_err(|error| {
        cleanup_pool_journal_error(
            slot,
            format!("cleanup slot journal could not be cloned: {error}"),
        )
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        cleanup_pool_journal_error(
            slot,
            format!("cleanup slot journal could not seek: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|error| {
        cleanup_pool_journal_error(
            slot,
            format!("cleanup slot journal could not be read: {error}"),
        )
    })?;
    Ok(bytes)
}

fn cleanup_pool_component(path: &Path) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.file_name().map(|name| name.as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.as_bytes().to_vec())
    }
}

fn cleanup_pool_slot_name(index: usize) -> OsString {
    OsString::from(format!("slot-{index:02}"))
}

fn cleanup_pool_transaction_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{}-{}", std::process::id(), hex::encode(bytes))
}

fn cleanup_pool_error(path: &Path, reason: impl Into<String>) -> GovernancePersistenceError {
    GovernancePersistenceError::CleanupMaintenance {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn verify_cleanup_slot_name_binding(
    slot: &AuthorityCleanupRetirement,
) -> Result<(), GovernancePersistenceError> {
    let held_identity = slot
        .file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata));
    let named_identity = directory_entry_identity_at(&slot.pool_file, &slot.slot_name)
        .map_err(|source| cleanup_pool_error(&slot.path, source.to_string()))?;
    if held_identity != Some(slot.identity) || named_identity != Some(slot.identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup slot descriptor is orphaned or its fixed name was replaced",
        ));
    }
    Ok(())
}

fn append_cleanup_pool_record(
    slot: &mut AuthorityCleanupRetirement,
    phase: CleanupPoolPhase,
    entries: Vec<CleanupPoolEntryRecord>,
) -> Result<(), GovernancePersistenceError> {
    verify_cleanup_slot_name_binding(slot)?;
    let named_lock_identity = open_regular_entry_at(
        &slot.pool_file,
        OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
    )
    .ok()
    .and_then(|lock| lock.metadata().ok())
    .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_lock_identity != Some(slot.lock_identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup pool lock name no longer refers to the held lock",
        ));
    }
    let lock_identity = slot
        .lock_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| cleanup_pool_error(&slot.path, "cleanup pool lock descriptor is invalid"))?;
    if lock_identity != slot.lock_identity {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup pool lock identity changed while slot was active",
        ));
    }
    let journal_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
    if slot.journal_file.is_none() {
        let journal = create_regular_file_at(&slot.file, journal_name).map_err(|source| {
            cleanup_pool_error(
                &slot.path,
                format!("could not create cleanup slot journal: {source}"),
            )
        })?;
        let identity = journal
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata))
            .ok_or_else(|| cleanup_pool_error(&slot.path, "cleanup slot journal is not regular"))?;
        slot.journal_identity = Some(identity);
        slot.journal_file = Some(journal);
    }
    let expected_journal_identity = slot.journal_identity.ok_or_else(|| {
        cleanup_pool_error(&slot.path, "cleanup slot journal identity is missing")
    })?;
    let named_journal_identity = open_regular_entry_at(&slot.file, journal_name)
        .ok()
        .and_then(|journal| journal.metadata().ok())
        .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_journal_identity != Some(expected_journal_identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup slot journal name no longer refers to the held journal",
        ));
    }
    let current_bytes = read_cleanup_pool_journal(slot)?;
    let (current_digest, current_phase) = validate_cleanup_pool_journal_bytes(
        slot,
        &current_bytes,
        &slot.journal_expected_bytes,
        slot.journal_expected_len,
        &slot.journal_expected_digest,
    )?;
    if current_digest != slot.previous_record_digest || current_phase != slot.journal_last_phase {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal chain state disagrees with the held transaction",
        ));
    }
    if let Some(current_phase) = current_phase {
        if matches!(
            current_phase,
            CleanupPoolPhase::ForeignPreserved | CleanupPoolPhase::Retained
        ) || cleanup_pool_phase_rank(phase) < cleanup_pool_phase_rank(current_phase)
        {
            return Err(cleanup_pool_journal_error(
                slot,
                "cleanup slot journal append would regress or extend a terminal phase",
            ));
        }
    } else if phase != CleanupPoolPhase::Reserved {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal first phase must be Reserved",
        ));
    }
    let mut record = CleanupPoolRecord {
        schema_version: CLEANUP_POOL_RECORD_SCHEMA_VERSION,
        transaction_id: slot.transaction_id.clone(),
        parent_identity: slot.parent_identity,
        pool_identity: slot.pool_identity,
        lock_identity: slot.lock_identity,
        slot_identity: slot.identity,
        target_component: slot.target_component.clone(),
        entries,
        previous_digest: current_digest,
        phase,
        record_digest: String::new(),
    };
    let bytes = cleanup_pool_record_line(&record).map_err(|source| {
        cleanup_pool_error(
            &slot.path,
            format!("could not encode cleanup slot journal: {source}"),
        )
    })?;
    record.record_digest = cleanup_pool_record_digest(&record).map_err(|source| {
        cleanup_pool_error(
            &slot.path,
            format!("could not authenticate cleanup slot journal: {source}"),
        )
    })?;
    let mut expected_bytes_after = slot.journal_expected_bytes.clone();
    expected_bytes_after.extend_from_slice(&bytes);
    let expected_len_after = expected_bytes_after.len() as u64;
    let expected_digest_after = sha256_hex(&expected_bytes_after);
    let journal = slot.journal_file.as_mut().ok_or_else(|| {
        cleanup_pool_error(&slot.path, "cleanup slot journal descriptor is missing")
    })?;
    let offset = journal.seek(SeekFrom::End(0)).map_err(|source| {
        cleanup_pool_error(
            &slot.path,
            format!("could not seek cleanup slot journal EOF: {source}"),
        )
    })?;
    if offset != slot.journal_expected_len {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal EOF moved since its authenticated read",
        ));
    }
    journal
        .write_all(&bytes)
        .and_then(|()| journal.sync_all())
        .map_err(|source| {
            cleanup_pool_error(
                &slot.path,
                format!("could not fsync cleanup slot journal: {source}"),
            )
        })?;
    let after_write_bytes = read_cleanup_pool_journal(slot)?;
    let (after_write_digest, after_write_phase) = validate_cleanup_pool_journal_bytes(
        slot,
        &after_write_bytes,
        &expected_bytes_after,
        expected_len_after,
        &expected_digest_after,
    )?;
    if after_write_digest.as_deref() != Some(record.record_digest.as_str())
        || after_write_phase != Some(phase)
    {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal chain did not converge after append",
        ));
    }
    let named_journal_identity_after = open_regular_entry_at(&slot.file, journal_name)
        .ok()
        .and_then(|journal| journal.metadata().ok())
        .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_journal_identity_after != Some(expected_journal_identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup slot journal name changed during phase append",
        ));
    }
    let named_lock_identity_after = open_regular_entry_at(
        &slot.pool_file,
        OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
    )
    .ok()
    .and_then(|lock| lock.metadata().ok())
    .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_lock_identity_after != Some(slot.lock_identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup pool lock name changed during phase append",
        ));
    }
    slot.file.sync_all().map_err(|source| {
        cleanup_pool_error(
            &slot.path,
            format!("could not fsync cleanup slot directory: {source}"),
        )
    })?;
    slot.pool_file.sync_all().map_err(|source| {
        cleanup_pool_error(
            &slot.pool_path,
            format!("could not fsync cleanup pool directory: {source}"),
        )
    })?;
    slot.parent_file.sync_all().map_err(|source| {
        cleanup_pool_error(
            &slot.path,
            format!("could not fsync cleanup pool parent: {source}"),
        )
    })?;
    let named_lock_identity_final = open_regular_entry_at(
        &slot.pool_file,
        OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
    )
    .ok()
    .and_then(|lock| lock.metadata().ok())
    .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_lock_identity_final != Some(slot.lock_identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup pool lock name changed before phase durability completed",
        ));
    }
    let named_journal_identity_final = open_regular_entry_at(&slot.file, journal_name)
        .ok()
        .and_then(|journal| journal.metadata().ok())
        .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_journal_identity_final != Some(expected_journal_identity) {
        return Err(cleanup_pool_error(
            &slot.path,
            "cleanup slot journal name changed before phase durability completed",
        ));
    }
    let final_bytes = read_cleanup_pool_journal(slot)?;
    let (final_digest, final_phase) = validate_cleanup_pool_journal_bytes(
        slot,
        &final_bytes,
        &expected_bytes_after,
        expected_len_after,
        &expected_digest_after,
    )?;
    if final_digest.as_deref() != Some(record.record_digest.as_str()) || final_phase != Some(phase)
    {
        return Err(cleanup_pool_journal_error(
            slot,
            "cleanup slot journal changed before phase durability completed",
        ));
    }
    verify_cleanup_slot_name_binding(slot)?;
    slot.journal_expected_bytes = expected_bytes_after;
    slot.journal_expected_len = expected_len_after;
    slot.journal_expected_digest = expected_digest_after;
    slot.journal_last_phase = Some(phase);
    slot.previous_record_digest = Some(record.record_digest);
    Ok(())
}

fn acquire_cleanup_pool_slot(
    path: &Path,
    parent_handle: &AuthorityCleanupParent,
) -> Result<AuthorityCleanupRetirement, GovernancePersistenceError> {
    let target_component = cleanup_pool_component(path)
        .ok_or_else(|| cleanup_pool_error(path, "cleanup target has no raw final component"))?;
    let pool_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
    if !authority_cleanup_parent_is_current(path, parent_handle) {
        return Err(cleanup_pool_error(
            path,
            "cleanup parent changed before pool acquisition",
        ));
    }
    let (pool_file, _pool_created) = open_or_create_directory_at(&parent_handle.file, pool_name)
        .map_err(|source| {
            cleanup_pool_error(path, format!("could not open cleanup pool: {source}"))
        })?;
    let pool_identity = pool_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        .ok_or_else(|| cleanup_pool_error(path, "cleanup pool is not a regular directory"))?;
    let lock_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME);
    let (lock_file, lock_created) = match create_regular_file_at(&pool_file, lock_name) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
            open_writable_entry_at(&pool_file, lock_name).map_err(|source| {
                cleanup_pool_error(path, format!("could not open cleanup pool lock: {source}"))
            })?,
            false,
        ),
        Err(source) => {
            return Err(cleanup_pool_error(
                path,
                format!("could not create cleanup pool lock: {source}"),
            ));
        }
    };
    let lock_identity = lock_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| cleanup_pool_error(path, "cleanup pool lock is not a regular file"))?;
    match lock_file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Err(cleanup_pool_error(
                path,
                "cleanup pool lock is held by another writer",
            ));
        }
        Err(fs::TryLockError::Error(source)) => {
            return Err(cleanup_pool_error(
                path,
                format!("could not lock cleanup pool: {source}"),
            ));
        }
    }
    if lock_created {
        lock_file.sync_all().map_err(|source| {
            cleanup_pool_error(
                path,
                format!("could not fsync new cleanup pool lock: {source}"),
            )
        })?;
        pool_file.sync_all().map_err(|source| {
            cleanup_pool_error(
                path,
                format!("could not fsync cleanup pool after lock: {source}"),
            )
        })?;
        parent_handle.file.sync_all().map_err(|source| {
            cleanup_pool_error(
                path,
                format!("could not fsync cleanup pool parent: {source}"),
            )
        })?;
    }
    let mut selected = None;
    for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
        let slot_name = cleanup_pool_slot_name(index);
        match open_directory_at(&pool_file, &slot_name) {
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_directory_at(&pool_file, &slot_name) {
                    Ok(file) => {
                        selected = Some((slot_name, file));
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(source) => {
                        return Err(cleanup_pool_error(
                            path,
                            format!("could not create cleanup pool slot: {source}"),
                        ));
                    }
                }
            }
            // Any existing, malformed, non-directory, symlink, or partially
            // written slot is occupied forever.  Never repair it by name and
            // never treat it as reusable capacity; an operator can inspect
            // or drain it under an exclusive maintenance protocol.
            Err(_) => continue,
        }
    }
    let Some((slot_name, file)) = selected else {
        return Err(GovernancePersistenceError::CleanupPoolExhausted {
            path: path.to_path_buf(),
        });
    };
    pool_file.sync_all().map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not fsync cleanup pool slot creation: {source}"),
        )
    })?;
    parent_handle.file.sync_all().map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not fsync cleanup pool parent: {source}"),
        )
    })?;
    let slot_identity = file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        .ok_or_else(|| cleanup_pool_error(path, "cleanup pool slot is not a directory"))?;
    let pool_path = path
        .parent()
        .unwrap_or(path)
        .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
    let slot_path = pool_path.join(&slot_name);
    let mut slot = AuthorityCleanupRetirement {
        path: slot_path,
        pool_path,
        slot_name: slot_name.clone(),
        parent_file: parent_handle.file.try_clone().map_err(|source| {
            cleanup_pool_error(path, format!("could not clone cleanup parent: {source}"))
        })?,
        parent_identity: parent_handle.identity,
        pool_file,
        pool_identity,
        lock_file,
        lock_identity,
        file,
        identity: slot_identity,
        transaction_id: cleanup_pool_transaction_id(),
        target_component,
        previous_record_digest: None,
        journal_file: None,
        journal_identity: None,
        journal_expected_bytes: Vec::new(),
        journal_expected_len: 0,
        journal_expected_digest: sha256_hex(&[]),
        journal_last_phase: None,
    };
    append_cleanup_pool_record(&mut slot, CleanupPoolPhase::Reserved, Vec::new())?;
    Ok(slot)
}

/// Reserve one slot from an already authenticated, live cleanup-pool context.
/// Unlike `acquire_cleanup_pool_slot`, this path never opens or creates the
/// pool by pathname: the context's held pool and lock descriptors are the
/// namespace capability.  This is the only allocator used by the exported
/// normal-operation retention API.
fn acquire_cleanup_pool_slot_bound(
    path: &Path,
    parent_handle: &AuthorityCleanupParent,
    context: &CleanupPoolContext,
) -> Result<AuthorityCleanupRetirement, GovernancePersistenceError> {
    let target_component = cleanup_pool_component(path)
        .ok_or_else(|| cleanup_pool_error(path, "cleanup target has no raw final component"))?;
    if !authority_cleanup_parent_is_current(path, parent_handle) {
        return Err(cleanup_pool_error(
            path,
            "cleanup parent changed before bound pool acquisition",
        ));
    }
    let pool_identity = context
        .pool_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        .ok_or_else(|| cleanup_pool_error(path, "bound cleanup pool is not a directory"))?;
    if pool_identity != context.pool_identity
        || context.parent_identity != parent_handle.identity
        || context.binding.pool_identity != context.pool_identity
        || context.binding.parent_identity != context.parent_identity
        || context.binding.lock_identity != context.lock_identity
    {
        return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: path.to_path_buf(),
            reason:
                "bound cleanup-pool context identity no longer matches its authenticated binding"
                    .to_string(),
        });
    }
    let named_lock_identity = open_regular_entry_at(
        &context.pool_file,
        OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
    )
    .ok()
    .and_then(|file| file.metadata().ok())
    .and_then(|metadata| governance_artifact_identity(&metadata));
    if named_lock_identity != Some(context.lock_identity) {
        return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: path.to_path_buf(),
            reason: "bound cleanup-pool lock name was replaced".to_string(),
        });
    }
    let mut selected = None;
    for index in 0..context.binding.slot_count {
        let slot_name = OsString::from(&context.binding.slot_names[index]);
        match open_directory_at(&context.pool_file, &slot_name) {
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match create_directory_at(&context.pool_file, &slot_name) {
                    Ok(file) => {
                        selected = Some((slot_name, file));
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(source) => {
                        return Err(cleanup_pool_error(
                            path,
                            format!("could not create bound cleanup pool slot: {source}"),
                        ));
                    }
                }
            }
            // A malformed, symlink, or non-directory entry is occupied
            // forever.  It may be handled only by explicit reset.
            Err(_) => continue,
        }
    }
    let Some((slot_name, file)) = selected else {
        return Err(GovernancePersistenceError::CleanupPoolExhausted {
            path: path.to_path_buf(),
        });
    };
    context.pool_file.sync_all().map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not fsync bound cleanup pool slot creation: {source}"),
        )
    })?;
    parent_handle.file.sync_all().map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not fsync bound cleanup pool parent: {source}"),
        )
    })?;
    let slot_identity = file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        .ok_or_else(|| cleanup_pool_error(path, "bound cleanup pool slot is not a directory"))?;
    let pool_path = context.pool_path.clone();
    let slot_path = pool_path.join(&slot_name);
    let mut slot = AuthorityCleanupRetirement {
        path: slot_path,
        pool_path,
        slot_name: slot_name.clone(),
        parent_file: parent_handle.file.try_clone().map_err(|source| {
            cleanup_pool_error(path, format!("could not clone cleanup parent: {source}"))
        })?,
        parent_identity: parent_handle.identity,
        pool_file: context.pool_file.try_clone().map_err(|source| {
            cleanup_pool_error(
                path,
                format!("could not clone bound cleanup pool: {source}"),
            )
        })?,
        pool_identity: context.pool_identity,
        lock_file: context.lock_file.try_clone().map_err(|source| {
            cleanup_pool_error(
                path,
                format!("could not clone bound cleanup lock: {source}"),
            )
        })?,
        lock_identity: context.lock_identity,
        file,
        identity: slot_identity,
        transaction_id: cleanup_pool_transaction_id(),
        target_component,
        previous_record_digest: None,
        journal_file: None,
        journal_identity: None,
        journal_expected_bytes: Vec::new(),
        journal_expected_len: 0,
        journal_expected_digest: sha256_hex(&[]),
        journal_last_phase: None,
    };
    append_cleanup_pool_record(&mut slot, CleanupPoolPhase::Reserved, Vec::new())?;
    Ok(slot)
}

fn bind_authority_cleanup_parent(path: &Path) -> Option<AuthorityCleanupParent> {
    let parent = path.parent()?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(parent).ok()?;
    let identity = file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))?;
    Some(AuthorityCleanupParent { file, identity })
}

fn authority_cleanup_parent_is_current(path: &Path, parent: &AuthorityCleanupParent) -> bool {
    path.parent()
        .and_then(|parent_path| fs::symlink_metadata(parent_path).ok())
        .and_then(|metadata| governance_directory_identity(&metadata))
        == Some(parent.identity)
}

fn open_regular_entry_at(parent: &fs::File, name: &OsStr) -> Result<fs::File, std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd, FromRawFd};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup entry name contains an interior NUL",
            )
        })?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a successful openat result owned by this function.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative cleanup open is unavailable on this platform",
        ))
    }
}

fn create_directory_at(parent: &fs::File, name: &OsStr) -> Result<fs::File, std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::io::FromRawFd;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup directory name contains an interior NUL",
            )
        })?;
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a successful openat result owned by this function.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative cleanup directory creation is unavailable on this platform",
        ))
    }
}

fn open_directory_at(parent: &fs::File, name: &OsStr) -> Result<fs::File, std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd, FromRawFd};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup directory name contains an interior NUL",
            )
        })?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative cleanup directory open is unavailable on this platform",
        ))
    }
}

/// Enumerate one held directory descriptor without reopening its pathname.
/// The duplicated descriptor is consumed by `fdopendir`; the caller's
/// descriptor remains the stable namespace capability for subsequent moves.
fn directory_entry_names(directory: &fs::File) -> Result<Vec<OsString>, std::io::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::io::AsRawFd;

        let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(duplicate);
            }
            return Err(error);
        }
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        unsafe {
            libc::closedir(stream);
        }
        Ok(names)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = directory;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "held-directory enumeration is unavailable on this platform",
        ))
    }
}

/// Read an entry identity without following a symlink.  A reset operation may
/// archive a malformed/symlink slot opaquely, so it cannot rely on
/// `openat(O_NOFOLLOW)` alone for this preflight observation.
fn directory_entry_identity_at(
    directory: &fs::File,
    name: &OsStr,
) -> Result<Option<GovernanceArtifactIdentity>, std::io::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory entry name contains an interior NUL",
            )
        })?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(error);
        }
        let stat = unsafe { stat.assume_init() };
        Ok(Some(GovernanceArtifactIdentity {
            device: stat.st_dev as u64,
            inode: stat.st_ino,
        }))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (directory, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative entry identity is unavailable on this platform",
        ))
    }
}

fn open_writable_entry_at(parent: &fs::File, name: &OsStr) -> Result<fs::File, std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd, FromRawFd};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup lock name contains an interior NUL",
            )
        })?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative cleanup lock open is unavailable on this platform",
        ))
    }
}

fn open_or_create_directory_at(
    parent: &fs::File,
    name: &OsStr,
) -> Result<(fs::File, bool), std::io::Error> {
    match create_directory_at(parent, name) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok((open_directory_at(parent, name)?, false))
        }
        Err(error) => Err(error),
    }
}

fn create_regular_file_at(parent: &fs::File, name: &OsStr) -> Result<fs::File, std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::io::FromRawFd;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic temporary name contains an interior NUL",
            )
        })?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a successful openat result owned by this function.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative atomic publication is unavailable on this platform",
        ))
    }
}

fn snapshot_cleanup_file(
    mut file: fs::File,
) -> Result<(GovernanceArtifactSnapshot, Vec<u8>), std::io::Error> {
    let metadata_before = file.metadata()?;
    let Some(identity) = governance_artifact_identity(&metadata_before) else {
        return Err(std::io::Error::other(
            "retired cleanup entry is not a regular non-symlink file",
        ));
    };
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let metadata_after = file.metadata()?;
    let Some(after_identity) = governance_artifact_identity(&metadata_after) else {
        return Err(std::io::Error::other(
            "retired cleanup entry ceased to be a regular file",
        ));
    };
    if identity != after_identity || metadata_after.len() != bytes.len() as u64 {
        return Err(std::io::Error::other(
            "retired cleanup entry changed while being snapshotted",
        ));
    }
    Ok((
        GovernanceArtifactSnapshot {
            identity,
            content_digest: sha256_hex(&bytes),
            byte_len: bytes.len() as u64,
        },
        bytes,
    ))
}

fn linkat_relative(
    source_parent: &fs::File,
    source_name: &OsStr,
    destination_parent: &fs::File,
    destination_name: &OsStr,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let source_name = CString::new(source_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup entry name contains an interior NUL",
            )
        })?;
        let destination_name = CString::new(destination_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup destination contains an interior NUL",
            )
        })?;
        let result = unsafe {
            libc::linkat(
                source_parent.as_raw_fd(),
                source_name.as_ptr(),
                destination_parent.as_raw_fd(),
                destination_name.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        );
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "dirfd-relative cleanup restore is unavailable on this platform",
        ))
    }
}

fn atomic_no_replace_move_between(
    source_parent: &fs::File,
    source_name: &OsStr,
    destination_parent: &fs::File,
    destination_name: &OsStr,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let source = CString::new(source_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup source name contains an interior NUL",
            )
        })?;
        let destination = CString::new(destination_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cleanup destination name contains an interior NUL",
            )
        })?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2 as libc::c_long,
                source_parent.as_raw_fd(),
                source.as_ptr(),
                destination_parent.as_raw_fd(),
                destination.as_ptr(),
                1u32,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                source_parent.as_raw_fd(),
                source.as_ptr(),
                destination_parent.as_raw_fd(),
                destination.as_ptr(),
                0x0000_0004u32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        );
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "atomic no-replace cleanup move is unavailable on this platform",
        ))
    }
}

/// Conditionally publish over an existing canonical artifact without ever
/// treating a pathname observation as authority.  Linux `RENAME_EXCHANGE` and
/// macOS `RENAME_SWAP` atomically exchange the temporary and canonical names;
/// the identities on both names are then checked.  If a foreign inode won the
/// final seam, the exchange is reversed while the two expected identities are
/// still held, leaving the foreign entry at the canonical name and retaining
/// our temporary for authenticated recovery.  There is deliberately no
/// unconditional unlink of the old inode: neither platform exposes a
/// conditional unlink-by-inode primitive.
fn atomic_replace_if_identity(
    source_parent: &fs::File,
    source_name: &OsStr,
    destination_parent: &fs::File,
    destination_name: &OsStr,
    expected_destination: GovernanceArtifactIdentity,
    expected_source: GovernanceArtifactIdentity,
) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::io::AsRawFd;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let source = CString::new(source_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic replacement source contains an interior NUL",
            )
        })?;
        let destination = CString::new(destination_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic replacement destination contains an interior NUL",
            )
        })?;
        let result = unsafe {
            #[cfg(target_os = "linux")]
            {
                libc::syscall(
                    libc::SYS_renameat2 as libc::c_long,
                    source_parent.as_raw_fd(),
                    source.as_ptr(),
                    destination_parent.as_raw_fd(),
                    destination.as_ptr(),
                    2u32,
                )
            }
            #[cfg(target_os = "macos")]
            {
                libc::renameatx_np(
                    source_parent.as_raw_fd(),
                    source.as_ptr(),
                    destination_parent.as_raw_fd(),
                    destination.as_ptr(),
                    0x0000_0002u32,
                )
            }
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let observed_destination =
            directory_entry_identity_at(destination_parent, destination_name)?;
        let observed_source = directory_entry_identity_at(source_parent, source_name)?;
        if observed_destination == Some(expected_source)
            && observed_source == Some(expected_destination)
        {
            return Ok(());
        }
        // A foreign destination may have appeared after the caller's initial
        // read.  Restore the exact pre-exchange namespace only if the names
        // still contain the two identities produced by this exchange.  If a
        // further writer changed either name, preserve both entries and fail
        // closed rather than guessing which inode may be removed.
        if observed_destination == Some(expected_source)
            && observed_source != Some(expected_destination)
        {
            let restore = unsafe {
                #[cfg(target_os = "linux")]
                {
                    libc::syscall(
                        libc::SYS_renameat2 as libc::c_long,
                        source_parent.as_raw_fd(),
                        source.as_ptr(),
                        destination_parent.as_raw_fd(),
                        destination.as_ptr(),
                        2u32,
                    )
                }
                #[cfg(target_os = "macos")]
                {
                    libc::renameatx_np(
                        source_parent.as_raw_fd(),
                        source.as_ptr(),
                        destination_parent.as_raw_fd(),
                        destination.as_ptr(),
                        0x0000_0002u32,
                    )
                }
            };
            if restore != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "conditional publication lost its rollback exchange: {}",
                        std::io::Error::last_os_error()
                    ),
                ));
            }
        }
        Err(std::io::Error::other(
            "canonical artifact identity changed during conditional publication",
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        );
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "descriptor-relative atomic replacement is unavailable on this platform",
        ))
    }
}

fn read_governance_artifact_snapshot(
    path: &Path,
) -> Result<Option<(GovernanceArtifactSnapshot, Vec<u8>)>, std::io::Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata_before = file.metadata()?;
    let Some(identity) = governance_artifact_identity(&metadata_before) else {
        return Err(std::io::Error::other(
            "artifact is not a regular non-symlink file",
        ));
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let metadata_after = file.metadata()?;
    let Some(after_identity) = governance_artifact_identity(&metadata_after) else {
        return Err(std::io::Error::other(
            "artifact ceased to be a regular non-symlink file",
        ));
    };
    if after_identity != identity || metadata_after.len() != bytes.len() as u64 {
        return Err(std::io::Error::other(
            "artifact changed while its immutable snapshot was being read",
        ));
    }
    Ok(Some((
        GovernanceArtifactSnapshot {
            identity,
            content_digest: sha256_hex(&bytes),
            byte_len: bytes.len() as u64,
        },
        bytes,
    )))
}

/// Read one regular artifact through an already-held parent directory
/// descriptor.  This is the mutation-safe counterpart to the pathname
/// observation helper above: a replaced parent pathname cannot redirect the
/// descriptor-bound read used by rollback and cleanup decisions.
fn read_governance_artifact_snapshot_at(
    parent: &fs::File,
    name: &OsStr,
) -> Result<Option<(GovernanceArtifactSnapshot, Vec<u8>)>, std::io::Error> {
    let file = match open_regular_entry_at(parent, name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    snapshot_cleanup_file(file).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GovernanceCheckpointLag {
    sequence: u64,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingHealthObservation {
    governing_agent_id: AgentId,
    entries: Vec<AgentHealthEntry>,
    observed_at_ms: i64,
}

/// Ephemeral health-tick backoff for a failed checkpoint repair.
///
/// A governed effect never consults this value: its repair-before-effect path
/// always attempts repair immediately. The `saturated` bit distinguishes a
/// real deadline at `i64::MAX` from an overflowed deadline, so a clock parked
/// at the maximum value cannot turn a failed repair into a tight retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GovernanceCheckpointRepairBackoff {
    retry_at_ms: i64,
    saturated: bool,
}

impl GovernanceCheckpointRepairBackoff {
    fn after(observed_at_ms: i64) -> Self {
        match observed_at_ms.checked_add(GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS) {
            Some(retry_at_ms) => Self {
                retry_at_ms,
                saturated: false,
            },
            None => Self {
                retry_at_ms: i64::MAX,
                saturated: true,
            },
        }
    }

    fn is_due(self, observed_at_ms: i64) -> bool {
        !self.saturated && observed_at_ms >= self.retry_at_ms
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedGovernanceState {
    lock_binding: GovernanceLockBinding,
    cleanup_pool_binding: CleanupPoolBinding,
    governing_agent_id: Option<AgentId>,
    /// Display identity to consensus identity bindings used by health quorum
    /// accounting. These are signed state because losing the mapping can turn a
    /// failed governor into an apparently healthy one after restart.
    display_governors: BTreeMap<AgentId, AgentId>,
    /// Admitted peer governors, by consensus identity. NEVER a key.
    ///
    /// Persisted because forgetting them is a FAIL-OPEN across restart: a
    /// policy that knows about three peers refuses every destructive action
    /// (the shipped solo transport cannot serve a four-member committee), and
    /// one that has forgotten them is back to a committee of one and starts
    /// authorizing again. The default supports signed schema evolution only;
    /// legacy unsigned state is rejected before payload deserialization.
    #[serde(default)]
    peer_governors: BTreeSet<AgentId>,
    /// The exact health observations that drive `can_act` vetoes.
    unhealthy_agents: Vec<AgentHealthEntry>,
    previous_commit_hash: String,
    receipt_counter: u64,
    partition_state: PartitionState,
    partition_started_at_ms: Option<i64>,
    last_transition_at_ms: Option<i64>,
    last_healthy_governors: usize,
    last_quorum_threshold: usize,
    active_contingency_leases: Vec<ContingencyLease>,
    #[serde(default)]
    pending_authorizations: VecDeque<PendingGovernanceAuthorization>,
    #[serde(default)]
    consumed_authorizations: VecDeque<ConsumedGovernanceAuthorization>,
    #[serde(default)]
    pending_human_authorizations: VecDeque<GovernedHumanAuthorizationHold>,
    partition_activity: Vec<PartitionActionRecord>,
    reconciliation_reports: Vec<PartitionReconciliationReport>,
    /// A signed fail-closed marker for a health observation that could not yet
    /// be committed against a repaired checkpoint. Legacy signed payloads may
    /// omit this optional field; absence means no pending observation was
    /// recorded by that older schema and is safe because no newer observation
    /// could have existed in the authenticated payload.
    #[serde(default)]
    pending_health_observation: Option<PendingHealthObservation>,
}

impl Default for PersistedGovernanceState {
    fn default() -> Self {
        Self {
            lock_binding: GovernanceLockBinding::unbound(),
            cleanup_pool_binding: CleanupPoolBinding::unbound(),
            governing_agent_id: None,
            display_governors: BTreeMap::new(),
            peer_governors: BTreeSet::new(),
            unhealthy_agents: Vec::new(),
            previous_commit_hash: "governance-bootstrap".to_string(),
            receipt_counter: 0,
            partition_state: PartitionState::Healthy,
            partition_started_at_ms: None,
            last_transition_at_ms: None,
            last_healthy_governors: 0,
            last_quorum_threshold: 0,
            active_contingency_leases: Vec::new(),
            pending_authorizations: VecDeque::new(),
            consumed_authorizations: VecDeque::new(),
            pending_human_authorizations: VecDeque::new(),
            partition_activity: Vec::new(),
            reconciliation_reports: Vec::new(),
            pending_health_observation: None,
        }
    }
}

impl PersistedGovernanceState {
    fn without_pending_health_observation(mut self) -> Self {
        self.pending_health_observation = None;
        self
    }

    fn from_runtime(state: &GovernanceState) -> Self {
        Self::from_runtime_with_binding(state, CleanupPoolBinding::unbound())
    }

    fn from_runtime_with_binding(
        state: &GovernanceState,
        cleanup_pool_binding: CleanupPoolBinding,
    ) -> Self {
        Self {
            lock_binding: GovernanceLockBinding::unbound(),
            cleanup_pool_binding,
            governing_agent_id: state.governing_agent_id.clone(),
            display_governors: state.display_governors.clone(),
            peer_governors: state.peer_governors.clone(),
            unhealthy_agents: state.unhealthy_agents.clone(),
            previous_commit_hash: state.previous_commit_hash.clone(),
            receipt_counter: state.receipt_counter,
            partition_state: state.partition_state,
            partition_started_at_ms: state.partition_started_at_ms,
            last_transition_at_ms: state.last_transition_at_ms,
            last_healthy_governors: state.last_healthy_governors,
            last_quorum_threshold: state.last_quorum_threshold,
            active_contingency_leases: state.active_contingency_leases.clone(),
            pending_authorizations: state.pending_authorizations.clone(),
            consumed_authorizations: state.consumed_authorizations.clone(),
            pending_human_authorizations: state.pending_human_authorizations.clone(),
            partition_activity: state.partition_activity.clone(),
            reconciliation_reports: state.reconciliation_reports.clone(),
            pending_health_observation: state.durable_pending_health_observation.clone(),
        }
    }

    fn restore_into(self, state: &mut GovernanceState) {
        state.governing_agent_id = self.governing_agent_id;
        state.display_governors = self.display_governors;
        state.peer_governors = self.peer_governors;
        state.unhealthy_agents = self.unhealthy_agents;
        state.previous_commit_hash = self.previous_commit_hash;
        state.receipt_counter = self.receipt_counter;
        state.partition_state = self.partition_state;
        state.partition_started_at_ms = self.partition_started_at_ms;
        state.last_transition_at_ms = self.last_transition_at_ms;
        state.last_healthy_governors = self.last_healthy_governors;
        state.last_quorum_threshold = self.last_quorum_threshold;
        state.active_contingency_leases = self.active_contingency_leases;
        state.pending_authorizations = self.pending_authorizations;
        state.consumed_authorizations = self.consumed_authorizations;
        state.pending_human_authorizations = self.pending_human_authorizations;
        state.partition_activity = self.partition_activity;
        state.reconciliation_reports = self.reconciliation_reports;
        state.pending_health_observation = self.pending_health_observation.clone();
        state.durable_pending_health_observation = self.pending_health_observation;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernanceSequenceCheckpoint {
    accepted_sequence: u64,
    lock_binding: GovernanceLockBinding,
    cleanup_pool_binding: CleanupPoolBinding,
    /// A signed fail-closed marker for an observation whose state envelope
    /// could not be committed.  This is intentionally anchored in the
    /// checkpoint as well as the state envelope: when the state write itself
    /// fails, the already-existing checkpoint is still an authenticated
    /// recovery anchor that prevents a restart from treating stale Healthy as
    /// authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_health_observation: Option<PendingHealthObservation>,
}

#[derive(Debug)]
struct LoadedGovernanceState {
    payload: PersistedGovernanceState,
    sequence: u64,
    digest: String,
    checkpoint_sequence: u64,
}

#[derive(Debug)]
struct GovernanceStateVersion {
    sequence: u64,
    digest: String,
    health_marker_cleared: bool,
}

/// Result of an explicit offline permanent-lock migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernanceLockMigrationReport {
    pub state_path: PathBuf,
    pub previous_state_sequence: u64,
    pub previous_checkpoint_sequence: u64,
    pub migrated_sequence: u64,
    pub resumed_state_commit: bool,
    pub already_migrated: bool,
}

/// The only supported modes for explicit cleanup-pool maintenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceCleanupPoolMaintenanceMode {
    Drain,
    Reset,
}

/// Authenticated result of one cleanup-pool maintenance transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernanceCleanupPoolMaintenanceReport {
    pub mode: GovernanceCleanupPoolMaintenanceMode,
    pub archive_path: PathBuf,
    pub moved_slots: Vec<String>,
    pub opaque_slots: Vec<String>,
}

/// The authenticated identity and bytes a caller observed for an artifact it
/// needs to retain during normal governance operation.  The expectation is
/// checked against a no-follow descriptor before a fixed cleanup-pool slot is
/// reserved; a caller cannot use this API to make the pool accept a different
/// inode or silently create a replacement namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceCleanupArtifactExpectation {
    pub device: u64,
    pub inode: u64,
    pub content_digest: String,
    pub byte_len: u64,
}

/// Result of normal-operation retention in the authenticated fixed cleanup
/// pool.  `ForeignPreserved` and `Uncertain` are safe, non-success outcomes:
/// the caller must retain its higher-level recovery material and must not infer
/// that the expected artifact was retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceCleanupPoolRetentionOutcome {
    Retained,
    ForeignPreserved,
    PoolExhausted,
    Uncertain,
}

#[derive(Debug)]
struct VerifiedGovernanceMigrationAnchors {
    state_bytes: Vec<u8>,
    checkpoint_bytes: Vec<u8>,
    state_payload: serde_json::Value,
    state_binding: Option<GovernanceLockBinding>,
    state_sequence: u64,
    state_pending_health_observation: Option<PendingHealthObservation>,
    checkpoint_binding: Option<GovernanceLockBinding>,
    checkpoint_sequence: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum GovernancePersistenceError {
    #[error("failed to open governance state lock `{path}`: {source}")]
    OpenLock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to inspect governance state lock `{path}`: {source}")]
    InspectLock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("governance state lock `{path}` must be a regular non-symlink file")]
    InvalidLockFileType { path: PathBuf },

    #[error("governance state lock is missing at `{path}`; refusing implicit replacement")]
    MissingLock { path: PathBuf },

    #[error("governance state lock record `{path}` is invalid: {reason}")]
    InvalidLockRecord { path: PathBuf, reason: String },

    #[error("failed to read governance state lock record `{path}`: {source}")]
    ReadLockRecord {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to persist governance state lock record `{path}`: {source}")]
    WriteLockRecord {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "governance state lock path identity changed for `{path}`: held {expected}, observed {observed}; refusing persistence"
    )]
    LockIdentityChanged {
        path: PathBuf,
        expected: String,
        observed: String,
    },

    #[error(
        "signed {artifact} lock binding does not match the externally held governance lock `{path}`: expected {expected}, observed {observed}"
    )]
    LockBindingMismatch {
        path: PathBuf,
        artifact: &'static str,
        expected: String,
        observed: String,
    },

    #[error(
        "governance state persistence is unavailable on `{platform}` because secure lock-file identity checks are unsupported"
    )]
    UnsupportedLockIdentityPlatform { platform: &'static str },

    #[error("governance state lock `{path}` is held by another process")]
    StateLocked { path: PathBuf },

    #[error("failed to open governance authority lifetime lock `{path}`: {source}")]
    OpenAuthorityLock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("governance authority lifetime lock `{path}` must be a regular non-symlink file")]
    InvalidAuthorityLockFileType { path: PathBuf },

    #[error(
        "governance authority lifetime lock is missing at `{path}`; refusing implicit replacement"
    )]
    MissingAuthorityLock { path: PathBuf },

    #[error("governance authority lock binding `{path}` is held by another process")]
    AuthorityStateLocked { path: PathBuf },

    #[error(
        "governance authority lifetime lock path identity changed for `{path}`: held {expected}, observed {observed}; refusing persistence"
    )]
    AuthorityLockIdentityChanged {
        path: PathBuf,
        expected: String,
        observed: String,
    },

    #[error("failed to acquire governance state lock `{path}`: {source}")]
    LockState {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("governance state is missing at `{path}`; refusing implicit reinitialization")]
    MissingState { path: PathBuf },

    #[error("governance sequence checkpoint is missing at `{path}`")]
    MissingSequence { path: PathBuf },

    #[error(
        "governance persistence already exists at `{state_path}` or `{sequence_path}`; refusing initialization"
    )]
    AlreadyInitialized {
        state_path: PathBuf,
        sequence_path: PathBuf,
    },

    #[error(
        "legacy unsigned governance state at `{path}` is not trusted; run explicit offline reinitialization"
    )]
    LegacyUnsignedState { path: PathBuf },

    #[error("failed to read governance state `{path}`: {source}")]
    ReadState {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse signed governance state `{path}`: {source}")]
    ParseState {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to read governance sequence checkpoint `{path}`: {source}")]
    ReadSequence {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse governance sequence checkpoint `{path}`: {source}")]
    ParseSequence {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("governance sequence checkpoint `{path}` is invalid: {reason}")]
    InvalidSequence { path: PathBuf, reason: String },

    #[error(
        "stale governance transaction for `{path}`: caller expected signed predecessor {expected_sequence}/{expected_digest}, durable predecessor is {observed_sequence}/{observed_digest}"
    )]
    StalePredecessor {
        path: PathBuf,
        expected_sequence: u64,
        expected_digest: String,
        observed_sequence: u64,
        observed_digest: String,
    },

    #[error("unsupported signed governance state schema version `{observed}`")]
    UnsupportedSchema { observed: u32 },

    #[error("signed governance identity binding is invalid: {reason}")]
    InvalidIdentityBinding { reason: String },

    #[error("governance migration input `{path}` is invalid: {reason}")]
    InvalidMigrationInput { path: PathBuf, reason: String },

    #[error("governance migration anchors changed while acquiring `{path}`; refusing rewrite")]
    MigrationAnchorsChanged { path: PathBuf },

    #[error(
        "governance migration state committed at sequence {sequence}, but checkpoint advancement is incomplete: {reason}"
    )]
    MigrationCheckpointLagging { sequence: u64, reason: String },

    #[error(transparent)]
    SignedState(#[from] SignedStateError),

    #[error("failed to write governance persistence `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("governance state cannot be persisted without the admitted local Tom key")]
    MissingLocalSigner,

    #[error("governance initialization did not establish both signed anchors: {reason}")]
    IncompleteInitialization { reason: String },

    #[error("explicit governance reinitialization failed: {reason}")]
    ReinitializationFailed { reason: String },

    #[error("governance cleanup pool is exhausted or requires maintenance for `{path}`: {reason}")]
    CleanupMaintenance { path: PathBuf, reason: String },

    #[error("governance cleanup pool is exhausted for `{path}`; explicit maintenance is required")]
    CleanupPoolExhausted { path: PathBuf },

    #[error("governance cleanup-pool namespace changed for `{path}`: {reason}")]
    CleanupPoolNamespaceChanged { path: PathBuf, reason: String },

    #[error("cleanup-pool maintenance is busy for `{path}` ({resource})")]
    MaintenanceBusy { path: PathBuf, resource: String },

    #[error("cleanup-pool maintenance journal `{path}` is invalid: {reason}")]
    CleanupMaintenanceJournal { path: PathBuf, reason: String },

    #[error("cleanup-pool maintenance archive `{path}` is unavailable: {reason}")]
    CleanupMaintenanceArchive { path: PathBuf, reason: String },
}

fn read_migration_anchor(
    path: &Path,
    state_anchor: bool,
) -> Result<Vec<u8>, GovernancePersistenceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if state_anchor {
            GovernancePersistenceError::ReadState {
                path: path.to_path_buf(),
                source,
            }
        } else {
            GovernancePersistenceError::ReadSequence {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "anchor must be a regular non-symlink file".to_string(),
        });
    }
    fs::read(path).map_err(|source| {
        if state_anchor {
            GovernancePersistenceError::ReadState {
                path: path.to_path_buf(),
                source,
            }
        } else {
            GovernancePersistenceError::ReadSequence {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn decode_migration_state_payload(
    path: &Path,
    payload: &serde_json::Value,
) -> Result<(PersistedGovernanceState, Option<GovernanceLockBinding>), GovernancePersistenceError> {
    let mut unsigned_shape = payload.clone();
    let object = unsigned_shape.as_object_mut().ok_or_else(|| {
        GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "signed state payload is not a JSON object".to_string(),
        }
    })?;
    let binding = object
        .remove("lock_binding")
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: format!("signed state lock binding is invalid: {error}"),
        })?;
    let cleanup_pool_binding = object.remove("cleanup_pool_binding");
    let cleanup_pool_binding_present = cleanup_pool_binding.is_some();
    if let Some(cleanup_pool_binding) = cleanup_pool_binding {
        object.insert("cleanup_pool_binding".to_string(), cleanup_pool_binding);
    }
    let mut typed_shape = unsigned_shape.clone();
    let unbound = serde_json::to_value(GovernanceLockBinding::unbound()).map_err(|error| {
        GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: format!("lock binding could not be normalized: {error}"),
        }
    })?;
    let Some(typed_object) = typed_shape.as_object_mut() else {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "signed state payload is not a JSON object".to_string(),
        });
    };
    typed_object.insert("lock_binding".to_string(), unbound);
    if !cleanup_pool_binding_present {
        typed_object.insert(
            "cleanup_pool_binding".to_string(),
            serde_json::to_value(CleanupPoolBinding::unbound()).map_err(|error| {
                GovernancePersistenceError::InvalidMigrationInput {
                    path: path.to_path_buf(),
                    reason: format!("cleanup pool binding could not be normalized: {error}"),
                }
            })?,
        );
    }
    let typed: PersistedGovernanceState = serde_json::from_value(typed_shape).map_err(|error| {
        GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: format!(
                "state is not the exact supported pre-lock/current security schema: {error}"
            ),
        }
    })?;
    let mut round_trip = serde_json::to_value(&typed).map_err(|error| {
        GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: format!("state schema could not be normalized: {error}"),
        }
    })?;
    let Some(round_trip_object) = round_trip.as_object_mut() else {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "normalized state is not a JSON object".to_string(),
        });
    };
    round_trip_object.remove("lock_binding");
    if !cleanup_pool_binding_present {
        round_trip_object.remove("cleanup_pool_binding");
    }
    if round_trip != unsigned_shape {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "state omits required security fields or uses unsupported defaults".to_string(),
        });
    }
    Ok((typed, binding))
}

fn decode_migration_checkpoint_payload(
    path: &Path,
    payload: &serde_json::Value,
    envelope_sequence: u64,
) -> Result<
    (
        Option<GovernanceLockBinding>,
        Option<PendingHealthObservation>,
    ),
    GovernancePersistenceError,
> {
    let mut unsigned_shape = payload.clone();
    let object = unsigned_shape.as_object_mut().ok_or_else(|| {
        GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "signed checkpoint payload is not a JSON object".to_string(),
        }
    })?;
    let binding = object
        .remove("lock_binding")
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: format!("signed checkpoint lock binding is invalid: {error}"),
        })?;
    let pending_health_observation = object
        .remove("pending_health_observation")
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: format!("signed checkpoint pending health marker is invalid: {error}"),
        })?;
    // Current signed streams carry the authenticated cleanup-pool namespace
    // beside the lock binding. Migration validates and rewrites that copy
    // through the held cleanup context; it is not part of the legacy
    // checkpoint sequence shape check below.
    object.remove("cleanup_pool_binding");
    let accepted_sequence = unsigned_shape
        .get("accepted_sequence")
        .and_then(serde_json::Value::as_u64);
    if unsigned_shape
        .as_object()
        .is_none_or(|object| object.len() != 1)
        || accepted_sequence != Some(envelope_sequence)
        || envelope_sequence == 0
    {
        return Err(GovernancePersistenceError::InvalidSequence {
            path: path.to_path_buf(),
            reason: "signed migration checkpoint must contain only an accepted_sequence and optional pending health marker matching its positive envelope sequence"
                .to_string(),
        });
    }
    Ok((binding, pending_health_observation))
}

fn verify_governance_migration_anchors(
    path: &Path,
    governing_agent_id: &AgentId,
    expected_signer_agent_id: &AgentId,
) -> Result<VerifiedGovernanceMigrationAnchors, GovernancePersistenceError> {
    let sequence_path = path.with_extension("sequence.json");
    let state_bytes = read_migration_anchor(path, true)?;
    let state_shape: serde_json::Value =
        serde_json::from_slice(&state_bytes).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: path.to_path_buf(),
                source,
            }
        })?;
    if state_shape.get("statement").is_none() || state_shape.get("signature").is_none() {
        return Err(GovernancePersistenceError::LegacyUnsignedState {
            path: path.to_path_buf(),
        });
    }
    let state_envelope: SignedStateEnvelope<serde_json::Value> =
        serde_json::from_value(state_shape).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: path.to_path_buf(),
                source,
            }
        })?;

    let checkpoint_bytes = read_migration_anchor(&sequence_path, false)?;
    let checkpoint_envelope: SignedStateEnvelope<serde_json::Value> =
        serde_json::from_slice(&checkpoint_bytes).map_err(|source| {
            GovernancePersistenceError::ParseSequence {
                path: sequence_path.clone(),
                source,
            }
        })?;
    let checkpoint = checkpoint_envelope.verify(SignedStateExpectation {
        state_kind: GOVERNANCE_CHECKPOINT_KIND,
        stream_id: GOVERNANCE_STATE_STREAM,
        expected_signer_agent_id: Some(expected_signer_agent_id),
        accepted_sequence: None,
    })?;
    if checkpoint.schema_version != SIGNED_STATE_SCHEMA_VERSION {
        return Err(GovernancePersistenceError::UnsupportedSchema {
            observed: checkpoint.schema_version,
        });
    }
    let (checkpoint_binding, checkpoint_pending_health_observation) =
        decode_migration_checkpoint_payload(
            &sequence_path,
            &checkpoint.payload,
            checkpoint.sequence,
        )?;

    let state = state_envelope.verify(SignedStateExpectation {
        state_kind: GOVERNANCE_STATE_KIND,
        stream_id: GOVERNANCE_STATE_STREAM,
        expected_signer_agent_id: Some(expected_signer_agent_id),
        accepted_sequence: Some(checkpoint.sequence),
    })?;
    if state.schema_version != SIGNED_STATE_SCHEMA_VERSION {
        return Err(GovernancePersistenceError::UnsupportedSchema {
            observed: state.schema_version,
        });
    }
    if state.sequence == 0 {
        return Err(GovernancePersistenceError::InvalidSequence {
            path: path.to_path_buf(),
            reason: "signed governance state sequence must be positive".to_string(),
        });
    }
    let (typed_state, state_binding) = decode_migration_state_payload(path, &state.payload)?;
    if typed_state.governing_agent_id.as_ref() != Some(governing_agent_id)
        || typed_state.display_governors.get(governing_agent_id) != Some(expected_signer_agent_id)
    {
        return Err(GovernancePersistenceError::InvalidIdentityBinding {
            reason: format!(
                "persisted governor `{governing_agent_id}` is not bound to admitted local signer `{expected_signer_agent_id}`"
            ),
        });
    }
    if state_binding.is_none() && checkpoint_binding.is_some() {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: sequence_path,
            reason: "checkpoint is lock-bound while its state predecessor is unbound".to_string(),
        });
    }
    if state.sequence == checkpoint.sequence && state_binding != checkpoint_binding {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: path.to_path_buf(),
            reason: "state and checkpoint at the same sequence have divergent lock bindings"
                .to_string(),
        });
    }
    if checkpoint_pending_health_observation
        .as_ref()
        .is_some_and(|pending| {
            typed_state
                .pending_health_observation
                .as_ref()
                .is_some_and(|state_pending| state_pending != pending)
        })
    {
        return Err(GovernancePersistenceError::InvalidMigrationInput {
            path: sequence_path.clone(),
            reason: "checkpoint pending health marker is not present identically in its authenticated state predecessor"
                .to_string(),
        });
    }
    Ok(VerifiedGovernanceMigrationAnchors {
        state_bytes,
        checkpoint_bytes,
        state_payload: state.payload,
        state_binding,
        state_sequence: state.sequence,
        state_pending_health_observation: checkpoint_pending_health_observation
            .or(typed_state.pending_health_observation),
        checkpoint_binding,
        checkpoint_sequence: checkpoint.sequence,
    })
}

fn ensure_lock_identity_supported() -> Result<(), GovernancePersistenceError> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(
            GovernancePersistenceError::UnsupportedLockIdentityPlatform {
                platform: std::env::consts::OS,
            },
        )
    }
}

/// Derive the canonical process-lifetime authority sidecar for a governance
/// state path. The sidecar deliberately replaces the state extension rather
/// than appending to it, yielding e.g. `state.authority.lock`.
pub fn governance_authority_lock_path(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref().with_extension("authority.lock")
}

/// Validate a canonical authority sidecar and return its regular-file identity.
/// Symlinks, directories, missing files, and unsupported identity platforms all
/// fail closed so a selector cannot bind two logical paths to different locks.
pub fn governance_authority_lock_identity(
    state_path: impl AsRef<Path>,
) -> Result<GovernanceAuthorityLockIdentity, GovernancePersistenceError> {
    let path = governance_authority_lock_path(state_path);
    let metadata = fs::symlink_metadata(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            GovernancePersistenceError::MissingAuthorityLock { path: path.clone() }
        } else {
            GovernancePersistenceError::OpenAuthorityLock {
                path: path.clone(),
                source,
            }
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(GovernancePersistenceError::InvalidAuthorityLockFileType { path });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(GovernanceAuthorityLockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(
            GovernancePersistenceError::UnsupportedLockIdentityPlatform {
                platform: std::env::consts::OS,
            },
        )
    }
}

/// Validate the authority sidecars for two logical state paths and return their
/// shared filesystem identity. Path-selection code must call this after it has
/// created any missing sidecar as a hard link while holding its selection lock;
/// a pair with different devices/inodes is never a single authority stream.
pub fn governance_authority_lock_pair_identity(
    first_state_path: impl AsRef<Path>,
    second_state_path: impl AsRef<Path>,
) -> Result<GovernanceAuthorityLockIdentity, GovernancePersistenceError> {
    let first_state_path = first_state_path.as_ref().to_path_buf();
    let second_state_path = second_state_path.as_ref().to_path_buf();
    let second_path = governance_authority_lock_path(&second_state_path);
    let first = governance_authority_lock_identity(&first_state_path)?;
    let second = governance_authority_lock_identity(&second_state_path)?;
    if first != second {
        return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
            path: second_path,
            expected: authority_lock_identity_description(first),
            observed: authority_lock_identity_description(second),
        });
    }
    Ok(first)
}

/// Opaque nonblocking quiescence guard for explicit cleanup-pool maintenance.
///
/// The guard owns the process-lifetime authority sidecar lock.  It must be
/// acquired before the state lock and is consumed by a drain/reset operation;
/// it never deletes or replaces the sidecar on drop.
#[derive(Debug)]
pub struct GovernanceCleanupPoolMaintenanceGuard {
    state_path: PathBuf,
    sidecar_path: PathBuf,
    file: Option<fs::File>,
    identity: GovernanceAuthorityLockIdentity,
    transferred: bool,
}

/// Pre-construction capability for retaining a verified governance artifact.
/// The caller must already hold the daemon's external path-selection lock;
/// this guard adds the authenticated parent/pool namespace and nonblocking pool
/// lock, but deliberately does not acquire the governance state lock.  Drop it
/// before calling a policy constructor.
#[derive(Debug)]
pub struct GovernanceCleanupPoolRetentionGuard {
    state_path: PathBuf,
    parent: AuthorityCleanupParent,
    pool_path: PathBuf,
    pool_file: fs::File,
    lock_file: fs::File,
    binding_file: fs::File,
    binding_identity: GovernanceArtifactIdentity,
    binding: CleanupPoolBinding,
    expected_governing_agent_id: AgentId,
    expected_signer_agent_id: AgentId,
}

impl Drop for GovernanceCleanupPoolRetentionGuard {
    fn drop(&mut self) {
        // Advisory locks are released with the descriptor.  The fixed pool,
        // signed binding, and any retained slots are intentionally preserved
        // for the subsequent constructor or explicit maintenance operation.
    }
}

fn retention_guard_error(path: &Path, reason: impl Into<String>) -> GovernancePersistenceError {
    GovernancePersistenceError::CleanupPoolNamespaceChanged {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn read_retention_guard_anchor(
    state_path: &Path,
    parent: &AuthorityCleanupParent,
    name: &OsStr,
    sequence: bool,
) -> Result<Option<(Vec<u8>, GovernanceArtifactIdentity)>, GovernancePersistenceError> {
    let file = match open_regular_entry_at(&parent.file, name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(retention_guard_error(
                state_path,
                format!(
                    "{} anchor is not a regular no-follow file: {source}",
                    if sequence { "sequence" } else { "state" }
                ),
            ));
        }
    };
    let before = file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| {
            retention_guard_error(
                state_path,
                format!(
                    "{} anchor is not a regular file",
                    if sequence { "sequence" } else { "state" }
                ),
            )
        })?;
    let mut reader = file.try_clone().map_err(|source| {
        retention_guard_error(
            state_path,
            format!("anchor descriptor could not clone: {source}"),
        )
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(|source| {
        retention_guard_error(state_path, format!("anchor could not seek: {source}"))
    })?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|source| {
        retention_guard_error(state_path, format!("anchor could not read: {source}"))
    })?;
    let after = file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata));
    if after != Some(before)
        || file
            .metadata()
            .ok()
            .is_none_or(|metadata| metadata.len() != bytes.len() as u64)
    {
        return Err(retention_guard_error(
            state_path,
            "anchor changed while being read",
        ));
    }
    Ok(Some((bytes, before)))
}

fn verify_retention_guard_anchors(
    state_path: &Path,
    state_bytes: &[u8],
    checkpoint_bytes: &[u8],
    binding: &CleanupPoolBinding,
    expected_governing_agent_id: &AgentId,
    expected_signer_agent_id: &AgentId,
) -> Result<(), GovernancePersistenceError> {
    let checkpoint: SignedStateEnvelope<GovernanceSequenceCheckpoint> =
        serde_json::from_slice(checkpoint_bytes).map_err(|error| {
            retention_guard_error(
                state_path,
                format!("signed sequence anchor is malformed: {error}"),
            )
        })?;
    let verified_checkpoint = checkpoint
        .verify(SignedStateExpectation {
            state_kind: GOVERNANCE_CHECKPOINT_KIND,
            stream_id: GOVERNANCE_STATE_STREAM,
            expected_signer_agent_id: Some(expected_signer_agent_id),
            accepted_sequence: None,
        })
        .map_err(|error| {
            retention_guard_error(state_path, format!("sequence anchor refused: {error}"))
        })?;
    if verified_checkpoint.schema_version != SIGNED_STATE_SCHEMA_VERSION
        || verified_checkpoint.payload.cleanup_pool_binding != *binding
    {
        return Err(retention_guard_error(
            state_path,
            "signed checkpoint schema or cleanup binding does not match the held pool",
        ));
    }
    let state: SignedStateEnvelope<PersistedGovernanceState> = serde_json::from_slice(state_bytes)
        .map_err(|error| {
            retention_guard_error(
                state_path,
                format!("signed state anchor is malformed: {error}"),
            )
        })?;
    let verified_state = state
        .verify(SignedStateExpectation {
            state_kind: GOVERNANCE_STATE_KIND,
            stream_id: GOVERNANCE_STATE_STREAM,
            expected_signer_agent_id: Some(expected_signer_agent_id),
            accepted_sequence: Some(verified_checkpoint.payload.accepted_sequence),
        })
        .map_err(|error| {
            retention_guard_error(state_path, format!("state anchor refused: {error}"))
        })?;
    if verified_state.schema_version != SIGNED_STATE_SCHEMA_VERSION
        || verified_state.payload.cleanup_pool_binding != *binding
        || verified_state.payload.governing_agent_id.as_ref() != Some(expected_governing_agent_id)
        || verified_state
            .payload
            .display_governors
            .get(expected_governing_agent_id)
            != Some(expected_signer_agent_id)
    {
        return Err(retention_guard_error(
            state_path,
            "signed state identity, schema, or cleanup binding does not match the request",
        ));
    }
    Ok(())
}

impl GovernanceCleanupPoolMaintenanceGuard {
    fn verify(&self) -> Result<(), GovernancePersistenceError> {
        let file =
            self.file
                .as_ref()
                .ok_or_else(|| GovernancePersistenceError::MaintenanceBusy {
                    path: self.state_path.clone(),
                    resource: "maintenance guard was already transferred".to_string(),
                })?;
        verify_governance_authority_lock_path(&self.sidecar_path, file, self.identity)
    }

    fn transfer(
        mut self,
    ) -> Result<
        (PathBuf, fs::File, GovernanceAuthorityLockIdentity, bool),
        GovernancePersistenceError,
    > {
        self.verify()?;
        let file = self
            .file
            .take()
            .ok_or_else(|| GovernancePersistenceError::MaintenanceBusy {
                path: self.state_path.clone(),
                resource: "maintenance guard was already transferred".to_string(),
            })?;
        self.transferred = true;
        Ok((self.sidecar_path.clone(), file, self.identity, false))
    }
}

impl Drop for GovernanceCleanupPoolMaintenanceGuard {
    fn drop(&mut self) {
        if !self.transferred {
            drop(self.file.take());
        }
    }
}

/// A verified authority-pair lifetime guard transferred from a selector into
/// governance construction.  The guard owns the locked current sidecar and
/// verifies that the current and legacy sidecars remain hard links to the same
/// inode until construction consumes it.  A constructor that rejects the
/// guard leaves newly-created sidecars eligible for exact-identity cleanup;
/// it never reacquires by pathname.
#[derive(Debug)]
pub struct GovernanceAuthorityPairGuard {
    current_state_path: PathBuf,
    legacy_state_path: PathBuf,
    primary_sidecar_path: PathBuf,
    legacy_sidecar_path: PathBuf,
    file: Option<fs::File>,
    identity: GovernanceAuthorityLockIdentity,
    created_primary: bool,
    created_legacy: bool,
    transferred: bool,
}

struct GovernanceAuthorityPairTransfer {
    primary: (PathBuf, fs::File, GovernanceAuthorityLockIdentity, bool),
    cleanup_primary: fs::File,
    legacy_sidecar_path: PathBuf,
    identity: GovernanceAuthorityLockIdentity,
    created_legacy: bool,
}

/// Acquire and verify the shared current/legacy authority sidecar while the
/// caller still holds its selection lock.  The legacy sidecar is created only
/// with a no-replace hard link to the already-locked current inode.
pub fn acquire_governance_authority_pair_guard(
    current_state_path: impl AsRef<Path>,
    legacy_state_path: impl AsRef<Path>,
) -> Result<GovernanceAuthorityPairGuard, GovernancePersistenceError> {
    ensure_lock_identity_supported()?;
    let current_state_path = current_state_path.as_ref().to_path_buf();
    let legacy_state_path = legacy_state_path.as_ref().to_path_buf();
    let primary_sidecar_path = governance_authority_lock_path(&current_state_path);
    let legacy_sidecar_path = governance_authority_lock_path(&legacy_state_path);
    if primary_sidecar_path == legacy_sidecar_path {
        return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
            path: legacy_sidecar_path,
            expected: "distinct current and legacy sidecars".to_string(),
            observed: "same sidecar path".to_string(),
        });
    }
    let (file, identity, created_primary) =
        open_governance_authority_lock(&primary_sidecar_path, true)?;
    let mut created_legacy = false;
    let result = (|| {
        match fs::symlink_metadata(&legacy_sidecar_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(GovernancePersistenceError::InvalidAuthorityLockFileType {
                        path: legacy_sidecar_path.clone(),
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::hard_link(&primary_sidecar_path, &legacy_sidecar_path).map_err(|source| {
                    GovernancePersistenceError::OpenAuthorityLock {
                        path: legacy_sidecar_path.clone(),
                        source,
                    }
                })?;
                created_legacy = true;
                if let Some(parent) = legacy_sidecar_path.parent() {
                    fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|source| GovernancePersistenceError::OpenAuthorityLock {
                            path: parent.to_path_buf(),
                            source,
                        })?;
                }
            }
            Err(source) => {
                return Err(GovernancePersistenceError::OpenAuthorityLock {
                    path: legacy_sidecar_path.clone(),
                    source,
                });
            }
        }
        let observed = governance_authority_lock_identity(&legacy_state_path)?;
        if observed != identity {
            return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                path: legacy_sidecar_path.clone(),
                expected: authority_lock_identity_description(identity),
                observed: authority_lock_identity_description(observed),
            });
        }
        verify_governance_authority_lock_path(&primary_sidecar_path, &file, identity)?;
        Ok(())
    })();
    if let Err(error) = result {
        let mut cleanup_errors = Vec::new();
        if created_legacy
            && let Err(cleanup_error) = remove_authority_lock_if_identity_with_held_file(
                &legacy_sidecar_path,
                &file,
                identity,
            )
        {
            cleanup_errors.push(cleanup_error);
        }
        if created_primary {
            if let Err(cleanup_error) =
                remove_new_authority_lock_if_owned(&primary_sidecar_path, file, identity)
            {
                cleanup_errors.push(cleanup_error);
            }
        } else {
            drop(file);
        }
        return Err(compose_operation_cleanup_failure(
            &primary_sidecar_path,
            error,
            cleanup_errors,
        ));
    }
    Ok(GovernanceAuthorityPairGuard {
        current_state_path,
        legacy_state_path,
        primary_sidecar_path,
        legacy_sidecar_path,
        file: Some(file),
        identity,
        created_primary,
        created_legacy,
        transferred: false,
    })
}

impl GovernanceAuthorityPairGuard {
    /// Return the inode identity that was verified for both logical sidecar
    /// paths.  The value is a capability provenance marker, not a pathname
    /// lookup; callers must still transfer this guard to construction rather
    /// than reacquiring either sidecar by name.
    pub fn identity(&self) -> GovernanceAuthorityLockIdentity {
        self.identity
    }

    /// Revalidate the pair while the guard is still held.  This is useful for
    /// a selector's final pre-construction check and never opens a second
    /// descriptor or lock stream.
    pub fn verify(&self) -> Result<(), GovernancePersistenceError> {
        self.verify_for_state_path(&self.current_state_path)
    }

    fn verify_for_state_path(&self, state_path: &Path) -> Result<(), GovernancePersistenceError> {
        let canonical = governance_authority_lock_path(state_path);
        if canonical != self.primary_sidecar_path && canonical != self.legacy_sidecar_path {
            return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                path: canonical,
                expected: self.primary_sidecar_path.display().to_string(),
                observed: "guard belongs to a different authority pair".to_string(),
            });
        }
        let file =
            self.file
                .as_ref()
                .ok_or_else(|| GovernancePersistenceError::OpenAuthorityLock {
                    path: self.primary_sidecar_path.clone(),
                    source: std::io::Error::other("authority pair guard was already transferred"),
                })?;
        verify_governance_authority_lock_path(&self.primary_sidecar_path, file, self.identity)?;
        let current = governance_authority_lock_identity(&self.current_state_path)?;
        let legacy = governance_authority_lock_identity(&self.legacy_state_path)?;
        if current != self.identity || legacy != self.identity {
            return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                path: self.legacy_sidecar_path.clone(),
                expected: authority_lock_identity_description(self.identity),
                observed: format!(
                    "current {}, legacy {}",
                    authority_lock_identity_description(current),
                    authority_lock_identity_description(legacy)
                ),
            });
        }
        Ok(())
    }

    fn transfer(
        mut self,
        state_path: &Path,
    ) -> Result<GovernanceAuthorityPairTransfer, GovernancePersistenceError> {
        self.verify_for_state_path(state_path)?;
        let cleanup_primary = self
            .file
            .as_ref()
            .ok_or_else(|| GovernancePersistenceError::OpenAuthorityLock {
                path: self.primary_sidecar_path.clone(),
                source: std::io::Error::other("authority pair guard was already transferred"),
            })?
            .try_clone()
            .map_err(|source| GovernancePersistenceError::OpenAuthorityLock {
                path: self.primary_sidecar_path.clone(),
                source,
            })?;
        let file =
            self.file
                .take()
                .ok_or_else(|| GovernancePersistenceError::OpenAuthorityLock {
                    path: self.primary_sidecar_path.clone(),
                    source: std::io::Error::other("authority pair guard was already transferred"),
                })?;
        self.transferred = true;
        Ok(GovernanceAuthorityPairTransfer {
            primary: (
                self.primary_sidecar_path.clone(),
                file,
                self.identity,
                self.created_primary,
            ),
            cleanup_primary,
            legacy_sidecar_path: self.legacy_sidecar_path.clone(),
            identity: self.identity,
            created_legacy: self.created_legacy,
        })
    }
}

impl Drop for GovernanceAuthorityPairGuard {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        let Some(file) = self.file.take() else {
            return;
        };
        if self.created_legacy {
            let _ = remove_authority_lock_if_identity(&self.legacy_sidecar_path, self.identity);
        }
        if self.created_primary {
            let _ =
                remove_new_authority_lock_if_owned(&self.primary_sidecar_path, file, self.identity);
        } else {
            drop(file);
        }
    }
}

fn authority_lock_identity_description(identity: GovernanceAuthorityLockIdentity) -> String {
    format!("device {}, inode {}", identity.device, identity.inode)
}

fn authority_lock_identity_from_metadata(
    metadata: &fs::Metadata,
) -> Option<GovernanceAuthorityLockIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(GovernanceAuthorityLockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Owns a newly-created authority sidecar until acquisition has completed.
/// If any fsync, lock, or identity check fails, the drop path removes the
/// name only when it still denotes the exact inode held by this guard.  A
/// replacement, pre-existing file, symlink, or non-regular path is never
/// deleted as cleanup collateral.
struct NewAuthorityLockGuard {
    path: PathBuf,
    file: Option<fs::File>,
}

impl NewAuthorityLockGuard {
    fn new(path: &Path, file: fs::File) -> Self {
        Self {
            path: path.to_path_buf(),
            file: Some(file),
        }
    }

    fn file(&self) -> Result<&fs::File, GovernancePersistenceError> {
        self.file
            .as_ref()
            .ok_or_else(|| GovernancePersistenceError::OpenAuthorityLock {
                path: self.path.clone(),
                source: std::io::Error::other("authority lock guard lost its file"),
            })
    }

    fn disarm(
        mut self,
        identity: GovernanceAuthorityLockIdentity,
    ) -> Result<(fs::File, GovernanceAuthorityLockIdentity), GovernancePersistenceError> {
        Ok((
            self.file
                .take()
                .ok_or_else(|| GovernancePersistenceError::OpenAuthorityLock {
                    path: self.path.clone(),
                    source: std::io::Error::other("authority lock guard lost its file"),
                })?,
            identity,
        ))
    }
}

impl Drop for NewAuthorityLockGuard {
    fn drop(&mut self) {
        let Some(file) = self.file.take() else {
            return;
        };
        let expected = file
            .metadata()
            .ok()
            .and_then(|metadata| authority_lock_identity_from_metadata(&metadata));
        if let Some(expected) = expected {
            let _ = remove_verified_authority_entry(&self.path, &file, expected);
        }
        // Keep the descriptor (and its advisory lock) held through quarantine:
        // cooperating replacement attempts cannot win the directory-entry
        // transition and leave cleanup deleting a foreign inode.
        drop(file);
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum InjectedAuthorityLockFailure {
    FileSync,
    ParentSync,
    TryLock,
    IdentityVerification,
    PostAcquireVerification,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedHealthCrashPoint {
    Intent,
    StateWrite,
    CheckpointWrite,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectedReinitializationCrashPoint {
    ArchiveCreated,
    OriginalsQuarantined,
    StateRenamed,
    CheckpointRenamed,
    BeforeCommitJournal,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupMaintenanceCrashPoint {
    Prepared,
    AfterMove(usize),
    BeforeCompleted,
}

#[cfg(test)]
thread_local! {
    static INJECT_AUTHORITY_LOCK_FAILURE:
        std::cell::RefCell<Option<(PathBuf, InjectedAuthorityLockFailure)>> =
        const { std::cell::RefCell::new(None) };
    static INJECT_HEALTH_CRASH:
        std::cell::RefCell<Option<(PathBuf, InjectedHealthCrashPoint)>> =
        const { std::cell::RefCell::new(None) };
static INJECT_REINITIALIZATION_CRASH:
        std::cell::RefCell<Option<(PathBuf, InjectedReinitializationCrashPoint)>> =
        const { std::cell::RefCell::new(None) };
    static INJECT_REINITIALIZATION_COMMIT_JOURNAL_FAILURE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    static INJECT_CLEANUP_MAINTENANCE_CRASH:
        std::cell::RefCell<Option<(PathBuf, CleanupMaintenanceCrashPoint)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
type AuthorityCleanupBarrier = (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
type AuthorityCleanupPostVerifyBarrier = (
    PathBuf,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
type AuthorityCleanupPreRenameBarrier = (
    PathBuf,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
type AuthorityCleanupFinalUnlinkBarrier = (
    PathBuf,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
type AuthorityCleanupFinalAbsenceBarrier =
    (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
type AuthorityCleanupSourceFinalBarrier =
    (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
type AuthorityCleanupPostMoveBarrier = (
    PathBuf,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
type AuthorityCleanupReclaimBarrier = (
    PathBuf,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
type ReinitializationArchiveBarrier = (
    PathBuf,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
type ReinitializationPublicationBarrier =
    (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
type ReinitializationRestoreLinkBarrier =
    (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
type GovernanceStreamCleanupBarrier = (PathBuf, Arc<std::sync::Barrier>, Arc<std::sync::Barrier>);

#[cfg(test)]
type CleanupMaintenanceMoveBarrier = (
    PathBuf,
    String,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
);

#[cfg(test)]
static AUTHORITY_CLEANUP_BARRIER: std::sync::OnceLock<Mutex<Option<AuthorityCleanupBarrier>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_POST_VERIFY_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupPostVerifyBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_PRE_RENAME_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupPreRenameBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_FINAL_UNLINK_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupFinalUnlinkBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_FINAL_ABSENCE_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupFinalAbsenceBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_SOURCE_FINAL_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupSourceFinalBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_POST_MOVE_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupPostMoveBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_RECLAIM_BARRIER: std::sync::OnceLock<
    Mutex<Option<AuthorityCleanupReclaimBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AUTHORITY_CLEANUP_TEST_MUTEX: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

#[cfg(test)]
static REINITIALIZATION_ARCHIVE_BARRIER: std::sync::OnceLock<
    Mutex<Option<ReinitializationArchiveBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static REINITIALIZATION_PUBLICATION_BARRIER: std::sync::OnceLock<
    Mutex<Option<ReinitializationPublicationBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static REINITIALIZATION_RESTORE_LINK_BARRIER: std::sync::OnceLock<
    Mutex<Option<ReinitializationRestoreLinkBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static GOVERNANCE_STREAM_CLEANUP_BARRIER: std::sync::OnceLock<
    Mutex<Option<GovernanceStreamCleanupBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static CLEANUP_MAINTENANCE_MOVE_BARRIER: std::sync::OnceLock<
    Mutex<Option<CleanupMaintenanceMoveBarrier>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn lock_authority_cleanup_tests() -> std::sync::MutexGuard<'static, ()> {
    AUTHORITY_CLEANUP_TEST_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
fn install_cleanup_maintenance_move_barrier(
    pool_path: &Path,
    slot_name: &str,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *CLEANUP_MAINTENANCE_MOVE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        pool_path.to_path_buf(),
        slot_name.to_string(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_before_cleanup_maintenance_move(pool_path: &Path, slot_name: &str) {
    let barrier = CLEANUP_MAINTENANCE_MOVE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, target_slot, _, _)| target == pool_path && target_slot == slot_name)
        .map(|(_, _, reached, resume)| (Arc::clone(reached), Arc::clone(resume)));
    if let Some((reached, resume)) = barrier {
        reached.wait();
        resume.wait();
        CLEANUP_MAINTENANCE_MOVE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_barrier(
    path: &Path,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *AUTHORITY_CLEANUP_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_after_authority_cleanup_identity_read(path: &Path) {
    let mut barrier = AUTHORITY_CLEANUP_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let barrier = if barrier
        .as_ref()
        .is_some_and(|(target, _, _)| target == path)
    {
        barrier.take()
    } else {
        None
    };
    if let Some((_, reached, resume)) = barrier {
        reached.wait();
        resume.wait();
    }
}

#[cfg(test)]
fn install_authority_cleanup_post_verify_barrier(
    path: &Path,
) -> (
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let destination = Arc::new(Mutex::new(None));
    *AUTHORITY_CLEANUP_POST_VERIFY_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
        Arc::clone(&destination),
    ));
    (reached, resume, destination)
}

#[cfg(test)]
fn pause_after_authority_cleanup_post_verify(path: &Path, quarantine: &Path) {
    let barrier = AUTHORITY_CLEANUP_POST_VERIFY_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _, _)| target == path)
        .map(|(_, reached, resume, destination)| {
            (
                Arc::clone(reached),
                Arc::clone(resume),
                Arc::clone(destination),
            )
        });
    if let Some((reached, resume, destination)) = barrier {
        *destination
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(quarantine.to_path_buf());
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_POST_VERIFY_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_pre_rename_barrier(
    path: &Path,
) -> (
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let destination = Arc::new(Mutex::new(None));
    *AUTHORITY_CLEANUP_PRE_RENAME_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
        Arc::clone(&destination),
    ));
    (reached, resume, destination)
}

#[cfg(test)]
fn pause_before_authority_cleanup_rename(path: &Path, quarantine: &Path) {
    let barrier = AUTHORITY_CLEANUP_PRE_RENAME_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _, _)| target == path)
        .map(|(_, reached, resume, destination)| {
            (
                Arc::clone(reached),
                Arc::clone(resume),
                Arc::clone(destination),
            )
        });
    if let Some((reached, resume, destination)) = barrier {
        *destination
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(quarantine.to_path_buf());
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_PRE_RENAME_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_source_final_barrier(
    path: &Path,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *AUTHORITY_CLEANUP_SOURCE_FINAL_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_after_authority_cleanup_source_identity_read(path: &Path) {
    let barrier = AUTHORITY_CLEANUP_SOURCE_FINAL_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _)| target == path)
        .map(|(_, reached, resume)| (Arc::clone(reached), Arc::clone(resume)));
    if let Some((reached, resume)) = barrier {
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_SOURCE_FINAL_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_post_move_barrier(
    path: &Path,
) -> (
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let retirement = Arc::new(Mutex::new(None));
    *AUTHORITY_CLEANUP_POST_MOVE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
        Arc::clone(&retirement),
    ));
    (reached, resume, retirement)
}

#[cfg(test)]
fn pause_after_authority_cleanup_move(path: &Path, retirement: &Path) {
    let barrier = AUTHORITY_CLEANUP_POST_MOVE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _, _)| target == path)
        .map(|(_, reached, resume, retirement_path)| {
            (
                Arc::clone(reached),
                Arc::clone(resume),
                Arc::clone(retirement_path),
            )
        });
    if let Some((reached, resume, retirement_path)) = barrier {
        *retirement_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(retirement.to_path_buf());
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_POST_MOVE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_reclaim_barrier(
    path: &Path,
) -> (
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let reclaim = Arc::new(Mutex::new(None));
    *AUTHORITY_CLEANUP_RECLAIM_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
        Arc::clone(&reclaim),
    ));
    (reached, resume, reclaim)
}

#[cfg(test)]
fn pause_after_authority_cleanup_reclaim_snapshot(path: &Path, reclaim: &Path) {
    let barrier = AUTHORITY_CLEANUP_RECLAIM_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _, _)| target == path)
        .map(|(_, reached, resume, destination)| {
            (
                Arc::clone(reached),
                Arc::clone(resume),
                Arc::clone(destination),
            )
        });
    if let Some((reached, resume, destination)) = barrier {
        *destination
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reclaim.to_path_buf());
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_RECLAIM_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_final_unlink_barrier(
    path: &Path,
) -> (
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let destination = Arc::new(Mutex::new(None));
    *AUTHORITY_CLEANUP_FINAL_UNLINK_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
        Arc::clone(&destination),
    ));
    (reached, resume, destination)
}

#[cfg(test)]
fn pause_after_authority_cleanup_final_identity_read(path: &Path, quarantine: &Path) {
    let barrier = AUTHORITY_CLEANUP_FINAL_UNLINK_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _, _)| target == path)
        .map(|(_, reached, resume, destination)| {
            (
                Arc::clone(reached),
                Arc::clone(resume),
                Arc::clone(destination),
            )
        });
    if let Some((reached, resume, destination)) = barrier {
        *destination
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(quarantine.to_path_buf());
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_FINAL_UNLINK_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_authority_cleanup_final_absence_barrier(
    path: &Path,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *AUTHORITY_CLEANUP_FINAL_ABSENCE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_after_authority_cleanup_final_absence_read(path: &Path) {
    let barrier = AUTHORITY_CLEANUP_FINAL_ABSENCE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _)| target == path)
        .map(|(_, reached, resume)| (Arc::clone(reached), Arc::clone(resume)));
    if let Some((reached, resume)) = barrier {
        reached.wait();
        resume.wait();
        AUTHORITY_CLEANUP_FINAL_ABSENCE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_reinitialization_archive_barrier(
    path: &Path,
) -> (
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
    Arc<Mutex<Option<PathBuf>>>,
) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    let destination = Arc::new(Mutex::new(None));
    *REINITIALIZATION_ARCHIVE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
        Arc::clone(&destination),
    ));
    (reached, resume, destination)
}

#[cfg(test)]
fn install_reinitialization_publication_barrier(
    path: &Path,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *REINITIALIZATION_PUBLICATION_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_before_reinitialization_no_replace_publication(path: &Path) {
    let barrier = REINITIALIZATION_PUBLICATION_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _)| target == path)
        .map(|(_, reached, resume)| (Arc::clone(reached), Arc::clone(resume)));
    if let Some((reached, resume)) = barrier {
        reached.wait();
        resume.wait();
        REINITIALIZATION_PUBLICATION_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_reinitialization_restore_link_barrier(
    path: &Path,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *REINITIALIZATION_RESTORE_LINK_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_after_reinitialization_restore_link(path: &Path) {
    let barrier = REINITIALIZATION_RESTORE_LINK_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _)| target == path)
        .map(|(_, reached, resume)| (Arc::clone(reached), Arc::clone(resume)));
    if let Some((reached, resume)) = barrier {
        reached.wait();
        resume.wait();
        REINITIALIZATION_RESTORE_LINK_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn pause_after_reinitialization_archive_check(path: &Path, archive: &Path) {
    let barrier = REINITIALIZATION_ARCHIVE_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _, _)| target == path)
        .map(|(_, reached, resume, destination)| {
            (
                Arc::clone(reached),
                Arc::clone(resume),
                Arc::clone(destination),
            )
        });
    if let Some((reached, resume, destination)) = barrier {
        *destination
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(archive.to_path_buf());
        reached.wait();
        resume.wait();
        REINITIALIZATION_ARCHIVE_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn install_governance_stream_cleanup_barrier(
    path: &Path,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let reached = Arc::new(std::sync::Barrier::new(2));
    let resume = Arc::new(std::sync::Barrier::new(2));
    *GOVERNANCE_STREAM_CLEANUP_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
        path.to_path_buf(),
        Arc::clone(&reached),
        Arc::clone(&resume),
    ));
    (reached, resume)
}

#[cfg(test)]
fn pause_before_governance_stream_cleanup(path: &Path) {
    let barrier = GOVERNANCE_STREAM_CLEANUP_BARRIER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .filter(|(target, _, _)| target == path)
        .map(|(_, reached, resume)| (Arc::clone(reached), Arc::clone(resume)));
    if let Some((reached, resume)) = barrier {
        reached.wait();
        resume.wait();
        GOVERNANCE_STREAM_CLEANUP_BARRIER
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[cfg(test)]
fn inject_authority_lock_failure(path: &Path, failure: InjectedAuthorityLockFailure) {
    INJECT_AUTHORITY_LOCK_FAILURE.with(|injected| {
        *injected.borrow_mut() = Some((path.to_path_buf(), failure));
    });
}

#[cfg(test)]
fn take_injected_authority_lock_failure(
    path: &Path,
    failure: InjectedAuthorityLockFailure,
) -> bool {
    INJECT_AUTHORITY_LOCK_FAILURE.with(|injected| {
        let mut injected = injected.borrow_mut();
        if injected
            .as_ref()
            .is_some_and(|(target, observed)| target == path && *observed == failure)
        {
            injected.take();
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn inject_health_crash(path: &Path, point: InjectedHealthCrashPoint) {
    INJECT_HEALTH_CRASH.with(|injected| {
        *injected.borrow_mut() = Some((path.to_path_buf(), point));
    });
}

#[cfg(test)]
fn take_injected_health_crash(path: &Path, point: InjectedHealthCrashPoint) -> bool {
    INJECT_HEALTH_CRASH.with(|injected| {
        let mut injected = injected.borrow_mut();
        if injected
            .as_ref()
            .is_some_and(|(target, observed)| target == path && *observed == point)
        {
            injected.take();
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn maybe_inject_health_crash(path: &Path, point: InjectedHealthCrashPoint) {
    if take_injected_health_crash(path, point) {
        panic!("injected governance health crash at {point:?}");
    }
}

#[cfg(test)]
fn inject_reinitialization_crash(path: &Path, point: InjectedReinitializationCrashPoint) {
    INJECT_REINITIALIZATION_CRASH.with(|injected| {
        *injected.borrow_mut() = Some((path.to_path_buf(), point));
    });
}

#[cfg(test)]
fn take_injected_reinitialization_crash(
    path: &Path,
    point: InjectedReinitializationCrashPoint,
) -> bool {
    INJECT_REINITIALIZATION_CRASH.with(|injected| {
        let mut injected = injected.borrow_mut();
        if injected
            .as_ref()
            .is_some_and(|(target, observed)| target == path && *observed == point)
        {
            injected.take();
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn maybe_inject_reinitialization_crash(path: &Path, point: InjectedReinitializationCrashPoint) {
    if take_injected_reinitialization_crash(path, point) {
        panic!("injected governance reinitialization crash at {point:?}");
    }
}

#[cfg(test)]
fn inject_reinitialization_commit_journal_failure(path: &Path) {
    INJECT_REINITIALIZATION_COMMIT_JOURNAL_FAILURE.with(|target| {
        *target.borrow_mut() = Some(path.to_path_buf());
    });
}

#[cfg(test)]
fn maybe_inject_reinitialization_commit_journal_failure(path: &Path) {
    let inject = INJECT_REINITIALIZATION_COMMIT_JOURNAL_FAILURE.with(|target| {
        let mut target = target.borrow_mut();
        if target.as_deref() == Some(path) {
            target.take();
            true
        } else {
            false
        }
    });
    if inject {
        inject_atomic_parent_sync_failure(&reinitialization_journal_path(path));
    }
}

#[cfg(test)]
fn inject_cleanup_maintenance_crash(path: &Path, point: CleanupMaintenanceCrashPoint) {
    INJECT_CLEANUP_MAINTENANCE_CRASH.with(|target| {
        *target.borrow_mut() = Some((path.to_path_buf(), point));
    });
}

#[cfg(test)]
fn maybe_inject_cleanup_maintenance_crash(path: &Path, point: CleanupMaintenanceCrashPoint) {
    let should_crash = INJECT_CLEANUP_MAINTENANCE_CRASH.with(|target| {
        let mut target = target.borrow_mut();
        if target
            .as_ref()
            .is_some_and(|(target_path, expected)| target_path == path && *expected == point)
        {
            target.take();
            true
        } else {
            false
        }
    });
    if should_crash {
        panic!("injected cleanup maintenance crash at {point:?}");
    }
}

fn open_governance_authority_lock(
    path: &Path,
    allow_create: bool,
) -> Result<(fs::File, GovernanceAuthorityLockIdentity, bool), GovernancePersistenceError> {
    ensure_lock_identity_supported()?;
    if allow_create && let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| {
            GovernancePersistenceError::OpenAuthorityLock {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    for _ in 0..2 {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(GovernancePersistenceError::OpenAuthorityLock {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        if let Some(metadata) = metadata {
            if !metadata.file_type().is_file() {
                return Err(GovernancePersistenceError::InvalidAuthorityLockFileType {
                    path: path.to_path_buf(),
                });
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file = options.open(path).map_err(|source| {
                GovernancePersistenceError::OpenAuthorityLock {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            let identity = {
                let held = file.metadata().map_err(|source| {
                    GovernancePersistenceError::OpenAuthorityLock {
                        path: path.to_path_buf(),
                        source,
                    }
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    GovernanceAuthorityLockIdentity {
                        device: held.dev(),
                        inode: held.ino(),
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = held;
                    return Err(
                        GovernancePersistenceError::UnsupportedLockIdentityPlatform {
                            platform: std::env::consts::OS,
                        },
                    );
                }
            };
            match file.try_lock() {
                Ok(()) => {
                    let named = fs::symlink_metadata(path).map_err(|source| {
                        GovernancePersistenceError::OpenAuthorityLock {
                            path: path.to_path_buf(),
                            source,
                        }
                    })?;
                    if !named.file_type().is_file() {
                        return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                            path: path.to_path_buf(),
                            expected: authority_lock_identity_description(identity),
                            observed: "nonregular or symlink".to_string(),
                        });
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        let named_identity = GovernanceAuthorityLockIdentity {
                            device: named.dev(),
                            inode: named.ino(),
                        };
                        if named_identity != identity {
                            return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                                path: path.to_path_buf(),
                                expected: authority_lock_identity_description(identity),
                                observed: authority_lock_identity_description(named_identity),
                            });
                        }
                    }
                    return Ok((file, identity, false));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(GovernancePersistenceError::AuthorityStateLocked {
                        path: path.to_path_buf(),
                    });
                }
                Err(fs::TryLockError::Error(source)) => {
                    return Err(GovernancePersistenceError::OpenAuthorityLock {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        if !allow_create {
            return Err(GovernancePersistenceError::MissingAuthorityLock {
                path: path.to_path_buf(),
            });
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        match options.open(path) {
            Ok(file) => {
                let guard = NewAuthorityLockGuard::new(path, file);
                #[cfg(test)]
                if take_injected_authority_lock_failure(
                    path,
                    InjectedAuthorityLockFailure::FileSync,
                ) {
                    return Err(GovernancePersistenceError::OpenAuthorityLock {
                        path: path.to_path_buf(),
                        source: std::io::Error::other("injected authority lock file sync failure"),
                    });
                }
                guard.file()?.sync_all().map_err(|source| {
                    GovernancePersistenceError::OpenAuthorityLock {
                        path: path.to_path_buf(),
                        source,
                    }
                })?;
                if let Some(parent) = path.parent() {
                    #[cfg(test)]
                    if take_injected_authority_lock_failure(
                        path,
                        InjectedAuthorityLockFailure::ParentSync,
                    ) {
                        return Err(GovernancePersistenceError::OpenAuthorityLock {
                            path: path.to_path_buf(),
                            source: std::io::Error::other(
                                "injected authority lock parent sync failure",
                            ),
                        });
                    }
                    fs::File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(|source| GovernancePersistenceError::OpenAuthorityLock {
                            path: path.to_path_buf(),
                            source,
                        })?;
                }
                let identity = {
                    let metadata = guard.file()?.metadata().map_err(|source| {
                        GovernancePersistenceError::OpenAuthorityLock {
                            path: path.to_path_buf(),
                            source,
                        }
                    })?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        GovernanceAuthorityLockIdentity {
                            device: metadata.dev(),
                            inode: metadata.ino(),
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = metadata;
                        return Err(
                            GovernancePersistenceError::UnsupportedLockIdentityPlatform {
                                platform: std::env::consts::OS,
                            },
                        );
                    }
                };
                #[cfg(test)]
                if take_injected_authority_lock_failure(path, InjectedAuthorityLockFailure::TryLock)
                {
                    return Err(GovernancePersistenceError::AuthorityStateLocked {
                        path: path.to_path_buf(),
                    });
                }
                guard.file()?.try_lock().map_err(|error| match error {
                    fs::TryLockError::WouldBlock => {
                        GovernancePersistenceError::AuthorityStateLocked {
                            path: path.to_path_buf(),
                        }
                    }
                    fs::TryLockError::Error(source) => {
                        GovernancePersistenceError::OpenAuthorityLock {
                            path: path.to_path_buf(),
                            source,
                        }
                    }
                })?;
                #[cfg(test)]
                if take_injected_authority_lock_failure(
                    path,
                    InjectedAuthorityLockFailure::IdentityVerification,
                ) {
                    return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                        path: path.to_path_buf(),
                        expected: authority_lock_identity_description(identity),
                        observed: "injected identity verification failure".to_string(),
                    });
                }
                let named = fs::symlink_metadata(path).map_err(|source| {
                    GovernancePersistenceError::OpenAuthorityLock {
                        path: path.to_path_buf(),
                        source,
                    }
                })?;
                if !named.file_type().is_file() {
                    return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                        path: path.to_path_buf(),
                        expected: authority_lock_identity_description(identity),
                        observed: "nonregular or symlink".to_string(),
                    });
                }
                if let Some(named_identity) = authority_lock_identity_from_metadata(&named)
                    && named_identity != identity
                {
                    return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                        path: path.to_path_buf(),
                        expected: authority_lock_identity_description(identity),
                        observed: authority_lock_identity_description(named_identity),
                    });
                }
                let (file, identity) = guard.disarm(identity)?;
                return Ok((file, identity, true));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(GovernancePersistenceError::OpenAuthorityLock {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
    Err(GovernancePersistenceError::OpenAuthorityLock {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "authority lock path changed during open",
        ),
    })
}

/// Acquire the external quiescence guard required by explicit cleanup-pool
/// maintenance.  Existing authority/state owners are reported as typed busy
/// contention; no pool or archive path is touched by this operation.
pub fn acquire_governance_cleanup_pool_maintenance_guard(
    state_path: impl AsRef<Path>,
) -> Result<GovernanceCleanupPoolMaintenanceGuard, GovernancePersistenceError> {
    let state_path = state_path.as_ref().to_path_buf();
    let sidecar_path = governance_authority_lock_path(&state_path);
    let (file, identity, created) =
        open_governance_authority_lock(&sidecar_path, false).map_err(|error| match error {
            GovernancePersistenceError::AuthorityStateLocked { .. } => {
                GovernancePersistenceError::MaintenanceBusy {
                    path: state_path.clone(),
                    resource: "authority sidecar".to_string(),
                }
            }
            other => other,
        })?;
    if created {
        drop(file);
        return Err(GovernancePersistenceError::MaintenanceBusy {
            path: state_path,
            resource: "authority sidecar was unexpectedly created".to_string(),
        });
    }
    let guard = GovernanceCleanupPoolMaintenanceGuard {
        state_path,
        sidecar_path,
        file: Some(file),
        identity,
        transferred: false,
    };
    guard.verify()?;
    Ok(guard)
}

/// Acquire the pre-construction normal-retention capability.  The caller must
/// hold its external path-selection/quiescence lock while invoking this
/// function and must drop the returned guard before a governance constructor
/// acquires the state lock.  Existing streams require two authenticated anchors
/// and an exact signed pool binding; a genuinely fresh pair of absent anchors
/// may create that signed binding for the first explicit Initialize adoption.
pub fn acquire_governance_cleanup_pool_retention_guard(
    state_path: impl AsRef<Path>,
    expected_governing_agent_id: AgentId,
    expected_signer_agent_id: AgentId,
    signing_key: SigningKey,
) -> Result<GovernanceCleanupPoolRetentionGuard, GovernancePersistenceError> {
    let state_path = state_path.as_ref().to_path_buf();
    let actual_signer = AgentId::from_verifying_key(&signing_key.verifying_key());
    if actual_signer != expected_signer_agent_id {
        return Err(retention_guard_error(
            &state_path,
            "retention signer does not match the expected signer identity",
        ));
    }
    let parent = bind_authority_cleanup_parent(&state_path).ok_or_else(|| {
        retention_guard_error(
            &state_path,
            "retention stream parent is not a regular directory",
        )
    })?;
    if !authority_cleanup_parent_is_current(&state_path, &parent) {
        return Err(retention_guard_error(
            &state_path,
            "retention stream parent changed during acquisition",
        ));
    }
    let state_name = state_path
        .file_name()
        .ok_or_else(|| retention_guard_error(&state_path, "retention state has no final name"))?;
    let sequence_path = state_path.with_extension("sequence.json");
    let sequence_name = sequence_path.file_name().ok_or_else(|| {
        retention_guard_error(&state_path, "retention sequence has no final name")
    })?;
    let state_present = directory_entry_identity_at(&parent.file, state_name)
        .map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("state anchor inspection failed: {source}"),
            )
        })?
        .is_some();
    let sequence_present = directory_entry_identity_at(&parent.file, sequence_name)
        .map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("sequence anchor inspection failed: {source}"),
            )
        })?
        .is_some();
    if state_present != sequence_present {
        return Err(retention_guard_error(
            &state_path,
            "mixed state/checkpoint anchors are not eligible for pre-construction retention",
        ));
    }
    let existing_anchors = if state_present {
        let state = read_retention_guard_anchor(&state_path, &parent, state_name, false)?
            .ok_or_else(|| retention_guard_error(&state_path, "state anchor disappeared"))?;
        let sequence = read_retention_guard_anchor(&state_path, &parent, sequence_name, true)?
            .ok_or_else(|| retention_guard_error(&state_path, "sequence anchor disappeared"))?;
        Some((state, sequence))
    } else {
        None
    };
    let pool_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
    let (pool_file, pool_created) = if existing_anchors.is_some() {
        (
            open_directory_at(&parent.file, pool_name).map_err(|source| {
                retention_guard_error(
                    &state_path,
                    format!("signed stream cleanup pool is missing or changed: {source}"),
                )
            })?,
            false,
        )
    } else {
        open_or_create_directory_at(&parent.file, pool_name).map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("fresh cleanup pool could not be opened: {source}"),
            )
        })?
    };
    let pool_identity = pool_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        .ok_or_else(|| retention_guard_error(&state_path, "cleanup pool is not a directory"))?;
    let binding_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME);
    let binding_preexisting = directory_entry_identity_at(&pool_file, binding_name)
        .map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("cleanup pool binding inspection failed: {source}"),
            )
        })?
        .is_some();
    if existing_anchors.is_none() && !pool_created && !binding_preexisting {
        let entries = directory_entry_names(&pool_file).map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("existing cleanup pool enumeration failed: {source}"),
            )
        })?;
        if !entries.is_empty() {
            return Err(retention_guard_error(
                &state_path,
                "existing cleanup pool has entries but no authenticated binding",
            ));
        }
    }
    if existing_anchors.is_none() && !pool_created && binding_preexisting {
        let binding_probe = open_writable_entry_at(&pool_file, binding_name).map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("existing cleanup pool binding could not be opened: {source}"),
            )
        })?;
        let mut bytes = Vec::new();
        binding_probe
            .try_clone()
            .and_then(|mut reader| reader.read_to_end(&mut bytes).map(|_| reader))
            .map_err(|source| {
                retention_guard_error(
                    &state_path,
                    format!("existing cleanup pool binding could not be read: {source}"),
                )
            })?;
        let envelope: SignedStateEnvelope<CleanupPoolBinding> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                retention_guard_error(
                    &state_path,
                    format!("existing cleanup pool binding is malformed: {error}"),
                )
            })?;
        envelope
            .verify(SignedStateExpectation {
                state_kind: CLEANUP_POOL_BINDING_KIND,
                stream_id: CLEANUP_POOL_BINDING_STREAM,
                expected_signer_agent_id: Some(&expected_signer_agent_id),
                accepted_sequence: Some(1),
            })
            .map_err(|error| {
                retention_guard_error(
                    &state_path,
                    format!("existing cleanup pool binding refused: {error}"),
                )
            })?;
    }
    let lock_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME);
    let (lock_file, lock_created) = if existing_anchors.is_some() || binding_preexisting {
        (
            open_writable_entry_at(&pool_file, lock_name).map_err(|source| {
                retention_guard_error(
                    &state_path,
                    format!("signed stream cleanup pool lock is missing or changed: {source}"),
                )
            })?,
            false,
        )
    } else {
        match create_regular_file_at(&pool_file, lock_name) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                open_writable_entry_at(&pool_file, lock_name).map_err(|source| {
                    retention_guard_error(
                        &state_path,
                        format!("cleanup pool lock could not be opened: {source}"),
                    )
                })?,
                false,
            ),
            Err(source) => {
                return Err(retention_guard_error(
                    &state_path,
                    format!("cleanup pool lock could not be created: {source}"),
                ));
            }
        }
    };
    let lock_identity = lock_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| retention_guard_error(&state_path, "cleanup pool lock is not regular"))?;
    if let Err(error) = lock_file.try_lock() {
        return Err(match error {
            fs::TryLockError::WouldBlock => GovernancePersistenceError::MaintenanceBusy {
                path: state_path,
                resource: "cleanup pool lock".to_string(),
            },
            fs::TryLockError::Error(source) => retention_guard_error(
                &state_path,
                format!("cleanup pool lock could not be acquired: {source}"),
            ),
        });
    }
    if lock_created {
        lock_file
            .sync_all()
            .and_then(|()| pool_file.sync_all())
            .and_then(|()| parent.file.sync_all())
            .map_err(|source| {
                retention_guard_error(
                    &state_path,
                    format!("fresh cleanup pool durability sync failed: {source}"),
                )
            })?;
    }
    let pool_path = state_path
        .parent()
        .unwrap_or(&state_path)
        .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
    let (mut binding_file, binding_created) = if existing_anchors.is_some() || binding_preexisting {
        (
            open_writable_entry_at(&pool_file, binding_name).map_err(|source| {
                retention_guard_error(
                    &state_path,
                    format!("signed stream cleanup pool binding is missing or changed: {source}"),
                )
            })?,
            false,
        )
    } else {
        match create_regular_file_at(&pool_file, binding_name) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                open_writable_entry_at(&pool_file, binding_name).map_err(|source| {
                    retention_guard_error(
                        &state_path,
                        format!("cleanup pool binding could not be opened: {source}"),
                    )
                })?,
                false,
            ),
            Err(source) => {
                return Err(retention_guard_error(
                    &state_path,
                    format!("cleanup pool binding could not be created: {source}"),
                ));
            }
        }
    };
    let binding_identity = binding_file
        .metadata()
        .ok()
        .and_then(|metadata| governance_artifact_identity(&metadata))
        .ok_or_else(|| retention_guard_error(&state_path, "cleanup pool binding is not regular"))?;
    let mut binding_bytes = Vec::new();
    let mut binding_reader = binding_file.try_clone().map_err(|source| {
        retention_guard_error(
            &state_path,
            format!("cleanup pool binding could not clone: {source}"),
        )
    })?;
    binding_reader
        .read_to_end(&mut binding_bytes)
        .map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("cleanup pool binding could not read: {source}"),
            )
        })?;
    let binding = if binding_created && binding_bytes.is_empty() {
        CleanupPoolBinding::new(parent.identity, pool_identity, lock_identity)
    } else {
        let envelope: SignedStateEnvelope<CleanupPoolBinding> =
            serde_json::from_slice(&binding_bytes).map_err(|error| {
                retention_guard_error(
                    &state_path,
                    format!("cleanup pool binding is unsigned or malformed: {error}"),
                )
            })?;
        let verified = envelope
            .verify(SignedStateExpectation {
                state_kind: CLEANUP_POOL_BINDING_KIND,
                stream_id: CLEANUP_POOL_BINDING_STREAM,
                expected_signer_agent_id: Some(&expected_signer_agent_id),
                accepted_sequence: Some(1),
            })
            .map_err(|error| {
                retention_guard_error(
                    &state_path,
                    format!("cleanup pool binding refused: {error}"),
                )
            })?;
        if verified.schema_version != SIGNED_STATE_SCHEMA_VERSION {
            return Err(retention_guard_error(
                &state_path,
                "cleanup pool binding schema is unsupported",
            ));
        }
        verified.payload
    };
    binding
        .validate_namespace(parent.identity, pool_identity, lock_identity)
        .map_err(|reason| retention_guard_error(&state_path, reason))?;
    if binding_created && binding_bytes.is_empty() {
        let envelope = SignedStateEnvelope::sign(
            CLEANUP_POOL_BINDING_KIND,
            CLEANUP_POOL_BINDING_STREAM,
            expected_signer_agent_id.clone(),
            1,
            binding.clone(),
            &signing_key,
        )?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            retention_guard_error(
                &state_path,
                format!("cleanup pool binding serialization failed: {source}"),
            )
        })?;
        binding_file
            .write_all(&bytes)
            .and_then(|()| binding_file.sync_all())
            .and_then(|()| pool_file.sync_all())
            .and_then(|()| parent.file.sync_all())
            .map_err(|source| {
                retention_guard_error(
                    &state_path,
                    format!("cleanup pool binding durability failed: {source}"),
                )
            })?;
    }
    if let Some(((state_bytes, _), (checkpoint_bytes, _))) = existing_anchors {
        verify_retention_guard_anchors(
            &state_path,
            &state_bytes,
            &checkpoint_bytes,
            &binding,
            &expected_governing_agent_id,
            &expected_signer_agent_id,
        )?;
    }
    if let Some(mut journal) = open_cleanup_pool_maintenance_journal(&pool_file, &pool_path, false)?
    {
        let maintenance = read_cleanup_pool_maintenance_journal(
            &mut journal,
            &pool_file,
            &pool_path,
            &binding,
            &expected_signer_agent_id,
        )?;
        if !matches!(
            maintenance.phase,
            CleanupPoolMaintenanceJournalPhase::Completed
        ) {
            return Err(GovernancePersistenceError::CleanupMaintenanceJournal {
                path: cleanup_maintenance_journal_path(&pool_path),
                reason: "cleanup maintenance is active during pre-construction retention"
                    .to_string(),
            });
        }
    }
    Ok(GovernanceCleanupPoolRetentionGuard {
        state_path,
        parent,
        pool_path,
        pool_file,
        lock_file,
        binding_file,
        binding_identity,
        binding,
        expected_governing_agent_id,
        expected_signer_agent_id,
    })
}

impl GovernanceCleanupPoolRetentionGuard {
    /// Retain an artifact using the exact pool namespace held by this
    /// pre-construction guard.  The fixed slot is reserved before the source
    /// move; no pool or binding pathname is reopened as an authority source.
    pub fn retain_cleanup_artifact(
        &self,
        path: impl AsRef<Path>,
        expected: GovernanceCleanupArtifactExpectation,
    ) -> Result<GovernanceCleanupPoolRetentionOutcome, GovernancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let expected_parent = self
            .state_path
            .parent()
            .unwrap_or(&self.state_path)
            .to_path_buf();
        if path.parent().map(Path::to_path_buf).as_ref() != Some(&expected_parent)
            || !authority_cleanup_parent_is_current(&self.state_path, &self.parent)
        {
            return Err(retention_guard_error(
                &path,
                "pre-construction retention target parent changed or is outside the held namespace",
            ));
        }
        let held_pool_identity = self
            .pool_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata));
        if held_pool_identity != Some(self.binding.pool_identity)
            || self.binding.parent_identity != self.parent.identity
        {
            return Err(retention_guard_error(
                &path,
                "held pre-construction cleanup pool identity changed",
            ));
        }
        let named_lock_identity = open_regular_entry_at(
            &self.pool_file,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
        )
        .ok()
        .and_then(|file| file.metadata().ok())
        .and_then(|metadata| governance_artifact_identity(&metadata));
        if named_lock_identity != Some(self.binding.lock_identity) {
            return Err(retention_guard_error(
                &path,
                "pre-construction cleanup pool lock name changed",
            ));
        }
        let named_binding_identity = open_regular_entry_at(
            &self.pool_file,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
        )
        .ok()
        .and_then(|file| file.metadata().ok())
        .and_then(|metadata| governance_artifact_identity(&metadata));
        if named_binding_identity != Some(self.binding_identity) {
            return Err(retention_guard_error(
                &path,
                "pre-construction cleanup pool binding name changed",
            ));
        }
        let mut binding_reader = self.binding_file.try_clone().map_err(|source| {
            retention_guard_error(
                &path,
                format!("cleanup pool binding clone failed: {source}"),
            )
        })?;
        binding_reader.seek(SeekFrom::Start(0)).map_err(|source| {
            retention_guard_error(&path, format!("cleanup pool binding seek failed: {source}"))
        })?;
        let mut binding_bytes = Vec::new();
        binding_reader
            .read_to_end(&mut binding_bytes)
            .map_err(|source| {
                retention_guard_error(&path, format!("cleanup pool binding read failed: {source}"))
            })?;
        let envelope: SignedStateEnvelope<CleanupPoolBinding> =
            serde_json::from_slice(&binding_bytes).map_err(|error| {
                retention_guard_error(&path, format!("cleanup pool binding changed: {error}"))
            })?;
        let verified = envelope
            .verify(SignedStateExpectation {
                state_kind: CLEANUP_POOL_BINDING_KIND,
                stream_id: CLEANUP_POOL_BINDING_STREAM,
                expected_signer_agent_id: Some(&self.expected_signer_agent_id),
                accepted_sequence: Some(1),
            })
            .map_err(|error| {
                retention_guard_error(&path, format!("cleanup pool binding changed: {error}"))
            })?;
        if verified.payload != self.binding {
            return Err(retention_guard_error(
                &path,
                "pre-construction cleanup pool binding content changed",
            ));
        }
        let state_name = self
            .state_path
            .file_name()
            .ok_or_else(|| retention_guard_error(&path, "retention state has no final name"))?;
        let sequence_path = self.state_path.with_extension("sequence.json");
        let sequence_name = sequence_path
            .file_name()
            .ok_or_else(|| retention_guard_error(&path, "retention sequence has no final name"))?;
        let state_present = directory_entry_identity_at(&self.parent.file, state_name)
            .map_err(|source| {
                retention_guard_error(&path, format!("state anchor inspection failed: {source}"))
            })?
            .is_some();
        let sequence_present = directory_entry_identity_at(&self.parent.file, sequence_name)
            .map_err(|source| {
                retention_guard_error(
                    &path,
                    format!("sequence anchor inspection failed: {source}"),
                )
            })?
            .is_some();
        if state_present != sequence_present {
            return Err(retention_guard_error(
                &path,
                "state/checkpoint anchor set changed while retention guard was held",
            ));
        }
        if state_present {
            let state =
                read_retention_guard_anchor(&self.state_path, &self.parent, state_name, false)?
                    .ok_or_else(|| retention_guard_error(&path, "state anchor disappeared"))?;
            let sequence =
                read_retention_guard_anchor(&self.state_path, &self.parent, sequence_name, true)?
                    .ok_or_else(|| retention_guard_error(&path, "sequence anchor disappeared"))?;
            verify_retention_guard_anchors(
                &self.state_path,
                &state.0,
                &sequence.0,
                &self.binding,
                &self.expected_governing_agent_id,
                &self.expected_signer_agent_id,
            )?;
        }
        let context = CleanupPoolContext {
            pool_path: self.pool_path.clone(),
            binding_path: self.pool_path.join(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
            parent_identity: self.parent.identity,
            pool_file: self.pool_file.try_clone().map_err(|source| {
                retention_guard_error(&path, format!("cleanup pool clone failed: {source}"))
            })?,
            pool_identity: self.binding.pool_identity,
            lock_file: self.lock_file.try_clone().map_err(|source| {
                retention_guard_error(&path, format!("cleanup pool lock clone failed: {source}"))
            })?,
            lock_identity: self.binding.lock_identity,
            binding_file: self.binding_file.try_clone().map_err(|source| {
                retention_guard_error(
                    &path,
                    format!("cleanup pool binding clone failed: {source}"),
                )
            })?,
            binding_identity: self.binding_identity,
            binding: self.binding.clone(),
            signed: true,
        };
        retain_cleanup_artifact_in_bound_pool(&path, &expected, &self.parent, &context)
    }
}

fn verify_governance_authority_lock_path(
    path: &Path,
    lock_file: &fs::File,
    expected: GovernanceAuthorityLockIdentity,
) -> Result<(), GovernancePersistenceError> {
    #[cfg(test)]
    if take_injected_authority_lock_failure(
        path,
        InjectedAuthorityLockFailure::PostAcquireVerification,
    ) {
        return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
            path: path.to_path_buf(),
            expected: authority_lock_identity_description(expected),
            observed: "injected post-acquisition identity verification failure".to_string(),
        });
    }
    let held_metadata =
        lock_file
            .metadata()
            .map_err(|source| GovernancePersistenceError::OpenAuthorityLock {
                path: path.to_path_buf(),
                source,
            })?;
    #[cfg(unix)]
    let held = {
        use std::os::unix::fs::MetadataExt;
        GovernanceAuthorityLockIdentity {
            device: held_metadata.dev(),
            inode: held_metadata.ino(),
        }
    };
    #[cfg(not(unix))]
    let held = {
        let _ = held_metadata;
        return Err(
            GovernancePersistenceError::UnsupportedLockIdentityPlatform {
                platform: std::env::consts::OS,
            },
        );
    };
    if held != expected {
        return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
            path: path.to_path_buf(),
            expected: authority_lock_identity_description(expected),
            observed: authority_lock_identity_description(held),
        });
    }
    let named = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GovernancePersistenceError::AuthorityLockIdentityChanged {
                path: path.to_path_buf(),
                expected: authority_lock_identity_description(expected),
                observed: "missing".to_string(),
            }
        } else {
            GovernancePersistenceError::OpenAuthorityLock {
                path: path.to_path_buf(),
                source: error,
            }
        }
    })?;
    if !named.file_type().is_file() {
        return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
            path: path.to_path_buf(),
            expected: authority_lock_identity_description(expected),
            observed: "nonregular or symlink".to_string(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let named_identity = GovernanceAuthorityLockIdentity {
            device: named.dev(),
            inode: named.ino(),
        };
        if named_identity != expected {
            return Err(GovernancePersistenceError::AuthorityLockIdentityChanged {
                path: path.to_path_buf(),
                expected: authority_lock_identity_description(expected),
                observed: authority_lock_identity_description(named_identity),
            });
        }
    }
    Ok(())
}

fn quarantine_outcome_from_error(error: &GovernancePersistenceError) -> QuarantineOutcome {
    match error {
        GovernancePersistenceError::CleanupPoolExhausted { .. } => QuarantineOutcome::PoolExhausted,
        GovernancePersistenceError::CleanupMaintenance { .. }
        | GovernancePersistenceError::Write { .. }
        | GovernancePersistenceError::OpenAuthorityLock { .. }
        | GovernancePersistenceError::AuthorityStateLocked { .. }
        | GovernancePersistenceError::AuthorityLockIdentityChanged { .. } => {
            QuarantineOutcome::Uncertain
        }
        _ => QuarantineOutcome::Uncertain,
    }
}

fn cleanup_error_for_outcome(
    path: &Path,
    outcome: QuarantineOutcome,
) -> GovernancePersistenceError {
    match outcome {
        QuarantineOutcome::PoolExhausted => GovernancePersistenceError::CleanupPoolExhausted {
            path: path.to_path_buf(),
        },
        _ => cleanup_pool_error(path, outcome.maintenance_reason()),
    }
}

/// Preserve the original operation error when cleanup succeeds, but make any
/// cleanup uncertainty part of the returned non-Drop failure.  Callers must
/// not proceed after ForeignPreserved, PoolExhausted, or Uncertain cleanup;
/// the retained material is the recovery authority and is never silently
/// discarded.
fn compose_operation_cleanup_failure(
    path: &Path,
    original: GovernancePersistenceError,
    mut cleanup_errors: Vec<GovernancePersistenceError>,
) -> GovernancePersistenceError {
    if cleanup_errors.is_empty() {
        return original;
    }
    if cleanup_errors.len() == 1 {
        let cleanup_error = cleanup_errors.remove(0);
        if matches!(
            &cleanup_error,
            GovernancePersistenceError::CleanupPoolExhausted { .. }
        ) {
            return cleanup_error;
        }
        cleanup_errors.push(cleanup_error);
    }
    let cleanup = cleanup_errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    cleanup_pool_error(
        path,
        format!("operation failed: {original}; cleanup failed: {cleanup}"),
    )
}

fn cleanup_pool_entry_record(
    target_component: &[u8],
    snapshot: &GovernanceArtifactSnapshot,
) -> CleanupPoolEntryRecord {
    CleanupPoolEntryRecord {
        target_component: target_component.to_vec(),
        identity: snapshot.identity,
        content_digest: snapshot.content_digest.clone(),
        byte_len: snapshot.byte_len,
    }
}

fn cleanup_pool_entry_snapshot(
    slot: &AuthorityCleanupRetirement,
    name: &OsStr,
) -> Result<GovernanceArtifactSnapshot, std::io::Error> {
    let file = open_regular_entry_at(&slot.file, name)?;
    snapshot_cleanup_file(file).map(|(snapshot, _)| snapshot)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupRestoreDecision {
    Candidate,
    Quarantine,
    BothTrusted,
    NoTrustedLink,
}

fn cleanup_pool_entry_snapshot_optional(
    slot: &AuthorityCleanupRetirement,
    name: &OsStr,
) -> Result<Option<GovernanceArtifactSnapshot>, std::io::Error> {
    match cleanup_pool_entry_snapshot(slot, name) {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn cleanup_canonical_name_absent(
    parent: &AuthorityCleanupParent,
    name: &OsStr,
) -> Result<bool, std::io::Error> {
    match open_regular_entry_at(&parent.file, name) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

/// Select a private link only from snapshots taken together at the restore
/// decision.  A foreign same-content inode is not trusted because identity is
/// part of the authenticated source snapshot.  When both links still name the
/// source, retain the normal moved-source behavior and restore quarantine.
fn restore_cleanup_pool_entry_from_trusted_link(
    slot: &AuthorityCleanupRetirement,
    source_snapshot: &GovernanceArtifactSnapshot,
    parent: &AuthorityCleanupParent,
    original_name: &OsStr,
) -> Result<CleanupRestoreDecision, std::io::Error> {
    let candidate_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME);
    let quarantine_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME);
    let candidate = cleanup_pool_entry_snapshot_optional(slot, candidate_name)?;
    let quarantine = cleanup_pool_entry_snapshot_optional(slot, quarantine_name)?;
    let candidate_trusted = candidate.as_ref() == Some(source_snapshot);
    let quarantine_trusted = quarantine.as_ref() == Some(source_snapshot);
    let decision = match (candidate_trusted, quarantine_trusted) {
        (true, false) => CleanupRestoreDecision::Candidate,
        (false, true) => CleanupRestoreDecision::Quarantine,
        (true, true) => CleanupRestoreDecision::BothTrusted,
        (false, false) => CleanupRestoreDecision::NoTrustedLink,
    };
    let selected = match decision {
        CleanupRestoreDecision::Candidate => Some(candidate_name),
        CleanupRestoreDecision::Quarantine | CleanupRestoreDecision::BothTrusted => {
            Some(quarantine_name)
        }
        CleanupRestoreDecision::NoTrustedLink => None,
    };
    if let Some(selected) = selected {
        linkat_relative(&slot.file, selected, &parent.file, original_name)?;
    }
    Ok(decision)
}

/// Quarantine one already-authenticated regular file into one write-once,
/// fixed-cardinality pool slot.  The slot descriptor is the capability for
/// every post-move read and restore; no callback is ever evaluated against a
/// pool pathname.
fn quarantine_verified_entry<F, G>(
    path: &Path,
    verify_initial: F,
    verify_quarantine: G,
) -> QuarantineOutcome
where
    F: Fn() -> bool,
    G: Fn(&Path) -> bool,
{
    let Some(parent_handle) = bind_authority_cleanup_parent(path) else {
        return QuarantineOutcome::Uncertain;
    };
    quarantine_verified_entry_at(path, &parent_handle, verify_initial, verify_quarantine)
}

fn quarantine_verified_entry_at<F, G>(
    path: &Path,
    parent_handle: &AuthorityCleanupParent,
    verify_initial: F,
    verify_quarantine: G,
) -> QuarantineOutcome
where
    F: Fn() -> bool,
    G: Fn(&Path) -> bool,
{
    if !verify_initial() {
        return QuarantineOutcome::NotVerified;
    }
    let Some(original_name) = path.file_name() else {
        return QuarantineOutcome::Uncertain;
    };
    let source_snapshot = match read_governance_artifact_snapshot(path) {
        Ok(Some((snapshot, _))) => snapshot,
        Ok(None) => return QuarantineOutcome::NotVerified,
        Err(_) => return QuarantineOutcome::Uncertain,
    };
    #[cfg(test)]
    pause_after_authority_cleanup_identity_read(path);
    if !authority_cleanup_parent_is_current(path, &parent_handle) || !verify_initial() {
        return QuarantineOutcome::NotVerified;
    }
    let mut slot = match acquire_cleanup_pool_slot(path, &parent_handle) {
        Ok(slot) => slot,
        Err(error) => return quarantine_outcome_from_error(&error),
    };
    let target_component = slot.target_component.clone();
    let candidate_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME);
    if linkat_relative(
        &parent_handle.file,
        original_name,
        &slot.file,
        candidate_name,
    )
    .is_err()
    {
        return QuarantineOutcome::Uncertain;
    }
    let candidate_snapshot = match cleanup_pool_entry_snapshot(&slot, candidate_name) {
        Ok(snapshot) => snapshot,
        Err(_) => return QuarantineOutcome::Uncertain,
    };
    if candidate_snapshot != source_snapshot {
        return QuarantineOutcome::Uncertain;
    }
    if append_cleanup_pool_record(
        &mut slot,
        CleanupPoolPhase::Reserved,
        vec![cleanup_pool_entry_record(
            &target_component,
            &candidate_snapshot,
        )],
    )
    .is_err()
    {
        return QuarantineOutcome::Uncertain;
    }
    if !authority_cleanup_parent_is_current(path, &parent_handle)
        || !verify_initial()
        // This callback is intentionally evaluated only against the original
        // path.  Pool state is verified from `slot.file` below.
        || !verify_quarantine(path)
    {
        return QuarantineOutcome::Uncertain;
    }
    #[cfg(test)]
    pause_after_authority_cleanup_source_identity_read(path);
    let quarantine_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME);
    if verify_cleanup_slot_name_binding(&slot).is_err() {
        return QuarantineOutcome::Uncertain;
    }
    if atomic_no_replace_move_between(
        &parent_handle.file,
        original_name,
        &slot.file,
        quarantine_name,
    )
    .is_err()
    {
        return QuarantineOutcome::Uncertain;
    }
    #[cfg(test)]
    let quarantine_path = slot.path.join(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME);

    #[cfg(test)]
    pause_after_authority_cleanup_move(path, &slot.path);
    // The source name must remain absent in the held original-parent
    // namespace after the move.  A writer may create a replacement during the
    // post-move seam; that is a foreign-preserved outcome, never evidence that
    // this quarantine completed.  No pathname delete follows this read.
    match open_regular_entry_at(&parent_handle.file, original_name) {
        Ok(file) => {
            let foreign_snapshot = snapshot_cleanup_file(file)
                .map(|(snapshot, _)| snapshot)
                .map_err(|_| ())
                .ok();
            let _ = append_cleanup_pool_record(
                &mut slot,
                CleanupPoolPhase::ForeignPreserved,
                foreign_snapshot
                    .as_ref()
                    .map(|snapshot| vec![cleanup_pool_entry_record(&target_component, snapshot)])
                    .unwrap_or_default(),
            );
            return QuarantineOutcome::ForeignPreserved;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return QuarantineOutcome::Uncertain,
    }
    #[cfg(test)]
    pause_before_authority_cleanup_rename(path, &quarantine_path);
    let _moved_snapshot_before = match cleanup_pool_entry_snapshot(&slot, quarantine_name) {
        Ok(snapshot) => snapshot,
        Err(_) => return QuarantineOutcome::Uncertain,
    };
    #[cfg(test)]
    pause_after_authority_cleanup_reclaim_snapshot(path, &slot.path);

    #[cfg(test)]
    pause_after_authority_cleanup_post_verify(path, &quarantine_path);
    let _moved_snapshot_after_post = match cleanup_pool_entry_snapshot(&slot, quarantine_name) {
        Ok(snapshot) => snapshot,
        Err(_) => return QuarantineOutcome::Uncertain,
    };
    let candidate_after_post = cleanup_pool_entry_snapshot(&slot, candidate_name).ok();
    if candidate_after_post.as_ref() != Some(&candidate_snapshot) {
        let _ = append_cleanup_pool_record(
            &mut slot,
            CleanupPoolPhase::ForeignPreserved,
            candidate_after_post
                .as_ref()
                .map(|snapshot| vec![cleanup_pool_entry_record(&target_component, snapshot)])
                .unwrap_or_default(),
        );
        if restore_cleanup_pool_entry_from_trusted_link(
            &slot,
            &source_snapshot,
            &parent_handle,
            original_name,
        )
        .is_err()
        {
            return QuarantineOutcome::Uncertain;
        }
        return QuarantineOutcome::ForeignPreserved;
    }
    #[cfg(test)]
    pause_after_authority_cleanup_final_identity_read(path, &quarantine_path);
    let moved_snapshot = match cleanup_pool_entry_snapshot(&slot, quarantine_name) {
        Ok(snapshot) => snapshot,
        Err(_) => return QuarantineOutcome::Uncertain,
    };
    let candidate_after_final = cleanup_pool_entry_snapshot(&slot, candidate_name).ok();
    if candidate_after_final.as_ref() != Some(&candidate_snapshot) {
        let _ = append_cleanup_pool_record(
            &mut slot,
            CleanupPoolPhase::ForeignPreserved,
            candidate_after_final
                .as_ref()
                .map(|snapshot| vec![cleanup_pool_entry_record(&target_component, snapshot)])
                .unwrap_or_default(),
        );
        if restore_cleanup_pool_entry_from_trusted_link(
            &slot,
            &source_snapshot,
            &parent_handle,
            original_name,
        )
        .is_err()
        {
            return QuarantineOutcome::Uncertain;
        }
        return QuarantineOutcome::ForeignPreserved;
    }
    // Repeat the canonical-absence check after every adversarial seam.  The
    // source move itself is atomic, but a writer can create the canonical name
    // while the private slot is being authenticated.  Leave that foreign
    // inode untouched and keep the slot for explicit recovery.
    match open_regular_entry_at(&parent_handle.file, original_name) {
        Ok(file) => {
            let foreign_snapshot = snapshot_cleanup_file(file)
                .map(|(snapshot, _)| snapshot)
                .map_err(|_| ())
                .ok();
            let _ = append_cleanup_pool_record(
                &mut slot,
                CleanupPoolPhase::ForeignPreserved,
                foreign_snapshot
                    .as_ref()
                    .map(|snapshot| vec![cleanup_pool_entry_record(&target_component, snapshot)])
                    .unwrap_or_default(),
            );
            return QuarantineOutcome::ForeignPreserved;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return QuarantineOutcome::Uncertain,
    }
    #[cfg(test)]
    pause_after_authority_cleanup_final_absence_read(path);
    if !cleanup_canonical_name_absent(&parent_handle, original_name).unwrap_or(false) {
        let foreign_snapshot = open_regular_entry_at(&parent_handle.file, original_name)
            .ok()
            .and_then(|file| snapshot_cleanup_file(file).ok())
            .map(|(snapshot, _)| snapshot);
        let _ = append_cleanup_pool_record(
            &mut slot,
            CleanupPoolPhase::ForeignPreserved,
            foreign_snapshot
                .as_ref()
                .map(|snapshot| vec![cleanup_pool_entry_record(&target_component, snapshot)])
                .unwrap_or_default(),
        );
        return QuarantineOutcome::ForeignPreserved;
    }
    if verify_cleanup_slot_name_binding(&slot).is_err() {
        return QuarantineOutcome::Uncertain;
    }
    if moved_snapshot != source_snapshot {
        let _ = append_cleanup_pool_record(
            &mut slot,
            CleanupPoolPhase::ForeignPreserved,
            vec![cleanup_pool_entry_record(
                &target_component,
                &moved_snapshot,
            )],
        );
        if restore_cleanup_pool_entry_from_trusted_link(
            &slot,
            &source_snapshot,
            &parent_handle,
            original_name,
        )
        .is_err()
        {
            return QuarantineOutcome::Uncertain;
        }
        return QuarantineOutcome::ForeignPreserved;
    }
    if verify_cleanup_slot_name_binding(&slot).is_err()
        || !cleanup_canonical_name_absent(&parent_handle, original_name).unwrap_or(false)
    {
        return QuarantineOutcome::Uncertain;
    }
    if append_cleanup_pool_record(
        &mut slot,
        CleanupPoolPhase::QuarantineMoved,
        vec![
            cleanup_pool_entry_record(&target_component, &candidate_snapshot),
            cleanup_pool_entry_record(&target_component, &moved_snapshot),
        ],
    )
    .is_err()
    {
        return QuarantineOutcome::Uncertain;
    }
    if verify_cleanup_slot_name_binding(&slot).is_err()
        || !cleanup_canonical_name_absent(&parent_handle, original_name).unwrap_or(false)
    {
        return QuarantineOutcome::Uncertain;
    }
    if append_cleanup_pool_record(
        &mut slot,
        CleanupPoolPhase::Retained,
        vec![cleanup_pool_entry_record(
            &target_component,
            &moved_snapshot,
        )],
    )
    .is_err()
    {
        return QuarantineOutcome::Uncertain;
    }
    QuarantineOutcome::Retained
}

fn retain_cleanup_artifact_in_bound_pool(
    path: &Path,
    expected: &GovernanceCleanupArtifactExpectation,
    parent_handle: &AuthorityCleanupParent,
    context: &CleanupPoolContext,
) -> Result<GovernanceCleanupPoolRetentionOutcome, GovernancePersistenceError> {
    let Some(original_name) = path.file_name() else {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    };
    if expected.content_digest.len() != 64
        || !expected
            .content_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    let source_file = match open_regular_entry_at(&parent_handle.file, original_name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
        }
        Err(source) => {
            return Err(cleanup_pool_error(
                path,
                format!("could not open expected cleanup artifact: {source}"),
            ));
        }
    };
    let source_snapshot = snapshot_cleanup_file(source_file.try_clone().map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not clone expected cleanup artifact: {source}"),
        )
    })?)
    .map(|(snapshot, _)| snapshot)
    .map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not snapshot expected cleanup artifact: {source}"),
        )
    })?;
    let expected_snapshot = GovernanceArtifactSnapshot {
        identity: GovernanceArtifactIdentity {
            device: expected.device,
            inode: expected.inode,
        },
        content_digest: expected.content_digest.clone(),
        byte_len: expected.byte_len,
    };
    if source_snapshot != expected_snapshot
        || source_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata))
            != Some(expected_snapshot.identity)
    {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    if !authority_cleanup_parent_is_current(path, parent_handle) {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    let mut slot = match acquire_cleanup_pool_slot_bound(path, parent_handle, context) {
        Ok(slot) => slot,
        Err(GovernancePersistenceError::CleanupPoolExhausted { .. }) => {
            return Ok(GovernanceCleanupPoolRetentionOutcome::PoolExhausted);
        }
        Err(error) => return Err(error),
    };
    let target_component = slot.target_component.clone();
    let candidate_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME);
    if linkat_relative(
        &parent_handle.file,
        original_name,
        &slot.file,
        candidate_name,
    )
    .is_err()
    {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    let candidate_snapshot = match cleanup_pool_entry_snapshot(&slot, candidate_name) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain),
    };
    if candidate_snapshot != expected_snapshot {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    append_cleanup_pool_record(
        &mut slot,
        CleanupPoolPhase::Reserved,
        vec![cleanup_pool_entry_record(
            &target_component,
            &candidate_snapshot,
        )],
    )?;
    let source_still_expected = open_regular_entry_at(&parent_handle.file, original_name)
        .ok()
        .and_then(|file| snapshot_cleanup_file(file).ok())
        .is_some_and(|(snapshot, _)| snapshot == expected_snapshot);
    if !source_still_expected || !authority_cleanup_parent_is_current(path, parent_handle) {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    let quarantine_name = OsStr::new(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME);
    if verify_cleanup_slot_name_binding(&slot).is_err() {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    if atomic_no_replace_move_between(
        &parent_handle.file,
        original_name,
        &slot.file,
        quarantine_name,
    )
    .is_err()
    {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    if open_regular_entry_at(&parent_handle.file, original_name).is_ok() {
        let _ =
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::ForeignPreserved, Vec::new());
        return Ok(GovernanceCleanupPoolRetentionOutcome::ForeignPreserved);
    }
    let moved_snapshot = match cleanup_pool_entry_snapshot(&slot, quarantine_name) {
        Ok(snapshot) => snapshot,
        Err(_) => return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain),
    };
    let candidate_after =
        cleanup_pool_entry_snapshot_optional(&slot, candidate_name).map_err(|source| {
            cleanup_pool_error(
                path,
                format!("could not verify bound cleanup candidate: {source}"),
            )
        })?;
    if candidate_after.as_ref() != Some(&candidate_snapshot) {
        let _ = append_cleanup_pool_record(
            &mut slot,
            CleanupPoolPhase::ForeignPreserved,
            candidate_after
                .as_ref()
                .map(|snapshot| vec![cleanup_pool_entry_record(&target_component, snapshot)])
                .unwrap_or_default(),
        );
        return if restore_cleanup_pool_entry_from_trusted_link(
            &slot,
            &expected_snapshot,
            parent_handle,
            original_name,
        )
        .is_ok()
        {
            Ok(GovernanceCleanupPoolRetentionOutcome::ForeignPreserved)
        } else {
            Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain)
        };
    }
    if open_regular_entry_at(&parent_handle.file, original_name).is_ok() {
        let _ =
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::ForeignPreserved, Vec::new());
        return Ok(GovernanceCleanupPoolRetentionOutcome::ForeignPreserved);
    }
    #[cfg(test)]
    pause_after_authority_cleanup_final_absence_read(path);
    if !cleanup_canonical_name_absent(parent_handle, original_name).unwrap_or(false) {
        let _ =
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::ForeignPreserved, Vec::new());
        return Ok(GovernanceCleanupPoolRetentionOutcome::ForeignPreserved);
    }
    if verify_cleanup_slot_name_binding(&slot).is_err() {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    if moved_snapshot != expected_snapshot {
        let _ = append_cleanup_pool_record(
            &mut slot,
            CleanupPoolPhase::ForeignPreserved,
            vec![cleanup_pool_entry_record(
                &target_component,
                &moved_snapshot,
            )],
        );
        return if restore_cleanup_pool_entry_from_trusted_link(
            &slot,
            &expected_snapshot,
            parent_handle,
            original_name,
        )
        .is_ok()
        {
            Ok(GovernanceCleanupPoolRetentionOutcome::ForeignPreserved)
        } else {
            Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain)
        };
    }
    if verify_cleanup_slot_name_binding(&slot).is_err()
        || !cleanup_canonical_name_absent(parent_handle, original_name).unwrap_or(false)
    {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    append_cleanup_pool_record(
        &mut slot,
        CleanupPoolPhase::QuarantineMoved,
        vec![
            cleanup_pool_entry_record(&target_component, &candidate_snapshot),
            cleanup_pool_entry_record(&target_component, &moved_snapshot),
        ],
    )?;
    if verify_cleanup_slot_name_binding(&slot).is_err()
        || !cleanup_canonical_name_absent(parent_handle, original_name).unwrap_or(false)
    {
        return Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain);
    }
    append_cleanup_pool_record(
        &mut slot,
        CleanupPoolPhase::Retained,
        vec![cleanup_pool_entry_record(
            &target_component,
            &moved_snapshot,
        )],
    )?;
    Ok(GovernanceCleanupPoolRetentionOutcome::Retained)
}

fn remove_verified_authority_entry(
    path: &Path,
    lock_file: &fs::File,
    expected: GovernanceAuthorityLockIdentity,
) -> Result<(), GovernancePersistenceError> {
    let outcome = quarantine_verified_entry(
        path,
        || verify_governance_authority_lock_path(path, lock_file, expected).is_ok(),
        |quarantine| verify_governance_authority_lock_path(quarantine, lock_file, expected).is_ok(),
    );
    if outcome.is_semantic_success() {
        Ok(())
    } else {
        Err(cleanup_error_for_outcome(path, outcome))
    }
}

fn remove_new_authority_lock_if_owned(
    path: &Path,
    lock_file: fs::File,
    expected: GovernanceAuthorityLockIdentity,
) -> Result<(), GovernancePersistenceError> {
    let result = remove_verified_authority_entry(path, &lock_file, expected);
    drop(lock_file);
    result
}

fn remove_authority_lock_if_identity(
    path: &Path,
    expected: GovernanceAuthorityLockIdentity,
) -> Result<(), GovernancePersistenceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not inspect authority cleanup target: {source}"),
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(cleanup_pool_error(
            path,
            "authority cleanup target is not a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|source| {
        cleanup_pool_error(
            path,
            format!("could not open authority cleanup target: {source}"),
        )
    })?;
    file.try_lock().map_err(|error| {
        cleanup_pool_error(
            path,
            format!("could not acquire authority cleanup target lock: {error}"),
        )
    })?;
    let result = remove_verified_authority_entry(path, &file, expected);
    drop(file);
    result
}

fn remove_authority_lock_if_identity_with_held_file(
    path: &Path,
    file: &fs::File,
    expected: GovernanceAuthorityLockIdentity,
) -> Result<(), GovernancePersistenceError> {
    remove_verified_authority_entry(path, file, expected)
}

fn preflight_governance_lock_path(
    path: &Path,
    allow_missing: bool,
) -> Result<(), GovernancePersistenceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(GovernancePersistenceError::InvalidLockFileType {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && allow_missing => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(GovernancePersistenceError::MissingLock {
                path: path.to_path_buf(),
            })
        }
        Err(source) => Err(GovernancePersistenceError::InspectLock {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn governance_lock_identity(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<GovernanceLockIdentity, GovernancePersistenceError> {
    if !metadata.file_type().is_file() {
        return Err(GovernancePersistenceError::InvalidLockFileType {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(GovernanceLockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(
            GovernancePersistenceError::UnsupportedLockIdentityPlatform {
                platform: std::env::consts::OS,
            },
        )
    }
}

fn governance_lock_identity_description(identity: GovernanceLockIdentity) -> String {
    #[cfg(unix)]
    {
        format!("device {}, inode {}", identity.device, identity.inode)
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        "unsupported platform identity".to_string()
    }
}

fn governance_lock_binding_description(binding: &GovernanceLockBinding) -> String {
    format!(
        "device {}, inode {}, generation {}",
        binding.device, binding.inode, binding.generation_id
    )
}

fn new_governance_lock_record() -> GovernanceLockRecord {
    let mut generation = [0_u8; GOVERNANCE_LOCK_GENERATION_BYTES];
    OsRng.fill_bytes(&mut generation);
    GovernanceLockRecord {
        schema_version: GOVERNANCE_LOCK_RECORD_SCHEMA_VERSION,
        generation_id: hex::encode(generation),
    }
}

#[cfg(unix)]
fn read_governance_lock_record(
    path: &Path,
    lock_file: &fs::File,
) -> Result<GovernanceLockRecord, GovernancePersistenceError> {
    use std::os::unix::fs::FileExt;

    let length = lock_file
        .metadata()
        .map_err(|source| GovernancePersistenceError::ReadLockRecord {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if length == 0 || length > MAX_GOVERNANCE_LOCK_RECORD_BYTES {
        return Err(GovernancePersistenceError::InvalidLockRecord {
            path: path.to_path_buf(),
            reason: format!(
                "record length {length} is outside 1..={MAX_GOVERNANCE_LOCK_RECORD_BYTES} bytes"
            ),
        });
    }
    let mut bytes = vec![0_u8; length as usize];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let read = lock_file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|source| GovernancePersistenceError::ReadLockRecord {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            return Err(GovernancePersistenceError::InvalidLockRecord {
                path: path.to_path_buf(),
                reason: "record ended before its reported file length".to_string(),
            });
        }
        offset += read;
    }
    let record: GovernanceLockRecord = serde_json::from_slice(&bytes).map_err(|error| {
        GovernancePersistenceError::InvalidLockRecord {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    if record.schema_version != GOVERNANCE_LOCK_RECORD_SCHEMA_VERSION {
        return Err(GovernancePersistenceError::InvalidLockRecord {
            path: path.to_path_buf(),
            reason: format!("unsupported schema version {}", record.schema_version),
        });
    }
    let decoded = hex::decode(&record.generation_id).map_err(|error| {
        GovernancePersistenceError::InvalidLockRecord {
            path: path.to_path_buf(),
            reason: format!("generation ID is not hexadecimal: {error}"),
        }
    })?;
    if decoded.len() != GOVERNANCE_LOCK_GENERATION_BYTES {
        return Err(GovernancePersistenceError::InvalidLockRecord {
            path: path.to_path_buf(),
            reason: format!(
                "generation ID is {} bytes, expected {GOVERNANCE_LOCK_GENERATION_BYTES}",
                decoded.len()
            ),
        });
    }
    Ok(record)
}

#[cfg(not(unix))]
fn read_governance_lock_record(
    path: &Path,
    _lock_file: &fs::File,
) -> Result<GovernanceLockRecord, GovernancePersistenceError> {
    Err(
        GovernancePersistenceError::UnsupportedLockIdentityPlatform {
            platform: std::env::consts::OS,
        },
    )
}

fn write_governance_lock_record(
    path: &Path,
    lock_file: &mut fs::File,
    record: &GovernanceLockRecord,
    sync_parent: bool,
) -> Result<(), GovernancePersistenceError> {
    let bytes = serde_json::to_vec(record).map_err(|error| {
        GovernancePersistenceError::InvalidLockRecord {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    lock_file
        .set_len(0)
        .and_then(|()| lock_file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| lock_file.write_all(&bytes))
        .and_then(|()| lock_file.sync_all())
        .map_err(|source| GovernancePersistenceError::WriteLockRecord {
            path: path.to_path_buf(),
            source,
        })?;
    if sync_parent {
        sync_governance_lock_parent(path)?;
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_GOVERNANCE_LOCK_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn fail_next_governance_lock_parent_sync() {
    FAIL_NEXT_GOVERNANCE_LOCK_PARENT_SYNC.with(|flag| flag.set(true));
}

fn sync_governance_lock_parent(path: &Path) -> Result<(), GovernancePersistenceError> {
    #[cfg(test)]
    if FAIL_NEXT_GOVERNANCE_LOCK_PARENT_SYNC.with(|flag| flag.replace(false)) {
        return Err(GovernancePersistenceError::WriteLockRecord {
            path: path.to_path_buf(),
            source: std::io::Error::other("injected governance lock parent sync failure"),
        });
    }
    sync_parent_directory(path).map_err(|error| GovernancePersistenceError::WriteLockRecord {
        path: path.to_path_buf(),
        source: std::io::Error::other(error.to_string()),
    })
}

fn governance_lock_binding(
    identity: GovernanceLockIdentity,
    record: GovernanceLockRecord,
) -> GovernanceLockBinding {
    #[cfg(unix)]
    {
        GovernanceLockBinding {
            device: identity.device,
            inode: identity.inode,
            generation_id: record.generation_id,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (identity, record);
        GovernanceLockBinding::unbound()
    }
}

fn lock_identity_changed(
    path: &Path,
    expected: GovernanceLockIdentity,
    observed: String,
) -> GovernancePersistenceError {
    GovernancePersistenceError::LockIdentityChanged {
        path: path.to_path_buf(),
        expected: governance_lock_identity_description(expected),
        observed,
    }
}

fn verify_governance_lock_path(
    path: &Path,
    lock_file: &fs::File,
    expected: &GovernanceLockBinding,
) -> Result<(), GovernancePersistenceError> {
    let expected_identity = expected.identity();
    let held_metadata =
        lock_file
            .metadata()
            .map_err(|source| GovernancePersistenceError::InspectLock {
                path: path.to_path_buf(),
                source,
            })?;
    let held = governance_lock_identity(path, &held_metadata)?;
    if held != expected_identity {
        return Err(lock_identity_changed(
            path,
            expected_identity,
            governance_lock_identity_description(held),
        ));
    }

    let named_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(lock_identity_changed(
                path,
                expected_identity,
                "missing".to_string(),
            ));
        }
        Err(source) => {
            return Err(GovernancePersistenceError::InspectLock {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !named_metadata.file_type().is_file() {
        return Err(lock_identity_changed(
            path,
            expected_identity,
            "nonregular or symlink".to_string(),
        ));
    }
    let named = governance_lock_identity(path, &named_metadata)?;
    if named != expected_identity {
        return Err(lock_identity_changed(
            path,
            expected_identity,
            governance_lock_identity_description(named),
        ));
    }
    let record = read_governance_lock_record(path, lock_file)?;
    if record.generation_id != expected.generation_id {
        return Err(GovernancePersistenceError::LockBindingMismatch {
            path: path.to_path_buf(),
            artifact: "held lock record",
            expected: governance_lock_binding_description(expected),
            observed: governance_lock_binding_description(&governance_lock_binding(held, record)),
        });
    }
    Ok(())
}

fn remove_new_governance_lock_if_owned(
    path: &Path,
    lock_file: fs::File,
    expected: &GovernanceLockBinding,
) -> Result<(), GovernancePersistenceError> {
    let outcome = quarantine_verified_entry(
        path,
        || verify_governance_lock_path(path, &lock_file, expected).is_ok(),
        |quarantine| verify_governance_lock_path(quarantine, &lock_file, expected).is_ok(),
    );
    drop(lock_file);
    if outcome.is_semantic_success() {
        Ok(())
    } else {
        Err(cleanup_error_for_outcome(path, outcome))
    }
}

impl GovernancePersistence {
    fn cleanup_pool_namespace_error(
        &self,
        reason: impl Into<String>,
    ) -> GovernancePersistenceError {
        GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: self.path.clone(),
            reason: reason.into(),
        }
    }

    fn cleanup_pool_binding(&self) -> Result<CleanupPoolBinding, GovernancePersistenceError> {
        self.verify_cleanup_pool_context()?;
        self.cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|context| context.binding.clone())
            .ok_or_else(|| {
                self.cleanup_pool_namespace_error("verified cleanup pool context is absent")
            })
    }

    fn cleanup_pool_binding_bytes(
        &self,
        file: &fs::File,
    ) -> Result<Vec<u8>, GovernancePersistenceError> {
        let mut clone =
            file.try_clone()
                .map_err(|source| GovernancePersistenceError::ReadState {
                    path: self.path.clone(),
                    source,
                })?;
        clone
            .seek(SeekFrom::Start(0))
            .map(|_| ())
            .and_then(|()| {
                let mut bytes = Vec::new();
                clone.read_to_end(&mut bytes).map(|_| bytes)
            })
            .map_err(|source| GovernancePersistenceError::ReadState {
                path: self.path.clone(),
                source,
            })
    }

    fn decode_cleanup_pool_binding(
        &self,
        bytes: &[u8],
        allow_unbound: bool,
    ) -> Result<(CleanupPoolBinding, bool), GovernancePersistenceError> {
        if let Ok(envelope) =
            serde_json::from_slice::<SignedStateEnvelope<CleanupPoolBinding>>(bytes)
        {
            let verified = envelope
                .verify(SignedStateExpectation {
                    state_kind: CLEANUP_POOL_BINDING_KIND,
                    stream_id: CLEANUP_POOL_BINDING_STREAM,
                    expected_signer_agent_id: Some(&self.expected_signer_agent_id),
                    accepted_sequence: Some(1),
                })
                .map_err(|error| {
                    self.cleanup_pool_namespace_error(format!(
                        "invalid signed pool binding: {error}"
                    ))
                })?;
            if verified.schema_version != SIGNED_STATE_SCHEMA_VERSION {
                return Err(self.cleanup_pool_namespace_error(format!(
                    "unsupported signed pool binding schema `{}`",
                    verified.schema_version
                )));
            }
            return Ok((verified.payload, true));
        }
        if !allow_unbound {
            return Err(self.cleanup_pool_namespace_error(
                "cleanup pool binding is unsigned; explicit initialization or migration is required",
            ));
        }
        let binding = serde_json::from_slice::<CleanupPoolBinding>(bytes).map_err(|error| {
            self.cleanup_pool_namespace_error(format!("malformed cleanup pool binding: {error}"))
        })?;
        Ok((binding, false))
    }

    fn sign_cleanup_pool_binding(
        &self,
        context: &mut CleanupPoolContext,
        signing_key: &SigningKey,
    ) -> Result<(), GovernancePersistenceError> {
        let envelope = SignedStateEnvelope::sign(
            CLEANUP_POOL_BINDING_KIND,
            CLEANUP_POOL_BINDING_STREAM,
            self.expected_signer_agent_id.clone(),
            1,
            context.binding.clone(),
            signing_key,
        )?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::Write {
                path: context.binding_path.clone(),
                source: std::io::Error::other(source.to_string()),
            }
        })?;
        let held_identity = context
            .binding_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if held_identity != Some(context.binding_identity) {
            return Err(self.cleanup_pool_namespace_error(
                "cleanup pool binding descriptor identity changed before signing",
            ));
        }
        context
            .binding_file
            .set_len(0)
            .and_then(|()| context.binding_file.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| context.binding_file.write_all(&bytes))
            .and_then(|()| context.binding_file.sync_all())
            .map_err(|source| GovernancePersistenceError::Write {
                path: context.binding_path.clone(),
                source,
            })?;
        let named = open_writable_entry_at(
            &context.pool_file,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
        )
        .map_err(|source| {
            self.cleanup_pool_namespace_error(format!("binding name disappeared: {source}"))
        })?;
        let named_identity = named
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if named_identity != Some(context.binding_identity) {
            return Err(self.cleanup_pool_namespace_error(
                "cleanup pool binding name identity changed while signing",
            ));
        }
        context
            .pool_file
            .sync_all()
            .and_then(|()| self.parent_directory.sync_all())
            .map_err(|source| GovernancePersistenceError::Write {
                path: context.pool_path.clone(),
                source,
            })?;
        context.signed = true;
        Ok(())
    }

    fn verify_cleanup_pool_context_locked(
        &self,
        context: &mut CleanupPoolContext,
    ) -> Result<(), GovernancePersistenceError> {
        if self
            .parent_directory
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata))
            != Some(context.parent_identity)
            || context.parent_identity != self.parent_directory_identity
        {
            return Err(
                self.cleanup_pool_namespace_error("held cleanup pool parent identity changed")
            );
        }
        let named_pool = open_directory_at(
            &self.parent_directory,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME),
        )
        .map_err(|source| {
            self.cleanup_pool_namespace_error(format!("cleanup pool path changed: {source}"))
        })?;
        let named_pool_identity = named_pool
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata));
        if named_pool_identity != Some(context.pool_identity) {
            return Err(
                self.cleanup_pool_namespace_error("cleanup pool directory identity changed")
            );
        }
        let held_pool_identity = context
            .pool_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata));
        if held_pool_identity != Some(context.pool_identity) {
            return Err(
                self.cleanup_pool_namespace_error("held cleanup pool descriptor identity changed")
            );
        }
        let named_lock = open_regular_entry_at(
            &context.pool_file,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
        )
        .map_err(|source| {
            self.cleanup_pool_namespace_error(format!("cleanup pool lock changed: {source}"))
        })?;
        let named_lock_identity = named_lock
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if named_lock_identity != Some(context.lock_identity) {
            return Err(self.cleanup_pool_namespace_error("cleanup pool lock identity changed"));
        }
        let held_lock_identity = context
            .lock_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if held_lock_identity != Some(context.lock_identity) {
            return Err(self.cleanup_pool_namespace_error(
                "held cleanup pool lock descriptor identity changed",
            ));
        }
        let named_binding = open_writable_entry_at(
            &context.pool_file,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
        )
        .map_err(|source| {
            self.cleanup_pool_namespace_error(format!("cleanup pool binding changed: {source}"))
        })?;
        let named_binding_identity = named_binding
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if named_binding_identity != Some(context.binding_identity) {
            return Err(self.cleanup_pool_namespace_error("cleanup pool binding identity changed"));
        }
        let held_binding_identity = context
            .binding_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if held_binding_identity != Some(context.binding_identity) {
            return Err(self.cleanup_pool_namespace_error(
                "held cleanup pool binding descriptor identity changed",
            ));
        }
        let bytes = self.cleanup_pool_binding_bytes(&context.binding_file)?;
        let (binding, signed) = self.decode_cleanup_pool_binding(&bytes, false)?;
        binding
            .validate_namespace(
                context.parent_identity,
                context.pool_identity,
                context.lock_identity,
            )
            .map_err(|reason| self.cleanup_pool_namespace_error(reason))?;
        if !signed || binding != context.binding {
            return Err(self.cleanup_pool_namespace_error("cleanup pool binding content changed"));
        }
        context.signed = true;
        Ok(())
    }

    fn verify_cleanup_pool_context(&self) -> Result<(), GovernancePersistenceError> {
        let mut guard = self
            .cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let context = guard.as_mut().ok_or_else(|| {
            self.cleanup_pool_namespace_error("cleanup pool context has not been authenticated")
        })?;
        self.verify_cleanup_pool_context_locked(context)
    }

    fn release_cleanup_pool_context(&self) {
        self.cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }

    /// Authenticate the current fixed cleanup namespace without retaining its
    /// advisory lock. Ordinary startup runs this read-only preflight before
    /// journal recovery so a replaced pool cannot receive recovery writes.
    fn preflight_cleanup_pool_namespace(&self) -> Result<(), GovernancePersistenceError> {
        self.preflight_cleanup_pool_namespace_with_maintenance(false, false)
    }

    fn preflight_cleanup_pool_namespace_with_maintenance(
        &self,
        allow_active_maintenance: bool,
        allow_opaque_slots: bool,
    ) -> Result<(), GovernancePersistenceError> {
        if self
            .cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
        {
            return self.verify_cleanup_pool_context();
        }
        let pool_file = open_directory_at(
            &self.parent_directory,
            OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME),
        )
        .map_err(|source| {
            self.cleanup_pool_namespace_error(format!(
                "cleanup pool is missing or changed before recovery: {source}"
            ))
        })?;
        let pool_identity = pool_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata))
            .ok_or_else(|| self.cleanup_pool_namespace_error("cleanup pool is not a directory"))?;
        let lock_file =
            open_writable_entry_at(&pool_file, OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME))
                .map_err(|source| {
                    self.cleanup_pool_namespace_error(format!(
                        "cleanup pool lock is missing or changed before recovery: {source}"
                    ))
                })?;
        let lock_identity = lock_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata))
            .ok_or_else(|| self.cleanup_pool_namespace_error("cleanup pool lock is not regular"))?;
        if lock_file
            .try_lock()
            .map_err(|error| match error {
                fs::TryLockError::WouldBlock => {
                    self.cleanup_pool_namespace_error("cleanup pool lock is held by another writer")
                }
                fs::TryLockError::Error(source) => self
                    .cleanup_pool_namespace_error(format!("could not lock cleanup pool: {source}")),
            })
            .is_err()
        {
            return Err(
                self.cleanup_pool_namespace_error("cleanup pool lock could not be acquired")
            );
        }
        let binding_file =
            open_writable_entry_at(&pool_file, OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME))
                .map_err(|source| {
                    self.cleanup_pool_namespace_error(format!(
                        "cleanup pool binding is missing or changed before recovery: {source}"
                    ))
                })?;
        binding_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata))
            .ok_or_else(|| {
                self.cleanup_pool_namespace_error("cleanup pool binding is not regular")
            })?;
        let mut clone = binding_file.try_clone().map_err(|source| {
            self.cleanup_pool_namespace_error(format!(
                "could not read cleanup pool binding: {source}"
            ))
        })?;
        clone.seek(SeekFrom::Start(0)).map_err(|source| {
            self.cleanup_pool_namespace_error(format!(
                "could not seek cleanup pool binding: {source}"
            ))
        })?;
        let mut bytes = Vec::new();
        clone.read_to_end(&mut bytes).map_err(|source| {
            self.cleanup_pool_namespace_error(format!(
                "could not read cleanup pool binding: {source}"
            ))
        })?;
        let (binding, signed) = self.decode_cleanup_pool_binding(&bytes, false)?;
        if !signed {
            return Err(self
                .cleanup_pool_namespace_error("cleanup pool binding is unsigned before recovery"));
        }
        binding
            .validate_namespace(self.parent_directory_identity, pool_identity, lock_identity)
            .map_err(|reason| self.cleanup_pool_namespace_error(reason))?;
        let pool_path = self
            .path
            .parent()
            .unwrap_or(&self.path)
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
        validate_cleanup_pool_directory_namespace(&pool_file, &binding, &pool_path)?;
        let parent = AuthorityCleanupParent {
            file: self.parent_directory.try_clone().map_err(|source| {
                self.cleanup_pool_namespace_error(format!(
                    "could not clone cleanup pool parent for namespace validation: {source}"
                ))
            })?,
            identity: self.parent_directory_identity,
        };
        for slot_name in &binding.slot_names {
            let name = OsStr::new(slot_name);
            if directory_entry_identity_at(&pool_file, name)
                .map_err(|source| self.cleanup_pool_namespace_error(source.to_string()))?
                .is_some()
            {
                let inspection = inspect_cleanup_pool_slot(
                    &parent, &pool_file, &lock_file, &binding, &pool_path, name,
                );
                if !allow_opaque_slots {
                    inspection?;
                }
            }
        }
        if let Some(mut maintenance) =
            open_cleanup_pool_maintenance_journal(&pool_file, &pool_path, false)?
        {
            let journal = read_cleanup_pool_maintenance_journal(
                &mut maintenance,
                &pool_file,
                &pool_path,
                &binding,
                &self.expected_signer_agent_id,
            )?;
            if !allow_active_maintenance
                && !matches!(journal.phase, CleanupPoolMaintenanceJournalPhase::Completed)
            {
                return Err(cleanup_maintenance_error(
                    &cleanup_maintenance_journal_path(&pool_path),
                    "an authenticated cleanup maintenance transaction is still in progress",
                ));
            }
        }
        Ok(())
    }

    fn ensure_cleanup_pool_context(
        &self,
        signing_key: &SigningKey,
        allow_unbound: bool,
    ) -> Result<(), GovernancePersistenceError> {
        if AgentId::from_verifying_key(&signing_key.verifying_key())
            != self.expected_signer_agent_id
        {
            return Err(self.cleanup_pool_namespace_error(
                "cleanup pool signer is not the admitted local governor",
            ));
        }
        if self
            .cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
        {
            return self.verify_cleanup_pool_context();
        }
        let pool_path = self
            .path
            .parent()
            .unwrap_or(&self.path)
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
        let (pool_file, _pool_created) = if allow_unbound {
            open_or_create_directory_at(
                &self.parent_directory,
                OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME),
            )
            .map_err(|source| {
                self.cleanup_pool_namespace_error(format!("could not open cleanup pool: {source}"))
            })?
        } else {
            (
                open_directory_at(
                    &self.parent_directory,
                    OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME),
                )
                .map_err(|source| {
                    self.cleanup_pool_namespace_error(format!(
                        "cleanup pool is missing or changed: {source}"
                    ))
                })?,
                false,
            )
        };
        let pool_identity = pool_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata))
            .ok_or_else(|| self.cleanup_pool_namespace_error("cleanup pool is not a directory"))?;
        let (lock_file, lock_created) = if allow_unbound {
            match create_regular_file_at(&pool_file, OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME))
            {
                Ok(file) => (file, true),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                    open_writable_entry_at(
                        &pool_file,
                        OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME),
                    )
                    .map_err(|source| {
                        self.cleanup_pool_namespace_error(format!(
                            "cleanup pool lock is missing or changed: {source}"
                        ))
                    })?,
                    false,
                ),
                Err(source) => {
                    return Err(self.cleanup_pool_namespace_error(format!(
                        "could not create cleanup pool lock: {source}"
                    )));
                }
            }
        } else {
            (
                open_writable_entry_at(&pool_file, OsStr::new(GOVERNANCE_CLEANUP_POOL_LOCK_NAME))
                    .map_err(|source| {
                    self.cleanup_pool_namespace_error(format!(
                        "cleanup pool lock is missing or changed: {source}"
                    ))
                })?,
                false,
            )
        };
        let lock_identity = lock_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata))
            .ok_or_else(|| {
                self.cleanup_pool_namespace_error("cleanup pool lock is not a regular file")
            })?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(self
                    .cleanup_pool_namespace_error("cleanup pool lock is held by another writer"));
            }
            Err(fs::TryLockError::Error(source)) => {
                return Err(self.cleanup_pool_namespace_error(format!(
                    "could not lock cleanup pool: {source}"
                )));
            }
        }
        if lock_created {
            lock_file
                .sync_all()
                .and_then(|()| pool_file.sync_all())
                .and_then(|()| self.parent_directory.sync_all())
                .map_err(|source| {
                    self.cleanup_pool_namespace_error(format!(
                        "could not durably create cleanup pool lock: {source}"
                    ))
                })?;
        }
        let (binding_file, binding_created) = if allow_unbound {
            match create_regular_file_at(
                &pool_file,
                OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
            ) {
                Ok(file) => (file, true),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                    open_writable_entry_at(
                        &pool_file,
                        OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
                    )
                    .map_err(|source| {
                        self.cleanup_pool_namespace_error(format!(
                            "cleanup pool binding is missing or changed: {source}"
                        ))
                    })?,
                    false,
                ),
                Err(source) => {
                    return Err(self.cleanup_pool_namespace_error(format!(
                        "could not create cleanup pool binding: {source}"
                    )));
                }
            }
        } else {
            (
                open_writable_entry_at(
                    &pool_file,
                    OsStr::new(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
                )
                .map_err(|source| {
                    self.cleanup_pool_namespace_error(format!(
                        "cleanup pool binding is missing or changed: {source}"
                    ))
                })?,
                false,
            )
        };
        let binding_identity = binding_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata))
            .ok_or_else(|| {
                self.cleanup_pool_namespace_error("cleanup pool binding is not a regular file")
            })?;
        let mut context = CleanupPoolContext {
            pool_path: pool_path.clone(),
            binding_path: pool_path.join(GOVERNANCE_CLEANUP_POOL_BINDING_NAME),
            parent_identity: self.parent_directory_identity,
            pool_file,
            pool_identity,
            lock_file,
            lock_identity,
            binding_file,
            binding_identity,
            binding: CleanupPoolBinding::unbound(),
            signed: false,
        };
        let bytes = self.cleanup_pool_binding_bytes(&context.binding_file)?;
        let (binding, signed) = if binding_created || bytes.is_empty() {
            if !allow_unbound {
                return Err(self.cleanup_pool_namespace_error("cleanup pool binding is missing"));
            }
            (
                CleanupPoolBinding::new(
                    context.parent_identity,
                    context.pool_identity,
                    context.lock_identity,
                ),
                false,
            )
        } else {
            self.decode_cleanup_pool_binding(&bytes, allow_unbound)?
        };
        binding
            .validate_namespace(
                context.parent_identity,
                context.pool_identity,
                context.lock_identity,
            )
            .map_err(|reason| self.cleanup_pool_namespace_error(reason))?;
        context.binding = binding;
        context.signed = signed;
        if !context.signed {
            if !allow_unbound {
                return Err(
                    self.cleanup_pool_namespace_error("cleanup pool binding is not authenticated")
                );
            }
            self.sign_cleanup_pool_binding(&mut context, signing_key)?;
        }
        let mut guard = self
            .cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(context);
        drop(guard);
        self.verify_cleanup_pool_context()
    }

    fn write_atomic_artifact(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<AtomicWriteOutcome, GovernancePersistenceError> {
        let no_replace_initial_publication = *self
            .no_replace_initial_publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let parent = AuthorityCleanupParent {
            file: self.parent_directory.try_clone().map_err(|source| {
                GovernancePersistenceError::Write {
                    path: path.parent().unwrap_or(path).to_path_buf(),
                    source,
                }
            })?,
            identity: self.parent_directory_identity,
        };
        write_atomic_synced_at(path, bytes, &parent, no_replace_initial_publication)
    }

    fn clear_new_stream_artifacts(&self) {
        self.new_stream_artifacts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    fn arm_reinitialization_journal(&self, signing_key: &SigningKey) {
        *self
            .reinitialization_journal_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(self.path.clone());
        *self
            .reinitialization_journal_signing_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(signing_key.clone());
    }

    fn disarm_reinitialization_journal(&self) {
        *self
            .reinitialization_journal_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        *self
            .reinitialization_journal_signing_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn update_reinitialization_journal_new_artifact(
        &self,
        path: &Path,
        content_digest: String,
        byte_len: u64,
        identity: Option<GovernanceArtifactIdentity>,
    ) -> Result<(), GovernancePersistenceError> {
        let journal_active = self
            .reinitialization_journal_path
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some();
        if !journal_active {
            return Ok(());
        }
        let signing_key = self
            .reinitialization_journal_signing_key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| {
                reinitialization_journal_error(&self.path, "active transaction has no signing key")
            })?;
        let Some((mut journal, _, _)) =
            read_reinitialization_journal(&self.path, &self.expected_signer_agent_id)?
        else {
            return Err(reinitialization_journal_error(
                &self.path,
                "active transaction journal disappeared",
            ));
        };
        if let Some(existing) = journal
            .new_stream_artifacts
            .iter_mut()
            .find(|artifact| artifact.path == path)
        {
            if existing.content_digest != content_digest || existing.byte_len != byte_len {
                return Err(reinitialization_journal_error(
                    &self.path,
                    "new-stream artifact content intent changed",
                ));
            }
            if identity.is_some() {
                existing.identity = identity;
            }
        } else {
            journal
                .new_stream_artifacts
                .push(ReinitializationNewArtifact {
                    path: path.to_path_buf(),
                    content_digest,
                    byte_len,
                    identity,
                });
        }
        let parent = held_persistence_parent(self)?;
        write_reinitialization_journal_at(&self.path, &journal, &signing_key, &parent)?;
        Ok(())
    }

    fn record_new_stream_intent(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), GovernancePersistenceError> {
        self.update_reinitialization_journal_new_artifact(
            path,
            sha256_hex(bytes),
            bytes.len() as u64,
            None,
        )
    }

    fn record_new_stream_artifact(
        &self,
        path: &Path,
        identity: GovernanceArtifactIdentity,
        bytes: &[u8],
    ) -> Result<(), GovernancePersistenceError> {
        let mut artifacts = self
            .new_stream_artifacts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = artifacts.iter_mut().find(|(known, _)| known == path) {
            existing.1 = identity;
        } else {
            artifacts.push((path.to_path_buf(), identity));
        }
        drop(artifacts);
        self.update_reinitialization_journal_new_artifact(
            path,
            sha256_hex(bytes),
            bytes.len() as u64,
            Some(identity),
        )
    }

    fn new_stream_artifacts(&self) -> Vec<(PathBuf, GovernanceArtifactIdentity)> {
        let artifacts = self
            .new_stream_artifacts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        artifacts.clone()
    }

    fn recover_reinitialization_transaction(
        &self,
        signing_key: &SigningKey,
    ) -> Result<(), GovernancePersistenceError> {
        let Some((mut journal, journal_identity, journal_digest)) =
            read_reinitialization_journal(&self.path, &self.expected_signer_agent_id)?
        else {
            return Ok(());
        };
        // A crash can occur after an archive copy is fsynced but before the
        // phase journal records its identity. The archive is still private
        // rollback material, so digest/length alone are not enough to bind a
        // newly observed inode. Fail closed and retain the authenticated
        // journal when an archive exists without its journaled identity.
        for artifact in &mut journal.artifacts {
            if artifact.archive_identity.is_none()
                && read_governance_artifact_snapshot(&artifact.archive)
                    .map_err(|source| GovernancePersistenceError::Write {
                        path: artifact.archive.clone(),
                        source,
                    })?
                    .is_some()
            {
                return Err(GovernancePersistenceError::Write {
                    path: artifact.archive.clone(),
                    source: std::io::Error::other(
                        "reinitialization archive identity is absent from the authenticated journal",
                    ),
                });
            }
        }
        verify_reinitialization_journal_identity_and_digest(
            &self.path,
            journal_identity,
            &journal_digest,
            &self.expected_signer_agent_id,
        )?;
        match journal.phase {
            ReinitializationJournalPhase::NewStreamCommitted => {
                finalize_reinitialization_transaction(self, &journal, signing_key)
            }
            ReinitializationJournalPhase::Restored => {
                cleanup_reinitialization_archives(self, &journal.artifacts, None)?;
                let Some((_, journal_identity, journal_digest)) = read_reinitialization_journal(
                    &journal.state_path,
                    &self.expected_signer_agent_id,
                )?
                else {
                    return Err(reinitialization_journal_error(
                        &journal.state_path,
                        "restored transaction journal disappeared",
                    ));
                };
                let parent = held_persistence_parent(self)?;
                remove_reinitialization_journal_if_owned_at(
                    &journal.state_path,
                    journal_identity,
                    &journal_digest,
                    &self.expected_signer_agent_id,
                    &parent,
                )
            }
            ReinitializationJournalPhase::Prepared
            | ReinitializationJournalPhase::ArchivesCreated
            | ReinitializationJournalPhase::OriginalsRemoved => {
                rollback_reinitialization_transaction(self, &mut journal, signing_key)
            }
        }
    }

    fn new(
        path: PathBuf,
        expected_signer_agent_id: AgentId,
        open_mode: GovernanceLockOpenMode,
    ) -> Result<Self, GovernancePersistenceError> {
        Self::new_with_authority_lock(path, expected_signer_agent_id, open_mode, None)
    }

    fn new_with_authority_pair_guard(
        path: PathBuf,
        expected_signer_agent_id: AgentId,
        open_mode: GovernanceLockOpenMode,
        guard: GovernanceAuthorityPairGuard,
    ) -> Result<Self, GovernancePersistenceError> {
        let transfer = guard.transfer(&path)?;
        let primary_path = transfer.primary.0.clone();
        let cleanup_file = transfer.cleanup_primary;
        let created_primary = transfer.primary.3;
        let legacy_sidecar_path = transfer.legacy_sidecar_path.clone();
        let identity = transfer.identity;
        let created_legacy = transfer.created_legacy;
        let result = Self::new_with_authority_lock(
            path,
            expected_signer_agent_id,
            open_mode,
            Some(transfer.primary),
        );
        if let Err(error) = result {
            let mut cleanup_errors = Vec::new();
            if created_legacy
                && let Err(cleanup_error) = remove_authority_lock_if_identity_with_held_file(
                    &legacy_sidecar_path,
                    &cleanup_file,
                    identity,
                )
            {
                cleanup_errors.push(cleanup_error);
            }
            if created_primary {
                if let Err(cleanup_error) =
                    remove_new_authority_lock_if_owned(&primary_path, cleanup_file, identity)
                {
                    cleanup_errors.push(cleanup_error);
                }
            } else {
                drop(cleanup_file);
            }
            return Err(compose_operation_cleanup_failure(
                &primary_path,
                error,
                cleanup_errors,
            ));
        }
        result
    }

    fn new_with_authority_lock(
        path: PathBuf,
        expected_signer_agent_id: AgentId,
        open_mode: GovernanceLockOpenMode,
        authority_lock: Option<(PathBuf, fs::File, GovernanceAuthorityLockIdentity, bool)>,
    ) -> Result<Self, GovernancePersistenceError> {
        ensure_lock_identity_supported()?;
        let sequence_path = path.with_extension("sequence.json");
        let lock_path = path.with_extension("lock");
        let anchors_absent = if open_mode == GovernanceLockOpenMode::Initialize {
            let state_anchor_absent = match fs::symlink_metadata(&path) {
                Ok(_) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(source) => {
                    return Err(GovernancePersistenceError::ReadState {
                        path: path.clone(),
                        source,
                    });
                }
            };
            let checkpoint_anchor_absent = match fs::symlink_metadata(&sequence_path) {
                Ok(_) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(source) => {
                    return Err(GovernancePersistenceError::ReadSequence {
                        path: sequence_path.clone(),
                        source,
                    });
                }
            };
            state_anchor_absent && checkpoint_anchor_absent
        } else {
            false
        };
        let initialize_empty_stream =
            open_mode == GovernanceLockOpenMode::Initialize && anchors_absent;
        let explicit_migration = open_mode == GovernanceLockOpenMode::Migrate;
        let may_create_authority_lock = initialize_empty_stream
            || explicit_migration
            || open_mode == GovernanceLockOpenMode::Reinitialize;
        let may_create_lock = initialize_empty_stream || explicit_migration;
        if may_create_lock && let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|source| GovernancePersistenceError::OpenLock {
                path: lock_path.clone(),
                source,
            })?;
        }
        let parent_handle = bind_authority_cleanup_parent(&path).ok_or_else(|| {
            GovernancePersistenceError::Write {
                path: path.parent().unwrap_or(&path).to_path_buf(),
                source: std::io::Error::other(
                    "governance stream parent is not a regular directory",
                ),
            }
        })?;
        preflight_governance_lock_path(&lock_path, may_create_lock)?;
        let mut existing_options = OpenOptions::new();
        existing_options.read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            existing_options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let (mut lock_file, created) = if may_create_lock {
            let mut create_options = OpenOptions::new();
            create_options
                .read(true)
                .write(true)
                .create_new(true)
                .truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                create_options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
            }
            match create_options.open(&lock_path) {
                Ok(file) => (file, true),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                    existing_options.open(&lock_path).map_err(|source| {
                        GovernancePersistenceError::OpenLock {
                            path: lock_path.clone(),
                            source,
                        }
                    })?,
                    false,
                ),
                Err(source) => {
                    return Err(GovernancePersistenceError::OpenLock {
                        path: lock_path.clone(),
                        source,
                    });
                }
            }
        } else {
            let file = existing_options.open(&lock_path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::NotFound {
                    GovernancePersistenceError::MissingLock {
                        path: lock_path.clone(),
                    }
                } else {
                    GovernancePersistenceError::OpenLock {
                        path: lock_path.clone(),
                        source,
                    }
                }
            })?;
            (file, false)
        };
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(GovernancePersistenceError::StateLocked { path: lock_path });
            }
            Err(fs::TryLockError::Error(source)) => {
                return Err(GovernancePersistenceError::LockState {
                    path: lock_path.clone(),
                    source,
                });
            }
        }
        let lock_metadata =
            lock_file
                .metadata()
                .map_err(|source| GovernancePersistenceError::InspectLock {
                    path: lock_path.clone(),
                    source,
                })?;
        let lock_identity = governance_lock_identity(&lock_path, &lock_metadata)?;
        let lock_record = if created {
            let record = new_governance_lock_record();
            write_governance_lock_record(&lock_path, &mut lock_file, &record, true)?;
            record
        } else {
            match read_governance_lock_record(&lock_path, &lock_file) {
                Ok(record) => {
                    if (open_mode == GovernanceLockOpenMode::Initialize && anchors_absent)
                        || explicit_migration
                    {
                        // A prior fresh initialization may have created and
                        // fsynced the record but failed syncing its parent.
                        // Rewrite the exact valid record and sync the parent
                        // before either signed anchor is created; do not rotate
                        // the generation.
                        write_governance_lock_record(&lock_path, &mut lock_file, &record, true)?;
                    }
                    record
                }
                Err(GovernancePersistenceError::InvalidLockRecord { .. })
                    if open_mode == GovernanceLockOpenMode::Initialize && anchors_absent =>
                {
                    // A partial first initialization can leave a locked but
                    // incomplete record before either signed anchor exists.
                    // Under that exact empty-stream condition, establish and
                    // durably anchor a fresh generation. Once either anchor
                    // exists, corrupt lock metadata always fails closed.
                    let record = new_governance_lock_record();
                    write_governance_lock_record(&lock_path, &mut lock_file, &record, true)?;
                    record
                }
                Err(GovernancePersistenceError::InvalidLockRecord { .. })
                    if open_mode == GovernanceLockOpenMode::Reinitialize =>
                {
                    let record = new_governance_lock_record();
                    write_governance_lock_record(&lock_path, &mut lock_file, &record, false)?;
                    record
                }
                Err(GovernancePersistenceError::InvalidLockRecord { .. }) if explicit_migration => {
                    // Only the explicit offline migration path may replace a
                    // partial/corrupt lock beside signed anchors. Those anchors
                    // were authenticated before this lock was opened and are
                    // re-read unchanged while it is held before either is
                    // rewritten.
                    let record = new_governance_lock_record();
                    write_governance_lock_record(&lock_path, &mut lock_file, &record, true)?;
                    record
                }
                Err(error) => return Err(error),
            }
        };
        let lock_binding = governance_lock_binding(lock_identity, lock_record);
        verify_governance_lock_path(&lock_path, &lock_file, &lock_binding)?;
        let (
            authority_lock_path,
            authority_lock_file,
            authority_lock_identity,
            authority_lock_created,
        ) = match if let Some(authority_lock) = authority_lock {
            Ok(authority_lock)
        } else {
            let authority_lock_path = governance_authority_lock_path(&path);
            open_governance_authority_lock(&authority_lock_path, may_create_authority_lock).map(
                |(authority_lock_file, authority_lock_identity, authority_lock_created)| {
                    (
                        authority_lock_path,
                        authority_lock_file,
                        authority_lock_identity,
                        authority_lock_created,
                    )
                },
            )
        } {
            Ok(authority_lock) => authority_lock,
            Err(error) => {
                let mut cleanup_errors = Vec::new();
                if created
                    && let Err(cleanup_error) =
                        remove_new_governance_lock_if_owned(&lock_path, lock_file, &lock_binding)
                {
                    cleanup_errors.push(cleanup_error);
                }
                return Err(compose_operation_cleanup_failure(
                    &lock_path,
                    error,
                    cleanup_errors,
                ));
            }
        };
        if let Err(error) = verify_governance_authority_lock_path(
            &authority_lock_path,
            &authority_lock_file,
            authority_lock_identity,
        ) {
            let mut cleanup_errors = Vec::new();
            if created
                && let Err(cleanup_error) =
                    remove_new_governance_lock_if_owned(&lock_path, lock_file, &lock_binding)
            {
                cleanup_errors.push(cleanup_error);
            }
            if authority_lock_created
                && let Err(cleanup_error) = remove_new_authority_lock_if_owned(
                    &authority_lock_path,
                    authority_lock_file,
                    authority_lock_identity,
                )
            {
                cleanup_errors.push(cleanup_error);
            }
            return Err(compose_operation_cleanup_failure(
                &authority_lock_path,
                error,
                cleanup_errors,
            ));
        }
        Ok(Self {
            path,
            sequence_path,
            parent_directory: parent_handle.file,
            parent_directory_identity: parent_handle.identity,
            no_replace_initial_publication: Mutex::new(
                initialize_empty_stream || open_mode == GovernanceLockOpenMode::Reinitialize,
            ),
            lock_path,
            authority_lock_path,
            lock_binding,
            expected_signer_agent_id,
            lock_file,
            authority_lock_file,
            authority_lock_identity,
            cleanup_pool_context: Mutex::new(None),
            new_stream_artifacts: Mutex::new(Vec::new()),
            reinitialization_journal_path: Mutex::new(None),
            reinitialization_journal_signing_key: Mutex::new(None),
            #[cfg(test)]
            test_pre_write_barrier: Mutex::new(None),
            #[cfg(test)]
            test_loader_barrier: Mutex::new(None),
        })
    }

    fn migrate_lock_binding(
        &self,
        governing_agent_id: &AgentId,
        signing_key: &SigningKey,
        before_lock: &VerifiedGovernanceMigrationAnchors,
    ) -> Result<GovernanceLockMigrationReport, GovernancePersistenceError> {
        self.verify_lock_path()?;
        let under_lock = verify_governance_migration_anchors(
            &self.path,
            governing_agent_id,
            &self.expected_signer_agent_id,
        )?;
        if under_lock.state_bytes != before_lock.state_bytes
            || under_lock.checkpoint_bytes != before_lock.checkpoint_bytes
        {
            return Err(GovernancePersistenceError::MigrationAnchorsChanged {
                path: self.path.clone(),
            });
        }
        let signer_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        if signer_agent_id != self.expected_signer_agent_id {
            return Err(GovernancePersistenceError::SignedState(
                SignedStateError::SignerMismatch {
                    state_kind: GOVERNANCE_STATE_KIND.to_string(),
                    stream_id: GOVERNANCE_STATE_STREAM.to_string(),
                    expected: self.expected_signer_agent_id.to_string(),
                    actual: signer_agent_id.to_string(),
                },
            ));
        }

        let previous_state_sequence = under_lock.state_sequence;
        let previous_checkpoint_sequence = under_lock.checkpoint_sequence;
        if under_lock.state_binding.as_ref() == Some(&self.lock_binding) {
            if under_lock.checkpoint_binding.as_ref() == Some(&self.lock_binding)
                && under_lock.checkpoint_sequence == under_lock.state_sequence
            {
                // A prior attempt may have renamed this exact checkpoint and
                // then failed its parent-directory sync. Rewriting the signed
                // checkpoint makes the idempotent success boundary durable;
                // merely loading matching bytes cannot prove that durability.
                self.write_migration_checkpoint(
                    under_lock.state_sequence,
                    signing_key,
                    under_lock.state_pending_health_observation.as_ref(),
                )
                .map_err(|error| {
                    GovernancePersistenceError::MigrationCheckpointLagging {
                        sequence: under_lock.state_sequence,
                        reason: error.to_string(),
                    }
                })?;
                let local = LocalGovernorKey::new(signing_key.clone());
                self.load(&local)?;
                return Ok(GovernanceLockMigrationReport {
                    state_path: self.path.clone(),
                    previous_state_sequence,
                    previous_checkpoint_sequence,
                    migrated_sequence: under_lock.state_sequence,
                    resumed_state_commit: false,
                    already_migrated: true,
                });
            }
            if under_lock.checkpoint_sequence >= under_lock.state_sequence {
                return Err(GovernancePersistenceError::InvalidSequence {
                    path: self.sequence_path.clone(),
                    reason: "a migrated state may resume only from a strictly older checkpoint"
                        .to_string(),
                });
            }
            self.write_migration_checkpoint(
                under_lock.state_sequence,
                signing_key,
                under_lock.state_pending_health_observation.as_ref(),
            )
            .map_err(|error| {
                GovernancePersistenceError::MigrationCheckpointLagging {
                    sequence: under_lock.state_sequence,
                    reason: error.to_string(),
                }
            })?;
            let local = LocalGovernorKey::new(signing_key.clone());
            self.load(&local)?;
            return Ok(GovernanceLockMigrationReport {
                state_path: self.path.clone(),
                previous_state_sequence,
                previous_checkpoint_sequence,
                migrated_sequence: under_lock.state_sequence,
                resumed_state_commit: true,
                already_migrated: false,
            });
        }

        let migrated_sequence = under_lock.state_sequence.checked_add(1).ok_or_else(|| {
            GovernancePersistenceError::InvalidSequence {
                path: self.path.clone(),
                reason: "governance migration sequence overflow".to_string(),
            }
        })?;
        let pending_health_observation = under_lock.state_pending_health_observation.clone();
        let mut migrated_payload = under_lock.state_payload;
        let Some(payload_object) = migrated_payload.as_object_mut() else {
            return Err(GovernancePersistenceError::InvalidMigrationInput {
                path: self.path.clone(),
                reason: "signed state payload is not a JSON object".to_string(),
            });
        };
        let cleanup_pool_binding = self.cleanup_pool_binding()?;
        payload_object.insert(
            "lock_binding".to_string(),
            serde_json::to_value(&self.lock_binding).map_err(|error| {
                GovernancePersistenceError::InvalidMigrationInput {
                    path: self.path.clone(),
                    reason: format!("new lock binding could not be encoded: {error}"),
                }
            })?,
        );
        payload_object.insert(
            "cleanup_pool_binding".to_string(),
            serde_json::to_value(&cleanup_pool_binding).map_err(|error| {
                GovernancePersistenceError::InvalidMigrationInput {
                    path: self.path.clone(),
                    reason: format!("cleanup pool binding could not be encoded: {error}"),
                }
            })?,
        );
        if let Some(pending_health_observation) = pending_health_observation.as_ref() {
            payload_object.insert(
                "pending_health_observation".to_string(),
                serde_json::to_value(pending_health_observation).map_err(|error| {
                    GovernancePersistenceError::InvalidMigrationInput {
                        path: self.path.clone(),
                        reason: format!(
                            "pending health intent could not be encoded during migration: {error}"
                        ),
                    }
                })?,
            );
        }
        let envelope = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            self.expected_signer_agent_id.clone(),
            migrated_sequence,
            migrated_payload,
            signing_key,
        )?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            }
        })?;
        self.verify_lock_path()?;
        self.record_new_stream_intent(&self.path, &bytes)?;
        let state_outcome = self.write_atomic_artifact(&self.path, &bytes)?;
        let state_directory_sync_error = match state_outcome {
            AtomicWriteOutcome::Synced(identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                None
            }
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error, identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                Some(error.to_string())
            }
        };
        if let Err(error) = self.verify_lock_path() {
            return Err(GovernancePersistenceError::MigrationCheckpointLagging {
                sequence: migrated_sequence,
                reason: error.to_string(),
            });
        }
        if let Err(error) = self.write_migration_checkpoint(
            migrated_sequence,
            signing_key,
            pending_health_observation.as_ref(),
        ) {
            return Err(GovernancePersistenceError::MigrationCheckpointLagging {
                sequence: migrated_sequence,
                reason: match state_directory_sync_error {
                    Some(state_error) => format!(
                        "state rename committed but directory sync failed: {state_error}; checkpoint failed: {error}"
                    ),
                    None => error.to_string(),
                },
            });
        }
        let local = LocalGovernorKey::new(signing_key.clone());
        self.load(&local)?;
        Ok(GovernanceLockMigrationReport {
            state_path: self.path.clone(),
            previous_state_sequence,
            previous_checkpoint_sequence,
            migrated_sequence,
            resumed_state_commit: false,
            already_migrated: false,
        })
    }

    fn write_migration_checkpoint(
        &self,
        sequence: u64,
        signing_key: &SigningKey,
        pending_health_observation: Option<&PendingHealthObservation>,
    ) -> Result<(), GovernancePersistenceError> {
        self.verify_lock_path()?;
        let checkpoint = GovernanceSequenceCheckpoint {
            accepted_sequence: sequence,
            lock_binding: self.lock_binding.clone(),
            cleanup_pool_binding: self.cleanup_pool_binding()?,
            pending_health_observation: pending_health_observation.cloned(),
        };
        let envelope = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            self.expected_signer_agent_id.clone(),
            sequence,
            checkpoint,
            signing_key,
        )?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseSequence {
                path: self.sequence_path.clone(),
                source,
            }
        })?;
        self.record_new_stream_intent(&self.sequence_path, &bytes)?;
        let outcome = self.write_atomic_artifact(&self.sequence_path, &bytes)?;
        self.verify_lock_path()?;
        match outcome {
            AtomicWriteOutcome::Synced(identity) => {
                self.record_new_stream_artifact(&self.sequence_path, identity, &bytes)?;
                Ok(())
            }
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error, identity) => {
                self.record_new_stream_artifact(&self.sequence_path, identity, &bytes)?;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn duplicate_locked_handle_for_stale_snapshot(&self) -> std::io::Result<Self> {
        Ok(Self {
            path: self.path.clone(),
            sequence_path: self.sequence_path.clone(),
            parent_directory: self.parent_directory.try_clone()?,
            parent_directory_identity: self.parent_directory_identity,
            no_replace_initial_publication: Mutex::new(
                *self
                    .no_replace_initial_publication
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            ),
            lock_path: self.lock_path.clone(),
            authority_lock_path: self.authority_lock_path.clone(),
            lock_binding: self.lock_binding.clone(),
            expected_signer_agent_id: self.expected_signer_agent_id.clone(),
            lock_file: self.lock_file.try_clone()?,
            authority_lock_file: self.authority_lock_file.try_clone()?,
            authority_lock_identity: self.authority_lock_identity,
            cleanup_pool_context: Mutex::new(
                self.cleanup_pool_context
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .map(CleanupPoolContext::try_clone)
                    .transpose()?,
            ),
            new_stream_artifacts: Mutex::new(
                self.new_stream_artifacts
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
            reinitialization_journal_path: Mutex::new(
                self.reinitialization_journal_path
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
            reinitialization_journal_signing_key: Mutex::new(
                self.reinitialization_journal_signing_key
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
            test_pre_write_barrier: Mutex::new(None),
            #[cfg(test)]
            test_loader_barrier: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn install_pre_write_barrier(&self) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let reached = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        *self
            .test_pre_write_barrier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((Arc::clone(&reached), Arc::clone(&resume)));
        (reached, resume)
    }

    #[cfg(test)]
    fn pause_after_pre_write_verification(&self) {
        let barrier = self
            .test_pre_write_barrier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some((reached, resume)) = barrier {
            reached.wait();
            resume.wait();
        }
    }

    #[cfg(test)]
    fn install_loader_barrier(
        &self,
        path: &Path,
    ) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let reached = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        *self
            .test_loader_barrier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((
            path.to_path_buf(),
            Arc::clone(&reached),
            Arc::clone(&resume),
        ));
        (reached, resume)
    }

    #[cfg(test)]
    fn pause_after_loader_open(&self, path: &Path) {
        let barrier = self
            .test_loader_barrier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some((expected_path, reached, resume)) = barrier
            && expected_path == path
        {
            reached.wait();
            resume.wait();
        }
    }

    fn verify_lock_path(&self) -> Result<(), GovernancePersistenceError> {
        verify_governance_lock_path(&self.lock_path, &self.lock_file, &self.lock_binding)?;
        verify_governance_authority_lock_path(
            &self.authority_lock_path,
            &self.authority_lock_file,
            self.authority_lock_identity,
        )
    }

    fn load(
        &self,
        local: &LocalGovernorKey,
    ) -> Result<LoadedGovernanceState, GovernancePersistenceError> {
        self.verify_cleanup_pool_context()?;
        self.load_internal(local, true)
    }

    fn load_for_cas(
        &self,
        local: &LocalGovernorKey,
    ) -> Result<LoadedGovernanceState, GovernancePersistenceError> {
        self.verify_cleanup_pool_context()?;
        self.load_internal(local, false)
    }

    /// Read a signed stream anchor through the parent directory descriptor
    /// that was bound when this persistence instance was constructed.  The
    /// pathname is used only for diagnostics and identity revalidation; no
    /// state bytes are ever obtained through a path-following read.
    fn read_bound_stream_artifact(
        &self,
        path: &Path,
        state_anchor: bool,
    ) -> Result<Vec<u8>, GovernancePersistenceError> {
        let read_error = |source| {
            if state_anchor {
                GovernancePersistenceError::ReadState {
                    path: path.to_path_buf(),
                    source,
                }
            } else {
                GovernancePersistenceError::ReadSequence {
                    path: path.to_path_buf(),
                    source,
                }
            }
        };
        let missing_error = || {
            if state_anchor {
                GovernancePersistenceError::MissingState {
                    path: path.to_path_buf(),
                }
            } else {
                GovernancePersistenceError::MissingSequence {
                    path: path.to_path_buf(),
                }
            }
        };
        let parent_path = path.parent().ok_or_else(|| {
            read_error(std::io::Error::other(
                "governance stream anchor has no parent directory",
            ))
        })?;
        let parent_identity = fs::symlink_metadata(parent_path)
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata));
        if parent_identity != Some(self.parent_directory_identity) {
            return Err(read_error(std::io::Error::other(
                "governance stream anchor parent directory identity changed",
            )));
        }
        let name = path.file_name().ok_or_else(|| {
            read_error(std::io::Error::other(
                "governance stream anchor has no final component",
            ))
        })?;
        let mut file = match open_regular_entry_at(&self.parent_directory, name) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing_error());
            }
            Err(source) => return Err(read_error(source)),
        };
        let metadata_before = file.metadata().map_err(read_error)?;
        let Some(identity_before) = governance_artifact_identity(&metadata_before) else {
            return Err(read_error(std::io::Error::other(
                "governance stream anchor is not a regular file",
            )));
        };
        #[cfg(test)]
        self.pause_after_loader_open(path);
        file.seek(SeekFrom::Start(0)).map_err(read_error)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(read_error)?;
        let metadata_after = file.metadata().map_err(read_error)?;
        let Some(identity_after) = governance_artifact_identity(&metadata_after) else {
            return Err(read_error(std::io::Error::other(
                "governance stream anchor ceased to be a regular file",
            )));
        };
        if identity_before != identity_after || metadata_after.len() != bytes.len() as u64 {
            return Err(read_error(std::io::Error::other(
                "governance stream anchor changed while being read",
            )));
        }
        let named_file = open_regular_entry_at(&self.parent_directory, name).map_err(read_error)?;
        let named_identity = named_file
            .metadata()
            .ok()
            .and_then(|metadata| governance_artifact_identity(&metadata));
        if named_identity != Some(identity_before) {
            return Err(read_error(std::io::Error::other(
                "governance stream anchor name identity changed during read",
            )));
        }
        let parent_identity_after = fs::symlink_metadata(parent_path)
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata));
        if parent_identity_after != Some(self.parent_directory_identity) {
            return Err(read_error(std::io::Error::other(
                "governance stream anchor parent directory changed during read",
            )));
        }
        Ok(bytes)
    }

    fn load_internal(
        &self,
        local: &LocalGovernorKey,
        repair_checkpoint: bool,
    ) -> Result<LoadedGovernanceState, GovernancePersistenceError> {
        self.verify_lock_path()?;
        let cleanup_pool_binding = self
            .cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|context| context.binding.clone());
        if cleanup_pool_binding.is_some() {
            self.verify_cleanup_pool_context()?;
        }
        let bytes = self.read_bound_stream_artifact(&self.path, true)?;
        let shape: serde_json::Value = serde_json::from_slice(&bytes).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            }
        })?;
        if shape.get("statement").is_none() || shape.get("signature").is_none() {
            return Err(GovernancePersistenceError::LegacyUnsignedState {
                path: self.path.clone(),
            });
        }
        let envelope: SignedStateEnvelope<PersistedGovernanceState> = serde_json::from_value(shape)
            .map_err(|source| GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            })?;
        let digest = signed_governance_envelope_digest(&envelope, &self.path)?;

        let checkpoint_bytes = self.read_bound_stream_artifact(&self.sequence_path, false)?;
        let checkpoint_envelope: SignedStateEnvelope<GovernanceSequenceCheckpoint> =
            serde_json::from_slice(&checkpoint_bytes).map_err(|source| {
                GovernancePersistenceError::ParseSequence {
                    path: self.sequence_path.clone(),
                    source,
                }
            })?;
        let checkpoint = checkpoint_envelope.verify(SignedStateExpectation {
            state_kind: GOVERNANCE_CHECKPOINT_KIND,
            stream_id: GOVERNANCE_STATE_STREAM,
            expected_signer_agent_id: Some(&self.expected_signer_agent_id),
            accepted_sequence: None,
        })?;
        if checkpoint.schema_version != SIGNED_STATE_SCHEMA_VERSION {
            return Err(GovernancePersistenceError::UnsupportedSchema {
                observed: checkpoint.schema_version,
            });
        }
        self.validate_signed_lock_binding(&checkpoint.payload.lock_binding, "checkpoint")?;
        if cleanup_pool_binding
            .as_ref()
            .is_some_and(|binding| checkpoint.payload.cleanup_pool_binding != *binding)
        {
            return Err(self.cleanup_pool_namespace_error(
                "signed checkpoint cleanup pool binding does not match the held namespace",
            ));
        }
        self.validate_checkpoint(&checkpoint.payload, checkpoint.sequence)?;

        let verified = envelope.verify(SignedStateExpectation {
            state_kind: GOVERNANCE_STATE_KIND,
            stream_id: GOVERNANCE_STATE_STREAM,
            expected_signer_agent_id: Some(&self.expected_signer_agent_id),
            accepted_sequence: Some(checkpoint.payload.accepted_sequence),
        })?;
        if verified.schema_version != SIGNED_STATE_SCHEMA_VERSION {
            return Err(GovernancePersistenceError::UnsupportedSchema {
                observed: verified.schema_version,
            });
        }
        self.validate_signed_lock_binding(&verified.payload.lock_binding, "state")?;
        if cleanup_pool_binding
            .as_ref()
            .is_some_and(|binding| verified.payload.cleanup_pool_binding != *binding)
        {
            return Err(self.cleanup_pool_namespace_error(
                "signed state cleanup pool binding does not match the held namespace",
            ));
        }
        let mut payload = verified.payload;
        if let Some(checkpoint_pending) = checkpoint.payload.pending_health_observation.as_ref() {
            if checkpoint.payload.accepted_sequence > verified.sequence {
                return Err(GovernancePersistenceError::InvalidSequence {
                    path: self.sequence_path.clone(),
                    reason:
                        "signed checkpoint pending health marker is ahead of its state predecessor"
                            .to_string(),
                });
            }
            if payload
                .pending_health_observation
                .as_ref()
                .is_some_and(|state_pending| state_pending != checkpoint_pending)
            {
                return Err(GovernancePersistenceError::InvalidSequence {
                    path: self.sequence_path.clone(),
                    reason:
                        "signed state and checkpoint carry divergent pending health observations"
                            .to_string(),
                });
            }
            payload.pending_health_observation = Some(checkpoint_pending.clone());
        }
        if repair_checkpoint && checkpoint.payload.accepted_sequence < verified.sequence {
            // State is committed before its high-water checkpoint. A crash in
            // that narrow window leaves a fully signed newer envelope, which is
            // safe to accept and use to repair the lagging checkpoint.
            self.write_checkpoint(
                verified.sequence,
                local,
                payload.pending_health_observation.as_ref(),
            )?;
        }
        self.verify_lock_path()?;
        Ok(LoadedGovernanceState {
            payload,
            sequence: verified.sequence,
            digest,
            checkpoint_sequence: checkpoint.payload.accepted_sequence,
        })
    }

    fn initialize(
        &self,
        state: &GovernanceState,
    ) -> Result<GovernanceStateVersion, GovernancePersistenceError> {
        self.clear_new_stream_artifacts();
        self.verify_lock_path()?;
        let local = state
            .local_governor
            .as_ref()
            .ok_or(GovernancePersistenceError::MissingLocalSigner)?;
        self.ensure_cleanup_pool_context(&local.signing_key, true)?;
        if self.path.exists() || self.sequence_path.exists() {
            return Err(GovernancePersistenceError::AlreadyInitialized {
                state_path: self.path.clone(),
                sequence_path: self.sequence_path.clone(),
            });
        }
        let (outcome, version) = self.write_state_and_checkpoint(state, 1)?;
        match outcome {
            GovernancePersistenceOutcome::Committed => {
                *self
                    .no_replace_initial_publication
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
                Ok(version)
            }
            GovernancePersistenceOutcome::StateCommittedCheckpointLagging { reason, .. } => {
                self.release_cleanup_pool_context();
                let rollback = self.rollback_incomplete_initialization();
                Err(GovernancePersistenceError::IncompleteInitialization {
                    reason: match rollback {
                        Ok(()) => reason,
                        Err(rollback_error) => {
                            format!("{reason}; rollback also failed: {rollback_error}")
                        }
                    },
                })
            }
        }
    }

    fn save(
        &self,
        state: &GovernanceState,
        expected_sequence: u64,
        expected_digest: &str,
    ) -> Result<(GovernancePersistenceOutcome, GovernanceStateVersion), GovernancePersistenceError>
    {
        self.save_internal(state, expected_sequence, expected_digest)
    }

    fn save_internal(
        &self,
        state: &GovernanceState,
        expected_sequence: u64,
        expected_digest: &str,
    ) -> Result<(GovernancePersistenceOutcome, GovernanceStateVersion), GovernancePersistenceError>
    {
        let local = state
            .local_governor
            .as_ref()
            .ok_or(GovernancePersistenceError::MissingLocalSigner)?;
        let loaded = self.load_for_cas(local)?;
        if loaded.sequence != expected_sequence || loaded.digest != expected_digest {
            return Err(GovernancePersistenceError::StalePredecessor {
                path: self.path.clone(),
                expected_sequence,
                expected_digest: expected_digest.to_string(),
                observed_sequence: loaded.sequence,
                observed_digest: loaded.digest,
            });
        }
        if loaded.checkpoint_sequence < loaded.sequence {
            self.write_checkpoint(
                loaded.sequence,
                local,
                loaded.payload.pending_health_observation.as_ref(),
            )?;
        }
        let next_sequence = loaded.sequence.checked_add(1).ok_or_else(|| {
            GovernancePersistenceError::InvalidSequence {
                path: self.sequence_path.clone(),
                reason: "sequence overflow".to_string(),
            }
        })?;
        self.write_state_and_checkpoint(state, next_sequence)
    }

    /// Write a restrictive health intent at the current signed sequence before
    /// the runtime health projection is changed.  The checkpoint is the
    /// preferred write-ahead journal: it is independently signed, fsynced,
    /// and can veto a stale state envelope after restart.  If that anchor is
    /// unavailable, rewrite the current state envelope at the same sequence
    /// with the intent before allowing the caller to mutate memory.  Sequence
    /// identity is never advanced by this write-ahead step.
    fn write_pending_health_intent(
        &self,
        state: &GovernanceState,
        observation: &PendingHealthObservation,
    ) -> Result<GovernanceStateVersion, GovernancePersistenceError> {
        let local = state
            .local_governor
            .as_ref()
            .ok_or(GovernancePersistenceError::MissingLocalSigner)?;
        let expected_sequence = state.persistence_sequence.ok_or_else(|| {
            GovernancePersistenceError::InvalidSequence {
                path: self.path.clone(),
                reason: "signed governance state has no in-memory sequence anchor".to_string(),
            }
        })?;
        let expected_digest = state.persistence_digest.as_deref().ok_or_else(|| {
            GovernancePersistenceError::InvalidSequence {
                path: self.path.clone(),
                reason: "signed governance state has no in-memory digest anchor".to_string(),
            }
        })?;
        let loaded = self.load_for_cas(local)?;
        if loaded.sequence != expected_sequence || loaded.digest != expected_digest {
            return Err(GovernancePersistenceError::StalePredecessor {
                path: self.path.clone(),
                expected_sequence,
                expected_digest: expected_digest.to_string(),
                observed_sequence: loaded.sequence,
                observed_digest: loaded.digest,
            });
        }
        if loaded
            .payload
            .pending_health_observation
            .as_ref()
            .is_some_and(|existing| existing == observation)
        {
            return Ok(GovernanceStateVersion {
                sequence: loaded.sequence,
                digest: loaded.digest,
                health_marker_cleared: false,
            });
        }

        // Do not replace an older restrictive marker with a different
        // same-sequence observation. The state envelope is the durable
        // predecessor, so writing the new observation only to the checkpoint
        // would create divergent signed anchors that a restart must reject.
        // The older marker is itself fail-closed, so retaining it is safer
        // than creating an unauthenticated/ambiguous convergence point.
        if loaded
            .payload
            .pending_health_observation
            .as_ref()
            .is_some_and(|existing| existing != observation)
        {
            return Err(GovernancePersistenceError::Write {
                path: self.sequence_path.clone(),
                source: std::io::Error::other(format!(
                    "signed pending health marker differs at sequence {}; refusing same-sequence divergence",
                    loaded.sequence
                )),
            });
        }

        let checkpoint_error =
            match self.write_checkpoint(loaded.sequence, local, Some(observation)) {
                Ok(()) => {
                    return Ok(GovernanceStateVersion {
                        sequence: loaded.sequence,
                        digest: loaded.digest,
                        health_marker_cleared: false,
                    });
                }
                Err(error) => error,
            };

        // Checkpoint publication can fail before its directory entry becomes
        // durable (for example, an injected directory blocker).  A same-
        // sequence signed state rewrite is the recovery anchor in that case;
        // it is still a write-ahead intent and does not move the CAS sequence.
        let mut persisted = PersistedGovernanceState::from_runtime_with_binding(
            state,
            self.cleanup_pool_binding()?,
        );
        persisted.lock_binding = self.lock_binding.clone();
        persisted.pending_health_observation = Some(observation.clone());
        let envelope = local.sign_persisted_state(loaded.sequence, persisted)?;
        let digest = signed_governance_envelope_digest(&envelope, &self.path)?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            }
        })?;
        self.verify_lock_path()?;
        self.record_new_stream_intent(&self.path, &bytes)?;
        let outcome = self.write_atomic_artifact(&self.path, &bytes)?;
        let state_directory_sync_error = match outcome {
            AtomicWriteOutcome::Synced(identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                None
            }
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error, identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                Some(error)
            }
        };
        if let Some(error) = state_directory_sync_error {
            return Err(error);
        }
        self.verify_lock_path().map_err(|error| {
            GovernancePersistenceError::Write {
                path: self.path.clone(),
                source: std::io::Error::other(format!(
                    "write-ahead health intent checkpoint failed ({checkpoint_error}); state anchor verification failed: {error}"
                )),
            }
        })?;
        Ok(GovernanceStateVersion {
            sequence: loaded.sequence,
            digest,
            health_marker_cleared: false,
        })
    }

    fn write_state_and_checkpoint(
        &self,
        state: &GovernanceState,
        sequence: u64,
    ) -> Result<(GovernancePersistenceOutcome, GovernanceStateVersion), GovernancePersistenceError>
    {
        let local = state
            .local_governor
            .as_ref()
            .ok_or(GovernancePersistenceError::MissingLocalSigner)?;
        if local.consensus_agent_id() != &self.expected_signer_agent_id {
            return Err(GovernancePersistenceError::SignedState(
                SignedStateError::SignerMismatch {
                    state_kind: GOVERNANCE_STATE_KIND.to_string(),
                    stream_id: GOVERNANCE_STATE_STREAM.to_string(),
                    expected: self.expected_signer_agent_id.to_string(),
                    actual: local.consensus_agent_id().to_string(),
                },
            ));
        }
        let mut persisted = PersistedGovernanceState::from_runtime_with_binding(
            state,
            self.cleanup_pool_binding()?,
        );
        persisted.lock_binding = self.lock_binding.clone();
        let pending_health_observation = persisted.pending_health_observation.clone();
        let envelope = local.sign_persisted_state(sequence, persisted)?;
        let digest = signed_governance_envelope_digest(&envelope, &self.path)?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            }
        })?;
        self.verify_lock_path()?;
        self.record_new_stream_intent(&self.path, &bytes)?;
        #[cfg(test)]
        self.pause_after_pre_write_verification();
        let state_outcome = self.write_atomic_artifact(&self.path, &bytes)?;
        let state_directory_sync_error = match state_outcome {
            AtomicWriteOutcome::Synced(identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                None
            }
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error, identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                Some(error.to_string())
            }
        };
        #[cfg(test)]
        maybe_inject_reinitialization_crash(
            &self.path,
            InjectedReinitializationCrashPoint::StateRenamed,
        );
        #[cfg(test)]
        maybe_inject_health_crash(&self.path, InjectedHealthCrashPoint::StateWrite);
        let lock_after_state = self.verify_lock_path();
        let mut outcome = match lock_after_state.and_then(|()| {
            let result =
                self.write_checkpoint(sequence, local, pending_health_observation.as_ref());
            #[cfg(test)]
            if result.is_ok() {
                maybe_inject_health_crash(&self.path, InjectedHealthCrashPoint::CheckpointWrite);
            }
            result
        }) {
            Ok(()) => GovernancePersistenceOutcome::Committed,
            Err(error) => GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason: match state_directory_sync_error {
                    Some(state_error) => format!(
                        "state rename committed but directory sync failed: {state_error}; checkpoint failed: {error}"
                    ),
                    None => error.to_string(),
                },
            },
        };
        let mut final_digest = digest;
        let mut health_marker_cleared = false;
        if matches!(outcome, GovernancePersistenceOutcome::Committed)
            && pending_health_observation.is_some()
        {
            let (clear_outcome, clear_version) =
                self.clear_pending_health_marker(state, sequence, local, final_digest)?;
            outcome = clear_outcome;
            final_digest = clear_version.digest;
            health_marker_cleared = clear_version.health_marker_cleared;
        }
        Ok((
            outcome,
            GovernanceStateVersion {
                sequence,
                digest: final_digest,
                health_marker_cleared,
            },
        ))
    }

    /// Remove a write-ahead health marker only after the state and checkpoint
    /// carrying the restrictive projection have both committed.  The
    /// checkpoint is cleared first: if the subsequent state rewrite fails,
    /// the old signed state marker remains authoritative and the next repair
    /// restores that marker into the checkpoint.  A successful state rename
    /// returns its digest even when the parent-directory sync is the only
    /// remaining failure, because the rename changed the in-process state
    /// anchor and must be reflected by the caller's CAS snapshot.
    fn clear_pending_health_marker(
        &self,
        state: &GovernanceState,
        sequence: u64,
        local: &LocalGovernorKey,
        marker_digest: String,
    ) -> Result<(GovernancePersistenceOutcome, GovernanceStateVersion), GovernancePersistenceError>
    {
        if let Err(error) = self.write_checkpoint(sequence, local, None) {
            return Ok((
                GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                    sequence,
                    reason: format!("health marker clear checkpoint failed: {error}"),
                },
                GovernanceStateVersion {
                    sequence,
                    digest: marker_digest,
                    health_marker_cleared: false,
                },
            ));
        }

        let mut persisted = PersistedGovernanceState::from_runtime_with_binding(
            state,
            self.cleanup_pool_binding()?,
        );
        persisted.lock_binding = self.lock_binding.clone();
        persisted.pending_health_observation = None;
        let envelope = local.sign_persisted_state(sequence, persisted)?;
        let digest = signed_governance_envelope_digest(&envelope, &self.path)?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            }
        })?;
        self.verify_lock_path()?;
        self.record_new_stream_intent(&self.path, &bytes)?;
        let state_outcome = self.write_atomic_artifact(&self.path, &bytes)?;
        let (state_committed, state_sync_error) = match state_outcome {
            AtomicWriteOutcome::Synced(identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                (true, None)
            }
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error, identity) => {
                self.record_new_stream_artifact(&self.path, identity, &bytes)?;
                (true, Some(error.to_string()))
            }
        };
        if let Err(error) = self.verify_lock_path() {
            return Ok((
                GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                    sequence,
                    reason: format!(
                        "health marker state clear committed but authority verification failed: {error}"
                    ),
                },
                GovernanceStateVersion {
                    sequence,
                    digest: if state_committed {
                        digest
                    } else {
                        marker_digest
                    },
                    health_marker_cleared: state_committed,
                },
            ));
        }
        if !state_committed {
            return Ok((
                GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                    sequence,
                    reason: "health marker state clear did not commit".to_string(),
                },
                GovernanceStateVersion {
                    sequence,
                    digest: marker_digest,
                    health_marker_cleared: false,
                },
            ));
        }
        let outcome = match state_sync_error {
            Some(error) => GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason: format!("health marker state clear directory sync failed: {error}"),
            },
            None => GovernancePersistenceOutcome::Committed,
        };
        Ok((
            outcome,
            GovernanceStateVersion {
                sequence,
                digest,
                health_marker_cleared: true,
            },
        ))
    }

    fn repair_checkpoint(
        &self,
        state: &GovernanceState,
        lag: &GovernanceCheckpointLag,
    ) -> Result<(), GovernancePersistenceError> {
        let local = state
            .local_governor
            .as_ref()
            .ok_or(GovernancePersistenceError::MissingLocalSigner)?;
        let loaded = self.load(local)?;
        if loaded.sequence != lag.sequence
            || state.persistence_digest.as_deref() != Some(loaded.digest.as_str())
            || serde_json::to_value(&loaded.payload).map_err(|source| {
                GovernancePersistenceError::ParseState {
                    path: self.path.clone(),
                    source,
                }
            })? != {
                let mut persisted = PersistedGovernanceState::from_runtime_with_binding(
                    state,
                    self.cleanup_pool_binding()?,
                );
                persisted.lock_binding = self.lock_binding.clone();
                serde_json::to_value(persisted).map_err(|source| {
                    GovernancePersistenceError::ParseState {
                        path: self.path.clone(),
                        source,
                    }
                })?
            }
        {
            return Err(GovernancePersistenceError::InvalidSequence {
                path: self.path.clone(),
                reason: format!(
                    "durable state at sequence {} does not match in-memory committed state at sequence {}",
                    loaded.sequence, lag.sequence
                ),
            });
        }
        // `load` repairs a numerically lagging checkpoint. Rewrite even when
        // the file already names this sequence: the original failure may have
        // happened after checkpoint rename but before parent-directory sync.
        self.write_checkpoint(
            lag.sequence,
            local,
            loaded.payload.pending_health_observation.as_ref(),
        )?;
        Ok(())
    }

    fn rollback_incomplete_initialization(&self) -> Result<(), GovernancePersistenceError> {
        let artifacts = self.new_stream_artifacts();
        remove_governance_stream_files(self, &artifacts)
    }

    fn validate_checkpoint(
        &self,
        checkpoint: &GovernanceSequenceCheckpoint,
        envelope_sequence: u64,
    ) -> Result<(), GovernancePersistenceError> {
        let invalid =
            checkpoint.accepted_sequence == 0 || checkpoint.accepted_sequence != envelope_sequence;
        if invalid {
            return Err(GovernancePersistenceError::InvalidSequence {
                path: self.sequence_path.clone(),
                reason: "signed checkpoint payload does not match its envelope sequence"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn validate_signed_lock_binding(
        &self,
        observed: &GovernanceLockBinding,
        artifact: &'static str,
    ) -> Result<(), GovernancePersistenceError> {
        if observed != &self.lock_binding {
            return Err(GovernancePersistenceError::LockBindingMismatch {
                path: self.lock_path.clone(),
                artifact,
                expected: governance_lock_binding_description(&self.lock_binding),
                observed: governance_lock_binding_description(observed),
            });
        }
        Ok(())
    }

    fn write_checkpoint(
        &self,
        sequence: u64,
        local: &LocalGovernorKey,
        pending_health_observation: Option<&PendingHealthObservation>,
    ) -> Result<(), GovernancePersistenceError> {
        self.verify_lock_path()?;
        let checkpoint = GovernanceSequenceCheckpoint {
            accepted_sequence: sequence,
            lock_binding: self.lock_binding.clone(),
            cleanup_pool_binding: self.cleanup_pool_binding()?,
            pending_health_observation: pending_health_observation.cloned(),
        };
        let envelope = local.sign_checkpoint(sequence, checkpoint)?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseSequence {
                path: self.sequence_path.clone(),
                source,
            }
        })?;
        self.record_new_stream_intent(&self.sequence_path, &bytes)?;
        let outcome = self.write_atomic_artifact(&self.sequence_path, &bytes)?;
        self.verify_lock_path()?;
        match outcome {
            AtomicWriteOutcome::Synced(identity) => {
                self.record_new_stream_artifact(&self.sequence_path, identity, &bytes)?;
                #[cfg(test)]
                maybe_inject_reinitialization_crash(
                    &self.path,
                    InjectedReinitializationCrashPoint::CheckpointRenamed,
                );
                Ok(())
            }
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error, identity) => {
                self.record_new_stream_artifact(&self.sequence_path, identity, &bytes)?;
                #[cfg(test)]
                maybe_inject_reinitialization_crash(
                    &self.path,
                    InjectedReinitializationCrashPoint::CheckpointRenamed,
                );
                Err(error)
            }
        }
    }
}

type CleanupPoolMaintenanceScan = (
    Vec<String>,
    Vec<String>,
    BTreeMap<String, GovernanceArtifactIdentity>,
    BTreeMap<String, CleanupPoolMaintenanceSlotProof>,
);

fn scan_cleanup_pool_slots_for_maintenance(
    parent: &AuthorityCleanupParent,
    pool: &fs::File,
    lock: &fs::File,
    binding: &CleanupPoolBinding,
    pool_path: &Path,
    mode: GovernanceCleanupPoolMaintenanceMode,
) -> Result<CleanupPoolMaintenanceScan, GovernancePersistenceError> {
    validate_cleanup_pool_directory_namespace(pool, binding, pool_path)?;
    let mut selected = Vec::new();
    let mut opaque = Vec::new();
    let mut identities = BTreeMap::new();
    let mut proofs = BTreeMap::new();
    for slot_name in &binding.slot_names {
        let name = OsStr::new(slot_name);
        let Some(identity) = directory_entry_identity_at(pool, name).map_err(|source| {
            cleanup_maintenance_error(
                pool_path,
                format!("could not inspect slot `{slot_name}`: {source}"),
            )
        })?
        else {
            continue;
        };
        let proof = match cleanup_pool_slot_content_proof(pool, name) {
            Ok((content_digest, byte_len)) => CleanupPoolMaintenanceSlotProof {
                identity,
                content_digest,
                byte_len,
            },
            Err(_) if mode == GovernanceCleanupPoolMaintenanceMode::Reset => {
                CleanupPoolMaintenanceSlotProof {
                    identity,
                    content_digest: sha256_hex(
                        format!("opaque-slot:{}:{}", identity.device, identity.inode).as_bytes(),
                    ),
                    byte_len: 0,
                }
            }
            Err(source) => {
                return Err(cleanup_maintenance_error(
                    pool_path,
                    format!("could not snapshot slot `{slot_name}`: {source}"),
                ));
            }
        };
        let is_opaque = match mode {
            GovernanceCleanupPoolMaintenanceMode::Reset => {
                match inspect_cleanup_pool_slot(parent, pool, lock, binding, pool_path, name) {
                    Ok(slot) => {
                        slot.opaque
                            || !matches!(
                                slot.phase,
                                Some(
                                    CleanupPoolPhase::Retained | CleanupPoolPhase::ForeignPreserved
                                )
                            )
                    }
                    Err(_) => true,
                }
            }
            GovernanceCleanupPoolMaintenanceMode::Drain => {
                let slot = inspect_cleanup_pool_slot(parent, pool, lock, binding, pool_path, name)?;
                if !matches!(
                    slot.phase,
                    Some(CleanupPoolPhase::Retained | CleanupPoolPhase::ForeignPreserved)
                ) {
                    return Err(cleanup_maintenance_error(
                        pool_path,
                        format!("drain found nonterminal slot `{slot_name}`"),
                    ));
                }
                slot.opaque
            }
        };
        selected.push(slot_name.clone());
        if is_opaque {
            opaque.push(slot_name.clone());
        }
        identities.insert(slot_name.clone(), identity);
        proofs.insert(slot_name.clone(), proof);
    }
    Ok((selected, opaque, identities, proofs))
}

fn create_cleanup_maintenance_archive(
    parent: &AuthorityCleanupParent,
    parent_path: &Path,
    archive_name: &str,
) -> Result<(PathBuf, fs::File, GovernanceArtifactIdentity), GovernancePersistenceError> {
    if !valid_cleanup_archive_name(archive_name) {
        return Err(cleanup_maintenance_archive_error(
            parent_path,
            "archive name must be one validated path component",
        ));
    }
    let name = OsStr::new(archive_name);
    let archive = match create_directory_at(&parent.file, name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(cleanup_maintenance_archive_error(
                &parent_path.join(archive_name),
                "archive destination already exists",
            ));
        }
        Err(source) => {
            return Err(cleanup_maintenance_archive_error(
                &parent_path.join(archive_name),
                format!("archive directory could not be created: {source}"),
            ));
        }
    };
    let identity = archive
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        .ok_or_else(|| {
            cleanup_maintenance_archive_error(
                &parent_path.join(archive_name),
                "archive directory identity is unavailable",
            )
        })?;
    archive
        .sync_all()
        .and_then(|()| parent.file.sync_all())
        .map_err(|source| {
            cleanup_maintenance_archive_error(
                &parent_path.join(archive_name),
                format!("archive creation durability sync failed: {source}"),
            )
        })?;
    Ok((parent_path.join(archive_name), archive, identity))
}

fn open_cleanup_maintenance_archive(
    parent: &AuthorityCleanupParent,
    parent_path: &Path,
    archive_name: &str,
    expected: GovernanceArtifactIdentity,
) -> Result<(PathBuf, fs::File), GovernancePersistenceError> {
    if !valid_cleanup_archive_name(archive_name) {
        return Err(cleanup_maintenance_archive_error(
            parent_path,
            "journal archive name is not one path component",
        ));
    }
    let path = parent_path.join(archive_name);
    let archive = open_directory_at(&parent.file, OsStr::new(archive_name)).map_err(|source| {
        cleanup_maintenance_archive_error(
            &path,
            format!("journal archive is unavailable: {source}"),
        )
    })?;
    let observed = archive
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata));
    if observed != Some(expected) {
        return Err(cleanup_maintenance_archive_error(
            &path,
            "journal archive identity changed",
        ));
    }
    Ok((path, archive))
}

fn validate_cleanup_maintenance_archive_entries(
    archive: &fs::File,
    selected: &[String],
    archive_path: &Path,
) -> Result<(), GovernancePersistenceError> {
    let selected = selected.iter().map(OsString::from).collect::<BTreeSet<_>>();
    for name in directory_entry_names(archive).map_err(|source| {
        cleanup_maintenance_archive_error(
            archive_path,
            format!("archive could not enumerate: {source}"),
        )
    })? {
        if !selected.contains(&name) {
            return Err(cleanup_maintenance_archive_error(
                archive_path,
                format!(
                    "archive contains unknown entry `{}`",
                    name.to_string_lossy()
                ),
            ));
        }
    }
    Ok(())
}

struct CleanupPoolMaintenanceMoveContext<'a> {
    pool: &'a fs::File,
    pool_identity: GovernanceArtifactIdentity,
    pool_name: &'a OsStr,
    archive: &'a fs::File,
    archive_identity: GovernanceArtifactIdentity,
    archive_name: &'a OsStr,
    parent: &'a AuthorityCleanupParent,
    state_path: &'a Path,
    pool_path: &'a Path,
    archive_path: &'a Path,
}

fn move_cleanup_maintenance_slot(
    context: CleanupPoolMaintenanceMoveContext<'_>,
    slot_name: &str,
    expected_identity: Option<GovernanceArtifactIdentity>,
    expected_proof: Option<&CleanupPoolMaintenanceSlotProof>,
    current_proof: Option<&CleanupPoolMaintenanceSlotProof>,
    expected_archive_identity: GovernanceArtifactIdentity,
) -> Result<(), GovernancePersistenceError> {
    let CleanupPoolMaintenanceMoveContext {
        pool,
        pool_identity,
        pool_name,
        archive,
        archive_identity,
        archive_name,
        parent,
        state_path,
        pool_path,
        archive_path,
    } = context;
    if pool
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        != Some(pool_identity)
        || archive
            .metadata()
            .ok()
            .and_then(|metadata| governance_directory_identity(&metadata))
            != Some(expected_archive_identity)
        || archive_identity != expected_archive_identity
        || directory_entry_identity_at(&parent.file, pool_name).ok() != Some(Some(pool_identity))
        || directory_entry_identity_at(&parent.file, archive_name).ok()
            != Some(Some(expected_archive_identity))
    {
        return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: state_path.to_path_buf(),
            reason: "maintenance pool or archive descriptor identity changed".to_string(),
        });
    }
    if !authority_cleanup_parent_is_current(state_path, parent) {
        return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: state_path.to_path_buf(),
            reason: "original parent directory changed during cleanup maintenance".to_string(),
        });
    }
    let name = OsStr::new(slot_name);
    let source_identity = directory_entry_identity_at(pool, name).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("could not inspect slot `{slot_name}`: {source}"),
        )
    })?;
    let archive_identity = directory_entry_identity_at(archive, name).map_err(|source| {
        cleanup_maintenance_archive_error(
            archive_path,
            format!("could not inspect archive slot `{slot_name}`: {source}"),
        )
    })?;
    let Some(expected_proof) = expected_proof else {
        return Err(cleanup_maintenance_error(
            pool_path,
            format!("slot `{slot_name}` has no authenticated maintenance proof"),
        ));
    };
    if source_identity.is_some()
        && (expected_identity != Some(expected_proof.identity)
            || current_proof != Some(expected_proof))
    {
        return Err(cleanup_maintenance_error(
            pool_path,
            format!("slot `{slot_name}` source proof changed before maintenance move"),
        ));
    }
    match (source_identity, archive_identity) {
        (None, Some(observed)) => {
            let (digest, byte_len) =
                cleanup_pool_slot_content_proof(archive, name).map_err(|source| {
                    cleanup_maintenance_archive_error(archive_path, source.to_string())
                })?;
            if observed != expected_proof.identity
                || digest != expected_proof.content_digest
                || byte_len != expected_proof.byte_len
            {
                return Err(cleanup_maintenance_archive_error(
                    archive_path,
                    format!("resumed archive slot `{slot_name}` does not match its journal proof"),
                ));
            }
            return Ok(());
        }
        (None, None) => {
            return Err(cleanup_maintenance_error(
                pool_path,
                format!("slot `{slot_name}` disappeared from both active and archive namespaces"),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(cleanup_maintenance_archive_error(
                archive_path,
                format!("archive slot `{slot_name}` already exists while active slot remains"),
            ));
        }
        (Some(observed), None) => {
            if observed != expected_proof.identity {
                return Err(cleanup_maintenance_error(
                    pool_path,
                    format!("slot `{slot_name}` identity changed before no-replace move"),
                ));
            }
        }
    }
    #[cfg(test)]
    pause_before_cleanup_maintenance_move(pool_path, slot_name);
    if !authority_cleanup_parent_is_current(state_path, parent) {
        return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: state_path.to_path_buf(),
            reason: "original parent directory changed after maintenance move preflight"
                .to_string(),
        });
    }
    if directory_entry_identity_at(pool, name)
        .map_err(|source| cleanup_maintenance_error(pool_path, source.to_string()))?
        != Some(expected_proof.identity)
    {
        return Err(cleanup_maintenance_error(
            pool_path,
            format!("slot `{slot_name}` identity changed at the final move seam"),
        ));
    }
    let (digest, byte_len) = cleanup_pool_slot_content_proof(pool, name)
        .map_err(|source| cleanup_maintenance_error(pool_path, source.to_string()))?;
    if digest != expected_proof.content_digest || byte_len != expected_proof.byte_len {
        return Err(cleanup_maintenance_error(
            pool_path,
            format!("slot `{slot_name}` content changed at the final move seam"),
        ));
    }
    atomic_no_replace_move_between(pool, name, archive, name).map_err(|source| {
        cleanup_maintenance_error(
            pool_path,
            format!("slot `{slot_name}` could not move atomically: {source}"),
        )
    })?;
    if archive
        .metadata()
        .ok()
        .and_then(|metadata| governance_directory_identity(&metadata))
        != Some(expected_archive_identity)
        || directory_entry_identity_at(&parent.file, archive_name).ok()
            != Some(Some(expected_archive_identity))
        || directory_entry_identity_at(&parent.file, pool_name).ok() != Some(Some(pool_identity))
    {
        return Err(cleanup_maintenance_archive_error(
            archive_path,
            "archive directory identity changed after slot move",
        ));
    }
    let moved_identity = directory_entry_identity_at(archive, name)
        .map_err(|source| cleanup_maintenance_archive_error(archive_path, source.to_string()))?;
    let source_after = directory_entry_identity_at(pool, name)
        .map_err(|source| cleanup_maintenance_error(pool_path, source.to_string()))?;
    let (moved_digest, moved_byte_len) = cleanup_pool_slot_content_proof(archive, name)
        .map_err(|source| cleanup_maintenance_archive_error(archive_path, source.to_string()))?;
    if moved_identity != Some(expected_proof.identity)
        || source_after.is_some()
        || moved_digest != expected_proof.content_digest
        || moved_byte_len != expected_proof.byte_len
    {
        return Err(cleanup_maintenance_error(
            pool_path,
            format!("slot `{slot_name}` move did not converge"),
        ));
    }
    archive
        .sync_all()
        .and_then(|()| pool.sync_all())
        .and_then(|()| parent.file.sync_all())
        .map_err(|source| {
            cleanup_maintenance_error(
                pool_path,
                format!("slot `{slot_name}` durability sync failed: {source}"),
            )
        })?;
    Ok(())
}

fn run_cleanup_pool_maintenance(
    path: PathBuf,
    governing_agent_id: AgentId,
    signing_key: SigningKey,
    guard: GovernanceCleanupPoolMaintenanceGuard,
    mode: GovernanceCleanupPoolMaintenanceMode,
    archive_name: &str,
) -> Result<GovernanceCleanupPoolMaintenanceReport, GovernancePersistenceError> {
    let local = LocalGovernorKey::new(signing_key.clone());
    let expected_signer = local.consensus_agent_id().clone();
    let authority_lock = guard.transfer()?;
    let persistence = GovernancePersistence::new_with_authority_lock(
        path.clone(),
        expected_signer.clone(),
        GovernanceLockOpenMode::Existing,
        Some(authority_lock),
    )
    .map_err(map_cleanup_maintenance_contention)?;
    persistence.verify_lock_path()?;
    persistence
        .preflight_cleanup_pool_namespace_with_maintenance(
            true,
            mode == GovernanceCleanupPoolMaintenanceMode::Reset,
        )
        .map_err(map_cleanup_maintenance_contention)?;
    persistence
        .ensure_cleanup_pool_context(&signing_key, false)
        .map_err(map_cleanup_maintenance_contention)?;
    let loaded = persistence.load(&local)?;
    if loaded.payload.governing_agent_id.as_ref() != Some(&governing_agent_id)
        || loaded.payload.display_governors.get(&governing_agent_id) != Some(&expected_signer)
    {
        return Err(GovernancePersistenceError::InvalidIdentityBinding {
            reason: "maintenance signer is not the admitted governing agent".to_string(),
        });
    }
    let mut context_guard = persistence
        .cleanup_pool_context
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let context = context_guard.as_mut().ok_or_else(|| {
        GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: path.clone(),
            reason: "maintenance cleanup-pool context was not retained".to_string(),
        }
    })?;
    persistence.verify_cleanup_pool_context_locked(context)?;
    let parent = AuthorityCleanupParent {
        file: persistence.parent_directory.try_clone().map_err(|source| {
            cleanup_maintenance_error(
                &path,
                format!("parent descriptor could not clone: {source}"),
            )
        })?,
        identity: persistence.parent_directory_identity,
    };
    let pool_path = context.pool_path.clone();
    let pool = context.pool_file.try_clone().map_err(|source| {
        cleanup_maintenance_error(
            &pool_path,
            format!("pool descriptor could not clone: {source}"),
        )
    })?;
    let lock = context.lock_file.try_clone().map_err(|source| {
        cleanup_maintenance_error(
            &pool_path,
            format!("pool lock descriptor could not clone: {source}"),
        )
    })?;
    let binding = context.binding.clone();
    drop(context_guard);
    if !authority_cleanup_parent_is_current(&path, &parent) {
        return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
            path: path.clone(),
            reason: "original parent directory changed before cleanup maintenance".to_string(),
        });
    }

    let mut journal_handle = open_cleanup_pool_maintenance_journal(&pool, &pool_path, false)?;
    let mut journal = if let Some(ref mut handle) = journal_handle {
        read_cleanup_pool_maintenance_journal(
            handle,
            &pool,
            &pool_path,
            &binding,
            &expected_signer,
        )?
    } else {
        CleanupPoolMaintenanceJournal {
            schema_version: CLEANUP_POOL_MAINTENANCE_SCHEMA_VERSION,
            operation_id: cleanup_pool_transaction_id(),
            mode,
            binding: binding.clone(),
            archive_name: archive_name.to_string(),
            archive_identity: GovernanceArtifactIdentity {
                device: 0,
                inode: 0,
            },
            selected_slots: Vec::new(),
            slot_proofs: BTreeMap::new(),
            moved_slots: Vec::new(),
            opaque_slots: Vec::new(),
            phase: CleanupPoolMaintenanceJournalPhase::Prepared,
        }
    };
    let resume = journal_handle.is_some()
        && !matches!(journal.phase, CleanupPoolMaintenanceJournalPhase::Completed);
    if resume {
        if journal.mode != mode || journal.archive_name != archive_name {
            return Err(GovernancePersistenceError::MaintenanceBusy {
                path: pool_path,
                resource: "a different cleanup maintenance transaction is active".to_string(),
            });
        }
    } else {
        let (selected, opaque, _identities, slot_proofs) = scan_cleanup_pool_slots_for_maintenance(
            &parent, &pool, &lock, &binding, &pool_path, mode,
        )?;
        let parent_path = path.parent().unwrap_or(&path).to_path_buf();
        let (archive_path, archive, archive_identity) =
            create_cleanup_maintenance_archive(&parent, &parent_path, archive_name)?;
        validate_cleanup_maintenance_archive_entries(&archive, &selected, &archive_path)?;
        journal = CleanupPoolMaintenanceJournal {
            schema_version: CLEANUP_POOL_MAINTENANCE_SCHEMA_VERSION,
            operation_id: cleanup_pool_transaction_id(),
            mode,
            binding: binding.clone(),
            archive_name: archive_name.to_string(),
            archive_identity,
            selected_slots: selected,
            slot_proofs,
            moved_slots: Vec::new(),
            opaque_slots: opaque,
            phase: CleanupPoolMaintenanceJournalPhase::Prepared,
        };
        let mut handle = match journal_handle.take() {
            Some(handle) => handle,
            None => open_cleanup_pool_maintenance_journal(&pool, &pool_path, true)?.ok_or_else(
                || {
                    cleanup_maintenance_error(
                        &pool_path,
                        "maintenance journal could not be created",
                    )
                },
            )?,
        };
        write_cleanup_pool_maintenance_journal(
            CleanupPoolMaintenanceJournalWriteContext {
                handle: &mut handle,
                pool: &pool,
                parent: &parent.file,
                archive: &archive,
                pool_path: &pool_path,
                binding: &binding,
                expected_signer: &expected_signer,
                signing_key: &signing_key,
            },
            &journal,
        )?;
        journal_handle = Some(handle);
        #[cfg(test)]
        maybe_inject_cleanup_maintenance_crash(&path, CleanupMaintenanceCrashPoint::Prepared);
    }

    let parent_path = path.parent().unwrap_or(&path).to_path_buf();
    let (archive_path, archive) = open_cleanup_maintenance_archive(
        &parent,
        &parent_path,
        &journal.archive_name,
        journal.archive_identity,
    )?;
    validate_cleanup_maintenance_archive_entries(&archive, &journal.selected_slots, &archive_path)?;
    let scan_mode = if resume { journal.mode } else { mode };
    let (_, _, identities, current_proofs) = scan_cleanup_pool_slots_for_maintenance(
        &parent, &pool, &lock, &binding, &pool_path, scan_mode,
    )?;
    let moved: BTreeSet<String> = journal.moved_slots.iter().cloned().collect();
    for slot_name in journal.selected_slots.clone() {
        if moved.contains(&slot_name) {
            continue;
        }
        move_cleanup_maintenance_slot(
            CleanupPoolMaintenanceMoveContext {
                pool: &pool,
                pool_identity: binding.pool_identity,
                pool_name: OsStr::new(GOVERNANCE_CLEANUP_POOL_DIR_NAME),
                archive: &archive,
                archive_identity: journal.archive_identity,
                archive_name: OsStr::new(&journal.archive_name),
                parent: &parent,
                state_path: &path,
                pool_path: &pool_path,
                archive_path: &archive_path,
            },
            &slot_name,
            identities.get(&slot_name).copied(),
            journal.slot_proofs.get(&slot_name),
            current_proofs.get(&slot_name),
            journal.archive_identity,
        )?;
        journal.moved_slots.push(slot_name.clone());
        journal.moved_slots.sort();
        journal.phase = CleanupPoolMaintenanceJournalPhase::InProgress;
        let handle = journal_handle.as_mut().ok_or_else(|| {
            cleanup_maintenance_error(&pool_path, "maintenance journal descriptor disappeared")
        })?;
        write_cleanup_pool_maintenance_journal(
            CleanupPoolMaintenanceJournalWriteContext {
                handle,
                pool: &pool,
                parent: &parent.file,
                archive: &archive,
                pool_path: &pool_path,
                binding: &binding,
                expected_signer: &expected_signer,
                signing_key: &signing_key,
            },
            &journal,
        )?;
        #[cfg(test)]
        maybe_inject_cleanup_maintenance_crash(
            &path,
            CleanupMaintenanceCrashPoint::AfterMove(journal.moved_slots.len()),
        );
    }
    #[cfg(test)]
    maybe_inject_cleanup_maintenance_crash(&path, CleanupMaintenanceCrashPoint::BeforeCompleted);
    journal.phase = CleanupPoolMaintenanceJournalPhase::Completed;
    let handle = journal_handle.as_mut().ok_or_else(|| {
        cleanup_maintenance_error(&pool_path, "maintenance journal descriptor disappeared")
    })?;
    write_cleanup_pool_maintenance_journal(
        CleanupPoolMaintenanceJournalWriteContext {
            handle,
            pool: &pool,
            parent: &parent.file,
            archive: &archive,
            pool_path: &pool_path,
            binding: &binding,
            expected_signer: &expected_signer,
            signing_key: &signing_key,
        },
        &journal,
    )?;
    Ok(GovernanceCleanupPoolMaintenanceReport {
        mode: journal.mode,
        archive_path,
        moved_slots: journal.moved_slots,
        opaque_slots: journal.opaque_slots,
    })
}

fn signed_governance_envelope_digest(
    envelope: &SignedStateEnvelope<PersistedGovernanceState>,
    path: &Path,
) -> Result<String, GovernancePersistenceError> {
    let statement_bytes = serde_json::to_vec(&envelope.statement).map_err(|source| {
        GovernancePersistenceError::ParseState {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(sha256_hex(&statement_bytes))
}

fn write_atomic_synced_at(
    path: &Path,
    bytes: &[u8],
    parent: &AuthorityCleanupParent,
    no_replace: bool,
) -> Result<AtomicWriteOutcome, GovernancePersistenceError> {
    let parent_path = path.parent().unwrap_or(path);
    if !authority_cleanup_parent_is_current(path, parent) {
        return Err(GovernancePersistenceError::Write {
            path: parent_path.to_path_buf(),
            source: std::io::Error::other("atomic write parent directory changed"),
        });
    }
    let final_name = path
        .file_name()
        .ok_or_else(|| GovernancePersistenceError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::other("atomic write path has no final component"),
        })?;
    let existing_identity =
        directory_entry_identity_at(&parent.file, final_name).map_err(|source| {
            GovernancePersistenceError::Write {
                path: path.to_path_buf(),
                source,
            }
        })?;
    if no_replace && existing_identity.is_some() {
        return Err(GovernancePersistenceError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "no-replace publication destination already exists",
            ),
        });
    }
    // Preserve the historical fixed blocker name as an occupied namespace
    // signal.  This also prevents a stale or foreign process-id temporary
    // from being bypassed by the monotonic recovery suffix below.
    let legacy_temporary_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    let legacy_temporary_name = legacy_temporary_path
        .file_name()
        .ok_or_else(|| GovernancePersistenceError::Write {
            path: legacy_temporary_path.clone(),
            source: std::io::Error::other("legacy atomic temporary has no final component"),
        })?
        .to_os_string();
    if directory_entry_identity_at(&parent.file, &legacy_temporary_name)
        .map_err(|source| GovernancePersistenceError::Write {
            path: path.to_path_buf(),
            source,
        })?
        .is_some()
    {
        return Err(GovernancePersistenceError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "atomic publication temporary namespace is occupied",
            ),
        });
    }
    let temporary_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("state"),
        AUTHORITY_CLEANUP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary_name = temporary_path
        .file_name()
        .ok_or_else(|| GovernancePersistenceError::Write {
            path: temporary_path.clone(),
            source: std::io::Error::other("atomic write temporary has no final component"),
        })?
        .to_os_string();
    let mut file = create_regular_file_at(&parent.file, &temporary_name).map_err(|source| {
        GovernancePersistenceError::Write {
            path: parent_path.join(&temporary_name),
            source,
        }
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| GovernancePersistenceError::Write {
            path: parent_path.join(&temporary_name),
            source,
        })?;
    let artifact_identity = governance_artifact_identity(&file.metadata().map_err(|source| {
        GovernancePersistenceError::Write {
            path: parent_path.join(&temporary_name),
            source,
        }
    })?)
    .ok_or_else(|| GovernancePersistenceError::Write {
        path: parent_path.join(&temporary_name),
        source: std::io::Error::other("atomic write temporary is not a regular file"),
    })?;
    if !authority_cleanup_parent_is_current(path, parent) {
        return Err(GovernancePersistenceError::Write {
            path: parent_path.to_path_buf(),
            source: std::io::Error::other("atomic write parent changed before publication"),
        });
    }
    #[cfg(test)]
    pause_before_reinitialization_no_replace_publication(path);
    let move_result = if no_replace {
        atomic_no_replace_move_between(&parent.file, &temporary_name, &parent.file, final_name)
    } else if let Some(expected_identity) = existing_identity {
        atomic_replace_if_identity(
            &parent.file,
            &temporary_name,
            &parent.file,
            final_name,
            expected_identity,
            artifact_identity,
        )
    } else {
        atomic_no_replace_move_between(&parent.file, &temporary_name, &parent.file, final_name)
    };
    move_result.map_err(|source| GovernancePersistenceError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(test)]
    if take_injected_atomic_parent_sync_failure(path) {
        return Ok(AtomicWriteOutcome::RenamedDirectorySyncFailed(
            GovernancePersistenceError::Write {
                path: parent_path.to_path_buf(),
                source: std::io::Error::other("injected post-rename parent sync failure"),
            },
            artifact_identity,
        ));
    }
    if let Err(source) = parent.file.sync_all() {
        return Ok(AtomicWriteOutcome::RenamedDirectorySyncFailed(
            GovernancePersistenceError::Write {
                path: parent_path.to_path_buf(),
                source,
            },
            artifact_identity,
        ));
    }
    Ok(AtomicWriteOutcome::Synced(artifact_identity))
}

#[cfg(test)]
thread_local! {
    static INJECT_ATOMIC_PARENT_SYNC_FAILURE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn inject_atomic_parent_sync_failure(path: &Path) {
    INJECT_ATOMIC_PARENT_SYNC_FAILURE.with(|target| {
        *target.borrow_mut() = Some(path.to_path_buf());
    });
}

#[cfg(test)]
fn take_injected_atomic_parent_sync_failure(path: &Path) -> bool {
    INJECT_ATOMIC_PARENT_SYNC_FAILURE.with(|target| {
        let mut target = target.borrow_mut();
        if target.as_deref() == Some(path) {
            target.take();
            true
        } else {
            false
        }
    })
}

fn remove_governance_stream_files(
    persistence: &GovernancePersistence,
    artifacts: &[(PathBuf, GovernanceArtifactIdentity)],
) -> Result<(), GovernancePersistenceError> {
    let parent = artifacts
        .first()
        .and_then(|(path, _)| bind_authority_cleanup_parent(path))
        .ok_or_else(|| GovernancePersistenceError::Write {
            path: artifacts
                .first()
                .map_or_else(PathBuf::new, |(path, _)| path.clone()),
            source: std::io::Error::other("new-stream cleanup parent is not a regular directory"),
        })?;
    let mut first_error = None;
    for (path, expected) in artifacts {
        persistence.verify_lock_path()?;
        if !authority_cleanup_parent_is_current(path, &parent) {
            if first_error.is_none() {
                first_error = Some(GovernancePersistenceError::Write {
                    path: path.clone(),
                    source: std::io::Error::other(
                        "new-stream cleanup parent directory changed before cleanup",
                    ),
                });
            }
            continue;
        }
        let observed = match read_governance_artifact_identity(path) {
            Ok(observed) => observed,
            Err(source) => {
                if first_error.is_none() {
                    first_error = Some(GovernancePersistenceError::Write {
                        path: path.clone(),
                        source,
                    });
                }
                continue;
            }
        };
        let Some(observed) = observed else {
            continue;
        };
        if observed != *expected {
            if first_error.is_none() {
                first_error = Some(GovernancePersistenceError::Write {
                    path: path.clone(),
                    source: std::io::Error::other(format!(
                        "new-stream artifact identity changed before cleanup: expected {expected:?}, observed {observed:?}"
                    )),
                });
            }
            continue;
        }
        #[cfg(test)]
        pause_before_governance_stream_cleanup(path);
        let cleanup_outcome = quarantine_verified_entry_at(
            path,
            &parent,
            || {
                persistence.verify_lock_path().is_ok()
                    && authority_cleanup_parent_is_current(path, &parent)
                    && read_governance_artifact_identity(path).ok().flatten() == Some(*expected)
            },
            |quarantine| {
                persistence.verify_lock_path().is_ok()
                    && authority_cleanup_parent_is_current(path, &parent)
                    && read_governance_artifact_identity(quarantine).ok().flatten()
                        == Some(*expected)
            },
        );
        if !cleanup_outcome.is_semantic_success() && first_error.is_none() {
            first_error = Some(cleanup_error_for_outcome(path, cleanup_outcome));
        }
        persistence.verify_lock_path()?;
    }
    parent
        .file
        .sync_all()
        .map_err(|source| GovernancePersistenceError::Write {
            path: artifacts.first().map_or_else(PathBuf::new, |(path, _)| {
                path.parent().unwrap_or(path).to_path_buf()
            }),
            source,
        })?;
    first_error.map_or(Ok(()), Err)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReinitializationArtifact {
    original: PathBuf,
    archive: PathBuf,
    identity: GovernanceArtifactIdentity,
    content_digest: String,
    byte_len: u64,
    #[serde(default)]
    archive_identity: Option<GovernanceArtifactIdentity>,
    #[serde(default)]
    restored_identity: Option<GovernanceArtifactIdentity>,
}

const REINITIALIZATION_JOURNAL_SCHEMA_VERSION: u32 = 1;
const REINITIALIZATION_JOURNAL_KIND: &str = "swarm.governance.reinitialization-journal.v1";
const REINITIALIZATION_JOURNAL_STREAM: &str = "tom-primary-reinitialization";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ReinitializationJournalPhase {
    Prepared,
    ArchivesCreated,
    OriginalsRemoved,
    NewStreamCommitted,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReinitializationRollbackJournal {
    schema_version: u32,
    transaction_id: String,
    archive_suffix: String,
    state_path: PathBuf,
    sequence_path: PathBuf,
    artifacts: Vec<ReinitializationArtifact>,
    #[serde(default)]
    new_stream_artifacts: Vec<ReinitializationNewArtifact>,
    phase: ReinitializationJournalPhase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReinitializationNewArtifact {
    path: PathBuf,
    content_digest: String,
    byte_len: u64,
    #[serde(default)]
    identity: Option<GovernanceArtifactIdentity>,
}

fn reinitialization_journal_path(path: &Path) -> PathBuf {
    path.with_extension("reinitialize.journal")
}

fn reinitialization_archive_path(path: &Path, suffix: &str) -> PathBuf {
    path.with_extension(format!(
        "{}.{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("state"),
        suffix
    ))
}

fn valid_reinitialization_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && Path::new(suffix).file_name().and_then(|name| name.to_str()) == Some(suffix)
        && !suffix.contains('.')
}

fn write_reinitialization_archive_at(
    artifact: &ReinitializationArtifact,
    bytes: &[u8],
    parent: &AuthorityCleanupParent,
) -> Result<GovernanceArtifactIdentity, GovernancePersistenceError> {
    let archive_parent = artifact.archive.parent().unwrap_or(&artifact.archive);
    if artifact.original.parent() != artifact.archive.parent()
        || !authority_cleanup_parent_is_current(&artifact.original, parent)
    {
        return Err(GovernancePersistenceError::Write {
            path: artifact.archive.clone(),
            source: std::io::Error::other("archive parent changed or is not the source parent"),
        });
    }
    let archive_name =
        artifact
            .archive
            .file_name()
            .ok_or_else(|| GovernancePersistenceError::Write {
                path: artifact.archive.clone(),
                source: std::io::Error::other("archive path has no final component"),
            })?;
    let mut archive = create_regular_file_at(&parent.file, archive_name).map_err(|source| {
        GovernancePersistenceError::Write {
            path: archive_parent.join(archive_name),
            source,
        }
    })?;
    archive
        .write_all(bytes)
        .and_then(|()| archive.sync_all())
        .map_err(|source| GovernancePersistenceError::Write {
            path: artifact.archive.clone(),
            source,
        })?;
    let metadata = archive
        .metadata()
        .map_err(|source| GovernancePersistenceError::Write {
            path: artifact.archive.clone(),
            source,
        })?;
    let Some(identity) = governance_artifact_identity(&metadata) else {
        return Err(GovernancePersistenceError::Write {
            path: artifact.archive.clone(),
            source: std::io::Error::other("archive is not a regular non-symlink file"),
        });
    };
    if metadata.len() != artifact.byte_len || sha256_hex(bytes) != artifact.content_digest {
        return Err(GovernancePersistenceError::Write {
            path: artifact.archive.clone(),
            source: std::io::Error::other("archive bytes do not match authenticated snapshot"),
        });
    }
    parent
        .file
        .sync_all()
        .map_err(|source| GovernancePersistenceError::Write {
            path: archive_parent.to_path_buf(),
            source,
        })?;
    Ok(identity)
}

fn reinitialization_journal_error(
    path: &Path,
    reason: impl Into<String>,
) -> GovernancePersistenceError {
    GovernancePersistenceError::ReinitializationFailed {
        reason: format!(
            "reinitialization journal `{}`: {}",
            path.display(),
            reason.into()
        ),
    }
}

fn validate_reinitialization_journal(
    path: &Path,
    journal: &ReinitializationRollbackJournal,
) -> Result<(), GovernancePersistenceError> {
    let sequence_path = path.with_extension("sequence.json");
    let expected_journal_path = reinitialization_journal_path(path);
    if journal.schema_version != REINITIALIZATION_JOURNAL_SCHEMA_VERSION {
        return Err(reinitialization_journal_error(
            &reinitialization_journal_path(path),
            format!("unsupported schema version {}", journal.schema_version),
        ));
    }
    if journal.transaction_id.is_empty()
        || !valid_reinitialization_suffix(&journal.archive_suffix)
        || journal.state_path != path
        || journal.sequence_path != sequence_path
    {
        return Err(reinitialization_journal_error(
            &reinitialization_journal_path(path),
            "journal stream identity or transaction id does not match the requested path",
        ));
    }
    if journal.artifacts.iter().any(|artifact| {
        let expected_archive =
            reinitialization_archive_path(&artifact.original, &journal.archive_suffix);
        artifact.original != path && artifact.original != sequence_path
            || artifact.archive != expected_archive
            || artifact.archive.parent() != artifact.original.parent()
            || artifact.archive.file_name() != expected_archive.file_name()
            || artifact.archive == artifact.original
            || artifact.content_digest.is_empty()
            || artifact.archive_identity.is_none()
                && !matches!(
                    journal.phase,
                    ReinitializationJournalPhase::Prepared | ReinitializationJournalPhase::Restored
                )
            || matches!(journal.phase, ReinitializationJournalPhase::Restored)
                && artifact.restored_identity.is_none()
    }) {
        return Err(reinitialization_journal_error(
            &reinitialization_journal_path(path),
            "journal contains an invalid canonical archive or incomplete snapshot",
        ));
    }
    let mut originals = journal
        .artifacts
        .iter()
        .map(|artifact| artifact.original.clone())
        .collect::<Vec<_>>();
    originals.sort();
    originals.dedup();
    if originals.len() != journal.artifacts.len() {
        return Err(reinitialization_journal_error(
            &reinitialization_journal_path(path),
            "journal contains duplicate artifacts",
        ));
    }
    if journal.new_stream_artifacts.iter().any(|artifact| {
        (artifact.path != path && artifact.path != sequence_path)
            || artifact.content_digest.is_empty()
    }) {
        return Err(reinitialization_journal_error(
            &reinitialization_journal_path(path),
            "journal contains an unknown new-stream artifact",
        ));
    }
    let mut new_stream_paths = journal
        .new_stream_artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    new_stream_paths.sort();
    new_stream_paths.dedup();
    if new_stream_paths.len() != journal.new_stream_artifacts.len() {
        return Err(reinitialization_journal_error(
            &expected_journal_path,
            "journal contains duplicate new-stream artifacts",
        ));
    }
    Ok(())
}

fn read_reinitialization_journal(
    path: &Path,
    expected_signer_agent_id: &AgentId,
) -> Result<
    Option<(
        ReinitializationRollbackJournal,
        GovernanceArtifactIdentity,
        String,
    )>,
    GovernancePersistenceError,
> {
    let journal_path = reinitialization_journal_path(path);
    read_reinitialization_journal_at(&journal_path, path, expected_signer_agent_id)
}

fn read_reinitialization_journal_at(
    journal_path: &Path,
    path: &Path,
    expected_signer_agent_id: &AgentId,
) -> Result<
    Option<(
        ReinitializationRollbackJournal,
        GovernanceArtifactIdentity,
        String,
    )>,
    GovernancePersistenceError,
> {
    let expected_journal_path = reinitialization_journal_path(path);
    if journal_path != expected_journal_path {
        return Err(reinitialization_journal_error(
            journal_path,
            "journal path is not the canonical same-parent stream journal",
        ));
    }
    let Some((snapshot, bytes)) = read_governance_artifact_snapshot(journal_path)
        .map_err(|source| reinitialization_journal_error(journal_path, source.to_string()))?
    else {
        return Ok(None);
    };
    let identity = snapshot.identity;
    let envelope: SignedStateEnvelope<ReinitializationRollbackJournal> =
        serde_json::from_slice(&bytes).map_err(|source| {
            reinitialization_journal_error(journal_path, format!("journal is invalid: {source}"))
        })?;
    let verified = envelope
        .verify(SignedStateExpectation {
            state_kind: REINITIALIZATION_JOURNAL_KIND,
            stream_id: REINITIALIZATION_JOURNAL_STREAM,
            expected_signer_agent_id: Some(expected_signer_agent_id),
            accepted_sequence: None,
        })
        .map_err(|source| {
            reinitialization_journal_error(
                journal_path,
                format!("journal authentication failed: {source}"),
            )
        })?;
    let journal = verified.payload;
    validate_reinitialization_journal(path, &journal)?;
    Ok(Some((journal, identity, sha256_hex(&bytes))))
}

fn verify_reinitialization_journal_identity_and_digest(
    path: &Path,
    expected_identity: GovernanceArtifactIdentity,
    expected_digest: &str,
    expected_signer_agent_id: &AgentId,
) -> Result<(), GovernancePersistenceError> {
    let Some((_, identity, digest)) =
        read_reinitialization_journal(path, expected_signer_agent_id)?
    else {
        return Err(reinitialization_journal_error(
            path,
            "journal disappeared during recovery",
        ));
    };
    if identity != expected_identity || digest != expected_digest {
        return Err(reinitialization_journal_error(
            path,
            "journal identity or authenticated content changed during recovery",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn write_reinitialization_journal(
    path: &Path,
    journal: &ReinitializationRollbackJournal,
    signing_key: &SigningKey,
) -> Result<(GovernanceArtifactIdentity, String), GovernancePersistenceError> {
    let parent = bind_authority_cleanup_parent(path).ok_or_else(|| {
        reinitialization_journal_error(path, "journal parent is not a regular directory")
    })?;
    write_reinitialization_journal_at(path, journal, signing_key, &parent)
}

fn write_reinitialization_journal_at(
    path: &Path,
    journal: &ReinitializationRollbackJournal,
    signing_key: &SigningKey,
    parent: &AuthorityCleanupParent,
) -> Result<(GovernanceArtifactIdentity, String), GovernancePersistenceError> {
    validate_reinitialization_journal(path, journal)?;
    if !authority_cleanup_parent_is_current(path, parent) {
        return Err(reinitialization_journal_error(
            path,
            "journal parent changed before write",
        ));
    }
    let journal_path = reinitialization_journal_path(path);
    let signer = AgentId::from_verifying_key(&signing_key.verifying_key());
    let envelope = SignedStateEnvelope::sign(
        REINITIALIZATION_JOURNAL_KIND,
        REINITIALIZATION_JOURNAL_STREAM,
        signer,
        0,
        journal,
        signing_key,
    )
    .map_err(|source| reinitialization_journal_error(&journal_path, source.to_string()))?;
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
        reinitialization_journal_error(
            &journal_path,
            format!("journal serialization failed: {source}"),
        )
    })?;
    let digest = sha256_hex(&bytes);
    match write_atomic_synced_at(&journal_path, &bytes, parent, false)? {
        AtomicWriteOutcome::Synced(identity) => Ok((identity, digest)),
        AtomicWriteOutcome::RenamedDirectorySyncFailed(error, _) => Err(error),
    }
}

fn remove_reinitialization_journal_if_owned_at(
    path: &Path,
    expected: GovernanceArtifactIdentity,
    expected_digest: &str,
    expected_signer_agent_id: &AgentId,
    parent: &AuthorityCleanupParent,
) -> Result<(), GovernancePersistenceError> {
    let journal_path = reinitialization_journal_path(path);
    let matches = || {
        read_reinitialization_journal_at(&journal_path, path, expected_signer_agent_id)
            .ok()
            .flatten()
            .is_some_and(|(_, identity, digest)| identity == expected && digest == expected_digest)
    };
    let cleanup_outcome =
        quarantine_verified_entry_at(&journal_path, parent, matches, |quarantine| {
            read_governance_artifact_snapshot(quarantine)
                .ok()
                .flatten()
                .is_some_and(|(snapshot, bytes)| {
                    snapshot.identity == expected && sha256_hex(&bytes) == expected_digest
                })
        });
    if !cleanup_outcome.is_semantic_success() {
        return Err(cleanup_error_for_outcome(&journal_path, cleanup_outcome));
    }
    Ok(())
}

fn reinitialization_artifact_matches_at(
    parent: &AuthorityCleanupParent,
    path: &Path,
    artifact: &ReinitializationArtifact,
) -> bool {
    path.file_name()
        .and_then(|name| read_governance_artifact_snapshot_at(&parent.file, name).ok())
        .flatten()
        .is_some_and(|(snapshot, _)| {
            snapshot.identity == artifact.identity
                && snapshot.content_digest == artifact.content_digest
                && snapshot.byte_len == artifact.byte_len
        })
}

fn restore_reinitialization_artifact(
    persistence: &GovernancePersistence,
    artifact: &mut ReinitializationArtifact,
) -> Result<(), GovernancePersistenceError> {
    persistence.verify_lock_path()?;
    let parent = held_persistence_parent(persistence)?;
    let original_name =
        artifact
            .original
            .file_name()
            .ok_or_else(|| GovernancePersistenceError::Write {
                path: artifact.original.clone(),
                source: std::io::Error::other("rollback original has no final component"),
            })?;
    let archive_name =
        artifact
            .archive
            .file_name()
            .ok_or_else(|| GovernancePersistenceError::Write {
                path: artifact.archive.clone(),
                source: std::io::Error::other("rollback archive has no final component"),
            })?;
    if artifact.original.parent() != artifact.archive.parent()
        || !authority_cleanup_parent_is_current(&artifact.original, &parent)
    {
        return Err(GovernancePersistenceError::Write {
            path: artifact.original.clone(),
            source: std::io::Error::other(
                "rollback artifacts are not in the held current parent directory",
            ),
        });
    }
    let Some((archive_snapshot, bytes)) =
        read_governance_artifact_snapshot_at(&parent.file, archive_name).map_err(|source| {
            GovernancePersistenceError::Write {
                path: artifact.archive.clone(),
                source,
            }
        })?
    else {
        let Some((original_snapshot, _)) =
            read_governance_artifact_snapshot_at(&parent.file, original_name).map_err(
                |source| GovernancePersistenceError::Write {
                    path: artifact.original.clone(),
                    source,
                },
            )?
        else {
            return Err(GovernancePersistenceError::Write {
                path: artifact.archive.clone(),
                source: std::io::Error::other(
                    "rollback archive is missing before its original was proven restored",
                ),
            });
        };
        if original_snapshot.content_digest != artifact.content_digest
            || original_snapshot.byte_len != artifact.byte_len
            || (artifact.restored_identity != Some(original_snapshot.identity)
                && artifact.identity != original_snapshot.identity)
        {
            return Err(GovernancePersistenceError::Write {
                path: artifact.original.clone(),
                source: std::io::Error::other(
                    "rollback archive is missing and original bytes do not match",
                ),
            });
        }
        artifact.restored_identity = Some(original_snapshot.identity);
        return Ok(());
    };
    if artifact
        .archive_identity
        .is_some_and(|expected| expected != archive_snapshot.identity)
        || archive_snapshot.content_digest != artifact.content_digest
        || archive_snapshot.byte_len != artifact.byte_len
    {
        return Err(GovernancePersistenceError::Write {
            path: artifact.archive.clone(),
            source: std::io::Error::other(
                "archive identity or authenticated bytes changed during rollback",
            ),
        });
    }
    if let Some((original_snapshot, _)) =
        read_governance_artifact_snapshot_at(&parent.file, original_name).map_err(|source| {
            GovernancePersistenceError::Write {
                path: artifact.original.clone(),
                source,
            }
        })?
    {
        if original_snapshot.content_digest != artifact.content_digest
            || original_snapshot.byte_len != artifact.byte_len
            || (artifact.restored_identity != Some(original_snapshot.identity)
                && artifact.identity != original_snapshot.identity)
        {
            return Err(GovernancePersistenceError::Write {
                path: artifact.original.clone(),
                source: std::io::Error::other("foreign original appeared during rollback"),
            });
        }
        artifact.restored_identity = Some(original_snapshot.identity);
        return Ok(());
    }
    let restore_tmp = artifact.original.with_extension(format!(
        "restore.tmp-{}",
        AUTHORITY_CLEANUP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let restore_tmp_name =
        restore_tmp
            .file_name()
            .ok_or_else(|| GovernancePersistenceError::Write {
                path: restore_tmp.clone(),
                source: std::io::Error::other("restore temporary has no final component"),
            })?;
    if !authority_cleanup_parent_is_current(&artifact.original, &parent) {
        return Err(GovernancePersistenceError::Write {
            path: artifact.original.clone(),
            source: std::io::Error::other("rollback parent changed before temporary creation"),
        });
    }
    let mut restored =
        create_regular_file_at(&parent.file, restore_tmp_name).map_err(|source| {
            GovernancePersistenceError::Write {
                path: restore_tmp.clone(),
                source,
            }
        })?;
    restored
        .write_all(&bytes)
        .and_then(|()| restored.sync_all())
        .map_err(|source| GovernancePersistenceError::Write {
            path: restore_tmp.clone(),
            source,
        })?;
    let restore_tmp_identity =
        governance_artifact_identity(&restored.metadata().map_err(|source| {
            GovernancePersistenceError::Write {
                path: restore_tmp.clone(),
                source,
            }
        })?)
        .ok_or_else(|| GovernancePersistenceError::Write {
            path: restore_tmp.clone(),
            source: std::io::Error::other(
                "restore temporary disappeared before its identity was journaled",
            ),
        })?;
    if !authority_cleanup_parent_is_current(&artifact.original, &parent)
        || directory_entry_identity_at(&parent.file, original_name)
            .map_err(|source| GovernancePersistenceError::Write {
                path: artifact.original.clone(),
                source,
            })?
            .is_some()
    {
        return Err(GovernancePersistenceError::Write {
            path: artifact.original.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "rollback original appeared before descriptor-bound restore",
            ),
        });
    }
    linkat_relative(&parent.file, restore_tmp_name, &parent.file, original_name).map_err(
        |source| GovernancePersistenceError::Write {
            path: artifact.original.clone(),
            source,
        },
    )?;
    #[cfg(test)]
    pause_after_reinitialization_restore_link(&artifact.original);
    let Some((restored_snapshot, _)) =
        read_governance_artifact_snapshot_at(&parent.file, original_name).map_err(|source| {
            GovernancePersistenceError::Write {
                path: artifact.original.clone(),
                source,
            }
        })?
    else {
        return Err(GovernancePersistenceError::Write {
            path: artifact.original.clone(),
            source: std::io::Error::other("restored original disappeared"),
        });
    };
    if restored_snapshot.identity != restore_tmp_identity
        || restored_snapshot.content_digest != artifact.content_digest
        || restored_snapshot.byte_len != artifact.byte_len
    {
        return Err(GovernancePersistenceError::Write {
            path: artifact.original.clone(),
            source: std::io::Error::other(
                "restored original identity or bytes do not match the authenticated temporary",
            ),
        });
    }
    artifact.restored_identity = Some(restored_snapshot.identity);
    let cleanup_outcome = quarantine_verified_entry_at(
        &restore_tmp,
        &parent,
        || {
            read_governance_artifact_snapshot_at(&parent.file, restore_tmp_name)
                .ok()
                .flatten()
                .is_some_and(|(snapshot, _)| {
                    snapshot.identity == restore_tmp_identity
                        && snapshot.content_digest == artifact.content_digest
                        && snapshot.byte_len == artifact.byte_len
                })
        },
        |quarantine| {
            quarantine
                .file_name()
                .and_then(|name| read_governance_artifact_snapshot_at(&parent.file, name).ok())
                .flatten()
                .is_some_and(|(snapshot, _)| {
                    snapshot.identity == restore_tmp_identity
                        && snapshot.content_digest == artifact.content_digest
                        && snapshot.byte_len == artifact.byte_len
                })
        },
    );
    if !cleanup_outcome.is_semantic_success() {
        return Err(cleanup_error_for_outcome(&restore_tmp, cleanup_outcome));
    }
    parent
        .file
        .sync_all()
        .map_err(|source| GovernancePersistenceError::Write {
            path: artifact
                .original
                .parent()
                .unwrap_or(&artifact.original)
                .to_path_buf(),
            source,
        })?;
    Ok(())
}

fn restore_reinitialization_artifacts(
    persistence: &GovernancePersistence,
    artifacts: &mut [ReinitializationArtifact],
) -> Result<(), GovernancePersistenceError> {
    let parent = held_persistence_parent(persistence)?;
    // First compensate every source entry without deleting any archive. This
    // makes state+sequence restoration one all-or-safe phase: a later peer
    // failure cannot leave an earlier archive discarded before its peer has
    // been proven restorable. Continue after an individual peer failure so
    // earlier mutations are still compensated before the error is returned.
    let mut first_error = None;
    for artifact in artifacts.iter_mut().rev() {
        if let Err(error) = restore_reinitialization_artifact(persistence, artifact)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    for artifact in artifacts.iter() {
        let Some(original_name) = artifact.original.file_name() else {
            if first_error.is_none() {
                first_error = Some(GovernancePersistenceError::Write {
                    path: artifact.original.clone(),
                    source: std::io::Error::other("rollback original has no final component"),
                });
            }
            continue;
        };
        let observed = if authority_cleanup_parent_is_current(&artifact.original, &parent) {
            read_governance_artifact_snapshot_at(&parent.file, original_name)
        } else {
            Err(std::io::Error::other(
                "rollback original parent directory changed during compensation",
            ))
        };
        match observed {
            Ok(Some((snapshot, _)))
                if snapshot.content_digest == artifact.content_digest
                    && snapshot.byte_len == artifact.byte_len
                    && (artifact.restored_identity == Some(snapshot.identity)
                        || artifact.identity == snapshot.identity) => {}
            Ok(observed) => {
                if first_error.is_none() {
                    first_error = Some(GovernancePersistenceError::Write {
                        path: artifact.original.clone(),
                        source: std::io::Error::other(format!(
                            "rollback did not prove original state/sequence bytes: observed {observed:?}"
                        )),
                    });
                }
            }
            Err(source) => {
                if first_error.is_none() {
                    first_error = Some(GovernancePersistenceError::Write {
                        path: artifact.original.clone(),
                        source,
                    });
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn cleanup_reinitialization_archives(
    persistence: &GovernancePersistence,
    artifacts: &[ReinitializationArtifact],
    committed_new_stream_artifacts: Option<&[ReinitializationNewArtifact]>,
) -> Result<(), GovernancePersistenceError> {
    persistence.verify_lock_path()?;
    let parent = held_persistence_parent(persistence)?;
    if let Some(new_stream_artifacts) = committed_new_stream_artifacts {
        for artifact in new_stream_artifacts {
            let Some(expected_identity) = artifact.identity else {
                return Err(GovernancePersistenceError::Write {
                    path: artifact.path.clone(),
                    source: std::io::Error::other(
                        "new-stream cleanup lacks a journaled inode identity",
                    ),
                });
            };
            let name =
                artifact
                    .path
                    .file_name()
                    .ok_or_else(|| GovernancePersistenceError::Write {
                        path: artifact.path.clone(),
                        source: std::io::Error::other("new-stream artifact has no final component"),
                    })?;
            let Some((snapshot, _)) = read_governance_artifact_snapshot_at(&parent.file, name)
                .map_err(|source| GovernancePersistenceError::Write {
                    path: artifact.path.clone(),
                    source,
                })?
            else {
                return Err(GovernancePersistenceError::Write {
                    path: artifact.path.clone(),
                    source: std::io::Error::other(
                        "new-stream artifact disappeared before archive cleanup",
                    ),
                });
            };
            if snapshot.identity != expected_identity
                || snapshot.content_digest != artifact.content_digest
                || snapshot.byte_len != artifact.byte_len
            {
                return Err(GovernancePersistenceError::Write {
                    path: artifact.path.clone(),
                    source: std::io::Error::other(
                        "new-stream identity or authenticated bytes changed before archive cleanup",
                    ),
                });
            }
        }
    } else {
        for artifact in artifacts {
            let name =
                artifact
                    .original
                    .file_name()
                    .ok_or_else(|| GovernancePersistenceError::Write {
                        path: artifact.original.clone(),
                        source: std::io::Error::other("restored original has no final component"),
                    })?;
            let Some((snapshot, _)) = read_governance_artifact_snapshot_at(&parent.file, name)
                .map_err(|source| GovernancePersistenceError::Write {
                    path: artifact.original.clone(),
                    source,
                })?
            else {
                return Err(GovernancePersistenceError::Write {
                    path: artifact.original.clone(),
                    source: std::io::Error::other(
                        "restored original disappeared before archive cleanup",
                    ),
                });
            };
            let identity_matches = artifact
                .restored_identity
                .or(Some(artifact.identity))
                .is_some_and(|expected| expected == snapshot.identity);
            if !identity_matches
                || snapshot.content_digest != artifact.content_digest
                || snapshot.byte_len != artifact.byte_len
            {
                return Err(GovernancePersistenceError::Write {
                    path: artifact.original.clone(),
                    source: std::io::Error::other(
                        "restored original identity or authenticated bytes changed before archive cleanup",
                    ),
                });
            }
        }
    }
    // Archive deletion is intentionally a separate phase after every peer has
    // committed or been restored. A failure here leaves the durable journal
    // available for an idempotent retry rather than losing rollback material.
    for artifact in artifacts {
        let archive_name =
            artifact
                .archive
                .file_name()
                .ok_or_else(|| GovernancePersistenceError::Write {
                    path: artifact.archive.clone(),
                    source: std::io::Error::other("archive has no final component"),
                })?;
        let observed =
            read_governance_artifact_snapshot_at(&parent.file, archive_name).map_err(|source| {
                GovernancePersistenceError::Write {
                    path: artifact.archive.clone(),
                    source,
                }
            })?;
        let Some((observed, _)) = observed else {
            continue;
        };
        if artifact
            .archive_identity
            .is_some_and(|expected| expected != observed.identity)
            || observed.content_digest != artifact.content_digest
            || observed.byte_len != artifact.byte_len
        {
            return Err(GovernancePersistenceError::Write {
                path: artifact.archive.clone(),
                source: std::io::Error::other(
                    "archive identity or authenticated bytes changed before deferred cleanup",
                ),
            });
        }
        let cleanup_outcome = quarantine_verified_entry_at(
            &artifact.archive,
            &parent,
            || {
                persistence.verify_lock_path().is_ok()
                    && authority_cleanup_parent_is_current(&artifact.archive, &parent)
                    && read_governance_artifact_snapshot_at(&parent.file, archive_name)
                        .ok()
                        .flatten()
                        .is_some_and(|(snapshot, _)| {
                            artifact
                                .archive_identity
                                .is_none_or(|expected| expected == snapshot.identity)
                                && snapshot.content_digest == artifact.content_digest
                                && snapshot.byte_len == artifact.byte_len
                        })
            },
            |quarantine| {
                persistence.verify_lock_path().is_ok()
                    && authority_cleanup_parent_is_current(&artifact.archive, &parent)
                    && quarantine
                        .file_name()
                        .and_then(|name| {
                            read_governance_artifact_snapshot_at(&parent.file, name).ok()
                        })
                        .flatten()
                        .is_some_and(|(snapshot, _)| {
                            artifact
                                .archive_identity
                                .is_none_or(|expected| expected == snapshot.identity)
                                && snapshot.content_digest == artifact.content_digest
                                && snapshot.byte_len == artifact.byte_len
                        })
            },
        );
        if !cleanup_outcome.is_semantic_success() {
            return Err(cleanup_error_for_outcome(
                &artifact.archive,
                cleanup_outcome,
            ));
        }
    }
    if !artifacts.is_empty() {
        parent
            .file
            .sync_all()
            .map_err(|source| GovernancePersistenceError::Write {
                path: persistence
                    .path
                    .parent()
                    .unwrap_or(&persistence.path)
                    .to_path_buf(),
                source,
            })?;
    }
    Ok(())
}

fn remove_reinitialization_new_stream_artifacts(
    persistence: &GovernancePersistence,
    artifacts: &[ReinitializationNewArtifact],
) -> Result<(), GovernancePersistenceError> {
    let parent = held_persistence_parent(persistence)?;
    let mut identities = Vec::new();
    for artifact in artifacts {
        let name = artifact
            .path
            .file_name()
            .ok_or_else(|| GovernancePersistenceError::Write {
                path: artifact.path.clone(),
                source: std::io::Error::other("new-stream artifact has no final component"),
            })?;
        let observed = if authority_cleanup_parent_is_current(&artifact.path, &parent) {
            read_governance_artifact_snapshot_at(&parent.file, name)
        } else {
            Err(std::io::Error::other(
                "new-stream artifact parent directory changed during cleanup",
            ))
        }
        .map_err(|source| GovernancePersistenceError::Write {
            path: artifact.path.clone(),
            source,
        })?;
        let Some((snapshot, _)) = observed else {
            continue;
        };
        let Some(expected_identity) = artifact.identity else {
            return Err(GovernancePersistenceError::Write {
                path: artifact.path.clone(),
                source: std::io::Error::other(
                    "new-stream cleanup cannot remove an intent-only artifact without its journaled inode identity",
                ),
            });
        };
        if snapshot.content_digest != artifact.content_digest
            || snapshot.byte_len != artifact.byte_len
            || expected_identity != snapshot.identity
        {
            return Err(GovernancePersistenceError::Write {
                path: artifact.path.clone(),
                source: std::io::Error::other(
                    "new-stream artifact identity or authenticated bytes changed",
                ),
            });
        }
        identities.push((artifact.path.clone(), snapshot.identity));
    }
    remove_governance_stream_files(persistence, &identities)
}

fn rollback_reinitialization_transaction(
    persistence: &GovernancePersistence,
    journal: &mut ReinitializationRollbackJournal,
    signing_key: &SigningKey,
) -> Result<(), GovernancePersistenceError> {
    let parent = held_persistence_parent(persistence)?;
    let new_stream_cleanup_error = if journal.new_stream_artifacts.is_empty() {
        None
    } else {
        remove_reinitialization_new_stream_artifacts(persistence, &journal.new_stream_artifacts)
            .err()
    };
    let restore_error =
        restore_reinitialization_artifacts(persistence, &mut journal.artifacts).err();
    if let Some(error) = restore_error.or(new_stream_cleanup_error) {
        // Persist any successfully restored peer identities before returning
        // the later-peer failure.  The authenticated journal then prevents a
        // restart from treating a same-content foreign inode as the restored
        // stream merely because its bytes happen to match the archive.
        let journal_error =
            write_reinitialization_journal_at(&journal.state_path, journal, signing_key, &parent)
                .err();
        return Err(journal_error.unwrap_or(error));
    }
    journal.phase = ReinitializationJournalPhase::Restored;
    journal.new_stream_artifacts.clear();
    let (journal_identity, journal_digest) =
        write_reinitialization_journal_at(&journal.state_path, journal, signing_key, &parent)?;
    cleanup_reinitialization_archives(persistence, &journal.artifacts, None)?;
    remove_reinitialization_journal_if_owned_at(
        &journal.state_path,
        journal_identity,
        &journal_digest,
        &AgentId::from_verifying_key(&signing_key.verifying_key()),
        &parent,
    )
}

fn finalize_reinitialization_transaction(
    persistence: &GovernancePersistence,
    journal: &ReinitializationRollbackJournal,
    signing_key: &SigningKey,
) -> Result<(), GovernancePersistenceError> {
    let parent = held_persistence_parent(persistence)?;
    if journal.new_stream_artifacts.is_empty() {
        return Err(reinitialization_journal_error(
            &journal.state_path,
            "committed journal has no new-stream identities",
        ));
    }
    for artifact in &journal.new_stream_artifacts {
        let Some(expected_identity) = artifact.identity else {
            return Err(GovernancePersistenceError::Write {
                path: artifact.path.clone(),
                source: std::io::Error::other(
                    "committed reinitialization stream lacks a journaled inode identity",
                ),
            });
        };
        let snapshot = read_governance_artifact_snapshot(&artifact.path).map_err(|source| {
            GovernancePersistenceError::Write {
                path: artifact.path.clone(),
                source,
            }
        })?;
        if snapshot.as_ref().is_none_or(|(snapshot, _)| {
            snapshot.identity != expected_identity
                || snapshot.content_digest != artifact.content_digest
                || snapshot.byte_len != artifact.byte_len
        }) {
            return Err(GovernancePersistenceError::Write {
                path: artifact.path.clone(),
                source: std::io::Error::other(
                    "committed reinitialization stream identity or bytes changed",
                ),
            });
        }
    }
    cleanup_reinitialization_archives(
        persistence,
        &journal.artifacts,
        Some(&journal.new_stream_artifacts),
    )?;
    let journal_path = reinitialization_journal_path(&journal.state_path);
    let Some((_, journal_identity, journal_digest)) = read_reinitialization_journal(
        &journal.state_path,
        &AgentId::from_verifying_key(&signing_key.verifying_key()),
    )?
    else {
        return Err(reinitialization_journal_error(
            &journal_path,
            "journal disappeared during committed cleanup",
        ));
    };
    remove_reinitialization_journal_if_owned_at(
        &journal.state_path,
        journal_identity,
        &journal_digest,
        &AgentId::from_verifying_key(&signing_key.verifying_key()),
        &parent,
    )
}

fn sync_parent_directory(path: &Path) -> Result<(), GovernancePersistenceError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| GovernancePersistenceError::Write {
            path: parent.to_path_buf(),
            source,
        })
}

fn held_persistence_parent(
    persistence: &GovernancePersistence,
) -> Result<AuthorityCleanupParent, GovernancePersistenceError> {
    Ok(AuthorityCleanupParent {
        file: persistence.parent_directory.try_clone().map_err(|source| {
            GovernancePersistenceError::Write {
                path: persistence
                    .path
                    .parent()
                    .unwrap_or(&persistence.path)
                    .to_path_buf(),
                source,
            }
        })?,
        identity: persistence.parent_directory_identity,
    })
}

#[derive(Debug)]
pub struct GovernancePolicy {
    state: Mutex<GovernanceState>,
    config: GovernancePolicyConfig,
    persistence: Option<GovernancePersistence>,
    /// How this policy's governance rounds reach the rest of the committee.
    ///
    /// Defaults to [`SoloGovernorTransport`], which serves a committee of one
    /// and REFUSES any larger committee. A deployment that admits peer
    /// governors and does not also install a networked transport therefore
    /// fails closed -- `can_act` vetoes -- instead of minting receipts from a
    /// round nobody else took part in.
    transport: Arc<dyn ConsensusTransport>,
}

/// A cloneable capability for invoking the authenticated governance policy.
///
/// The wrapped policy allocation and every constructor are private. A caller can
/// obtain this handle only from [`GovernancePolicy::authority`], after that policy
/// has authenticated its signed persistence stream and admitted local governor.
/// There is deliberately no backend trait, generic constructor, `Deref`, or raw
/// policy accessor for downstream code to substitute behavior behind this type.
#[derive(Clone)]
pub struct GovernanceAuthority {
    policy: Arc<GovernancePolicy>,
}

impl std::fmt::Debug for GovernanceAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GovernanceAuthority(..)")
    }
}

/// Opaque, process-local identity of one authenticated governance policy allocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GovernanceAuthorityIdentity(*const ());

impl std::fmt::Debug for GovernanceAuthorityIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("GovernanceAuthorityIdentity(..)")
    }
}

/// Refusal reasons for minting an authority handle.
#[derive(Debug, thiserror::Error)]
pub enum GovernanceAuthorityError {
    #[error("an in-memory governance policy cannot mint a production authority")]
    Unpersisted,

    #[error("persisted governance authority has no admitted local governor")]
    MissingLocalGovernor,

    #[error("persisted governance authority has no authenticated sequence/digest anchor")]
    MissingSignedAnchor,

    #[error("persisted governance authority identity binding is invalid")]
    InvalidIdentityBinding,

    #[error("persisted governance authority has restrictive pending health: {reason}")]
    PendingHealthObservation { reason: String },

    #[error(transparent)]
    Persistence(#[from] GovernancePersistenceError),
}

impl Default for GovernancePolicy {
    fn default() -> Self {
        Self::new(GovernancePolicyConfig::default())
    }
}

impl GovernancePolicy {
    pub fn new(config: GovernancePolicyConfig) -> Self {
        Self {
            state: Mutex::new(GovernanceState::default()),
            config,
            persistence: None,
            transport: Arc::new(SoloGovernorTransport::new()),
        }
    }

    /// Mint the concrete authority capability after rechecking the authenticated
    /// persistence and admitted local-governor anchors.
    ///
    /// [`Self::new`] and [`Self::default`] deliberately fail here. Production
    /// authority is available only from a policy returned by signed initialize,
    /// open, or explicit offline reinitialization.
    pub fn authority(self: &Arc<Self>) -> Result<GovernanceAuthority, GovernanceAuthorityError> {
        let persistence = self
            .persistence
            .as_ref()
            .ok_or(GovernanceAuthorityError::Unpersisted)?;
        persistence.verify_lock_path()?;
        persistence.verify_cleanup_pool_context()?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(reason) = self.ensure_checkpoint_repaired_locked(&mut state) {
            return Err(GovernanceAuthorityError::Persistence(
                GovernancePersistenceError::Write {
                    path: persistence.path.clone(),
                    source: std::io::Error::other(reason),
                },
            ));
        }
        if let Some(reason) = Self::pending_health_observation_error(&state) {
            return Err(GovernanceAuthorityError::PendingHealthObservation { reason });
        }
        let local = state
            .local_governor
            .as_ref()
            .ok_or(GovernanceAuthorityError::MissingLocalGovernor)?;
        let governing_agent_id = state
            .governing_agent_id
            .as_ref()
            .ok_or(GovernanceAuthorityError::MissingLocalGovernor)?;
        if state.persistence_sequence.is_none() || state.persistence_digest.is_none() {
            return Err(GovernanceAuthorityError::MissingSignedAnchor);
        }
        if state.display_governors.get(governing_agent_id) != Some(local.consensus_agent_id())
            || local.consensus_agent_id() != &persistence.expected_signer_agent_id
        {
            return Err(GovernanceAuthorityError::InvalidIdentityBinding);
        }
        drop(state);
        persistence.verify_lock_path()?;
        Ok(GovernanceAuthority {
            policy: Arc::clone(self),
        })
    }

    /// Replace the consensus transport. See [`GovernancePolicy::transport`].
    #[must_use]
    pub fn with_transport(mut self, transport: Arc<dyn ConsensusTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_persistence(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<Self, GovernancePersistenceError> {
        let local_governor = LocalGovernorKey::new(signing_key);
        let persistence = GovernancePersistence::new(
            path.as_ref().to_path_buf(),
            local_governor.consensus_agent_id().clone(),
            GovernanceLockOpenMode::Existing,
        )?;
        Self::with_locked_persistence(config, persistence, governing_agent_id, local_governor)
    }

    /// Acquire the external quiescence guard required before cleanup-pool
    /// maintenance.  The guard is intentionally separate from a live policy;
    /// callers must acquire it before opening the state lock.
    pub fn acquire_cleanup_pool_maintenance_guard(
        path: impl AsRef<Path>,
    ) -> Result<GovernanceCleanupPoolMaintenanceGuard, GovernancePersistenceError> {
        acquire_governance_cleanup_pool_maintenance_guard(path)
    }

    /// Acquire the opaque pre-construction retention capability.  The caller
    /// must hold its external path-selection lock and drop this guard before
    /// invoking `initialize_persistence` or another policy constructor.
    pub fn acquire_cleanup_pool_retention_guard(
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signer_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<GovernanceCleanupPoolRetentionGuard, GovernancePersistenceError> {
        acquire_governance_cleanup_pool_retention_guard(
            path,
            governing_agent_id,
            signer_agent_id,
            signing_key,
        )
    }

    /// Drain terminal cleanup slots into a caller-selected same-parent archive
    /// directory.  The caller must supply the guard acquired before the state
    /// lock; all maintenance locks are nonblocking and fail closed.
    pub fn drain_cleanup_pool(
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
        guard: GovernanceCleanupPoolMaintenanceGuard,
        archive_name: impl AsRef<str>,
    ) -> Result<GovernanceCleanupPoolMaintenanceReport, GovernancePersistenceError> {
        run_cleanup_pool_maintenance(
            path.as_ref().to_path_buf(),
            governing_agent_id,
            signing_key,
            guard,
            GovernanceCleanupPoolMaintenanceMode::Drain,
            archive_name.as_ref(),
        )
    }

    /// Reset the fixed cleanup pool.  Every occupied slot is moved opaquely,
    /// including malformed/uncertain contents; no slot bytes are interpreted
    /// as authority during reset.
    pub fn reset_cleanup_pool(
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
        guard: GovernanceCleanupPoolMaintenanceGuard,
        archive_name: impl AsRef<str>,
    ) -> Result<GovernanceCleanupPoolMaintenanceReport, GovernancePersistenceError> {
        run_cleanup_pool_maintenance(
            path.as_ref().to_path_buf(),
            governing_agent_id,
            signing_key,
            guard,
            GovernanceCleanupPoolMaintenanceMode::Reset,
            archive_name.as_ref(),
        )
    }

    /// Retain one caller-verified artifact in the authenticated fixed pool
    /// during ordinary operation.  The artifact must live beside this policy's
    /// state stream, and the expectation must contain the exact no-follow
    /// device/inode and content digest/length observed by the caller.  The
    /// already-held policy namespace is used; this method never creates or
    /// reopens a cleanup pool by pathname.
    pub fn retain_cleanup_artifact(
        &self,
        path: impl AsRef<Path>,
        expected: GovernanceCleanupArtifactExpectation,
    ) -> Result<GovernanceCleanupPoolRetentionOutcome, GovernancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let persistence = self.persistence.as_ref().ok_or_else(|| {
            GovernancePersistenceError::CleanupPoolNamespaceChanged {
                path: path.clone(),
                reason: "normal cleanup retention requires an authenticated persisted policy"
                    .to_string(),
            }
        })?;
        persistence.verify_lock_path()?;
        persistence.preflight_cleanup_pool_namespace()?;
        persistence.verify_cleanup_pool_context()?;
        let expected_parent = persistence
            .path
            .parent()
            .unwrap_or(&persistence.path)
            .to_path_buf();
        if path.parent().map(Path::to_path_buf).as_ref() != Some(&expected_parent) {
            return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
                path,
                reason:
                    "normal cleanup retention target is outside the authenticated stream parent"
                        .to_string(),
            });
        }
        let parent = AuthorityCleanupParent {
            file: persistence.parent_directory.try_clone().map_err(|source| {
                cleanup_pool_error(
                    &path,
                    format!("could not clone authenticated cleanup parent: {source}"),
                )
            })?,
            identity: persistence.parent_directory_identity,
        };
        let context_guard = persistence
            .cleanup_pool_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let context = context_guard.as_ref().ok_or_else(|| {
            GovernancePersistenceError::CleanupPoolNamespaceChanged {
                path: path.clone(),
                reason: "authenticated cleanup-pool context is absent".to_string(),
            }
        })?;
        if !context.signed {
            return Err(GovernancePersistenceError::CleanupPoolNamespaceChanged {
                path,
                reason: "normal cleanup retention requires a signed cleanup-pool binding"
                    .to_string(),
            });
        }
        retain_cleanup_artifact_in_bound_pool(&path, &expected, &parent, context)
    }

    fn with_locked_persistence(
        config: GovernancePolicyConfig,
        persistence: GovernancePersistence,
        governing_agent_id: AgentId,
        local_governor: LocalGovernorKey,
    ) -> Result<Self, GovernancePersistenceError> {
        persistence.verify_lock_path()?;
        // Keep the historical decode/error ordering for an ordinary stream,
        // but allow a transaction-recovery restart to authenticate the fixed
        // cleanup namespace before it can mutate rollback material.  A crash
        // after source quarantine can leave the canonical state absent; a
        // crash during anchor publication can leave it temporarily
        // undecodable.  The authenticated journal candidate is the only
        // reason to proceed past either result.
        let journal_path = reinitialization_journal_path(&persistence.path);
        let journal_present = fs::symlink_metadata(&journal_path).is_ok();
        if let Err(error) = persistence.load_internal(&local_governor, false)
            && !journal_present
        {
            return Err(error);
        }
        persistence.preflight_cleanup_pool_namespace()?;
        persistence.recover_reinitialization_transaction(&local_governor.signing_key)?;
        persistence.ensure_cleanup_pool_context(&local_governor.signing_key, false)?;
        let loaded = persistence.load(&local_governor)?;
        let persisted = loaded.payload;
        let consensus_agent_id = local_governor.consensus_agent_id().clone();
        if persisted.governing_agent_id.as_ref() != Some(&governing_agent_id)
            || persisted.display_governors.get(&governing_agent_id) != Some(&consensus_agent_id)
        {
            return Err(GovernancePersistenceError::InvalidIdentityBinding {
                reason: format!(
                    "persisted governor `{}` is not bound to admitted local signer `{}`",
                    governing_agent_id, consensus_agent_id
                ),
            });
        }
        let mut state = GovernanceState {
            governing_agent_id: Some(governing_agent_id.clone()),
            display_governors: persisted.display_governors,
            peer_governors: persisted.peer_governors,
            unhealthy_agents: persisted.unhealthy_agents,
            previous_commit_hash: persisted.previous_commit_hash,
            receipt_counter: persisted.receipt_counter,
            partition_state: persisted.partition_state,
            partition_started_at_ms: persisted.partition_started_at_ms,
            last_transition_at_ms: persisted.last_transition_at_ms,
            last_healthy_governors: persisted.last_healthy_governors,
            last_quorum_threshold: persisted.last_quorum_threshold,
            active_contingency_leases: persisted.active_contingency_leases,
            pending_authorizations: persisted.pending_authorizations,
            consumed_authorizations: persisted.consumed_authorizations,
            pending_human_authorizations: persisted.pending_human_authorizations,
            partition_activity: persisted.partition_activity,
            reconciliation_reports: persisted.reconciliation_reports,
            pending_health_observation: persisted.pending_health_observation.clone(),
            durable_pending_health_observation: persisted.pending_health_observation,
            persistence_sequence: Some(loaded.sequence),
            persistence_digest: Some(loaded.digest),
            ..Default::default()
        };
        state.peer_governors.remove(&consensus_agent_id);
        state.local_governor = Some(local_governor);
        retain_current_committee_contingency_leases(&mut state);
        prune_authorization_ledgers(&mut state, now_ms());
        Ok(Self {
            state: Mutex::new(state),
            config,
            persistence: Some(persistence),
            transport: Arc::new(SoloGovernorTransport::new()),
        })
    }

    /// Initialize a brand-new governance stream for a newly admitted Tom identity.
    ///
    /// Ordinary [`GovernancePolicy::with_persistence`] never creates missing state.
    /// The daemon may call this only when it atomically created the Tom/primary key in
    /// the same bootstrap. Registry admission is mutable and cannot authorize clean
    /// initialization. A loaded key with deleted state must fail startup instead.
    pub fn initialize_persistence(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<Self, GovernancePersistenceError> {
        let local_governor = LocalGovernorKey::new(signing_key);
        let persistence = GovernancePersistence::new(
            path.as_ref().to_path_buf(),
            local_governor.consensus_agent_id().clone(),
            GovernanceLockOpenMode::Initialize,
        )?;
        Self::initialize_with_persistence(config, persistence, governing_agent_id, local_governor)
    }

    /// Initialize through a selector-held, verified current/legacy authority
    /// pair. The guard is consumed by construction; governance never
    /// reacquires the sidecar by pathname, so the selector can prove that this
    /// invocation owns the exact pair it preflighted.
    pub fn initialize_persistence_with_authority_pair_guard(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
        guard: GovernanceAuthorityPairGuard,
    ) -> Result<Self, GovernancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let local_governor = LocalGovernorKey::new(signing_key);
        let persistence = GovernancePersistence::new_with_authority_pair_guard(
            path,
            local_governor.consensus_agent_id().clone(),
            GovernanceLockOpenMode::Initialize,
            guard,
        )?;
        Self::initialize_with_persistence(config, persistence, governing_agent_id, local_governor)
    }

    fn initialize_with_persistence(
        config: GovernancePolicyConfig,
        persistence: GovernancePersistence,
        governing_agent_id: AgentId,
        local_governor: LocalGovernorKey,
    ) -> Result<Self, GovernancePersistenceError> {
        persistence.recover_reinitialization_transaction(&local_governor.signing_key)?;
        persistence.ensure_cleanup_pool_context(&local_governor.signing_key, true)?;
        let mut display_governors = BTreeMap::new();
        display_governors.insert(
            governing_agent_id.clone(),
            local_governor.consensus_agent_id().clone(),
        );
        let mut state = GovernanceState {
            governing_agent_id: Some(governing_agent_id),
            display_governors,
            local_governor: Some(local_governor),
            ..GovernanceState::default()
        };
        let version = persistence.initialize(&state)?;
        state.persistence_sequence = Some(version.sequence);
        state.persistence_digest = Some(version.digest);
        Ok(Self {
            state: Mutex::new(state),
            config,
            persistence: Some(persistence),
            transport: Arc::new(SoloGovernorTransport::new()),
        })
    }

    /// Explicit OFFLINE migration for a signed governance stream that predates
    /// permanent lock binding, or for a verified state-preserving PVC restore.
    ///
    /// The caller must derive `signing_key` and `governing_agent_id` from the
    /// already-admitted local Tom/primary identity and must prove all daemon
    /// processes are stopped. This method authenticates both existing anchors
    /// before it may create a lock, acquires the new permanent lock, re-reads
    /// the unchanged anchors under that lock, and advances the state/checkpoint
    /// sequence while changing no state payload member except `lock_binding`.
    /// Ordinary startup deliberately never invokes this path.
    pub fn migrate_persistence_lock(
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<GovernanceLockMigrationReport, GovernancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let expected_signer_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let authority_lock_path = governance_authority_lock_path(&path);
        let (authority_lock_file, authority_lock_identity, authority_lock_created) =
            open_governance_authority_lock(&authority_lock_path, true)?;
        let before_lock = match verify_governance_migration_anchors(
            &path,
            &governing_agent_id,
            &expected_signer_agent_id,
        ) {
            Ok(before_lock) => before_lock,
            Err(error) => {
                if authority_lock_created {
                    let cleanup = remove_new_authority_lock_if_owned(
                        &authority_lock_path,
                        authority_lock_file,
                        authority_lock_identity,
                    );
                    return Err(compose_operation_cleanup_failure(
                        &authority_lock_path,
                        error,
                        cleanup.err().into_iter().collect(),
                    ));
                } else {
                    drop(authority_lock_file);
                }
                return Err(error);
            }
        };
        let authority_cleanup_handle = if authority_lock_created {
            authority_lock_file.try_clone().ok()
        } else {
            None
        };
        let persistence = match GovernancePersistence::new_with_authority_lock(
            path.clone(),
            expected_signer_agent_id,
            GovernanceLockOpenMode::Migrate,
            Some((
                authority_lock_path.clone(),
                authority_lock_file,
                authority_lock_identity,
                authority_lock_created,
            )),
        ) {
            Ok(persistence) => {
                drop(authority_cleanup_handle);
                persistence
            }
            Err(error) => {
                let mut cleanup_errors = Vec::new();
                if let Some(cleanup_handle) = authority_cleanup_handle {
                    if let Err(cleanup_error) = remove_new_authority_lock_if_owned(
                        &authority_lock_path,
                        cleanup_handle,
                        authority_lock_identity,
                    ) {
                        cleanup_errors.push(cleanup_error);
                    }
                } else if authority_lock_created
                    && let Err(cleanup_error) = remove_authority_lock_if_identity(
                        &authority_lock_path,
                        authority_lock_identity,
                    )
                {
                    cleanup_errors.push(cleanup_error);
                }
                return Err(compose_operation_cleanup_failure(
                    &authority_lock_path,
                    error,
                    cleanup_errors,
                ));
            }
        };
        persistence.recover_reinitialization_transaction(&signing_key)?;
        persistence.ensure_cleanup_pool_context(&signing_key, true)?;
        persistence.migrate_lock_binding(&governing_agent_id, &signing_key, &before_lock)
    }

    /// Explicit offline recovery for unsigned, corrupt, or intentionally discarded
    /// governance persistence. Existing files are archived and NONE of their peers,
    /// leases, pending/consumed authorizations, human holds, or chain position is
    /// copied into the new stream.
    pub fn reinitialize_persistence(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<Self, GovernancePersistenceError> {
        let path = path.as_ref().to_path_buf();
        let suffix = format!("discarded-{}-{}", now_ms(), std::process::id());
        Self::reinitialize_persistence_with_suffix(
            config,
            path,
            governing_agent_id,
            signing_key,
            &suffix,
            None,
        )
    }

    /// Explicit offline reinitialization through a selector-held authority
    /// pair. The guard transfer is identity-bound and construction does not
    /// reacquire either sidecar pathname.
    pub fn reinitialize_persistence_with_authority_pair_guard(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
        suffix: impl AsRef<str>,
        guard: GovernanceAuthorityPairGuard,
    ) -> Result<Self, GovernancePersistenceError> {
        Self::reinitialize_persistence_with_suffix(
            config,
            path.as_ref().to_path_buf(),
            governing_agent_id,
            signing_key,
            suffix.as_ref(),
            Some(guard),
        )
    }

    fn reinitialize_persistence_with_suffix(
        config: GovernancePolicyConfig,
        path: PathBuf,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
        suffix: &str,
        authority_guard: Option<GovernanceAuthorityPairGuard>,
    ) -> Result<Self, GovernancePersistenceError> {
        if !valid_reinitialization_suffix(suffix) {
            return Err(GovernancePersistenceError::ReinitializationFailed {
                reason: format!("invalid reinitialization suffix `{suffix}`"),
            });
        }
        let local_governor = LocalGovernorKey::new(signing_key);
        let persistence = if let Some(guard) = authority_guard {
            GovernancePersistence::new_with_authority_pair_guard(
                path.clone(),
                local_governor.consensus_agent_id().clone(),
                GovernanceLockOpenMode::Reinitialize,
                guard,
            )?
        } else {
            GovernancePersistence::new(
                path.clone(),
                local_governor.consensus_agent_id().clone(),
                GovernanceLockOpenMode::Reinitialize,
            )?
        };
        persistence.recover_reinitialization_transaction(&local_governor.signing_key)?;
        let cleanup_parent = held_persistence_parent(&persistence)?;
        let sequence_path = path.with_extension("sequence.json");
        let mut plan: Vec<ReinitializationArtifact> = Vec::new();
        for existing in [&path, &sequence_path] {
            let name = existing.file_name().ok_or_else(|| {
                GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "stream artifact `{}` has no final component",
                        existing.display()
                    ),
                }
            })?;
            let Some((snapshot, _bytes)) =
                read_governance_artifact_snapshot_at(&cleanup_parent.file, name).map_err(
                    |source| GovernancePersistenceError::ReinitializationFailed {
                        reason: format!("could not snapshot `{}`: {source}", existing.display()),
                    },
                )?
            else {
                continue;
            };
            let archive = reinitialization_archive_path(existing, suffix);
            let archive_name = archive.file_name().ok_or_else(|| {
                GovernancePersistenceError::ReinitializationFailed {
                    reason: format!("archive `{}` has no final component", archive.display()),
                }
            })?;
            match directory_entry_identity_at(&cleanup_parent.file, archive_name) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Err(GovernancePersistenceError::ReinitializationFailed {
                        reason: format!(
                            "reinitialization archive destination already exists: `{}`",
                            archive.display()
                        ),
                    });
                }
                Err(source) => {
                    return Err(GovernancePersistenceError::ReinitializationFailed {
                        reason: format!(
                            "could not inspect archive `{}`: {source}",
                            archive.display()
                        ),
                    });
                }
            }
            plan.push(ReinitializationArtifact {
                original: existing.to_path_buf(),
                archive,
                identity: snapshot.identity,
                content_digest: snapshot.content_digest,
                byte_len: snapshot.byte_len,
                archive_identity: None,
                restored_identity: None,
            });
        }
        // Validate every source and every archive destination once more under
        // the held locks before the first mutation.  The archive is copied
        // with create-new/no-follow semantics below, so a foreign candidate
        // created after this check cannot be overwritten.
        persistence.verify_lock_path()?;
        for artifact in &plan {
            let original_name = artifact.original.file_name().ok_or_else(|| {
                GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "reinitialization source `{}` has no final component",
                        artifact.original.display()
                    ),
                }
            })?;
            let archive_name = artifact.archive.file_name().ok_or_else(|| {
                GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "reinitialization archive `{}` has no final component",
                        artifact.archive.display()
                    ),
                }
            })?;
            let Some((snapshot, _bytes)) =
                read_governance_artifact_snapshot_at(&cleanup_parent.file, original_name).map_err(
                    |source| GovernancePersistenceError::ReinitializationFailed {
                        reason: format!(
                            "could not recheck `{}`: {source}",
                            artifact.original.display()
                        ),
                    },
                )?
            else {
                return Err(GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "reinitialization source disappeared: `{}`",
                        artifact.original.display()
                    ),
                });
            };
            if snapshot.identity != artifact.identity
                || snapshot.content_digest != artifact.content_digest
                || snapshot.byte_len != artifact.byte_len
            {
                return Err(GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "reinitialization source changed before mutation: `{}`",
                        artifact.original.display()
                    ),
                });
            }
            match directory_entry_identity_at(&cleanup_parent.file, archive_name) {
                Ok(Some(_)) => {
                    return Err(GovernancePersistenceError::ReinitializationFailed {
                        reason: format!(
                            "reinitialization archive destination appeared before mutation: `{}`",
                            artifact.archive.display()
                        ),
                    });
                }
                Ok(None) => {}
                Err(source) => {
                    return Err(GovernancePersistenceError::ReinitializationFailed {
                        reason: format!(
                            "could not recheck archive destination `{}`: {source}",
                            artifact.archive.display()
                        ),
                    });
                }
            }
        }

        let mut journal = if plan.is_empty() {
            None
        } else {
            let journal = ReinitializationRollbackJournal {
                schema_version: REINITIALIZATION_JOURNAL_SCHEMA_VERSION,
                transaction_id: format!("{suffix}-{}-{}", now_ms(), std::process::id()),
                archive_suffix: suffix.to_string(),
                state_path: path.clone(),
                sequence_path: sequence_path.clone(),
                artifacts: plan.clone(),
                new_stream_artifacts: Vec::new(),
                phase: ReinitializationJournalPhase::Prepared,
            };
            write_reinitialization_journal_at(
                &path,
                &journal,
                &local_governor.signing_key,
                &cleanup_parent,
            )?;
            Some(journal)
        };
        let archive_result = if let Some(journal) = journal.as_mut() {
            (|| -> Result<(), GovernancePersistenceError> {
                // Create every archive first. No source is removed until the
                // complete state+sequence peer set has a durable rollback
                // journal and every archive identity has been verified.
                for index in 0..journal.artifacts.len() {
                    let artifact = journal.artifacts[index].clone();
                    persistence.verify_lock_path()?;
                    let original_name = artifact.original.file_name().ok_or_else(|| {
                        GovernancePersistenceError::Write {
                            path: artifact.original.clone(),
                            source: std::io::Error::other(
                                "reinitialization source has no final component",
                            ),
                        }
                    })?;
                    let archive_name = artifact.archive.file_name().ok_or_else(|| {
                        GovernancePersistenceError::Write {
                            path: artifact.archive.clone(),
                            source: std::io::Error::other(
                                "reinitialization archive has no final component",
                            ),
                        }
                    })?;
                    let Some((snapshot, bytes)) =
                        read_governance_artifact_snapshot_at(&cleanup_parent.file, original_name)
                            .map_err(|source| GovernancePersistenceError::Write {
                            path: artifact.original.clone(),
                            source,
                        })?
                    else {
                        return Err(GovernancePersistenceError::Write {
                            path: artifact.original.clone(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "reinitialization source disappeared before archive",
                            ),
                        });
                    };
                    if snapshot.identity != artifact.identity
                        || snapshot.content_digest != artifact.content_digest
                        || snapshot.byte_len != artifact.byte_len
                    {
                        return Err(GovernancePersistenceError::Write {
                            path: artifact.original.clone(),
                            source: std::io::Error::other(
                                "reinitialization source snapshot changed before archive",
                            ),
                        });
                    }
                    match directory_entry_identity_at(&cleanup_parent.file, archive_name) {
                        Ok(Some(_)) => {
                            return Err(GovernancePersistenceError::Write {
                                path: artifact.archive.clone(),
                                source: std::io::Error::new(
                                    std::io::ErrorKind::AlreadyExists,
                                    "reinitialization archive destination appeared before no-replace link",
                                ),
                            });
                        }
                        Ok(None) => {}
                        Err(source) => {
                            return Err(GovernancePersistenceError::Write {
                                path: artifact.archive.clone(),
                                source,
                            });
                        }
                    }
                    #[cfg(test)]
                    pause_after_reinitialization_archive_check(
                        &artifact.original,
                        &artifact.archive,
                    );
                    let archive_identity =
                        write_reinitialization_archive_at(&artifact, &bytes, &cleanup_parent)?;
                    journal.artifacts[index].archive_identity = Some(archive_identity);
                }
                journal.phase = ReinitializationJournalPhase::ArchivesCreated;
                write_reinitialization_journal_at(
                    &path,
                    journal,
                    &local_governor.signing_key,
                    &cleanup_parent,
                )?;
                #[cfg(test)]
                maybe_inject_reinitialization_crash(
                    &path,
                    InjectedReinitializationCrashPoint::ArchiveCreated,
                );

                // Only after both peers are archived may either canonical
                // source entry be quarantined. The archives remain until the
                // new state and checkpoint commit is durable.
                for artifact in &journal.artifacts {
                    let cleanup_outcome = quarantine_verified_entry_at(
                        &artifact.original,
                        &cleanup_parent,
                        || {
                            persistence.verify_lock_path().is_ok()
                                && authority_cleanup_parent_is_current(
                                    &artifact.original,
                                    &cleanup_parent,
                                )
                                && reinitialization_artifact_matches_at(
                                    &cleanup_parent,
                                    &artifact.original,
                                    artifact,
                                )
                        },
                        |quarantine| {
                            persistence.verify_lock_path().is_ok()
                                && authority_cleanup_parent_is_current(
                                    &artifact.original,
                                    &cleanup_parent,
                                )
                                && reinitialization_artifact_matches_at(
                                    &cleanup_parent,
                                    quarantine,
                                    artifact,
                                )
                        },
                    );
                    if !cleanup_outcome.is_semantic_success() {
                        return Err(cleanup_error_for_outcome(
                            &artifact.original,
                            cleanup_outcome,
                        ));
                    }
                }
                #[cfg(test)]
                maybe_inject_reinitialization_crash(
                    &path,
                    InjectedReinitializationCrashPoint::OriginalsQuarantined,
                );
                cleanup_parent.file.sync_all().map_err(|source| {
                    GovernancePersistenceError::Write {
                        path: path.parent().unwrap_or(&path).to_path_buf(),
                        source,
                    }
                })?;
                journal.phase = ReinitializationJournalPhase::OriginalsRemoved;
                write_reinitialization_journal_at(
                    &path,
                    journal,
                    &local_governor.signing_key,
                    &cleanup_parent,
                )?;
                persistence.verify_lock_path()?;
                Ok(())
            })()
        } else {
            Ok(())
        };
        if let Err(error) = archive_result {
            if let Some(journal) = journal.as_mut() {
                let rollback = rollback_reinitialization_transaction(
                    &persistence,
                    journal,
                    &local_governor.signing_key,
                );
                return Err(GovernancePersistenceError::ReinitializationFailed {
                    reason: match rollback {
                        Ok(()) => format!("could not archive prior governance stream: {error}"),
                        Err(rollback_error) => format!(
                            "could not archive prior governance stream: {error}; archive rollback also failed: {rollback_error}"
                        ),
                    },
                });
            }
            return Err(GovernancePersistenceError::ReinitializationFailed {
                reason: format!("could not initialize an empty governance stream: {error}"),
            });
        }
        let mut display_governors = BTreeMap::new();
        display_governors.insert(
            governing_agent_id.clone(),
            local_governor.consensus_agent_id().clone(),
        );
        let mut state = GovernanceState {
            governing_agent_id: Some(governing_agent_id),
            display_governors,
            local_governor: Some(local_governor),
            ..GovernanceState::default()
        };
        let local_signing_key = state
            .local_governor
            .as_ref()
            .map(|local| &local.signing_key)
            .ok_or(GovernancePersistenceError::MissingLocalSigner)?;
        if journal.is_some() {
            persistence.arm_reinitialization_journal(local_signing_key);
        }
        match persistence.initialize(&state) {
            Ok(version) => {
                state.persistence_sequence = Some(version.sequence);
                state.persistence_digest = Some(version.digest);
                if let Some(journal) = journal.as_mut() {
                    if let Some((durable, _, _)) =
                        read_reinitialization_journal(&path, &persistence.expected_signer_agent_id)?
                    {
                        journal.new_stream_artifacts = durable.new_stream_artifacts;
                    }
                    journal.phase = ReinitializationJournalPhase::NewStreamCommitted;
                    #[cfg(test)]
                    maybe_inject_reinitialization_commit_journal_failure(&path);
                    #[cfg(test)]
                    maybe_inject_reinitialization_crash(
                        &path,
                        InjectedReinitializationCrashPoint::BeforeCommitJournal,
                    );
                    if let Err(commit_error) = write_reinitialization_journal_at(
                        &path,
                        journal,
                        local_signing_key,
                        &cleanup_parent,
                    ) {
                        persistence.release_cleanup_pool_context();
                        let rollback_error = rollback_reinitialization_transaction(
                            &persistence,
                            journal,
                            local_signing_key,
                        )
                        .err();
                        persistence.disarm_reinitialization_journal();
                        return Err(GovernancePersistenceError::ReinitializationFailed {
                            reason: format!(
                                "new signed stream commit journal failed: {commit_error}{}",
                                rollback_error
                                    .map(|rollback_error| format!(
                                        "; transactional rollback failed: {rollback_error}"
                                    ))
                                    .unwrap_or_default()
                            ),
                        });
                    }
                    // Once the committed phase is durable, archive cleanup is
                    // a resumable post-commit operation.  Keep the journal if
                    // it fails so the next opener can retry without rolling
                    // back a valid new stream.
                    persistence.release_cleanup_pool_context();
                    let finalized = finalize_reinitialization_transaction(
                        &persistence,
                        journal,
                        local_signing_key,
                    );
                    persistence.disarm_reinitialization_journal();
                    finalized?;
                    persistence.ensure_cleanup_pool_context(local_signing_key, true)?;
                }
                Ok(Self {
                    state: Mutex::new(state),
                    config,
                    persistence: Some(persistence),
                    transport: Arc::new(SoloGovernorTransport::new()),
                })
            }
            Err(error) => {
                let rollback_error = if let Some(journal) = journal.as_mut() {
                    if let Some((durable, _, _)) =
                        read_reinitialization_journal(&path, &persistence.expected_signer_agent_id)?
                    {
                        journal.new_stream_artifacts = durable.new_stream_artifacts;
                    }
                    let journal_write_error = write_reinitialization_journal_at(
                        &path,
                        journal,
                        local_signing_key,
                        &cleanup_parent,
                    )
                    .err();
                    persistence.release_cleanup_pool_context();
                    let rollback_error = rollback_reinitialization_transaction(
                        &persistence,
                        journal,
                        local_signing_key,
                    )
                    .err();
                    persistence.disarm_reinitialization_journal();
                    journal_write_error.or(rollback_error)
                } else {
                    remove_governance_stream_files(
                        &persistence,
                        &persistence.new_stream_artifacts(),
                    )
                    .err()
                };
                Err(GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "new signed stream initialization failed: {error}{}",
                        rollback_error
                            .map(|rollback_error| format!(
                                "; transactional rollback failed: {rollback_error}"
                            ))
                            .unwrap_or_default()
                    ),
                })
            }
        }
    }

    pub fn persistence_sequence_path(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().with_extension("sequence.json")
    }

    pub fn persistence_lock_path(path: impl AsRef<Path>) -> PathBuf {
        path.as_ref().with_extension("lock")
    }

    /// Canonical process-lifetime authority sidecar path used by every
    /// persisted policy initializer and loader.
    pub fn persistence_authority_lock_path(path: impl AsRef<Path>) -> PathBuf {
        governance_authority_lock_path(path)
    }

    /// Return the regular-file identity of the canonical authority sidecar.
    /// Path-selection code can compare identities for current and legacy state
    /// paths and require a hard-link pair before selecting either stream.
    pub fn persistence_authority_lock_identity(
        path: impl AsRef<Path>,
    ) -> Result<GovernanceAuthorityLockIdentity, GovernancePersistenceError> {
        governance_authority_lock_identity(path)
    }

    /// Validate the canonical authority sidecars for two logical state paths.
    pub fn persistence_authority_lock_pair_identity(
        first_path: impl AsRef<Path>,
        second_path: impl AsRef<Path>,
    ) -> Result<GovernanceAuthorityLockIdentity, GovernancePersistenceError> {
        governance_authority_lock_pair_identity(first_path, second_path)
    }

    /// Install THE local governor signing key.
    ///
    /// Idempotent for the same key. A second, DIFFERENT key is refused: holding
    /// two means this process could cast two committee members' votes, which is
    /// exactly the property BFT-03 removes.
    pub fn register_governor(
        &self,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<(), GovernanceKeyError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let offered = LocalGovernorKey::new(signing_key);
        if let Some(existing) = state.local_governor.as_ref()
            && existing.verifying_key() != offered.verifying_key()
        {
            return Err(GovernanceKeyError::SecondSigningKey {
                existing: existing.consensus_agent_id().clone(),
                offered: offered.consensus_agent_id().clone(),
            });
        }
        if let Err(reason) = self.ensure_authority_ready_locked(&mut state) {
            return Err(GovernanceKeyError::Persistence { reason });
        }
        if state.local_governor.is_some()
            && state.governing_agent_id.as_ref() == Some(&governing_agent_id)
        {
            return Ok(());
        }
        let previous_governing_agent_id = state.governing_agent_id.clone();
        let previous_display_governors = state.display_governors.clone();
        let previous_peers = state.peer_governors.clone();
        let previous_committee = state.committee_member_ids();
        let previous_leases = state.active_contingency_leases.clone();
        let had_local_governor = state.local_governor.is_some();
        state
            .governing_agent_id
            .get_or_insert(governing_agent_id.clone());
        let consensus_agent_id = offered.consensus_agent_id().clone();
        state
            .display_governors
            .insert(governing_agent_id, consensus_agent_id.clone());
        state.peer_governors.remove(&consensus_agent_id);
        if !had_local_governor {
            state.local_governor = Some(offered);
        }
        if state.committee_member_ids() != previous_committee {
            state.active_contingency_leases.clear();
        }
        match self.persist_locked(&mut state) {
            Err(reason) => {
                state.governing_agent_id = previous_governing_agent_id;
                state.display_governors = previous_display_governors;
                state.peer_governors = previous_peers;
                state.active_contingency_leases = previous_leases;
                if !had_local_governor {
                    state.local_governor = None;
                }
                return Err(GovernanceKeyError::Persistence { reason });
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => tracing::warn!(
                sequence,
                reason = %reason,
                module = module_path!(),
                "governor registration committed while its checkpoint remains lagging"
            ),
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(())
    }

    /// Admit a peer governor by identity alone.
    ///
    /// This is how a committee grows past one member without this process
    /// acquiring a second key. It exists so the multi-member path is
    /// EXPRESSIBLE and therefore testable: with a peer admitted, `can_act`
    /// builds a committee of two, the shipped `SoloGovernorTransport` refuses
    /// it, and the decision is a Veto naming the missing networked transport
    /// rather than a receipt minted from keys this process should not have.
    pub fn register_peer_governor(&self, peer: &VerifyingKey) -> Result<(), String> {
        let consensus_agent_id = AgentId::from_verifying_key(peer);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_authority_ready_locked(&mut state)?;
        if state
            .local_governor
            .as_ref()
            .is_some_and(|local| local.consensus_agent_id() == &consensus_agent_id)
        {
            return Ok(());
        }
        if state.local_governor.is_none() {
            return Err("peer governor cannot be admitted without the local Tom key".to_string());
        }
        if !state.peer_governors.insert(consensus_agent_id.clone()) {
            return Ok(());
        }
        let previous_leases = std::mem::take(&mut state.active_contingency_leases);
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.peer_governors.remove(&consensus_agent_id);
                state.active_contingency_leases = previous_leases;
                return Err(format!(
                    "peer governor was not admitted because persistence failed: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => tracing::warn!(
                sequence,
                reason = %reason,
                module = module_path!(),
                "peer governor admission committed while its checkpoint remains lagging"
            ),
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(())
    }

    pub fn observe_health(
        &self,
        governing_agent_id: &AgentId,
        entries: &[AgentHealthEntry],
        observed_at_ms: i64,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let checkpoint_lagging_before_health = state.checkpoint_lagging.is_some();
        self.repair_checkpoint_from_health_tick_locked(&mut state, observed_at_ms);
        let pending_observation = PendingHealthObservation {
            governing_agent_id: governing_agent_id.clone(),
            entries: entries.to_vec(),
            observed_at_ms,
        };
        let mut wrote_new_health_intent = false;
        #[cfg(test)]
        let pre_intent_persisted = PersistedGovernanceState::from_runtime(&state);
        if Self::restrictive_health_intent_needed(&state, governing_agent_id, entries)
            && !state
                .durable_pending_health_observation
                .as_ref()
                .is_some_and(|existing| {
                    Self::same_health_observation(existing, &pending_observation)
                })
        {
            if let Err(error) =
                self.persist_pending_health_intent_locked(&mut state, &pending_observation)
            {
                // No restrictive health projection may become authoritative
                // until its write-ahead intent is authenticated and synced.
                // Retain only the in-memory veto when the filesystem itself
                // is unavailable; the next tick retries the intent.
                state.pending_health_observation = Some(pending_observation);
                tracing::warn!(
                    reason = %error,
                    module = module_path!(),
                    "restrictive governance health observation was retained fail-closed because its write-ahead intent could not be committed"
                );
                return;
            }
            wrote_new_health_intent = true;
        }
        #[cfg(test)]
        if pre_intent_persisted != PersistedGovernanceState::from_runtime(&state) {
            maybe_inject_health_crash(
                self.persistence
                    .as_ref()
                    .map(|persistence| persistence.path.as_path())
                    .unwrap_or_else(|| Path::new("<memory>")),
                InjectedHealthCrashPoint::Intent,
            );
        }
        let previous_persisted = PersistedGovernanceState::from_runtime(&state);
        let previous_unhealthy_agents = state.unhealthy_agents.clone();
        let previous_last_healthy_governors = state.last_healthy_governors;
        let previous_last_quorum_threshold = state.last_quorum_threshold;
        let previous_pending_events = state.pending_events.clone();
        let previous_pending_health_observation = state.pending_health_observation.clone();
        if state.governing_agent_id.as_ref() != Some(governing_agent_id) {
            if let Some(previous) = state.governing_agent_id.clone() {
                state.display_governors.remove(&previous);
            }
            if let Some(consensus_agent_id) = state
                .local_governor
                .as_ref()
                .map(|local| local.consensus_agent_id().clone())
            {
                state
                    .display_governors
                    .insert(governing_agent_id.clone(), consensus_agent_id);
            }
        }
        state.governing_agent_id = Some(governing_agent_id.clone());
        state.unhealthy_agents = entries
            .iter()
            .filter(|entry| entry.health != AgentHealth::Healthy)
            .cloned()
            .collect();
        let total_governors = state.display_governors.len().max(state.governor_count());
        let unhealthy_governors = state.unhealthy_governor_ids(entries).len();
        let healthy_governors = total_governors.saturating_sub(unhealthy_governors);
        let quorum_threshold = governance_quorum_threshold(total_governors);
        state.last_healthy_governors = healthy_governors;
        state.last_quorum_threshold = quorum_threshold;

        let base_state = if healthy_governors < quorum_threshold {
            PartitionState::Partitioned
        } else if state.unhealthy_agents.is_empty() {
            PartitionState::Healthy
        } else {
            PartitionState::Degraded
        };
        let previous_state = state.partition_state;
        let next_state = match (previous_state, base_state) {
            (PartitionState::Partitioned, PartitionState::Healthy | PartitionState::Degraded) => {
                let report = self.reconcile_partition_activity_locked(&mut state, observed_at_ms);
                if let Some(governing_agent_id) = state.governing_agent_id.clone() {
                    state.pending_events.push_back(
                        GovernanceRuntimeEvent::PartitionReconciliation {
                            emitted_at_ms: observed_at_ms,
                            governing_agent_id,
                            report,
                        },
                    );
                }
                PartitionState::Healing
            }
            (PartitionState::Healing, settled) => settled,
            (_, settled) => settled,
        };
        if previous_state != next_state {
            if next_state == PartitionState::Partitioned {
                state.partition_started_at_ms = Some(observed_at_ms);
            } else if next_state == PartitionState::Healthy {
                state.partition_started_at_ms = None;
            }
            state.last_transition_at_ms = Some(observed_at_ms);
            if let Some(governing_agent_id) = state.governing_agent_id.clone() {
                state
                    .pending_events
                    .push_back(GovernanceRuntimeEvent::PartitionStateTransition {
                        emitted_at_ms: observed_at_ms,
                        governing_agent_id,
                        from: previous_state,
                        to: next_state,
                        healthy_governors,
                        total_governors,
                        quorum_threshold,
                        reason: partition_transition_reason(next_state).to_string(),
                    });
            }
            state.partition_state = next_state;
        }
        let health_projection_changed = PersistedGovernanceState::from_runtime(&state)
            .without_pending_health_observation()
            != previous_persisted
                .clone()
                .without_pending_health_observation()
            || state.pending_events != previous_pending_events;
        // When a prior checkpoint repair is still in its health-tick backoff,
        // do not let a changed health snapshot reach `save`: `save` repairs a
        // lagging checkpoint before writing the next state envelope. Revert
        // this observation in memory and leave both durable anchors alone.
        // The next observation at the logical deadline will repair first and
        // then persist the current health snapshot. Direct governed effects
        // still call `ensure_checkpoint_repaired_locked` and bypass this gate.
        let checkpoint_repair_deferred = checkpoint_lagging_before_health
            && state.checkpoint_lagging.is_some()
            && state
                .checkpoint_repair_backoff
                .is_some_and(|backoff| !backoff.is_due(observed_at_ms));
        if checkpoint_repair_deferred {
            let pending_observation = PendingHealthObservation {
                governing_agent_id: governing_agent_id.clone(),
                entries: entries.to_vec(),
                observed_at_ms,
            };
            previous_persisted.restore_into(&mut state);
            state.unhealthy_agents = previous_unhealthy_agents;
            state.last_healthy_governors = previous_last_healthy_governors;
            state.last_quorum_threshold = previous_last_quorum_threshold;
            state.pending_events = previous_pending_events;
            if health_projection_changed {
                // Preserve the latest genuinely different projection while
                // the checkpoint retry is deferred. A repeated baseline tick
                // must not overwrite an earlier alternate snapshot merely
                // because its host timestamp changed.
                state.pending_health_observation = Some(pending_observation);
            } else {
                state.pending_health_observation = previous_pending_health_observation;
            }
            return;
        }
        prune_expired_contingency_leases(&mut state, observed_at_ms);
        if state.partition_state == PartitionState::Healthy {
            self.ensure_contingency_leases_locked(&mut state, observed_at_ms);
        }
        // Tom calls this method on every dispatcher tick.  Do not turn an
        // unchanged health snapshot into a signed state rewrite: the state
        // envelope and checkpoint are both fsynced, and every rewrite advances
        // the durable sequence.  Transient pending events are emitted only
        // alongside a durable transition above, so comparing the persisted
        // projection is sufficient here.
        if !wrote_new_health_intent {
            state.pending_health_observation = None;
            state.durable_pending_health_observation = None;
        }
        if PersistedGovernanceState::from_runtime(&state) == previous_persisted {
            return;
        }
        match self.persist_locked(&mut state) {
            Err(error) => {
                let pending_observation = health_projection_changed
                    .then_some(PendingHealthObservation {
                        governing_agent_id: governing_agent_id.clone(),
                        entries: entries.to_vec(),
                        observed_at_ms,
                    })
                    .or_else(|| previous_persisted.pending_health_observation.clone());
                previous_persisted.restore_into(&mut state);
                state.unhealthy_agents = previous_unhealthy_agents;
                state.last_healthy_governors = previous_last_healthy_governors;
                state.last_quorum_threshold = previous_last_quorum_threshold;
                state.pending_events = previous_pending_events;
                state.pending_health_observation = pending_observation.clone();
                let marker_error = pending_observation.as_ref().and_then(|observation| {
                    if state
                        .durable_pending_health_observation
                        .as_ref()
                        .is_some_and(|existing| {
                            Self::same_health_observation(existing, observation)
                        })
                    {
                        None
                    } else {
                        self.persist_pending_health_intent_locked(&mut state, observation)
                            .err()
                    }
                });
                let path = self
                    .persistence
                    .as_ref()
                    .map(|persistence| persistence.path.display().to_string())
                    .unwrap_or_else(|| "<memory>".to_string());
                tracing::warn!(
                    reason = %error,
                    checkpoint_marker_error = ?marker_error,
                    path = %path,
                    module = module_path!(),
                    "discarded an unpersisted governance health transition and contingency leases; retained its write-ahead health veto"
                );
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => {
                state.checkpoint_repair_backoff =
                    Some(GovernanceCheckpointRepairBackoff::after(observed_at_ms));
                tracing::warn!(
                    sequence,
                    reason = %reason,
                    retry_at_ms = state
                        .checkpoint_repair_backoff
                        .map(|backoff| backoff.retry_at_ms),
                    module = module_path!(),
                    "governance health transition committed while its checkpoint remains lagging"
                );
            }
            Ok(GovernancePersistenceOutcome::Committed) => {
                state.pending_health_observation = None;
                state.durable_pending_health_observation = None;
            }
        }
    }

    pub fn can_act(&self, request: &ActionRequest) -> GovernanceDecision {
        if !request.action.requires_governance_receipt() {
            return GovernanceDecision::NotRequired;
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Fail closed with no governor key. Without one this policy cannot issue the
        // receipt that authorizes a destructive action: `issue_governance_receipt`
        // returns `None` on an empty keyring and every downstream arm of this function
        // used to fall through to `Allow`. This check sits AHEAD of the partition
        // branch on purpose - `active_contingency_leases` is rehydrated from disk by
        // `with_persistence` before any governor registers, so the partition branch
        // would otherwise authorize a destructive action off a state file alone.
        if state.local_governor.is_none() {
            return GovernanceDecision::Veto {
                governing_agent_id: state
                    .governing_agent_id
                    .clone()
                    .unwrap_or_else(|| AgentId::new("tom", "unconfigured")),
                reason: "blocked destructive action because no governor signing key is registered"
                    .to_string(),
                receipt: None,
            };
        }
        if let Err(error) = self.ensure_checkpoint_repaired_locked(&mut state) {
            return GovernanceDecision::Veto {
                governing_agent_id: state
                    .governing_agent_id
                    .clone()
                    .unwrap_or_else(|| AgentId::new("tom", "unconfigured")),
                reason: format!(
                    "blocked destructive action until the signed governance checkpoint is repaired: {error}"
                ),
                receipt: None,
            };
        }
        if Self::pending_health_observation(&state).is_some() {
            return GovernanceDecision::Veto {
                governing_agent_id: state
                    .governing_agent_id
                    .clone()
                    .unwrap_or_else(|| AgentId::new("tom", "health-pending")),
                reason:
                    "blocked destructive action until the deferred health observation is persisted"
                        .to_string(),
                receipt: None,
            };
        }
        if state.partition_state == PartitionState::Partitioned {
            if let Some(lease) = preview_matching_contingency_lease(&state, request, now_ms()) {
                return GovernanceDecision::Authorize {
                    receipt: lease.governance_receipt.clone(),
                    contingency_lease: Some(lease),
                };
            }
            return GovernanceDecision::Veto {
                governing_agent_id: state
                    .governing_agent_id
                    .clone()
                    .unwrap_or_else(|| AgentId::new("tom", "partition")),
                reason:
                    "blocked destructive action during partition without active contingency lease"
                        .to_string(),
                receipt: None,
            };
        }
        let unhealthy_agents = state
            .unhealthy_agents
            .iter()
            .map(|entry| format!("{}:{:?}", entry.id, entry.health))
            .collect::<Vec<_>>()
            .join(", ");
        let (decision, reason) = if state.unhealthy_agents.is_empty() {
            (GovernanceReceiptDecision::Approve, None)
        } else {
            (
                GovernanceReceiptDecision::Veto,
                Some(format!(
                    "blocked destructive action while swarm unhealthy: {unhealthy_agents}"
                )),
            )
        };
        let receipt = match self.issue_request_authorization_locked(
            &mut state,
            request,
            decision,
            now_ms(),
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                // Fail closed on a round that did not commit. This is the arm a
                // committee with admitted peer governors and no networked
                // transport lands in: `SoloGovernorTransport` refuses the
                // committee, no receipt exists, and authorizing the action
                // anyway would mean acting on a quorum nobody reached. The
                // consensus error is carried into the reason verbatim so the
                // operator is told "this transport cannot serve a committee of
                // N" rather than a generic denial.
                tracing::warn!(
                    reason = %error,
                    module = module_path!(),
                    "governance round produced no receipt; refusing destructive action"
                );
                return GovernanceDecision::Veto {
                    governing_agent_id: state
                        .governing_agent_id
                        .clone()
                        .unwrap_or_else(|| AgentId::new("tom", "unconfigured")),
                    reason: format!(
                        "blocked destructive action because the governance round produced \
                             no receipt: {error}"
                    ),
                    receipt: None,
                };
            }
        };
        let governing_agent_id = state
            .governing_agent_id
            .clone()
            .unwrap_or_else(|| receipt.payload.issued_by.clone());

        match reason {
            // A missing `governing_agent_id` is a labelling problem, not grounds to
            // permit the action: this used to `return Allow` with the veto reason
            // discarded. A local governor key exists by the guard above, so
            // `register_governor` has run and has already set `governing_agent_id`;
            // the fallback mirrors the partition branch and cannot be reached through
            // the public API.
            Some(reason) => GovernanceDecision::Veto {
                governing_agent_id,
                reason,
                receipt: Some(receipt),
            },
            None => GovernanceDecision::Authorize {
                receipt,
                contingency_lease: None,
            },
        }
    }

    fn issue_request_authorization_locked(
        &self,
        state: &mut GovernanceState,
        request: &ActionRequest,
        decision: GovernanceReceiptDecision,
        issued_at_ms: i64,
    ) -> Result<ConsensusGovernanceReceipt, String> {
        let subject = governance_request_subject_value(request)?;
        let proposal = ConsensusProposal {
            proposal_id: proposal_id_for_payload(&subject).map_err(|error| error.to_string())?,
            payload: subject,
        };
        let previous_commit_hash = state.previous_commit_hash.clone();
        let receipt_counter = state.receipt_counter;
        let previous_pending = state.pending_authorizations.clone();
        let previous_consumed = state.consumed_authorizations.clone();
        let receipt = run_governance_round(
            state,
            self.transport.as_ref(),
            proposal,
            decision,
            issued_at_ms,
        )
        .map_err(|error| error.to_string())?;
        let pending = PendingGovernanceAuthorization {
            receipt_id: receipt.payload.receipt_id.clone(),
            subject_digest: receipt.payload.proposal_id.clone(),
            decision,
            issued_at_ms,
        };
        state.pending_authorizations.push_back(pending);
        prune_authorization_ledgers(state, issued_at_ms);
        match self.persist_locked(state) {
            Err(error) => {
                state.previous_commit_hash = previous_commit_hash;
                state.receipt_counter = receipt_counter;
                state.pending_authorizations = previous_pending;
                state.consumed_authorizations = previous_consumed;
                return Err(format!(
                    "governance authorization was not issued because pending-ledger persistence failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => {
                return Err(format!(
                    "governance authorization state committed at sequence {sequence}, but no receipt was issued because pending-ledger persistence failed to advance the checkpoint: {reason}"
                ));
            }
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(receipt)
    }

    pub fn verify_and_consume_action_authorization(
        &self,
        request: &ActionRequest,
        receipt_value: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> {
        self.verify_and_consume_request_receipt(
            request,
            receipt_value,
            GovernanceReceiptDecision::Approve,
            now_ms,
        )
    }

    pub fn verify_and_consume_veto(
        &self,
        request: &ActionRequest,
        receipt_value: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> {
        self.verify_and_consume_request_receipt(
            request,
            receipt_value,
            GovernanceReceiptDecision::Veto,
            now_ms,
        )
    }

    fn verify_and_consume_request_receipt(
        &self,
        request: &ActionRequest,
        receipt_value: &serde_json::Value,
        expected_decision: GovernanceReceiptDecision,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_checkpoint_repaired_locked(&mut state)?;
        if let Some(error) = Self::pending_health_observation_error(&state) {
            return Err(error);
        }
        let (receipt, subject_digest, index) = validate_pending_request_receipt_locked(
            &state,
            request,
            receipt_value,
            expected_decision,
            now_ms,
        )?;

        let previous_pending = state.pending_authorizations.clone();
        let previous_consumed = state.consumed_authorizations.clone();
        state.pending_authorizations.remove(index);
        state
            .consumed_authorizations
            .push_back(ConsumedGovernanceAuthorization {
                receipt_id: receipt.payload.receipt_id.clone(),
                subject_digest,
                decision: expected_decision,
                consumed_at_ms: now_ms,
            });
        prune_authorization_ledgers(&mut state, now_ms);
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.pending_authorizations = previous_pending;
                state.consumed_authorizations = previous_consumed;
                return Err(format!(
                    "governance receipt was not consumed because ledger persistence failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => {
                return Err(format!(
                    "governance receipt was consumed in signed state sequence {sequence}, but execution is refused because ledger persistence failed to advance the checkpoint: {reason}"
                ));
            }
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        serde_json::to_value(receipt).map_err(|error| {
            format!("verified governance receipt could not be serialized: {error}")
        })
    }

    pub fn begin_human_authorization_hold(
        &self,
        request: &ActionRequest,
        receipt_value: &serde_json::Value,
        policy_decision: &PolicyDecision,
        now_ms: i64,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        if policy_decision.verdict != PolicyVerdict::RequireHuman {
            return Err("human authorization hold requires a require_human policy decision".into());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_checkpoint_repaired_locked(&mut state)?;
        if let Some(error) = Self::pending_health_observation_error(&state) {
            return Err(error);
        }
        let (receipt, subject_digest, _) = validate_pending_request_receipt_locked(
            &state,
            request,
            receipt_value,
            GovernanceReceiptDecision::Approve,
            now_ms,
        )?;
        if let Some(existing) = state.pending_human_authorizations.iter().find(|hold| {
            hold.governance_receipt
                .get("payload")
                .and_then(|payload| payload.get("receipt_id"))
                .and_then(serde_json::Value::as_str)
                == Some(receipt.payload.receipt_id.as_str())
        }) {
            if existing.request != *request || existing.policy_decision != *policy_decision {
                return Err("pending human authorization does not match the exact request".into());
            }
            return Ok(existing.clone());
        }

        let hold_seed = serde_json::json!({
            "domain": "swarm.governance.human-authorization-hold.v1",
            "subject_digest": subject_digest,
            "receipt_id": receipt.payload.receipt_id,
            "policy_decision": policy_decision,
        });
        let hold_id = format!(
            "governance-human-hold:{}",
            sha256_hex(&canonical_json_bytes(&hold_seed).map_err(|error| error.to_string())?)
        );
        let hold = GovernedHumanAuthorizationHold {
            hold_id,
            request: request.clone(),
            policy_decision: policy_decision.clone(),
            governance_receipt: receipt_value.clone(),
            created_at_ms: now_ms,
            approval_set_id: None,
            approval_set_digest: None,
        };
        let previous = state.pending_human_authorizations.clone();
        state.pending_human_authorizations.push_back(hold.clone());
        prune_authorization_ledgers(&mut state, now_ms);
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.pending_human_authorizations = previous;
                return Err(format!(
                    "human authorization hold was not created because persistence failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => tracing::warn!(
                sequence,
                reason = %reason,
                module = module_path!(),
                "human authorization hold committed while its checkpoint remains lagging"
            ),
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(hold)
    }

    pub fn bind_human_approval_set(
        &self,
        hold_id: &str,
        approval_set_id: &str,
        approval_set_digest: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        if approval_set_id.is_empty() || approval_set_digest.is_empty() {
            return Err("human approval binding fields must not be empty".into());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_checkpoint_repaired_locked(&mut state)?;
        if let Some(error) = Self::pending_health_observation_error(&state) {
            return Err(error);
        }
        let previous = state.pending_human_authorizations.clone();
        let Some(hold) = state
            .pending_human_authorizations
            .iter_mut()
            .find(|hold| hold.hold_id == hold_id)
        else {
            return Err(format!(
                "pending human authorization hold `{hold_id}` was not found"
            ));
        };
        match (&hold.approval_set_id, &hold.approval_set_digest) {
            (Some(existing_id), Some(existing_digest))
                if existing_id == approval_set_id && existing_digest == approval_set_digest =>
            {
                return Ok(hold.clone());
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "pending human authorization hold `{hold_id}` is already bound"
                ));
            }
            _ => {}
        }
        hold.approval_set_id = Some(approval_set_id.to_string());
        hold.approval_set_digest = Some(approval_set_digest.to_string());
        let bound = hold.clone();
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.pending_human_authorizations = previous;
                return Err(format!(
                    "human approval set was not bound because persistence failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => tracing::warn!(
                sequence,
                reason = %reason,
                module = module_path!(),
                "human approval binding committed while its checkpoint remains lagging"
            ),
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(bound)
    }

    /// Repair the only cross-store crash window in governed human approval.
    ///
    /// The approval set and ledger are persisted by the runtime before this
    /// signed governance state is updated. If the process exits between those
    /// commits, a later authenticated resume supplies the exact persisted set
    /// identity, digest, and hold-derived evidence reference. This method binds
    /// that set to one and only one unbound hold, persists the repair, and is
    /// idempotent for an already-reconciled binding.
    pub fn reconcile_human_approval_set(
        &self,
        approval_set_id: &str,
        approval_set_digest: &str,
        approval_evidence_ref: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        if approval_set_id.is_empty()
            || approval_set_digest.is_empty()
            || approval_evidence_ref.is_empty()
        {
            return Err("human approval reconciliation fields must not be empty".into());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(existing) = state
            .pending_human_authorizations
            .iter()
            .find(|hold| hold.approval_set_id.as_deref() == Some(approval_set_id))
        {
            if existing.approval_set_digest.as_deref() != Some(approval_set_digest)
                || existing.approval_evidence_ref() != approval_evidence_ref
            {
                return Err(format!(
                    "pending human authorization for approval set `{approval_set_id}` conflicts with the persisted approval artifact"
                ));
            }
            return Ok(existing.clone());
        }

        let matching_indexes = state
            .pending_human_authorizations
            .iter()
            .enumerate()
            .filter_map(|(index, hold)| {
                (hold.approval_set_id.is_none()
                    && hold.approval_set_digest.is_none()
                    && hold.approval_evidence_ref() == approval_evidence_ref)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        let hold_index = match matching_indexes.as_slice() {
            [] => {
                return Err(format!(
                    "pending human authorization for approval evidence `{approval_evidence_ref}` was not found"
                ));
            }
            [hold_index] => *hold_index,
            indexes => {
                return Err(format!(
                    "approval evidence `{approval_evidence_ref}` matched {} unbound human authorization holds; expected exactly one",
                    indexes.len()
                ));
            }
        };

        let previous = state.pending_human_authorizations.clone();
        let hold = &mut state.pending_human_authorizations[hold_index];
        hold.approval_set_id = Some(approval_set_id.to_string());
        hold.approval_set_digest = Some(approval_set_digest.to_string());
        let reconciled = hold.clone();
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.pending_human_authorizations = previous;
                return Err(format!(
                    "human approval set reconciliation failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => tracing::warn!(
                sequence,
                reason = %reason,
                module = module_path!(),
                "human approval reconciliation committed while its checkpoint remains lagging"
            ),
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(reconciled)
    }

    pub fn pending_human_authorization(
        &self,
        approval_set_id: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_human_authorizations
            .iter()
            .find(|hold| hold.approval_set_id.as_deref() == Some(approval_set_id))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "pending human authorization for approval set `{approval_set_id}` was not found"
                )
            })
    }

    pub fn verify_and_consume_human_authorization(
        &self,
        hold_id: &str,
        approval_set_id: &str,
        approval_set_digest: &str,
        now_ms: i64,
    ) -> Result<ConsumedGovernedHumanAuthorization, String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_checkpoint_repaired_locked(&mut state)?;
        if let Some(error) = Self::pending_health_observation_error(&state) {
            return Err(error);
        }
        // The hold and its receipt may have been created while quorum was
        // healthy, but they are bearer state until this final, one-shot
        // consumption.  Recheck the current governance state under the same
        // mutex immediately before validating/consuming them.  Otherwise a
        // persisted pre-partition approval could bypass the contingency-lease
        // path and route a destructive action while the committee is
        // partitioned (or while governance is still degraded/healing).
        if state.partition_state != PartitionState::Healthy {
            return Err(format!(
                "human authorization hold cannot be consumed while governance state is {:?}; use the current governance or contingency-lease path",
                state.partition_state
            ));
        }
        let Some(hold_index) = state
            .pending_human_authorizations
            .iter()
            .position(|hold| hold.hold_id == hold_id)
        else {
            return Err(format!(
                "pending human authorization hold `{hold_id}` was not found"
            ));
        };
        let hold = state.pending_human_authorizations[hold_index].clone();
        if hold.approval_set_id.as_deref() != Some(approval_set_id)
            || hold.approval_set_digest.as_deref() != Some(approval_set_digest)
        {
            return Err("human approval set does not match the persisted hold binding".into());
        }
        let (receipt, subject_digest, receipt_index) = validate_pending_request_receipt_locked(
            &state,
            &hold.request,
            &hold.governance_receipt,
            GovernanceReceiptDecision::Approve,
            now_ms,
        )?;
        let verified_governance_receipt = serde_json::to_value(&receipt).map_err(|error| {
            format!("verified governance receipt could not be serialized: {error}")
        })?;

        let previous_pending = state.pending_authorizations.clone();
        let previous_consumed = state.consumed_authorizations.clone();
        let previous_holds = state.pending_human_authorizations.clone();
        state.pending_authorizations.remove(receipt_index);
        state
            .consumed_authorizations
            .push_back(ConsumedGovernanceAuthorization {
                receipt_id: receipt.payload.receipt_id,
                subject_digest,
                decision: GovernanceReceiptDecision::Approve,
                consumed_at_ms: now_ms,
            });
        state.pending_human_authorizations.remove(hold_index);
        prune_authorization_ledgers(&mut state, now_ms);
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.pending_authorizations = previous_pending;
                state.consumed_authorizations = previous_consumed;
                state.pending_human_authorizations = previous_holds;
                return Err(format!(
                    "human and governance authorization were not consumed because persistence failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => {
                return Err(format!(
                    "human and governance authorization were consumed in signed state sequence {sequence}, but execution is refused because checkpoint persistence failed: {reason}"
                ));
            }
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(ConsumedGovernedHumanAuthorization {
            hold,
            verified_governance_receipt,
        })
    }

    pub fn is_partitioned(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::effective_partition_projection(&state).0 == PartitionState::Partitioned
    }

    pub fn authorize_partition_request(
        &self,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<Option<ContingencyLease>, String> {
        if !request.action.requires_governance_receipt() {
            return Ok(None);
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.ensure_checkpoint_repaired_locked(&mut state)?;
        if let Some(error) = Self::pending_health_observation_error(&state) {
            return Err(error);
        }
        if state.partition_state != PartitionState::Partitioned {
            return Ok(None);
        }

        let lease_value = match request.evidence.get("contingency_lease").cloned() {
            Some(value) => value,
            None => {
                let reason = "missing contingency lease during partition".to_string();
                self.record_partition_activity_locked(
                    &mut state,
                    request,
                    false,
                    reason.clone(),
                    None,
                    now_ms,
                );
                self.persist_best_effort_locked(&mut state);
                return Err(reason);
            }
        };
        let lease: ContingencyLease = match serde_json::from_value(lease_value) {
            Ok(lease) => lease,
            Err(error) => {
                let reason = format!("invalid contingency lease: {error}");
                self.record_partition_activity_locked(
                    &mut state,
                    request,
                    false,
                    reason.clone(),
                    None,
                    now_ms,
                );
                self.persist_best_effort_locked(&mut state);
                return Err(reason);
            }
        };
        let current_committee = match state.committee() {
            Ok(committee) => committee,
            Err(error) => {
                let reason = format!("invalid current governance committee: {error}");
                self.record_partition_activity_locked(
                    &mut state,
                    request,
                    false,
                    reason.clone(),
                    Some(lease.lease_id.clone()),
                    now_ms,
                );
                self.persist_best_effort_locked(&mut state);
                return Err(reason);
            }
        };
        if let Err(reason) =
            lease.verify_for_committee(&governor_public_keys_locked(&state), &current_committee)
        {
            self.record_partition_activity_locked(
                &mut state,
                request,
                false,
                reason.clone(),
                Some(lease.lease_id.clone()),
                now_ms,
            );
            self.persist_best_effort_locked(&mut state);
            return Err(reason);
        }
        let Some(index) = state
            .active_contingency_leases
            .iter()
            .position(|candidate| candidate.lease_id == lease.lease_id)
        else {
            let reason = format!("unknown contingency lease `{}`", lease.lease_id);
            self.record_partition_activity_locked(
                &mut state,
                request,
                false,
                reason.clone(),
                None,
                now_ms,
            );
            self.persist_best_effort_locked(&mut state);
            return Err(reason);
        };
        if state.active_contingency_leases[index] != lease {
            let reason = format!(
                "contingency lease `{}` did not match persisted lease",
                lease.lease_id
            );
            self.record_partition_activity_locked(
                &mut state,
                request,
                false,
                reason.clone(),
                None,
                now_ms,
            );
            self.persist_best_effort_locked(&mut state);
            return Err(reason);
        }
        let previous_leases = state.active_contingency_leases.clone();
        let previous_activity = state.partition_activity.clone();
        let redeem_result = {
            let existing = &mut state.active_contingency_leases[index];
            existing
                .redeem(request, now_ms)
                .map(|_| existing.clone())
                .map_err(|reason| (reason, existing.lease_id.clone()))
        };
        let redeemed = match redeem_result {
            Ok(redeemed) => redeemed,
            Err((reason, lease_id)) => {
                self.record_partition_activity_locked(
                    &mut state,
                    request,
                    false,
                    reason.clone(),
                    Some(lease_id),
                    now_ms,
                );
                self.persist_best_effort_locked(&mut state);
                return Err(reason);
            }
        };
        self.record_partition_activity_locked(
            &mut state,
            request,
            true,
            "authorized by contingency lease".to_string(),
            Some(redeemed.lease_id.clone()),
            now_ms,
        );
        match self.persist_locked(&mut state) {
            Err(error) => {
                state.active_contingency_leases = previous_leases;
                state.partition_activity = previous_activity;
                return Err(format!(
                    "contingency lease redemption was not authorized because persistence failed before commit: {error}"
                ));
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => {
                return Err(format!(
                    "contingency lease was redeemed in signed state sequence {sequence}, but execution is refused because checkpoint persistence failed: {reason}"
                ));
            }
            Ok(GovernancePersistenceOutcome::Committed) => {}
        }
        Ok(Some(redeemed))
    }

    /// Sign `subject` on the governance receipt chain and return the receipt.
    ///
    /// THE SAME SIGNING PATH, LITERALLY. This holds the same `Mutex<GovernanceState>`,
    /// reads the same `governors` keyring, calls the same
    /// [`simulate_governance_commit`], advances the same `previous_commit_hash` and
    /// `receipt_counter`, issues through the same
    /// [`ConsensusGovernanceReceipt::issue`], and persists through the same
    /// `persist_locked`, as [`issue_governance_receipt`] and
    /// [`issue_contingency_lease`] do. A release attested here sits in the same chain
    /// as the governance receipt that authorized the containment being released; that
    /// is what QRT-04's "the same governance signing path" has to mean to be worth
    /// anything.
    ///
    /// THE PROPOSAL ID IS THE SUBJECT DIGEST, NOT A DERIVED LABEL. Both sibling
    /// builders hash a payload of their own shape into `proposal_id`. This one hashes
    /// the caller's `subject` verbatim, because the caller has to be able to
    /// re-derive it: `swarm_runtime::containment::verify_release_attestation`
    /// re-canonicalizes the rollback receipt and compares. Hashing anything else here
    /// would leave a signature that verifies while covering an unknown body.
    ///
    /// `None` when no governor is registered -- there is no key to sign with, and a
    /// fabricated signer would be worse than an unattested release.
    pub fn attest_release(
        &self,
        subject: &serde_json::Value,
        now_ms: i64,
    ) -> Option<ConsensusGovernanceReceipt> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) = self.ensure_checkpoint_repaired_locked(&mut state) {
            tracing::warn!(
                reason = %error,
                module = module_path!(),
                "containment release attestation was refused until governance checkpoint repair"
            );
            return None;
        }
        if let Some(error) = Self::pending_health_observation_error(&state) {
            tracing::warn!(
                reason = %error,
                module = module_path!(),
                "containment release attestation was refused while a health observation is pending"
            );
            return None;
        }
        // Rebased onto BFT-03's single-key path. This used to read
        // `state.governors` and call `simulate_governance_commit` with the whole
        // keyring; both are gone, and the round now runs through the transport
        // exactly as `issue_governance_receipt` does. That is the point of the
        // rebase rather than an incidental fix -- a second commit path here
        // would be a second place for the release attestation to drift from the
        // governance chain it is supposed to advance.
        state.local_governor.as_ref()?;
        let proposal_payload = subject.clone();
        let proposal = ConsensusProposal {
            proposal_id: proposal_id_for_payload(&proposal_payload).ok()?,
            payload: proposal_payload,
        };
        let previous_commit_hash = state.previous_commit_hash.clone();
        let previous_receipt_counter = state.receipt_counter;
        match run_governance_round(
            &mut state,
            self.transport.as_ref(),
            proposal,
            GovernanceReceiptDecision::Approve,
            now_ms,
        ) {
            Ok(receipt) => {
                match self.persist_locked(&mut state) {
                    Err(error) => {
                        state.previous_commit_hash = previous_commit_hash;
                        state.receipt_counter = previous_receipt_counter;
                        tracing::warn!(
                            reason = %error,
                            module = module_path!(),
                            "containment release attestation was not issued because governance persistence failed before commit"
                        );
                        return None;
                    }
                    Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                        sequence,
                        reason,
                    }) => {
                        tracing::warn!(
                            sequence,
                            reason = %reason,
                            module = module_path!(),
                            "containment release attestation committed, but was withheld while its checkpoint remains lagging"
                        );
                        return None;
                    }
                    Ok(GovernancePersistenceOutcome::Committed) => {}
                }
                Some(receipt)
            }
            Err(error) => {
                tracing::warn!(
                    reason = %error,
                    module = module_path!(),
                    "failed to build governance consensus receipt for a containment release"
                );
                None
            }
        }
    }

    pub fn note_partition_veto(&self, request: &ActionRequest, reason: &str, now_ms: i64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(error) = self.ensure_authority_ready_locked(&mut state) {
            tracing::warn!(
                reason = %error,
                module = module_path!(),
                "partition veto activity was withheld until governance repair and health veto cleared"
            );
            return;
        }
        if Self::effective_partition_projection(&state).0 != PartitionState::Partitioned {
            return;
        }
        self.record_partition_activity_locked(
            &mut state,
            request,
            false,
            reason.to_string(),
            request
                .evidence
                .get("contingency_lease")
                .and_then(|value| value.get("lease_id"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            now_ms,
        );
        self.persist_best_effort_locked(&mut state);
    }

    /// Receipt-verification anchors admitted locally in this process.
    ///
    /// Persisted peers still influence committee size, so forgetting them cannot
    /// collapse a fail-closed committee into solo authorization. They are NOT signer
    /// trust anchors until an authenticated peer-admission protocol exists.
    pub fn governor_public_keys(&self) -> BTreeSet<AgentId> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .local_governor
            .iter()
            .map(|local| local.consensus_agent_id().clone())
            .collect()
    }

    pub fn status_report(&self) -> GovernanceStatusReport {
        self.status_report_at(now_ms())
    }

    fn status_report_at(&self, observed_at_ms: i64) -> GovernanceStatusReport {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (partition_state, total_governors, healthy_governors, quorum_threshold, pending_at) =
            Self::effective_partition_projection(&state);
        GovernanceStatusReport {
            partition_state,
            total_governors,
            healthy_governors,
            quorum_threshold,
            active_contingency_leases: state
                .active_contingency_leases
                .iter()
                .filter(|lease| lease.expires_at_ms > observed_at_ms)
                .count(),
            unauthorized_partition_actions: state
                .partition_activity
                .iter()
                .filter(|record| !record.authorized)
                .count(),
            last_transition_at_ms: pending_at,
            last_reconciliation_report_id: state
                .reconciliation_reports
                .last()
                .map(|report| report.report_id.clone()),
        }
    }

    pub fn drain_runtime_events(&self) -> Vec<GovernanceRuntimeEvent> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.pending_events.drain(..).collect()
    }

    fn ensure_contingency_leases_locked(&self, state: &mut GovernanceState, now_ms: i64) {
        retain_current_committee_contingency_leases(state);
        let current_committee = state.committee().ok();
        for action_kind in ResponseAction::governed_action_kinds() {
            let already_active = state.active_contingency_leases.iter().any(|lease| {
                lease.action_kind == action_kind
                    && lease.scope.is_none()
                    && lease.expires_at_ms > now_ms
                    && lease.redeemed_scopes.len() < lease.blast_radius_cap
                    && current_committee
                        .as_ref()
                        .is_some_and(|committee| lease.matches_committee(committee))
            });
            if already_active {
                continue;
            }
            if let Some(lease) = issue_contingency_lease(
                state,
                self.transport.as_ref(),
                action_kind,
                None,
                self.config.contingency_blast_radius_cap,
                self.config.contingency_lease_ttl_ms,
                now_ms,
            ) {
                state.active_contingency_leases.push(lease);
            }
        }
    }

    fn pending_health_observation_error(state: &GovernanceState) -> Option<String> {
        state
            .pending_health_observation
            .as_ref()
            .or(state.durable_pending_health_observation.as_ref())
            .map(|observation| {
            format!(
                "governance authority is blocked until deferred health observed at {} is persisted",
                observation.observed_at_ms
            )
            })
    }

    fn same_health_observation(
        first: &PendingHealthObservation,
        second: &PendingHealthObservation,
    ) -> bool {
        first.governing_agent_id == second.governing_agent_id && first.entries == second.entries
    }

    fn restrictive_health_intent_needed(
        state: &GovernanceState,
        governing_agent_id: &AgentId,
        entries: &[AgentHealthEntry],
    ) -> bool {
        if !entries
            .iter()
            .any(|entry| entry.health != AgentHealth::Healthy)
        {
            return false;
        }
        // A previously committed restrictive projection is already fail
        // closed across restart.  Do not turn oscillating restrictive health
        // entries into another write while a checkpoint repair is deferred;
        // the first transition from Healthy is the only one that needs a
        // write-ahead intent.
        if state.partition_state != PartitionState::Healthy
            || !state.unhealthy_agents.is_empty()
            || state.durable_pending_health_observation.is_some()
        {
            return false;
        }
        if state.pending_health_observation.is_some()
            && state.durable_pending_health_observation.is_none()
        {
            return true;
        }
        if state.governing_agent_id.as_ref() != Some(governing_agent_id) {
            return true;
        }
        let unhealthy_agents = entries
            .iter()
            .filter(|entry| entry.health != AgentHealth::Healthy)
            .cloned()
            .collect::<Vec<_>>();
        if state.unhealthy_agents != unhealthy_agents {
            return true;
        }
        let total_governors = state.display_governors.len().max(state.governor_count());
        let unhealthy_governors = state.unhealthy_governor_ids(entries).len();
        let healthy_governors = total_governors.saturating_sub(unhealthy_governors);
        let quorum_threshold = governance_quorum_threshold(total_governors);
        let base_state = if healthy_governors < quorum_threshold {
            PartitionState::Partitioned
        } else if unhealthy_agents.is_empty() {
            PartitionState::Healthy
        } else {
            PartitionState::Degraded
        };
        state.last_healthy_governors != healthy_governors
            || state.last_quorum_threshold != quorum_threshold
            || state.partition_state != base_state
    }

    /// Every public authority mutation uses this ordering: repair the signed
    /// checkpoint first, then reject any restrictive health observation that is
    /// still pending.  Keeping this gate shared prevents bookkeeping paths such
    /// as governor admission and partition-veto activity from becoming a side
    /// channel around the direct governed-effect veto.
    fn ensure_authority_ready_locked(&self, state: &mut GovernanceState) -> Result<(), String> {
        self.ensure_checkpoint_repaired_locked(state)?;
        if let Some(error) = Self::pending_health_observation_error(state) {
            return Err(error);
        }
        Ok(())
    }

    fn pending_health_observation(state: &GovernanceState) -> Option<&PendingHealthObservation> {
        state
            .pending_health_observation
            .as_ref()
            .or(state.durable_pending_health_observation.as_ref())
    }

    fn pending_health_projection(
        state: &GovernanceState,
        observation: &PendingHealthObservation,
    ) -> (PartitionState, usize, usize, usize) {
        let mut display_governors = state.display_governors.clone();
        if let Some(local) = state.local_governor.as_ref() {
            display_governors.insert(
                observation.governing_agent_id.clone(),
                local.consensus_agent_id().clone(),
            );
        }
        let unhealthy_governors = observation
            .entries
            .iter()
            .filter(|entry| entry.role == AgentRole::Tom && entry.health != AgentHealth::Healthy)
            .filter_map(|entry| {
                let observed_id = AgentId(entry.id.clone());
                display_governors.get(&observed_id).cloned().or_else(|| {
                    (display_governors
                        .values()
                        .any(|consensus_id| consensus_id == &observed_id)
                        || state.peer_governors.contains(&observed_id))
                    .then_some(observed_id)
                })
            })
            .collect::<BTreeSet<_>>()
            .len();
        let total_governors = display_governors.len().max(state.governor_count());
        let healthy_governors = total_governors.saturating_sub(unhealthy_governors);
        let quorum_threshold = governance_quorum_threshold(total_governors);
        // A pending marker itself means the latest observation is not yet
        // checkpoint-anchored. Never expose stale Healthy to a dispatcher.
        let partition_state = if healthy_governors < quorum_threshold {
            PartitionState::Partitioned
        } else {
            PartitionState::Degraded
        };
        (
            partition_state,
            total_governors,
            healthy_governors,
            quorum_threshold,
        )
    }

    fn effective_partition_projection(
        state: &GovernanceState,
    ) -> (PartitionState, usize, usize, usize, Option<i64>) {
        if let Some(observation) = Self::pending_health_observation(state) {
            let (partition_state, total, healthy, quorum) =
                Self::pending_health_projection(state, observation);
            return (
                partition_state,
                total,
                healthy,
                quorum,
                Some(observation.observed_at_ms),
            );
        }
        (
            state.partition_state,
            state.display_governors.len().max(state.governor_count()),
            state.last_healthy_governors,
            state.last_quorum_threshold,
            state.last_transition_at_ms,
        )
    }

    fn reconcile_partition_activity_locked(
        &self,
        state: &mut GovernanceState,
        healed_at_ms: i64,
    ) -> PartitionReconciliationReport {
        let report_id = format!(
            "partition-reconciliation:{}:{}",
            healed_at_ms, state.receipt_counter
        );
        let mut authorized_actions = Vec::new();
        let mut unauthorized_actions = Vec::new();
        for record in std::mem::take(&mut state.partition_activity) {
            if record.authorized {
                authorized_actions.push(record);
            } else {
                unauthorized_actions.push(record);
            }
        }
        let report = PartitionReconciliationReport {
            report_id,
            created_at_ms: healed_at_ms,
            partition_started_at_ms: state.partition_started_at_ms,
            healed_at_ms,
            authorized_actions,
            unauthorized_actions,
        };
        state.reconciliation_reports.push(report.clone());
        if state.reconciliation_reports.len() > MAX_RECONCILIATION_REPORTS {
            let trim_to = state.reconciliation_reports.len() - MAX_RECONCILIATION_REPORTS;
            state.reconciliation_reports.drain(0..trim_to);
        }
        report
    }

    fn record_partition_activity_locked(
        &self,
        state: &mut GovernanceState,
        request: &ActionRequest,
        authorized: bool,
        reason: String,
        lease_id: Option<String>,
        now_ms: i64,
    ) {
        state.partition_activity.push(PartitionActionRecord {
            recorded_at_ms: now_ms,
            hunt_id: request.hunt_id.0.clone(),
            requested_by: request.requested_by.to_string(),
            action_kind: request.action.kind().to_string(),
            scope: scope_for_response_action(&request.action),
            authorized,
            reason,
            lease_id,
        });
    }

    fn persist_locked(
        &self,
        state: &mut GovernanceState,
    ) -> Result<GovernancePersistenceOutcome, String> {
        let Some(persistence) = &self.persistence else {
            state.checkpoint_lagging = None;
            state.checkpoint_repair_backoff = None;
            return Ok(GovernancePersistenceOutcome::Committed);
        };
        let expected_sequence = state.persistence_sequence.ok_or_else(|| {
            "persisted governance state has no in-memory signed sequence anchor".to_string()
        })?;
        let expected_digest = state.persistence_digest.as_deref().ok_or_else(|| {
            "persisted governance state has no in-memory signed digest anchor".to_string()
        })?;
        let next_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| "signed governance state sequence overflow".to_string())?;
        let (outcome, version) = persistence
            .save(state, expected_sequence, expected_digest)
            .map_err(|error| error.to_string())?;
        debug_assert_eq!(version.sequence, next_sequence);
        state.persistence_sequence = Some(version.sequence);
        state.persistence_digest = Some(version.digest);
        if version.health_marker_cleared {
            state.pending_health_observation = None;
            state.durable_pending_health_observation = None;
        }
        state.checkpoint_lagging = match &outcome {
            GovernancePersistenceOutcome::Committed => None,
            GovernancePersistenceOutcome::StateCommittedCheckpointLagging { sequence, reason } => {
                debug_assert_eq!(*sequence, next_sequence);
                Some(GovernanceCheckpointLag {
                    sequence: *sequence,
                    reason: reason.clone(),
                })
            }
        };
        if matches!(&outcome, GovernancePersistenceOutcome::Committed) {
            state.checkpoint_repair_backoff = None;
        }
        Ok(outcome)
    }

    fn persist_pending_health_intent_locked(
        &self,
        state: &mut GovernanceState,
        observation: &PendingHealthObservation,
    ) -> Result<(), String> {
        let Some(persistence) = &self.persistence else {
            state.pending_health_observation = Some(observation.clone());
            return Ok(());
        };
        let version = persistence
            .write_pending_health_intent(state, observation)
            .map_err(|error| error.to_string())?;
        state.persistence_sequence = Some(version.sequence);
        state.persistence_digest = Some(version.digest);
        state.pending_health_observation = Some(observation.clone());
        state.durable_pending_health_observation = Some(observation.clone());
        Ok(())
    }

    fn repair_checkpoint_from_health_tick_locked(
        &self,
        state: &mut GovernanceState,
        observed_at_ms: i64,
    ) {
        if state.checkpoint_lagging.is_none() {
            state.checkpoint_repair_backoff = None;
            return;
        }
        if state
            .checkpoint_repair_backoff
            .is_some_and(|backoff| !backoff.is_due(observed_at_ms))
        {
            return;
        }
        match self.ensure_checkpoint_repaired_locked(state) {
            Ok(()) => {
                // `ensure_checkpoint_repaired_locked` also clears this on
                // success; keep the invariant local to this health path.
                state.checkpoint_repair_backoff = None;
            }
            Err(error) => {
                state.checkpoint_repair_backoff =
                    Some(GovernanceCheckpointRepairBackoff::after(observed_at_ms));
                tracing::warn!(
                    reason = %error,
                    retry_at_ms = state
                        .checkpoint_repair_backoff
                        .map(|backoff| backoff.retry_at_ms),
                    module = module_path!(),
                    "governance health observation retained a lagging checkpoint"
                );
            }
        }
    }

    fn ensure_checkpoint_repaired_locked(&self, state: &mut GovernanceState) -> Result<(), String> {
        let Some(lag) = state.checkpoint_lagging.clone() else {
            state.checkpoint_repair_backoff = None;
            return Ok(());
        };
        let Some(persistence) = &self.persistence else {
            state.checkpoint_lagging = None;
            state.checkpoint_repair_backoff = None;
            return Ok(());
        };
        persistence.repair_checkpoint(state, &lag).map_err(|error| {
            format!(
                "signed governance state sequence {} is committed but its checkpoint remains lagging (initial failure: {}; repair failure: {error})",
                lag.sequence, lag.reason
            )
        })?;
        state.checkpoint_lagging = None;
        state.checkpoint_repair_backoff = None;
        Ok(())
    }

    fn persist_best_effort_locked(&self, state: &mut GovernanceState) {
        let result = self.persist_locked(state);
        let warning = match result {
            Ok(GovernancePersistenceOutcome::Committed) => return,
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => {
                format!("state sequence {sequence} committed but checkpoint is lagging: {reason}")
            }
            Err(error) => error,
        };
        let path = self
            .persistence
            .as_ref()
            .map(|persistence| persistence.path.display().to_string())
            .unwrap_or_else(|| "<memory>".to_string());
        tracing::warn!(
            reason = %warning,
            path = %path,
            module = module_path!(),
            "governance policy persistence is not fully anchored"
        );
    }
}

pub struct TomAgent {
    id: AgentId,
    verifying_key: VerifyingKey,
    health: AgentHealth,
    degraded_tick_threshold: usize,
    degraded_ticks: BTreeMap<String, usize>,
    governance_policy: std::sync::Arc<GovernancePolicy>,
}

impl TomAgent {
    pub fn new(
        id: AgentId,
        degraded_tick_threshold: usize,
        governance_policy: std::sync::Arc<GovernancePolicy>,
    ) -> Result<Self, GovernanceKeyError> {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            degraded_tick_threshold,
            governance_policy,
        )
    }

    /// Construct a Tom and install its key as THE governor key of `governance_policy`.
    ///
    /// Fallible since BFT-03: a policy that already holds a different governor's
    /// key refuses this one rather than accumulating both. Swallowing that would
    /// leave a Tom that believes it governs while the policy signs with someone
    /// else's key, so the error propagates to the composition root.
    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        degraded_tick_threshold: usize,
        governance_policy: std::sync::Arc<GovernancePolicy>,
    ) -> Result<Self, GovernanceKeyError> {
        governance_policy.register_governor(id.clone(), signing_key.clone())?;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            id,
            verifying_key,
            health: AgentHealth::Healthy,
            degraded_tick_threshold,
            degraded_ticks: BTreeMap::new(),
            governance_policy,
        })
    }
}

#[async_trait]
impl SwarmAgent for TomAgent {
    fn identity(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        AgentRole::Tom
    }

    async fn tick(&mut self, env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        self.governance_policy
            .observe_health(&self.id, env.agent_health_summary(), now_ms());

        let mut actions = Vec::new();
        let mut degraded_ticks = BTreeMap::new();

        for entry in env.agent_health_summary() {
            if entry.id == self.id.0 {
                continue;
            }

            match entry.health {
                AgentHealth::Healthy => {}
                AgentHealth::Failed => {}
                AgentHealth::Degraded => {
                    let degraded_ticks_seen = self
                        .degraded_ticks
                        .get(&entry.id)
                        .copied()
                        .unwrap_or_default()
                        + 1;
                    degraded_ticks.insert(entry.id.clone(), degraded_ticks_seen);

                    if entry.role != AgentRole::Tom {
                        actions.push(SwarmAction::RoleShift {
                            target_agent_id: AgentId(entry.id.clone()),
                            new_role: AgentRole::Tom,
                        });
                    }

                    if degraded_ticks_seen == self.degraded_tick_threshold {
                        actions.push(SwarmAction::HealthReport {
                            target_agent_id: AgentId(entry.id.clone()),
                            status: AgentHealth::Failed,
                        });
                    }
                }
            }
        }

        self.degraded_ticks = degraded_ticks;
        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

fn governance_quorum_threshold(total_governors: usize) -> usize {
    if total_governors == 0 {
        0
    } else {
        recommended_max_faulty(total_governors)
            .saturating_mul(2)
            .saturating_add(1)
    }
}

fn partition_transition_reason(state: PartitionState) -> &'static str {
    match state {
        PartitionState::Healthy => "quorum restored and no unhealthy agents remain",
        PartitionState::Degraded => "quorum intact but unhealthy agents remain",
        PartitionState::Partitioned => "quorum lost across admitted governors",
        PartitionState::Healing => "quorum restored; reconciling partition-era actions",
    }
}

/// Run one governance round over `transport` and mint the receipt it commits.
///
/// This is the function that replaced `simulate_governance_commit` on the
/// production path (BFT-03). The differences that matter:
///
/// - exactly ONE `ConsensusNode` is built, from the ONE local key, so this
///   process can produce signed traffic for one committee member and no other;
/// - envelopes go out through a [`ConsensusTransport`], so the seam a networked
///   deployment needs exists and the shipped `SoloGovernorTransport` refuses
///   any committee it cannot honestly serve;
/// - a round that does not commit within `round_timeout_ms * (max_faulty + 1)`
///   returns `Err`, and every caller turns that into a refusal.
fn run_governance_round(
    state: &mut GovernanceState,
    transport: &dyn ConsensusTransport,
    proposal: ConsensusProposal,
    decision: GovernanceReceiptDecision,
    issued_at_ms: i64,
) -> Result<ConsensusGovernanceReceipt, ConsensusError> {
    let Some(local) = state.local_governor.as_ref() else {
        return Err(ConsensusError::InvalidCommittee(
            "governance policy holds no local governor signing key".to_string(),
        ));
    };
    let committee = state.committee()?;
    let mut node = local.consensus_node(
        committee.clone(),
        ConsensusConfig::default(),
        &state.previous_commit_hash,
        issued_at_ms,
    )?;
    let commit = drive_round(&mut node, transport, proposal, issued_at_ms)?;
    let previous_commit_hash = state.previous_commit_hash.clone();
    let receipt = local.issue_receipt(
        &commit,
        &previous_commit_hash,
        &committee,
        decision,
        issued_at_ms,
    )?;
    state.previous_commit_hash = commit.commit_hash;
    state.receipt_counter = state.receipt_counter.saturating_add(1);
    Ok(receipt)
}

/// Returns `Result`, not `Option`, so the refusal reason reaches the operator.
///
/// A round that cannot commit -- no transport for this committee, threshold
/// unreachable, deadline passed -- must produce a Veto that NAMES the cause.
/// Collapsing it to `None` is how the old shape fell through to `Allow`.
fn issue_contingency_lease(
    state: &mut GovernanceState,
    transport: &dyn ConsensusTransport,
    action_kind: &str,
    scope: Option<&str>,
    blast_radius_cap: usize,
    ttl_ms: i64,
    issued_at_ms: i64,
) -> Option<ContingencyLease> {
    if state.local_governor.is_none() || blast_radius_cap == 0 || ttl_ms <= 0 {
        return None;
    }
    let expires_at_ms = issued_at_ms.saturating_add(ttl_ms);
    let lease_id = sha256_hex(
        &canonical_json_bytes(&serde_json::json!({
            "kind": "contingency_lease",
            "action_kind": action_kind,
            "scope": scope,
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": expires_at_ms,
            "blast_radius_cap": blast_radius_cap,
        }))
        .ok()?,
    );
    let proposal = build_contingency_lease_proposal(
        &lease_id,
        action_kind,
        scope,
        blast_radius_cap,
        ttl_ms,
        issued_at_ms,
        expires_at_ms,
    )
    .ok()?;
    match run_governance_round(
        state,
        transport,
        proposal,
        GovernanceReceiptDecision::Approve,
        issued_at_ms,
    ) {
        Ok(governance_receipt) => Some(ContingencyLease {
            schema_version: CONTINGENCY_LEASE_SCHEMA_VERSION,
            lease_id,
            action_kind: action_kind.to_string(),
            scope: scope.map(str::to_string),
            blast_radius_cap,
            max_duration_ms: ttl_ms,
            issued_at_ms,
            expires_at_ms,
            redeemed_scopes: Vec::new(),
            redeemed_request_subjects: Vec::new(),
            governance_receipt,
        }),
        Err(error) => {
            tracing::warn!(
                reason = %error,
                action_kind,
                module = module_path!(),
                "failed to stage contingency lease"
            );
            None
        }
    }
}

fn build_contingency_lease_proposal(
    lease_id: &str,
    action_kind: &str,
    scope: Option<&str>,
    blast_radius_cap: usize,
    max_duration_ms: i64,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> Result<ConsensusProposal, ConsensusError> {
    let payload = serde_json::json!({
        "lease_id": lease_id,
        "kind": "contingency_lease",
        "action_kind": action_kind,
        "scope": scope,
        "blast_radius_cap": blast_radius_cap,
        "max_duration_ms": max_duration_ms,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
    });
    Ok(ConsensusProposal {
        proposal_id: proposal_id_for_payload(&payload)?,
        payload,
    })
}

fn preview_matching_contingency_lease(
    state: &GovernanceState,
    request: &ActionRequest,
    now_ms: i64,
) -> Option<ContingencyLease> {
    let current_committee = state.committee().ok()?;
    state
        .active_contingency_leases
        .iter()
        .find(|lease| {
            lease
                .verify_for_committee(&governor_public_keys_locked(state), &current_committee)
                .is_ok()
                && lease.can_redeem(request, now_ms)
        })
        .cloned()
}

fn governance_request_subject_value(request: &ActionRequest) -> Result<serde_json::Value, String> {
    serde_json::to_value(GovernanceActionRequestSubjectV1::from_request(request))
        .map_err(|error| format!("failed to encode governance request subject: {error}"))
}

fn governance_request_subject_digest(request: &ActionRequest) -> Result<String, String> {
    let subject = governance_request_subject_value(request)?;
    proposal_id_for_payload(&subject).map_err(|error| error.to_string())
}

fn governor_public_keys_locked(state: &GovernanceState) -> BTreeSet<AgentId> {
    state
        .local_governor
        .iter()
        .map(|local| local.consensus_agent_id().clone())
        .collect()
}

fn validate_pending_request_receipt_locked(
    state: &GovernanceState,
    request: &ActionRequest,
    receipt_value: &serde_json::Value,
    expected_decision: GovernanceReceiptDecision,
    now_ms: i64,
) -> Result<(ConsensusGovernanceReceipt, String, usize), String> {
    let receipt: ConsensusGovernanceReceipt = serde_json::from_value(receipt_value.clone())
        .map_err(|error| format!("invalid governance receipt: {error}"))?;
    let subject = governance_request_subject_value(request)?;
    let subject_digest = proposal_id_for_payload(&subject).map_err(|error| error.to_string())?;
    receipt
        .verify_signed_by(&governor_public_keys_locked(state))
        .map_err(|error| format!("governance receipt refused: {error}"))?;
    receipt
        .verify_internal_consistency(&subject, expected_decision)
        .map_err(|error| format!("governance receipt refused: {error}"))?;
    if receipt.payload.issued_at_ms > now_ms.saturating_add(MAX_AUTHORIZATION_FUTURE_SKEW_MS) {
        return Err("governance receipt was issued too far in the future".to_string());
    }
    if now_ms.saturating_sub(receipt.payload.issued_at_ms) > MAX_AUTHORIZATION_AGE_MS {
        return Err("governance receipt is stale".to_string());
    }
    if state
        .consumed_authorizations
        .iter()
        .any(|entry| entry.receipt_id == receipt.payload.receipt_id)
    {
        return Err(format!(
            "governance receipt `{}` was already consumed",
            receipt.payload.receipt_id
        ));
    }
    let index = state
        .pending_authorizations
        .iter()
        .position(|entry| {
            entry.receipt_id == receipt.payload.receipt_id
                && entry.subject_digest == subject_digest
                && entry.decision == expected_decision
                && entry.issued_at_ms == receipt.payload.issued_at_ms
        })
        .ok_or_else(|| {
            format!(
                "governance receipt `{}` is not present in the pending authorization ledger",
                receipt.payload.receipt_id
            )
        })?;
    Ok((receipt, subject_digest, index))
}

fn prune_authorization_ledgers(state: &mut GovernanceState, now_ms: i64) {
    let oldest_pending = now_ms.saturating_sub(MAX_AUTHORIZATION_AGE_MS);
    state
        .pending_authorizations
        .retain(|entry| entry.issued_at_ms >= oldest_pending);
    while state.pending_authorizations.len() > MAX_PENDING_AUTHORIZATIONS {
        state.pending_authorizations.pop_front();
    }
    while state.consumed_authorizations.len() > MAX_CONSUMED_AUTHORIZATIONS {
        state.consumed_authorizations.pop_front();
    }
    let pending_receipt_ids = state
        .pending_authorizations
        .iter()
        .map(|authorization| authorization.receipt_id.clone())
        .collect::<BTreeSet<_>>();
    state.pending_human_authorizations.retain(|hold| {
        hold.created_at_ms >= oldest_pending
            && hold
                .governance_receipt
                .get("payload")
                .and_then(|payload| payload.get("receipt_id"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|receipt_id| pending_receipt_ids.contains(receipt_id))
    });
    while state.pending_human_authorizations.len() > MAX_PENDING_HUMAN_AUTHORIZATIONS {
        state.pending_human_authorizations.pop_front();
    }
}

fn prune_expired_contingency_leases(state: &mut GovernanceState, now_ms: i64) {
    state
        .active_contingency_leases
        .retain(|lease| lease.expires_at_ms > now_ms);
}

fn retain_current_committee_contingency_leases(state: &mut GovernanceState) {
    let Ok(committee) = state.committee() else {
        state.active_contingency_leases.clear();
        return;
    };
    state
        .active_contingency_leases
        .retain(|lease| lease.matches_committee(&committee));
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

impl GovernanceAuthority {
    /// Whether this handle and `other` invoke the exact same policy allocation.
    pub fn same_policy(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.policy, &other.policy)
    }

    /// Opaque process-local identity used only to verify composition sharing.
    pub fn identity(&self) -> GovernanceAuthorityIdentity {
        GovernanceAuthorityIdentity(Arc::as_ptr(&self.policy).cast::<()>())
    }

    pub fn authorize_partition_request(
        &self,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<Option<serde_json::Value>, String> {
        GovernancePolicy::authorize_partition_request(&self.policy, request, now_ms)?.map_or(
            Ok(None),
            |lease| {
                serde_json::to_value(lease.governance_receipt)
                    .map(Some)
                    .map_err(|error| {
                        format!("verified contingency receipt could not be serialized: {error}")
                    })
            },
        )
    }

    pub fn verify_and_consume_action_authorization(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> {
        GovernancePolicy::verify_and_consume_action_authorization(
            &self.policy,
            request,
            receipt,
            now_ms,
        )
    }

    pub fn verify_and_consume_veto(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> {
        GovernancePolicy::verify_and_consume_veto(&self.policy, request, receipt, now_ms)
    }

    pub fn begin_human_authorization_hold(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        policy_decision: &PolicyDecision,
        now_ms: i64,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        GovernancePolicy::begin_human_authorization_hold(
            &self.policy,
            request,
            receipt,
            policy_decision,
            now_ms,
        )
    }

    pub fn bind_human_approval_set(
        &self,
        hold_id: &str,
        approval_set_id: &str,
        approval_set_digest: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        GovernancePolicy::bind_human_approval_set(
            &self.policy,
            hold_id,
            approval_set_id,
            approval_set_digest,
        )
    }

    pub fn reconcile_human_approval_set(
        &self,
        approval_set_id: &str,
        approval_set_digest: &str,
        approval_evidence_ref: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        GovernancePolicy::reconcile_human_approval_set(
            &self.policy,
            approval_set_id,
            approval_set_digest,
            approval_evidence_ref,
        )
    }

    pub fn pending_human_authorization(
        &self,
        approval_set_id: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> {
        GovernancePolicy::pending_human_authorization(&self.policy, approval_set_id)
    }

    pub fn verify_and_consume_human_authorization(
        &self,
        hold_id: &str,
        approval_set_id: &str,
        approval_set_digest: &str,
        now_ms: i64,
    ) -> Result<ConsumedGovernedHumanAuthorization, String> {
        GovernancePolicy::verify_and_consume_human_authorization(
            &self.policy,
            hold_id,
            approval_set_id,
            approval_set_digest,
            now_ms,
        )
    }

    pub fn is_partitioned(&self) -> bool {
        GovernancePolicy::is_partitioned(&self.policy)
    }

    pub fn note_partition_veto(&self, request: &ActionRequest, reason: &str, now_ms: i64) {
        GovernancePolicy::note_partition_veto(&self.policy, request, reason, now_ms);
    }

    pub fn drain_runtime_events(&self) -> Vec<GovernanceRuntimeEventRecord> {
        GovernancePolicy::drain_runtime_events(&self.policy)
            .into_iter()
            .map(governance_runtime_event_record)
            .collect()
    }

    /// Snapshot the authenticated policy's current governance health.
    pub fn status_report(&self) -> GovernanceStatusReport {
        GovernancePolicy::status_report(&self.policy)
    }

    /// Sign a release subject and serialize its consensus receipt for the runtime.
    pub fn attest_release(
        &self,
        subject: &serde_json::Value,
        now_ms: i64,
    ) -> Option<serde_json::Value> {
        let receipt = GovernancePolicy::attest_release(&self.policy, subject, now_ms)?;
        match serde_json::to_value(&receipt) {
            Ok(value) => Some(value),
            Err(error) => {
                tracing::warn!(
                    reason = %error,
                    module = module_path!(),
                    "governance release receipt could not be serialized; the release is recorded unattested"
                );
                None
            }
        }
    }

    /// Return the externally anchored governor identities trusted by this policy.
    pub fn governor_public_keys(&self) -> BTreeSet<AgentId> {
        GovernancePolicy::governor_public_keys(&self.policy)
    }
}

fn governance_runtime_event_record(event: GovernanceRuntimeEvent) -> GovernanceRuntimeEventRecord {
    let (governing_agent_id, action_kind) = match &event {
        GovernanceRuntimeEvent::PartitionStateTransition {
            governing_agent_id, ..
        } => (governing_agent_id.to_string(), "partition_state_transition"),
        GovernanceRuntimeEvent::PartitionReconciliation {
            governing_agent_id, ..
        } => (governing_agent_id.to_string(), "partition_reconciliation"),
    };

    GovernanceRuntimeEventRecord {
        governing_agent_id,
        role: AgentRole::Tom,
        action_kind: action_kind.to_string(),
        details: serde_json::to_value(&event).unwrap_or_else(|error| {
            serde_json::json!({
                "type": "serialization_error",
                "reason": error.to_string(),
            })
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        CLEANUP_POOL_BINDING_KIND, CLEANUP_POOL_BINDING_STREAM, CleanupMaintenanceCrashPoint,
        CleanupPoolBinding, CleanupPoolPhase, ConsumedGovernanceAuthorization,
        GOVERNANCE_CHECKPOINT_KIND, GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS,
        GOVERNANCE_CLEANUP_POOL_BINDING_NAME, GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME,
        GOVERNANCE_CLEANUP_POOL_DIR_NAME, GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME,
        GOVERNANCE_CLEANUP_POOL_LOCK_NAME, GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME,
        GOVERNANCE_CLEANUP_POOL_SLOT_COUNT, GOVERNANCE_STATE_KIND, GOVERNANCE_STATE_STREAM,
        GovernanceAuthorityError, GovernanceCleanupArtifactExpectation,
        GovernanceCleanupPoolMaintenanceMode, GovernanceCleanupPoolRetentionOutcome,
        GovernanceDecision, GovernanceKeyError, GovernanceLockRecord, GovernancePersistenceError,
        GovernancePolicy, GovernancePolicyConfig, GovernanceRuntimeEvent,
        GovernanceSequenceCheckpoint, InjectedAuthorityLockFailure, InjectedHealthCrashPoint,
        InjectedReinitializationCrashPoint, LocalGovernorKey, PartitionState,
        PendingGovernanceAuthorization, PendingHealthObservation, PersistedGovernanceState,
        QuarantineOutcome, REINITIALIZATION_JOURNAL_SCHEMA_VERSION, ReinitializationJournalPhase,
        ReinitializationRollbackJournal, TomAgent, acquire_cleanup_pool_slot,
        append_cleanup_pool_record, bind_authority_cleanup_parent, cleanup_pool_slot_name,
        inject_atomic_parent_sync_failure, inject_authority_lock_failure,
        inject_cleanup_maintenance_crash, inject_health_crash,
        inject_reinitialization_commit_journal_failure, inject_reinitialization_crash,
        install_authority_cleanup_barrier, install_authority_cleanup_final_absence_barrier,
        install_authority_cleanup_final_unlink_barrier,
        install_authority_cleanup_post_move_barrier, install_authority_cleanup_post_verify_barrier,
        install_authority_cleanup_pre_rename_barrier, install_authority_cleanup_reclaim_barrier,
        install_authority_cleanup_source_final_barrier, install_cleanup_maintenance_move_barrier,
        install_governance_stream_cleanup_barrier, install_reinitialization_archive_barrier,
        install_reinitialization_publication_barrier,
        install_reinitialization_restore_link_barrier, lock_authority_cleanup_tests,
        quarantine_verified_entry,
    };
    use ed25519_dalek::SigningKey;
    use serde::Serialize;
    use serde_json::json;
    use std::fs;
    use std::io::{Seek, SeekFrom, Write};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use swarm_consensus::{
        ConsensusCommittee, ConsensusError, ConsensusSignedEnvelope, ConsensusTransport,
    };
    use swarm_core::agent::{
        AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode,
    };
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity, SwarmAction};
    use swarm_core::{SignedStateEnvelope, SignedStateExpectation};
    use swarm_crypto::Ed25519Signer;
    use swarm_policy::ActionRequest;
    use swarm_runtime::approval::{
        DefaultApprovalHarness, ThresholdRule, approval_set_digest, build_receipt_pack,
        evaluate_verdict, verify_governed_human_receipt_pack,
    };

    fn persistence_path(label: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "swarm-governance-auth-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        directory.join("state.json")
    }

    struct BarrierReleaseGuard(Option<Arc<std::sync::Barrier>>);

    impl BarrierReleaseGuard {
        fn new(barrier: Arc<std::sync::Barrier>) -> Self {
            Self(Some(barrier))
        }

        fn release(&mut self) {
            if let Some(barrier) = self.0.take() {
                barrier.wait();
            }
        }
    }

    impl Drop for BarrierReleaseGuard {
        fn drop(&mut self) {
            self.release();
        }
    }

    fn initialize_signed_policy(path: &Path, key: &SigningKey) -> GovernancePolicy {
        GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        )
        .unwrap()
    }

    #[test]
    fn only_an_authenticated_persisted_policy_mints_an_authority_handle() {
        let unpersisted = Arc::new(GovernancePolicy::new(GovernancePolicyConfig::default()));
        assert!(matches!(
            unpersisted.authority(),
            Err(super::GovernanceAuthorityError::Unpersisted)
        ));

        let path = persistence_path("authenticated-authority-handle");
        let key = SigningKey::from_bytes(&[162; 32]);
        let persisted = Arc::new(initialize_signed_policy(&path, &key));
        let authority = persisted
            .authority()
            .expect("signed state, permanent lock, and admitted local key are authenticated");
        let cloned = authority.clone();
        assert!(authority.same_policy(&cloned));
        assert_eq!(authority.identity(), cloned.identity());

        drop(authority);
        drop(cloned);
        drop(persisted);
        cleanup_persistence(&path);
    }

    fn cleanup_pool_path(path: &Path) -> PathBuf {
        path.parent()
            .unwrap()
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME)
    }

    fn cleanup_pool_binding_path(path: &Path) -> PathBuf {
        cleanup_pool_path(path).join(GOVERNANCE_CLEANUP_POOL_BINDING_NAME)
    }

    fn cleanup_expectation(path: &Path) -> GovernanceCleanupArtifactExpectation {
        let snapshot = super::read_governance_artifact_snapshot(path)
            .unwrap()
            .unwrap()
            .0;
        GovernanceCleanupArtifactExpectation {
            device: snapshot.identity.device,
            inode: snapshot.identity.inode,
            content_digest: snapshot.content_digest,
            byte_len: snapshot.byte_len,
        }
    }

    fn read_cleanup_pool_binding_envelope(path: &Path) -> SignedStateEnvelope<CleanupPoolBinding> {
        serde_json::from_slice(&fs::read(cleanup_pool_binding_path(path)).unwrap()).unwrap()
    }

    fn write_cleanup_pool_binding_envelope(
        path: &Path,
        envelope: &SignedStateEnvelope<CleanupPoolBinding>,
    ) {
        fs::write(
            cleanup_pool_binding_path(path),
            serde_json::to_vec_pretty(envelope).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn cleanup_pool_binding_copies_are_authenticated_and_fixed_cardinality() {
        let path = persistence_path("cleanup-pool-binding-copies");
        let key = SigningKey::from_bytes(&[163; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let state: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        let checkpoint: GovernanceSequenceCheckpoint =
            serde_json::from_str(&read_checkpoint(&path).statement.payload_json).unwrap();
        let pool_envelope = read_cleanup_pool_binding_envelope(&path);
        let pool = pool_envelope
            .verify(SignedStateExpectation {
                state_kind: CLEANUP_POOL_BINDING_KIND,
                stream_id: CLEANUP_POOL_BINDING_STREAM,
                expected_signer_agent_id: Some(&AgentId::from_verifying_key(&key.verifying_key())),
                accepted_sequence: Some(1),
            })
            .unwrap();
        assert_eq!(state.cleanup_pool_binding, checkpoint.cleanup_pool_binding);
        assert_eq!(state.cleanup_pool_binding, pool.payload);
        assert_eq!(
            state.cleanup_pool_binding.slot_count,
            GOVERNANCE_CLEANUP_POOL_SLOT_COUNT
        );
        assert_eq!(
            state.cleanup_pool_binding.slot_names.len(),
            GOVERNANCE_CLEANUP_POOL_SLOT_COUNT
        );
        assert_eq!(state.cleanup_pool_binding.generation_id.len(), 64);
        assert_eq!(pool_envelope.sequence(), 1);
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_directory_replacement_across_restart_is_fail_closed_without_touching_either_tree()
     {
        let path = persistence_path("cleanup-pool-replacement-restart");
        let key = SigningKey::from_bytes(&[164; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let pool = cleanup_pool_path(&path);
        let old_pool = pool.with_file_name(".governance-cleanup-pool.old");
        fs::rename(&pool, &old_pool).unwrap();
        fs::create_dir(&pool).unwrap();
        let marker = pool.join("foreign-marker");
        fs::write(&marker, b"replacement-tree").unwrap();
        let old_binding = old_pool.join(GOVERNANCE_CLEANUP_POOL_BINDING_NAME);
        assert!(old_binding.exists());
        let error =
            load_signed_policy(&path, &key).expect_err("replacement pool must refuse startup");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"replacement-tree");
        assert!(old_binding.exists());
        fs::remove_file(&marker).unwrap();
        fs::remove_dir(&pool).unwrap();
        fs::rename(old_pool, pool).unwrap();
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_lock_inode_replacement_across_restart_is_fail_closed_without_touching_replacement()
     {
        let path = persistence_path("cleanup-pool-lock-replacement-restart");
        let key = SigningKey::from_bytes(&[165; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let pool = cleanup_pool_path(&path);
        let lock = pool.join(GOVERNANCE_CLEANUP_POOL_LOCK_NAME);
        let old_lock = pool.join("lock.old");
        fs::rename(&lock, &old_lock).unwrap();
        let replacement = b"foreign-lock-replacement";
        fs::write(&lock, replacement).unwrap();
        let error =
            load_signed_policy(&path, &key).expect_err("replacement lock must refuse startup");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&lock).unwrap(), replacement);
        assert!(old_lock.exists());
        fs::remove_file(&lock).unwrap();
        fs::rename(old_lock, lock).unwrap();
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_missing_or_unsigned_binding_refuses_restart_without_recreating_it() {
        let path = persistence_path("cleanup-pool-binding-refusal");
        let key = SigningKey::from_bytes(&[166; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let binding = cleanup_pool_binding_path(&path);
        let original = fs::read(&binding).unwrap();
        fs::remove_file(&binding).unwrap();
        let error = load_signed_policy(&path, &key).expect_err("missing binding must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert!(
            !binding.exists(),
            "ordinary load must not recreate a missing binding"
        );
        fs::write(&binding, b"unsigned binding").unwrap();
        let error = load_signed_policy(&path, &key).expect_err("unsigned binding must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&binding).unwrap(), b"unsigned binding");
        fs::write(&binding, original).unwrap();
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_state_checkpoint_binding_disagreement_refuses_restart_without_repair() {
        let path = persistence_path("cleanup-pool-state-checkpoint-disagreement");
        let key = SigningKey::from_bytes(&[167; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let mut state_envelope = read_envelope(&path);
        let state_before = serde_json::to_vec_pretty(&state_envelope).unwrap();
        let mut state: PersistedGovernanceState =
            serde_json::from_str(&state_envelope.statement.payload_json).unwrap();
        let mut generation = state
            .cleanup_pool_binding
            .generation_id
            .clone()
            .into_bytes();
        generation[0] = if generation[0] == b'0' { b'1' } else { b'0' };
        state.cleanup_pool_binding.generation_id = String::from_utf8(generation).unwrap();
        state_envelope = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            state_envelope.sequence(),
            state,
            &key,
        )
        .unwrap();
        write_envelope(&path, &state_envelope);
        let error = load_signed_policy(&path, &key)
            .expect_err("divergent signed bindings must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(
            fs::read(&path).unwrap(),
            serde_json::to_vec_pretty(&state_envelope).unwrap()
        );
        assert_ne!(fs::read(&path).unwrap(), state_before);
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_generation_change_refuses_restart_without_touching_signed_streams() {
        let path = persistence_path("cleanup-pool-generation-change");
        let key = SigningKey::from_bytes(&[168; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let state_before = fs::read(&path).unwrap();
        let checkpoint_path = GovernancePolicy::persistence_sequence_path(&path);
        let checkpoint_before = fs::read(&checkpoint_path).unwrap();
        let mut pool_envelope = read_cleanup_pool_binding_envelope(&path);
        let mut binding: CleanupPoolBinding =
            serde_json::from_str(&pool_envelope.statement.payload_json).unwrap();
        let mut generation = binding.generation_id.clone().into_bytes();
        generation[1] = if generation[1] == b'0' { b'1' } else { b'0' };
        binding.generation_id = String::from_utf8(generation).unwrap();
        pool_envelope = SignedStateEnvelope::sign(
            CLEANUP_POOL_BINDING_KIND,
            CLEANUP_POOL_BINDING_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            1,
            binding,
            &key,
        )
        .unwrap();
        write_cleanup_pool_binding_envelope(&path, &pool_envelope);
        let error =
            load_signed_policy(&path, &key).expect_err("generation replacement must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), state_before);
        assert_eq!(fs::read(&checkpoint_path).unwrap(), checkpoint_before);
        cleanup_persistence(&path);
    }

    #[test]
    fn legacy_signed_stream_without_cleanup_pool_binding_refuses_ordinary_load() {
        let path = persistence_path("legacy-without-cleanup-pool-binding");
        let key = SigningKey::from_bytes(&[169; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let state = read_envelope(&path);
        let mut state_payload: serde_json::Value =
            serde_json::from_str(&state.statement.payload_json).unwrap();
        state_payload
            .as_object_mut()
            .unwrap()
            .remove("cleanup_pool_binding");
        let legacy_state = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            state.sequence(),
            state_payload,
            &key,
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&legacy_state).unwrap()).unwrap();
        let checkpoint = read_checkpoint(&path);
        let mut checkpoint_payload: serde_json::Value =
            serde_json::from_str(&checkpoint.statement.payload_json).unwrap();
        checkpoint_payload
            .as_object_mut()
            .unwrap()
            .remove("cleanup_pool_binding");
        let legacy_checkpoint = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            checkpoint.sequence(),
            checkpoint_payload,
            &key,
        )
        .unwrap();
        write_checkpoint_value(&path, &legacy_checkpoint);
        let error = load_signed_policy(&path, &key)
            .expect_err("legacy signed stream must require migration");
        assert!(matches!(
            error,
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::DecodePayload { .. }
            )
        ));
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn live_cleanup_pool_path_replacement_refuses_authority_without_touching_foreign_tree() {
        let path = persistence_path("live-cleanup-pool-replacement");
        let key = SigningKey::from_bytes(&[170; 32]);
        let policy = Arc::new(initialize_signed_policy(&path, &key));
        let pool = cleanup_pool_path(&path);
        let old_pool = pool.with_file_name(".governance-cleanup-pool.live-old");
        fs::rename(&pool, &old_pool).unwrap();
        fs::create_dir(&pool).unwrap();
        let marker = pool.join("foreign-live-marker");
        fs::write(&marker, b"must-survive").unwrap();
        let error = policy
            .authority()
            .expect_err("live pool replacement must veto authority");
        assert!(matches!(
            error,
            GovernanceAuthorityError::Persistence(
                GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
            )
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"must-survive");
        fs::remove_file(&marker).unwrap();
        fs::remove_dir(&pool).unwrap();
        fs::rename(old_pool, pool).unwrap();
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_drain_moves_terminal_slot_and_reopens_capacity() {
        let path = persistence_path("cleanup-maintenance-drain");
        let key = SigningKey::from_bytes(&[231; 32]);
        let artifact = path.with_file_name("cleanup-maintenance-artifact");
        fs::write(&artifact, b"terminal cleanup material").unwrap();
        assert!(matches!(
            quarantine_verified_entry(&artifact, || true, |_| true),
            QuarantineOutcome::Retained
        ));
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let report = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
            guard,
            "cleanup-maintenance-archive",
        )
        .unwrap();
        assert_eq!(report.mode, GovernanceCleanupPoolMaintenanceMode::Drain);
        assert_eq!(report.moved_slots.len(), 1);
        assert!(report.opaque_slots.is_empty());
        assert!(report.archive_path.join(&report.moved_slots[0]).exists());
        let pool = cleanup_pool_path(&path);
        assert!(!pool.join(&report.moved_slots[0]).exists());

        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let second = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            guard,
            "cleanup-maintenance-archive-2",
        )
        .unwrap();
        assert!(second.moved_slots.is_empty());
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
        let _ = fs::remove_dir_all(report.archive_path);
        let _ = fs::remove_dir_all(second.archive_path);
    }

    #[test]
    fn cleanup_pool_maintenance_guard_reports_live_policy_contention_without_archive() {
        let path = persistence_path("cleanup-maintenance-live-contention");
        let key = SigningKey::from_bytes(&[232; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let archive = path
            .parent()
            .unwrap()
            .join("cleanup-maintenance-live-archive");
        let error = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path)
            .expect_err("a live policy must hold the authority sidecar");
        assert!(matches!(
            error,
            GovernancePersistenceError::MaintenanceBusy { .. }
        ));
        assert!(!archive.exists());
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_maintenance_crash_points_refuse_ordinary_restart_and_resume() {
        let points = [
            ("prepared", CleanupMaintenanceCrashPoint::Prepared),
            ("after-move", CleanupMaintenanceCrashPoint::AfterMove(1)),
            (
                "before-completed",
                CleanupMaintenanceCrashPoint::BeforeCompleted,
            ),
        ];
        for (index, (label, point)) in points.into_iter().enumerate() {
            let path = persistence_path(&format!("cleanup-maintenance-crash-{label}"));
            let key = SigningKey::from_bytes(&[233 + index as u8; 32]);
            let artifact =
                path.with_file_name(format!("cleanup-maintenance-crash-artifact-{label}"));
            fs::write(&artifact, b"crash-recovery cleanup material").unwrap();
            assert!(matches!(
                quarantine_verified_entry(&artifact, || true, |_| true),
                QuarantineOutcome::Retained
            ));
            let policy = initialize_signed_policy(&path, &key);
            drop(policy);
            inject_cleanup_maintenance_crash(&path, point);
            let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
            let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = GovernancePolicy::drain_cleanup_pool(
                    &path,
                    AgentId::from_verifying_key(&key.verifying_key()),
                    key.clone(),
                    guard,
                    "cleanup-maintenance-crash-archive",
                );
            }));
            assert!(
                crashed.is_err(),
                "injected maintenance crash must fire: {label}"
            );
            let ordinary = load_signed_policy(&path, &key);
            assert!(matches!(
                ordinary,
                Err(GovernancePersistenceError::CleanupMaintenanceJournal { .. })
            ));
            let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
            let report = GovernancePolicy::drain_cleanup_pool(
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
                guard,
                "cleanup-maintenance-crash-archive",
            )
            .unwrap();
            assert_eq!(report.moved_slots.len(), 1);
            assert!(report.archive_path.join(&report.moved_slots[0]).exists());
            cleanup_persistence(&path);
            let _ = fs::remove_file(artifact);
            let _ = fs::remove_dir_all(report.archive_path);
        }
    }

    #[test]
    fn cleanup_pool_drain_refuses_malformed_slot_before_archive_mutation() {
        let path = persistence_path("cleanup-maintenance-drain-malformed");
        let key = SigningKey::from_bytes(&[236; 32]);
        let artifact = path.with_file_name("cleanup-maintenance-malformed-artifact");
        fs::write(&artifact, b"malformed cleanup material").unwrap();
        assert!(matches!(
            quarantine_verified_entry(&artifact, || true, |_| true),
            QuarantineOutcome::Retained
        ));
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let slot_journal = cleanup_pool_path(&path)
            .join("slot-00")
            .join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        fs::write(&slot_journal, b"tampered maintenance slot").unwrap();
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            guard,
            "cleanup-maintenance-malformed-archive",
        )
        .expect_err("drain must preflight malformed slots");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupMaintenanceJournal { .. }
        ));
        assert!(
            !path
                .parent()
                .unwrap()
                .join("cleanup-maintenance-malformed-archive")
                .exists()
        );
        assert_eq!(
            fs::read(&slot_journal).unwrap(),
            b"tampered maintenance slot"
        );
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn cleanup_pool_reset_archives_malformed_slot_opaquely_and_reopens_capacity() {
        let path = persistence_path("cleanup-maintenance-reset-malformed");
        let key = SigningKey::from_bytes(&[237; 32]);
        let artifact = path.with_file_name("cleanup-maintenance-reset-artifact");
        fs::write(&artifact, b"opaque cleanup material").unwrap();
        assert!(matches!(
            quarantine_verified_entry(&artifact, || true, |_| true),
            QuarantineOutcome::Retained
        ));
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let slot_journal = cleanup_pool_path(&path)
            .join("slot-00")
            .join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        fs::write(&slot_journal, b"opaque malformed bytes").unwrap();
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let report = GovernancePolicy::reset_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
            guard,
            "cleanup-maintenance-reset-archive",
        )
        .unwrap();
        assert_eq!(report.moved_slots, vec!["slot-00".to_string()]);
        assert_eq!(report.opaque_slots, vec!["slot-00".to_string()]);
        assert_eq!(
            fs::read(
                report
                    .archive_path
                    .join("slot-00")
                    .join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME)
            )
            .unwrap(),
            b"opaque malformed bytes"
        );
        let second_artifact = path.with_file_name("cleanup-maintenance-reset-second-artifact");
        fs::write(&second_artifact, b"new capacity material").unwrap();
        assert!(matches!(
            quarantine_verified_entry(&second_artifact, || true, |_| true),
            QuarantineOutcome::Retained
        ));
        assert!(cleanup_pool_path(&path).join("slot-00").exists());
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
        let _ = fs::remove_file(second_artifact);
        let _ = fs::remove_dir_all(report.archive_path);
    }

    #[test]
    fn preconstruction_retention_guard_authenticates_existing_stream() {
        let path = persistence_path("cleanup-preconstruction-existing");
        let key = SigningKey::from_bytes(&[250; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let artifact = path.with_file_name("cleanup-preconstruction-existing-artifact");
        fs::write(&artifact, b"preconstruction existing material").unwrap();
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let guard = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent.clone(),
            key.clone(),
        )
        .unwrap();
        assert!(matches!(
            guard.retain_cleanup_artifact(&artifact, cleanup_expectation(&artifact)),
            Ok(GovernanceCleanupPoolRetentionOutcome::Retained)
        ));
        drop(guard);
        assert!(!artifact.exists());
        let reopened = load_signed_policy(&path, &key).unwrap();
        drop(reopened);
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn preconstruction_fresh_retention_binding_is_adopted_by_initialize() {
        let path = persistence_path("cleanup-preconstruction-fresh");
        let key = SigningKey::from_bytes(&[251; 32]);
        let artifact = path.with_file_name("cleanup-preconstruction-fresh-artifact");
        fs::write(&artifact, b"preconstruction fresh material").unwrap();
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let guard = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent.clone(),
            key.clone(),
        )
        .unwrap();
        let binding_before = read_cleanup_pool_binding_envelope(&path)
            .verify(SignedStateExpectation {
                state_kind: CLEANUP_POOL_BINDING_KIND,
                stream_id: CLEANUP_POOL_BINDING_STREAM,
                expected_signer_agent_id: Some(&agent),
                accepted_sequence: Some(1),
            })
            .unwrap()
            .payload;
        assert!(matches!(
            guard.retain_cleanup_artifact(&artifact, cleanup_expectation(&artifact)),
            Ok(GovernanceCleanupPoolRetentionOutcome::Retained)
        ));
        drop(guard);
        let policy = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            agent.clone(),
            key.clone(),
        )
        .unwrap();
        let state: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert_eq!(state.cleanup_pool_binding, binding_before);
        drop(policy);
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn preconstruction_retention_guard_requires_both_anchors_and_rejects_legacy_mixed_state() {
        let path = persistence_path("cleanup-preconstruction-mixed");
        let key = SigningKey::from_bytes(&[252; 32]);
        fs::write(&path, b"legacy unsigned state").unwrap();
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let error = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent,
            key,
        )
        .expect_err("mixed/legacy state must fail before pool creation");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert!(!cleanup_pool_path(&path).exists());
        cleanup_persistence(&path);
    }

    #[test]
    fn preconstruction_retention_guard_rejects_missing_checkpoint_without_touching_pool() {
        let path = persistence_path("cleanup-preconstruction-missing-checkpoint");
        let key = SigningKey::from_bytes(&[253; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence = GovernancePolicy::persistence_sequence_path(&path);
        let sequence_bytes = fs::read(&sequence).unwrap();
        fs::remove_file(&sequence).unwrap();
        let pool_before = fs::read_dir(cleanup_pool_path(&path)).unwrap().count();
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let error = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent,
            key,
        )
        .expect_err("missing checkpoint must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(
            fs::read_dir(cleanup_pool_path(&path)).unwrap().count(),
            pool_before
        );
        fs::write(sequence, sequence_bytes).unwrap();
        cleanup_persistence(&path);
    }

    #[test]
    fn preconstruction_retention_guard_rejects_replaced_pool_without_touching_replacement() {
        let path = persistence_path("cleanup-preconstruction-replaced-pool");
        let key = SigningKey::from_bytes(&[254; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let pool = cleanup_pool_path(&path);
        let old_pool = pool.with_file_name(".cleanup-preconstruction-old-pool");
        let _ = fs::remove_dir_all(&old_pool);
        fs::rename(&pool, &old_pool).unwrap();
        fs::create_dir(&pool).unwrap();
        let marker = pool.join("replacement-marker");
        fs::write(&marker, b"replacement survives").unwrap();
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let error = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent,
            key,
        )
        .expect_err("replaced pool must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"replacement survives");
        fs::remove_file(marker).unwrap();
        fs::remove_dir(&pool).unwrap();
        fs::rename(old_pool, pool).unwrap();
        cleanup_persistence(&path);
    }

    #[test]
    fn preconstruction_retention_guard_pool_lock_contention_is_typed_and_preserves_source() {
        let path = persistence_path("cleanup-preconstruction-pool-contention");
        let key = SigningKey::from_bytes(&[255; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let lock_path = cleanup_pool_path(&path).join(GOVERNANCE_CLEANUP_POOL_LOCK_NAME);
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        held.try_lock().unwrap();
        let artifact = path.with_file_name("cleanup-preconstruction-pool-contention-artifact");
        fs::write(&artifact, b"pool contention source").unwrap();
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let error = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent,
            key,
        )
        .expect_err("pool lock contention must be typed");
        assert!(matches!(
            error,
            GovernancePersistenceError::MaintenanceBusy { .. }
        ));
        assert!(artifact.exists());
        drop(held);
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn preconstruction_retention_guard_drop_allows_initialize_constructor() {
        let path = persistence_path("cleanup-preconstruction-drop-constructor");
        let key = SigningKey::from_bytes(&[1; 32]);
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let guard = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent.clone(),
            key.clone(),
        )
        .unwrap();
        drop(guard);
        let policy = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            agent,
            key,
        )
        .unwrap();
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn preconstruction_retention_guard_rejects_wrong_signer_before_pool_mutation() {
        let path = persistence_path("cleanup-preconstruction-wrong-signer");
        let key = SigningKey::from_bytes(&[2; 32]);
        let wrong_key = SigningKey::from_bytes(&[3; 32]);
        let agent = AgentId::from_verifying_key(&key.verifying_key());
        let error = GovernancePolicy::acquire_cleanup_pool_retention_guard(
            &path,
            agent.clone(),
            agent,
            wrong_key,
        )
        .expect_err("wrong signer must fail before fresh pool creation");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert!(!cleanup_pool_path(&path).exists());
        cleanup_persistence(&path);
    }

    #[test]
    fn normal_retention_uses_authenticated_fixed_pool_and_returns_terminal_outcome() {
        let path = persistence_path("cleanup-pool-normal-retention");
        let key = SigningKey::from_bytes(&[236; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let artifact = path.with_file_name("normal-retention-artifact");
        fs::write(&artifact, b"normal-operation cleanup material").unwrap();
        let snapshot = super::read_governance_artifact_snapshot(&artifact)
            .unwrap()
            .unwrap()
            .0;
        let expected = GovernanceCleanupArtifactExpectation {
            device: snapshot.identity.device,
            inode: snapshot.identity.inode,
            content_digest: snapshot.content_digest,
            byte_len: snapshot.byte_len,
        };
        assert!(matches!(
            policy.retain_cleanup_artifact(&artifact, expected),
            Ok(GovernanceCleanupPoolRetentionOutcome::Retained)
        ));
        assert!(
            !artifact.exists(),
            "retained source must leave canonical name absent"
        );
        let pool = cleanup_pool_path(&path);
        let slot_count = fs::read_dir(&pool)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("slot-"))
            .count();
        assert_eq!(slot_count, 1);
        drop(policy);
        let reopened = load_signed_policy(&path, &key).unwrap();
        assert!(Arc::new(reopened).authority().is_ok());
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn normal_retention_rejects_wrong_expectation_without_reserving_slot() {
        let path = persistence_path("cleanup-pool-normal-retention-mismatch");
        let key = SigningKey::from_bytes(&[237; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let artifact = path.with_file_name("normal-retention-mismatch-artifact");
        fs::write(&artifact, b"actual cleanup material").unwrap();
        let snapshot = super::read_governance_artifact_snapshot(&artifact)
            .unwrap()
            .unwrap()
            .0;
        let expected = GovernanceCleanupArtifactExpectation {
            device: snapshot.identity.device,
            inode: snapshot.identity.inode,
            content_digest: "0".repeat(64),
            byte_len: snapshot.byte_len,
        };
        assert!(matches!(
            policy.retain_cleanup_artifact(&artifact, expected),
            Ok(GovernanceCleanupPoolRetentionOutcome::Uncertain)
        ));
        assert!(artifact.exists());
        let pool = cleanup_pool_path(&path);
        assert_eq!(
            fs::read_dir(&pool)
                .unwrap()
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("slot-"))
                .count(),
            0
        );
        drop(policy);
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn normal_retention_reports_pool_exhaustion_without_unbounded_growth() {
        let path = persistence_path("cleanup-pool-normal-retention-exhaustion");
        let key = SigningKey::from_bytes(&[238; 32]);
        let mut artifacts = Vec::new();
        for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
            let artifact = path.with_file_name(format!("normal-retention-exhaustion-{index}"));
            fs::write(&artifact, format!("retained-{index}")).unwrap();
            assert!(matches!(
                quarantine_verified_entry(&artifact, || true, |_| true),
                QuarantineOutcome::Retained
            ));
            artifacts.push(artifact);
        }
        let policy = initialize_signed_policy(&path, &key);
        let extra = path.with_file_name("normal-retention-exhaustion-extra");
        fs::write(&extra, b"extra retained material").unwrap();
        let snapshot = super::read_governance_artifact_snapshot(&extra)
            .unwrap()
            .unwrap()
            .0;
        let expected = GovernanceCleanupArtifactExpectation {
            device: snapshot.identity.device,
            inode: snapshot.identity.inode,
            content_digest: snapshot.content_digest,
            byte_len: snapshot.byte_len,
        };
        assert!(matches!(
            policy.retain_cleanup_artifact(&extra, expected),
            Ok(GovernanceCleanupPoolRetentionOutcome::PoolExhausted)
        ));
        assert!(extra.exists());
        let pool = cleanup_pool_path(&path);
        assert_eq!(
            fs::read_dir(&pool)
                .unwrap()
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("slot-"))
                .count(),
            GOVERNANCE_CLEANUP_POOL_SLOT_COUNT
        );
        drop(policy);
        cleanup_persistence(&path);
        for artifact in artifacts {
            let _ = fs::remove_file(artifact);
        }
        let _ = fs::remove_file(extra);
    }

    #[test]
    fn cleanup_pool_reset_reopens_all_fixed_slots_for_normal_retention() {
        let path = persistence_path("cleanup-pool-reset-full-capacity");
        let key = SigningKey::from_bytes(&[246; 32]);
        let mut old_artifacts = Vec::new();
        for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
            let artifact = path.with_file_name(format!("cleanup-reset-old-{index}"));
            fs::write(&artifact, format!("old retained material {index}")).unwrap();
            assert!(matches!(
                quarantine_verified_entry(&artifact, || true, |_| true),
                QuarantineOutcome::Retained
            ));
            old_artifacts.push(artifact);
        }
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let report = GovernancePolicy::reset_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
            guard,
            "cleanup-reset-full-capacity-archive",
        )
        .unwrap();
        assert_eq!(report.moved_slots.len(), GOVERNANCE_CLEANUP_POOL_SLOT_COUNT);
        assert!(report.opaque_slots.is_empty());
        let pool = cleanup_pool_path(&path);
        for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
            assert!(!pool.join(cleanup_pool_slot_name(index)).exists());
        }
        let policy = load_signed_policy(&path, &key).unwrap();
        let mut new_artifacts = Vec::new();
        for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
            let artifact = path.with_file_name(format!("cleanup-reset-new-{index}"));
            fs::write(&artifact, format!("new retained material {index}")).unwrap();
            let snapshot = super::read_governance_artifact_snapshot(&artifact)
                .unwrap()
                .unwrap()
                .0;
            let expected = GovernanceCleanupArtifactExpectation {
                device: snapshot.identity.device,
                inode: snapshot.identity.inode,
                content_digest: snapshot.content_digest,
                byte_len: snapshot.byte_len,
            };
            assert!(matches!(
                policy.retain_cleanup_artifact(&artifact, expected),
                Ok(GovernanceCleanupPoolRetentionOutcome::Retained)
            ));
            new_artifacts.push(artifact);
        }
        drop(policy);
        cleanup_persistence(&path);
        for artifact in old_artifacts.into_iter().chain(new_artifacts) {
            let _ = fs::remove_file(artifact);
        }
    }

    #[test]
    fn cleanup_pool_maintenance_rejects_archive_collision_and_second_guard() {
        let path = persistence_path("cleanup-maintenance-archive-collision");
        let key = SigningKey::from_bytes(&[239; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let first = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let second = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path)
            .expect_err("only one maintenance guard may hold the authority sidecar");
        assert!(matches!(
            second,
            GovernancePersistenceError::MaintenanceBusy { .. }
        ));
        let archive = path.parent().unwrap().join("cleanup-maintenance-existing");
        fs::create_dir(&archive).unwrap();
        let marker = archive.join("foreign");
        fs::write(&marker, b"must survive").unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            first,
            "cleanup-maintenance-existing",
        )
        .expect_err("preexisting archive must fail before mutation");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupMaintenanceArchive { .. }
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"must survive");
        cleanup_persistence(&path);
        let _ = fs::remove_dir_all(archive);
    }

    #[test]
    fn cleanup_pool_maintenance_simultaneous_guard_acquisition_has_one_winner() {
        let path = persistence_path("cleanup-maintenance-simultaneous-guard");
        let key = SigningKey::from_bytes(&[247; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let start = Arc::new(std::sync::Barrier::new(3));
        let first_path = path.clone();
        let first_start = Arc::clone(&start);
        let first = std::thread::spawn(move || {
            first_start.wait();
            GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&first_path)
        });
        let second_path = path.clone();
        let second_start = Arc::clone(&start);
        let second = std::thread::spawn(move || {
            second_start.wait();
            GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&second_path)
        });
        start.wait();
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        match (first, second) {
            (Ok(guard), Err(error)) | (Err(error), Ok(guard)) => {
                drop(guard);
                assert!(matches!(
                    error,
                    GovernancePersistenceError::MaintenanceBusy { .. }
                ));
            }
            (Ok(_), Ok(_)) => panic!("two concurrent maintenance guards won"),
            (Err(first), Err(second)) => {
                panic!("both concurrent maintenance guards failed: {first}; {second}")
            }
        }
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_maintenance_pool_lock_contention_is_typed_and_pre_archive() {
        let path = persistence_path("cleanup-maintenance-pool-lock-contention");
        let key = SigningKey::from_bytes(&[248; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let lock_path = cleanup_pool_path(&path).join(GOVERNANCE_CLEANUP_POOL_LOCK_NAME);
        let held_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        held_lock.try_lock().unwrap();
        let archive_name = "cleanup-maintenance-pool-lock-contention-archive";
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            guard,
            archive_name,
        )
        .expect_err("pool-lock contention must fail before archive creation");
        assert!(matches!(
            error,
            GovernancePersistenceError::MaintenanceBusy { .. }
        ));
        assert!(!path.parent().unwrap().join(archive_name).exists());
        drop(held_lock);
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_maintenance_state_lock_contention_is_typed_and_pre_archive() {
        let path = persistence_path("cleanup-maintenance-state-lock-contention");
        let key = SigningKey::from_bytes(&[249; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let state_lock_path = GovernancePolicy::persistence_lock_path(&path);
        let held_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&state_lock_path)
            .unwrap();
        held_lock.try_lock().unwrap();
        let archive_name = "cleanup-maintenance-state-lock-contention-archive";
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            guard,
            archive_name,
        )
        .expect_err("state-lock contention must fail before archive creation");
        assert!(matches!(
            error,
            GovernancePersistenceError::MaintenanceBusy { .. }
        ));
        assert!(!path.parent().unwrap().join(archive_name).exists());
        drop(held_lock);
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_maintenance_archive_slot_collision_preserves_foreign_destination() {
        let _test_lock = lock_authority_cleanup_tests();
        let path = persistence_path("cleanup-maintenance-archive-slot-collision");
        let key = SigningKey::from_bytes(&[244; 32]);
        let artifact = path.with_file_name("cleanup-maintenance-slot-artifact");
        fs::write(&artifact, b"terminal cleanup slot material").unwrap();
        assert!(matches!(
            quarantine_verified_entry(&artifact, || true, |_| true),
            QuarantineOutcome::Retained
        ));
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let archive_name = "cleanup-maintenance-archive-slot-collision-destination";
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let (reached, resume) =
            install_cleanup_maintenance_move_barrier(&cleanup_pool_path(&path), "slot-00");
        let operation_path = path.clone();
        let operation_key = key.clone();
        let operation = std::thread::spawn(move || {
            GovernancePolicy::drain_cleanup_pool(
                &operation_path,
                AgentId::from_verifying_key(&operation_key.verifying_key()),
                operation_key,
                guard,
                archive_name,
            )
        });
        reached.wait();
        let archive = path.parent().unwrap().join(archive_name);
        let foreign_slot = archive.join("slot-00");
        fs::create_dir(&foreign_slot).unwrap();
        let marker = foreign_slot.join("foreign-marker");
        fs::write(&marker, b"foreign archive destination").unwrap();
        resume.wait();
        let error = operation
            .join()
            .unwrap()
            .expect_err("no-replace archive publication must refuse a foreign slot");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupMaintenance { .. }
                | GovernancePersistenceError::CleanupMaintenanceArchive { .. }
                | GovernancePersistenceError::CleanupMaintenanceJournal { .. }
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"foreign archive destination");
        assert!(cleanup_pool_path(&path).join("slot-00").exists());
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[test]
    fn cleanup_pool_maintenance_held_parent_retarget_fails_closed_and_preserves_replacement() {
        let _test_lock = lock_authority_cleanup_tests();
        let path = persistence_path("cleanup-maintenance-parent-retarget");
        let key = SigningKey::from_bytes(&[245; 32]);
        let artifact = path.with_file_name("cleanup-maintenance-parent-artifact");
        fs::write(&artifact, b"parent-retarget material").unwrap();
        assert!(matches!(
            quarantine_verified_entry(&artifact, || true, |_| true),
            QuarantineOutcome::Retained
        ));
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let archive_name = "cleanup-maintenance-parent-retarget-archive";
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let (reached, resume) =
            install_cleanup_maintenance_move_barrier(&cleanup_pool_path(&path), "slot-00");
        let operation_path = path.clone();
        let operation_key = key.clone();
        let operation = std::thread::spawn(move || {
            GovernancePolicy::drain_cleanup_pool(
                &operation_path,
                AgentId::from_verifying_key(&operation_key.verifying_key()),
                operation_key,
                guard,
                archive_name,
            )
        });
        reached.wait();
        let original_parent = path.parent().unwrap().to_path_buf();
        let moved_parent = original_parent.with_file_name(".cleanup-parent-retarget-old");
        let _ = fs::remove_dir_all(&moved_parent);
        fs::rename(&original_parent, &moved_parent).unwrap();
        fs::create_dir(&original_parent).unwrap();
        let marker = original_parent.join("foreign-parent-marker");
        fs::write(&marker, b"replacement parent survives").unwrap();
        resume.wait();
        let error = operation
            .join()
            .unwrap()
            .expect_err("parent retarget must fail before slot move");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"replacement parent survives");
        assert!(moved_parent.join(GOVERNANCE_CLEANUP_POOL_DIR_NAME).exists());
        fs::remove_file(marker).unwrap();
        fs::remove_dir(&original_parent).unwrap();
        fs::rename(&moved_parent, &original_parent).unwrap();
        cleanup_persistence(&path);
        let _ = fs::remove_file(artifact);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_maintenance_rejects_archive_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let path = persistence_path("cleanup-maintenance-archive-symlink");
        let key = SigningKey::from_bytes(&[240; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let archive_target = path.parent().unwrap().join("cleanup-maintenance-target");
        fs::create_dir(&archive_target).unwrap();
        let marker = archive_target.join("foreign");
        fs::write(&marker, b"target survives").unwrap();
        let archive_link = path.parent().unwrap().join("cleanup-maintenance-link");
        symlink(&archive_target, &archive_link).unwrap();
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            guard,
            "cleanup-maintenance-link",
        )
        .expect_err("symlink archive must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupMaintenanceArchive { .. }
        ));
        assert!(archive_link.is_symlink());
        assert_eq!(fs::read(&marker).unwrap(), b"target survives");
        cleanup_persistence(&path);
        let _ = fs::remove_file(archive_link);
        let _ = fs::remove_dir_all(archive_target);
    }

    #[test]
    fn cleanup_pool_maintenance_rejects_wrong_signer_before_regular_archive_creation() {
        let path = persistence_path("cleanup-maintenance-wrong-signer");
        let key = SigningKey::from_bytes(&[241; 32]);
        let wrong_key = SigningKey::from_bytes(&[243; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let archive_name = "cleanup-maintenance-wrong-signer-archive";
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            wrong_key,
            guard,
            archive_name,
        )
        .expect_err("a non-admitted signer must fail before archive creation");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert!(!path.parent().unwrap().join(archive_name).exists());
        cleanup_persistence(&path);
    }

    #[test]
    fn cleanup_pool_maintenance_rejects_replaced_namespace_without_creating_archive() {
        let path = persistence_path("cleanup-maintenance-replaced-namespace");
        let key = SigningKey::from_bytes(&[242; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let pool = cleanup_pool_path(&path);
        let old_pool = pool.with_file_name(".cleanup-pool-maintenance-old");
        fs::rename(&pool, &old_pool).unwrap();
        fs::create_dir(&pool).unwrap();
        let marker = pool.join("replacement-marker");
        fs::write(&marker, b"replacement survives").unwrap();
        let guard = GovernancePolicy::acquire_cleanup_pool_maintenance_guard(&path).unwrap();
        let error = GovernancePolicy::drain_cleanup_pool(
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            guard,
            "cleanup-maintenance-replaced-archive",
        )
        .expect_err("replacement namespace must refuse maintenance");
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolNamespaceChanged { .. }
        ));
        assert_eq!(fs::read(&marker).unwrap(), b"replacement survives");
        assert!(
            !path
                .parent()
                .unwrap()
                .join("cleanup-maintenance-replaced-archive")
                .exists()
        );
        fs::remove_file(&marker).unwrap();
        fs::remove_dir(&pool).unwrap();
        fs::rename(old_pool, pool).unwrap();
        cleanup_persistence(&path);
    }

    fn read_envelope(path: &Path) -> SignedStateEnvelope<PersistedGovernanceState> {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn write_envelope(path: &Path, envelope: &SignedStateEnvelope<PersistedGovernanceState>) {
        fs::write(path, serde_json::to_vec_pretty(envelope).unwrap()).unwrap();
    }

    fn read_checkpoint(path: &Path) -> SignedStateEnvelope<GovernanceSequenceCheckpoint> {
        serde_json::from_slice(
            &fs::read(GovernancePolicy::persistence_sequence_path(path)).unwrap(),
        )
        .unwrap()
    }

    fn checkpoint_sequence(checkpoint: &SignedStateEnvelope<GovernanceSequenceCheckpoint>) -> u64 {
        let payload: GovernanceSequenceCheckpoint =
            serde_json::from_str(&checkpoint.statement.payload_json).unwrap();
        assert_eq!(payload.accepted_sequence, checkpoint.sequence());
        payload.accepted_sequence
    }

    fn write_checkpoint(
        path: &Path,
        checkpoint: &SignedStateEnvelope<GovernanceSequenceCheckpoint>,
    ) {
        fs::write(
            GovernancePolicy::persistence_sequence_path(path),
            serde_json::to_vec_pretty(checkpoint).unwrap(),
        )
        .unwrap();
    }

    fn write_checkpoint_value<T: Serialize>(path: &Path, checkpoint: &SignedStateEnvelope<T>) {
        fs::write(
            GovernancePolicy::persistence_sequence_path(path),
            serde_json::to_vec_pretty(checkpoint).unwrap(),
        )
        .unwrap();
    }

    fn rewrite_as_signed_pre_lock_stream(
        path: &Path,
        key: &SigningKey,
    ) -> (serde_json::Value, u64) {
        let signer = AgentId::from_verifying_key(&key.verifying_key());
        let state = read_envelope(path);
        let mut state_payload: serde_json::Value =
            serde_json::from_str(&state.statement.payload_json).unwrap();
        state_payload
            .as_object_mut()
            .unwrap()
            .remove("lock_binding");
        state_payload
            .as_object_mut()
            .unwrap()
            .remove("cleanup_pool_binding");
        let legacy_state = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            signer.clone(),
            state.sequence(),
            state_payload.clone(),
            key,
        )
        .unwrap();
        fs::write(path, serde_json::to_vec_pretty(&legacy_state).unwrap()).unwrap();

        let checkpoint = read_checkpoint(path);
        let checkpoint_payload = json!({"accepted_sequence": checkpoint.sequence()});
        let legacy_checkpoint = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            signer,
            checkpoint.sequence(),
            checkpoint_payload,
            key,
        )
        .unwrap();
        fs::write(
            GovernancePolicy::persistence_sequence_path(path),
            serde_json::to_vec_pretty(&legacy_checkpoint).unwrap(),
        )
        .unwrap();
        fs::remove_file(GovernancePolicy::persistence_lock_path(path)).unwrap();
        (state_payload, state.sequence())
    }

    fn state_payload_without_lock(path: &Path) -> serde_json::Value {
        let envelope: SignedStateEnvelope<serde_json::Value> =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        payload.as_object_mut().unwrap().remove("lock_binding");
        payload
            .as_object_mut()
            .unwrap()
            .remove("cleanup_pool_binding");
        payload
    }

    fn load_signed_policy(
        path: &Path,
        key: &SigningKey,
    ) -> Result<GovernancePolicy, GovernancePersistenceError> {
        GovernancePolicy::with_persistence(
            GovernancePolicyConfig::default(),
            path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        )
    }

    fn copied_reinitialization_artifact(
        original: &Path,
        archive: &Path,
    ) -> super::ReinitializationArtifact {
        fs::copy(original, archive).unwrap();
        let source = super::read_governance_artifact_snapshot(original)
            .unwrap()
            .unwrap()
            .0;
        let archive_identity = super::read_governance_artifact_identity(archive)
            .unwrap()
            .unwrap();
        super::ReinitializationArtifact {
            original: original.to_path_buf(),
            archive: archive.to_path_buf(),
            identity: source.identity,
            content_digest: source.content_digest,
            byte_len: source.byte_len,
            archive_identity: Some(archive_identity),
            restored_identity: None,
        }
    }

    fn duplicate_locked_policy_snapshot(
        policy: &GovernancePolicy,
        key: &SigningKey,
    ) -> GovernancePolicy {
        let duplicate_persistence = policy
            .persistence
            .as_ref()
            .unwrap()
            .duplicate_locked_handle_for_stale_snapshot()
            .unwrap();
        GovernancePolicy::with_locked_persistence(
            GovernancePolicyConfig::default(),
            duplicate_persistence,
            AgentId::from_verifying_key(&key.verifying_key()),
            LocalGovernorKey::new(key.clone()),
        )
        .unwrap()
    }

    fn cleanup_persistence(path: &Path) {
        let _ = fs::remove_file(path);
        let sequence_path = GovernancePolicy::persistence_sequence_path(path);
        let _ = fs::remove_file(&sequence_path);
        let _ = fs::remove_file(GovernancePolicy::persistence_lock_path(path));
        let _ = fs::remove_file(GovernancePolicy::persistence_authority_lock_path(path));
        for original in [path, sequence_path.as_path()] {
            let Some(parent) = original.parent() else {
                continue;
            };
            let Some(prefix) = original.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    if entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(&format!("{prefix}.discarded-")))
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent.join(GOVERNANCE_CLEANUP_POOL_DIR_NAME));
            let is_test_parent = parent
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("swarm-governance-auth-"));
            if is_test_parent {
                let _ = fs::remove_dir(parent);
            }
        }
    }

    #[cfg(unix)]
    fn replace_lock_with_copied_record(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let lock_path = GovernancePolicy::persistence_lock_path(path);
        let record = fs::read(&lock_path).unwrap();
        fs::remove_file(&lock_path).unwrap();
        fs::write(&lock_path, record).unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn block_atomic_write(path: &Path) -> PathBuf {
        let blocker = path.with_extension(format!(
            "{}.tmp-{}",
            path.extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("state"),
            std::process::id()
        ));
        fs::create_dir(&blocker).unwrap();
        blocker
    }

    fn rewrite_same_inode(path: &Path, bytes: &[u8]) {
        let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[derive(Debug, Default)]
    struct CountingTransport {
        rounds: std::sync::Mutex<usize>,
        published: std::sync::Mutex<usize>,
    }

    impl CountingTransport {
        fn rounds(&self) -> usize {
            *self.rounds.lock().unwrap()
        }
    }

    impl ConsensusTransport for CountingTransport {
        fn accept_committee(&self, _committee: &ConsensusCommittee) -> Result<(), ConsensusError> {
            *self.rounds.lock().unwrap() += 1;
            Ok(())
        }

        fn publish(&self, _envelope: &ConsensusSignedEnvelope) -> Result<(), ConsensusError> {
            *self.published.lock().unwrap() += 1;
            Ok(())
        }

        fn drain(&self) -> Result<Vec<ConsensusSignedEnvelope>, ConsensusError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    struct HealthMemorySnapshot {
        projection: super::PersistedGovernanceState,
        pending_events: std::collections::VecDeque<super::GovernanceRuntimeEvent>,
        checkpoint_lagging: Option<super::GovernanceCheckpointLag>,
        checkpoint_repair_backoff: Option<super::GovernanceCheckpointRepairBackoff>,
        pending_health_observation: Option<super::PendingHealthObservation>,
        persistence_sequence: Option<u64>,
        persistence_digest: Option<String>,
    }

    fn health_memory_snapshot(policy: &GovernancePolicy) -> HealthMemorySnapshot {
        let state = policy.state.lock().unwrap();
        HealthMemorySnapshot {
            projection: super::PersistedGovernanceState::from_runtime(&state),
            pending_events: state.pending_events.clone(),
            checkpoint_lagging: state.checkpoint_lagging.clone(),
            checkpoint_repair_backoff: state.checkpoint_repair_backoff,
            pending_health_observation: state.pending_health_observation.clone(),
            persistence_sequence: state.persistence_sequence,
            persistence_digest: state.persistence_digest.clone(),
        }
    }

    fn request(action: ResponseAction) -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-governance-test".to_string()),
            requested_by: AgentId::new("pounce", "test"),
            action,
            severity: Severity::Critical,
            evidence: json!({"signal": "test"}),
        }
    }

    fn env(agent_health: Vec<AgentHealthEntry>) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones: Vec::new(),
            mode: SwarmMode::Alert,
            mode_transition_at: Some(1_700_000_000),
            now: 1_700_000_010,
            peer_findings: Vec::new(),
            agent_health,
        }
    }

    #[cfg(unix)]
    #[test]
    fn authority_pair_guard_transfers_without_reacquiring_and_releases_on_drop() {
        let current = persistence_path("authority-pair-guard-current");
        let legacy = persistence_path("authority-pair-guard-legacy");
        let key = SigningKey::from_bytes(&[205; 32]);
        let guard = super::acquire_governance_authority_pair_guard(&current, &legacy).unwrap();
        let identity = super::governance_authority_lock_pair_identity(&current, &legacy).unwrap();
        assert_eq!(
            super::governance_authority_lock_identity(&current).unwrap(),
            identity
        );
        assert_eq!(
            super::governance_authority_lock_identity(&legacy).unwrap(),
            identity
        );
        let policy = GovernancePolicy::initialize_persistence_with_authority_pair_guard(
            GovernancePolicyConfig::default(),
            &current,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
            guard,
        )
        .unwrap();
        let contending = super::acquire_governance_authority_pair_guard(&current, &legacy);
        assert!(matches!(
            contending,
            Err(GovernancePersistenceError::AuthorityStateLocked { .. })
        ));
        drop(policy);
        let released = super::acquire_governance_authority_pair_guard(&current, &legacy)
            .expect("transferred authority guard must release with policy drop");
        drop(released);
        cleanup_persistence(&current);
        cleanup_persistence(&legacy);
    }

    #[cfg(unix)]
    #[test]
    fn authority_pair_constructor_failure_preserves_preexisting_primary_and_removes_new_legacy() {
        let current = persistence_path("authority-pair-guard-preexisting-current");
        let legacy = persistence_path("authority-pair-guard-new-legacy");
        let key = SigningKey::from_bytes(&[206; 32]);
        let current_sidecar = GovernancePolicy::persistence_authority_lock_path(&current);
        let legacy_sidecar = GovernancePolicy::persistence_authority_lock_path(&legacy);
        let preexisting = b"preexisting current authority inode";
        fs::write(&current_sidecar, preexisting).unwrap();
        let guard = super::acquire_governance_authority_pair_guard(&current, &legacy).unwrap();
        assert!(legacy_sidecar.exists());
        let state_lock_path = GovernancePolicy::persistence_lock_path(&current);
        let held_state_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&state_lock_path)
            .unwrap();
        held_state_lock.try_lock().unwrap();
        assert!(
            GovernancePolicy::initialize_persistence_with_authority_pair_guard(
                GovernancePolicyConfig::default(),
                &current,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
                guard,
            )
            .is_err()
        );
        assert_eq!(fs::read(&current_sidecar).unwrap(), preexisting);
        assert!(!legacy_sidecar.exists());
        drop(held_state_lock);
        cleanup_persistence(&current);
        cleanup_persistence(&legacy);
    }

    #[test]
    fn genuine_signed_state_restarts_with_the_same_admitted_tom() {
        let path = persistence_path("restart-control");
        let key = SigningKey::from_bytes(&[81; 32]);
        let policy = initialize_signed_policy(&path, &key);
        policy.observe_health(
            &AgentId::from_verifying_key(&key.verifying_key()),
            &[],
            super::now_ms(),
        );
        let before = policy.status_report();
        drop(policy);

        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert_eq!(
            reloaded.status_report().partition_state,
            before.partition_state
        );
        assert_eq!(
            reloaded.status_report().active_contingency_leases,
            before.active_contingency_leases
        );
        assert_eq!(
            reloaded.governor_public_keys(),
            [AgentId::from_verifying_key(&key.verifying_key())]
                .into_iter()
                .collect()
        );
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn fresh_lock_record_is_0600_durable_metadata_signed_by_both_anchors() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path = persistence_path("fresh-lock-binding");
        let key = SigningKey::from_bytes(&[142; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let lock_path = GovernancePolicy::persistence_lock_path(&path);
        let lock_metadata = fs::symlink_metadata(&lock_path).unwrap();
        assert!(lock_metadata.file_type().is_file());
        assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);
        let record: GovernanceLockRecord =
            serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        assert_eq!(
            record.schema_version,
            super::GOVERNANCE_LOCK_RECORD_SCHEMA_VERSION
        );
        assert_eq!(
            hex::decode(&record.generation_id).unwrap().len(),
            super::GOVERNANCE_LOCK_GENERATION_BYTES
        );
        let state: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        let checkpoint: GovernanceSequenceCheckpoint =
            serde_json::from_str(&read_checkpoint(&path).statement.payload_json).unwrap();
        for binding in [&state.lock_binding, &checkpoint.lock_binding] {
            assert_eq!(binding.device, lock_metadata.dev());
            assert_eq!(binding.inode, lock_metadata.ino());
            assert_eq!(binding.generation_id, record.generation_id);
        }
        assert_eq!(state.lock_binding, checkpoint.lock_binding);
        drop(policy);

        let reloaded = load_signed_policy(&path, &key)
            .expect("restart on the same permanent lock inode preserves the stream binding");
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_load_rejects_corrupt_and_copied_lock_records() {
        use std::os::unix::fs::PermissionsExt;

        let key = SigningKey::from_bytes(&[143; 32]);
        let corrupt_path = persistence_path("corrupt-lock-record");
        let corrupt = initialize_signed_policy(&corrupt_path, &key);
        drop(corrupt);
        fs::write(
            GovernancePolicy::persistence_lock_path(&corrupt_path),
            b"not a governance lock record",
        )
        .unwrap();
        let Err(error) = load_signed_policy(&corrupt_path, &key) else {
            panic!("a corrupt permanent lock record loaded an authority stream");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::InvalidLockRecord { .. }
        ));
        cleanup_persistence(&corrupt_path);

        let source_path = persistence_path("copied-lock-source");
        let copied_path = persistence_path("copied-lock-target");
        let source = initialize_signed_policy(&source_path, &key);
        drop(source);
        fs::copy(&source_path, &copied_path).unwrap();
        fs::copy(
            GovernancePolicy::persistence_sequence_path(&source_path),
            GovernancePolicy::persistence_sequence_path(&copied_path),
        )
        .unwrap();
        let copied_lock = GovernancePolicy::persistence_lock_path(&copied_path);
        fs::copy(
            GovernancePolicy::persistence_lock_path(&source_path),
            &copied_lock,
        )
        .unwrap();
        fs::copy(
            GovernancePolicy::persistence_authority_lock_path(&source_path),
            GovernancePolicy::persistence_authority_lock_path(&copied_path),
        )
        .unwrap();
        fs::set_permissions(&copied_lock, fs::Permissions::from_mode(0o600)).unwrap();
        let Err(error) = load_signed_policy(&copied_path, &key) else {
            panic!("a copied stream loaded on a different lock inode");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::LockBindingMismatch { .. }
        ));
        cleanup_persistence(&source_path);
        cleanup_persistence(&copied_path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_sidecar_is_hard_linked_lifetime_exclusive_and_fail_closed() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        let key = SigningKey::from_bytes(&[186; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let first_path = persistence_path("authority-sidecar-first");
        let alternate_path = persistence_path("authority-sidecar-alternate");
        let first = initialize_signed_policy(&first_path, &key);
        let first_sidecar = GovernancePolicy::persistence_authority_lock_path(&first_path);
        let alternate_sidecar = GovernancePolicy::persistence_authority_lock_path(&alternate_path);
        let first_metadata = fs::symlink_metadata(&first_sidecar).unwrap();
        assert!(first_metadata.file_type().is_file());
        assert_eq!(first_metadata.permissions().mode() & 0o777, 0o600);
        let first_identity = GovernancePolicy::persistence_authority_lock_identity(&first_path)
            .expect("initialized authority has a regular canonical sidecar");
        assert_eq!(first_identity.device, first_metadata.dev());
        assert_eq!(first_identity.inode, first_metadata.ino());

        fs::hard_link(&first_sidecar, &alternate_sidecar).unwrap();
        assert_eq!(
            GovernancePolicy::persistence_authority_lock_identity(&alternate_path).unwrap(),
            first_identity
        );
        assert_eq!(
            GovernancePolicy::persistence_authority_lock_pair_identity(
                &first_path,
                &alternate_path,
            )
            .unwrap(),
            first_identity
        );
        let error = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &alternate_path,
            governing_id.clone(),
            key.clone(),
        )
        .expect_err("an alternate state path cannot open a hard-linked live authority");
        assert!(matches!(
            error,
            GovernancePersistenceError::AuthorityStateLocked { ref path }
                if path == &alternate_sidecar
        ));
        assert!(
            !GovernancePolicy::persistence_lock_path(&alternate_path).exists(),
            "failed alternate initialization must not leave a state-lock residue"
        );

        drop(first);
        let alternate = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &alternate_path,
            governing_id,
            key.clone(),
        )
        .expect("dropping the original policy releases the shared authority sidecar");
        drop(alternate);

        let mismatched_path = persistence_path("authority-sidecar-mismatch");
        let mismatched = initialize_signed_policy(&mismatched_path, &key);
        drop(mismatched);
        let mismatched_identity =
            GovernancePolicy::persistence_authority_lock_identity(&mismatched_path).unwrap();
        assert_ne!(mismatched_identity, first_identity);
        assert!(matches!(
            GovernancePolicy::persistence_authority_lock_pair_identity(
                &first_path,
                &mismatched_path,
            )
            .unwrap_err(),
            GovernancePersistenceError::AuthorityLockIdentityChanged { ref path, .. }
                if path == &GovernancePolicy::persistence_authority_lock_path(&mismatched_path)
        ));

        let symlink_path = persistence_path("authority-sidecar-symlink");
        let symlink_policy = initialize_signed_policy(&symlink_path, &key);
        drop(symlink_policy);
        let symlink_sidecar = GovernancePolicy::persistence_authority_lock_path(&symlink_path);
        let symlink_target = symlink_path.with_extension("authority-target");
        fs::write(&symlink_target, b"authority-target").unwrap();
        fs::remove_file(&symlink_sidecar).unwrap();
        symlink(&symlink_target, &symlink_sidecar).unwrap();
        assert!(matches!(
            GovernancePolicy::persistence_authority_lock_identity(&symlink_path).unwrap_err(),
            GovernancePersistenceError::InvalidAuthorityLockFileType { ref path }
                if path == &symlink_sidecar
        ));
        assert!(matches!(
            GovernancePolicy::persistence_authority_lock_pair_identity(
                &first_path,
                &symlink_path,
            )
            .unwrap_err(),
            GovernancePersistenceError::InvalidAuthorityLockFileType { ref path }
                if path == &symlink_sidecar
        ));
        assert!(matches!(
            load_signed_policy(&symlink_path, &key).unwrap_err(),
            GovernancePersistenceError::InvalidAuthorityLockFileType { ref path }
                if path == &symlink_sidecar
        ));

        let directory_path = persistence_path("authority-sidecar-directory");
        let directory_policy = initialize_signed_policy(&directory_path, &key);
        drop(directory_policy);
        let directory_sidecar = GovernancePolicy::persistence_authority_lock_path(&directory_path);
        fs::remove_file(&directory_sidecar).unwrap();
        fs::create_dir(&directory_sidecar).unwrap();
        assert!(matches!(
            GovernancePolicy::persistence_authority_lock_identity(&directory_path).unwrap_err(),
            GovernancePersistenceError::InvalidAuthorityLockFileType { ref path }
                if path == &directory_sidecar
        ));
        assert!(matches!(
            load_signed_policy(&directory_path, &key).unwrap_err(),
            GovernancePersistenceError::InvalidAuthorityLockFileType { ref path }
                if path == &directory_sidecar
        ));

        cleanup_persistence(&first_path);
        cleanup_persistence(&alternate_path);
        cleanup_persistence(&mismatched_path);
        cleanup_persistence(&symlink_path);
        cleanup_persistence(&directory_path);
        let _ = fs::remove_file(symlink_target);
    }

    #[cfg(unix)]
    #[test]
    fn failed_new_authority_lock_acquisition_removes_only_new_residues() {
        let failures = [
            (
                "authority-lock-file-sync-failure",
                InjectedAuthorityLockFailure::FileSync,
            ),
            (
                "authority-lock-parent-sync-failure",
                InjectedAuthorityLockFailure::ParentSync,
            ),
            (
                "authority-lock-try-lock-failure",
                InjectedAuthorityLockFailure::TryLock,
            ),
            (
                "authority-lock-open-identity-failure",
                InjectedAuthorityLockFailure::IdentityVerification,
            ),
            (
                "authority-lock-post-acquire-identity-failure",
                InjectedAuthorityLockFailure::PostAcquireVerification,
            ),
        ];
        for (suffix, failure) in failures {
            let path = persistence_path(suffix);
            let authority_path = GovernancePolicy::persistence_authority_lock_path(&path);
            let state_lock_path = GovernancePolicy::persistence_lock_path(&path);
            let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
            let key = SigningKey::from_bytes(&[196; 32]);
            inject_authority_lock_failure(&authority_path, failure);
            assert!(
                GovernancePolicy::initialize_persistence(
                    GovernancePolicyConfig::default(),
                    &path,
                    AgentId::from_verifying_key(&key.verifying_key()),
                    key.clone(),
                )
                .is_err()
            );
            assert!(
                !authority_path.exists(),
                "failed authority acquisition left a newly-created sidecar for {suffix}"
            );
            assert!(
                !state_lock_path.exists(),
                "failed authority acquisition left a newly-created state lock for {suffix}"
            );
            assert!(!path.exists());
            assert!(!sequence_path.exists());
            let reopened = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .expect("cleanup must leave the stream reopenable after an injected failure");
            drop(reopened);
            cleanup_persistence(&path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_quarantine_preserves_barrier_replacement() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-barrier-replacement");
        let key = SigningKey::from_bytes(&[199; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let state_lock = GovernancePolicy::persistence_lock_path(&path);
        let foreign = b"foreign sidecar wins the cleanup race".to_vec();
        let (reached, resume) = install_authority_cleanup_barrier(&sidecar);
        let replacement_sidecar = sidecar.clone();
        let replacement_bytes = foreign.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::remove_file(&replacement_sidecar).unwrap();
            fs::write(&replacement_sidecar, replacement_bytes).unwrap();
            resume.wait();
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        assert_eq!(fs::read(&sidecar).unwrap(), foreign);
        assert!(
            !state_lock.exists(),
            "foreign sidecar replacement must not strand the newly-created state lock"
        );
        drop(fs::remove_file(&sidecar));
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_post_verify_collision_preserves_foreign_destination() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-post-verify-collision");
        let key = SigningKey::from_bytes(&[200; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign post-verify quarantine destination".to_vec();
        let expected_foreign = foreign.clone();
        let (reached, resume, destination) =
            install_authority_cleanup_post_verify_barrier(&sidecar);
        let destination_for_replacer = Arc::clone(&destination);
        let replacer = std::thread::spawn(move || {
            reached.wait();
            let quarantine = destination_for_replacer
                .lock()
                .unwrap()
                .clone()
                .expect("cleanup publishes its reserved destination before the barrier");
            fs::remove_file(&quarantine).unwrap();
            fs::write(&quarantine, &foreign).unwrap();
            resume.wait();
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        assert_eq!(fs::read(&sidecar).unwrap(), Vec::<u8>::new());
        let quarantine = destination.lock().unwrap().clone().unwrap();
        assert_eq!(fs::read(quarantine).unwrap(), expected_foreign);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    fn run_private_restore_selection_control(
        label: &str,
        replace_candidate: bool,
        replace_quarantine: bool,
    ) {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path(label);
        let key = SigningKey::from_bytes(&[219; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = format!("foreign private replacement for {label}").into_bytes();
        let (reached, resume, destination) =
            install_authority_cleanup_post_verify_barrier(&sidecar);
        let replacer = std::thread::spawn({
            let destination = Arc::clone(&destination);
            let foreign = foreign.clone();
            move || {
                reached.wait();
                let quarantine = destination
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("cleanup publishes the quarantine link before the decision seam");
                let slot = quarantine.parent().unwrap().to_path_buf();
                let candidate = slot.join(GOVERNANCE_CLEANUP_POOL_CANDIDATE_NAME);
                let source_snapshot = super::read_governance_artifact_snapshot(&candidate)
                    .unwrap()
                    .unwrap()
                    .0;
                if replace_candidate {
                    fs::remove_file(&candidate).unwrap();
                    fs::write(&candidate, &foreign).unwrap();
                }
                if replace_quarantine {
                    fs::remove_file(&quarantine).unwrap();
                    fs::write(&quarantine, &foreign).unwrap();
                }
                resume.wait();
                (source_snapshot, candidate, quarantine)
            }
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        let (source_snapshot, candidate, quarantine) = replacer.join().unwrap();
        if replace_candidate && !replace_quarantine {
            let restored = super::read_governance_artifact_snapshot(&sidecar)
                .unwrap()
                .unwrap()
                .0;
            assert_eq!(restored, source_snapshot);
            assert_eq!(fs::read(&candidate).unwrap(), foreign);
        } else if replace_quarantine && !replace_candidate {
            let restored = super::read_governance_artifact_snapshot(&sidecar)
                .unwrap()
                .unwrap()
                .0;
            assert_eq!(restored, source_snapshot);
            assert_eq!(fs::read(&quarantine).unwrap(), foreign);
        } else {
            assert!(
                !sidecar.exists(),
                "two untrusted private links publish neither"
            );
            assert_eq!(fs::read(&candidate).unwrap(), foreign);
            assert_eq!(fs::read(&quarantine).unwrap(), foreign);
        }
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_single_quarantine_replacement_restores_trusted_candidate() {
        run_private_restore_selection_control(
            "authority-cleanup-single-quarantine-replacement",
            false,
            true,
        );
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_single_candidate_replacement_restores_trusted_quarantine() {
        run_private_restore_selection_control(
            "authority-cleanup-single-candidate-replacement",
            true,
            false,
        );
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_dual_private_replacement_publishes_neither_foreign_link() {
        run_private_restore_selection_control(
            "authority-cleanup-dual-private-replacement",
            true,
            true,
        );
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_pre_rename_collision_preserves_foreign_destination() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-pre-rename-collision");
        let key = SigningKey::from_bytes(&[201; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign pre-rename quarantine destination".to_vec();
        let expected_foreign = foreign.clone();
        let (reached, resume, destination) = install_authority_cleanup_pre_rename_barrier(&sidecar);
        let replacer_destination = Arc::clone(&destination);
        let replacer = std::thread::spawn(move || {
            reached.wait();
            let quarantine = replacer_destination
                .lock()
                .unwrap()
                .clone()
                .expect("cleanup publishes its reserved destination before the barrier");
            fs::remove_file(&quarantine).unwrap();
            fs::write(&quarantine, &foreign).unwrap();
            resume.wait();
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        let quarantine = destination
            .lock()
            .unwrap()
            .clone()
            .expect("test barrier retains the collision path");
        assert_eq!(fs::read(&quarantine).unwrap(), expected_foreign);
        fs::remove_file(quarantine).unwrap();
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_source_final_gap_preserves_foreign_source() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-source-final-gap");
        let key = SigningKey::from_bytes(&[212; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign source won the final cleanup gap".to_vec();
        let (reached, resume) = install_authority_cleanup_source_final_barrier(&sidecar);
        let replacer_path = sidecar.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::remove_file(&replacer_path).unwrap();
            fs::write(&replacer_path, &foreign).unwrap();
            resume.wait();
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        // The foreign source was moved into the private quarantine, while the
        // simultaneously snapshotted trusted candidate is the only link that
        // may be restored to the canonical name.
        assert_eq!(fs::read(&sidecar).unwrap(), Vec::<u8>::new());
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_post_move_canonical_replacement_is_foreign_preserved() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-post-move-canonical-replacement");
        let key = SigningKey::from_bytes(&[216; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign canonical replacement after source move".to_vec();
        let (reached, resume, _) = install_authority_cleanup_post_move_barrier(&sidecar);
        let replacement_path = sidecar.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::write(&replacement_path, &foreign).unwrap();
            resume.wait();
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        assert_eq!(
            fs::read(&sidecar).unwrap(),
            b"foreign canonical replacement after source move"
        );
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_post_move_dirfd_preserves_foreign_source_after_directory_replacement() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-post-move-dirfd");
        let key = SigningKey::from_bytes(&[213; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign source recovered from held retirement fd".to_vec();
        let retirement_marker = b"foreign replacement retirement namespace".to_vec();
        let (source_reached, source_resume) =
            install_authority_cleanup_source_final_barrier(&sidecar);
        let (move_reached, move_resume, retirement_destination) =
            install_authority_cleanup_post_move_barrier(&sidecar);

        let replacer_path = sidecar.clone();
        let source_replacer = std::thread::spawn({
            let foreign = foreign.clone();
            move || {
                source_reached.wait();
                fs::remove_file(&replacer_path).unwrap();
                fs::write(&replacer_path, foreign).unwrap();
                source_resume.wait();
            }
        });
        let move_replacer = std::thread::spawn({
            let retirement_destination = Arc::clone(&retirement_destination);
            let sidecar_name = sidecar.file_name().unwrap().to_os_string();
            let retirement_marker = retirement_marker.clone();
            move || {
                move_reached.wait();
                let retirement = retirement_destination
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("cleanup publishes the held retirement directory");
                let backup = retirement.with_file_name(format!(
                    "{}.held",
                    retirement.file_name().unwrap().to_string_lossy()
                ));
                fs::rename(&retirement, &backup).unwrap();
                fs::create_dir(&retirement).unwrap();
                fs::write(retirement.join(sidecar_name), retirement_marker).unwrap();
                move_resume.wait();
                backup
            }
        });

        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        source_replacer.join().unwrap();
        let backup = move_replacer.join().unwrap();
        let retirement = retirement_destination.lock().unwrap().clone().unwrap();

        assert!(
            !sidecar.exists(),
            "a replaced private cleanup slot must not be trusted to restore the canonical name"
        );
        assert_eq!(
            fs::read(backup.join(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME)).unwrap(),
            foreign
        );
        assert_eq!(
            fs::read(retirement.join(sidecar.file_name().unwrap())).unwrap(),
            retirement_marker
        );

        cleanup_persistence(&path);
        let _ = fs::remove_dir_all(backup);
        let _ = fs::remove_dir_all(retirement);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_pool_path_replacement_uses_held_slot_namespace() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-pool-path-replacement");
        let key = SigningKey::from_bytes(&[217; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let (reached, resume, retirement_destination) =
            install_authority_cleanup_post_move_barrier(&sidecar);
        let pool_marker = b"foreign replacement pool namespace".to_vec();
        let replacer = std::thread::spawn({
            let retirement_destination = Arc::clone(&retirement_destination);
            let pool_marker = pool_marker.clone();
            move || {
                reached.wait();
                let slot = retirement_destination
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("cleanup publishes a fixed slot before the pool swap");
                let pool = slot.parent().unwrap().to_path_buf();
                let held_pool = pool.with_file_name(format!(
                    "{}.held",
                    pool.file_name().unwrap().to_string_lossy()
                ));
                fs::rename(&pool, &held_pool).unwrap();
                fs::create_dir(&pool).unwrap();
                fs::write(pool.join("foreign-marker"), pool_marker).unwrap();
                resume.wait();
                (held_pool, pool)
            }
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        let (held_pool, replacement_pool) = replacer.join().unwrap();
        assert_eq!(
            fs::read(replacement_pool.join("foreign-marker")).unwrap(),
            pool_marker
        );
        let slot_name = retirement_destination
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .file_name()
            .unwrap()
            .to_os_string();
        assert!(
            held_pool
                .join(slot_name)
                .join(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME)
                .exists()
        );
        cleanup_persistence(&path);
        let _ = fs::remove_dir_all(held_pool);
        let _ = fs::remove_dir_all(replacement_pool);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_pool_lock_replacement_is_fail_closed() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-pool-lock-replacement");
        let key = SigningKey::from_bytes(&[218; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let (reached, resume, retirement_destination) =
            install_authority_cleanup_post_move_barrier(&sidecar);
        let replacement_lock = b"foreign pool lock replacement".to_vec();
        let replacer = std::thread::spawn({
            let retirement_destination = Arc::clone(&retirement_destination);
            let replacement_lock = replacement_lock.clone();
            move || {
                reached.wait();
                let slot = retirement_destination
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("cleanup publishes a fixed slot before lock replacement");
                let pool = slot.parent().unwrap().to_path_buf();
                let lock = pool.join(GOVERNANCE_CLEANUP_POOL_LOCK_NAME);
                let held_lock = pool.join("lock.held");
                fs::rename(&lock, &held_lock).unwrap();
                fs::write(&lock, replacement_lock).unwrap();
                resume.wait();
                held_lock
            }
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        let held_lock = replacer.join().unwrap();
        let pool = sidecar
            .parent()
            .unwrap()
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
        assert_eq!(
            fs::read(pool.join(GOVERNANCE_CLEANUP_POOL_LOCK_NAME)).unwrap(),
            replacement_lock
        );
        assert!(
            held_lock.exists(),
            "the held lock inode remains recoverable"
        );
        cleanup_persistence(&path);
        let _ = fs::remove_file(held_lock);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_original_parent_replacement_preserves_foreign_source() {
        let _test_guard = lock_authority_cleanup_tests();
        let parent_marker = persistence_path("authority-cleanup-original-parent");
        let parent = parent_marker.parent().unwrap().to_path_buf();
        let path = parent.join("stream.json");
        let key = SigningKey::from_bytes(&[214; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign source restored through held original parent".to_vec();
        let parent_marker = b"foreign replacement parent survives".to_vec();
        let (source_reached, source_resume) =
            install_authority_cleanup_source_final_barrier(&sidecar);
        let (move_reached, move_resume, retirement_destination) =
            install_authority_cleanup_post_move_barrier(&sidecar);

        let replacer_path = sidecar.clone();
        let source_replacer = std::thread::spawn({
            let foreign = foreign.clone();
            move || {
                source_reached.wait();
                fs::remove_file(&replacer_path).unwrap();
                fs::write(&replacer_path, foreign).unwrap();
                source_resume.wait();
            }
        });
        let parent_replacer = std::thread::spawn({
            let retirement_destination = Arc::clone(&retirement_destination);
            let sidecar_name = sidecar.file_name().unwrap().to_os_string();
            let parent_marker = parent_marker.clone();
            move || {
                move_reached.wait();
                let retirement = retirement_destination
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("cleanup publishes the retirement directory before parent swap");
                let held_parent = retirement.with_file_name(format!(
                    "{}.held",
                    retirement.file_name().unwrap().to_string_lossy()
                ));
                fs::rename(&retirement, &held_parent).unwrap();
                fs::create_dir(&retirement).unwrap();
                fs::write(retirement.join(&sidecar_name), parent_marker).unwrap();
                move_resume.wait();
                held_parent
            }
        });

        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        source_replacer.join().unwrap();
        let held_parent = parent_replacer.join().unwrap();
        let replacement_parent = retirement_destination
            .lock()
            .unwrap()
            .clone()
            .expect("cleanup retains the fixed slot path");
        let replacement_parent_sidecar = replacement_parent.join(sidecar.file_name().unwrap());
        let held_parent_quarantine = held_parent.join(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME);
        assert_eq!(fs::read(&held_parent_quarantine).unwrap(), foreign);
        assert_eq!(
            fs::read(&replacement_parent_sidecar).unwrap(),
            parent_marker
        );

        let _ = fs::remove_dir_all(held_parent);
        let _ = fs::remove_dir_all(parent);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_reclaim_snapshot_replacement_preserves_foreign_entry() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-reclaim-final-gap");
        let key = SigningKey::from_bytes(&[215; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign reclaim entry survives final snapshot gap".to_vec();
        let (reached, resume, reclaim_destination) =
            install_authority_cleanup_reclaim_barrier(&sidecar);
        let replacer = std::thread::spawn({
            let reclaim_destination = Arc::clone(&reclaim_destination);
            move || {
                reached.wait();
                let reclaim = reclaim_destination
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("cleanup publishes the held reclaim directory");
                let entry = reclaim.join(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME);
                let replacement = fs::remove_file(&entry).and_then(|()| fs::write(&entry, foreign));
                resume.wait();
                replacement.unwrap();
            }
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        let reclaim = reclaim_destination
            .lock()
            .unwrap()
            .clone()
            .expect("test barrier retains the reclaim path");
        assert_eq!(
            fs::read(reclaim.join(GOVERNANCE_CLEANUP_POOL_QUARANTINE_NAME)).unwrap(),
            b"foreign reclaim entry survives final snapshot gap"
        );
        cleanup_persistence(&path);
        if let Some(retirement) = reclaim.parent() {
            let _ = fs::remove_dir_all(retirement);
        }
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_final_unlink_barrier_preserves_foreign_destination() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-final-unlink-barrier");
        let key = SigningKey::from_bytes(&[202; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign final-unlink destination".to_vec();
        let expected_foreign = foreign.clone();
        let (reached, resume, destination) =
            install_authority_cleanup_final_unlink_barrier(&sidecar);
        let replacer_destination = Arc::clone(&destination);
        let replacer = std::thread::spawn(move || {
            reached.wait();
            let quarantine = replacer_destination
                .lock()
                .unwrap()
                .clone()
                .expect("cleanup publishes its reserved destination before the barrier");
            fs::remove_file(&quarantine).unwrap();
            fs::write(&quarantine, &foreign).unwrap();
            resume.wait();
        });
        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();
        let quarantine = destination
            .lock()
            .unwrap()
            .clone()
            .expect("test barrier retains the collision path");
        assert_eq!(fs::read(&sidecar).unwrap(), Vec::<u8>::new());
        assert_eq!(fs::read(&quarantine).unwrap(), expected_foreign);
        fs::remove_file(quarantine).unwrap();
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn authority_cleanup_final_absence_race_preserves_foreign_canonical_entry() {
        let _test_guard = lock_authority_cleanup_tests();
        let path = persistence_path("authority-cleanup-final-absence-race");
        let key = SigningKey::from_bytes(&[203; 32]);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let foreign = b"foreign canonical entry created after final absence read".to_vec();
        let expected_foreign = foreign.clone();
        let (reached, resume) = install_authority_cleanup_final_absence_barrier(&sidecar);
        let replacement = sidecar.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::write(&replacement, foreign).unwrap();
            resume.wait();
        });

        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key,
            )
            .is_err()
        );
        replacer.join().unwrap();

        assert_eq!(fs::read(&sidecar).unwrap(), expected_foreign);
        fs::remove_file(&sidecar).unwrap();
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn live_authority_sidecar_replacement_refuses_mutation_without_deleting_foreign_file() {
        let path = persistence_path("authority-sidecar-live-replacement");
        let key = SigningKey::from_bytes(&[197; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let replacement_bytes = b"foreign authority replacement";
        let before_memory = health_memory_snapshot(&policy);
        let before_state = fs::read(&path).unwrap();
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let before_checkpoint = fs::read(&sequence_path).unwrap();
        fs::remove_file(&sidecar).unwrap();
        fs::write(&sidecar, replacement_bytes).unwrap();

        let peer = SigningKey::from_bytes(&[198; 32]);
        let error = policy
            .register_peer_governor(&peer.verifying_key())
            .expect_err("a live sidecar replacement must fail closed before mutation");
        assert!(error.contains("authority lifetime lock path identity changed"));
        assert_eq!(health_memory_snapshot(&policy), before_memory);
        assert_eq!(fs::read(&path).unwrap(), before_state);
        assert_eq!(fs::read(&sequence_path).unwrap(), before_checkpoint);
        assert_eq!(fs::read(&sidecar).unwrap(), replacement_bytes);
        drop(policy);
        let _ = fs::remove_file(&sidecar);
        cleanup_persistence(&path);
    }

    #[test]
    fn signed_payloads_without_the_permanent_lock_binding_fail_closed() {
        let path = persistence_path("missing-signed-lock-binding");
        let key = SigningKey::from_bytes(&[144; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let signer = AgentId::from_verifying_key(&key.verifying_key());
        let original_state = read_envelope(&path);
        let mut state_payload: serde_json::Value =
            serde_json::from_str(&original_state.statement.payload_json).unwrap();
        state_payload
            .as_object_mut()
            .unwrap()
            .remove("lock_binding");
        let legacy_state = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            signer.clone(),
            original_state.sequence(),
            state_payload,
            &key,
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&legacy_state).unwrap()).unwrap();
        let error = load_signed_policy(&path, &key)
            .expect_err("a trusted old payload without lock binding must not load");
        assert!(error.to_string().contains("lock_binding"), "{error}");
        write_envelope(&path, &original_state);

        let original_checkpoint = read_checkpoint(&path);
        let mut checkpoint_payload: serde_json::Value =
            serde_json::from_str(&original_checkpoint.statement.payload_json).unwrap();
        checkpoint_payload
            .as_object_mut()
            .unwrap()
            .remove("lock_binding");
        let legacy_checkpoint = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            signer,
            original_checkpoint.sequence(),
            checkpoint_payload,
            &key,
        )
        .unwrap();
        fs::write(
            GovernancePolicy::persistence_sequence_path(&path),
            serde_json::to_vec_pretty(&legacy_checkpoint).unwrap(),
        )
        .unwrap();
        let error = load_signed_policy(&path, &key)
            .expect_err("a trusted old checkpoint without lock binding must not load");
        assert!(error.to_string().contains("lock_binding"), "{error}");
        let reset = GovernancePolicy::reinitialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        )
        .expect("explicit offline reinitialization establishes the current lock binding");
        drop(reset);
        cleanup_persistence(&path);
    }

    #[test]
    fn explicit_offline_migration_preserves_pre_lock_signed_authority_and_advances_sequence() {
        let path = persistence_path("offline-lock-migration");
        let key = SigningKey::from_bytes(&[151; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let observed_at_ms = super::now_ms();
        policy.observe_health(&governing_id, &[], observed_at_ms);
        drop(policy);

        let original = read_envelope(&path);
        let mut payload: PersistedGovernanceState =
            serde_json::from_str(&original.statement.payload_json).unwrap();
        payload
            .pending_authorizations
            .push_back(PendingGovernanceAuthorization {
                receipt_id: "migration-pending".to_string(),
                subject_digest: "migration-subject".to_string(),
                decision: swarm_consensus::GovernanceReceiptDecision::Approve,
                issued_at_ms: observed_at_ms,
            });
        payload
            .consumed_authorizations
            .push_back(ConsumedGovernanceAuthorization {
                receipt_id: "migration-consumed".to_string(),
                subject_digest: "migration-consumed-subject".to_string(),
                decision: swarm_consensus::GovernanceReceiptDecision::Veto,
                consumed_at_ms: observed_at_ms,
            });
        payload.pending_human_authorizations.push_back(
            swarm_policy::governance::GovernedHumanAuthorizationHold {
                hold_id: "migration-human-hold".to_string(),
                request: request(ResponseAction::BlockEgress {
                    target: "203.0.113.151".to_string(),
                }),
                policy_decision: swarm_policy::PolicyDecision::require_human_with_rule(
                    "migration-review",
                    "preserve the signed hold",
                ),
                governance_receipt: json!({
                    "payload": {"receipt_id": "migration-pending"},
                    "signed_fixture": true
                }),
                created_at_ms: observed_at_ms,
                approval_set_id: Some("migration-approval-set".to_string()),
                approval_set_digest: Some("migration-approval-digest".to_string()),
            },
        );
        assert!(!payload.active_contingency_leases.is_empty());
        let enriched = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            governing_id.clone(),
            original.sequence(),
            payload,
            &key,
        )
        .unwrap();
        write_envelope(&path, &enriched);
        let (authority_payload, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);

        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::MissingLock { .. }
        ));
        let report =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id, key.clone()).unwrap();
        assert_eq!(report.previous_state_sequence, previous_sequence);
        assert_eq!(report.migrated_sequence, previous_sequence + 1);
        assert!(!report.resumed_state_commit);
        assert!(!report.already_migrated);
        assert_eq!(state_payload_without_lock(&path), authority_payload);
        assert_eq!(read_envelope(&path).sequence(), previous_sequence + 1);
        assert_eq!(read_checkpoint(&path).sequence(), previous_sequence + 1);

        let restarted = load_signed_policy(&path, &key).unwrap();
        let state = restarted.state.lock().unwrap();
        assert_eq!(state.pending_authorizations.len(), 1);
        assert_eq!(state.consumed_authorizations.len(), 1);
        assert_eq!(state.pending_human_authorizations.len(), 1);
        assert!(!state.active_contingency_leases.is_empty());
        drop(state);
        drop(restarted);
        cleanup_persistence(&path);
    }

    #[test]
    fn migration_preserves_a_genuine_pending_action_receipt_and_its_one_shot_ledger() {
        let path = persistence_path("migration-action-receipt");
        let key = SigningKey::from_bytes(&[160; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.160".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: production governance issued an action receipt");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let preconsumed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.162".to_string(),
        });
        let GovernanceDecision::Authorize {
            receipt: preconsumed_receipt,
            ..
        } = policy.can_act(&preconsumed_request)
        else {
            panic!("precondition: production governance issued the pre-consumed receipt");
        };
        let preconsumed_value = serde_json::to_value(&preconsumed_receipt).unwrap();
        policy
            .verify_and_consume_action_authorization(
                &preconsumed_request,
                &preconsumed_value,
                preconsumed_receipt.payload.issued_at_ms + 1,
            )
            .expect("precondition: the second genuine receipt is consumed before migration");
        drop(policy);

        let (authority_payload, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);
        let report =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id, key.clone()).unwrap();
        assert_eq!(report.migrated_sequence, previous_sequence + 1);
        assert_eq!(state_payload_without_lock(&path), authority_payload);

        let restarted = load_signed_policy(&path, &key).unwrap();
        let error = restarted
            .verify_and_consume_action_authorization(
                &preconsumed_request,
                &preconsumed_value,
                preconsumed_receipt.payload.issued_at_ms + 2,
            )
            .expect_err("a receipt consumed before migration must remain consumed");
        assert!(error.contains("already consumed"), "{error}");
        restarted
            .verify_and_consume_action_authorization(
                &governed_request,
                &receipt_value,
                receipt.payload.issued_at_ms + 1,
            )
            .expect("the genuine pending receipt survives migration and restart");
        drop(restarted);

        let replay = load_signed_policy(&path, &key).unwrap();
        let error = replay
            .verify_and_consume_action_authorization(
                &governed_request,
                &receipt_value,
                receipt.payload.issued_at_ms + 2,
            )
            .expect_err("the migrated action receipt remains one-shot after another restart");
        assert!(error.contains("already consumed"), "{error}");
        let state = replay.state.lock().unwrap();
        assert!(state.pending_authorizations.is_empty());
        assert_eq!(state.consumed_authorizations.len(), 2);
        assert!(
            state
                .consumed_authorizations
                .iter()
                .any(|consumed| consumed.receipt_id == receipt.payload.receipt_id)
        );
        assert!(
            state
                .consumed_authorizations
                .iter()
                .any(|consumed| { consumed.receipt_id == preconsumed_receipt.payload.receipt_id })
        );
        drop(state);
        drop(replay);
        cleanup_persistence(&path);
    }

    #[test]
    fn unbound_human_hold_reconciles_idempotently_after_restart() {
        let path = persistence_path("human-approval-reconciliation");
        let key = SigningKey::from_bytes(&[166; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.166".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: production governance issued an action receipt");
        };
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &serde_json::to_value(&receipt).unwrap(),
                &swarm_policy::PolicyDecision::require_human_with_rule(
                    "reconcile-human-review",
                    "human review required",
                ),
                receipt.payload.issued_at_ms + 1,
            )
            .unwrap();
        assert!(hold.approval_set_id.is_none());
        drop(policy);

        let restarted = load_signed_policy(&path, &key).unwrap();
        let set_id = "approval-set:reconciled";
        let set_digest = swarm_crypto::sha256_hex(b"approval-set:reconciled");
        let evidence_ref = hold.approval_evidence_ref();
        let reconciled = restarted
            .reconcile_human_approval_set(set_id, &set_digest, &evidence_ref)
            .expect("an exact unbound hold must reconcile after restart");
        assert_eq!(reconciled.approval_set_id.as_deref(), Some(set_id));
        assert_eq!(
            reconciled.approval_set_digest.as_deref(),
            Some(set_digest.as_str())
        );
        assert_eq!(
            restarted
                .reconcile_human_approval_set(set_id, &set_digest, &evidence_ref)
                .unwrap(),
            reconciled,
            "an exact reconciliation retry must be idempotent"
        );
        assert!(
            restarted
                .reconcile_human_approval_set(set_id, "different-digest", &evidence_ref)
                .unwrap_err()
                .contains("conflicts")
        );
        drop(restarted);

        let replay = load_signed_policy(&path, &key).unwrap();
        assert_eq!(
            replay.pending_human_authorization(set_id).unwrap(),
            reconciled,
            "the repaired binding must survive another restart"
        );
        drop(replay);
        cleanup_persistence(&path);
    }

    #[test]
    fn migration_preserves_a_genuine_human_approval_pack_and_atomic_one_shot() {
        let path = persistence_path("migration-human-pack");
        let approval_root = path.with_extension("approval-fixture");
        let key = SigningKey::from_bytes(&[161; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.161".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: production governance issued an action receipt");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let decision = swarm_policy::PolicyDecision::require_human_with_rule(
            "migration-human-review",
            "human review required",
        );
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &receipt_value,
                &decision,
                receipt.payload.issued_at_ms + 1,
            )
            .unwrap();
        let approval_harness = DefaultApprovalHarness::from_path(
            approval_root.join("config"),
            approval_root.join("verdicts"),
            approval_root.join("packs"),
            approval_root.join("sets"),
            approval_root.join("ledgers"),
        )
        .unwrap();
        let voter = Ed25519Signer::from_secret_material("migration-human-voter");
        let voter_id = format!("swarm:ed25519:{}", voter.public_key_hex());
        let set_record = approval_harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::Unanimous,
                &hold.approval_evidence_ref(),
            )
            .unwrap();
        approval_harness
            .append_vote(&set_record.set_id, &voter_id, &voter)
            .unwrap();
        let set = approval_harness
            .load_approval_set(&set_record.set_id)
            .unwrap()
            .unwrap()
            .report;
        let ledger_id = approval_harness
            .list_ledgers(Some(&set.set_id))
            .unwrap()
            .ledgers[0]
            .ledger_id
            .clone();
        let ledger = approval_harness
            .load_ledger(&ledger_id)
            .unwrap()
            .unwrap()
            .report;
        let evaluated_at_ms = super::now_ms();
        let verdict = evaluate_verdict(&set, &ledger, evaluated_at_ms).unwrap();
        let pack_signer = Ed25519Signer::from_secret_material("migration-human-pack");
        let pack = build_receipt_pack(
            &set,
            &ledger,
            &verdict,
            vec![hold.approval_evidence_ref()],
            &pack_signer,
            "migration-human-pack",
            evaluated_at_ms + 1,
        )
        .unwrap();
        let set_digest = approval_set_digest(&set).unwrap();
        let bound = policy
            .bind_human_approval_set(&hold.hold_id, &set.set_id, &set_digest)
            .unwrap();
        verify_governed_human_receipt_pack(
            &pack,
            bound.approval_set_id.as_deref().unwrap(),
            bound.approval_set_digest.as_deref().unwrap(),
            &bound.approval_evidence_ref(),
            bound.created_at_ms,
            pack.created_at_ms + 1,
        )
        .expect("precondition: genuine signed pack matches the persisted hold");
        drop(policy);

        let (authority_payload, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);
        let report =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id, key.clone()).unwrap();
        assert_eq!(report.migrated_sequence, previous_sequence + 1);
        assert_eq!(state_payload_without_lock(&path), authority_payload);

        let restarted = load_signed_policy(&path, &key).unwrap();
        let migrated_hold = restarted
            .pending_human_authorization(&set.set_id)
            .expect("the exact bound hold survives migration and restart");
        assert_eq!(migrated_hold, bound);
        verify_governed_human_receipt_pack(
            &pack,
            migrated_hold.approval_set_id.as_deref().unwrap(),
            migrated_hold.approval_set_digest.as_deref().unwrap(),
            &migrated_hold.approval_evidence_ref(),
            migrated_hold.created_at_ms,
            pack.created_at_ms + 1,
        )
        .expect("the genuine pack still verifies against the migrated hold");
        restarted
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                &set.set_id,
                &set_digest,
                pack.created_at_ms + 1,
            )
            .expect("the migrated hold and receipt are consumed atomically");
        drop(restarted);

        let replay = load_signed_policy(&path, &key).unwrap();
        let error = replay
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                &set.set_id,
                &set_digest,
                pack.created_at_ms + 2,
            )
            .expect_err("the migrated human authorization remains one-shot after restart");
        assert!(error.contains("was not found"), "{error}");
        let state = replay.state.lock().unwrap();
        assert!(state.pending_human_authorizations.is_empty());
        assert!(state.pending_authorizations.is_empty());
        assert_eq!(state.consumed_authorizations.len(), 1);
        drop(state);
        drop(replay);
        cleanup_persistence(&path);
        fs::remove_dir_all(approval_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pvc_restore_rebinds_signed_state_without_clearing_authority() {
        use std::os::unix::fs::PermissionsExt;

        let source_path = persistence_path("pvc-source");
        let restored_path = persistence_path("pvc-restored");
        let key = SigningKey::from_bytes(&[152; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let source = initialize_signed_policy(&source_path, &key);
        source.observe_health(&governing_id, &[], super::now_ms());
        drop(source);
        let original_sequence = read_envelope(&source_path).sequence();
        let authority_payload = state_payload_without_lock(&source_path);
        fs::copy(&source_path, &restored_path).unwrap();
        fs::copy(
            GovernancePolicy::persistence_sequence_path(&source_path),
            GovernancePolicy::persistence_sequence_path(&restored_path),
        )
        .unwrap();
        let restored_lock = GovernancePolicy::persistence_lock_path(&restored_path);
        fs::copy(
            GovernancePolicy::persistence_lock_path(&source_path),
            &restored_lock,
        )
        .unwrap();
        fs::copy(
            GovernancePolicy::persistence_authority_lock_path(&source_path),
            GovernancePolicy::persistence_authority_lock_path(&restored_path),
        )
        .unwrap();
        fs::set_permissions(&restored_lock, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            load_signed_policy(&restored_path, &key).unwrap_err(),
            GovernancePersistenceError::LockBindingMismatch { .. }
        ));
        let report =
            GovernancePolicy::migrate_persistence_lock(&restored_path, governing_id, key.clone())
                .unwrap();
        assert_eq!(report.migrated_sequence, original_sequence + 1);
        assert_eq!(
            state_payload_without_lock(&restored_path),
            authority_payload
        );
        drop(load_signed_policy(&restored_path, &key).unwrap());
        assert_eq!(read_envelope(&source_path).sequence(), original_sequence);
        cleanup_persistence(&source_path);
        cleanup_persistence(&restored_path);
    }

    #[test]
    fn migration_checkpoint_failure_resumes_the_committed_state_without_second_increment() {
        let path = persistence_path("migration-checkpoint-retry");
        let key = SigningKey::from_bytes(&[153; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let (authority_payload, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);
        let checkpoint_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&checkpoint_path);
        let error =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id.clone(), key.clone())
                .unwrap_err();
        assert!(matches!(
            error,
            GovernancePersistenceError::MigrationCheckpointLagging {
                sequence,
                ..
            } if sequence == previous_sequence + 1
        ));
        assert_eq!(read_envelope(&path).sequence(), previous_sequence + 1);
        assert_eq!(read_checkpoint(&path).sequence(), previous_sequence);
        assert_eq!(state_payload_without_lock(&path), authority_payload);
        fs::remove_dir(blocker).unwrap();

        let resumed =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id.clone(), key.clone())
                .unwrap();
        assert!(resumed.resumed_state_commit);
        assert_eq!(resumed.migrated_sequence, previous_sequence + 1);
        assert_eq!(read_checkpoint(&path).sequence(), previous_sequence + 1);
        let idempotent =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id, key).unwrap();
        assert!(idempotent.already_migrated);
        assert_eq!(idempotent.migrated_sequence, previous_sequence + 1);
        cleanup_persistence(&path);
    }

    #[test]
    fn migration_retry_resyncs_checkpoint_after_post_rename_parent_sync_failure() {
        let path = persistence_path("migration-checkpoint-parent-sync-retry");
        let key = SigningKey::from_bytes(&[159; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        drop(initialize_signed_policy(&path, &key));
        let (_, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);
        let checkpoint_path = GovernancePolicy::persistence_sequence_path(&path);

        inject_atomic_parent_sync_failure(&checkpoint_path);
        let first =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id.clone(), key.clone())
                .unwrap_err();
        assert!(matches!(
            first,
            GovernancePersistenceError::MigrationCheckpointLagging { sequence, .. }
                if sequence == previous_sequence + 1
        ));
        assert_eq!(read_envelope(&path).sequence(), previous_sequence + 1);
        assert_eq!(read_checkpoint(&path).sequence(), previous_sequence + 1);

        inject_atomic_parent_sync_failure(&checkpoint_path);
        let retry =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id.clone(), key.clone());
        assert!(matches!(
            retry,
            Err(GovernancePersistenceError::MigrationCheckpointLagging { sequence, .. })
                if sequence == previous_sequence + 1
        ));

        let repaired = GovernancePolicy::migrate_persistence_lock(&path, governing_id, key)
            .expect("retry must durably rewrite and sync the migrated checkpoint");
        assert!(repaired.already_migrated);
        assert_eq!(repaired.migrated_sequence, previous_sequence + 1);
        cleanup_persistence(&path);
    }

    #[test]
    fn migration_rejects_wrong_signer_checkpoint_ahead_and_active_owner_without_rewriting() {
        let wrong_path = persistence_path("migration-wrong-signer");
        let key = SigningKey::from_bytes(&[154; 32]);
        let attacker = SigningKey::from_bytes(&[155; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&wrong_path, &key);
        drop(policy);
        let (_, sequence) = rewrite_as_signed_pre_lock_stream(&wrong_path, &key);
        let state: SignedStateEnvelope<serde_json::Value> =
            serde_json::from_slice(&fs::read(&wrong_path).unwrap()).unwrap();
        let attacker_state = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&attacker.verifying_key()),
            sequence,
            serde_json::from_str::<serde_json::Value>(&state.statement.payload_json).unwrap(),
            &attacker,
        )
        .unwrap();
        fs::write(
            &wrong_path,
            serde_json::to_vec_pretty(&attacker_state).unwrap(),
        )
        .unwrap();
        assert!(
            GovernancePolicy::migrate_persistence_lock(
                &wrong_path,
                governing_id.clone(),
                key.clone()
            )
            .is_err()
        );
        assert!(!GovernancePolicy::persistence_lock_path(&wrong_path).exists());
        cleanup_persistence(&wrong_path);

        let ahead_path = persistence_path("migration-checkpoint-ahead");
        let policy = initialize_signed_policy(&ahead_path, &key);
        drop(policy);
        let (_, sequence) = rewrite_as_signed_pre_lock_stream(&ahead_path, &key);
        let ahead_checkpoint = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            governing_id.clone(),
            sequence + 1,
            json!({"accepted_sequence": sequence + 1}),
            &key,
        )
        .unwrap();
        fs::write(
            GovernancePolicy::persistence_sequence_path(&ahead_path),
            serde_json::to_vec_pretty(&ahead_checkpoint).unwrap(),
        )
        .unwrap();
        assert!(
            GovernancePolicy::migrate_persistence_lock(
                &ahead_path,
                governing_id.clone(),
                key.clone()
            )
            .is_err()
        );
        assert!(!GovernancePolicy::persistence_lock_path(&ahead_path).exists());
        cleanup_persistence(&ahead_path);

        let active_path = persistence_path("migration-active-owner");
        let active = initialize_signed_policy(&active_path, &key);
        let state_before = fs::read(&active_path).unwrap();
        let checkpoint_before =
            fs::read(GovernancePolicy::persistence_sequence_path(&active_path)).unwrap();
        assert!(matches!(
            GovernancePolicy::migrate_persistence_lock(&active_path, governing_id, key)
                .unwrap_err(),
            GovernancePersistenceError::StateLocked { .. }
                | GovernancePersistenceError::AuthorityStateLocked { .. }
        ));
        assert_eq!(fs::read(&active_path).unwrap(), state_before);
        assert_eq!(
            fs::read(GovernancePolicy::persistence_sequence_path(&active_path)).unwrap(),
            checkpoint_before
        );
        drop(active);
        cleanup_persistence(&active_path);
    }

    #[test]
    fn migration_rejects_unsigned_corrupt_and_incomplete_signed_schemas_without_lock_residue() {
        let key = SigningKey::from_bytes(&[156; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());

        let unsigned_path = persistence_path("migration-unsigned");
        let policy = initialize_signed_policy(&unsigned_path, &key);
        drop(policy);
        fs::remove_file(GovernancePolicy::persistence_lock_path(&unsigned_path)).unwrap();
        fs::write(&unsigned_path, b"{\"peer_governors\":[]}").unwrap();
        assert!(matches!(
            GovernancePolicy::migrate_persistence_lock(
                &unsigned_path,
                governing_id.clone(),
                key.clone()
            )
            .unwrap_err(),
            GovernancePersistenceError::LegacyUnsignedState { .. }
        ));
        assert!(!GovernancePolicy::persistence_lock_path(&unsigned_path).exists());
        cleanup_persistence(&unsigned_path);

        let corrupt_path = persistence_path("migration-corrupt");
        let policy = initialize_signed_policy(&corrupt_path, &key);
        drop(policy);
        fs::remove_file(GovernancePolicy::persistence_lock_path(&corrupt_path)).unwrap();
        fs::write(&corrupt_path, b"{not-json").unwrap();
        assert!(matches!(
            GovernancePolicy::migrate_persistence_lock(
                &corrupt_path,
                governing_id.clone(),
                key.clone()
            )
            .unwrap_err(),
            GovernancePersistenceError::ParseState { .. }
        ));
        assert!(!GovernancePolicy::persistence_lock_path(&corrupt_path).exists());
        cleanup_persistence(&corrupt_path);

        let old_schema_path = persistence_path("migration-old-health-schema");
        let policy = initialize_signed_policy(&old_schema_path, &key);
        drop(policy);
        let (mut payload, sequence) = rewrite_as_signed_pre_lock_stream(&old_schema_path, &key);
        payload.as_object_mut().unwrap().remove("unhealthy_agents");
        let incomplete = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            governing_id.clone(),
            sequence,
            payload,
            &key,
        )
        .unwrap();
        fs::write(
            &old_schema_path,
            serde_json::to_vec_pretty(&incomplete).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            GovernancePolicy::migrate_persistence_lock(&old_schema_path, governing_id, key)
                .unwrap_err(),
            GovernancePersistenceError::InvalidMigrationInput { .. }
        ));
        assert!(!GovernancePolicy::persistence_lock_path(&old_schema_path).exists());
        cleanup_persistence(&old_schema_path);
    }

    #[test]
    fn migration_retries_a_durable_lock_only_failure_without_rotating_authority() {
        let path = persistence_path("migration-lock-only-retry");
        let key = SigningKey::from_bytes(&[157; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let (authority_payload, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);

        super::fail_next_governance_lock_parent_sync();
        assert!(matches!(
            GovernancePolicy::migrate_persistence_lock(&path, governing_id.clone(), key.clone())
                .unwrap_err(),
            GovernancePersistenceError::WriteLockRecord { .. }
        ));
        assert!(GovernancePolicy::persistence_lock_path(&path).exists());
        assert_eq!(read_envelope(&path).sequence(), previous_sequence);
        assert_eq!(state_payload_without_lock(&path), authority_payload);

        let report = GovernancePolicy::migrate_persistence_lock(&path, governing_id, key).unwrap();
        assert_eq!(report.migrated_sequence, previous_sequence + 1);
        assert_eq!(state_payload_without_lock(&path), authority_payload);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn migration_recovers_a_partial_lock_record_only_after_anchor_authentication() {
        use std::os::unix::fs::PermissionsExt;

        let path = persistence_path("migration-partial-lock-retry");
        let key = SigningKey::from_bytes(&[159; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let (authority_payload, previous_sequence) = rewrite_as_signed_pre_lock_stream(&path, &key);
        let lock_path = GovernancePolicy::persistence_lock_path(&path);
        fs::write(&lock_path, b"partial").unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();

        let report =
            GovernancePolicy::migrate_persistence_lock(&path, governing_id.clone(), key.clone())
                .unwrap();
        assert_eq!(report.migrated_sequence, previous_sequence + 1);
        assert_eq!(state_payload_without_lock(&path), authority_payload);
        drop(load_signed_policy(&path, &key).unwrap());

        // The same partial lock beside an unauthenticated state is never
        // regenerated into a usable authority stream.
        let invalid_path = persistence_path("migration-partial-lock-invalid-anchors");
        fs::copy(&path, &invalid_path).unwrap();
        fs::copy(
            GovernancePolicy::persistence_sequence_path(&path),
            GovernancePolicy::persistence_sequence_path(&invalid_path),
        )
        .unwrap();
        let invalid_lock_path = GovernancePolicy::persistence_lock_path(&invalid_path);
        fs::write(&invalid_lock_path, b"partial").unwrap();
        fs::set_permissions(&invalid_lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&invalid_path, b"not signed state").unwrap();
        assert!(
            GovernancePolicy::migrate_persistence_lock(&invalid_path, governing_id, key).is_err()
        );
        assert_eq!(fs::read(&invalid_lock_path).unwrap(), b"partial");
        cleanup_persistence(&path);
        cleanup_persistence(&invalid_path);
    }

    #[test]
    fn unhealthy_veto_and_health_inputs_survive_signed_restart() {
        let path = persistence_path("unhealthy-restart-veto");
        let key = SigningKey::from_bytes(&[101; 32]);
        let governing_id = AgentId::new("tom", "primary");
        let policy = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id.clone(),
            key.clone(),
        )
        .unwrap();
        let observed_at_ms = super::now_ms();
        policy.observe_health(
            &governing_id,
            &[
                AgentHealthEntry {
                    id: "whisker-primary".to_string(),
                    role: AgentRole::Whisker,
                    health: AgentHealth::Degraded,
                },
                AgentHealthEntry {
                    // Even an exact string collision cannot turn a non-governor
                    // health entry into a committee member.
                    id: governing_id.to_string(),
                    role: AgentRole::Whisker,
                    health: AgentHealth::Failed,
                },
            ],
            observed_at_ms,
        );
        let before = policy.status_report();
        assert_eq!(before.partition_state, PartitionState::Degraded);
        assert_eq!(before.total_governors, 1);
        assert_eq!(before.healthy_governors, 1);
        assert_eq!(before.quorum_threshold, 1);
        assert!(matches!(
            policy.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.101".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        drop(policy);

        let reloaded = GovernancePolicy::with_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id,
            key,
        )
        .unwrap();
        assert!(matches!(
            reloaded.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.102".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        assert_eq!(reloaded.status_report(), before);
        cleanup_persistence(&path);
    }

    #[test]
    fn health_partition_state_and_lease_semantics_are_restart_invariant() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum DecisionClass {
            Approve,
            Veto,
            ContingencyLease,
        }

        fn classify(decision: GovernanceDecision) -> DecisionClass {
            match decision {
                GovernanceDecision::Authorize {
                    contingency_lease: Some(_),
                    ..
                } => DecisionClass::ContingencyLease,
                GovernanceDecision::Authorize { .. } => DecisionClass::Approve,
                GovernanceDecision::Veto { .. } => DecisionClass::Veto,
                GovernanceDecision::NotRequired => panic!("test action requires governance"),
            }
        }

        let base_ms = super::now_ms();
        for (label, expected_state) in [
            ("healthy", PartitionState::Healthy),
            ("degraded", PartitionState::Degraded),
            ("partitioned", PartitionState::Partitioned),
            ("healing", PartitionState::Healing),
        ] {
            let path = persistence_path(label);
            let key = SigningKey::from_bytes(&match expected_state {
                PartitionState::Healthy => [102; 32],
                PartitionState::Degraded => [103; 32],
                PartitionState::Partitioned => [104; 32],
                PartitionState::Healing => [105; 32],
            });
            let governing_id = AgentId::new("tom", "primary");
            let policy = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                governing_id.clone(),
                key.clone(),
            )
            .unwrap();
            policy.observe_health(&governing_id, &[], base_ms);
            match expected_state {
                PartitionState::Healthy => {}
                PartitionState::Degraded => policy.observe_health(
                    &governing_id,
                    &[AgentHealthEntry {
                        id: "whisker-primary".to_string(),
                        role: AgentRole::Whisker,
                        health: AgentHealth::Degraded,
                    }],
                    base_ms + 1,
                ),
                PartitionState::Partitioned | PartitionState::Healing => {
                    policy.observe_health(
                        &governing_id,
                        &[AgentHealthEntry {
                            id: governing_id.to_string(),
                            role: AgentRole::Tom,
                            health: AgentHealth::Failed,
                        }],
                        base_ms + 1,
                    );
                    if expected_state == PartitionState::Healing {
                        policy.observe_health(&governing_id, &[], base_ms + 2);
                    }
                }
            }
            let before_status = policy.status_report();
            assert_eq!(before_status.partition_state, expected_state);
            assert_eq!(before_status.total_governors, 1, "{label}");
            assert_eq!(before_status.quorum_threshold, 1, "{label}");
            assert_eq!(
                before_status.healthy_governors,
                usize::from(expected_state != PartitionState::Partitioned),
                "{label}"
            );
            let before_decision = classify(policy.can_act(&request(ResponseAction::IsolateHost {
                host_id: format!("host-before-{label}"),
            })));
            let expected_decision = match expected_state {
                PartitionState::Healthy | PartitionState::Healing => DecisionClass::Approve,
                PartitionState::Degraded => DecisionClass::Veto,
                PartitionState::Partitioned => DecisionClass::ContingencyLease,
            };
            assert_eq!(before_decision, expected_decision, "{label}");
            drop(policy);

            let reloaded = GovernancePolicy::with_persistence(
                GovernancePolicyConfig::default(),
                &path,
                governing_id,
                key,
            )
            .unwrap();
            assert_eq!(reloaded.status_report(), before_status, "{label}");
            let after_decision =
                classify(reloaded.can_act(&request(ResponseAction::IsolateHost {
                    host_id: format!("host-after-{label}"),
                })));
            assert_eq!(after_decision, before_decision, "{label}");
            cleanup_persistence(&path);
        }
    }

    #[test]
    fn local_display_and_consensus_health_ids_each_reduce_quorum_across_restart() {
        for (label, seed, report_by_consensus_id) in [
            ("local-display-health", 121, false),
            ("local-consensus-health", 122, true),
        ] {
            let path = persistence_path(label);
            let key = SigningKey::from_bytes(&[seed; 32]);
            let governing_id = AgentId::new("tom", "primary");
            let consensus_id = AgentId::from_verifying_key(&key.verifying_key());
            let policy = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                governing_id.clone(),
                key.clone(),
            )
            .unwrap();
            let base_ms = super::now_ms();
            policy.observe_health(&governing_id, &[], base_ms);
            assert_eq!(
                policy.status_report().partition_state,
                PartitionState::Healthy
            );
            policy.observe_health(
                &governing_id,
                &[AgentHealthEntry {
                    id: if report_by_consensus_id {
                        consensus_id.to_string()
                    } else {
                        governing_id.to_string()
                    },
                    role: AgentRole::Tom,
                    health: AgentHealth::Failed,
                }],
                base_ms + 1,
            );

            let before = policy.status_report();
            assert_eq!(before.total_governors, 1, "{label}");
            assert_eq!(before.healthy_governors, 0, "{label}");
            assert_eq!(before.quorum_threshold, 1, "{label}");
            assert_eq!(before.active_contingency_leases, 12, "{label}");
            assert_eq!(
                before.partition_state,
                PartitionState::Partitioned,
                "{label}"
            );
            assert!(matches!(
                policy.can_act(&request(ResponseAction::BlockEgress {
                    target: format!("{label}-before"),
                })),
                GovernanceDecision::Authorize {
                    contingency_lease: Some(_),
                    ..
                }
            ));
            drop(policy);

            let reloaded = GovernancePolicy::with_persistence(
                GovernancePolicyConfig::default(),
                &path,
                governing_id,
                key,
            )
            .unwrap();
            assert_eq!(reloaded.status_report(), before, "{label}");
            assert!(matches!(
                reloaded.can_act(&request(ResponseAction::BlockEgress {
                    target: format!("{label}-after"),
                })),
                GovernanceDecision::Authorize {
                    contingency_lease: Some(_),
                    ..
                }
            ));
            cleanup_persistence(&path);
        }
    }

    #[test]
    fn committee_expansion_invalidates_solo_lease_across_alias_health_and_restart() {
        let path = persistence_path("mixed-governor-health-aliases");
        let key = SigningKey::from_bytes(&[123; 32]);
        let governing_id = AgentId::new("tom", "primary");
        let local_consensus_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id.clone(),
            key.clone(),
        )
        .unwrap();
        let base_ms = super::now_ms();
        policy.observe_health(&governing_id, &[], base_ms);
        let staged_solo_lease = policy
            .state
            .lock()
            .unwrap()
            .active_contingency_leases
            .iter()
            .find(|lease| lease.action_kind == "block_egress")
            .cloned()
            .expect("solo healthy committee stages block-egress contingency authority");
        assert_eq!(
            staged_solo_lease
                .governance_receipt
                .payload
                .committee_members
                .len(),
            1
        );
        let peer_keys = [
            SigningKey::from_bytes(&[129; 32]),
            SigningKey::from_bytes(&[130; 32]),
            SigningKey::from_bytes(&[131; 32]),
        ];
        for peer in &peer_keys {
            policy
                .register_peer_governor(&peer.verifying_key())
                .unwrap();
        }
        let failed_peer_id = AgentId::from_verifying_key(&peer_keys[0].verifying_key());
        policy.observe_health(
            &governing_id,
            &[
                AgentHealthEntry {
                    id: governing_id.to_string(),
                    role: AgentRole::Tom,
                    health: AgentHealth::Failed,
                },
                AgentHealthEntry {
                    id: local_consensus_id.to_string(),
                    role: AgentRole::Tom,
                    health: AgentHealth::Failed,
                },
                AgentHealthEntry {
                    id: failed_peer_id.to_string(),
                    role: AgentRole::Tom,
                    health: AgentHealth::Failed,
                },
                AgentHealthEntry {
                    id: "whisker-unrelated".to_string(),
                    role: AgentRole::Whisker,
                    health: AgentHealth::Failed,
                },
            ],
            base_ms + 1,
        );

        let before = policy.status_report();
        assert_eq!(before.total_governors, 4);
        assert_eq!(before.healthy_governors, 2);
        assert_eq!(before.quorum_threshold, 3);
        assert_eq!(before.partition_state, PartitionState::Partitioned);
        match policy.can_act(&request(ResponseAction::BlockEgress {
            target: "mixed-aliases-before".to_string(),
        })) {
            GovernanceDecision::Veto { .. } => {}
            GovernanceDecision::Authorize {
                contingency_lease: Some(lease),
                ..
            } => panic!(
                "solo contingency lease authorized a four-member committee; receipt carried {} member(s)",
                lease.governance_receipt.payload.committee_members.len()
            ),
            other => panic!("expected stale contingency authority to be vetoed, got {other:?}"),
        }
        assert_eq!(before.active_contingency_leases, 0);
        let mut stale_external_request = request(ResponseAction::BlockEgress {
            target: "mixed-aliases-external-before".to_string(),
        });
        stale_external_request.evidence = json!({"contingency_lease": staged_solo_lease.clone()});
        let error = policy
            .authorize_partition_request(&stale_external_request, base_ms + 2)
            .expect_err("an external lease for the old solo committee must be refused");
        assert!(error.contains("not current committee"), "{error}");
        let persisted_before_restart = policy.status_report();
        drop(policy);

        // Simulate a genuinely local-signed envelope produced by the previous
        // implementation, where committee admission and the old solo leases
        // were persisted together. Restart must not bless those leases merely
        // because the outer state signature and persisted equality are valid.
        let envelope = read_envelope(&path);
        let mut stale_signed_payload: PersistedGovernanceState =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        stale_signed_payload
            .active_contingency_leases
            .push(staged_solo_lease.clone());
        let stale_signed_envelope = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            envelope.sequence(),
            stale_signed_payload,
            &key,
        )
        .unwrap();
        write_envelope(&path, &stale_signed_envelope);

        let reloaded = GovernancePolicy::with_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id,
            key,
        )
        .unwrap();
        assert_eq!(reloaded.status_report(), persisted_before_restart);
        assert!(matches!(
            reloaded.can_act(&request(ResponseAction::BlockEgress {
                target: "mixed-aliases-after".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        let error = reloaded
            .authorize_partition_request(&stale_external_request, base_ms + 3)
            .expect_err("the old external lease must remain invalid after signed restart");
        assert!(error.contains("not current committee"), "{error}");
        cleanup_persistence(&path);
    }

    #[test]
    fn idempotent_current_member_admission_preserves_current_committee_leases() {
        let key = SigningKey::from_bytes(&[124; 32]);
        let governing_id = AgentId::new("tom", "primary");
        let policy = GovernancePolicy::new(GovernancePolicyConfig::default());
        policy
            .register_governor(governing_id.clone(), key.clone())
            .unwrap();
        policy.observe_health(&governing_id, &[], super::now_ms());
        let before = policy
            .state
            .lock()
            .unwrap()
            .active_contingency_leases
            .clone();
        assert_eq!(before.len(), 12);

        policy
            .register_peer_governor(&key.verifying_key())
            .expect("the local member is already part of the committee");

        assert_eq!(
            policy.state.lock().unwrap().active_contingency_leases,
            before
        );
    }

    #[test]
    fn status_excludes_expired_same_committee_leases_before_and_after_restart() {
        let path = persistence_path("expired-status-restart");
        let key = SigningKey::from_bytes(&[125; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let config = GovernancePolicyConfig {
            contingency_lease_ttl_ms: 10,
            ..GovernancePolicyConfig::default()
        };
        let policy = GovernancePolicy::initialize_persistence(
            config.clone(),
            &path,
            governing_id.clone(),
            key.clone(),
        )
        .unwrap();
        policy.observe_health(&governing_id, &[], 1_000);
        assert_eq!(
            policy.state.lock().unwrap().active_contingency_leases.len(),
            12,
            "expired leases remain signed history until a governed mutation prunes them"
        );
        assert_eq!(policy.status_report_at(1_009).active_contingency_leases, 12);
        assert_eq!(policy.status_report_at(1_010).active_contingency_leases, 0);
        assert_eq!(policy.status_report().active_contingency_leases, 0);
        assert_eq!(
            policy.state.lock().unwrap().active_contingency_leases.len(),
            12,
            "a status read must not mutate signed governance state"
        );
        drop(policy);

        let reloaded =
            GovernancePolicy::with_persistence(config, &path, governing_id, key).unwrap();
        assert_eq!(
            reloaded
                .state
                .lock()
                .unwrap()
                .active_contingency_leases
                .len(),
            12,
            "same-committee persisted leases survive load as signed history"
        );
        assert_eq!(
            reloaded.status_report_at(1_009).active_contingency_leases,
            12
        );
        assert_eq!(
            reloaded.status_report_at(1_010).active_contingency_leases,
            0
        );
        assert_eq!(reloaded.status_report().active_contingency_leases, 0);
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[test]
    fn second_persisted_policy_is_refused_while_first_holds_the_state_lock() {
        let path = persistence_path("exclusive-state-lock");
        let key = SigningKey::from_bytes(&[126; 32]);
        let first = initialize_signed_policy(&path, &key);

        let second = load_signed_policy(&path, &key);
        let Err(error) = second else {
            panic!("two independent policies opened the same signed authority stream");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::StateLocked { path: ref lock_path }
                if lock_path == &GovernancePolicy::persistence_lock_path(&path)
        ));
        let Err(error) = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        ) else {
            panic!("initialization bypassed the live state lock");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::StateLocked { .. }
        ));
        let Err(error) = GovernancePolicy::reinitialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        ) else {
            panic!("offline reinitialization bypassed the live state lock");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::StateLocked { .. }
        ));

        drop(first);
        let second =
            load_signed_policy(&path, &key).expect("dropping the owner releases its advisory lock");
        drop(second);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn unlinking_the_live_lock_cannot_create_two_governance_writers() {
        const CHILD_PATH_ENV: &str = "SWARM_TEST_GOVERNANCE_SAME_RECEIPT_CHILD_PATH";
        const CHILD_RECEIPT_ENV: &str = "SWARM_TEST_GOVERNANCE_SAME_RECEIPT_PATH";
        const CHILD_RESULT_ENV: &str = "SWARM_TEST_GOVERNANCE_SAME_RECEIPT_RESULT";
        let key = SigningKey::from_bytes(&[133; 32]);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.133".to_string(),
        });
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let receipt_path = PathBuf::from(std::env::var_os(CHILD_RECEIPT_ENV).unwrap());
            let result_path = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).unwrap());
            let result = match load_signed_policy(Path::new(&path), &key) {
                Ok(policy) => {
                    let receipt: serde_json::Value =
                        serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
                    let issued_at_ms = receipt["payload"]["issued_at_ms"].as_i64().unwrap();
                    match policy.verify_and_consume_action_authorization(
                        &governed_request,
                        &receipt,
                        issued_at_ms + 1,
                    ) {
                        Ok(_) => "consume_ok".to_string(),
                        Err(error) => format!("consume_error:{error}"),
                    }
                }
                Err(error) => format!("load_error:{error}"),
            };
            fs::write(result_path, result).unwrap();
            return;
        }

        let path = persistence_path("unlinked-lock-second-writer");
        let receipt_path = path.with_extension("same-receipt.json");
        let result_path = path.with_extension("same-receipt-result");
        let first = initialize_signed_policy(&path, &key);
        let GovernanceDecision::Authorize { receipt, .. } = first.can_act(&governed_request) else {
            panic!("precondition: the first owner issues a pending authorization");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        fs::write(&receipt_path, serde_json::to_vec(&receipt_value).unwrap()).unwrap();
        let sequence_before_consume = read_envelope(&path).sequence();
        replace_lock_with_copied_record(&path);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::unlinking_the_live_lock_cannot_create_two_governance_writers")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .env(CHILD_RECEIPT_ENV, &receipt_path)
            .env(CHILD_RESULT_ENV, &result_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "same-receipt child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let child_result = fs::read_to_string(&result_path).unwrap();
        assert!(
            child_result.starts_with("load_error:") && child_result.contains("lock binding"),
            "replacement subprocess obtained same-receipt authority: {child_result}"
        );

        let error = first
            .verify_and_consume_action_authorization(
                &governed_request,
                &receipt_value,
                receipt.payload.issued_at_ms + 1,
            )
            .expect_err("the owner of the unlinked lock inode must lose write authority");
        assert!(error.contains("lock path identity changed"), "{error}");
        assert_eq!(
            read_envelope(&path).sequence(),
            sequence_before_consume,
            "the displaced owner must refuse before committing the consumption"
        );

        drop(first);
        let Err(error) = load_signed_policy(&path, &key) else {
            panic!("the pending receipt restarted on the replacement lock inode");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::LockBindingMismatch { .. }
        ));
        let _ = fs::remove_file(receipt_path);
        let _ = fs::remove_file(result_path);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn existing_stream_load_and_reinitialize_never_recreate_a_missing_lock() {
        let key = SigningKey::from_bytes(&[139; 32]);
        for (label, reinitialize) in [("load", false), ("reinitialize", true)] {
            let path = persistence_path(&format!("missing-existing-lock-{label}"));
            let policy = initialize_signed_policy(&path, &key);
            drop(policy);
            let lock_path = GovernancePolicy::persistence_lock_path(&path);
            fs::remove_file(&lock_path).unwrap();

            let result = if reinitialize {
                GovernancePolicy::reinitialize_persistence(
                    GovernancePolicyConfig::default(),
                    &path,
                    AgentId::from_verifying_key(&key.verifying_key()),
                    key.clone(),
                )
            } else {
                load_signed_policy(&path, &key)
            };
            let Err(error) = result else {
                panic!("{label} silently recreated a deleted permanent stream lock");
            };
            assert!(error.to_string().contains("lock"), "{error}");
            assert!(
                !lock_path.exists(),
                "{label} must leave the missing lock absent for operator recovery"
            );
            cleanup_persistence(&path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn initialization_never_creates_a_missing_lock_beside_any_anchor_entry() {
        use std::os::unix::fs::symlink;

        let key = SigningKey::from_bytes(&[148; 32]);
        for (label, keep_state, keep_checkpoint) in [
            ("both-real", true, true),
            ("state-real", true, false),
            ("checkpoint-real", false, true),
        ] {
            let path = persistence_path(&format!("initialize-missing-lock-{label}"));
            let policy = initialize_signed_policy(&path, &key);
            drop(policy);
            let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
            let lock_path = GovernancePolicy::persistence_lock_path(&path);
            fs::remove_file(&lock_path).unwrap();
            if !keep_state {
                fs::remove_file(&path).unwrap();
            }
            if !keep_checkpoint {
                fs::remove_file(&sequence_path).unwrap();
            }
            let state_before = keep_state.then(|| fs::read(&path).unwrap());
            let sequence_before = keep_checkpoint.then(|| fs::read(&sequence_path).unwrap());

            let error = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
            )
            .expect_err("Initialize must not replace a missing permanent lock beside any anchor");
            assert!(matches!(
                error,
                GovernancePersistenceError::MissingLock { .. }
            ));
            assert!(!lock_path.exists(), "Initialize left a new lock residue");
            assert_eq!(state_before, keep_state.then(|| fs::read(&path).unwrap()));
            assert_eq!(
                sequence_before,
                keep_checkpoint.then(|| fs::read(&sequence_path).unwrap())
            );
            cleanup_persistence(&path);
        }

        for (label, symlink_state) in [("state-symlink", true), ("checkpoint-symlink", false)] {
            let path = persistence_path(&format!("initialize-missing-lock-{label}"));
            let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
            let lock_path = GovernancePolicy::persistence_lock_path(&path);
            let target = path.with_extension(format!("{label}-target"));
            fs::write(&target, b"anchor-path-entry").unwrap();
            let anchor_path = if symlink_state { &path } else { &sequence_path };
            symlink(&target, anchor_path).unwrap();

            let error = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
            )
            .expect_err("a symlinked anchor entry must prevent implicit lock creation");
            assert!(matches!(
                error,
                GovernancePersistenceError::MissingLock { .. }
            ));
            assert!(!lock_path.exists(), "Initialize left a new lock residue");
            assert!(
                fs::symlink_metadata(anchor_path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(&target).unwrap(), b"anchor-path-entry");
            cleanup_persistence(&path);
            fs::remove_file(target).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn replacement_inode_cannot_resurrect_a_consumed_action_after_stale_overwrite() {
        const CHILD_PATH_ENV: &str = "SWARM_TEST_GOVERNANCE_ACTION_RACE_CHILD_PATH";
        const CHILD_RECEIPT_ENV: &str = "SWARM_TEST_GOVERNANCE_ACTION_RACE_RECEIPT_PATH";
        const CHILD_RESULT_ENV: &str = "SWARM_TEST_GOVERNANCE_ACTION_RACE_RESULT_PATH";
        let key = SigningKey::from_bytes(&[140; 32]);
        let child_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.141".to_string(),
        });
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let receipt_path = PathBuf::from(std::env::var_os(CHILD_RECEIPT_ENV).unwrap());
            let result_path = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).unwrap());
            let result = match load_signed_policy(Path::new(&path), &key) {
                Ok(policy) => {
                    let receipt: serde_json::Value =
                        serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
                    match policy.verify_and_consume_action_authorization(
                        &child_request,
                        &receipt,
                        super::now_ms(),
                    ) {
                        Ok(_) => "mutation_ok".to_string(),
                        Err(error) => format!("mutation_error:{error}"),
                    }
                }
                Err(error) => format!("load_error:{error}"),
            };
            fs::write(result_path, result).unwrap();
            return;
        }

        let path = persistence_path("replacement-action-stale-overwrite");
        let receipt_path = path.with_extension("child-receipt.json");
        let result_path = path.with_extension("child-result");
        let policy = initialize_signed_policy(&path, &key);
        let parent_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.140".to_string(),
        });
        let GovernanceDecision::Authorize {
            receipt: parent_receipt,
            ..
        } = policy.can_act(&parent_request)
        else {
            panic!("precondition: parent authorization was not issued");
        };
        let GovernanceDecision::Authorize {
            receipt: child_receipt,
            ..
        } = policy.can_act(&child_request)
        else {
            panic!("precondition: child authorization was not issued");
        };
        let parent_receipt_value = serde_json::to_value(&parent_receipt).unwrap();
        fs::write(
            &receipt_path,
            serde_json::to_vec(&serde_json::to_value(&child_receipt).unwrap()).unwrap(),
        )
        .unwrap();
        let (pre_write_reached, resume_parent_write) = policy
            .persistence
            .as_ref()
            .unwrap()
            .install_pre_write_barrier();

        std::thread::scope(|scope| {
            let parent_consume = scope.spawn(|| {
                policy.verify_and_consume_action_authorization(
                    &parent_request,
                    &parent_receipt_value,
                    parent_receipt.payload.issued_at_ms + 1,
                )
            });
            let mut resume_parent_write =
                BarrierReleaseGuard::new(Arc::clone(&resume_parent_write));
            pre_write_reached.wait();
            replace_lock_with_copied_record(&path);

            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(
                    "tests::replacement_inode_cannot_resurrect_a_consumed_action_after_stale_overwrite",
                )
                .arg("--nocapture")
                .env(CHILD_PATH_ENV, &path)
                .env(CHILD_RECEIPT_ENV, &receipt_path)
                .env(CHILD_RESULT_ENV, &result_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn();
            let output = child.and_then(|child| child.wait_with_output());
            resume_parent_write.release();
            let parent_result = parent_consume.join().unwrap();
            let output = output.unwrap();
            assert!(
                output.status.success(),
                "replacement child failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let child_result = fs::read_to_string(&result_path).unwrap();
            assert!(
                parent_result.is_err(),
                "the displaced parent must receive no execution admission"
            );
            assert!(
                child_result.starts_with("load_error:") && child_result.contains("lock binding"),
                "replacement inode admitted the child mutation: {child_result}"
            );
        });

        drop(policy);
        let Err(error) = load_signed_policy(&path, &key) else {
            panic!("a stream signed for the displaced inode restarted on its replacement");
        };
        assert!(error.to_string().contains("lock binding"), "{error}");
        let _ = fs::remove_file(receipt_path);
        let _ = fs::remove_file(result_path);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_inode_admits_neither_side_of_a_human_one_shot() {
        const CHILD_PATH_ENV: &str = "SWARM_TEST_GOVERNANCE_HUMAN_RACE_CHILD_PATH";
        const CHILD_HOLD_ENV: &str = "SWARM_TEST_GOVERNANCE_HUMAN_RACE_HOLD";
        const CHILD_SET_ENV: &str = "SWARM_TEST_GOVERNANCE_HUMAN_RACE_SET";
        const CHILD_DIGEST_ENV: &str = "SWARM_TEST_GOVERNANCE_HUMAN_RACE_DIGEST";
        const CHILD_NOW_ENV: &str = "SWARM_TEST_GOVERNANCE_HUMAN_RACE_NOW";
        const CHILD_RESULT_ENV: &str = "SWARM_TEST_GOVERNANCE_HUMAN_RACE_RESULT";
        let key = SigningKey::from_bytes(&[141; 32]);
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let hold_id = std::env::var(CHILD_HOLD_ENV).unwrap();
            let set_id = std::env::var(CHILD_SET_ENV).unwrap();
            let set_digest = std::env::var(CHILD_DIGEST_ENV).unwrap();
            let now_ms = std::env::var(CHILD_NOW_ENV).unwrap().parse().unwrap();
            let result_path = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).unwrap());
            let result = match load_signed_policy(Path::new(&path), &key) {
                Ok(policy) => match policy.verify_and_consume_human_authorization(
                    &hold_id,
                    &set_id,
                    &set_digest,
                    now_ms,
                ) {
                    Ok(_) => "consume_ok".to_string(),
                    Err(error) => format!("consume_error:{error}"),
                },
                Err(error) => format!("load_error:{error}"),
            };
            fs::write(result_path, result).unwrap();
            return;
        }

        let path = persistence_path("replacement-human-one-shot");
        let approval_root = path.with_extension("approval-fixture");
        let result_path = path.with_extension("human-child-result");
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.142".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: governance authorization was not issued");
        };
        let decision = swarm_policy::PolicyDecision::require_human_with_rule(
            "replacement-human-one-shot",
            "human review required",
        );
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &serde_json::to_value(&receipt).unwrap(),
                &decision,
                receipt.payload.issued_at_ms + 1,
            )
            .unwrap();
        let approval_harness = DefaultApprovalHarness::from_path(
            approval_root.join("config"),
            approval_root.join("verdicts"),
            approval_root.join("packs"),
            approval_root.join("sets"),
            approval_root.join("ledgers"),
        )
        .unwrap();
        let voter = Ed25519Signer::from_secret_material("replacement-human-voter");
        let voter_id = format!("swarm:ed25519:{}", voter.public_key_hex());
        let set_record = approval_harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::Unanimous,
                &hold.approval_evidence_ref(),
            )
            .unwrap();
        approval_harness
            .append_vote(&set_record.set_id, &voter_id, &voter)
            .unwrap();
        let set = approval_harness
            .load_approval_set(&set_record.set_id)
            .unwrap()
            .unwrap()
            .report;
        let ledger_id = approval_harness
            .list_ledgers(Some(&set.set_id))
            .unwrap()
            .ledgers[0]
            .ledger_id
            .clone();
        let ledger = approval_harness
            .load_ledger(&ledger_id)
            .unwrap()
            .unwrap()
            .report;
        let evaluated_at_ms = super::now_ms();
        let verdict = evaluate_verdict(&set, &ledger, evaluated_at_ms).unwrap();
        let pack_signer = Ed25519Signer::from_secret_material("replacement-human-pack");
        let pack = build_receipt_pack(
            &set,
            &ledger,
            &verdict,
            vec![hold.approval_evidence_ref()],
            &pack_signer,
            "replacement-human-pack",
            evaluated_at_ms + 1,
        )
        .unwrap();
        let set_digest = approval_set_digest(&set).unwrap();
        let bound_hold = policy
            .bind_human_approval_set(&hold.hold_id, &set.set_id, &set_digest)
            .unwrap();
        verify_governed_human_receipt_pack(
            &pack,
            bound_hold.approval_set_id.as_deref().unwrap(),
            bound_hold.approval_set_digest.as_deref().unwrap(),
            &bound_hold.approval_evidence_ref(),
            bound_hold.created_at_ms,
            pack.created_at_ms + 1,
        )
        .expect("precondition: a genuine signed approval pack matches the exact persisted hold");

        let consume_at_ms = pack.created_at_ms + 1;
        let (pre_write_reached, resume_parent_write) = policy
            .persistence
            .as_ref()
            .unwrap()
            .install_pre_write_barrier();
        std::thread::scope(|scope| {
            let parent_consume = scope.spawn(|| {
                policy.verify_and_consume_human_authorization(
                    &hold.hold_id,
                    &set.set_id,
                    &set_digest,
                    consume_at_ms,
                )
            });
            pre_write_reached.wait();
            replace_lock_with_copied_record(&path);
            resume_parent_write.wait();
            let error = parent_consume
                .join()
                .unwrap()
                .expect_err("the displaced owner must not obtain human execution authority");
            assert!(error.contains("lock path identity changed"), "{error}");
        });

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::replacement_inode_admits_neither_side_of_a_human_one_shot")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .env(CHILD_HOLD_ENV, &hold.hold_id)
            .env(CHILD_SET_ENV, &set.set_id)
            .env(CHILD_DIGEST_ENV, &set_digest)
            .env(CHILD_NOW_ENV, consume_at_ms.to_string())
            .env(CHILD_RESULT_ENV, &result_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "human replacement child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let child_result = fs::read_to_string(&result_path).unwrap();
        assert!(
            child_result.starts_with("load_error:") && child_result.contains("lock binding"),
            "replacement subprocess obtained human one-shot authority: {child_result}"
        );
        drop(policy);

        let Err(error) = load_signed_policy(&path, &key) else {
            panic!("pending human authority restarted on a replacement lock inode");
        };
        assert!(error.to_string().contains("lock binding"), "{error}");
        let _ = fs::remove_file(result_path);
        cleanup_persistence(&path);
        fs::remove_dir_all(approval_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unlinked_lock_race_admits_neither_displaced_nor_replacement_process() {
        const CHILD_PATH_ENV: &str = "SWARM_TEST_GOVERNANCE_REPLACED_LOCK_CHILD_PATH";
        const CHILD_READY_ENV: &str = "SWARM_TEST_GOVERNANCE_REPLACED_LOCK_READY_PATH";
        const CHILD_GO_ENV: &str = "SWARM_TEST_GOVERNANCE_REPLACED_LOCK_GO_PATH";
        let key = SigningKey::from_bytes(&[136; 32]);
        let child_peer = SigningKey::from_bytes(&[138; 32]);
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let ready_path = PathBuf::from(std::env::var_os(CHILD_READY_ENV).unwrap());
            let go_path = PathBuf::from(std::env::var_os(CHILD_GO_ENV).unwrap());
            let policy = match load_signed_policy(Path::new(&path), &key) {
                Ok(policy) => policy,
                Err(error) => {
                    fs::write(&ready_path, format!("load_error:{error}")).unwrap();
                    return;
                }
            };
            fs::write(&ready_path, b"ready").unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !go_path.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "parent did not release the synchronized mutation race"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            policy
                .register_peer_governor(&child_peer.verifying_key())
                .expect("replacement lock owner commits its distinct peer admission");
            return;
        }

        let path = persistence_path("unlinked-lock-subprocess-race");
        let ready_path = path.with_extension("race-ready");
        let go_path = path.with_extension("race-go");
        let parent_peer = SigningKey::from_bytes(&[137; 32]);
        let parent = initialize_signed_policy(&path, &key);
        let initial_sequence = read_envelope(&path).sequence();
        replace_lock_with_copied_record(&path);

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::unlinked_lock_race_admits_neither_displaced_nor_replacement_process")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .env(CHILD_READY_ENV, &ready_path)
            .env(CHILD_GO_ENV, &go_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !ready_path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "replacement child did not acquire the new lock inode"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        fs::write(&go_path, b"go").unwrap();
        let error = parent
            .register_peer_governor(&parent_peer.verifying_key())
            .expect_err("the displaced parent must fail its synchronized mutation before write");
        assert!(error.contains("lock path identity changed"), "{error}");
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "replacement child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let child_result = fs::read_to_string(&ready_path).unwrap();
        assert!(
            child_result.starts_with("load_error:") && child_result.contains("lock binding"),
            "replacement child reached peer admission: {child_result}"
        );

        assert_eq!(read_envelope(&path).sequence(), initial_sequence);
        let durable: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert!(durable.peer_governors.is_empty());

        drop(parent);
        let Err(error) = load_signed_policy(&path, &key) else {
            panic!("the stream restarted on its replacement lock inode");
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::LockBindingMismatch { .. }
        ));
        let _ = fs::remove_file(ready_path);
        let _ = fs::remove_file(go_path);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn governance_lock_path_rejects_a_symlink() {
        use std::os::unix::fs::symlink;

        let path = persistence_path("symlink-lock-path");
        let key = SigningKey::from_bytes(&[134; 32]);
        let lock_path = GovernancePolicy::persistence_lock_path(&path);
        let symlink_target = lock_path.with_extension("lock-target");
        fs::write(&symlink_target, b"not a governance lock").unwrap();
        symlink(&symlink_target, &lock_path).unwrap();

        let error = match GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        ) {
            Ok(policy) => {
                drop(policy);
                cleanup_persistence(&path);
                let _ = fs::remove_file(&symlink_target);
                panic!("a symlink was accepted as the governance lock path");
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("regular non-symlink"), "{error}");
        cleanup_persistence(&path);
        let _ = fs::remove_file(symlink_target);
    }

    #[test]
    fn governance_lock_path_rejects_a_nonregular_file() {
        let path = persistence_path("nonregular-lock-path");
        let key = SigningKey::from_bytes(&[135; 32]);
        let lock_path = GovernancePolicy::persistence_lock_path(&path);
        fs::create_dir(&lock_path).unwrap();

        let error = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        )
        .expect_err("a directory was accepted as the governance lock path");
        assert!(error.to_string().contains("regular non-symlink"), "{error}");

        fs::remove_dir(lock_path).unwrap();
        cleanup_persistence(&path);
    }

    #[test]
    fn separate_process_cannot_open_a_live_governance_state_lock() {
        const CHILD_PATH_ENV: &str = "SWARM_TEST_GOVERNANCE_LOCK_CHILD_PATH";
        let key = SigningKey::from_bytes(&[128; 32]);
        if let Some(path) = std::env::var_os(CHILD_PATH_ENV) {
            let error = match load_signed_policy(Path::new(&path), &key) {
                Ok(_) => panic!("child process opened the parent's authority stream"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                GovernancePersistenceError::StateLocked { .. }
            ));
            return;
        }

        let path = persistence_path("exclusive-state-lock-process");
        let first = initialize_signed_policy(&path, &key);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::separate_process_cannot_open_a_live_governance_state_lock")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child lock assertion failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        drop(first);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[test]
    fn sequence_cas_refuses_the_exact_stale_double_consume_snapshot() {
        let path = persistence_path("stale-double-consume-cas");
        let key = SigningKey::from_bytes(&[127; 32]);
        let first = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.127".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = first.can_act(&governed_request) else {
            panic!("precondition: first policy issues a pending authorization");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let sequence_before_consumption = read_envelope(&path).sequence();
        let stale_second = duplicate_locked_policy_snapshot(&first, &key);

        first
            .verify_and_consume_action_authorization(
                &governed_request,
                &receipt_value,
                receipt.payload.issued_at_ms + 1,
            )
            .expect("the first snapshot consumes and commits the authorization");
        let committed_sequence = read_envelope(&path).sequence();
        assert_eq!(committed_sequence, sequence_before_consumption + 1);

        let error = stale_second
            .verify_and_consume_action_authorization(
                &governed_request,
                &receipt_value,
                receipt.payload.issued_at_ms + 1,
            )
            .expect_err("the stale snapshot must not borrow the durable next sequence");
        assert!(error.contains("stale governance transaction"), "{error}");
        assert_eq!(
            read_envelope(&path).sequence(),
            committed_sequence,
            "the rejected stale snapshot must not create sequence four"
        );
        assert_eq!(
            stale_second
                .state
                .lock()
                .unwrap()
                .pending_authorizations
                .len(),
            1,
            "pre-commit CAS failure restores the stale caller's memory"
        );

        drop(first);
        drop(stale_second);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert!(
            reloaded
                .verify_and_consume_action_authorization(
                    &governed_request,
                    &receipt_value,
                    receipt.payload.issued_at_ms + 2,
                )
                .is_err(),
            "durable state records exactly one consumption"
        );
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[test]
    fn sequence_cas_refuses_stale_human_consumption_and_restores_the_hold() {
        let path = persistence_path("stale-human-consume-cas");
        let key = SigningKey::from_bytes(&[129; 32]);
        let first = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.129".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = first.can_act(&governed_request) else {
            panic!("precondition: healthy governance issues an approval");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let decision = swarm_policy::PolicyDecision::require_human_with_rule(
            "stale-human-cas",
            "human review required",
        );
        let hold = first
            .begin_human_authorization_hold(
                &governed_request,
                &receipt_value,
                &decision,
                receipt.payload.issued_at_ms + 1,
            )
            .unwrap();
        first
            .bind_human_approval_set(&hold.hold_id, "approval-set:129", "digest:129")
            .unwrap();
        let stale_second = duplicate_locked_policy_snapshot(&first, &key);
        let sequence_before_consumption = read_envelope(&path).sequence();

        first
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:129",
                "digest:129",
                receipt.payload.issued_at_ms + 2,
            )
            .expect("the first snapshot commits human and governance consumption");
        let committed_sequence = read_envelope(&path).sequence();
        assert_eq!(committed_sequence, sequence_before_consumption + 1);
        let error = stale_second
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:129",
                "digest:129",
                receipt.payload.issued_at_ms + 2,
            )
            .expect_err("a stale human hold must not authorize a second execution");
        assert!(error.contains("stale governance transaction"), "{error}");
        assert_eq!(read_envelope(&path).sequence(), committed_sequence);
        let stale_state = stale_second.state.lock().unwrap();
        assert_eq!(stale_state.pending_human_authorizations.len(), 1);
        assert_eq!(stale_state.pending_authorizations.len(), 1);
        assert!(stale_state.consumed_authorizations.is_empty());
        drop(stale_state);

        drop(first);
        drop(stale_second);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert!(
            reloaded
                .verify_and_consume_human_authorization(
                    &hold.hold_id,
                    "approval-set:129",
                    "digest:129",
                    receipt.payload.issued_at_ms + 3,
                )
                .is_err()
        );
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[test]
    fn pre_partition_human_hold_is_refused_during_partition_without_mutation() {
        let path = persistence_path("pre-partition-human-hold-partition");
        let key = SigningKey::from_bytes(&[177; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.177".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: healthy governance issues an approval");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let decision = swarm_policy::PolicyDecision::require_human_with_rule(
            "pre-partition-human-hold",
            "human review required",
        );
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &receipt_value,
                &decision,
                receipt.payload.issued_at_ms + 1,
            )
            .unwrap();
        policy
            .bind_human_approval_set(&hold.hold_id, "approval-set:177", "digest:177")
            .unwrap();

        policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            receipt.payload.issued_at_ms + 2,
        );
        assert_eq!(
            policy.status_report().partition_state,
            PartitionState::Partitioned
        );
        let partition_sequence = read_envelope(&path).sequence();
        let partition_bytes = fs::read(&path).unwrap();
        let partition_checkpoint_bytes =
            fs::read(GovernancePolicy::persistence_sequence_path(&path)).unwrap();

        let error = policy
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:177",
                "digest:177",
                receipt.payload.issued_at_ms + 3,
            )
            .expect_err("a pre-partition human hold must not route during partition");
        assert!(
            error.contains("partition")
                || error.contains("Partitioned")
                || error.contains("healthy"),
            "unexpected refusal reason: {error}"
        );
        assert_eq!(
            read_envelope(&path).sequence(),
            partition_sequence,
            "a refused hold must not advance the durable sequence"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            partition_bytes,
            "a refused hold must not rewrite signed state"
        );
        assert_eq!(
            fs::read(GovernancePolicy::persistence_sequence_path(&path)).unwrap(),
            partition_checkpoint_bytes,
            "a refused hold must not rewrite its checkpoint"
        );
        assert!(
            policy
                .pending_human_authorization("approval-set:177")
                .is_ok(),
            "the one-time hold remains pending after a fail-closed refusal"
        );

        let retry_error = policy
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:177",
                "digest:177",
                receipt.payload.issued_at_ms + 4,
            )
            .expect_err("retrying the same pre-partition hold must remain refused");
        assert_eq!(retry_error, error, "partition refusal is idempotent");
        assert_eq!(read_envelope(&path).sequence(), partition_sequence);
        assert_eq!(fs::read(&path).unwrap(), partition_bytes);
        assert_eq!(
            fs::read(GovernancePolicy::persistence_sequence_path(&path)).unwrap(),
            partition_checkpoint_bytes
        );

        drop(policy);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert_eq!(
            reloaded.status_report().partition_state,
            PartitionState::Partitioned
        );
        assert!(
            reloaded
                .verify_and_consume_human_authorization(
                    &hold.hold_id,
                    "approval-set:177",
                    "digest:177",
                    receipt.payload.issued_at_ms + 5,
                )
                .is_err(),
            "restart must preserve the fail-closed partition boundary"
        );
        assert!(
            reloaded
                .pending_human_authorization("approval-set:177")
                .is_ok(),
            "restart must preserve the unconsumed hold rather than minting authority"
        );
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[test]
    fn unchanged_health_observation_does_not_persist_or_advance_sequence() {
        let path = persistence_path("unchanged-health-no-persist");
        let key = SigningKey::from_bytes(&[178; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        policy.observe_health(&governing_id, &[], 1_780_000_000_000);
        let stable_sequence = read_envelope(&path).sequence();
        let stable_state = fs::read(&path).unwrap();
        let stable_checkpoint =
            fs::read(GovernancePolicy::persistence_sequence_path(&path)).unwrap();
        let stable_status = policy.status_report_at(1_780_000_000_001);

        for observed_at_ms in 1_780_000_000_001..=1_780_000_000_010 {
            policy.observe_health(&governing_id, &[], observed_at_ms);
            assert_eq!(
                read_envelope(&path).sequence(),
                stable_sequence,
                "unchanged health at {observed_at_ms} must not advance the signed sequence"
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                stable_state,
                "unchanged health at {observed_at_ms} must not rewrite signed state"
            );
            assert_eq!(
                fs::read(GovernancePolicy::persistence_sequence_path(&path)).unwrap(),
                stable_checkpoint,
                "unchanged health at {observed_at_ms} must not rewrite its checkpoint"
            );
            assert_eq!(
                policy.status_report_at(observed_at_ms),
                stable_status,
                "unchanged health at {observed_at_ms} must not mutate durable status"
            );
        }

        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn health_checkpoint_repair_retries_only_at_the_logical_deadline() {
        let path = persistence_path("health-checkpoint-repair-backoff");
        let key = SigningKey::from_bytes(&[180; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let base_ms = 1_800_000_000_000;
        policy.observe_health(&governing_id, &[], base_ms);

        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);
        let degraded_entries = [AgentHealthEntry {
            id: "whisker-repair-backoff".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }];
        let changed_degraded_entries = [AgentHealthEntry {
            id: "whisker-repair-backoff-alternate".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }];
        policy.observe_health(&governing_id, &degraded_entries, base_ms + 1);
        let first_retry_at_ms = base_ms + 1 + GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS;
        {
            let state = policy.state.lock().unwrap();
            assert!(state.checkpoint_lagging.is_some());
            assert_eq!(
                state
                    .checkpoint_repair_backoff
                    .expect("initial checkpoint failure establishes a retry deadline")
                    .retry_at_ms,
                first_retry_at_ms
            );
        }

        // The first repair attempt fails while the checkpoint path is still
        // blocked. Subsequent unchanged health observations must not keep
        // retrying synchronously.
        policy.observe_health(&governing_id, &degraded_entries, first_retry_at_ms);
        {
            let state = policy.state.lock().unwrap();
            assert!(state.checkpoint_lagging.is_some());
            let backoff = state
                .checkpoint_repair_backoff
                .expect("failed repair establishes an ephemeral retry deadline");
            assert_eq!(
                backoff.retry_at_ms,
                first_retry_at_ms + GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS
            );
            assert!(!backoff.saturated);
        }
        fs::remove_dir(blocker).unwrap();
        let stable_sequence = read_envelope(&path).sequence();
        let stable_state = fs::read(&path).unwrap();
        let stable_checkpoint = fs::read(&sequence_path).unwrap();
        let stable_memory = health_memory_snapshot(&policy);
        let retry_at_ms = first_retry_at_ms + GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS;

        let mut expected_pending_health = stable_memory.pending_health_observation.clone();
        let mut expected_sequence = stable_sequence;
        let mut expected_state = stable_state.clone();
        let mut expected_digest = stable_memory.persistence_digest.clone();
        let mut expected_lag = stable_memory.checkpoint_lagging.clone();
        let mut durable_pending_committed = false;
        for (offset, observed_at_ms) in ((first_retry_at_ms + 1)..retry_at_ms).enumerate() {
            let entries = if offset % 2 == 0 {
                &degraded_entries
            } else {
                &changed_degraded_entries
            };
            policy.observe_health(&governing_id, entries, observed_at_ms);
            let memory = health_memory_snapshot(&policy);
            let observed_sequence = read_envelope(&path).sequence();
            if observed_sequence != expected_sequence {
                assert!(
                    !durable_pending_committed,
                    "health backoff may durably record the pending marker only once"
                );
                durable_pending_committed = true;
                expected_sequence = observed_sequence;
                expected_state = fs::read(&path).unwrap();
                expected_digest = memory.persistence_digest.clone();
                expected_lag = memory.checkpoint_lagging.clone();
            }
            if entries.as_slice() == changed_degraded_entries.as_slice()
                || durable_pending_committed
            {
                expected_pending_health = Some(super::PendingHealthObservation {
                    governing_agent_id: governing_id.clone(),
                    entries: entries.to_vec(),
                    observed_at_ms,
                });
            }
            assert_eq!(
                memory
                    .projection
                    .clone()
                    .without_pending_health_observation(),
                stable_memory
                    .projection
                    .clone()
                    .without_pending_health_observation(),
                "deferred health tick at {observed_at_ms} must restore the full health projection"
            );
            assert_eq!(
                memory.pending_events, stable_memory.pending_events,
                "deferred health tick at {observed_at_ms} must restore pending runtime events"
            );
            assert_eq!(
                memory.checkpoint_lagging, expected_lag,
                "deferred health tick at {observed_at_ms} must preserve checkpoint lag"
            );
            assert_eq!(
                memory.checkpoint_repair_backoff, stable_memory.checkpoint_repair_backoff,
                "deferred health tick at {observed_at_ms} must preserve retry state"
            );
            assert_eq!(
                memory.persistence_sequence,
                Some(expected_sequence),
                "deferred health tick at {observed_at_ms} must advance at most once for the durable pending marker"
            );
            assert_eq!(
                memory.persistence_digest, expected_digest,
                "deferred health tick at {observed_at_ms} must not rewrite after the durable pending marker"
            );
            assert_eq!(
                memory.pending_health_observation, expected_pending_health,
                "only the explicit pending-health safety marker may retain the latest observation"
            );
            assert!(
                policy.state.lock().unwrap().checkpoint_lagging.is_some(),
                "repair must remain deferred before its logical deadline at {observed_at_ms}"
            );
            assert_eq!(
                policy
                    .state
                    .lock()
                    .unwrap()
                    .checkpoint_repair_backoff
                    .expect("backoff remains armed before its deadline")
                    .retry_at_ms,
                retry_at_ms,
                "repeated failed health ticks must not move the retry deadline"
            );
            assert_eq!(fs::read(&path).unwrap(), expected_state);
            assert_eq!(fs::read(&sequence_path).unwrap(), stable_checkpoint);
        }

        // The final tick carries the latest alternate snapshot. Repair the
        // checkpoint first, then persist that snapshot as the next signed state.
        policy.observe_health(&governing_id, &changed_degraded_entries, retry_at_ms);
        let state = policy.state.lock().unwrap();
        assert!(
            state.checkpoint_lagging.is_none(),
            "repair must be retried at the exact logical deadline"
        );
        assert!(
            state.checkpoint_repair_backoff.is_none(),
            "successful checkpoint repair clears the health-tick backoff"
        );
        assert!(
            state.pending_health_observation.is_none(),
            "the exact-deadline health commit clears the pending safety marker"
        );
        assert_eq!(
            state.unhealthy_agents, changed_degraded_entries,
            "the latest alternate health snapshot must be retained in memory"
        );
        assert_eq!(state.partition_state, PartitionState::Degraded);
        drop(state);
        assert_eq!(
            policy.status_report_at(retry_at_ms).partition_state,
            PartitionState::Degraded,
            "status must reflect the latest alternate health snapshot"
        );
        let durable: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert_eq!(
            durable.unhealthy_agents, changed_degraded_entries,
            "the signed payload must reflect the latest alternate health snapshot"
        );
        assert_eq!(durable.partition_state, PartitionState::Degraded);
        let repaired_sequence = expected_sequence + 1;
        assert_eq!(read_envelope(&path).sequence(), repaired_sequence);
        assert_eq!(
            checkpoint_sequence(&read_checkpoint(&path)),
            repaired_sequence,
            "repair and the latest health snapshot must share the new checkpoint sequence"
        );

        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn health_checkpoint_backoff_skips_contingency_rounds_until_deadline() {
        let path = persistence_path("health-checkpoint-round-backoff");
        let key = SigningKey::from_bytes(&[181; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let transport = Arc::new(CountingTransport::default());
        let config = GovernancePolicyConfig {
            contingency_lease_ttl_ms: 1,
            ..GovernancePolicyConfig::default()
        };
        let policy = GovernancePolicy::initialize_persistence(
            config,
            &path,
            governing_id.clone(),
            key.clone(),
        )
        .unwrap()
        .with_transport(Arc::clone(&transport) as Arc<dyn ConsensusTransport>);
        let base_ms = 1_810_000_000_000;
        policy.observe_health(&governing_id, &[], base_ms);
        assert_eq!(
            transport.rounds(),
            ResponseAction::governed_action_kinds().len(),
            "initial healthy observation stages one lease for every governed action"
        );

        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);
        let degraded_entries = [AgentHealthEntry {
            id: "whisker-round-backoff".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }];
        policy.observe_health(&governing_id, &degraded_entries, base_ms + 2);
        let first_retry_at_ms = base_ms + 2 + GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS;
        let rounds_before_failed_retry = transport.rounds();

        // The failed repair at its first deadline must still roll the health
        // observation back before the healthy branch can stage leases.
        policy.observe_health(&governing_id, &[], first_retry_at_ms);
        assert_eq!(
            transport.rounds(),
            rounds_before_failed_retry,
            "a failed repair deadline must not run contingency rounds before rollback"
        );
        let retry_at_ms = first_retry_at_ms + GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS;
        fs::remove_dir(blocker).unwrap();

        let rounds_before_deferred_ticks = transport.rounds();
        for observed_at_ms in (first_retry_at_ms + 1)..retry_at_ms {
            // Healthy snapshots would call ensure_contingency_leases_locked
            // after the old rollback guard and therefore expose twelve rounds
            // per tick. They must remain side-effect-free while repair is
            // deferred.
            policy.observe_health(&governing_id, &[], observed_at_ms);
            assert_eq!(
                transport.rounds(),
                rounds_before_deferred_ticks,
                "health tick at {observed_at_ms} must not run a governance round before retry"
            );
            assert!(
                policy.state.lock().unwrap().checkpoint_lagging.is_some(),
                "checkpoint repair must remain deferred at {observed_at_ms}"
            );
        }

        policy.observe_health(&governing_id, &[], retry_at_ms);
        let rounds_at_deadline = transport.rounds() - rounds_before_deferred_ticks;
        assert_eq!(
            rounds_at_deadline,
            ResponseAction::governed_action_kinds().len(),
            "the exact retry deadline may stage one bounded lease round per governed action"
        );
        let state = policy.state.lock().unwrap();
        assert!(state.checkpoint_lagging.is_none());
        assert_eq!(state.partition_state, PartitionState::Healthy);
        assert_eq!(
            state.active_contingency_leases.len(),
            ResponseAction::governed_action_kinds().len()
        );
        drop(state);

        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn restrictive_health_pending_during_checkpoint_backoff_blocks_direct_authority() {
        let path = persistence_path("restrictive-health-pending-authority");
        let key = SigningKey::from_bytes(&[182; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let base_ms = 1_820_000_000_000;
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);

        // The first health write changes only the healthy state's staged leases,
        // so it commits a Healthy signed envelope while its checkpoint lags.
        policy.observe_health(&governing_id, &[], base_ms);
        {
            let state = policy.state.lock().unwrap();
            assert_eq!(state.partition_state, PartitionState::Healthy);
            assert!(state.checkpoint_lagging.is_some());
            assert!(state.checkpoint_repair_backoff.is_some());
        }

        let restrictive_entries = [AgentHealthEntry {
            id: governing_id.to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }];
        // This is before the health retry deadline. The restrictive input must
        // not leak into the rolled-back projection, but it must remain as an
        // explicit fail-closed pending observation.
        policy.observe_health(&governing_id, &restrictive_entries, base_ms + 1);
        {
            let state = policy.state.lock().unwrap();
            assert_eq!(state.partition_state, PartitionState::Healthy);
            assert_eq!(state.unhealthy_agents, Vec::<AgentHealthEntry>::new());
            let pending = state
                .pending_health_observation
                .as_ref()
                .expect("restrictive health input must remain pending");
            assert_eq!(pending.governing_agent_id, governing_id);
            assert_eq!(pending.entries, restrictive_entries);
            assert_eq!(pending.observed_at_ms, base_ms + 1);
        }
        let durable: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert_eq!(durable.partition_state, PartitionState::Healthy);
        assert!(durable.unhealthy_agents.is_empty());
        assert_eq!(
            durable.pending_health_observation.as_ref().unwrap().entries,
            restrictive_entries
        );
        let durable_state_bytes = fs::read(&path).unwrap();
        let durable_sequence = read_envelope(&path).sequence();
        assert!(durable_sequence > 1);

        // Repair is now possible, but the pending restrictive input must still
        // prevent can_act from issuing a stale Healthy authorization.
        fs::remove_dir(blocker).unwrap();
        let decision = policy.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.182".to_string(),
        }));
        let GovernanceDecision::Veto {
            reason, receipt, ..
        } = decision
        else {
            panic!("a pending restrictive health observation must fail closed");
        };
        assert!(reason.contains("deferred health observation"), "{reason}");
        assert!(receipt.is_none());
        {
            let state = policy.state.lock().unwrap();
            assert!(state.checkpoint_lagging.is_none());
            assert!(state.pending_health_observation.is_some());
            assert_eq!(state.partition_state, PartitionState::Healthy);
        }
        assert!(policy.is_partitioned());
        assert_eq!(
            policy.status_report().partition_state,
            PartitionState::Partitioned,
            "a restrictive pending projection must not expose stale Healthy status"
        );
        assert_eq!(read_envelope(&path).sequence(), durable_sequence);
        assert_eq!(fs::read(&path).unwrap(), durable_state_bytes);
        assert_eq!(
            checkpoint_sequence(&read_checkpoint(&path)),
            durable_sequence
        );

        // A subsequent health tick can clear the pending marker by committing
        // the restrictive snapshot; authority remains refused at the actual
        // partition boundary as well.
        policy.observe_health(&governing_id, &restrictive_entries, base_ms + 2);
        {
            let state = policy.state.lock().unwrap();
            assert_eq!(state.partition_state, PartitionState::Partitioned);
            assert!(state.pending_health_observation.is_none());
        }

        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn durable_pending_health_survives_restart_and_tampering_fails_closed() {
        let path = persistence_path("durable-pending-health-restart");
        let key = SigningKey::from_bytes(&[183; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let base_ms = 1_830_000_000_000;
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);
        policy.observe_health(&governing_id, &[], base_ms);
        let restrictive_entries = [AgentHealthEntry {
            id: governing_id.to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }];
        policy.observe_health(&governing_id, &restrictive_entries, base_ms + 1);
        let durable: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert_eq!(
            durable
                .pending_health_observation
                .as_ref()
                .map(|pending| pending.entries.clone()),
            Some(restrictive_entries.to_vec())
        );
        drop(policy);
        fs::remove_dir(blocker).unwrap();

        let reopened = Arc::new(load_signed_policy(&path, &key).unwrap());
        assert!(reopened.is_partitioned());
        assert_eq!(
            reopened.status_report().partition_state,
            PartitionState::Partitioned
        );
        let decision = reopened.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.183".to_string(),
        }));
        let GovernanceDecision::Veto {
            receipt, reason, ..
        } = decision
        else {
            panic!("restarted pending health must veto stale Healthy authority");
        };
        assert!(receipt.is_none());
        assert!(reason.contains("deferred health observation"), "{reason}");

        reopened.observe_health(&governing_id, &restrictive_entries, base_ms + 2);
        let committed: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert!(committed.pending_health_observation.is_none());
        assert_eq!(committed.partition_state, PartitionState::Partitioned);
        drop(reopened);

        let tamper_path = persistence_path("durable-pending-health-tamper");
        let tamper_source = initialize_signed_policy(&tamper_path, &key);
        let tamper_envelope = read_envelope(&tamper_path);
        drop(tamper_source);
        let mut tampered_payload: serde_json::Value =
            serde_json::from_str(&tamper_envelope.statement.payload_json).unwrap();
        tampered_payload.as_object_mut().unwrap().insert(
            "pending_health_observation".to_string(),
            serde_json::json!({
                "governing_agent_id": governing_id,
                "entries": restrictive_entries,
                "observed_at_ms": base_ms + 1,
            }),
        );
        let mut forged = tamper_envelope;
        forged.statement.payload_json = serde_json::to_string(&tampered_payload).unwrap();
        write_envelope(&tamper_path, &forged);
        assert!(matches!(
            load_signed_policy(&tamper_path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::InvalidSignature { .. }
            )
        ));
        cleanup_persistence(&path);
        cleanup_persistence(&tamper_path);
    }

    #[test]
    fn same_sequence_pending_marker_never_diverges_after_partial_clear() {
        let path = persistence_path("pending-health-partial-clear-divergence");
        let key = SigningKey::from_bytes(&[188; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let checkpoint_blocker = block_atomic_write(&sequence_path);
        let restrictive_entries = [AgentHealthEntry {
            id: governing_id.to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }];
        policy.observe_health(&governing_id, &restrictive_entries, 1_835_000_000_001);
        fs::remove_dir(checkpoint_blocker).unwrap();

        let durable: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert_eq!(
            durable
                .pending_health_observation
                .as_ref()
                .map(|pending| pending.entries.clone()),
            Some(restrictive_entries.to_vec())
        );
        let state_sequence = read_envelope(&path).sequence();

        // Simulate a crash/failure after the checkpoint is cleared but before
        // the matching state envelope can clear its marker. The durable state
        // marker remains the only valid same-sequence predecessor.
        let state_blocker = block_atomic_write(&path);
        let clear_result = {
            let state = policy.state.lock().unwrap();
            let persistence = policy.persistence.as_ref().unwrap();
            let local = state.local_governor.as_ref().unwrap();
            let digest = state.persistence_digest.clone().unwrap();
            persistence.clear_pending_health_marker(&state, state_sequence, local, digest)
        };
        assert!(clear_result.is_err());
        fs::remove_dir(state_blocker).unwrap();
        let checkpoint: GovernanceSequenceCheckpoint =
            serde_json::from_str(&read_checkpoint(&path).statement.payload_json).unwrap();
        assert!(
            checkpoint.pending_health_observation.is_none(),
            "partial marker clear must leave the checkpoint without a replacement marker"
        );

        let alternate = PendingHealthObservation {
            governing_agent_id: governing_id.clone(),
            entries: vec![AgentHealthEntry {
                id: "alternate-health-observation".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Degraded,
            }],
            observed_at_ms: 1_835_000_000_002,
        };
        let divergent_result = {
            let state = policy.state.lock().unwrap();
            let persistence = policy.persistence.as_ref().unwrap();
            persistence.write_pending_health_intent(&state, &alternate)
        };
        assert!(
            divergent_result.is_err(),
            "a different same-sequence marker must fail closed instead of writing checkpoint-only state"
        );
        assert!(
            serde_json::from_str::<GovernanceSequenceCheckpoint>(
                &read_checkpoint(&path).statement.payload_json,
            )
            .unwrap()
            .pending_health_observation
            .is_none(),
            "failed divergent intent must not leave a checkpoint marker that conflicts with state"
        );

        drop(policy);
        let reopened = load_signed_policy(&path, &key).unwrap();
        assert!(
            reopened.is_partitioned(),
            "the original authenticated marker must remain a restart veto"
        );
        drop(reopened);
        cleanup_persistence(&path);
    }

    #[test]
    fn signed_same_sequence_divergent_pending_markers_refuse_restart() {
        let path = persistence_path("pending-health-signed-divergence");
        let key = SigningKey::from_bytes(&[189; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);

        let state_envelope = read_envelope(&path);
        let checkpoint_envelope = read_checkpoint(&path);
        let mut state_payload: PersistedGovernanceState =
            serde_json::from_str(&state_envelope.statement.payload_json).unwrap();
        let mut checkpoint_payload: GovernanceSequenceCheckpoint =
            serde_json::from_str(&checkpoint_envelope.statement.payload_json).unwrap();
        assert_eq!(state_envelope.sequence(), checkpoint_envelope.sequence());
        state_payload.pending_health_observation = Some(PendingHealthObservation {
            governing_agent_id: governing_id.clone(),
            entries: vec![AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            observed_at_ms: 1_850_000_000_001,
        });
        checkpoint_payload.pending_health_observation = Some(PendingHealthObservation {
            governing_agent_id: governing_id.clone(),
            entries: vec![AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Degraded,
            }],
            observed_at_ms: 1_850_000_000_002,
        });
        let signed_state = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            governing_id.clone(),
            state_envelope.sequence(),
            state_payload,
            &key,
        )
        .unwrap();
        let signed_checkpoint = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            governing_id,
            checkpoint_envelope.sequence(),
            checkpoint_payload,
            &key,
        )
        .unwrap();
        write_envelope(&path, &signed_state);
        write_checkpoint(&path, &signed_checkpoint);

        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::InvalidSequence { ref path, .. }
                if path == &sequence_path
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn authority_mint_refuses_pending_health_before_and_after_restart() {
        let path = persistence_path("authority-pending-health");
        let key = SigningKey::from_bytes(&[190; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = Arc::new(initialize_signed_policy(&path, &key));
        let blocker = block_atomic_write(&path);
        policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            1_851_000_000_001,
        );
        let error = policy
            .authority()
            .err()
            .expect("pending health must refuse authority minting");
        assert!(
            matches!(
                error,
                super::GovernanceAuthorityError::PendingHealthObservation { .. }
            ),
            "expected pending-health refusal, got {error}"
        );
        drop(policy);
        fs::remove_dir(blocker).unwrap();

        let reopened = Arc::new(load_signed_policy(&path, &key).unwrap());
        let error = reopened
            .authority()
            .err()
            .expect("restarted pending health must refuse authority minting");
        assert!(
            matches!(
                error,
                super::GovernanceAuthorityError::PendingHealthObservation { .. }
            ),
            "expected restarted pending-health refusal, got {error}"
        );
        reopened.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            1_851_000_001_001,
        );
        assert!(reopened.authority().is_ok());
        drop(reopened);
        cleanup_persistence(&path);
    }

    #[test]
    fn health_write_ahead_recovers_after_injected_parent_directory_sync_failure() {
        let path = persistence_path("health-write-ahead-parent-sync");
        let key = SigningKey::from_bytes(&[191; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        inject_atomic_parent_sync_failure(&sequence_path);
        let restrictive_entries = [AgentHealthEntry {
            id: governing_id.to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }];
        policy.observe_health(&governing_id, &restrictive_entries, 1_852_000_000_001);
        let state_payload: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert!(
            state_payload.pending_health_observation.is_some()
                || state_payload.partition_state != PartitionState::Healthy,
            "post-rename checkpoint sync failure must leave a signed restrictive recovery anchor"
        );
        drop(policy);

        let reopened = Arc::new(load_signed_policy(&path, &key).unwrap());
        assert!(reopened.is_partitioned());
        let decision = reopened.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.191".to_string(),
        }));
        assert!(matches!(decision, GovernanceDecision::Veto { .. }));
        reopened.observe_health(&governing_id, &restrictive_entries, 1_852_000_001_001);
        assert!(reopened.authority().is_ok());
        drop(reopened);
        cleanup_persistence(&path);
    }

    #[test]
    fn failed_restrictive_health_persistence_leaves_restart_veto_until_repair() {
        let path = persistence_path("failed-health-persistence-restart-veto");
        let key = SigningKey::from_bytes(&[187; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.187".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: healthy governance issues a receipt");
        };
        let blocker = block_atomic_write(&path);
        let restrictive_entries = [AgentHealthEntry {
            id: governing_id.to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }];
        policy.observe_health(&governing_id, &restrictive_entries, 1_840_000_000_001);
        assert!(
            policy
                .state
                .lock()
                .unwrap()
                .pending_health_observation
                .is_some(),
            "a failed restrictive health write must retain a fail-closed marker in memory"
        );
        drop(policy);
        fs::remove_dir(blocker).unwrap();

        let reopened = load_signed_policy(&path, &key).unwrap();
        assert!(reopened.is_partitioned());
        let decision = reopened.can_act(&governed_request);
        let GovernanceDecision::Veto {
            reason,
            receipt: next,
            ..
        } = decision
        else {
            panic!("a failed restrictive health write must veto after restart");
        };
        assert!(next.is_none());
        assert!(
            reason.contains("deferred health observation")
                || reason.contains("partition")
                || reason.contains("Partitioned"),
            "unexpected restart veto reason: {reason}"
        );

        reopened.observe_health(&governing_id, &restrictive_entries, 1_840_000_000_002);
        let state = reopened.state.lock().unwrap();
        assert!(state.pending_health_observation.is_none());
        assert_eq!(state.partition_state, PartitionState::Partitioned);
        drop(state);
        assert!(
            reopened
                .verify_and_consume_action_authorization(
                    &governed_request,
                    &serde_json::to_value(receipt).unwrap(),
                    1_840_000_000_003,
                )
                .is_err(),
            "repair must preserve the actual restrictive partition veto"
        );
        drop(reopened);
        cleanup_persistence(&path);
    }

    #[test]
    fn restrictive_health_write_ahead_intent_survives_each_injected_crash_step() {
        let crash_points = [
            (
                "health-intent-crash-after-intent",
                InjectedHealthCrashPoint::Intent,
            ),
            (
                "health-intent-crash-after-state",
                InjectedHealthCrashPoint::StateWrite,
            ),
            (
                "health-intent-crash-after-checkpoint",
                InjectedHealthCrashPoint::CheckpointWrite,
            ),
        ];
        for (offset, (suffix, crash_point)) in crash_points.into_iter().enumerate() {
            let path = persistence_path(suffix);
            let key = SigningKey::from_bytes(&[200 + offset as u8; 32]);
            let governing_id = AgentId::from_verifying_key(&key.verifying_key());
            let policy = initialize_signed_policy(&path, &key);
            let request = request(ResponseAction::BlockEgress {
                target: format!("203.0.113.20{}", offset),
            });
            policy.observe_health(&governing_id, &[], 1_860_000_000_000);
            let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&request) else {
                panic!("healthy precondition must issue a receipt");
            };
            let restrictive_entries = [AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }];
            inject_health_crash(&path, crash_point);
            let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                policy.observe_health(&governing_id, &restrictive_entries, 1_860_000_000_001);
            }));
            assert!(crashed.is_err(), "injected crash point must fire: {suffix}");
            drop(policy);

            let reopened = load_signed_policy(&path, &key).unwrap();
            assert!(
                reopened.is_partitioned(),
                "restart must retain the restrictive veto"
            );
            let decision = reopened.can_act(&request);
            let GovernanceDecision::Veto {
                receipt: next_receipt,
                ..
            } = decision
            else {
                panic!("restart after {suffix} must not authorize stale Healthy state");
            };
            assert!(next_receipt.is_none());
            assert!(
                reopened
                    .verify_and_consume_action_authorization(
                        &request,
                        &serde_json::to_value(receipt).unwrap(),
                        1_860_000_000_002,
                    )
                    .is_err(),
                "the pre-crash Healthy receipt must remain unusable after {suffix}"
            );
            drop(reopened);
            cleanup_persistence(&path);
        }
    }

    #[test]
    fn pending_health_rejects_partition_and_governor_mutations_after_repair() {
        let path = persistence_path("pending-health-mutation-gates");
        let key = SigningKey::from_bytes(&[188; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);
        let base_ms = 1_850_000_000_000;
        policy.observe_health(&governing_id, &[], base_ms);
        policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 1,
        );
        let before_failed_repair = health_memory_snapshot(&policy);
        let before_failed_state = fs::read(&path).unwrap();
        let before_failed_checkpoint = fs::read(&sequence_path).unwrap();
        let peer = SigningKey::from_bytes(&[189; 32]);
        assert!(
            policy
                .register_peer_governor(&peer.verifying_key())
                .is_err()
        );
        assert!(matches!(
            policy.register_governor(AgentId::new("tom", "alternate"), key.clone()),
            Err(GovernanceKeyError::Persistence { .. })
        ));
        policy.note_partition_veto(
            &request(ResponseAction::BlockEgress {
                target: "203.0.113.188".to_string(),
            }),
            "pending health",
            base_ms + 2,
        );
        assert_eq!(health_memory_snapshot(&policy), before_failed_repair);
        assert_eq!(fs::read(&path).unwrap(), before_failed_state);
        assert_eq!(fs::read(&sequence_path).unwrap(), before_failed_checkpoint);

        fs::remove_dir(blocker).unwrap();
        {
            let mut state = policy.state.lock().unwrap();
            policy
                .ensure_checkpoint_repaired_locked(&mut state)
                .unwrap();
        }
        let repaired_state = health_memory_snapshot(&policy);
        let repaired_state_bytes = fs::read(&path).unwrap();
        let repaired_checkpoint_bytes = fs::read(&sequence_path).unwrap();
        let repaired_sequence = read_envelope(&path).sequence();
        assert!(
            policy
                .register_peer_governor(&peer.verifying_key())
                .is_err()
        );
        assert!(matches!(
            policy.register_governor(AgentId::new("tom", "alternate"), key),
            Err(GovernanceKeyError::Persistence { .. })
        ));
        policy.note_partition_veto(
            &request(ResponseAction::BlockEgress {
                target: "203.0.113.188".to_string(),
            }),
            "pending health",
            base_ms + 3,
        );
        assert_eq!(health_memory_snapshot(&policy), repaired_state);
        assert_eq!(fs::read(&path).unwrap(), repaired_state_bytes);
        assert_eq!(fs::read(&sequence_path).unwrap(), repaired_checkpoint_bytes);
        assert_eq!(read_envelope(&path).sequence(), repaired_sequence);
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn legacy_signed_state_without_pending_health_defaults_to_no_pending_marker() {
        let path = persistence_path("legacy-pending-health-default");
        let key = SigningKey::from_bytes(&[184; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let original = read_envelope(&path);
        let mut payload: serde_json::Value =
            serde_json::from_str(&original.statement.payload_json).unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .remove("pending_health_observation");
        let legacy = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            original.sequence(),
            payload,
            &key,
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        let reopened = load_signed_policy(&path, &key).unwrap();
        let state = reopened.state.lock().unwrap();
        assert!(state.pending_health_observation.is_none());
        assert!(state.durable_pending_health_observation.is_none());
        drop(state);
        drop(reopened);
        cleanup_persistence(&path);
    }

    #[test]
    fn checkpoint_repair_backoff_deadline_is_overflow_safe() {
        let saturated = super::GovernanceCheckpointRepairBackoff::after(i64::MAX);
        assert!(saturated.saturated);
        assert!(!saturated.is_due(i64::MAX));

        let exact_max = super::GovernanceCheckpointRepairBackoff::after(
            i64::MAX - GOVERNANCE_CHECKPOINT_REPAIR_RETRY_INTERVAL_MS,
        );
        assert!(!exact_max.saturated);
        assert_eq!(exact_max.retry_at_ms, i64::MAX);
        assert!(exact_max.is_due(i64::MAX));
    }

    #[test]
    fn pre_partition_human_hold_is_refused_while_governance_is_degraded() {
        let path = persistence_path("pre-partition-human-hold-degraded");
        let key = SigningKey::from_bytes(&[179; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.179".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: healthy governance issues an approval");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let decision = swarm_policy::PolicyDecision::require_human_with_rule(
            "pre-partition-human-hold-degraded",
            "human review required",
        );
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &receipt_value,
                &decision,
                receipt.payload.issued_at_ms + 1,
            )
            .unwrap();
        policy
            .bind_human_approval_set(&hold.hold_id, "approval-set:179", "digest:179")
            .unwrap();

        policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: "whisker-degraded".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Degraded,
            }],
            receipt.payload.issued_at_ms + 2,
        );
        assert_eq!(
            policy.status_report().partition_state,
            PartitionState::Degraded
        );
        let sequence = read_envelope(&path).sequence();
        let state_bytes = fs::read(&path).unwrap();

        let error = policy
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:179",
                "digest:179",
                receipt.payload.issued_at_ms + 3,
            )
            .expect_err("a pre-degraded human hold must not bypass the health veto");
        assert!(
            error.contains("Degraded"),
            "unexpected refusal reason: {error}"
        );
        assert_eq!(read_envelope(&path).sequence(), sequence);
        assert_eq!(fs::read(&path).unwrap(), state_bytes);
        assert!(
            policy
                .pending_human_authorization("approval-set:179")
                .is_ok()
        );

        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn checkpoint_repair_does_not_let_a_stale_lease_snapshot_redeem_twice() {
        let path = persistence_path("stale-lease-checkpoint-cas");
        let key = SigningKey::from_bytes(&[130; 32]);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let first = initialize_signed_policy(&path, &key);
        let base_ms = super::now_ms();
        first.observe_health(&governing_id, &[], base_ms);
        first.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 1,
        );
        let stale_second = duplicate_locked_policy_snapshot(&first, &key);
        let mut governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.130".to_string(),
        });
        let GovernanceDecision::Authorize {
            contingency_lease: Some(lease),
            ..
        } = first.can_act(&governed_request)
        else {
            panic!("precondition: partition preview returns a current-committee lease");
        };
        governed_request.evidence = json!({"contingency_lease": lease});
        let committed_before = read_envelope(&path).sequence();
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);

        let error = first
            .authorize_partition_request(&governed_request, base_ms + 2)
            .expect_err("checkpoint lag withholds execution after committing redemption");
        assert!(error.contains("checkpoint persistence failed"), "{error}");
        let committed_redemption = read_envelope(&path).sequence();
        assert_eq!(committed_redemption, committed_before + 1);
        assert_eq!(
            checkpoint_sequence(&read_checkpoint(&path)),
            committed_before
        );
        fs::remove_dir(blocker).unwrap();

        let error = stale_second
            .authorize_partition_request(&governed_request, base_ms + 3)
            .expect_err("checkpoint repair must precede and preserve stale-snapshot CAS");
        assert!(error.contains("stale governance transaction"), "{error}");
        assert_eq!(read_envelope(&path).sequence(), committed_redemption);
        assert_eq!(
            checkpoint_sequence(&read_checkpoint(&path)),
            committed_before,
            "a stale caller must not write even a checkpoint repair before CAS"
        );

        drop(first);
        drop(stale_second);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert_eq!(
            checkpoint_sequence(&read_checkpoint(&path)),
            committed_redemption,
            "startup repairs the signed checkpoint from the newer committed state"
        );
        assert!(
            reloaded
                .authorize_partition_request(&governed_request, base_ms + 4)
                .is_err(),
            "restart preserves the single committed redemption"
        );
        drop(reloaded);
        cleanup_persistence(&path);
    }

    #[test]
    fn cas_rejects_a_different_trusted_statement_at_the_expected_sequence() {
        let path = persistence_path("same-sequence-digest-cas");
        let key = SigningKey::from_bytes(&[131; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let envelope = read_envelope(&path);
        let sequence = envelope.sequence();
        let mut replacement: PersistedGovernanceState =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        replacement.receipt_counter = replacement.receipt_counter.saturating_add(1);
        let replacement = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            sequence,
            replacement,
            &key,
        )
        .unwrap();
        write_envelope(&path, &replacement);

        let peer = SigningKey::from_bytes(&[132; 32]);
        let error = policy
            .register_peer_governor(&peer.verifying_key())
            .expect_err("sequence equality alone must not pass transaction CAS");
        assert!(error.contains("stale governance transaction"), "{error}");
        let durable = read_envelope(&path);
        assert_eq!(durable.statement, replacement.statement);
        assert_eq!(durable.signature, replacement.signature);
        assert!(
            !policy
                .state
                .lock()
                .unwrap()
                .peer_governors
                .contains(&AgentId::from_verifying_key(&peer.verifying_key()))
        );
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn failed_peer_consensus_identities_reduce_quorum_before_and_after_restart() {
        let path = persistence_path("peer-consensus-health-restart");
        let key = SigningKey::from_bytes(&[125; 32]);
        let governing_id = AgentId::new("tom", "primary");
        let policy = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id.clone(),
            key.clone(),
        )
        .unwrap();
        let base_ms = super::now_ms();
        policy.observe_health(&governing_id, &[], base_ms);
        let peer_keys = [
            SigningKey::from_bytes(&[126; 32]),
            SigningKey::from_bytes(&[127; 32]),
            SigningKey::from_bytes(&[128; 32]),
        ];
        for peer in &peer_keys {
            policy
                .register_peer_governor(&peer.verifying_key())
                .unwrap();
        }
        let failed_peers = peer_keys
            .iter()
            .map(|peer| AgentHealthEntry {
                id: AgentId::from_verifying_key(&peer.verifying_key()).to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            })
            .collect::<Vec<_>>();
        policy.observe_health(&governing_id, &failed_peers, base_ms + 1);

        let before = policy.status_report();
        assert_eq!(before.total_governors, 4);
        assert_eq!(before.healthy_governors, 1);
        assert_eq!(before.quorum_threshold, 3);
        assert_eq!(before.partition_state, PartitionState::Partitioned);
        assert_eq!(before.active_contingency_leases, 0);
        assert!(matches!(
            policy.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.125".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        drop(policy);

        let reloaded = GovernancePolicy::with_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id,
            key,
        )
        .unwrap();
        assert_eq!(reloaded.status_report(), before);
        assert!(matches!(
            reloaded.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.126".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn committed_peer_health_and_issue_state_is_retained_until_checkpoint_repair() {
        let peer_path = persistence_path("peer-checkpoint-lag");
        let peer_key = SigningKey::from_bytes(&[106; 32]);
        let peer_policy = initialize_signed_policy(&peer_path, &peer_key);
        let peer = SigningKey::from_bytes(&[107; 32]);
        let peer_id = AgentId::from_verifying_key(&peer.verifying_key());
        let peer_governing_id = AgentId::from_verifying_key(&peer_key.verifying_key());
        peer_policy.observe_health(&peer_governing_id, &[], super::now_ms());
        assert_eq!(peer_policy.status_report().active_contingency_leases, 12);
        let peer_checkpoint = GovernancePolicy::persistence_sequence_path(&peer_path);
        let blocker = block_atomic_write(&peer_checkpoint);
        peer_policy
            .register_peer_governor(&peer.verifying_key())
            .expect("peer admission is committed even when its checkpoint lags");
        {
            let state = peer_policy.state.lock().unwrap();
            assert!(state.peer_governors.contains(&peer_id));
            assert!(state.active_contingency_leases.is_empty());
            assert!(state.checkpoint_lagging.is_some());
        }
        let payload: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&peer_path).statement.payload_json).unwrap();
        assert!(payload.peer_governors.contains(&peer_id));
        assert!(payload.active_contingency_leases.is_empty());
        fs::remove_dir(blocker).unwrap();
        assert!(matches!(
            peer_policy.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.106".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        assert!(
            peer_policy
                .state
                .lock()
                .unwrap()
                .checkpoint_lagging
                .is_none()
        );
        drop(peer_policy);
        let peer_reloaded = load_signed_policy(&peer_path, &peer_key).unwrap();
        assert_eq!(peer_reloaded.status_report().total_governors, 2);
        assert_eq!(peer_reloaded.status_report().active_contingency_leases, 0);
        let sequence_before_idempotent_readmission = read_envelope(&peer_path).sequence();
        peer_reloaded
            .register_peer_governor(&peer.verifying_key())
            .expect("idempotent peer re-admission does not mutate governance state");
        assert_eq!(
            read_envelope(&peer_path).sequence(),
            sequence_before_idempotent_readmission
        );
        cleanup_persistence(&peer_path);

        let health_path = persistence_path("health-checkpoint-lag");
        let health_key = SigningKey::from_bytes(&[108; 32]);
        let governing_id = AgentId::from_verifying_key(&health_key.verifying_key());
        let health_policy = initialize_signed_policy(&health_path, &health_key);
        health_policy.observe_health(&governing_id, &[], super::now_ms());
        let health_checkpoint = GovernancePolicy::persistence_sequence_path(&health_path);
        let blocker = block_atomic_write(&health_checkpoint);
        health_policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Degraded,
            }],
            super::now_ms() + 1,
        );
        assert_eq!(
            health_policy.status_report().partition_state,
            PartitionState::Degraded
        );
        {
            let state = health_policy.state.lock().unwrap();
            assert_eq!(state.unhealthy_agents.len(), 1);
            assert!(state.checkpoint_lagging.is_some());
        }
        assert!(matches!(
            health_policy.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.108".to_string(),
            })),
            GovernanceDecision::Veto { receipt: None, .. }
        ));
        fs::remove_dir(blocker).unwrap();
        assert!(matches!(
            health_policy.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.109".to_string(),
            })),
            GovernanceDecision::Veto { .. }
        ));
        assert!(
            health_policy
                .state
                .lock()
                .unwrap()
                .checkpoint_lagging
                .is_none()
        );
        drop(health_policy);
        let health_reloaded = load_signed_policy(&health_path, &health_key).unwrap();
        assert_eq!(
            health_reloaded.status_report().partition_state,
            PartitionState::Degraded
        );
        cleanup_persistence(&health_path);

        let issue_path = persistence_path("issue-checkpoint-lag");
        let issue_key = SigningKey::from_bytes(&[109; 32]);
        let issue_policy = initialize_signed_policy(&issue_path, &issue_key);
        let issue_checkpoint = GovernancePolicy::persistence_sequence_path(&issue_path);
        let blocker = block_atomic_write(&issue_checkpoint);
        assert!(matches!(
            issue_policy.can_act(&request(ResponseAction::BlockEgress {
                target: "203.0.113.110".to_string(),
            })),
            GovernanceDecision::Veto { receipt: None, .. }
        ));
        {
            let state = issue_policy.state.lock().unwrap();
            assert_eq!(state.pending_authorizations.len(), 1);
            assert!(state.checkpoint_lagging.is_some());
        }
        fs::remove_dir(blocker).unwrap();
        {
            let mut state = issue_policy.state.lock().unwrap();
            issue_policy
                .ensure_checkpoint_repaired_locked(&mut state)
                .unwrap();
            assert_eq!(state.pending_authorizations.len(), 1);
            assert!(state.checkpoint_lagging.is_none());
        }
        assert_eq!(
            read_envelope(&issue_path).sequence(),
            checkpoint_sequence(&read_checkpoint(&issue_path))
        );
        drop(issue_policy);
        let issue_reloaded = load_signed_policy(&issue_path, &issue_key).unwrap();
        assert_eq!(
            issue_reloaded
                .state
                .lock()
                .unwrap()
                .pending_authorizations
                .len(),
            1
        );
        cleanup_persistence(&issue_path);
    }

    #[test]
    fn incomplete_initialization_removes_unanchored_state() {
        let path = persistence_path("incomplete-initialize");
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);
        let key = SigningKey::from_bytes(&[110; 32]);
        let error = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        )
        .expect_err("initialization without both signed anchors must fail");
        assert!(matches!(
            error,
            GovernancePersistenceError::IncompleteInitialization { .. }
        ));
        assert!(!path.exists());
        assert!(!sequence_path.exists());
        let lock_path = GovernancePolicy::persistence_lock_path(&path);
        let lock_record_before_retry = fs::read(&lock_path).unwrap();
        fs::remove_dir(blocker).unwrap();
        let retry = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        )
        .expect("retry reuses the valid durable lock record left by partial initialization");
        assert_eq!(fs::read(lock_path).unwrap(), lock_record_before_retry);
        drop(retry);
        cleanup_persistence(&path);
    }

    #[test]
    fn initialization_retry_resyncs_a_precreated_lock_record_before_signing_state() {
        let path = persistence_path("lock-parent-sync-retry");
        let key = SigningKey::from_bytes(&[145; 32]);
        super::fail_next_governance_lock_parent_sync();
        let error = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        )
        .expect_err("injected lock-parent durability failure must abort before signed state");
        assert!(matches!(
            error,
            GovernancePersistenceError::WriteLockRecord { .. }
        ));
        assert!(!path.exists());
        assert!(!GovernancePolicy::persistence_sequence_path(&path).exists());
        let lock_path = GovernancePolicy::persistence_lock_path(&path);
        let record_before_retry = fs::read(&lock_path).unwrap();
        let parsed: GovernanceLockRecord = serde_json::from_slice(&record_before_retry).unwrap();
        assert_eq!(
            hex::decode(parsed.generation_id).unwrap().len(),
            super::GOVERNANCE_LOCK_GENERATION_BYTES
        );

        let retry = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        )
        .expect("retry durably reuses the exact precreated lock generation");
        assert_eq!(fs::read(lock_path).unwrap(), record_before_retry);
        drop(retry);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn initialization_regenerates_a_partial_lock_only_for_an_empty_stream() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let key = SigningKey::from_bytes(&[146; 32]);
        for (label, partial_record) in [("empty", b"".as_slice()), ("partial", b"{".as_slice())] {
            let path = persistence_path(&format!("partial-empty-lock-{label}"));
            let lock_path = GovernancePolicy::persistence_lock_path(&path);
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(&lock_path)
                .unwrap()
                .write_all(partial_record)
                .unwrap();

            let policy = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
            )
            .expect("an incomplete empty-stream lock record must be regenerated durably");
            let record: GovernanceLockRecord =
                serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
            assert_eq!(
                hex::decode(record.generation_id).unwrap().len(),
                super::GOVERNANCE_LOCK_GENERATION_BYTES
            );
            assert!(path.exists());
            assert!(GovernancePolicy::persistence_sequence_path(&path).exists());
            drop(policy);
            cleanup_persistence(&path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn initialization_never_regenerates_a_corrupt_lock_for_an_existing_stream() {
        let key = SigningKey::from_bytes(&[147; 32]);
        for (label, keep_state, keep_checkpoint) in [
            ("both", true, true),
            ("state-only", true, false),
            ("checkpoint-only", false, true),
        ] {
            let path = persistence_path(&format!("corrupt-existing-lock-initialize-{label}"));
            let policy = initialize_signed_policy(&path, &key);
            drop(policy);
            let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
            if !keep_state {
                fs::remove_file(&path).unwrap();
            }
            if !keep_checkpoint {
                fs::remove_file(&sequence_path).unwrap();
            }
            let state_before = keep_state.then(|| fs::read(&path).unwrap());
            let sequence_before = keep_checkpoint.then(|| fs::read(&sequence_path).unwrap());
            let lock_path = GovernancePolicy::persistence_lock_path(&path);
            fs::write(&lock_path, b"{").unwrap();

            let error = GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
            )
            .expect_err("either signed anchor must forbid implicit lock regeneration");
            assert!(matches!(
                error,
                GovernancePersistenceError::InvalidLockRecord { .. }
            ));
            assert_eq!(fs::read(&lock_path).unwrap(), b"{");
            assert_eq!(state_before, keep_state.then(|| fs::read(&path).unwrap()));
            assert_eq!(
                sequence_before,
                keep_checkpoint.then(|| fs::read(&sequence_path).unwrap())
            );
            cleanup_persistence(&path);
        }
    }

    #[test]
    fn offline_reinitialization_handles_missing_checkpoint_and_rolls_back_partial_failure() {
        let missing_path = persistence_path("reinit-missing-checkpoint");
        let missing_key = SigningKey::from_bytes(&[119; 32]);
        let missing_policy = initialize_signed_policy(&missing_path, &missing_key);
        missing_policy.observe_health(
            &AgentId::from_verifying_key(&missing_key.verifying_key()),
            &[AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Failed,
            }],
            super::now_ms(),
        );
        drop(missing_policy);
        fs::remove_file(GovernancePolicy::persistence_sequence_path(&missing_path)).unwrap();
        let reset = GovernancePolicy::reinitialize_persistence(
            GovernancePolicyConfig::default(),
            &missing_path,
            AgentId::from_verifying_key(&missing_key.verifying_key()),
            missing_key,
        )
        .expect("explicit offline recovery may replace state whose checkpoint is missing");
        assert_eq!(
            reset.status_report().partition_state,
            PartitionState::Healthy
        );
        assert!(reset.state.lock().unwrap().unhealthy_agents.is_empty());
        drop(reset);
        cleanup_persistence(&missing_path);

        let partial_path = persistence_path("reinit-partial-archive");
        let partial_key = SigningKey::from_bytes(&[120; 32]);
        let partial_policy = initialize_signed_policy(&partial_path, &partial_key);
        drop(partial_policy);
        let original_state = fs::read(&partial_path).unwrap();
        let partial_sequence_path = GovernancePolicy::persistence_sequence_path(&partial_path);
        let original_checkpoint = fs::read(&partial_sequence_path).unwrap();
        let suffix = "discarded-partial-test";
        let checkpoint_archive = partial_sequence_path.with_extension(format!(
            "{}.{}",
            partial_sequence_path.extension().unwrap().to_str().unwrap(),
            suffix
        ));
        fs::create_dir(&checkpoint_archive).unwrap();
        let error = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            partial_path.clone(),
            AgentId::from_verifying_key(&partial_key.verifying_key()),
            partial_key,
            suffix,
            None,
        )
        .expect_err("a partial archive failure must restore the prior stream");
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(fs::read(&partial_path).unwrap(), original_state);
        assert_eq!(
            fs::read(&partial_sequence_path).unwrap(),
            original_checkpoint
        );
        let state_archive = partial_path.with_extension(format!(
            "{}.{}",
            partial_path.extension().unwrap().to_str().unwrap(),
            suffix
        ));
        assert!(!state_archive.exists());
        fs::remove_dir(checkpoint_archive).unwrap();
        cleanup_persistence(&partial_path);

        let init_fail_path = persistence_path("reinit-new-stream-failure");
        let init_fail_key = SigningKey::from_bytes(&[121; 32]);
        let init_fail_policy = initialize_signed_policy(&init_fail_path, &init_fail_key);
        drop(init_fail_policy);
        let original_state = fs::read(&init_fail_path).unwrap();
        let init_fail_sequence_path = GovernancePolicy::persistence_sequence_path(&init_fail_path);
        let original_checkpoint = fs::read(&init_fail_sequence_path).unwrap();
        let blocker = block_atomic_write(&init_fail_path);
        let error = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            init_fail_path.clone(),
            AgentId::from_verifying_key(&init_fail_key.verifying_key()),
            init_fail_key,
            "discarded-init-failure-test",
            None,
        )
        .expect_err("a replacement initialization failure must restore the prior stream");
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(fs::read(&init_fail_path).unwrap(), original_state);
        assert_eq!(
            fs::read(&init_fail_sequence_path).unwrap(),
            original_checkpoint
        );
        fs::remove_dir(blocker).unwrap();
        cleanup_persistence(&init_fail_path);
    }

    #[test]
    fn reinitialization_archive_collision_is_no_replace_and_preserves_foreign_state() {
        let path = persistence_path("reinit-archive-collision");
        let key = SigningKey::from_bytes(&[122; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let original_state = fs::read(&path).unwrap();
        let suffix = "discarded-foreign-collision";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let foreign = b"foreign archive candidate".to_vec();
        fs::write(&state_archive, &foreign).unwrap();
        let error = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            path.clone(),
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            suffix,
            None,
        )
        .expect_err("a foreign archive destination must refuse reinitialization");
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), original_state);
        assert_eq!(fs::read(&state_archive).unwrap(), foreign);
        cleanup_persistence(&path);
        let _ = fs::remove_file(state_archive);
    }

    #[test]
    fn reinitialization_archives_are_private_authenticated_snapshots() {
        let path = persistence_path("reinit-private-archive-snapshot");
        let key = SigningKey::from_bytes(&[205; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);

        let suffix = "discarded-private-snapshot";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let artifact = copied_reinitialization_artifact(&path, &state_archive);
        let archive_snapshot = super::read_governance_artifact_snapshot(&state_archive)
            .unwrap()
            .unwrap()
            .0;
        assert_ne!(
            archive_snapshot.identity, artifact.identity,
            "rollback archives must be copied snapshots, never hard-link aliases"
        );

        let original_archive_bytes = fs::read(&state_archive).unwrap();
        fs::write(&path, b"mutated source bytes after archive creation").unwrap();
        assert_eq!(fs::read(&state_archive).unwrap(), original_archive_bytes);

        // Replacing the archive with a hard-link alias is rejected by the
        // identity+digest binding before rollback can consume it.
        fs::remove_file(&state_archive).unwrap();
        fs::hard_link(&path, &state_archive).unwrap();
        fs::remove_file(&path).unwrap();
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let journal = ReinitializationRollbackJournal {
            schema_version: REINITIALIZATION_JOURNAL_SCHEMA_VERSION,
            transaction_id: "private-archive-alias-rejected".to_string(),
            archive_suffix: suffix.to_string(),
            state_path: path.clone(),
            sequence_path: sequence_path.clone(),
            artifacts: vec![artifact],
            new_stream_artifacts: Vec::new(),
            phase: ReinitializationJournalPhase::ArchivesCreated,
        };
        // The state archive is intentionally the alias above; recovery must
        // reject it before it can consume the replacement inode.
        super::write_reinitialization_journal(&path, &journal, &key).unwrap();
        let error = load_signed_policy(&path, &key)
            .expect_err("an archive alias replacing the private snapshot must fail closed");
        assert!(matches!(error, GovernancePersistenceError::Write { .. }));
        assert!(state_archive.exists());
        cleanup_persistence(&path);
        let _ = fs::remove_file(state_archive);
    }

    #[test]
    fn reinitialization_missing_archive_identity_refuses_recovery() {
        let path = persistence_path("reinit-missing-archive-identity");
        let key = SigningKey::from_bytes(&[213; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let suffix = "discarded-missing-archive-identity";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let mut artifact = copied_reinitialization_artifact(&path, &state_archive);
        artifact.archive_identity = None;
        let journal = ReinitializationRollbackJournal {
            schema_version: REINITIALIZATION_JOURNAL_SCHEMA_VERSION,
            transaction_id: "missing-archive-identity".to_string(),
            archive_suffix: suffix.to_string(),
            state_path: path.clone(),
            sequence_path,
            artifacts: vec![artifact],
            new_stream_artifacts: Vec::new(),
            phase: ReinitializationJournalPhase::Prepared,
        };
        super::write_reinitialization_journal(&path, &journal, &key).unwrap();
        let archive_bytes = fs::read(&state_archive).unwrap();
        assert!(load_signed_policy(&path, &key).is_err());
        assert_eq!(fs::read(&state_archive).unwrap(), archive_bytes);
        assert!(super::reinitialization_journal_path(&path).exists());
        cleanup_persistence(&path);
        let _ = fs::remove_file(state_archive);
    }

    #[test]
    fn reinitialization_journal_authentication_and_path_injection_refuse_restart() {
        let path = persistence_path("reinit-journal-authentication");
        let key = SigningKey::from_bytes(&[206; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let suffix = "discarded-journal-authentication";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let sequence_archive = sequence_path.with_extension(format!("json.{suffix}"));
        let state_artifact = copied_reinitialization_artifact(&path, &state_archive);
        let sequence_artifact = copied_reinitialization_artifact(&sequence_path, &sequence_archive);
        fs::remove_file(&path).unwrap();
        let journal = ReinitializationRollbackJournal {
            schema_version: REINITIALIZATION_JOURNAL_SCHEMA_VERSION,
            transaction_id: "journal-authentication".to_string(),
            archive_suffix: suffix.to_string(),
            state_path: path.clone(),
            sequence_path: sequence_path.clone(),
            artifacts: vec![state_artifact, sequence_artifact],
            new_stream_artifacts: Vec::new(),
            phase: ReinitializationJournalPhase::ArchivesCreated,
        };
        super::write_reinitialization_journal(&path, &journal, &key).unwrap();
        let journal_path = super::reinitialization_journal_path(&path);
        let mut tampered = fs::read(&journal_path).unwrap();
        let byte = tampered
            .iter_mut()
            .find(|byte| **byte == b'j')
            .expect("signed journal contains a mutable payload byte");
        *byte = b'k';
        fs::write(&journal_path, tampered).unwrap();
        assert!(load_signed_policy(&path, &key).is_err());
        assert!(journal_path.exists());

        // A validly signed but path-injected journal is also rejected by the
        // canonical same-parent stream validation.
        let mut forged = journal.clone();
        forged.sequence_path = path.with_file_name("foreign.sequence.json");
        let signer = AgentId::from_verifying_key(&key.verifying_key());
        let envelope = SignedStateEnvelope::sign(
            super::REINITIALIZATION_JOURNAL_KIND,
            super::REINITIALIZATION_JOURNAL_STREAM,
            signer,
            0,
            forged,
            &key,
        )
        .unwrap();
        fs::write(&journal_path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        assert!(load_signed_policy(&path, &key).is_err());
        assert!(state_archive.exists());
        assert!(sequence_archive.exists());
        cleanup_persistence(&path);
        let _ = fs::remove_file(state_archive);
        let _ = fs::remove_file(sequence_archive);
    }

    #[cfg(unix)]
    #[test]
    fn orphaned_cleanup_reservation_blocks_uncertain_authority_cleanup_until_recovered() {
        let path = persistence_path("authority-cleanup-orphan-reservation");
        let key = SigningKey::from_bytes(&[207; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sidecar = GovernancePolicy::persistence_authority_lock_path(&path);
        let state_lock = GovernancePolicy::persistence_lock_path(&path);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        fs::remove_file(&path).unwrap();
        fs::remove_file(&sequence_path).unwrap();
        fs::remove_file(&state_lock).unwrap();
        fs::remove_file(&sidecar).unwrap();
        let pool = sidecar
            .parent()
            .unwrap()
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
        let orphan_slot = pool.join(cleanup_pool_slot_name(0));
        fs::create_dir_all(&orphan_slot).unwrap();
        let orphan = orphan_slot.join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        let orphan_bytes = b"foreign orphan reservation";
        fs::write(&orphan, orphan_bytes).unwrap();

        inject_authority_lock_failure(&sidecar, InjectedAuthorityLockFailure::IdentityVerification);
        assert!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &path,
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
            )
            .is_err()
        );
        assert_eq!(fs::read(&orphan).unwrap(), orphan_bytes);
        assert!(
            !sidecar.exists(),
            "the canonical sidecar is semantically quarantined into a fixed slot"
        );

        fs::remove_dir_all(&pool).unwrap();
        let reopened = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        )
        .expect("removing the recovered orphan must permit a fresh stream");
        drop(reopened);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_is_fixed_cardinality_and_exhaustion_is_fail_closed() {
        let path = persistence_path("cleanup-pool-fixed-cardinality");
        for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
            fs::write(&path, format!("owned-entry-{index}")).unwrap();
            let outcome = quarantine_verified_entry(&path, || true, |_| true);
            assert_eq!(outcome, QuarantineOutcome::Retained, "slot {index}");
        }
        let pool = path
            .parent()
            .unwrap()
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
        let slots = fs::read_dir(&pool)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("slot-"))
            .count();
        assert_eq!(slots, GOVERNANCE_CLEANUP_POOL_SLOT_COUNT);

        fs::write(&path, b"the 65th entry must remain canonical").unwrap();
        assert_eq!(
            quarantine_verified_entry(&path, || true, |_| true),
            QuarantineOutcome::PoolExhausted
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"the 65th entry must remain canonical"
        );
        let journal = pool
            .join(cleanup_pool_slot_name(0))
            .join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        assert!(fs::metadata(journal).unwrap().len() > 0);
        cleanup_persistence(&path);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn non_drop_cleanup_failure_composition_preserves_structural_outcomes() {
        let path = PathBuf::from("/tmp/governance-cleanup-composition");
        let original = GovernancePersistenceError::StateLocked { path: path.clone() };
        let exhausted = super::compose_operation_cleanup_failure(
            &path,
            original,
            vec![GovernancePersistenceError::CleanupPoolExhausted { path: path.clone() }],
        );
        assert!(matches!(
            exhausted,
            GovernancePersistenceError::CleanupPoolExhausted { path: ref observed }
                if observed == &path
        ));

        let original = GovernancePersistenceError::StateLocked { path: path.clone() };
        let composed = super::compose_operation_cleanup_failure(
            &path,
            original,
            vec![GovernancePersistenceError::CleanupMaintenance {
                path: path.clone(),
                reason: "foreign replacement was preserved; cleanup is uncertain".to_string(),
            }],
        );
        match composed {
            GovernancePersistenceError::CleanupMaintenance { reason, .. } => {
                assert!(reason.contains("operation failed: governance state lock"));
                assert!(reason.contains("foreign replacement was preserved"));
            }
            other => panic!("cleanup uncertainty must be returned as maintenance: {other:?}"),
        }

        let original = GovernancePersistenceError::StateLocked { path };
        let unchanged = super::compose_operation_cleanup_failure(
            Path::new("/tmp/governance-cleanup-composition"),
            original,
            Vec::new(),
        );
        assert!(matches!(
            unchanged,
            GovernancePersistenceError::StateLocked { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_partial_or_tampered_slots_are_occupied_after_restart_scan() {
        let path = persistence_path("cleanup-pool-tampered-restart");
        let pool = path
            .parent()
            .unwrap()
            .join(GOVERNANCE_CLEANUP_POOL_DIR_NAME);
        fs::create_dir(&pool).unwrap();
        for index in 0..GOVERNANCE_CLEANUP_POOL_SLOT_COUNT {
            let slot = pool.join(cleanup_pool_slot_name(index));
            fs::create_dir(&slot).unwrap();
            // Deliberately malformed/partial records are still occupied. A
            // restart must not parse or reuse them as deletion authority.
            fs::write(slot.join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME), b"partial").unwrap();
        }
        let parent = bind_authority_cleanup_parent(&path).unwrap();
        let error = match acquire_cleanup_pool_slot(&path, &parent) {
            Ok(_) => panic!("all malformed slots remain occupied after restart"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            GovernancePersistenceError::CleanupPoolExhausted { .. }
        ));
        assert_eq!(
            fs::read(
                pool.join(cleanup_pool_slot_name(0))
                    .join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME)
            )
            .unwrap(),
            b"partial"
        );
        cleanup_persistence(&path);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_journal_same_inode_truncate_is_occupied() {
        let path = persistence_path("cleanup-journal-same-inode-truncate");
        fs::write(&path, b"owned cleanup source").unwrap();
        let parent = bind_authority_cleanup_parent(&path).unwrap();
        let mut slot = acquire_cleanup_pool_slot(&path, &parent).unwrap();
        let journal = slot.path.join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        let identity = fs::symlink_metadata(&journal).unwrap().ino();
        let file = fs::OpenOptions::new().write(true).open(&journal).unwrap();
        file.set_len(0).unwrap();
        file.sync_all().unwrap();
        assert_eq!(fs::symlink_metadata(&journal).unwrap().ino(), identity);
        assert!(
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::Retained, Vec::new()).is_err()
        );
        drop(slot);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_journal_same_inode_overwrite_is_occupied() {
        let path = persistence_path("cleanup-journal-same-inode-overwrite");
        fs::write(&path, b"owned cleanup source").unwrap();
        let parent = bind_authority_cleanup_parent(&path).unwrap();
        let mut slot = acquire_cleanup_pool_slot(&path, &parent).unwrap();
        let journal = slot.path.join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        let mut bytes = fs::read(&journal).unwrap();
        let identity = fs::symlink_metadata(&journal).unwrap().ino();
        bytes[0] = if bytes[0] == b'{' { b'[' } else { b'{' };
        rewrite_same_inode(&journal, &bytes);
        assert_eq!(fs::symlink_metadata(&journal).unwrap().ino(), identity);
        assert!(
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::Retained, Vec::new()).is_err()
        );
        drop(slot);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_journal_reordered_record_is_occupied() {
        let path = persistence_path("cleanup-journal-reordered-record");
        fs::write(&path, b"owned cleanup source").unwrap();
        let parent = bind_authority_cleanup_parent(&path).unwrap();
        let mut slot = acquire_cleanup_pool_slot(&path, &parent).unwrap();
        append_cleanup_pool_record(&mut slot, CleanupPoolPhase::QuarantineMoved, Vec::new())
            .unwrap();
        let journal = slot.path.join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        let mut records = fs::read(&journal)
            .unwrap()
            .split_inclusive(|byte| *byte == b'\n')
            .map(|line| line.to_vec())
            .collect::<Vec<_>>();
        records.reverse();
        let reordered = records.into_iter().flatten().collect::<Vec<_>>();
        rewrite_same_inode(&journal, &reordered);
        assert!(
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::Retained, Vec::new()).is_err()
        );
        drop(slot);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_pool_journal_forged_prior_digest_is_occupied() {
        let path = persistence_path("cleanup-journal-forged-prior-digest");
        fs::write(&path, b"owned cleanup source").unwrap();
        let parent = bind_authority_cleanup_parent(&path).unwrap();
        let mut slot = acquire_cleanup_pool_slot(&path, &parent).unwrap();
        append_cleanup_pool_record(&mut slot, CleanupPoolPhase::QuarantineMoved, Vec::new())
            .unwrap();
        let journal = slot.path.join(GOVERNANCE_CLEANUP_POOL_JOURNAL_NAME);
        let mut records = fs::read(&journal)
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<super::CleanupPoolRecord>(line).unwrap())
            .collect::<Vec<_>>();
        records[1].previous_digest = Some("00".repeat(32));
        records[1].record_digest = super::cleanup_pool_record_digest(&records[1]).unwrap();
        let mut forged = Vec::new();
        for record in records {
            forged.extend_from_slice(&serde_json::to_vec(&record).unwrap());
            forged.push(b'\n');
        }
        rewrite_same_inode(&journal, &forged);
        assert!(
            append_cleanup_pool_record(&mut slot, CleanupPoolPhase::Retained, Vec::new()).is_err()
        );
        drop(slot);
        cleanup_persistence(&path);
    }

    #[test]
    fn reinitialization_durable_journal_restores_both_peers_after_restart() {
        let path = persistence_path("reinit-durable-journal-restart");
        let key = SigningKey::from_bytes(&[203; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let original_state = fs::read(&path).unwrap();
        let original_sequence = fs::read(&sequence_path).unwrap();
        let suffix = "discarded-durable-journal-restart";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let sequence_archive = sequence_path.with_extension(format!("json.{suffix}"));
        let state_artifact = copied_reinitialization_artifact(&path, &state_archive);
        let sequence_artifact = copied_reinitialization_artifact(&sequence_path, &sequence_archive);
        fs::remove_file(&path).unwrap();
        let journal = ReinitializationRollbackJournal {
            schema_version: REINITIALIZATION_JOURNAL_SCHEMA_VERSION,
            transaction_id: "later-peer-failure-restart".to_string(),
            archive_suffix: suffix.to_string(),
            state_path: path.clone(),
            sequence_path: sequence_path.clone(),
            artifacts: vec![state_artifact, sequence_artifact],
            new_stream_artifacts: Vec::new(),
            phase: ReinitializationJournalPhase::ArchivesCreated,
        };
        super::write_reinitialization_journal(&path, &journal, &key).unwrap();

        let restarted = load_signed_policy(&path, &key)
            .expect("restart must recover the complete state+sequence transaction");
        drop(restarted);
        assert_eq!(fs::read(&path).unwrap(), original_state);
        assert_eq!(fs::read(&sequence_path).unwrap(), original_sequence);
        assert!(!state_archive.exists());
        assert!(!sequence_archive.exists());
        assert!(!super::reinitialization_journal_path(&path).exists());
        cleanup_persistence(&path);
    }

    #[test]
    fn reinitialization_journal_later_peer_foreign_identity_is_preserved_until_retry() {
        let path = persistence_path("reinit-journal-later-peer-foreign");
        let key = SigningKey::from_bytes(&[204; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let suffix = "discarded-later-peer-foreign";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let sequence_archive = sequence_path.with_extension(format!("json.{suffix}"));
        let state_artifact = copied_reinitialization_artifact(&path, &state_archive);
        let sequence_artifact = copied_reinitialization_artifact(&sequence_path, &sequence_archive);
        fs::remove_file(&path).unwrap();
        let foreign = b"foreign later peer survives rollback".to_vec();
        fs::remove_file(&sequence_path).unwrap();
        fs::write(&sequence_path, &foreign).unwrap();
        let journal = ReinitializationRollbackJournal {
            schema_version: REINITIALIZATION_JOURNAL_SCHEMA_VERSION,
            transaction_id: "later-peer-foreign-retry".to_string(),
            archive_suffix: suffix.to_string(),
            state_path: path.clone(),
            sequence_path: sequence_path.clone(),
            artifacts: vec![state_artifact, sequence_artifact],
            new_stream_artifacts: Vec::new(),
            phase: ReinitializationJournalPhase::ArchivesCreated,
        };
        super::write_reinitialization_journal(&path, &journal, &key).unwrap();

        let error = load_signed_policy(&path, &key)
            .expect_err("a foreign later peer must veto restart recovery");
        assert!(matches!(error, GovernancePersistenceError::Write { .. }));
        assert_eq!(fs::read(&sequence_path).unwrap(), foreign);
        let restored_state = super::read_governance_artifact_snapshot(&path)
            .unwrap()
            .unwrap()
            .0;
        let archived_state = super::read_governance_artifact_snapshot(&state_archive)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(restored_state.content_digest, archived_state.content_digest);
        assert_eq!(restored_state.byte_len, archived_state.byte_len);
        assert!(state_archive.exists());
        assert!(sequence_archive.exists());
        assert!(super::reinitialization_journal_path(&path).exists());

        fs::remove_file(&sequence_path).unwrap();
        let restarted = load_signed_policy(&path, &key)
            .expect("retry after the foreign later peer is removed must recover both peers");
        drop(restarted);
        assert!(!state_archive.exists());
        assert!(!sequence_archive.exists());
        assert!(!super::reinitialization_journal_path(&path).exists());
        cleanup_persistence(&path);
    }

    #[test]
    fn reinitialization_archive_final_gap_preserves_foreign_candidate() {
        let path = persistence_path("reinit-archive-final-gap");
        let key = SigningKey::from_bytes(&[123; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let suffix = "discarded-final-gap";
        let state_archive = path.with_extension(format!("json.{suffix}"));
        let foreign = b"foreign candidate won the final archive gap".to_vec();
        let expected_foreign = foreign.clone();
        let (reached, resume, destination) = install_reinitialization_archive_barrier(&path);
        let replacer = std::thread::spawn(move || {
            reached.wait();
            let archive = destination
                .lock()
                .unwrap()
                .clone()
                .expect("reinitialization published its no-replace destination");
            fs::write(&archive, &foreign).unwrap();
            resume.wait();
        });
        let error = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            path.clone(),
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            suffix,
            None,
        )
        .expect_err("a foreign final-gap candidate must make reinitialization fail closed");
        replacer.join().unwrap();
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(fs::read(&state_archive).unwrap(), expected_foreign);
        cleanup_persistence(&path);
        let _ = fs::remove_file(state_archive);
    }

    #[test]
    fn reinitialization_foreign_source_after_quarantine_cannot_be_overwritten() {
        let path = persistence_path("reinit-foreign-source-after-quarantine");
        let key = SigningKey::from_bytes(&[216; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let foreign = b"foreign source appeared after quarantine absence check".to_vec();
        let (reached, resume) = install_reinitialization_publication_barrier(&path);
        let replacement_path = path.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::write(&replacement_path, &foreign).unwrap();
            resume.wait();
        });
        let result = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            path.clone(),
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            "discarded-foreign-source-after-quarantine",
            None,
        );
        replacer.join().unwrap();
        let error = result.expect_err("foreign publication candidate must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(
            fs::read(&path).unwrap(),
            b"foreign source appeared after quarantine absence check"
        );

        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let journal = super::reinitialization_journal_path(&path);
        cleanup_persistence(&path);
        let _ = fs::remove_file(journal);
        for original in [&path, &sequence_path] {
            let Some(parent) = original.parent() else {
                continue;
            };
            let Some(prefix) = original.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Ok(entries) = fs::read_dir(parent) {
                for entry in entries.flatten() {
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&format!("{prefix}.tmp-"))
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn fresh_initialization_foreign_publication_candidate_is_not_overwritten() {
        let path = persistence_path("fresh-initialization-foreign-publication");
        let key = SigningKey::from_bytes(&[221; 32]);
        let foreign = b"foreign fresh initialization publication candidate".to_vec();
        let (reached, resume) = install_reinitialization_publication_barrier(&path);
        let replacement_path = path.clone();
        let foreign_for_replacer = foreign.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::write(&replacement_path, &foreign_for_replacer).unwrap();
            resume.wait();
        });
        let result = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
        );
        replacer.join().unwrap();
        assert!(
            result.is_err(),
            "fresh publication must fail on a foreign name"
        );
        assert_eq!(fs::read(&path).unwrap(), foreign);
        cleanup_persistence(&path);
    }

    #[cfg(unix)]
    #[test]
    fn governance_loader_held_fd_rejects_symlink_and_inode_swap() {
        let path = persistence_path("loader-held-fd-races");
        let key = SigningKey::from_bytes(&[222; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let original_state = fs::read(&path).unwrap();
        let persistence = policy.persistence.as_ref().unwrap();

        let (reached, resume) = persistence.install_loader_barrier(&path);
        let replacement_path = path.clone();
        let foreign = b"foreign state inode replacement".to_vec();
        let foreign_for_replacer = foreign.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::remove_file(&replacement_path).unwrap();
            fs::write(&replacement_path, &foreign_for_replacer).unwrap();
            resume.wait();
        });
        let error = persistence
            .load(&LocalGovernorKey::new(key.clone()))
            .expect_err("loader must reject a canonical inode swap after held-FD open");
        replacer.join().unwrap();
        assert!(matches!(
            error,
            GovernancePersistenceError::ReadState { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), foreign);

        fs::remove_file(&path).unwrap();
        fs::write(&path, &original_state).unwrap();
        let symlink_target = path.with_file_name("loader-held-fd-target.json");
        fs::write(&symlink_target, &original_state).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&symlink_target, &path).unwrap();
        let error = persistence
            .load(&LocalGovernorKey::new(key))
            .expect_err("loader must reject a symlinked canonical state anchor");
        assert!(matches!(
            error,
            GovernancePersistenceError::ReadState { .. }
        ));

        fs::remove_file(&path).unwrap();
        fs::write(&path, &original_state).unwrap();
        fs::remove_file(symlink_target).unwrap();
        drop(policy);
        cleanup_persistence(&path);
    }

    #[test]
    fn reinitialization_cleanup_identity_mismatch_preserves_foreign_state() {
        let path = persistence_path("reinit-cleanup-foreign-state");
        let key = SigningKey::from_bytes(&[124; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let blocker = block_atomic_write(&sequence_path);
        let foreign = b"foreign state appeared during partial rollback".to_vec();
        let expected_foreign = foreign.clone();
        let (reached, resume) = install_governance_stream_cleanup_barrier(&path);
        let replacement_path = path.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::remove_file(&replacement_path).unwrap();
            fs::write(&replacement_path, &foreign).unwrap();
            resume.wait();
        });
        let error = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            path.clone(),
            AgentId::from_verifying_key(&key.verifying_key()),
            key,
            "discarded-cleanup-foreign-state",
            None,
        )
        .expect_err("partial initialization must refuse foreign cleanup replacement");
        replacer.join().unwrap();
        fs::remove_dir(blocker).unwrap();
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), expected_foreign);
        cleanup_persistence(&path);
    }

    #[test]
    fn reinitialization_crash_matrix_recovers_each_transaction_boundary() {
        let crash_points = [
            (
                "archive-created",
                InjectedReinitializationCrashPoint::ArchiveCreated,
            ),
            (
                "originals-quarantined",
                InjectedReinitializationCrashPoint::OriginalsQuarantined,
            ),
            (
                "state-renamed",
                InjectedReinitializationCrashPoint::StateRenamed,
            ),
            (
                "checkpoint-renamed",
                InjectedReinitializationCrashPoint::CheckpointRenamed,
            ),
            (
                "before-commit-journal",
                InjectedReinitializationCrashPoint::BeforeCommitJournal,
            ),
        ];
        for (offset, (label, crash_point)) in crash_points.into_iter().enumerate() {
            let path = persistence_path(&format!("reinit-crash-matrix-{label}"));
            let key = SigningKey::from_bytes(&[220 + offset as u8; 32]);
            let policy = initialize_signed_policy(&path, &key);
            drop(policy);
            let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
            let original_state = fs::read(&path).unwrap();
            let original_sequence = fs::read(&sequence_path).unwrap();
            inject_reinitialization_crash(&path, crash_point);
            let suffix = format!("discarded-crash-matrix-{label}");
            let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = GovernancePolicy::reinitialize_persistence_with_suffix(
                    GovernancePolicyConfig::default(),
                    path.clone(),
                    AgentId::from_verifying_key(&key.verifying_key()),
                    key.clone(),
                    &suffix,
                    None,
                );
            }));
            assert!(crashed.is_err(), "injected crash point must fire: {label}");

            let reopened = load_signed_policy(&path, &key)
                .expect("restart must rollback the incomplete reinitialization");
            drop(reopened);
            assert_eq!(fs::read(&path).unwrap(), original_state);
            assert_eq!(fs::read(&sequence_path).unwrap(), original_sequence);
            assert!(
                !super::reinitialization_journal_path(&path).exists(),
                "recovery must retire the journal after {label}"
            );
            cleanup_persistence(&path);
        }
    }

    #[test]
    fn reinitialization_restore_rejects_same_content_foreign_inode_after_link() {
        let path = persistence_path("reinit-restore-foreign-inode");
        let key = SigningKey::from_bytes(&[226; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let original_snapshot = super::read_governance_artifact_snapshot(&path)
            .unwrap()
            .unwrap()
            .0;
        let original_bytes = fs::read(&path).unwrap();
        inject_reinitialization_crash(
            &path,
            InjectedReinitializationCrashPoint::OriginalsQuarantined,
        );
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = GovernancePolicy::reinitialize_persistence_with_suffix(
                GovernancePolicyConfig::default(),
                path.clone(),
                AgentId::from_verifying_key(&key.verifying_key()),
                key.clone(),
                "discarded-restore-foreign-inode",
                None,
            );
        }));
        assert!(crashed.is_err(), "injected quarantine crash must fire");

        let (reached, resume) = install_reinitialization_restore_link_barrier(&path);
        let replacement_path = path.clone();
        let replacement_bytes = original_bytes.clone();
        let replacer = std::thread::spawn(move || {
            reached.wait();
            fs::remove_file(&replacement_path).unwrap();
            fs::write(&replacement_path, replacement_bytes).unwrap();
            resume.wait();
        });
        let reopened = load_signed_policy(&path, &key);
        replacer.join().unwrap();
        let error = reopened.expect_err(
            "same-content replacement after restore hard-link must fail closed on inode mismatch",
        );
        assert!(matches!(error, GovernancePersistenceError::Write { .. }));
        let restored_snapshot = super::read_governance_artifact_snapshot(&path)
            .unwrap()
            .unwrap()
            .0;
        assert_eq!(
            restored_snapshot.content_digest,
            original_snapshot.content_digest
        );
        assert_eq!(restored_snapshot.byte_len, original_snapshot.byte_len);
        assert_ne!(restored_snapshot.identity, original_snapshot.identity);
        assert!(super::reinitialization_journal_path(&path).exists());
        cleanup_persistence(&path);
        let _ = fs::remove_file(super::reinitialization_journal_path(&path));
    }

    #[test]
    fn reinitialization_commit_journal_parent_sync_failure_rolls_back() {
        let path = persistence_path("reinit-commit-journal-parent-sync");
        let key = SigningKey::from_bytes(&[225; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);
        let original_state = fs::read(&path).unwrap();
        let original_sequence = fs::read(&sequence_path).unwrap();
        inject_reinitialization_commit_journal_failure(&path);
        let error = GovernancePolicy::reinitialize_persistence_with_suffix(
            GovernancePolicyConfig::default(),
            path.clone(),
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
            "discarded-commit-journal-parent-sync",
            None,
        )
        .expect_err("a post-rename commit journal sync failure must fail closed");
        assert!(matches!(
            error,
            GovernancePersistenceError::ReinitializationFailed { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), original_state);
        assert_eq!(fs::read(&sequence_path).unwrap(), original_sequence);
        assert!(
            !super::reinitialization_journal_path(&path).exists(),
            "rollback must retire the commit journal after its sync failure"
        );
        cleanup_persistence(&path);
    }

    #[test]
    fn committed_human_hold_binding_and_consume_do_not_roll_back_on_checkpoint_lag() {
        let path = persistence_path("human-checkpoint-lag");
        let key = SigningKey::from_bytes(&[111; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.111".to_string(),
        });
        let GovernanceDecision::Authorize { receipt, .. } = policy.can_act(&governed_request)
        else {
            panic!("precondition: healthy governance issues an approval");
        };
        let receipt_value = serde_json::to_value(&receipt).unwrap();
        let issued_at_ms = receipt.payload.issued_at_ms;
        let decision = swarm_policy::PolicyDecision::require_human_with_rule(
            "checkpoint-lag",
            "human review required",
        );
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);

        let blocker = block_atomic_write(&sequence_path);
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &receipt_value,
                &decision,
                issued_at_ms + 1,
            )
            .expect("the durable hold is reported as created");
        assert_eq!(
            policy
                .state
                .lock()
                .unwrap()
                .pending_human_authorizations
                .len(),
            1
        );
        fs::remove_dir(blocker).unwrap();
        {
            let mut state = policy.state.lock().unwrap();
            policy
                .ensure_checkpoint_repaired_locked(&mut state)
                .unwrap();
        }

        let blocker = block_atomic_write(&sequence_path);
        let bound = policy
            .bind_human_approval_set(&hold.hold_id, "approval-set:111", "digest:111")
            .expect("the durable binding is reported as bound");
        assert_eq!(bound.approval_set_id.as_deref(), Some("approval-set:111"));
        assert_eq!(
            policy.state.lock().unwrap().pending_human_authorizations[0]
                .approval_set_id
                .as_deref(),
            Some("approval-set:111")
        );
        fs::remove_dir(blocker).unwrap();
        {
            let mut state = policy.state.lock().unwrap();
            policy
                .ensure_checkpoint_repaired_locked(&mut state)
                .unwrap();
        }

        let blocker = block_atomic_write(&sequence_path);
        let error = policy
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:111",
                "digest:111",
                issued_at_ms + 2,
            )
            .expect_err("execution is refused while the committed consume checkpoint lags");
        assert!(error.contains("consumed in signed state sequence"));
        {
            let state = policy.state.lock().unwrap();
            assert!(state.pending_human_authorizations.is_empty());
            assert!(
                state
                    .consumed_authorizations
                    .iter()
                    .any(|entry| entry.receipt_id == receipt.payload.receipt_id)
            );
            assert!(state.checkpoint_lagging.is_some());
        }
        fs::remove_dir(blocker).unwrap();
        let error = policy
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:111",
                "digest:111",
                issued_at_ms + 3,
            )
            .expect_err("a committed consume cannot be retried into a second effect");
        assert!(error.contains("was not found"));
        assert!(policy.state.lock().unwrap().checkpoint_lagging.is_none());
        drop(policy);

        let reloaded = load_signed_policy(&path, &key).unwrap();
        let state = reloaded.state.lock().unwrap();
        assert!(state.pending_human_authorizations.is_empty());
        assert!(
            state
                .consumed_authorizations
                .iter()
                .any(|entry| entry.receipt_id == receipt.payload.receipt_id)
        );
        drop(state);
        cleanup_persistence(&path);
    }

    #[test]
    fn committed_lease_redemption_and_attestation_are_not_rolled_back_on_checkpoint_lag() {
        let lease_path = persistence_path("redeem-checkpoint-lag");
        let lease_key = SigningKey::from_bytes(&[112; 32]);
        let lease_policy = initialize_signed_policy(&lease_path, &lease_key);
        let governing_id = AgentId::from_verifying_key(&lease_key.verifying_key());
        let base_ms = super::now_ms();
        lease_policy.observe_health(&governing_id, &[], base_ms);
        lease_policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 1,
        );
        let mut governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.112".to_string(),
        });
        let GovernanceDecision::Authorize {
            contingency_lease: Some(lease),
            ..
        } = lease_policy.can_act(&governed_request)
        else {
            panic!("precondition: partition preview returns a contingency lease");
        };
        governed_request.evidence = json!({"contingency_lease": lease});
        let lease_sequence_path = GovernancePolicy::persistence_sequence_path(&lease_path);
        let blocker = block_atomic_write(&lease_sequence_path);
        let error = lease_policy
            .authorize_partition_request(&governed_request, base_ms + 2)
            .expect_err("execution is refused while the committed redemption checkpoint lags");
        assert!(error.contains("redeemed in signed state sequence"));
        {
            let state = lease_policy.state.lock().unwrap();
            assert!(
                state
                    .active_contingency_leases
                    .iter()
                    .any(|lease| lease.redeemed_scopes == ["203.0.113.112"])
            );
            assert!(
                state
                    .partition_activity
                    .iter()
                    .any(|record| record.authorized)
            );
            assert!(state.checkpoint_lagging.is_some());
        }
        fs::remove_dir(blocker).unwrap();
        assert!(
            lease_policy
                .authorize_partition_request(&governed_request, base_ms + 3)
                .is_err()
        );
        assert!(
            lease_policy
                .state
                .lock()
                .unwrap()
                .checkpoint_lagging
                .is_none()
        );
        drop(lease_policy);
        let lease_reloaded = load_signed_policy(&lease_path, &lease_key).unwrap();
        assert!(
            lease_reloaded
                .state
                .lock()
                .unwrap()
                .active_contingency_leases
                .iter()
                .any(|lease| lease.redeemed_scopes == ["203.0.113.112"])
        );
        cleanup_persistence(&lease_path);

        let attest_path = persistence_path("attest-checkpoint-lag");
        let attest_key = SigningKey::from_bytes(&[113; 32]);
        let attest_policy = initialize_signed_policy(&attest_path, &attest_key);
        let before_counter = attest_policy.state.lock().unwrap().receipt_counter;
        let attest_sequence_path = GovernancePolicy::persistence_sequence_path(&attest_path);
        let blocker = block_atomic_write(&attest_sequence_path);
        assert!(
            attest_policy
                .attest_release(&json!({"release": "subject-113"}), base_ms + 4)
                .is_none()
        );
        {
            let state = attest_policy.state.lock().unwrap();
            assert_eq!(state.receipt_counter, before_counter + 1);
            assert!(state.checkpoint_lagging.is_some());
        }
        let payload: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&attest_path).statement.payload_json).unwrap();
        assert_eq!(payload.receipt_counter, before_counter + 1);
        fs::remove_dir(blocker).unwrap();
        {
            let mut state = attest_policy.state.lock().unwrap();
            attest_policy
                .ensure_checkpoint_repaired_locked(&mut state)
                .unwrap();
        }
        drop(attest_policy);
        assert_eq!(
            load_signed_policy(&attest_path, &attest_key)
                .unwrap()
                .state
                .lock()
                .unwrap()
                .receipt_counter,
            before_counter + 1
        );
        cleanup_persistence(&attest_path);
    }

    #[test]
    fn pre_state_write_failures_commit_neither_memory_nor_disk() {
        let peer_path = persistence_path("peer-precommit-failure");
        let peer_key = SigningKey::from_bytes(&[114; 32]);
        let peer_policy = initialize_signed_policy(&peer_path, &peer_key);
        let peer_governing_id = AgentId::from_verifying_key(&peer_key.verifying_key());
        peer_policy.observe_health(&peer_governing_id, &[], super::now_ms());
        let leases_before_failed_admission = peer_policy
            .state
            .lock()
            .unwrap()
            .active_contingency_leases
            .clone();
        assert_eq!(leases_before_failed_admission.len(), 12);
        let peer_sequence = read_envelope(&peer_path).sequence();
        let peer = SigningKey::from_bytes(&[115; 32]);
        let peer_id = AgentId::from_verifying_key(&peer.verifying_key());
        let blocker = block_atomic_write(&peer_path);
        assert!(
            peer_policy
                .register_peer_governor(&peer.verifying_key())
                .is_err()
        );
        assert!(
            !peer_policy
                .state
                .lock()
                .unwrap()
                .peer_governors
                .contains(&peer_id)
        );
        assert_eq!(
            peer_policy.state.lock().unwrap().active_contingency_leases,
            leases_before_failed_admission
        );
        assert_eq!(read_envelope(&peer_path).sequence(), peer_sequence);
        let persisted_after_failed_admission: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&peer_path).statement.payload_json).unwrap();
        assert!(persisted_after_failed_admission.peer_governors.is_empty());
        assert_eq!(
            persisted_after_failed_admission.active_contingency_leases,
            leases_before_failed_admission
        );
        fs::remove_dir(blocker).unwrap();
        cleanup_persistence(&peer_path);

        let health_path = persistence_path("health-precommit-failure");
        let health_key = SigningKey::from_bytes(&[116; 32]);
        let governing_id = AgentId::from_verifying_key(&health_key.verifying_key());
        let health_policy = initialize_signed_policy(&health_path, &health_key);
        health_policy.observe_health(&governing_id, &[], super::now_ms());
        let before = health_policy.status_report();
        let health_sequence = read_envelope(&health_path).sequence();
        let blocker = block_atomic_write(&health_path);
        health_policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Failed,
            }],
            super::now_ms() + 1,
        );
        let after = health_policy.status_report();
        assert_eq!(after.total_governors, before.total_governors);
        assert_eq!(after.healthy_governors, before.healthy_governors);
        assert_eq!(after.quorum_threshold, before.quorum_threshold);
        assert_eq!(
            after.active_contingency_leases,
            before.active_contingency_leases
        );
        assert_eq!(after.partition_state, PartitionState::Degraded);
        let state = health_policy.state.lock().unwrap();
        assert!(state.unhealthy_agents.is_empty());
        assert!(
            state.durable_pending_health_observation.is_some(),
            "a restrictive observation rejected by the state write must remain durably anchored"
        );
        assert!(state.pending_health_observation.is_some());
        assert_eq!(state.partition_state, before.partition_state);
        drop(state);
        assert_eq!(read_envelope(&health_path).sequence(), health_sequence);
        let checkpoint: GovernanceSequenceCheckpoint =
            serde_json::from_str(&read_checkpoint(&health_path).statement.payload_json).unwrap();
        assert!(checkpoint.pending_health_observation.is_some());
        fs::remove_dir(blocker).unwrap();
        cleanup_persistence(&health_path);

        let attest_path = persistence_path("attest-precommit-failure");
        let attest_key = SigningKey::from_bytes(&[117; 32]);
        let attest_policy = initialize_signed_policy(&attest_path, &attest_key);
        let before_counter = attest_policy.state.lock().unwrap().receipt_counter;
        let attest_sequence = read_envelope(&attest_path).sequence();
        let blocker = block_atomic_write(&attest_path);
        assert!(
            attest_policy
                .attest_release(&json!({"release": "precommit"}), super::now_ms())
                .is_none()
        );
        assert_eq!(
            attest_policy.state.lock().unwrap().receipt_counter,
            before_counter
        );
        assert_eq!(read_envelope(&attest_path).sequence(), attest_sequence);
        fs::remove_dir(blocker).unwrap();
        cleanup_persistence(&attest_path);

        let init_path = persistence_path("initialize-precommit-failure");
        let init_key = SigningKey::from_bytes(&[118; 32]);
        let blocker = block_atomic_write(&init_path);
        assert!(matches!(
            GovernancePolicy::initialize_persistence(
                GovernancePolicyConfig::default(),
                &init_path,
                AgentId::from_verifying_key(&init_key.verifying_key()),
                init_key,
            )
            .unwrap_err(),
            GovernancePersistenceError::Write { .. }
        ));
        assert!(!init_path.exists());
        assert!(!GovernancePolicy::persistence_sequence_path(&init_path).exists());
        fs::remove_dir(blocker).unwrap();
        cleanup_persistence(&init_path);
    }

    #[test]
    fn attacker_signed_peer_and_forged_leases_cannot_become_trust_anchors() {
        let victim_path = persistence_path("forged-peer-victim");
        let attacker_path = persistence_path("forged-peer-attacker");
        let victim_key = SigningKey::from_bytes(&[82; 32]);
        let attacker_key = SigningKey::from_bytes(&[83; 32]);
        let victim = initialize_signed_policy(&victim_path, &victim_key);
        victim.observe_health(
            &AgentId::from_verifying_key(&victim_key.verifying_key()),
            &[],
            super::now_ms(),
        );
        let victim_sequence = read_envelope(&victim_path).sequence();

        let attacker = initialize_signed_policy(&attacker_path, &attacker_key);
        attacker.observe_health(
            &AgentId::from_verifying_key(&attacker_key.verifying_key()),
            &[],
            super::now_ms(),
        );
        let mut forged_payload: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&attacker_path).statement.payload_json).unwrap();
        forged_payload
            .peer_governors
            .insert(AgentId::from_verifying_key(&attacker_key.verifying_key()));
        assert!(!forged_payload.active_contingency_leases.is_empty());
        let forged = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&attacker_key.verifying_key()),
            victim_sequence,
            forged_payload,
            &attacker_key,
        )
        .unwrap();
        write_envelope(&victim_path, &forged);
        drop(victim);
        drop(attacker);

        let error = load_signed_policy(&victim_path, &victim_key)
            .expect_err("an attacker-signed membership and lease set must fail startup");
        assert!(matches!(
            error,
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::SignerMismatch { .. }
            )
        ));
        cleanup_persistence(&victim_path);
        cleanup_persistence(&attacker_path);
    }

    #[test]
    fn attacker_resigned_authorization_ledgers_are_rejected_by_external_signer_binding() {
        let path = persistence_path("forged-ledgers");
        let victim_key = SigningKey::from_bytes(&[84; 32]);
        let attacker_key = SigningKey::from_bytes(&[85; 32]);
        let policy = initialize_signed_policy(&path, &victim_key);
        drop(policy);
        let envelope = read_envelope(&path);
        let mut payload: PersistedGovernanceState =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        payload
            .pending_authorizations
            .push_back(PendingGovernanceAuthorization {
                receipt_id: "forged-pending".to_string(),
                subject_digest: "forged-subject".to_string(),
                decision: swarm_consensus::GovernanceReceiptDecision::Approve,
                issued_at_ms: super::now_ms(),
            });
        payload
            .consumed_authorizations
            .push_back(ConsumedGovernanceAuthorization {
                receipt_id: "forged-consumed".to_string(),
                subject_digest: "forged-subject".to_string(),
                decision: swarm_consensus::GovernanceReceiptDecision::Approve,
                consumed_at_ms: super::now_ms(),
            });
        payload.pending_human_authorizations.push_back(
            swarm_policy::governance::GovernedHumanAuthorizationHold {
                hold_id: "forged-hold".to_string(),
                request: request(ResponseAction::BlockEgress {
                    target: "203.0.113.240".to_string(),
                }),
                policy_decision: swarm_policy::PolicyDecision::require_human_with_rule(
                    "forged", "forged",
                ),
                governance_receipt: json!({"forged": true}),
                created_at_ms: super::now_ms(),
                approval_set_id: Some("forged-set".to_string()),
                approval_set_digest: Some("forged-digest".to_string()),
            },
        );
        let forged = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&attacker_key.verifying_key()),
            envelope.sequence(),
            payload,
            &attacker_key,
        )
        .unwrap();
        write_envelope(&path, &forged);

        assert!(matches!(
            load_signed_policy(&path, &victim_key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::SignerMismatch { .. }
            )
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn byte_tampering_of_signed_governance_state_is_rejected() {
        let path = persistence_path("byte-tamper");
        let key = SigningKey::from_bytes(&[86; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let mut envelope = read_envelope(&path);
        let mut payload: serde_json::Value =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        payload["peer_governors"] = json!(["swarm:ed25519:attacker"]);
        payload["display_governors"] = json!({"tom-primary": "swarm:ed25519:attacker"});
        payload["unhealthy_agents"] = json!([]);
        payload["last_healthy_governors"] = json!(999);
        payload["last_quorum_threshold"] = json!(0);
        payload["pending_authorizations"] = json!([{"receipt_id":"injected"}]);
        payload["consumed_authorizations"] = json!([{"receipt_id":"deleted"}]);
        payload["pending_human_authorizations"] = json!([{"hold_id":"injected"}]);
        envelope.statement.payload_json = serde_json::to_string(&payload).unwrap();
        write_envelope(&path, &envelope);

        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::InvalidSignature { .. }
            )
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn signed_display_identity_substitution_is_rejected_against_bootstrap_identity() {
        let path = persistence_path("display-identity-substitution");
        let key = SigningKey::from_bytes(&[122; 32]);
        let governing_id = AgentId::new("tom", "primary");
        let policy = GovernancePolicy::initialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            governing_id.clone(),
            key.clone(),
        )
        .unwrap();
        drop(policy);
        let envelope = read_envelope(&path);
        let mut payload: PersistedGovernanceState =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        payload.display_governors.insert(
            governing_id.clone(),
            AgentId::from_verifying_key(&SigningKey::from_bytes(&[123; 32]).verifying_key()),
        );
        let substituted = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            envelope.sequence(),
            payload,
            &key,
        )
        .unwrap();
        write_envelope(&path, &substituted);

        assert!(matches!(
            GovernancePolicy::with_persistence(
                GovernancePolicyConfig::default(),
                &path,
                governing_id,
                key,
            )
            .unwrap_err(),
            GovernancePersistenceError::InvalidIdentityBinding { .. }
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn earlier_signed_schema_without_health_inputs_fails_closed() {
        let path = persistence_path("missing-signed-health-inputs");
        let key = SigningKey::from_bytes(&[124; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let envelope = read_envelope(&path);
        let mut payload: serde_json::Value =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        for field in [
            "display_governors",
            "unhealthy_agents",
            "last_healthy_governors",
            "last_quorum_threshold",
        ] {
            payload.as_object_mut().unwrap().remove(field);
        }
        let earlier_schema = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            envelope.sequence(),
            payload,
            &key,
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec_pretty(&earlier_schema).unwrap()).unwrap();

        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::DecodePayload { .. }
            )
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn trusted_older_envelope_cannot_delete_peers_and_collapse_committee() {
        let path = persistence_path("peer-replay");
        let key = SigningKey::from_bytes(&[87; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let before_peer = read_envelope(&path);
        policy
            .register_peer_governor(&SigningKey::from_bytes(&[88; 32]).verifying_key())
            .unwrap();
        assert!(read_envelope(&path).sequence() > before_peer.sequence());
        write_envelope(&path, &before_peer);
        drop(policy);

        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::ReplayDetected { .. }
            )
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn governance_checkpoint_fail_closed_and_crash_recovery_cases_are_explicit() {
        let path = persistence_path("checkpoint-cases");
        let key = SigningKey::from_bytes(&[89; 32]);
        let policy = initialize_signed_policy(&path, &key);
        drop(policy);
        let original_checkpoint = read_checkpoint(&path);
        let original_state = fs::read(&path).unwrap();
        let sequence_path = GovernancePolicy::persistence_sequence_path(&path);

        fs::remove_file(&sequence_path).unwrap();
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::MissingSequence { .. }
        ));
        write_checkpoint(&path, &original_checkpoint);

        fs::remove_file(&path).unwrap();
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::MissingState { .. }
        ));
        fs::write(&path, &original_state).unwrap();

        let original_sequence = checkpoint_sequence(&original_checkpoint);
        let original_checkpoint_payload: GovernanceSequenceCheckpoint =
            serde_json::from_str(&original_checkpoint.statement.payload_json).unwrap();
        let higher_sequence = original_sequence + 1;
        let trusted_high = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            higher_sequence,
            GovernanceSequenceCheckpoint {
                accepted_sequence: higher_sequence,
                lock_binding: original_checkpoint_payload.lock_binding.clone(),
                cleanup_pool_binding: original_checkpoint_payload.cleanup_pool_binding.clone(),
                pending_health_observation: None,
            },
            &key,
        )
        .unwrap();
        write_checkpoint(&path, &trusted_high);
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::ReplayDetected { .. }
            )
        ));

        let mut forged_high = original_checkpoint.clone();
        forged_high.statement.sequence = higher_sequence;
        forged_high.statement.payload_json = serde_json::to_string(&GovernanceSequenceCheckpoint {
            accepted_sequence: higher_sequence,
            lock_binding: original_checkpoint_payload.lock_binding.clone(),
            cleanup_pool_binding: original_checkpoint_payload.cleanup_pool_binding.clone(),
            pending_health_observation: None,
        })
        .unwrap();
        write_checkpoint(&path, &forged_high);
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::InvalidSignature { .. }
            )
        ));

        let mut forged_metadata = original_checkpoint.clone();
        forged_metadata.statement.stream_id = "attacker-stream".to_string();
        write_checkpoint(&path, &forged_metadata);
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::StreamMismatch { .. }
            )
        ));

        let attacker_key = SigningKey::from_bytes(&[90; 32]);
        let attacker_checkpoint = SignedStateEnvelope::sign(
            GOVERNANCE_CHECKPOINT_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&attacker_key.verifying_key()),
            higher_sequence,
            GovernanceSequenceCheckpoint {
                accepted_sequence: higher_sequence,
                lock_binding: original_checkpoint_payload.lock_binding.clone(),
                cleanup_pool_binding: original_checkpoint_payload.cleanup_pool_binding.clone(),
                pending_health_observation: None,
            },
            &attacker_key,
        )
        .unwrap();
        write_checkpoint(&path, &attacker_checkpoint);
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::SignerMismatch { .. }
            )
        ));

        let payload: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        let newer = SignedStateEnvelope::sign(
            GOVERNANCE_STATE_KIND,
            GOVERNANCE_STATE_STREAM,
            AgentId::from_verifying_key(&key.verifying_key()),
            higher_sequence,
            payload,
            &key,
        )
        .unwrap();
        write_envelope(&path, &newer);
        write_checkpoint(&path, &original_checkpoint);
        load_signed_policy(&path, &key).expect("a valid newer state repairs a lagging checkpoint");
        let repaired = read_checkpoint(&path);
        assert_eq!(checkpoint_sequence(&repaired), higher_sequence);
        repaired
            .verify(SignedStateExpectation {
                state_kind: GOVERNANCE_CHECKPOINT_KIND,
                stream_id: GOVERNANCE_STATE_STREAM,
                expected_signer_agent_id: Some(&AgentId::from_verifying_key(&key.verifying_key())),
                accepted_sequence: Some(higher_sequence),
            })
            .expect("repaired checkpoint is signed by the externally expected Tom key");

        let mut forged_low = repaired;
        forged_low.statement.sequence = original_sequence;
        forged_low.statement.payload_json = serde_json::to_string(&GovernanceSequenceCheckpoint {
            accepted_sequence: original_sequence,
            lock_binding: original_checkpoint_payload.lock_binding,
            cleanup_pool_binding: original_checkpoint_payload.cleanup_pool_binding,
            pending_health_observation: None,
        })
        .unwrap();
        write_checkpoint(&path, &forged_low);
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::SignedState(
                swarm_core::SignedStateError::InvalidSignature { .. }
            )
        ));
        cleanup_persistence(&path);
    }

    #[test]
    fn unsigned_legacy_and_corrupt_state_require_explicit_reinitialization() {
        let path = persistence_path("legacy");
        let source_path = persistence_path("legacy-source");
        let key = SigningKey::from_bytes(&[91; 32]);
        let source = initialize_signed_policy(&source_path, &key);
        source.observe_health(
            &AgentId::from_verifying_key(&key.verifying_key()),
            &[],
            super::now_ms(),
        );
        drop(source);
        let mut legacy: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&source_path).statement.payload_json).unwrap();
        legacy.peer_governors.insert(AgentId::from_verifying_key(
            &SigningKey::from_bytes(&[92; 32]).verifying_key(),
        ));
        legacy
            .pending_authorizations
            .push_back(PendingGovernanceAuthorization {
                receipt_id: "legacy-pending".to_string(),
                subject_digest: "legacy-subject".to_string(),
                decision: swarm_consensus::GovernanceReceiptDecision::Approve,
                issued_at_ms: super::now_ms(),
            });
        legacy
            .consumed_authorizations
            .push_back(ConsumedGovernanceAuthorization {
                receipt_id: "legacy-consumed".to_string(),
                subject_digest: "legacy-subject".to_string(),
                decision: swarm_consensus::GovernanceReceiptDecision::Approve,
                consumed_at_ms: super::now_ms(),
            });
        legacy.pending_human_authorizations.push_back(
            swarm_policy::governance::GovernedHumanAuthorizationHold {
                hold_id: "legacy-hold".to_string(),
                request: request(ResponseAction::BlockEgress {
                    target: "203.0.113.241".to_string(),
                }),
                policy_decision: swarm_policy::PolicyDecision::require_human_with_rule(
                    "legacy", "legacy",
                ),
                governance_receipt: json!({"legacy": true}),
                created_at_ms: super::now_ms(),
                approval_set_id: Some("legacy-set".to_string()),
                approval_set_digest: Some("legacy-digest".to_string()),
            },
        );
        assert!(!legacy.active_contingency_leases.is_empty());
        assert!(!legacy.pending_human_authorizations.is_empty());
        fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        fs::copy(
            GovernancePolicy::persistence_lock_path(&source_path),
            GovernancePolicy::persistence_lock_path(&path),
        )
        .unwrap();
        fs::copy(
            GovernancePolicy::persistence_authority_lock_path(&source_path),
            GovernancePolicy::persistence_authority_lock_path(&path),
        )
        .unwrap();
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::LegacyUnsignedState { .. }
        ));

        let reinitialized = GovernancePolicy::reinitialize_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&key.verifying_key()),
            key.clone(),
        )
        .expect("explicit offline reinitialization discards unsigned contents");
        assert_eq!(reinitialized.status_report().total_governors, 1);
        assert_eq!(reinitialized.status_report().active_contingency_leases, 0);
        drop(reinitialized);
        let reset: PersistedGovernanceState =
            serde_json::from_str(&read_envelope(&path).statement.payload_json).unwrap();
        assert!(reset.peer_governors.is_empty());
        assert!(reset.active_contingency_leases.is_empty());
        assert!(reset.pending_authorizations.is_empty());
        assert!(reset.consumed_authorizations.is_empty());
        assert!(reset.pending_human_authorizations.is_empty());

        fs::write(&path, b"{corrupt").unwrap();
        assert!(matches!(
            load_signed_policy(&path, &key).unwrap_err(),
            GovernancePersistenceError::ParseState { .. }
        ));
        cleanup_persistence(&path);
        cleanup_persistence(&source_path);
    }

    #[test]
    fn peers_never_become_trusted_signers_without_a_local_key() {
        let policy = GovernancePolicy::default();
        assert!(
            policy
                .register_peer_governor(&SigningKey::from_bytes(&[92; 32]).verifying_key())
                .is_err()
        );
        assert!(policy.governor_public_keys().is_empty());
    }

    #[test]
    fn contingency_lease_redemption_rolls_back_when_signed_persistence_fails() {
        let path = persistence_path("lease-persistence-failure");
        let key = SigningKey::from_bytes(&[93; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let governing_id = AgentId::from_verifying_key(&key.verifying_key());
        let base_ms = super::now_ms();
        policy.observe_health(&governing_id, &[], base_ms);
        policy.observe_health(
            &governing_id,
            &[AgentHealthEntry {
                id: governing_id.to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 1,
        );
        let mut governed_request = request(ResponseAction::BlockEgress {
            target: "203.0.113.93".to_string(),
        });
        let GovernanceDecision::Authorize {
            contingency_lease: Some(lease),
            ..
        } = policy.can_act(&governed_request)
        else {
            panic!("precondition: partition has a signed local contingency lease");
        };
        governed_request.evidence = json!({"contingency_lease": lease});

        let blocker = block_atomic_write(&path);
        let error = policy
            .authorize_partition_request(&governed_request, base_ms + 2)
            .expect_err("an unpersisted lease redemption must not authorize execution");
        assert!(error.contains("persistence failed"));
        fs::remove_dir(blocker).unwrap();

        policy
            .authorize_partition_request(&governed_request, base_ms + 3)
            .expect("failed persistence rolls the in-memory redemption back");
        drop(policy);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert!(
            reloaded
                .authorize_partition_request(&governed_request, base_ms + 4)
                .is_err(),
            "successful redemption remains consumed after restart"
        );
        cleanup_persistence(&path);
    }

    #[test]
    fn contingency_lease_staging_is_discarded_when_signed_persistence_fails() {
        let path = persistence_path("lease-staging-failure");
        let key = SigningKey::from_bytes(&[94; 32]);
        let policy = initialize_signed_policy(&path, &key);
        let blocker = block_atomic_write(&path);
        policy.observe_health(
            &AgentId::from_verifying_key(&key.verifying_key()),
            &[],
            super::now_ms(),
        );
        fs::remove_dir(blocker).unwrap();
        assert_eq!(policy.status_report().active_contingency_leases, 0);
        drop(policy);

        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert_eq!(reloaded.status_report().active_contingency_leases, 0);
        cleanup_persistence(&path);
    }

    #[test]
    fn governance_policy_vetoes_destructive_actions_when_swarm_is_unhealthy() {
        let policy = GovernancePolicy::default();
        policy
            .register_governor(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[7; 32]),
            )
            .expect("the policy holds no other governor key");
        policy.observe_health(
            &AgentId::new("tom", "primary"),
            &[AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Degraded,
            }],
            1_700_000_000_000,
        );

        let decision = policy.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        }));
        match decision {
            GovernanceDecision::Veto {
                governing_agent_id,
                receipt: Some(receipt),
                ..
            } => {
                assert_eq!(governing_agent_id, AgentId::new("tom", "primary"));
                assert!(
                    receipt.verify().is_ok(),
                    "receipt should verify: {receipt:?}"
                );
                assert_eq!(
                    receipt.payload.decision,
                    swarm_consensus::GovernanceReceiptDecision::Veto
                );
            }
            other => panic!("expected governance veto with receipt, got {other:?}"),
        }

        let non_destructive = policy.can_act(&request(ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        }));
        assert!(matches!(non_destructive, GovernanceDecision::NotRequired));
    }

    #[test]
    fn governance_policy_approves_destructive_actions_with_signed_receipt_when_healthy() {
        let policy = GovernancePolicy::default();
        policy
            .register_governor(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[11; 32]),
            )
            .expect("the policy holds no other governor key");
        policy.observe_health(&AgentId::new("tom", "primary"), &[], 1_700_000_000_000);

        let decision = policy.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.77".to_string(),
        }));
        match decision {
            GovernanceDecision::Authorize {
                receipt,
                contingency_lease: None,
            } => {
                assert!(
                    receipt.verify().is_ok(),
                    "receipt should verify: {receipt:?}"
                );
                assert_eq!(
                    receipt.payload.decision,
                    swarm_consensus::GovernanceReceiptDecision::Approve
                );
            }
            other => panic!("expected governance approval with receipt, got {other:?}"),
        }
    }

    // The keyless configuration is not hypothetical. `swarm_detect` registers exactly
    // one governor (crates/swarm-runtime-http/src/bin/swarm_detect.rs:815) through
    // `register_persisted_runtime_agent`, which returns `Ok(None)` and lets boot
    // continue when the Tom identity is not admitted by the identity registry. The
    // pouncer is registered separately, so the runtime can serve with a pouncer and no
    // governor. `PounceAgent::new_with_signing_key` also installs a keyless
    // `GovernancePolicy::default()` unless `.with_governance_policy(..)` is called.
    #[test]
    fn governance_policy_vetoes_destructive_action_without_a_registered_governor() {
        let policy = GovernancePolicy::default();

        let decision = policy.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        }));
        match decision {
            GovernanceDecision::Veto {
                governing_agent_id,
                reason,
                receipt,
            } => {
                assert_eq!(governing_agent_id, AgentId::new("tom", "unconfigured"));
                assert!(
                    reason.contains("no governor signing key is registered"),
                    "veto reason should name the cause, got {reason}"
                );
                assert!(
                    receipt.is_none(),
                    "a keyless policy cannot issue a receipt, got {receipt:?}"
                );
            }
            other => panic!("expected keyless governance to refuse, got {other:?}"),
        }

        // The guard must not become a blanket refusal: non-destructive actions never
        // needed a governance receipt and still do not.
        assert!(matches!(
            policy.can_act(&request(ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            })),
            GovernanceDecision::NotRequired
        ));
    }

    #[test]
    fn admitted_identity_with_missing_state_refuses_implicit_reinitialization() {
        let base_ms = super::now_ms();
        let path = std::env::temp_dir().join(format!(
            "swarm-governance-missing-{}-{base_ms}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let error = GovernancePolicy::with_persistence(
            GovernancePolicyConfig::default(),
            &path,
            AgentId::from_verifying_key(&SigningKey::from_bytes(&[19; 32]).verifying_key()),
            SigningKey::from_bytes(&[19; 32]),
        )
        .expect_err("ordinary load must never replace deleted governance history");
        assert!(matches!(
            error,
            super::GovernancePersistenceError::MissingLock { .. }
        ));
        assert!(!GovernancePolicy::persistence_lock_path(&path).exists());
    }

    #[test]
    fn governance_policy_stages_and_redeems_contingency_leases_during_partition() {
        let base_ms = super::now_ms();
        let policy = GovernancePolicy::new(GovernancePolicyConfig {
            contingency_lease_ttl_ms: 60_000,
            contingency_blast_radius_cap: 1,
        });
        policy
            .register_governor(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[13; 32]),
            )
            .expect("the policy holds no other governor key");
        policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms);
        let healthy_status = policy.status_report();
        assert_eq!(healthy_status.partition_state, PartitionState::Healthy);
        assert_eq!(healthy_status.active_contingency_leases, 12);

        let decision = policy.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.9".to_string(),
        }));
        assert!(matches!(
            decision,
            GovernanceDecision::Authorize {
                contingency_lease: None,
                ..
            }
        ));

        policy.observe_health(
            &AgentId::new("tom", "primary"),
            &[AgentHealthEntry {
                id: "tom-primary".to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 10_000,
        );
        assert!(policy.is_partitioned());

        let decision = policy.can_act(&request(ResponseAction::BlockEgress {
            target: "203.0.113.9".to_string(),
        }));
        let lease = match decision {
            GovernanceDecision::Authorize {
                receipt,
                contingency_lease: Some(lease),
            } => {
                assert!(receipt.verify().is_ok());
                lease
            }
            other => panic!("expected contingency lease, got {other:?}"),
        };
        let current_committee = policy.state.lock().unwrap().committee().unwrap();
        assert_eq!(
            lease
                .governance_receipt
                .payload
                .committee_members
                .as_slice(),
            current_committee.members()
        );
        assert_eq!(
            lease.governance_receipt.payload.committee_id,
            current_committee.committee_id()
        );
        assert!(
            lease.verify(&policy.governor_public_keys()).is_ok(),
            "lease should verify: {lease:?}"
        );

        let request = swarm_policy::ActionRequest {
            hunt_id: swarm_core::types::HuntId("hunt-partition-1".to_string()),
            requested_by: AgentId::new("pounce", "primary"),
            action: ResponseAction::BlockEgress {
                target: "203.0.113.9".to_string(),
            },
            severity: swarm_core::types::Severity::Critical,
            evidence: json!({
                "contingency_lease": lease,
            }),
        };

        let redeemed = policy
            .authorize_partition_request(&request, base_ms + 10_500)
            .expect("partition request should be authorized")
            .expect("expected redeemed lease");
        assert_eq!(redeemed.redeemed_scopes, vec!["203.0.113.9".to_string()]);

        policy
            .authorize_partition_request(&request, base_ms + 10_501)
            .expect_err("the exact partition request must be one-time");
        let mut same_scope_different_request = request.clone();
        same_scope_different_request.hunt_id =
            swarm_core::types::HuntId("hunt-partition-same-scope".to_string());
        assert!(matches!(
            policy.can_act(&same_scope_different_request),
            GovernanceDecision::Veto { .. }
        ));
    }

    #[test]
    fn governance_policy_reconciles_partition_activity_when_quorum_returns() {
        let base_ms = super::now_ms();
        let policy = GovernancePolicy::new(GovernancePolicyConfig {
            contingency_lease_ttl_ms: 60_000,
            contingency_blast_radius_cap: 1,
        });
        policy
            .register_governor(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[17; 32]),
            )
            .expect("the policy holds no other governor key");
        policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms);
        policy.observe_health(
            &AgentId::new("tom", "primary"),
            &[AgentHealthEntry {
                id: "tom-primary".to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 10_000,
        );

        let decision = policy.can_act(&request(ResponseAction::IsolateHost {
            host_id: "host-7".to_string(),
        }));
        let contingency_lease = match decision {
            GovernanceDecision::Authorize {
                contingency_lease: Some(lease),
                ..
            } => lease,
            other => panic!("expected active contingency lease, got {other:?}"),
        };
        let request = swarm_policy::ActionRequest {
            hunt_id: swarm_core::types::HuntId("hunt-partition-2".to_string()),
            requested_by: AgentId::new("pounce", "primary"),
            action: ResponseAction::IsolateHost {
                host_id: "host-7".to_string(),
            },
            severity: swarm_core::types::Severity::Critical,
            evidence: json!({
                "contingency_lease": contingency_lease,
            }),
        };
        policy
            .authorize_partition_request(&request, base_ms + 10_200)
            .unwrap();
        policy.note_partition_veto(
            &request,
            "missing contingency lease during partition",
            base_ms + 10_300,
        );

        policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms + 20_000);
        let events = policy.drain_runtime_events();
        assert!(events.iter().any(|event| matches!(
            event,
            GovernanceRuntimeEvent::PartitionReconciliation { report, .. }
            if report.authorized_actions.len() == 2 || report.authorized_actions.len() == 1
        )));
        assert_eq!(
            policy.status_report().partition_state,
            PartitionState::Healing
        );

        policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms + 30_000);
        assert_eq!(
            policy.status_report().partition_state,
            PartitionState::Healthy
        );
    }

    #[tokio::test]
    async fn tom_agent_shifts_degraded_agents_to_tom_role() {
        let policy = Arc::new(GovernancePolicy::default());
        let mut agent = TomAgent::new(AgentId::new("tom", "primary"), 3, Arc::clone(&policy))
            .expect("a fresh policy has no governor key yet");

        let actions = agent
            .tick(&env(vec![AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Degraded,
            }]))
            .await
            .unwrap();

        assert!(matches!(
            actions.as_slice(),
            [SwarmAction::RoleShift {
                target_agent_id,
                new_role: AgentRole::Tom,
            }] if target_agent_id == &AgentId::new("whisker", "primary")
        ));
    }

    #[tokio::test]
    async fn tom_agent_marks_agents_failed_after_threshold() {
        let policy = Arc::new(GovernancePolicy::default());
        let mut agent = TomAgent::new(AgentId::new("tom", "primary"), 3, Arc::clone(&policy))
            .expect("a fresh policy has no governor key yet");

        let first_actions = agent
            .tick(&env(vec![AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Whisker,
                health: AgentHealth::Degraded,
            }]))
            .await
            .unwrap();
        assert_eq!(first_actions.len(), 1);

        let second_actions = agent
            .tick(&env(vec![AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Degraded,
            }]))
            .await
            .unwrap();
        assert!(second_actions.is_empty());

        let third_actions = agent
            .tick(&env(vec![AgentHealthEntry {
                id: "whisker-primary".to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Degraded,
            }]))
            .await
            .unwrap();
        assert!(matches!(
            third_actions.as_slice(),
            [SwarmAction::HealthReport {
                target_agent_id,
                status: AgentHealth::Failed,
            }] if target_agent_id == &AgentId::new("whisker", "primary")
        ));
    }
}
