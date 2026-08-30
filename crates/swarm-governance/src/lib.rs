#![forbid(unsafe_code)]

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
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
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
const GOVERNANCE_STATE_KIND: &str = "swarm.governance.policy-state.v1";
const GOVERNANCE_CHECKPOINT_KIND: &str = "swarm.governance.policy-checkpoint.v1";
const GOVERNANCE_STATE_STREAM: &str = "tom-primary";
const GOVERNANCE_LOCK_RECORD_SCHEMA_VERSION: u32 = 1;
const GOVERNANCE_LOCK_GENERATION_BYTES: usize = 32;
const MAX_GOVERNANCE_LOCK_RECORD_BYTES: u64 = 4_096;

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

#[derive(Debug)]
struct GovernancePersistence {
    path: PathBuf,
    sequence_path: PathBuf,
    lock_path: PathBuf,
    lock_binding: GovernanceLockBinding,
    expected_signer_agent_id: AgentId,
    /// Exclusive OS advisory lock held for the full policy lifetime. The lock
    /// file may remain after exit; ownership comes only from this live handle,
    /// never from file existence.
    lock_file: fs::File,
    #[cfg(test)]
    test_pre_write_barrier: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
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
    Synced,
    /// The rename (the state commit point) succeeded, but syncing its parent
    /// directory did not. Callers must treat the new file as committed in this
    /// process even though crash durability is not yet proven.
    RenamedDirectorySyncFailed(GovernancePersistenceError),
}

#[derive(Debug, Clone)]
struct GovernanceCheckpointLag {
    sequence: u64,
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedGovernanceState {
    lock_binding: GovernanceLockBinding,
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
}

impl Default for PersistedGovernanceState {
    fn default() -> Self {
        Self {
            lock_binding: GovernanceLockBinding::unbound(),
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
        }
    }
}

impl PersistedGovernanceState {
    fn from_runtime(state: &GovernanceState) -> Self {
        Self {
            lock_binding: GovernanceLockBinding::unbound(),
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
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernanceSequenceCheckpoint {
    accepted_sequence: u64,
    lock_binding: GovernanceLockBinding,
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

#[derive(Debug)]
struct VerifiedGovernanceMigrationAnchors {
    state_bytes: Vec<u8>,
    checkpoint_bytes: Vec<u8>,
    state_payload: serde_json::Value,
    state_binding: Option<GovernanceLockBinding>,
    state_sequence: u64,
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
) -> Result<Option<GovernanceLockBinding>, GovernancePersistenceError> {
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
            reason: "signed migration checkpoint must contain only an accepted_sequence matching its positive envelope sequence"
                .to_string(),
        });
    }
    Ok(binding)
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
    let checkpoint_binding = decode_migration_checkpoint_payload(
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
    Ok(VerifiedGovernanceMigrationAnchors {
        state_bytes,
        checkpoint_bytes,
        state_payload: state.payload,
        state_binding,
        state_sequence: state.sequence,
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

impl GovernancePersistence {
    fn new(
        path: PathBuf,
        expected_signer_agent_id: AgentId,
        open_mode: GovernanceLockOpenMode,
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
        let may_create_lock = initialize_empty_stream || explicit_migration;
        if may_create_lock && let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|source| GovernancePersistenceError::OpenLock {
                path: lock_path.clone(),
                source,
            })?;
        }
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
        Ok(Self {
            path,
            sequence_path,
            lock_path,
            lock_binding,
            expected_signer_agent_id,
            lock_file,
            #[cfg(test)]
            test_pre_write_barrier: Mutex::new(None),
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
                self.write_migration_checkpoint(under_lock.state_sequence, signing_key)
                    .map_err(
                        |error| GovernancePersistenceError::MigrationCheckpointLagging {
                            sequence: under_lock.state_sequence,
                            reason: error.to_string(),
                        },
                    )?;
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
            self.write_migration_checkpoint(under_lock.state_sequence, signing_key)
                .map_err(
                    |error| GovernancePersistenceError::MigrationCheckpointLagging {
                        sequence: under_lock.state_sequence,
                        reason: error.to_string(),
                    },
                )?;
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
        let mut migrated_payload = under_lock.state_payload;
        let Some(payload_object) = migrated_payload.as_object_mut() else {
            return Err(GovernancePersistenceError::InvalidMigrationInput {
                path: self.path.clone(),
                reason: "signed state payload is not a JSON object".to_string(),
            });
        };
        payload_object.insert(
            "lock_binding".to_string(),
            serde_json::to_value(&self.lock_binding).map_err(|error| {
                GovernancePersistenceError::InvalidMigrationInput {
                    path: self.path.clone(),
                    reason: format!("new lock binding could not be encoded: {error}"),
                }
            })?,
        );
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
        let state_directory_sync_error = match write_atomic_synced(&self.path, &bytes)? {
            AtomicWriteOutcome::Synced => None,
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error) => Some(error.to_string()),
        };
        if let Err(error) = self.verify_lock_path() {
            return Err(GovernancePersistenceError::MigrationCheckpointLagging {
                sequence: migrated_sequence,
                reason: error.to_string(),
            });
        }
        if let Err(error) = self.write_migration_checkpoint(migrated_sequence, signing_key) {
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
    ) -> Result<(), GovernancePersistenceError> {
        self.verify_lock_path()?;
        let checkpoint = GovernanceSequenceCheckpoint {
            accepted_sequence: sequence,
            lock_binding: self.lock_binding.clone(),
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
        let outcome = write_atomic_synced(&self.sequence_path, &bytes)?;
        self.verify_lock_path()?;
        match outcome {
            AtomicWriteOutcome::Synced => Ok(()),
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error) => Err(error),
        }
    }

    #[cfg(test)]
    fn duplicate_locked_handle_for_stale_snapshot(&self) -> std::io::Result<Self> {
        Ok(Self {
            path: self.path.clone(),
            sequence_path: self.sequence_path.clone(),
            lock_path: self.lock_path.clone(),
            lock_binding: self.lock_binding.clone(),
            expected_signer_agent_id: self.expected_signer_agent_id.clone(),
            lock_file: self.lock_file.try_clone()?,
            test_pre_write_barrier: Mutex::new(None),
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

    fn verify_lock_path(&self) -> Result<(), GovernancePersistenceError> {
        verify_governance_lock_path(&self.lock_path, &self.lock_file, &self.lock_binding)
    }

    fn load(
        &self,
        local: &LocalGovernorKey,
    ) -> Result<LoadedGovernanceState, GovernancePersistenceError> {
        self.load_internal(local, true)
    }

    fn load_for_cas(
        &self,
        local: &LocalGovernorKey,
    ) -> Result<LoadedGovernanceState, GovernancePersistenceError> {
        self.load_internal(local, false)
    }

    fn load_internal(
        &self,
        local: &LocalGovernorKey,
        repair_checkpoint: bool,
    ) -> Result<LoadedGovernanceState, GovernancePersistenceError> {
        self.verify_lock_path()?;
        if !self.path.exists() {
            return Err(GovernancePersistenceError::MissingState {
                path: self.path.clone(),
            });
        }
        let bytes =
            fs::read(&self.path).map_err(|source| GovernancePersistenceError::ReadState {
                path: self.path.clone(),
                source,
            })?;
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

        if !self.sequence_path.exists() {
            return Err(GovernancePersistenceError::MissingSequence {
                path: self.sequence_path.clone(),
            });
        }
        let checkpoint_bytes = fs::read(&self.sequence_path).map_err(|source| {
            GovernancePersistenceError::ReadSequence {
                path: self.sequence_path.clone(),
                source,
            }
        })?;
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
        if repair_checkpoint && checkpoint.payload.accepted_sequence < verified.sequence {
            // State is committed before its high-water checkpoint. A crash in
            // that narrow window leaves a fully signed newer envelope, which is
            // safe to accept and use to repair the lagging checkpoint.
            self.write_checkpoint(verified.sequence, local)?;
        }
        self.verify_lock_path()?;
        Ok(LoadedGovernanceState {
            payload: verified.payload,
            sequence: verified.sequence,
            digest,
            checkpoint_sequence: checkpoint.payload.accepted_sequence,
        })
    }

    fn initialize(
        &self,
        state: &GovernanceState,
    ) -> Result<GovernanceStateVersion, GovernancePersistenceError> {
        self.verify_lock_path()?;
        if self.path.exists() || self.sequence_path.exists() {
            return Err(GovernancePersistenceError::AlreadyInitialized {
                state_path: self.path.clone(),
                sequence_path: self.sequence_path.clone(),
            });
        }
        let (outcome, version) = self.write_state_and_checkpoint(state, 1)?;
        match outcome {
            GovernancePersistenceOutcome::Committed => Ok(version),
            GovernancePersistenceOutcome::StateCommittedCheckpointLagging { reason, .. } => {
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
            self.write_checkpoint(loaded.sequence, local)?;
        }
        let next_sequence = loaded.sequence.checked_add(1).ok_or_else(|| {
            GovernancePersistenceError::InvalidSequence {
                path: self.sequence_path.clone(),
                reason: "sequence overflow".to_string(),
            }
        })?;
        self.write_state_and_checkpoint(state, next_sequence)
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
        let mut persisted = PersistedGovernanceState::from_runtime(state);
        persisted.lock_binding = self.lock_binding.clone();
        let envelope = local.sign_persisted_state(sequence, persisted)?;
        let digest = signed_governance_envelope_digest(&envelope, &self.path)?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseState {
                path: self.path.clone(),
                source,
            }
        })?;
        self.verify_lock_path()?;
        #[cfg(test)]
        self.pause_after_pre_write_verification();
        let state_directory_sync_error = match write_atomic_synced(&self.path, &bytes)? {
            AtomicWriteOutcome::Synced => None,
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error) => Some(error.to_string()),
        };
        let lock_after_state = self.verify_lock_path();
        let outcome = match lock_after_state.and_then(|()| self.write_checkpoint(sequence, local)) {
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
        Ok((outcome, GovernanceStateVersion { sequence, digest }))
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
                let mut persisted = PersistedGovernanceState::from_runtime(state);
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
        self.write_checkpoint(lag.sequence, local)?;
        Ok(())
    }

    fn rollback_incomplete_initialization(&self) -> Result<(), GovernancePersistenceError> {
        remove_governance_stream_files(self, &self.path, &self.sequence_path)
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
    ) -> Result<(), GovernancePersistenceError> {
        self.verify_lock_path()?;
        let checkpoint = GovernanceSequenceCheckpoint {
            accepted_sequence: sequence,
            lock_binding: self.lock_binding.clone(),
        };
        let envelope = local.sign_checkpoint(sequence, checkpoint)?;
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| {
            GovernancePersistenceError::ParseSequence {
                path: self.sequence_path.clone(),
                source,
            }
        })?;
        let outcome = write_atomic_synced(&self.sequence_path, &bytes)?;
        self.verify_lock_path()?;
        match outcome {
            AtomicWriteOutcome::Synced => Ok(()),
            AtomicWriteOutcome::RenamedDirectorySyncFailed(error) => Err(error),
        }
    }
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

fn write_atomic_synced(
    path: &Path,
    bytes: &[u8],
) -> Result<AtomicWriteOutcome, GovernancePersistenceError> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| GovernancePersistenceError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    match fs::symlink_metadata(&tmp_path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            // A process crash may leave the exact per-process temp name behind.
            // Removing the directory entry (including a symlink itself, never its
            // target) lets a valid state-ahead/checkpoint-behind restart recover.
            fs::remove_file(&tmp_path).map_err(|source| GovernancePersistenceError::Write {
                path: tmp_path.clone(),
                source,
            })?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(GovernancePersistenceError::Write {
                path: tmp_path.clone(),
                source,
            });
        }
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .map_err(|source| GovernancePersistenceError::Write {
            path: tmp_path.clone(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| GovernancePersistenceError::Write {
            path: tmp_path.clone(),
            source,
        })?;
    fs::rename(&tmp_path, path).map_err(|source| GovernancePersistenceError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(test)]
    if take_injected_atomic_parent_sync_failure(path) {
        return Ok(AtomicWriteOutcome::RenamedDirectorySyncFailed(
            GovernancePersistenceError::Write {
                path: path.parent().unwrap_or(path).to_path_buf(),
                source: std::io::Error::other("injected post-rename parent sync failure"),
            },
        ));
    }
    if let Some(parent) = path.parent()
        && let Err(source) = fs::File::open(parent).and_then(|directory| directory.sync_all())
    {
        return Ok(AtomicWriteOutcome::RenamedDirectorySyncFailed(
            GovernancePersistenceError::Write {
                path: parent.to_path_buf(),
                source,
            },
        ));
    }
    Ok(AtomicWriteOutcome::Synced)
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
    state_path: &Path,
    sequence_path: &Path,
) -> Result<(), GovernancePersistenceError> {
    for path in [state_path, sequence_path] {
        persistence.verify_lock_path()?;
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(GovernancePersistenceError::Write {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        persistence.verify_lock_path()?;
    }
    if let Some(parent) = state_path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| GovernancePersistenceError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
    }
    Ok(())
}

fn restore_governance_archives(
    persistence: &GovernancePersistence,
    archived: &[(PathBuf, PathBuf)],
) -> Result<(), GovernancePersistenceError> {
    for (original, archive) in archived.iter().rev() {
        if !archive.exists() {
            continue;
        }
        persistence.verify_lock_path()?;
        fs::rename(archive, original).map_err(|source| GovernancePersistenceError::Write {
            path: original.clone(),
            source,
        })?;
        persistence.verify_lock_path()?;
    }
    if let Some((original, _)) = archived.first() {
        sync_parent_directory(original)?;
    }
    Ok(())
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
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    fn with_locked_persistence(
        config: GovernancePolicyConfig,
        persistence: GovernancePersistence,
        governing_agent_id: AgentId,
        local_governor: LocalGovernorKey,
    ) -> Result<Self, GovernancePersistenceError> {
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
        let before_lock = verify_governance_migration_anchors(
            &path,
            &governing_agent_id,
            &expected_signer_agent_id,
        )?;
        let persistence = GovernancePersistence::new(
            path,
            expected_signer_agent_id,
            GovernanceLockOpenMode::Migrate,
        )?;
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
        )
    }

    fn reinitialize_persistence_with_suffix(
        config: GovernancePolicyConfig,
        path: PathBuf,
        governing_agent_id: AgentId,
        signing_key: SigningKey,
        suffix: &str,
    ) -> Result<Self, GovernancePersistenceError> {
        let local_governor = LocalGovernorKey::new(signing_key);
        let persistence = GovernancePersistence::new(
            path.clone(),
            local_governor.consensus_agent_id().clone(),
            GovernanceLockOpenMode::Reinitialize,
        )?;
        let sequence_path = path.with_extension("sequence.json");
        let mut archived: Vec<(PathBuf, PathBuf)> = Vec::new();
        for existing in [&path, &sequence_path] {
            if existing.exists() {
                let archive = existing.with_extension(format!(
                    "{}.{}",
                    existing
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .unwrap_or("state"),
                    suffix
                ));
                persistence.verify_lock_path()?;
                if let Err(source) = fs::rename(existing, &archive) {
                    let rollback = restore_governance_archives(&persistence, &archived);
                    return Err(GovernancePersistenceError::ReinitializationFailed {
                        reason: match rollback {
                            Ok(()) => format!(
                                "could not archive `{}` as `{}`: {source}",
                                existing.display(),
                                archive.display()
                            ),
                            Err(rollback_error) => format!(
                                "could not archive `{}` as `{}`: {source}; archive rollback also failed: {rollback_error}",
                                existing.display(),
                                archive.display()
                            ),
                        },
                    });
                }
                archived.push((existing.to_path_buf(), archive));
                persistence.verify_lock_path()?;
            }
        }
        if !archived.is_empty() {
            persistence.verify_lock_path()?;
            if let Err(sync_error) = sync_parent_directory(&path) {
                let rollback_error = restore_governance_archives(&persistence, &archived).err();
                return Err(GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "archived prior files but could not sync the archive directory: {sync_error}{}",
                        rollback_error
                            .map(|rollback_error| format!(
                                "; prior-state restore also failed: {rollback_error}"
                            ))
                            .unwrap_or_default()
                    ),
                });
            }
            persistence.verify_lock_path()?;
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
        match persistence.initialize(&state) {
            Ok(version) => {
                state.persistence_sequence = Some(version.sequence);
                state.persistence_digest = Some(version.digest);
                Ok(Self {
                    state: Mutex::new(state),
                    config,
                    persistence: Some(persistence),
                    transport: Arc::new(SoloGovernorTransport::new()),
                })
            }
            Err(error) => {
                let cleanup_error =
                    remove_governance_stream_files(&persistence, &path, &sequence_path).err();
                let rollback_error = restore_governance_archives(&persistence, &archived).err();
                Err(GovernancePersistenceError::ReinitializationFailed {
                    reason: format!(
                        "new signed stream initialization failed: {error}{}{}",
                        cleanup_error
                            .map(|cleanup_error| format!(
                                "; partial new-stream cleanup failed: {cleanup_error}"
                            ))
                            .unwrap_or_default(),
                        rollback_error
                            .map(|rollback_error| format!(
                                "; prior-state restore failed: {rollback_error}"
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
        let previous_persisted = PersistedGovernanceState::from_runtime(&state);
        let previous_unhealthy_agents = state.unhealthy_agents.clone();
        let previous_last_healthy_governors = state.last_healthy_governors;
        let previous_last_quorum_threshold = state.last_quorum_threshold;
        let previous_pending_events = state.pending_events.clone();
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
        prune_expired_contingency_leases(&mut state, observed_at_ms);
        if state.partition_state == PartitionState::Healthy {
            self.ensure_contingency_leases_locked(&mut state, observed_at_ms);
        }
        // Health is sampled on every dispatcher tick. Avoid turning an
        // unchanged projection into two fsyncs and an artificial sequence
        // advance. Expired leases and replenished leases are part of the
        // persisted projection, so real durable changes still commit.
        if PersistedGovernanceState::from_runtime(&state) == previous_persisted {
            return;
        }
        match self.persist_locked(&mut state) {
            Err(error) => {
                previous_persisted.restore_into(&mut state);
                state.unhealthy_agents = previous_unhealthy_agents;
                state.last_healthy_governors = previous_last_healthy_governors;
                state.last_quorum_threshold = previous_last_quorum_threshold;
                state.pending_events = previous_pending_events;
                let path = self
                    .persistence
                    .as_ref()
                    .map(|persistence| persistence.path.display().to_string())
                    .unwrap_or_else(|| "<memory>".to_string());
                tracing::warn!(
                    reason = %error,
                    path = %path,
                    module = module_path!(),
                    "discarded an unpersisted governance health transition and contingency leases"
                );
            }
            Ok(GovernancePersistenceOutcome::StateCommittedCheckpointLagging {
                sequence,
                reason,
            }) => tracing::warn!(
                sequence,
                reason = %reason,
                module = module_path!(),
                "governance health transition committed while its checkpoint remains lagging"
            ),
            Ok(GovernancePersistenceOutcome::Committed) => {}
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
        if state.partition_state != PartitionState::Healthy {
            return Err(format!(
                "human authorization requires healthy governance; current partition state is {:?}",
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
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .partition_state
            == PartitionState::Partitioned
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
        if state.partition_state != PartitionState::Partitioned {
            return Ok(None);
        }
        self.ensure_checkpoint_repaired_locked(&mut state)?;

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
        if state.partition_state != PartitionState::Partitioned {
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
        GovernanceStatusReport {
            partition_state: state.partition_state,
            total_governors: state.display_governors.len().max(state.governor_count()),
            healthy_governors: state.last_healthy_governors,
            quorum_threshold: state.last_quorum_threshold,
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
            last_transition_at_ms: state.last_transition_at_ms,
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
        Ok(outcome)
    }

    fn ensure_checkpoint_repaired_locked(&self, state: &mut GovernanceState) -> Result<(), String> {
        let Some(lag) = state.checkpoint_lagging.clone() else {
            return Ok(());
        };
        let Some(persistence) = &self.persistence else {
            state.checkpoint_lagging = None;
            return Ok(());
        };
        persistence.repair_checkpoint(state, &lag).map_err(|error| {
            format!(
                "signed governance state sequence {} is committed but its checkpoint remains lagging (initial failure: {}; repair failure: {error})",
                lag.sequence, lag.reason
            )
        })?;
        state.checkpoint_lagging = None;
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
        ConsumedGovernanceAuthorization, GOVERNANCE_CHECKPOINT_KIND, GOVERNANCE_STATE_KIND,
        GOVERNANCE_STATE_STREAM, GovernanceDecision, GovernanceLockRecord,
        GovernancePersistenceError, GovernancePolicy, GovernancePolicyConfig,
        GovernanceRuntimeEvent, GovernanceSequenceCheckpoint, LocalGovernorKey, PartitionState,
        PendingGovernanceAuthorization, PersistedGovernanceState, TomAgent,
        inject_atomic_parent_sync_failure,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
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
        std::env::temp_dir().join(format!(
            "swarm-governance-auth-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
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
        let hold = policy
            .begin_human_authorization_hold(
                &governed_request,
                &serde_json::to_value(&receipt).unwrap(),
                &swarm_policy::PolicyDecision::require_human_with_rule(
                    "pre-partition-human-hold",
                    "human review required",
                ),
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
        let sequence = read_envelope(&path).sequence();
        let state_bytes = fs::read(&path).unwrap();
        let checkpoint_path = GovernancePolicy::persistence_sequence_path(&path);
        let checkpoint_bytes = fs::read(&checkpoint_path).unwrap();

        let error = policy
            .verify_and_consume_human_authorization(
                &hold.hold_id,
                "approval-set:177",
                "digest:177",
                receipt.payload.issued_at_ms + 3,
            )
            .expect_err("a pre-partition human hold must not route during partition");
        assert!(error.contains("healthy governance"), "{error}");
        assert_eq!(read_envelope(&path).sequence(), sequence);
        assert_eq!(fs::read(&path).unwrap(), state_bytes);
        assert_eq!(fs::read(&checkpoint_path).unwrap(), checkpoint_bytes);
        assert!(
            policy
                .pending_human_authorization("approval-set:177")
                .is_ok(),
            "a refused hold must remain pending"
        );

        drop(policy);
        let reloaded = load_signed_policy(&path, &key).unwrap();
        assert!(
            reloaded
                .verify_and_consume_human_authorization(
                    &hold.hold_id,
                    "approval-set:177",
                    "digest:177",
                    receipt.payload.issued_at_ms + 4,
                )
                .is_err()
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
        let sequence = read_envelope(&path).sequence();
        let state_bytes = fs::read(&path).unwrap();
        let checkpoint_path = GovernancePolicy::persistence_sequence_path(&path);
        let checkpoint_bytes = fs::read(&checkpoint_path).unwrap();

        for observed_at_ms in 1_780_000_000_001..=1_780_000_000_010 {
            policy.observe_health(&governing_id, &[], observed_at_ms);
            assert_eq!(read_envelope(&path).sequence(), sequence);
            assert_eq!(fs::read(&path).unwrap(), state_bytes);
            assert_eq!(fs::read(&checkpoint_path).unwrap(), checkpoint_bytes);
        }

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
        assert_eq!(health_policy.status_report(), before);
        assert!(
            health_policy
                .state
                .lock()
                .unwrap()
                .unhealthy_agents
                .is_empty()
        );
        assert_eq!(read_envelope(&health_path).sequence(), health_sequence);
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
