use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_consensus::{
    ConsensusCommittee, ConsensusConfig, ConsensusError, ConsensusGovernanceReceipt, ConsensusNode,
    ConsensusProposal, ConsensusTransport, GovernanceReceiptDecision, SoloGovernorTransport,
    drive_round, recommended_max_faulty,
};
use swarm_core::agent::{
    AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError,
};
use swarm_core::types::{AgentId, ResponseAction, SwarmAction};
use swarm_crypto::{canonical_json_bytes, sha256_hex};
use swarm_policy::ActionRequest;
use swarm_policy::governance::{GovernanceAuthority, GovernanceRuntimeEventRecord};
// Both types are declared in `swarm-policy` as of SPLIT-05, so `GovernanceAuthority`
// can name its own return type. Re-exported rather than merely imported, because the
// paths `swarm_agents::tom_agent::{PartitionState, GovernanceStatusReport}` are what
// this module's callers and integration tests already spell.
pub use swarm_policy::governance::{GovernanceStatusReport, PartitionState};
use swarm_policy::static_gate::scope_for_response_action;

const DEFAULT_CONTINGENCY_LEASE_TTL_MS: i64 = 300_000;
const DEFAULT_CONTINGENCY_BLAST_RADIUS_CAP: usize = 1;
const CONTINGENCY_LEASE_SCHEMA_VERSION: u32 = 1;
const MAX_RECONCILIATION_REPORTS: usize = 16;

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
    pub governance_receipt: ConsensusGovernanceReceipt,
}

impl ContingencyLease {
    pub fn verify(&self) -> Result<(), String> {
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
            .verify()
            .map_err(|error| format!("invalid contingency lease receipt: {error}"))?;
        if receipt.payload.decision != GovernanceReceiptDecision::Approve {
            return Err("contingency lease receipt must be an approval".to_string());
        }
        if receipt.payload.proposal_id
            != build_contingency_lease_proposal(
                &self.lease_id,
                &self.action_kind,
                self.scope.as_deref(),
                self.blast_radius_cap,
                self.max_duration_ms,
                self.issued_at_ms,
                self.expires_at_ms,
            )
            .map_err(|error| format!("failed to rebuild contingency lease proposal: {error}"))?
            .proposal_id
        {
            return Err("contingency lease proposal hash did not match receipt".to_string());
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

    fn can_redeem(&self, action: &ResponseAction, now_ms: i64) -> bool {
        if !self.matches_action(action) || self.expires_at_ms <= now_ms {
            return false;
        }
        let scope = self.scope_key(action);
        self.redeemed_scopes
            .iter()
            .any(|existing| existing == &scope)
            || self.redeemed_scopes.len() < self.blast_radius_cap
    }

    fn redeem(&mut self, action: &ResponseAction, now_ms: i64) -> Result<(), String> {
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
        let scope = self.scope_key(action);
        if self
            .redeemed_scopes
            .iter()
            .any(|existing| existing == &scope)
        {
            return Ok(());
        }
        if self.redeemed_scopes.len() >= self.blast_radius_cap {
            return Err(format!(
                "contingency lease `{}` exceeded blast radius cap {}",
                self.lease_id, self.blast_radius_cap
            ));
        }
        self.redeemed_scopes.push(scope);
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
    Allow {
        receipt: Option<ConsensusGovernanceReceipt>,
        contingency_lease: Option<ContingencyLease>,
    },
    Veto {
        governing_agent_id: AgentId,
        reason: String,
        receipt: Option<ConsensusGovernanceReceipt>,
    },
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
}

/// Refusal reasons for [`GovernancePolicy::register_governor`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceKeyError {
    #[error(
        "governance policy already holds the signing key for governor `{existing}`; refusing to \
         also hold `{offered}` (no process may hold more than one governor signing key)"
    )]
    SecondSigningKey { existing: AgentId, offered: AgentId },
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
    partition_activity: Vec<PartitionActionRecord>,
    reconciliation_reports: Vec<PartitionReconciliationReport>,
    pending_events: VecDeque<GovernanceRuntimeEvent>,
}

impl GovernanceState {
    /// Every governor this policy knows about: the local one plus admitted peers.
    fn governor_count(&self) -> usize {
        self.peer_governors
            .len()
            .saturating_add(usize::from(self.local_governor.is_some()))
    }

    /// The committee for a round, by consensus identity. Contains no keys.
    fn committee(&self) -> Result<ConsensusCommittee, ConsensusError> {
        let mut members = self.peer_governors.iter().cloned().collect::<Vec<_>>();
        if let Some(local) = self.local_governor.as_ref() {
            members.push(local.consensus_agent_id().clone());
        }
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
            partition_activity: Vec::new(),
            reconciliation_reports: Vec::new(),
            pending_events: VecDeque::new(),
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

#[derive(Debug, Clone)]
struct GovernancePersistence {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedGovernanceState {
    governing_agent_id: Option<AgentId>,
    /// Admitted peer governors, by consensus identity. NEVER a key.
    ///
    /// Persisted because forgetting them is a FAIL-OPEN across restart: a
    /// policy that knows about three peers refuses every destructive action
    /// (the shipped solo transport cannot serve a four-member committee), and
    /// one that has forgotten them is back to a committee of one and starts
    /// authorizing again. `#[serde(default)]` so state files written before
    /// this field existed still load.
    #[serde(default)]
    peer_governors: BTreeSet<AgentId>,
    previous_commit_hash: String,
    receipt_counter: u64,
    partition_state: PartitionState,
    partition_started_at_ms: Option<i64>,
    last_transition_at_ms: Option<i64>,
    active_contingency_leases: Vec<ContingencyLease>,
    partition_activity: Vec<PartitionActionRecord>,
    reconciliation_reports: Vec<PartitionReconciliationReport>,
}

impl Default for PersistedGovernanceState {
    fn default() -> Self {
        Self {
            governing_agent_id: None,
            peer_governors: BTreeSet::new(),
            previous_commit_hash: "governance-bootstrap".to_string(),
            receipt_counter: 0,
            partition_state: PartitionState::Healthy,
            partition_started_at_ms: None,
            last_transition_at_ms: None,
            active_contingency_leases: Vec::new(),
            partition_activity: Vec::new(),
            reconciliation_reports: Vec::new(),
        }
    }
}

impl GovernancePersistence {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> Result<PersistedGovernanceState, std::io::Error> {
        if !self.path.exists() {
            return Ok(PersistedGovernanceState::default());
        }
        let bytes = fs::read(&self.path)?;
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)
    }

    fn save(&self, state: &GovernanceState) -> Result<(), std::io::Error> {
        let persisted = PersistedGovernanceState {
            governing_agent_id: state.governing_agent_id.clone(),
            peer_governors: state.peer_governors.clone(),
            previous_commit_hash: state.previous_commit_hash.clone(),
            receipt_counter: state.receipt_counter,
            partition_state: state.partition_state,
            partition_started_at_ms: state.partition_started_at_ms,
            last_transition_at_ms: state.last_transition_at_ms,
            active_contingency_leases: state.active_contingency_leases.clone(),
            partition_activity: state.partition_activity.clone(),
            reconciliation_reports: state.reconciliation_reports.clone(),
        };
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = self.path.with_extension("tmp");
        fs::write(
            &tmp_path,
            serde_json::to_vec_pretty(&persisted).map_err(std::io::Error::other)?,
        )?;
        fs::rename(tmp_path, &self.path)?;
        Ok(())
    }
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

    /// Replace the consensus transport. See [`GovernancePolicy::transport`].
    #[must_use]
    pub fn with_transport(mut self, transport: Arc<dyn ConsensusTransport>) -> Self {
        self.transport = transport;
        self
    }

    pub fn with_persistence(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        let persistence = GovernancePersistence::new(path.as_ref().to_path_buf());
        let persisted = persistence.load()?;
        let state = GovernanceState {
            governing_agent_id: persisted.governing_agent_id,
            peer_governors: persisted.peer_governors,
            previous_commit_hash: persisted.previous_commit_hash,
            receipt_counter: persisted.receipt_counter,
            partition_state: persisted.partition_state,
            partition_started_at_ms: persisted.partition_started_at_ms,
            last_transition_at_ms: persisted.last_transition_at_ms,
            active_contingency_leases: persisted.active_contingency_leases,
            partition_activity: persisted.partition_activity,
            reconciliation_reports: persisted.reconciliation_reports,
            ..Default::default()
        };
        Ok(Self {
            state: Mutex::new(state),
            config,
            persistence: Some(persistence),
            transport: Arc::new(SoloGovernorTransport::new()),
        })
    }

    /// Install THE local governor signing key.
    ///
    /// Idempotent for the same key -- `governance_resilience_integration.rs`
    /// re-registers the same identity after a persistence reload and must keep
    /// working. A second, DIFFERENT key is refused: holding two means this
    /// process could cast two committee members' votes, which is exactly the
    /// property BFT-03 removes.
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
        state
            .governing_agent_id
            .get_or_insert(governing_agent_id.clone());
        let consensus_agent_id = offered.consensus_agent_id().clone();
        state
            .display_governors
            .insert(governing_agent_id, consensus_agent_id.clone());
        state.peer_governors.remove(&consensus_agent_id);
        state.local_governor = Some(offered);
        self.persist_locked(&state);
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
    pub fn register_peer_governor(&self, peer: &VerifyingKey) {
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
            return;
        }
        state.peer_governors.insert(consensus_agent_id);
        self.persist_locked(&state);
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
        state.governing_agent_id = Some(governing_agent_id.clone());
        state.unhealthy_agents = entries
            .iter()
            .filter(|entry| entry.health != AgentHealth::Healthy)
            .cloned()
            .collect();
        let total_governors = state.display_governors.len().max(state.governor_count());
        let unhealthy_governors = entries
            .iter()
            .filter(|entry| {
                entry.health != AgentHealth::Healthy
                    && state
                        .display_governors
                        .contains_key(&AgentId(entry.id.clone()))
            })
            .count();
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
        self.persist_locked(&state);
    }

    pub fn can_act(&self, action: &ResponseAction) -> GovernanceDecision {
        if !is_destructive_action(action) {
            return GovernanceDecision::Allow {
                receipt: None,
                contingency_lease: None,
            };
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
        if state.partition_state == PartitionState::Partitioned {
            if let Some(lease) = preview_matching_contingency_lease(&state, action, now_ms()) {
                return GovernanceDecision::Allow {
                    receipt: Some(lease.governance_receipt.clone()),
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
        let receipt =
            match issue_governance_receipt(&mut state, self.transport.as_ref(), action, decision) {
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
            None => GovernanceDecision::Allow {
                receipt: Some(receipt),
                contingency_lease: None,
            },
        }
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
        if !is_destructive_action(&request.action) {
            return Ok(None);
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
                self.persist_locked(&state);
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
                self.persist_locked(&state);
                return Err(reason);
            }
        };
        if let Err(reason) = lease.verify() {
            self.record_partition_activity_locked(
                &mut state,
                request,
                false,
                reason.clone(),
                Some(lease.lease_id.clone()),
                now_ms,
            );
            self.persist_locked(&state);
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
            self.persist_locked(&state);
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
            self.persist_locked(&state);
            return Err(reason);
        }
        let redeem_result = {
            let existing = &mut state.active_contingency_leases[index];
            existing
                .redeem(&request.action, now_ms)
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
                self.persist_locked(&state);
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
        self.persist_locked(&state);
        Ok(Some(redeemed))
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
        self.persist_locked(&state);
    }

    pub fn status_report(&self) -> GovernanceStatusReport {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        GovernanceStatusReport {
            partition_state: state.partition_state,
            total_governors: state.display_governors.len().max(state.governor_count()),
            healthy_governors: state.last_healthy_governors,
            quorum_threshold: state.last_quorum_threshold,
            active_contingency_leases: state.active_contingency_leases.len(),
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
        for action_kind in destructive_action_kinds() {
            let already_active = state.active_contingency_leases.iter().any(|lease| {
                lease.action_kind == action_kind
                    && lease.scope.is_none()
                    && lease.expires_at_ms > now_ms
                    && lease.redeemed_scopes.len() < lease.blast_radius_cap
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

    fn persist_locked(&self, state: &GovernanceState) {
        let Some(persistence) = &self.persistence else {
            return;
        };
        if let Err(error) = persistence.save(state) {
            tracing::warn!(
                reason = %error,
                path = %persistence.path.display(),
                module = module_path!(),
                "failed to persist governance policy state"
            );
        }
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

fn is_destructive_action(action: &ResponseAction) -> bool {
    matches!(
        action,
        ResponseAction::BlockEgress { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::RevokeCredential { .. }
            | ResponseAction::SinkholeDns { .. }
            | ResponseAction::TerminateUserSession { .. }
            | ResponseAction::InjectFirewallRule { .. }
            | ResponseAction::QuarantineFile { .. }
            | ResponseAction::KillProcess { .. }
            | ResponseAction::SuspendProcess { .. }
            | ResponseAction::DisableUserAccount { .. }
            | ResponseAction::ForcePasswordReset { .. }
            | ResponseAction::RemoveScheduledTask { .. }
    )
}

fn destructive_action_kinds() -> [&'static str; 12] {
    [
        "block_egress",
        "isolate_host",
        "revoke_credential",
        "sinkhole_dns",
        "terminate_user_session",
        "inject_firewall_rule",
        "quarantine_file",
        "kill_process",
        "suspend_process",
        "disable_user_account",
        "force_password_reset",
        "remove_scheduled_task",
    ]
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
fn issue_governance_receipt(
    state: &mut GovernanceState,
    transport: &dyn ConsensusTransport,
    action: &ResponseAction,
    decision: GovernanceReceiptDecision,
) -> Result<ConsensusGovernanceReceipt, ConsensusError> {
    let issued_at_ms = now_ms();
    let proposal = build_governance_proposal(
        state.receipt_counter,
        action,
        decision,
        &state.unhealthy_agents,
        &state.previous_commit_hash,
    )?;
    run_governance_round(state, transport, proposal, decision, issued_at_ms)
}

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

fn build_governance_proposal(
    receipt_counter: u64,
    action: &ResponseAction,
    decision: GovernanceReceiptDecision,
    unhealthy_agents: &[AgentHealthEntry],
    previous_commit_hash: &str,
) -> Result<ConsensusProposal, ConsensusError> {
    let payload = serde_json::json!({
        "receipt_counter": receipt_counter,
        "action": action,
        "decision": decision,
        "unhealthy_agents": unhealthy_agents,
        "previous_commit_hash": previous_commit_hash,
    });
    Ok(ConsensusProposal {
        proposal_id: sha256_hex(&canonical_json_bytes(&payload)?),
        payload,
    })
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
        proposal_id: sha256_hex(&canonical_json_bytes(&payload)?),
        payload,
    })
}

fn preview_matching_contingency_lease(
    state: &GovernanceState,
    action: &ResponseAction,
    now_ms: i64,
) -> Option<ContingencyLease> {
    state
        .active_contingency_leases
        .iter()
        .find(|lease| lease.can_redeem(action, now_ms))
        .cloned()
}

fn prune_expired_contingency_leases(state: &mut GovernanceState, now_ms: i64) {
    state
        .active_contingency_leases
        .retain(|lease| lease.expires_at_ms > now_ms);
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

// The mapping from the private `GovernanceRuntimeEvent` enum to the flat record the
// runtime publishes lives HERE, with the enum, not in the dispatcher. That is the
// whole point of SPLIT-03: the dispatcher publishes governance events without ever
// naming a governance type.
//
// `GovernanceAuthority` is sealed so the set of types that can authorize a
// destructive action during a governance partition stays enumerable. See
// `swarm_policy::governance::GovernanceAuthority`.
impl swarm_policy::governance::sealed::SealedGovernanceAuthority for GovernancePolicy {}

// All FIVE methods below delegate to the inherent method of the same name. Inherent
// impls are probed before trait impls, so `GovernancePolicy::method(self, ..)`
// resolves to the inherent one.
//
// A differing return type would make a mis-resolution a compile error, but that
// covers only two of the five: `authorize_partition_request`
// (`Result<Option<ContingencyLease>, String>` inherent, `Result<bool, String>` here)
// and `drain_runtime_events` (`Vec<GovernanceRuntimeEvent>` inherent,
// `Vec<GovernanceRuntimeEventRecord>` here). `is_partitioned`, `note_partition_veto`
// and `status_report` have identical signatures on both sides, so for those three a
// mis-resolution is a silent infinite recursion, not a diagnostic.
//
// The `deny` below covers all five, which is why the guarantee is stated once here
// instead of per-method. `unconditional_recursion` is warn-by-default, so without
// the attribute these three were protected only by CI's `-D warnings` and not by a
// plain `cargo build`. Measured both ways by rewriting the `is_partitioned` body as
// `<Self as GovernanceAuthority>::is_partitioned(self)`: with this attribute
// `cargo build -p swarm-agents` exits 101 on `error: function cannot return without
// recursing`; with the attribute removed the same body exits 0 and only warns, so
// the recursion ships.
#[deny(unconditional_recursion)]
impl GovernanceAuthority for GovernancePolicy {
    fn authorize_partition_request(
        &self,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<bool, String> {
        GovernancePolicy::authorize_partition_request(self, request, now_ms)
            .map(|lease| lease.is_some())
    }

    fn is_partitioned(&self) -> bool {
        GovernancePolicy::is_partitioned(self)
    }

    fn note_partition_veto(&self, request: &ActionRequest, reason: &str, now_ms: i64) {
        GovernancePolicy::note_partition_veto(self, request, reason, now_ms);
    }

    fn drain_runtime_events(&self) -> Vec<GovernanceRuntimeEventRecord> {
        GovernancePolicy::drain_runtime_events(self)
            .into_iter()
            .map(governance_runtime_event_record)
            .collect()
    }

    // One of the three whose inherent twin has the SAME return type, so the
    // `deny(unconditional_recursion)` above is what stands between a mis-resolution
    // here and a silent hang. There is a runtime backstop too, if the lint is ever
    // weakened: `healthz_includes_governance_partition_component` reaches this method
    // through a `dyn GovernanceAuthority` and asserts on the rendered fields.
    fn status_report(&self) -> GovernanceStatusReport {
        GovernancePolicy::status_report(self)
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
        GovernanceDecision, GovernancePolicy, GovernancePolicyConfig, GovernanceRuntimeEvent,
        PartitionState, TomAgent,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::sync::Arc;
    use swarm_core::agent::{
        AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode,
    };
    use swarm_core::types::{AgentId, ResponseAction, SwarmAction};

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

        let decision = policy.can_act(&ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        });
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

        let non_destructive = policy.can_act(&ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        });
        assert!(matches!(
            non_destructive,
            GovernanceDecision::Allow {
                receipt: None,
                contingency_lease: None
            }
        ));
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

        let decision = policy.can_act(&ResponseAction::BlockEgress {
            target: "203.0.113.77".to_string(),
        });
        match decision {
            GovernanceDecision::Allow {
                receipt: Some(receipt),
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

        let decision = policy.can_act(&ResponseAction::BlockEgress {
            target: "203.0.113.10".to_string(),
        });
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
            policy.can_act(&ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            }),
            GovernanceDecision::Allow {
                receipt: None,
                contingency_lease: None
            }
        ));
    }

    // The partition branch of `can_act` authorizes off `active_contingency_leases`,
    // which `with_persistence` rehydrates from disk before any governor registers.
    // A restart whose Tom admission fails therefore reaches a keyless policy holding
    // live leases: the refusal has to be checked ahead of the partition branch, not
    // after it.
    #[test]
    fn keyless_policy_reloaded_into_a_partition_refuses_persisted_leases() {
        let base_ms = super::now_ms();
        let path = std::env::temp_dir().join(format!(
            "swarm-governance-keyless-{}-{base_ms}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let config = GovernancePolicyConfig {
            contingency_lease_ttl_ms: 600_000,
            contingency_blast_radius_cap: 1,
        };

        let keyed = GovernancePolicy::with_persistence(config.clone(), &path).unwrap();
        keyed
            .register_governor(
                AgentId::new("tom", "primary"),
                SigningKey::from_bytes(&[19; 32]),
            )
            .expect("the policy holds no other governor key");
        keyed.observe_health(&AgentId::new("tom", "primary"), &[], base_ms);
        keyed.observe_health(
            &AgentId::new("tom", "primary"),
            &[AgentHealthEntry {
                id: "tom-primary".to_string(),
                role: AgentRole::Tom,
                health: AgentHealth::Failed,
            }],
            base_ms + 1_000,
        );
        assert_eq!(
            keyed.status_report().partition_state,
            PartitionState::Partitioned
        );
        let action = ResponseAction::IsolateHost {
            host_id: "host-77".to_string(),
        };
        assert!(
            matches!(
                keyed.can_act(&action),
                GovernanceDecision::Allow {
                    contingency_lease: Some(_),
                    ..
                }
            ),
            "precondition: the keyed policy staged a redeemable lease before the restart"
        );

        // Restart with the same state file, Tom admission failing: no governor registers.
        let keyless = GovernancePolicy::with_persistence(config, &path).unwrap();
        assert_eq!(
            keyless.status_report().partition_state,
            PartitionState::Partitioned,
            "precondition: the partition and its leases were rehydrated from disk"
        );
        assert_eq!(
            keyless.status_report().active_contingency_leases,
            super::destructive_action_kinds().len(),
            "precondition: one live lease per destructive action kind survived the restart"
        );

        let decision = keyless.can_act(&action);
        let _ = std::fs::remove_file(&path);
        match decision {
            GovernanceDecision::Veto { reason, .. } => assert!(
                reason.contains("no governor signing key is registered"),
                "veto reason should name the cause, got {reason}"
            ),
            other => {
                panic!("expected a keyless policy to refuse a disk-rehydrated lease, got {other:?}")
            }
        }
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

        let decision = policy.can_act(&ResponseAction::BlockEgress {
            target: "203.0.113.9".to_string(),
        });
        assert!(matches!(
            decision,
            GovernanceDecision::Allow {
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

        let decision = policy.can_act(&ResponseAction::BlockEgress {
            target: "203.0.113.9".to_string(),
        });
        let lease = match decision {
            GovernanceDecision::Allow {
                receipt: Some(receipt),
                contingency_lease: Some(lease),
            } => {
                assert!(receipt.verify().is_ok());
                lease
            }
            other => panic!("expected contingency lease, got {other:?}"),
        };
        assert!(lease.verify().is_ok(), "lease should verify: {lease:?}");

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

        let decision = policy.can_act(&ResponseAction::IsolateHost {
            host_id: "host-7".to_string(),
        });
        let contingency_lease = match decision {
            GovernanceDecision::Allow {
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
