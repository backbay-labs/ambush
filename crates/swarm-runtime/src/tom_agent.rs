use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_consensus::{
    ConsensusCommittee, ConsensusConfig, ConsensusError, ConsensusGovernanceReceipt, ConsensusNode,
    ConsensusProgress, ConsensusProposal, ConsensusSignedEnvelope, GovernanceReceiptDecision,
    recommended_max_faulty,
};
use swarm_core::agent::{
    AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError,
};
use swarm_core::types::{AgentId, ResponseAction, SwarmAction};
use swarm_crypto::{canonical_json_bytes, sha256_hex};
use swarm_policy::ActionRequest;
use swarm_policy::static_gate::scope_for_response_action;

const DEFAULT_CONTINGENCY_LEASE_TTL_MS: i64 = 300_000;
const DEFAULT_CONTINGENCY_BLAST_RADIUS_CAP: usize = 1;
const CONTINGENCY_LEASE_SCHEMA_VERSION: u32 = 1;
const MAX_RECONCILIATION_REPORTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionState {
    Healthy,
    Degraded,
    Partitioned,
    Healing,
}

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

#[derive(Debug)]
struct GovernanceState {
    governing_agent_id: Option<AgentId>,
    display_governors: BTreeMap<AgentId, AgentId>,
    governors: BTreeMap<AgentId, SigningKey>,
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

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            governing_agent_id: None,
            display_governors: BTreeMap::new(),
            governors: BTreeMap::new(),
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
        }
    }

    pub fn with_persistence(
        config: GovernancePolicyConfig,
        path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        let persistence = GovernancePersistence::new(path.as_ref().to_path_buf());
        let persisted = persistence.load()?;
        let state = GovernanceState {
            governing_agent_id: persisted.governing_agent_id,
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
        })
    }

    pub fn register_governor(&self, governing_agent_id: AgentId, signing_key: SigningKey) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .governing_agent_id
            .get_or_insert(governing_agent_id.clone());
        let consensus_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        state
            .display_governors
            .insert(governing_agent_id, consensus_agent_id.clone());
        state.governors.insert(consensus_agent_id, signing_key);
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
        let total_governors = state.display_governors.len().max(state.governors.len());
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
        let receipt = issue_governance_receipt(&mut state, action, decision);
        let governing_agent_id = state.governing_agent_id.clone().or_else(|| {
            receipt
                .as_ref()
                .map(|receipt| receipt.payload.issued_by.clone())
        });

        match reason {
            Some(reason) => {
                let Some(governing_agent_id) = governing_agent_id else {
                    return GovernanceDecision::Allow {
                        receipt,
                        contingency_lease: None,
                    };
                };
                GovernanceDecision::Veto {
                    governing_agent_id,
                    reason,
                    receipt,
                }
            }
            None => GovernanceDecision::Allow {
                receipt,
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
            total_governors: state.display_governors.len().max(state.governors.len()),
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
    ) -> Self {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            degraded_tick_threshold,
            governance_policy,
        )
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        degraded_tick_threshold: usize,
        governance_policy: std::sync::Arc<GovernancePolicy>,
    ) -> Self {
        governance_policy.register_governor(id.clone(), signing_key.clone());
        let verifying_key = signing_key.verifying_key();

        Self {
            id,
            verifying_key,
            health: AgentHealth::Healthy,
            degraded_tick_threshold,
            degraded_ticks: BTreeMap::new(),
            governance_policy,
        }
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

fn issue_governance_receipt(
    state: &mut GovernanceState,
    action: &ResponseAction,
    decision: GovernanceReceiptDecision,
) -> Option<ConsensusGovernanceReceipt> {
    if state.governors.is_empty() {
        return None;
    }

    let issued_at_ms = now_ms();
    match simulate_governance_commit(
        &state.governors,
        &state.previous_commit_hash,
        build_governance_proposal(
            state.receipt_counter,
            action,
            decision,
            &state.unhealthy_agents,
            &state.previous_commit_hash,
        )
        .ok()?,
        issued_at_ms,
    ) {
        Ok((commit, committee)) => {
            let issued_by = state.governors.keys().next().cloned()?;
            let signing_key = state.governors.get(&issued_by)?;
            let previous_commit_hash = state.previous_commit_hash.clone();
            state.previous_commit_hash = commit.commit_hash.clone();
            state.receipt_counter = state.receipt_counter.saturating_add(1);
            ConsensusGovernanceReceipt::issue(
                &commit,
                &previous_commit_hash,
                &committee,
                decision,
                issued_by,
                signing_key,
                issued_at_ms,
            )
            .ok()
        }
        Err(error) => {
            tracing::warn!(
                reason = %error,
                module = module_path!(),
                "failed to build governance consensus receipt"
            );
            None
        }
    }
}

fn issue_contingency_lease(
    state: &mut GovernanceState,
    action_kind: &str,
    scope: Option<&str>,
    blast_radius_cap: usize,
    ttl_ms: i64,
    issued_at_ms: i64,
) -> Option<ContingencyLease> {
    if state.governors.is_empty() || blast_radius_cap == 0 || ttl_ms <= 0 {
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
    match simulate_governance_commit(
        &state.governors,
        &state.previous_commit_hash,
        proposal,
        issued_at_ms,
    ) {
        Ok((commit, committee)) => {
            let issued_by = state.governors.keys().next().cloned()?;
            let signing_key = state.governors.get(&issued_by)?;
            let previous_commit_hash = state.previous_commit_hash.clone();
            state.previous_commit_hash = commit.commit_hash.clone();
            state.receipt_counter = state.receipt_counter.saturating_add(1);
            let governance_receipt = ConsensusGovernanceReceipt::issue(
                &commit,
                &previous_commit_hash,
                &committee,
                GovernanceReceiptDecision::Approve,
                issued_by,
                signing_key,
                issued_at_ms,
            )
            .ok()?;
            Some(ContingencyLease {
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
            })
        }
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

fn simulate_governance_commit(
    governors: &BTreeMap<AgentId, SigningKey>,
    previous_commit_hash: &str,
    proposal: ConsensusProposal,
    now_ms: i64,
) -> Result<(swarm_consensus::ConsensusCommit, ConsensusCommittee), ConsensusError> {
    let committee = ConsensusCommittee::new(
        governors.keys().cloned().collect(),
        recommended_max_faulty(governors.len()),
    )?;
    let config = ConsensusConfig::default();
    let mut nodes = governors
        .iter()
        .map(|(agent_id, signing_key)| {
            ConsensusNode::new_with_signing_key(
                agent_id.clone(),
                signing_key.clone(),
                committee.clone(),
                config.clone(),
                previous_commit_hash.to_string(),
                now_ms,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut pending = std::collections::VecDeque::new();
    let mut commits = Vec::new();

    for node in &mut nodes {
        let progress = node.queue_proposal(proposal.clone(), now_ms)?;
        commits.extend(progress.commits.clone());
        collect_signed_progress(progress, governors, &mut pending)?;
    }

    while let Some(envelope) = pending.pop_front() {
        let mut outbound = Vec::new();
        for node in &mut nodes {
            let progress = node.handle_signed_envelope(&envelope, now_ms)?;
            commits.extend(progress.commits.clone());
            outbound.push(progress);
        }
        for progress in outbound {
            collect_signed_progress(progress, governors, &mut pending)?;
        }
    }

    commits
        .into_iter()
        .next()
        .map(|commit| (commit, committee))
        .ok_or_else(|| {
            ConsensusError::InvalidMessage("governance consensus did not commit".to_string())
        })
}

fn collect_signed_progress(
    progress: ConsensusProgress,
    governors: &BTreeMap<AgentId, SigningKey>,
    pending: &mut std::collections::VecDeque<ConsensusSignedEnvelope>,
) -> Result<(), ConsensusError> {
    for envelope in progress.outbound {
        let signing_key = governors.get(&envelope.message.from).ok_or_else(|| {
            ConsensusError::InvalidCommittee(format!(
                "missing signing key for governance member `{}`",
                envelope.message.from
            ))
        })?;
        pending.push_back(ConsensusSignedEnvelope::sign(envelope, signing_key)?);
    }
    Ok(())
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
        policy.register_governor(
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&[7; 32]),
        );
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
        policy.register_governor(
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&[11; 32]),
        );
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

    #[test]
    fn governance_policy_stages_and_redeems_contingency_leases_during_partition() {
        let base_ms = super::now_ms();
        let policy = GovernancePolicy::new(GovernancePolicyConfig {
            contingency_lease_ttl_ms: 60_000,
            contingency_blast_radius_cap: 1,
        });
        policy.register_governor(
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&[13; 32]),
        );
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
        policy.register_governor(
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&[17; 32]),
        );
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
        let mut agent = TomAgent::new(AgentId::new("tom", "primary"), 3, Arc::clone(&policy));

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
        let mut agent = TomAgent::new(AgentId::new("tom", "primary"), 3, Arc::clone(&policy));

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
