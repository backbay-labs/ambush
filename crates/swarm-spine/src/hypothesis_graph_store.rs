//! Durable persistence for collective hypothesis graphs and fenced work claims.
//!
//! The graph coordinator lives above this crate.  The spine owns only the
//! validated records and their durable state transitions.  A state transition
//! is an append to a signed generation chain: callers provide an optional
//! predecessor revision, the store verifies the current generation and digest,
//! and the next state is signed over canonical bytes before it becomes
//! visible.  The file backend holds an operating-system lock for its lifetime;
//! it is therefore deliberately not a last-writer-wins JSON index.

use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
#[cfg(test)]
use std::sync::{
    OnceLock,
    mpsc::{Receiver, Sender},
};
#[cfg(test)]
use std::time::Duration;
use swarm_core::hypothesis_graph::{
    ConfidenceDistribution, EvidenceWitness, FencingToken, GraphAdmissionError, GraphId,
    GraphLogicalTime, GraphResourceLimits, HYPOTHESIS_GRAPH_SCHEMA_VERSION, Hypothesis,
    HypothesisGraph, HypothesisId, LeaseId, LogicalTaskDescriptor, SchedulerBudget,
    TaskCapabilityProof, TaskClaimRequest, TaskCompletion, TaskId, TaskKind, TaskLease, TaskRecord,
    TaskState, TaskTarget, TaskTerminalEnvelope, TaskTerminalOutboxEntry, TaskTerminalProof,
    UncertaintyReason, derive_logical_task_id,
};
use swarm_core::types::AgentId;
use swarm_crypto::{
    DetachedSignature, Keypair, canonical_json_bytes, sha256_hex, verify_detached_signature,
};

pub const GRAPH_STORE_SCHEMA_VERSION: u32 = 1;
pub const GRAPH_STATE_MIGRATION_LEGACY: u32 = 0;
pub const GRAPH_STATE_MIGRATION_HYPOTHESES: u32 = 1;
pub const GRAPH_STATE_MIGRATION_CURRENT: u32 = GRAPH_STATE_MIGRATION_HYPOTHESES;

pub const fn legacy_graph_state_migration_marker() -> u32 {
    GRAPH_STATE_MIGRATION_LEGACY
}

fn default_graph_state_migration_marker() -> u32 {
    GRAPH_STATE_MIGRATION_LEGACY
}

fn default_graph_limits() -> GraphResourceLimits {
    GraphResourceLimits::default()
}

fn skip_default_graph_limits(value: &GraphResourceLimits) -> bool {
    value == &GraphResourceLimits::default()
}

/// Deployment-owned scheduler ceilings for a graph-store stream.
///
/// `SchedulerBudget` is persisted data supplied by an application boundary;
/// it is not the authority for its own ceilings.  A store keeps this policy
/// separately and requires every authenticated budget to carry the exact
/// configured pair before accepting or reloading a reasoning generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerBudgetPolicy {
    max_work_units: u32,
    max_claims: u16,
}

impl SchedulerBudgetPolicy {
    pub fn new(max_work_units: u32, max_claims: u16) -> Result<Self, GraphAdmissionError> {
        let policy = Self {
            max_work_units,
            max_claims,
        };
        if max_work_units == 0 || max_work_units > SchedulerBudget::MAX_WORK_UNITS {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "scheduler.max_work_units_per_tick".to_string(),
                reason: format!("must be between 1 and {}", SchedulerBudget::MAX_WORK_UNITS),
            });
        }
        if max_claims == 0 || max_claims > SchedulerBudget::MAX_CLAIMS {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "scheduler.max_claims_per_tick".to_string(),
                reason: format!("must be between 1 and {}", SchedulerBudget::MAX_CLAIMS),
            });
        }
        Ok(policy)
    }

    pub fn from_config(
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphAdmissionError> {
        config.validate_reasoning_limits()?;
        Self::new(config.max_work_units_per_tick, config.max_claims_per_tick)
    }

    pub const fn global() -> Self {
        Self {
            max_work_units: SchedulerBudget::MAX_WORK_UNITS,
            max_claims: SchedulerBudget::MAX_CLAIMS,
        }
    }

    pub const fn max_work_units(&self) -> u32 {
        self.max_work_units
    }

    pub const fn max_claims(&self) -> u16 {
        self.max_claims
    }

    /// Stable policy identity used in diagnostics and contract tests.
    pub const fn identity(&self) -> (u32, u16) {
        (self.max_work_units, self.max_claims)
    }

    fn validate_budget(&self, budget: &SchedulerBudget) -> Result<(), GraphStoreError> {
        if budget.max_work_units != self.max_work_units || budget.max_claims != self.max_claims {
            return Err(GraphStoreError::InvalidState {
                reason: format!(
                    "scheduler budget policy identity {:?} does not match configured store policy {:?}",
                    (budget.max_work_units, budget.max_claims),
                    self.identity()
                ),
            });
        }
        budget
            .validate_with_limits(self.max_work_units, self.max_claims)
            .map_err(GraphStoreError::Admission)
    }
}

impl Default for SchedulerBudgetPolicy {
    fn default() -> Self {
        Self::global()
    }
}

pub const GRAPH_STORE_STATE_KIND: &str = "collective_hypothesis_graph";
pub const GRAPH_STORE_STATE_FILE: &str = "state.json";
pub const GRAPH_STORE_LOCK_FILE: &str = "state.lock";
pub const GRAPH_STORE_ANCHOR_FILE: &str = "state.head";
pub const GRAPH_STORE_HIGH_WATER_FILE: &str = "state.highwater";
pub const GRAPH_STORE_HIGH_WATER_TAIL_FILE: &str = "state.highwater.tail";
const GRAPH_STORE_TXN_MANIFEST_FILE: &str = "state.txn.manifest";
const GRAPH_STORE_TXN_STATE_FILE: &str = "state.txn.state";
const GRAPH_STORE_TXN_HEAD_FILE: &str = "state.txn.head";
const GRAPH_STORE_TXN_HIGH_WATER_FILE: &str = "state.txn.highwater";
const GRAPH_STORE_TXN_HIGH_WATER_TAIL_FILE: &str = "state.txn.highwater.tail";
const GRAPH_STORE_TXN_ROLLBACK_FILE: &str = "state.txn.rollback";
const MONOTONIC_ROTATION_MANIFEST_FILE: &str = "state.headrotate";
const MONOTONIC_ROTATION_DATA_FILE: &str = "state.headlog.next";
const MONOTONIC_ROTATION_TAIL_FILE: &str = "state.headtail.next";
const APPEND_MANIFEST_SUFFIX: &str = ".append.manifest";
pub(crate) const MAX_PERSISTED_JSON_BYTES: usize = 16 * 1024 * 1024;

#[cfg(test)]
thread_local! {
    static TEST_PERSISTED_JSON_LIMIT: Cell<usize> = const { Cell::new(MAX_PERSISTED_JSON_BYTES) };
}

pub(crate) fn persisted_json_limit() -> usize {
    #[cfg(test)]
    {
        TEST_PERSISTED_JSON_LIMIT.with(Cell::get)
    }
    #[cfg(not(test))]
    {
        MAX_PERSISTED_JSON_BYTES
    }
}

#[cfg(test)]
pub(crate) struct PersistedJsonLimitGuard {
    previous: usize,
}

#[cfg(test)]
pub(crate) fn install_test_persisted_json_limit(limit: usize) -> PersistedJsonLimitGuard {
    let previous = TEST_PERSISTED_JSON_LIMIT.with(|current| current.replace(limit));
    PersistedJsonLimitGuard { previous }
}

#[cfg(test)]
impl Drop for PersistedJsonLimitGuard {
    fn drop(&mut self) {
        TEST_PERSISTED_JSON_LIMIT.with(|current| current.set(self.previous));
    }
}

static TEMP_FILE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// A generation and its canonical digest.  Both fields are required for CAS;
/// sequence equality alone is intentionally insufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphStoreRevision {
    pub generation: u64,
    pub digest: String,
}

impl GraphStoreRevision {
    pub fn new(generation: u64, digest: impl Into<String>) -> Self {
        Self {
            generation,
            digest: digest.into(),
        }
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        if self.digest.trim().is_empty() || self.digest.len() > 128 {
            return Err(GraphStoreError::InvalidState {
                reason: "store revision digest must be non-empty and bounded".to_string(),
            });
        }
        Ok(())
    }
}

/// One claim attempt.  `task` is always a core-validated state-machine
/// record; `history` retains prior terminal attempts so duplicate work and
/// stale-worker behavior remain measurable after reclaim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableTaskRecord {
    pub schema_version: u32,
    pub task: TaskRecord,
    pub generation: u64,
    pub history: Vec<TaskRecord>,
}

impl DurableTaskRecord {
    fn validate(&self, limits: &GraphResourceLimits) -> Result<(), GraphStoreError> {
        if self.schema_version != GRAPH_STORE_SCHEMA_VERSION {
            return Err(GraphStoreError::UnsupportedSchema(self.schema_version));
        }
        self.task
            .validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
            .map_err(GraphStoreError::Admission)?;
        if self.generation == 0 {
            return Err(GraphStoreError::InvalidState {
                reason: "task ledger generation must be positive".to_string(),
            });
        }
        if self.history.len() >= usize::from(limits.max_task_retries) {
            return Err(GraphStoreError::ResourceLimit {
                resource: "task.history".to_string(),
                limit: usize::from(limits.max_task_retries),
            });
        }
        for prior in &self.history {
            prior
                .validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
                .map_err(GraphStoreError::Admission)?;
            if prior.request.task_id != self.task.request.task_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "task history contains another task ID".to_string(),
                });
            }
            if !matches!(
                prior.state,
                TaskState::Completed | TaskState::Failed | TaskState::Expired
            ) || prior.lease.is_some()
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "task history must contain only terminal, unleased records".to_string(),
                });
            }
        }
        if self.task.request.task_id.as_str().trim().is_empty() {
            return Err(GraphStoreError::InvalidState {
                reason: "task ID must not be empty".to_string(),
            });
        }
        let expected_attempts = self.history.len().saturating_add(1);
        if usize::from(self.task.attempts) != expected_attempts {
            return Err(GraphStoreError::InvalidState {
                reason: "task attempts do not match retained terminal history".to_string(),
            });
        }
        Ok(())
    }

    pub fn current(&self) -> &TaskRecord {
        &self.task
    }
}

/// Per-task monotonicity retained independently from the replaceable task
/// map.  A CAS candidate may replace `tasks`, but it may not lower any of
/// these durable high-water fields or resurrect a completed/failed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMonotonicity {
    pub wrapper_generation: u64,
    pub core_generation: u64,
    pub attempts: u16,
    pub history_len: u32,
    pub lease_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<TaskState>,
    pub request_digest: String,
    pub task_digest: String,
    /// Digest of the complete retained wrapper history.  This is omitted on
    /// legacy v0 tombstones so their authenticated wire bytes remain exact;
    /// newly admitted reasoning tasks bind it in their tombstone.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub history_digest: String,
}

impl TaskMonotonicity {
    pub fn from_record(record: &DurableTaskRecord) -> Result<Self, GraphStoreError> {
        Self::from_record_with_history(record, true)
    }

    fn from_record_legacy(record: &DurableTaskRecord) -> Result<Self, GraphStoreError> {
        Self::from_record_with_history(record, false)
    }

    fn from_record_with_history(
        record: &DurableTaskRecord,
        bind_history: bool,
    ) -> Result<Self, GraphStoreError> {
        let request_identity = (
            &record.task.request.task_id,
            &record.task.request.kind,
            &record.task.request.target,
            &record.task.request.role,
            &record.task.request.evidence_scope,
        );
        let request_bytes = canonical_json_bytes(&request_identity).map_err(|error| {
            GraphStoreError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        let task_bytes = canonical_json_bytes(&record.task).map_err(|error| {
            GraphStoreError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        let history_digest = if bind_history {
            let history_bytes = canonical_json_bytes(&record.history).map_err(|error| {
                GraphStoreError::Canonicalization {
                    reason: error.to_string(),
                }
            })?;
            sha256_hex(&history_bytes)
        } else {
            String::new()
        };
        let lease_epoch = record
            .task
            .lease
            .as_ref()
            .map_or(0, |lease| lease.fencing_token.0)
            .max(
                record
                    .task
                    .terminal_history
                    .iter()
                    .map(|proof| proof.prior_lease.fencing_token.0)
                    .max()
                    .unwrap_or(0),
            )
            .max(
                record
                    .history
                    .iter()
                    .flat_map(|prior| {
                        prior.lease.iter().map(|lease| lease.fencing_token.0).chain(
                            prior
                                .terminal_history
                                .iter()
                                .map(|proof| proof.prior_lease.fencing_token.0),
                        )
                    })
                    .max()
                    .unwrap_or(0),
            );
        let terminal_state = matches!(record.task.state, TaskState::Completed | TaskState::Failed)
            .then_some(record.task.state);
        Ok(Self {
            wrapper_generation: record.generation,
            // Core task generations restart at one for a reclaimed attempt;
            // the durable wrapper history makes the task's *effective* core
            // epoch monotonic across those attempts.
            core_generation: record
                .task
                .generation
                .checked_add(u64::try_from(record.history.len()).map_err(|_| {
                    GraphStoreError::InvalidState {
                        reason: "task history generation overflow".to_string(),
                    }
                })?)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "task core generation overflow".to_string(),
                })?,
            attempts: record.task.attempts,
            history_len: u32::try_from(record.history.len()).map_err(|_| {
                GraphStoreError::InvalidState {
                    reason: "task history length overflow".to_string(),
                }
            })?,
            lease_epoch,
            terminal_state,
            request_digest: sha256_hex(&request_bytes),
            task_digest: sha256_hex(&task_bytes),
            history_digest,
        })
    }

    fn compare_to(&self, current: &Self, task_id: &TaskId) -> Result<(), GraphStoreError> {
        if self.request_digest != current.request_digest {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} immutable request regressed or changed"),
            });
        }
        if !current.history_digest.is_empty()
            && self.history_digest != current.history_digest
            && self.history_len == current.history_len
        {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} retained history digest changed"),
            });
        }
        if self.wrapper_generation < current.wrapper_generation
            || self.core_generation < current.core_generation
            || self.attempts < current.attempts
            || self.history_len < current.history_len
            || self.lease_epoch < current.lease_epoch
        {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} monotonic high-water regressed"),
            });
        }
        if current.terminal_state.is_some() && self.terminal_state != current.terminal_state {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} terminal state was resurrected or changed"),
            });
        }
        if self.wrapper_generation == current.wrapper_generation
            && self.core_generation == current.core_generation
            && self.attempts == current.attempts
            && self.history_len == current.history_len
            && self.lease_epoch == current.lease_epoch
            && self.task_digest != current.task_digest
        {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} changed without advancing its generation"),
            });
        }
        Ok(())
    }
}

fn tombstone_matches_record(
    observed: &TaskMonotonicity,
    record: &DurableTaskRecord,
    migration_marker: u32,
) -> Result<bool, GraphStoreError> {
    let expected = if migration_marker == GRAPH_STATE_MIGRATION_LEGACY {
        TaskMonotonicity::from_record_legacy(record)?
    } else {
        TaskMonotonicity::from_record(record)?
    };
    if observed == &expected {
        return Ok(true);
    }
    Ok(migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
        && observed.history_digest.is_empty()
        && observed.wrapper_generation == expected.wrapper_generation
        && observed.core_generation == expected.core_generation
        && observed.attempts == expected.attempts
        && observed.history_len == expected.history_len
        && observed.lease_epoch == expected.lease_epoch
        && observed.terminal_state == expected.terminal_state
        && observed.request_digest == expected.request_digest
        && observed.task_digest == expected.task_digest)
}

/// The canonical unsigned state covered by a generation digest and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphStoreState {
    pub schema_version: u32,
    pub graph_id: GraphId,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<String>,
    pub graph: HypothesisGraph,
    /// Durable reasoning projection carried in the same signed generation as
    /// graph and task state.  Empty legacy values are omitted so an
    /// authenticated Plan 03 state keeps its historical canonical bytes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    pub tasks: BTreeMap<TaskId, DurableTaskRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub logical_task_descriptors: BTreeMap<TaskId, LogicalTaskDescriptor>,
    #[serde(default)]
    pub task_tombstones: BTreeMap<TaskId, TaskMonotonicity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub terminal_outbox: BTreeMap<TaskId, TaskTerminalOutboxEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub task_failure_outbox: BTreeMap<TaskId, TaskFailureOutboxEntry>,
    pub fencing_counter: u64,
    #[serde(
        default = "default_graph_limits",
        skip_serializing_if = "skip_default_graph_limits"
    )]
    pub limits: GraphResourceLimits,
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub cross_graph_links: std::collections::BTreeSet<(GraphId, GraphId)>,
    /// Config-bound scheduler admission state. Legacy marker-0 states omit
    /// this field entirely; once attached, the budget is part of the same
    /// signed generation as tasks and coordinator publications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler_budget: Option<SchedulerBudget>,
    #[serde(
        default = "default_graph_state_migration_marker",
        skip_serializing_if = "is_legacy_graph_state_migration"
    )]
    pub migration_marker: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_projection_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_projection_digest: Option<String>,
    pub logical_time_high_water: GraphLogicalTime,
}

fn is_legacy_graph_state_migration(marker: &u32) -> bool {
    *marker == GRAPH_STATE_MIGRATION_LEGACY
}

/// Typed input for the one-way legacy-to-reasoning state transformation.
///
/// Keeping this as a value object prevents call sites from accidentally
/// swapping one of the maps or digest fields in the old positional API. The
/// builder defaults to empty reasoning projections and the current marker;
/// migration callers should use `migration_to_hypotheses` explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningStateUpdate {
    hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    tasks: BTreeMap<TaskId, DurableTaskRecord>,
    logical_task_descriptors: BTreeMap<TaskId, LogicalTaskDescriptor>,
    terminal_outbox: BTreeMap<TaskId, TaskTerminalOutboxEntry>,
    task_failure_outbox: BTreeMap<TaskId, TaskFailureOutboxEntry>,
    limits: GraphResourceLimits,
    cross_graph_links: std::collections::BTreeSet<(GraphId, GraphId)>,
    scheduler_budget: Option<SchedulerBudget>,
    migration_marker: u32,
    result_projection_digest: Option<String>,
    operator_projection_digest: Option<String>,
    logical_time_high_water: GraphLogicalTime,
}

impl ReasoningStateUpdate {
    pub fn migration_to_hypotheses(
        limits: GraphResourceLimits,
        logical_time_high_water: GraphLogicalTime,
    ) -> Self {
        Self {
            limits,
            logical_time_high_water,
            ..Self::default()
        }
    }

    pub fn with_hypotheses(mut self, hypotheses: BTreeMap<HypothesisId, Hypothesis>) -> Self {
        self.hypotheses = hypotheses;
        self
    }

    pub fn with_tasks(mut self, tasks: BTreeMap<TaskId, DurableTaskRecord>) -> Self {
        self.tasks = tasks;
        self
    }

    pub fn with_logical_task_descriptors(
        mut self,
        descriptors: BTreeMap<TaskId, LogicalTaskDescriptor>,
    ) -> Self {
        self.logical_task_descriptors = descriptors;
        self
    }

    pub fn with_terminal_outbox(
        mut self,
        terminal_outbox: BTreeMap<TaskId, TaskTerminalOutboxEntry>,
    ) -> Self {
        self.terminal_outbox = terminal_outbox;
        self
    }

    pub fn with_task_failure_outbox(
        mut self,
        task_failure_outbox: BTreeMap<TaskId, TaskFailureOutboxEntry>,
    ) -> Self {
        self.task_failure_outbox = task_failure_outbox;
        self
    }

    pub fn with_cross_graph_links(
        mut self,
        cross_graph_links: std::collections::BTreeSet<(GraphId, GraphId)>,
    ) -> Self {
        self.cross_graph_links = cross_graph_links;
        self
    }

    /// Attach the already config-validated scheduler budget to the same
    /// reasoning transition as tasks, hypotheses, and coordinator history.
    /// The spine revalidates its bounded wire invariants and monotonicity at
    /// the CAS boundary; it never constructs a caller-selected budget.
    pub fn with_scheduler_budget(mut self, scheduler_budget: SchedulerBudget) -> Self {
        self.scheduler_budget = Some(scheduler_budget);
        self
    }

    pub fn with_projection_digests(
        mut self,
        result_projection_digest: Option<String>,
        operator_projection_digest: Option<String>,
    ) -> Self {
        self.result_projection_digest = result_projection_digest;
        self.operator_projection_digest = operator_projection_digest;
        self
    }

    pub fn with_migration_marker(mut self, migration_marker: u32) -> Self {
        self.migration_marker = migration_marker;
        self
    }
}

impl Default for ReasoningStateUpdate {
    fn default() -> Self {
        Self {
            hypotheses: BTreeMap::new(),
            tasks: BTreeMap::new(),
            logical_task_descriptors: BTreeMap::new(),
            terminal_outbox: BTreeMap::new(),
            task_failure_outbox: BTreeMap::new(),
            limits: GraphResourceLimits::default(),
            cross_graph_links: std::collections::BTreeSet::new(),
            scheduler_budget: None,
            migration_marker: GRAPH_STATE_MIGRATION_HYPOTHESES,
            result_projection_digest: None,
            operator_projection_digest: None,
            logical_time_high_water: GraphLogicalTime::new(0),
        }
    }
}

impl GraphStoreState {
    pub fn new(graph: HypothesisGraph) -> Result<Self, GraphStoreError> {
        graph.validate().map_err(GraphStoreError::Admission)?;
        let limits = graph.limits.clone();
        Ok(Self {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            graph_id: graph.graph_id.clone(),
            generation: 0,
            predecessor_digest: None,
            graph,
            hypotheses: BTreeMap::new(),
            tasks: BTreeMap::new(),
            logical_task_descriptors: BTreeMap::new(),
            task_tombstones: BTreeMap::new(),
            terminal_outbox: BTreeMap::new(),
            task_failure_outbox: BTreeMap::new(),
            fencing_counter: 0,
            limits,
            cross_graph_links: std::collections::BTreeSet::new(),
            migration_marker: GRAPH_STATE_MIGRATION_LEGACY,
            result_projection_digest: None,
            operator_projection_digest: None,
            scheduler_budget: None,
            logical_time_high_water: GraphLogicalTime::new(0),
        })
    }

    pub fn validate(&self) -> Result<(), GraphStoreError> {
        self.validate_with_limits(&self.graph.limits)
    }

    pub fn validate_with_limits(
        &self,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphStoreError> {
        if self.schema_version != GRAPH_STORE_SCHEMA_VERSION {
            return Err(GraphStoreError::UnsupportedSchema(self.schema_version));
        }
        limits.validate().map_err(GraphStoreError::Admission)?;
        if self.graph.limits != *limits {
            return Err(GraphStoreError::InvalidState {
                reason: "graph resource limits do not match the configured store limits"
                    .to_string(),
            });
        }
        if self.migration_marker > GRAPH_STATE_MIGRATION_CURRENT {
            return Err(GraphStoreError::InvalidState {
                reason: format!(
                    "unknown graph-state migration marker {}",
                    self.migration_marker
                ),
            });
        }
        if self.migration_marker == GRAPH_STATE_MIGRATION_LEGACY
            && (!self.hypotheses.is_empty()
                || !self.logical_task_descriptors.is_empty()
                || !self.terminal_outbox.is_empty()
                || !self.task_failure_outbox.is_empty()
                || !self.cross_graph_links.is_empty()
                || self.scheduler_budget.is_some()
                || self.result_projection_digest.is_some()
                || self.operator_projection_digest.is_some())
        {
            return Err(GraphStoreError::InvalidState {
                reason: "legacy graph-state marker cannot carry reasoning fields".to_string(),
            });
        }
        if self.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES && self.limits != *limits {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning-state limits do not match configured store limits".to_string(),
            });
        }
        if self.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
            && self.scheduler_budget.is_none()
        {
            return Err(GraphStoreError::InvalidState {
                reason: "marker-1 reasoning state requires a persisted scheduler budget"
                    .to_string(),
            });
        }
        if self.graph_id != self.graph.graph_id {
            return Err(GraphStoreError::InvalidState {
                reason: "store graph ID does not match graph payload".to_string(),
            });
        }
        self.logical_time_high_water
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if let Some(scheduler_budget) = &self.scheduler_budget {
            scheduler_budget
                .validate()
                .map_err(GraphStoreError::Admission)?;
            if scheduler_budget.current_tick() > self.logical_time_high_water {
                return Err(GraphStoreError::InvalidState {
                    reason: "scheduler budget logical tick exceeds graph high-water".to_string(),
                });
            }
        }
        if self.generation == 0 {
            if self.predecessor_digest.is_some() {
                return Err(GraphStoreError::InvalidState {
                    reason: "initial state cannot have a predecessor digest".to_string(),
                });
            }
        } else if self.predecessor_digest.as_deref().is_none_or(str::is_empty) {
            return Err(GraphStoreError::InvalidState {
                reason: "advanced state requires a predecessor digest".to_string(),
            });
        }
        self.graph.validate().map_err(GraphStoreError::Admission)?;
        if self.hypotheses.len() > limits.max_hypotheses {
            return Err(GraphStoreError::ResourceLimit {
                resource: "hypotheses".to_string(),
                limit: limits.max_hypotheses,
            });
        }
        if self.logical_task_descriptors.len() > limits.max_tasks
            || self.terminal_outbox.len() > limits.max_tasks
            || self.task_failure_outbox.len() > limits.max_tasks
        {
            return Err(GraphStoreError::ResourceLimit {
                resource: "reasoning.tasks".to_string(),
                limit: limits.max_tasks,
            });
        }
        for (hypothesis_id, hypothesis) in &self.hypotheses {
            if hypothesis_id != &hypothesis.hypothesis_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "hypothesis map key does not match hypothesis ID".to_string(),
                });
            }
            hypothesis
                .validate(limits)
                .map_err(GraphStoreError::Admission)?;
            for edge_id in &hypothesis.claims {
                if !self.graph.edges.contains_key(edge_id) {
                    return Err(GraphStoreError::InvalidState {
                        reason: "hypothesis claim references an unknown graph edge".to_string(),
                    });
                }
            }
            for contradiction_id in &hypothesis.contradiction_ids {
                if !self.graph.contradictions.contains_key(contradiction_id)
                    && !self.graph.conflicts.contains_key(contradiction_id)
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "hypothesis references an unknown contradiction".to_string(),
                    });
                }
            }
            for decision in &hypothesis.decision_history {
                if self.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
                    && decision.decided_at > self.logical_time_high_water
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "decision logical time exceeds the durable graph high-water"
                            .to_string(),
                    });
                }
                if decision
                    .evidence_ids
                    .iter()
                    .any(|evidence_id| !self.graph.evidence.contains_key(evidence_id))
                {
                    return Err(GraphStoreError::Admission(
                        GraphAdmissionError::UnknownEvidence,
                    ));
                }
                decision
                    .validate_identity_admission(&self.graph.evidence)
                    .map_err(GraphStoreError::Admission)?;
            }
        }
        for (task_id, descriptor) in &self.logical_task_descriptors {
            descriptor.validate().map_err(GraphStoreError::Admission)?;
            if task_id != &descriptor.task_id || descriptor.graph_id != self.graph_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "logical task descriptor is not bound to this graph".to_string(),
                });
            }
            if !self.tasks.contains_key(task_id) {
                return Err(GraphStoreError::InvalidState {
                    reason: "logical task descriptor has no durable task".to_string(),
                });
            }
        }
        if self.cross_graph_links.len() > limits.max_tasks {
            return Err(GraphStoreError::ResourceLimit {
                resource: "reasoning.cross_graph_links".to_string(),
                limit: limits.max_tasks,
            });
        }
        for (left, right) in &self.cross_graph_links {
            if left.as_str().trim().is_empty() || right.as_str().trim().is_empty() || left == right
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "cross-graph links must contain two distinct graph IDs".to_string(),
                });
            }
        }
        if self.tasks.len() > limits.max_tasks {
            return Err(GraphStoreError::ResourceLimit {
                resource: "tasks".to_string(),
                limit: limits.max_tasks,
            });
        }
        if self.task_tombstones.len() > limits.max_tasks {
            return Err(GraphStoreError::ResourceLimit {
                resource: "task_tombstones".to_string(),
                limit: limits.max_tasks,
            });
        }
        for (task_id, task) in &self.tasks {
            if task_id != &task.task.request.task_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "task map key does not match task ID".to_string(),
                });
            }
            task.validate(limits)?;
            let observed_tombstone =
                self.task_tombstones
                    .get(task_id)
                    .ok_or_else(|| GraphStoreError::InvalidState {
                        reason: "task map entry has no durable monotonic tombstone".to_string(),
                    })?;
            if !tombstone_matches_record(observed_tombstone, task, self.migration_marker)? {
                return Err(GraphStoreError::InvalidState {
                    reason: "task tombstone does not describe the task map entry".to_string(),
                });
            }
            let mut maximum_fence = task
                .task
                .lease
                .as_ref()
                .map_or(0, |lease| lease.fencing_token.0);
            for proof in &task.task.terminal_history {
                maximum_fence = maximum_fence.max(proof.prior_lease.fencing_token.0);
            }
            for prior in &task.history {
                if let Some(lease) = &prior.lease {
                    maximum_fence = maximum_fence.max(lease.fencing_token.0);
                }
                for proof in &prior.terminal_history {
                    maximum_fence = maximum_fence.max(proof.prior_lease.fencing_token.0);
                }
            }
            if maximum_fence > self.fencing_counter {
                return Err(GraphStoreError::InvalidState {
                    reason: "fencing counter regressed below a retained lease token".to_string(),
                });
            }
            if task.task.request.requested_at > self.logical_time_high_water {
                return Err(GraphStoreError::InvalidState {
                    reason: "logical time high-water regressed below a task request".to_string(),
                });
            }
            for record in std::iter::once(&task.task).chain(task.history.iter()) {
                if let Some(lease) = &record.lease
                    && lease.issued_at > self.logical_time_high_water
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "logical time high-water regressed below a lease".to_string(),
                    });
                }
                if let Some(completion) = &record.completion
                    && completion.completed_at > self.logical_time_high_water
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "logical time high-water regressed below a completion".to_string(),
                    });
                }
                for proof in &record.terminal_history {
                    if proof.completed_at > self.logical_time_high_water
                        || proof.prior_lease.issued_at > self.logical_time_high_water
                    {
                        return Err(GraphStoreError::InvalidState {
                            reason: "logical time high-water regressed below terminal history"
                                .to_string(),
                        });
                    }
                }
            }
        }
        if self.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES {
            for task_id in self.tasks.keys() {
                if !self.logical_task_descriptors.contains_key(task_id) {
                    return Err(GraphStoreError::InvalidState {
                        reason: "reasoning task has no logical task descriptor".to_string(),
                    });
                }
            }
        }
        for task_id in self.task_tombstones.keys() {
            if !self.tasks.contains_key(task_id) {
                return Err(GraphStoreError::InvalidState {
                    reason: "task tombstone has no durable task record".to_string(),
                });
            }
        }
        for (task_id, entry) in &self.terminal_outbox {
            let task = self
                .tasks
                .get(task_id)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "terminal outbox references an unknown task".to_string(),
                })?;
            if !matches!(task.task.state, TaskState::Completed | TaskState::Failed) {
                return Err(GraphStoreError::InvalidState {
                    reason: "terminal outbox task is not terminal".to_string(),
                });
            }
            let descriptor = self.logical_task_descriptors.get(task_id).ok_or_else(|| {
                GraphStoreError::InvalidState {
                    reason: "terminal outbox task has no logical descriptor".to_string(),
                }
            })?;
            entry
                .validate_for_committed_task_at(
                    &task.task,
                    descriptor,
                    limits,
                    self.logical_time_high_water,
                )
                .map_err(GraphStoreError::Admission)?;
            entry
                .validate_graph_references(&self.graph, &self.hypotheses)
                .map_err(GraphStoreError::Admission)?;
            for evidence in &entry.evidence {
                match self.graph.evidence.get(&evidence.evidence_id) {
                    Some(admitted) if admitted == evidence => {}
                    Some(_) => {
                        return Err(GraphStoreError::InvalidState {
                            reason: "terminal outbox evidence differs from graph evidence"
                                .to_string(),
                        });
                    }
                    None => {
                        return Err(GraphStoreError::Admission(
                            GraphAdmissionError::UnknownEvidence,
                        ));
                    }
                }
            }
            if let Some(decision) = &entry.decision {
                if !decision
                    .evidence_ids
                    .iter()
                    .all(|evidence_id| self.graph.evidence.contains_key(evidence_id))
                {
                    return Err(GraphStoreError::Admission(
                        GraphAdmissionError::UnknownEvidence,
                    ));
                }
                let hypothesis = self
                    .hypotheses
                    .get(&decision.hypothesis_id)
                    .ok_or_else(|| GraphStoreError::InvalidState {
                        reason: "terminal outbox decision has no owning hypothesis".to_string(),
                    })?;
                if !hypothesis.decision_history.contains(decision) {
                    return Err(GraphStoreError::InvalidState {
                        reason: "terminal outbox decision is absent from hypothesis history"
                            .to_string(),
                    });
                }
                if let Some(link) = &entry.envelope.decision_link {
                    match &link.target {
                        TaskTarget::Edge { edge_id } => {
                            if !self.graph.edges.contains_key(edge_id) {
                                return Err(GraphStoreError::InvalidState {
                                    reason: "terminal decision targets an unknown edge".to_string(),
                                });
                            }
                        }
                        TaskTarget::Hypothesis { hypothesis_id } => {
                            if hypothesis_id != &decision.hypothesis_id
                                || !self.hypotheses.contains_key(hypothesis_id)
                            {
                                return Err(GraphStoreError::InvalidState {
                                    reason: "terminal decision targets an unknown hypothesis"
                                        .to_string(),
                                });
                            }
                        }
                        TaskTarget::Evidence { .. } => {
                            return Err(GraphStoreError::InvalidState {
                                reason: "terminal decision target cannot be evidence".to_string(),
                            });
                        }
                    }
                }
            }
        }
        for (task_id, entry) in &self.task_failure_outbox {
            let task = self
                .tasks
                .get(task_id)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "task failure outbox references an unknown task".to_string(),
                })?;
            let descriptor = self.logical_task_descriptors.get(task_id).ok_or_else(|| {
                GraphStoreError::InvalidState {
                    reason: "task failure outbox has no logical descriptor".to_string(),
                }
            })?;
            entry.validate_for_failed_task(&task.task, descriptor, self.logical_time_high_water)?;
        }
        Ok(())
    }

    /// Apply the exact legacy-to-reasoning transformation. The caller must
    /// authenticate the legacy signed envelope before invoking this method.
    pub fn with_reasoning_state(
        mut base: Self,
        update: ReasoningStateUpdate,
    ) -> Result<Self, GraphStoreError> {
        base.validate_with_limits(&base.graph.limits)?;
        if base.migration_marker != GRAPH_STATE_MIGRATION_LEGACY {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning-state migration requires the legacy marker".to_string(),
            });
        }
        if update.migration_marker != GRAPH_STATE_MIGRATION_HYPOTHESES {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning-state migration must target the hypotheses marker".to_string(),
            });
        }
        if update.limits != base.graph.limits {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning-state limits do not match graph limits".to_string(),
            });
        }
        if update.scheduler_budget.is_none() {
            return Err(GraphStoreError::InvalidState {
                reason: "marker-1 reasoning migration requires a persisted scheduler budget"
                    .to_string(),
            });
        }
        // Migration is not a replacement API. Every legacy task and its
        // monotonic tombstone must survive byte-for-byte. Descriptors are
        // required for every task in the marker-1 state, including legacy
        // tasks, so callers must supply an authenticated backfill.
        for (task_id, task) in &base.tasks {
            match update.tasks.get(task_id) {
                Some(candidate) if candidate == task => {}
                Some(_) => {
                    return Err(GraphStoreError::InvalidState {
                        reason: "reasoning-state migration rewrote an existing task".to_string(),
                    });
                }
                None => {
                    return Err(GraphStoreError::InvalidState {
                        reason: "reasoning-state migration removed an existing task".to_string(),
                    });
                }
            }
        }
        let mut task_tombstones = BTreeMap::new();
        for (task_id, task) in &update.tasks {
            if task_id != &task.task.request.task_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "reasoning-state task map key does not match task ID".to_string(),
                });
            }
            let tombstone = if let Some(prior) = base.task_tombstones.get(task_id) {
                // Preserve the exact legacy tombstone rather than filling its
                // new history digest during migration. The marker-1 validator
                // accepts this one-way compatibility form; subsequent
                // transitions bind the digest.
                let expected_legacy = TaskMonotonicity::from_record_legacy(task)?;
                if prior != &expected_legacy {
                    return Err(GraphStoreError::InvalidState {
                        reason: "reasoning-state migration rewrote an existing task tombstone"
                            .to_string(),
                    });
                }
                prior.clone()
            } else {
                TaskMonotonicity::from_record(task)?
            };
            task_tombstones.insert(task_id.clone(), tombstone);
        }
        for task_id in base.task_tombstones.keys() {
            if !task_tombstones.contains_key(task_id) {
                return Err(GraphStoreError::InvalidState {
                    reason: "reasoning-state migration removed an existing task tombstone"
                        .to_string(),
                });
            }
        }
        for task_id in update.tasks.keys() {
            if !base.tasks.contains_key(task_id)
                && !update.logical_task_descriptors.contains_key(task_id)
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "reasoning-state migration added a task without a logical descriptor"
                        .to_string(),
                });
            }
        }
        base.hypotheses = update.hypotheses;
        base.tasks = update.tasks;
        base.logical_task_descriptors = update.logical_task_descriptors;
        base.task_tombstones = task_tombstones;
        base.terminal_outbox = update.terminal_outbox;
        base.task_failure_outbox = update.task_failure_outbox;
        base.limits = update.limits;
        base.cross_graph_links = update.cross_graph_links;
        base.scheduler_budget = update.scheduler_budget;
        base.migration_marker = update.migration_marker;
        base.result_projection_digest = update.result_projection_digest;
        base.operator_projection_digest = update.operator_projection_digest;
        if update.logical_time_high_water < base.logical_time_high_water {
            return Err(GraphStoreError::InvalidTransition {
                reason: "reasoning-state logical time high-water regressed".to_string(),
            });
        }
        base.logical_time_high_water = update.logical_time_high_water;
        let limits_for_validation = base.graph.limits.clone();
        base.validate_with_limits(&limits_for_validation)?;
        Ok(base)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GraphStoreError> {
        let bytes =
            canonical_json_bytes(self).map_err(|error| GraphStoreError::Canonicalization {
                reason: error.to_string(),
            })?;
        if bytes.len() > persisted_json_limit() {
            return Err(GraphStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: persisted_json_limit(),
            });
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<String, GraphStoreError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    pub fn revision(&self) -> Result<GraphStoreRevision, GraphStoreError> {
        Ok(GraphStoreRevision::new(self.generation, self.digest()?))
    }

    pub fn task(&self, task_id: &str) -> Option<&DurableTaskRecord> {
        self.tasks.get(&TaskId::new(task_id))
    }

    pub fn tasks(&self) -> impl Iterator<Item = &DurableTaskRecord> {
        self.tasks.values()
    }
}

/// Public read result used by runtime coordinators and parity tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphStoreSnapshot {
    state: GraphStoreState,
    revision: GraphStoreRevision,
}

/// Validate a terminal publication against the exact claimed task and its
/// signed capability.  The persisted task record does not contain the seed
/// that was used to derive a claimant-independent logical [`TaskId`], so this
/// function deliberately does not pretend to re-derive that identity.  It
/// checks the stronger boundary that is available at this seam: task,
/// envelope, capability, lease, fence, completion, and decision/evidence
/// lineage must all describe one exact claimed request.  Callers that retain
/// the seed can additionally use [`validate_task_logical_identity`].
pub fn validate_task_terminal_envelope(
    task: &TaskRecord,
    envelope: &TaskTerminalEnvelope,
    capability: &TaskCapabilityProof,
    limits: &GraphResourceLimits,
) -> Result<(), GraphStoreError> {
    // Core owns structural, signature, exact-task, lease, fence, completion,
    // and lineage validation.  The spine supplies the configured persistence
    // boundary but does not reimplement those rules.
    envelope
        .validate_for_task(task, limits.max_task_lease_ms, limits.max_task_retries)
        .map_err(GraphStoreError::Admission)?;
    if envelope.capability != *capability {
        return Err(GraphStoreError::InvalidTransition {
            reason: "terminal envelope capability differs from supplied capability".to_string(),
        });
    }
    if let Some(link) = &envelope.decision_link
        && link.target != task.request.target
    {
        return Err(GraphStoreError::InvalidTransition {
            reason: "terminal decision lineage targets a different task target".to_string(),
        });
    }
    Ok(())
}

/// Validate a logical task identity when the creator has retained the seed
/// digest.  A [`TaskRecord`] alone cannot provide this proof because its
/// historical wire shape intentionally stores only the derived `TaskId`.
pub fn validate_task_logical_identity(
    graph_id: &GraphId,
    task: &TaskRecord,
    seed_digest: &str,
) -> Result<(), GraphStoreError> {
    task.request
        .validate()
        .map_err(GraphStoreError::Admission)?;
    let derived = derive_logical_task_id(
        graph_id,
        &task.request.target,
        task.request.kind,
        seed_digest,
    )
    .map_err(GraphStoreError::Admission)?;
    if derived != task.request.task_id {
        return Err(GraphStoreError::InvalidState {
            reason: "persisted task ID does not match the supplied logical seed".to_string(),
        });
    }
    Ok(())
}

impl GraphStoreSnapshot {
    /// Borrow the already-authenticated durable state carried by this
    /// snapshot.  Callers cannot construct a snapshot with an arbitrary state
    /// because both fields and the constructor remain private to the spine.
    pub fn state(&self) -> &GraphStoreState {
        &self.state
    }

    /// Borrow the revision authenticated together with [`Self::state`].
    pub fn revision(&self) -> &GraphStoreRevision {
        &self.revision
    }

    /// Consume this authenticated snapshot into its owned parts.  This is
    /// the only ownership transfer from a snapshot; it does not create a new
    /// snapshot and therefore cannot fabricate a state/revision pairing.
    pub fn into_parts(self) -> (GraphStoreState, GraphStoreRevision) {
        (self.state, self.revision)
    }

    pub fn graph(&self) -> &HypothesisGraph {
        &self.state.graph
    }

    pub fn tasks(&self) -> impl Iterator<Item = &DurableTaskRecord> {
        self.state.tasks.values()
    }

    pub fn hypotheses(&self) -> &BTreeMap<HypothesisId, Hypothesis> {
        &self.state.hypotheses
    }

    pub fn decision_history(
        &self,
    ) -> impl Iterator<Item = &swarm_core::hypothesis_graph::DecisionRecord> {
        self.state
            .hypotheses
            .values()
            .flat_map(|hypothesis| hypothesis.decision_history.iter())
    }

    pub fn terminal_outbox(&self) -> &BTreeMap<TaskId, TaskTerminalOutboxEntry> {
        &self.state.terminal_outbox
    }

    pub fn task_failure_outbox(&self) -> &BTreeMap<TaskId, TaskFailureOutboxEntry> {
        &self.state.task_failure_outbox
    }

    pub fn logical_task_descriptors(&self) -> &BTreeMap<TaskId, LogicalTaskDescriptor> {
        &self.state.logical_task_descriptors
    }

    pub fn limits(&self) -> &GraphResourceLimits {
        &self.state.limits
    }

    pub fn cross_graph_links(&self) -> &std::collections::BTreeSet<(GraphId, GraphId)> {
        &self.state.cross_graph_links
    }

    /// Return the authenticated scheduler budget, when this reasoning stream
    /// has attached one. Legacy marker-0 streams intentionally return `None`.
    pub fn scheduler_budget(&self) -> Option<&SchedulerBudget> {
        self.state.scheduler_budget.as_ref()
    }

    pub fn migration_marker(&self) -> u32 {
        self.state.migration_marker
    }

    pub fn result_projection_digest(&self) -> Option<&str> {
        self.state.result_projection_digest.as_deref()
    }

    pub fn operator_projection_digest(&self) -> Option<&str> {
        self.state.operator_projection_digest.as_deref()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GraphStoreError> {
        self.state.canonical_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedGraphStoreState {
    state: GraphStoreState,
    digest: String,
    signature: DetachedSignature,
}

/// Exact Plan 03 state wire shape. New reasoning fields are deliberately not
/// present and therefore cannot be filled by serde before the legacy bytes
/// have been authenticated. This type is also used for canonical digest and
/// signature verification, rather than converting through `GraphStoreState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDurableTaskRecord {
    schema_version: u32,
    task: TaskRecord,
    generation: u64,
    history: Vec<TaskRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyTaskMonotonicity {
    wrapper_generation: u64,
    core_generation: u64,
    attempts: u16,
    history_len: u32,
    lease_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_state: Option<TaskState>,
    request_digest: String,
    task_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyGraphStoreState {
    schema_version: u32,
    graph_id: GraphId,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_digest: Option<String>,
    graph: HypothesisGraph,
    tasks: BTreeMap<TaskId, LegacyDurableTaskRecord>,
    #[serde(default)]
    task_tombstones: BTreeMap<TaskId, LegacyTaskMonotonicity>,
    fencing_counter: u64,
    logical_time_high_water: GraphLogicalTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySignedGraphStoreState {
    state: LegacyGraphStoreState,
    digest: String,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyGraphStateSigningMaterial<'a> {
    schema_version: u32,
    state_kind: &'static str,
    stream_id: &'a GraphId,
    generation: u64,
    digest: &'a str,
    state: &'a LegacyGraphStoreState,
}

impl LegacyGraphStoreState {
    fn canonical_bytes(&self) -> Result<Vec<u8>, GraphStoreError> {
        let bytes =
            canonical_json_bytes(self).map_err(|error| GraphStoreError::Canonicalization {
                reason: error.to_string(),
            })?;
        if bytes.len() > persisted_json_limit() {
            return Err(GraphStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: persisted_json_limit(),
            });
        }
        Ok(bytes)
    }

    fn revision(&self, digest: impl Into<String>) -> GraphStoreRevision {
        GraphStoreRevision::new(self.generation, digest)
    }

    fn into_current(self) -> GraphStoreState {
        // Keep the new fields at their exact legacy wire defaults. In
        // particular, `limits` must remain default when it was absent from
        // the legacy bytes; otherwise reopening would change the signed
        // canonical state before an explicit migration CAS.
        GraphStoreState {
            schema_version: self.schema_version,
            graph_id: self.graph_id,
            generation: self.generation,
            predecessor_digest: self.predecessor_digest,
            graph: self.graph,
            hypotheses: BTreeMap::new(),
            tasks: self
                .tasks
                .into_iter()
                .map(|(task_id, record)| (task_id, record.into_current()))
                .collect(),
            logical_task_descriptors: BTreeMap::new(),
            task_tombstones: self
                .task_tombstones
                .into_iter()
                .map(|(task_id, tombstone)| (task_id, tombstone.into_current()))
                .collect(),
            terminal_outbox: BTreeMap::new(),
            task_failure_outbox: BTreeMap::new(),
            fencing_counter: self.fencing_counter,
            limits: GraphResourceLimits::default(),
            cross_graph_links: std::collections::BTreeSet::new(),
            scheduler_budget: None,
            migration_marker: GRAPH_STATE_MIGRATION_LEGACY,
            result_projection_digest: None,
            operator_projection_digest: None,
            logical_time_high_water: self.logical_time_high_water,
        }
    }
}

impl LegacyDurableTaskRecord {
    fn into_current(self) -> DurableTaskRecord {
        DurableTaskRecord {
            schema_version: self.schema_version,
            task: self.task,
            generation: self.generation,
            history: self.history,
        }
    }
}

impl LegacyTaskMonotonicity {
    fn into_current(self) -> TaskMonotonicity {
        TaskMonotonicity {
            wrapper_generation: self.wrapper_generation,
            core_generation: self.core_generation,
            attempts: self.attempts,
            history_len: self.history_len,
            lease_epoch: self.lease_epoch,
            terminal_state: self.terminal_state,
            request_digest: self.request_digest,
            task_digest: self.task_digest,
            history_digest: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphStateSigningMaterial<'a> {
    schema_version: u32,
    state_kind: &'static str,
    stream_id: &'a GraphId,
    generation: u64,
    digest: &'a str,
    state: &'a GraphStoreState,
}

/// A small signed high-water mark stored beside the state file.  The state
/// signature proves authenticity, while this anchor prevents an older valid
/// state file from being replayed after a later generation was committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableStateHead {
    pub schema_version: u32,
    pub state_kind: String,
    pub stream_id: String,
    pub generation: u64,
    pub digest: String,
    pub lock_generation: String,
    pub lock_identity: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableHighWaterTail {
    pub schema_version: u32,
    pub record_count: u64,
    pub generation: u64,
    pub digest: String,
}

pub(crate) fn read_high_water(
    lock: &DurableFileLock,
    path: &Path,
    tail_path: &Path,
) -> Result<DurableStateHead, GraphStoreError> {
    recover_high_water_rotation(lock, path, tail_path)?;
    recover_log_append(lock, path, tail_path)?;
    let records: Vec<DurableStateHead> = lock.read_json_log(path)?;
    let tail: DurableHighWaterTail = lock.read_json(tail_path)?;
    let last = records
        .last()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "local high-water log is empty".to_string(),
        })?;
    if tail.schema_version != GRAPH_STORE_SCHEMA_VERSION
        || tail.record_count
            != u64::try_from(records.len()).map_err(|_| GraphStoreError::InvalidState {
                reason: "local high-water record count overflow".to_string(),
            })?
        || tail.generation != last.generation
        || tail.digest != last.digest
    {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: tail.generation,
            observed_generation: last.generation,
        });
    }
    Ok(last.clone())
}

pub(crate) fn append_high_water(
    lock: &DurableFileLock,
    path: &Path,
    tail_path: &Path,
    head: &DurableStateHead,
) -> Result<(), GraphStoreError> {
    recover_high_water_rotation(lock, path, tail_path)?;
    recover_log_append(lock, path, tail_path)?;
    let existing = if fs::symlink_metadata(path).is_ok() {
        lock.read_json_log::<DurableStateHead>(path)?
    } else {
        Vec::new()
    };
    let current_len = if existing.is_empty() {
        0
    } else {
        lock.read_bytes(path)?.len()
    };
    let mut next_bytes = serde_json::to_vec(head).map_err(|source| GraphStoreError::Serialize {
        path: path.to_path_buf(),
        source,
    })?;
    next_bytes.push(b'\n');
    if current_len.saturating_add(next_bytes.len()) > MAX_PERSISTED_JSON_BYTES {
        let tail = DurableHighWaterTail {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            record_count: 1,
            generation: head.generation,
            digest: head.digest.clone(),
        };
        let tail_bytes =
            serde_json::to_vec(&tail).map_err(|source| GraphStoreError::Serialize {
                path: tail_path.to_path_buf(),
                source,
            })?;
        let (rotation_manifest, rotation_data, rotation_tail) =
            high_water_rotation_paths(path, tail_path)?;
        let manifest = DurableJournalRotationManifest {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            sequence: head.generation,
            record_digest: head.digest.clone(),
        };
        lock.atomic_write_bytes(&rotation_data, &next_bytes)?;
        lock.atomic_write_bytes(&rotation_tail, &tail_bytes)?;
        lock.atomic_write_json(&rotation_manifest, &manifest)?;
        recover_high_water_rotation(lock, path, tail_path)?;
        return Ok(());
    }
    let tail = DurableHighWaterTail {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        record_count: u64::try_from(existing.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "local high-water record count overflow".to_string(),
            })?,
        generation: head.generation,
        digest: head.digest.clone(),
    };
    append_json_with_tail(lock, path, tail_path, head, &tail, tail.record_count)
}

fn append_manifest_path(
    lock: &DurableFileLock,
    data_path: &Path,
) -> Result<PathBuf, GraphStoreError> {
    if data_path.parent() != Some(lock.namespace.path.as_path()) {
        return Err(GraphStoreError::LockBinding {
            path: data_path.to_path_buf(),
            reason: "append manifest data path is outside the acquired namespace".to_string(),
        });
    }
    let name = data_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append manifest data path has no UTF-8 file name".to_string(),
        })?;
    Ok(lock
        .namespace
        .path
        .join(format!("{name}{APPEND_MANIFEST_SUFFIX}")))
}

fn clear_log_append_manifest(
    lock: &DurableFileLock,
    data_path: &Path,
) -> Result<(), GraphStoreError> {
    let manifest_path = append_manifest_path(lock, data_path)?;
    if fs::symlink_metadata(&manifest_path).is_ok() {
        lock.remove_file(&manifest_path)?;
    }
    Ok(())
}

fn read_optional_log_bytes(
    lock: &DurableFileLock,
    path: &Path,
) -> Result<Vec<u8>, GraphStoreError> {
    if fs::symlink_metadata(path).is_ok() {
        lock.read_bytes(path)
    } else {
        Ok(Vec::new())
    }
}

fn validate_append_manifest_paths(
    manifest: &DurableLogAppendManifest,
    data_path: &Path,
    tail_path: &Path,
) -> Result<(), GraphStoreError> {
    let data_name = data_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append manifest data path has no UTF-8 file name".to_string(),
        })?;
    let tail_name = tail_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append manifest tail path has no UTF-8 file name".to_string(),
        })?;
    if manifest.schema_version != GRAPH_STORE_SCHEMA_VERSION
        || manifest.data_name != data_name
        || manifest.tail_name != tail_name
        || manifest.record_count == 0
        || manifest.record_bytes.is_empty()
        || manifest.tail_bytes.is_empty()
        || manifest.record_bytes.last() != Some(&b'\n')
    {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: manifest.sequence,
            observed_generation: manifest.record_count,
        });
    }
    if manifest.record_bytes.len() > MAX_PERSISTED_JSON_BYTES
        || manifest.tail_bytes.len() > MAX_PERSISTED_JSON_BYTES
    {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: MAX_PERSISTED_JSON_BYTES,
        });
    }
    let expected_len = manifest
        .prior_data_len
        .checked_add(u64::try_from(manifest.record_bytes.len()).map_err(|_| {
            GraphStoreError::InvalidState {
                reason: "append record length overflow".to_string(),
            }
        })?)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append data length overflow".to_string(),
        })?;
    if manifest.expected_data_len != expected_len {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: expected_len,
            observed_generation: manifest.expected_data_len,
        });
    }
    if sha256_hex(&manifest.record_bytes) != manifest.record_digest {
        return Err(GraphStoreError::DigestMismatch {
            expected: manifest.record_digest.clone(),
            observed: sha256_hex(&manifest.record_bytes),
        });
    }
    Ok(())
}

/// Finish an append whose data record was durable but whose tail replacement
/// was interrupted.  This runs before any log/tail validation, so an
/// otherwise-valid restart cannot brick on the intentionally incomplete
/// two-file commit window.
pub(crate) fn recover_log_append(
    lock: &DurableFileLock,
    data_path: &Path,
    tail_path: &Path,
) -> Result<(), GraphStoreError> {
    let manifest_path = append_manifest_path(lock, data_path)?;
    if fs::symlink_metadata(&manifest_path).is_err() {
        return Ok(());
    }
    let manifest: DurableLogAppendManifest = lock.read_json(&manifest_path)?;
    validate_append_manifest_paths(&manifest, data_path, tail_path)?;
    let current = read_optional_log_bytes(lock, data_path)?;
    let current_len = u64::try_from(current.len()).map_err(|_| GraphStoreError::InvalidState {
        reason: "append data length overflow".to_string(),
    })?;
    let current_digest = sha256_hex(&current);
    let expected_data = if current_len == manifest.expected_data_len
        && current_digest == manifest.expected_data_digest
    {
        current
    } else if current_len == manifest.prior_data_len && current_digest == manifest.prior_data_digest
    {
        let mut completed = current;
        completed.extend_from_slice(&manifest.record_bytes);
        if sha256_hex(&completed) != manifest.expected_data_digest {
            return Err(GraphStoreError::DigestMismatch {
                expected: manifest.expected_data_digest,
                observed: sha256_hex(&completed),
            });
        }
        lock.atomic_write_bytes(data_path, &completed)?;
        completed
    } else {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: manifest.expected_data_len,
            observed_generation: current_len,
        });
    };
    if expected_data.len()
        != usize::try_from(manifest.expected_data_len).map_err(|_| {
            GraphStoreError::InvalidState {
                reason: "append data length overflow".to_string(),
            }
        })?
        || sha256_hex(&expected_data) != manifest.expected_data_digest
    {
        return Err(GraphStoreError::DigestMismatch {
            expected: manifest.expected_data_digest,
            observed: sha256_hex(&expected_data),
        });
    }
    lock.atomic_write_bytes(tail_path, &manifest.tail_bytes)?;
    lock.remove_file(&manifest_path)
}

fn append_json_with_tail<T: Serialize, U: Serialize>(
    lock: &DurableFileLock,
    data_path: &Path,
    tail_path: &Path,
    value: &T,
    tail: &U,
    record_count: u64,
) -> Result<(), GraphStoreError> {
    recover_log_append(lock, data_path, tail_path)?;
    let prior = read_optional_log_bytes(lock, data_path)?;
    if !prior.is_empty() && prior.last() != Some(&b'\n') {
        return Err(GraphStoreError::InvalidState {
            reason: "JSON log is not newline-delimited".to_string(),
        });
    }
    let mut record_bytes =
        serde_json::to_vec(value).map_err(|source| GraphStoreError::Serialize {
            path: data_path.to_path_buf(),
            source,
        })?;
    record_bytes.push(b'\n');
    let tail_bytes = serde_json::to_vec(tail).map_err(|source| GraphStoreError::Serialize {
        path: tail_path.to_path_buf(),
        source,
    })?;
    let data_name = data_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append data path has no UTF-8 file name".to_string(),
        })?;
    let tail_name = tail_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append tail path has no UTF-8 file name".to_string(),
        })?;
    let prior_data_len = u64::try_from(prior.len()).map_err(|_| GraphStoreError::InvalidState {
        reason: "append data length overflow".to_string(),
    })?;
    let expected_data_len = prior_data_len
        .checked_add(u64::try_from(record_bytes.len()).map_err(|_| {
            GraphStoreError::InvalidState {
                reason: "append record length overflow".to_string(),
            }
        })?)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "append data length overflow".to_string(),
        })?;
    if expected_data_len > MAX_PERSISTED_JSON_BYTES as u64
        || tail_bytes.len() > MAX_PERSISTED_JSON_BYTES
    {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: MAX_PERSISTED_JSON_BYTES,
        });
    }
    let mut expected_data = prior.clone();
    expected_data.extend_from_slice(&record_bytes);
    let manifest = DurableLogAppendManifest {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        data_name: data_name.to_string(),
        tail_name: tail_name.to_string(),
        prior_data_len,
        prior_data_digest: sha256_hex(&prior),
        expected_data_len,
        expected_data_digest: sha256_hex(&expected_data),
        record_count,
        sequence: record_count,
        record_digest: sha256_hex(&record_bytes),
        record_bytes,
        tail_bytes,
    };
    let manifest_path = append_manifest_path(lock, data_path)?;
    lock.atomic_write_json(&manifest_path, &manifest)?;
    lock.append_json(data_path, value)?;
    #[cfg(test)]
    maybe_fail_commit(&lock.namespace.path, CommitFailureBoundary::AppendTail)?;
    recover_log_append(lock, data_path, tail_path)
}

fn high_water_rotation_paths(
    path: &Path,
    tail_path: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), GraphStoreError> {
    let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
        reason: "local high-water path has no parent namespace".to_string(),
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "local high-water path has no file name".to_string(),
        })?;
    let tail_name = tail_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "local high-water tail path has no file name".to_string(),
        })?;
    Ok((
        parent.join(format!("{name}.rotate")),
        parent.join(format!("{name}.next")),
        parent.join(format!("{tail_name}.next")),
    ))
}

fn recover_high_water_rotation(
    lock: &DurableFileLock,
    path: &Path,
    tail_path: &Path,
) -> Result<(), GraphStoreError> {
    let (rotation_manifest, rotation_data, rotation_tail) =
        high_water_rotation_paths(path, tail_path)?;
    if fs::symlink_metadata(&rotation_manifest).is_err() {
        return Ok(());
    }
    let manifest: DurableJournalRotationManifest = lock.read_json(&rotation_manifest)?;
    let staged_records: Vec<DurableStateHead> = lock.read_json_log(&rotation_data)?;
    let staged_tail: DurableHighWaterTail = lock.read_json(&rotation_tail)?;
    let staged = staged_records
        .last()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "local high-water rotation stage is empty".to_string(),
        })?;
    if manifest.schema_version != GRAPH_STORE_SCHEMA_VERSION
        || staged_records.len() != 1
        || staged.generation != manifest.sequence
        || staged.digest != manifest.record_digest
        || staged_tail.schema_version != GRAPH_STORE_SCHEMA_VERSION
        || staged_tail.record_count != 1
        || staged_tail.generation != staged.generation
        || staged_tail.digest != staged.digest
    {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: manifest.sequence,
            observed_generation: staged.generation,
        });
    }
    let staged_data = lock.read_bytes(&rotation_data)?;
    let staged_tail_bytes = lock.read_bytes(&rotation_tail)?;
    lock.atomic_write_bytes(path, &staged_data)?;
    lock.atomic_write_bytes(tail_path, &staged_tail_bytes)?;
    lock.remove_file(&rotation_manifest)?;
    lock.remove_file(&rotation_data)?;
    lock.remove_file(&rotation_tail)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableTransactionManifest {
    schema_version: u32,
    transaction_id: String,
    base_generation: u64,
    base_digest: String,
}

fn transaction_stage_path(lock: &DurableFileLock, name: &str) -> PathBuf {
    lock.namespace.path.join(name)
}

pub(crate) fn stage_transaction(
    lock: &DurableFileLock,
    transaction_id: &str,
    base: &GraphStoreRevision,
    state_bytes: &[u8],
    head_bytes: &[u8],
    high_water_bytes: &[u8],
    high_water_tail_bytes: &[u8],
) -> Result<(), GraphStoreError> {
    let manifest = DurableTransactionManifest {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        transaction_id: transaction_id.to_string(),
        base_generation: base.generation,
        base_digest: base.digest.clone(),
    };
    lock.atomic_write_bytes(
        &transaction_stage_path(lock, GRAPH_STORE_TXN_STATE_FILE),
        state_bytes,
    )?;
    lock.atomic_write_bytes(
        &transaction_stage_path(lock, GRAPH_STORE_TXN_HEAD_FILE),
        head_bytes,
    )?;
    lock.atomic_write_bytes(
        &transaction_stage_path(lock, GRAPH_STORE_TXN_HIGH_WATER_FILE),
        high_water_bytes,
    )?;
    lock.atomic_write_bytes(
        &transaction_stage_path(lock, GRAPH_STORE_TXN_HIGH_WATER_TAIL_FILE),
        high_water_tail_bytes,
    )?;
    lock.atomic_write_json(
        &transaction_stage_path(lock, GRAPH_STORE_TXN_MANIFEST_FILE),
        &manifest,
    )
}

pub(crate) fn clear_transaction_stage(lock: &DurableFileLock) -> Result<(), GraphStoreError> {
    for name in [
        GRAPH_STORE_TXN_MANIFEST_FILE,
        GRAPH_STORE_TXN_STATE_FILE,
        GRAPH_STORE_TXN_HEAD_FILE,
        GRAPH_STORE_TXN_HIGH_WATER_FILE,
        GRAPH_STORE_TXN_HIGH_WATER_TAIL_FILE,
        GRAPH_STORE_TXN_ROLLBACK_FILE,
    ] {
        lock.remove_file(&transaction_stage_path(lock, name))?;
    }
    Ok(())
}

pub(crate) fn restore_transaction_stage(
    lock: &DurableFileLock,
    pending: &DurableExternalCommitRecord,
) -> Result<GraphStoreRevision, GraphStoreError> {
    let manifest_path = transaction_stage_path(lock, GRAPH_STORE_TXN_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Err(GraphStoreError::InvalidState {
            reason: "pending external intent has no transaction stage".to_string(),
        });
    }
    let manifest: DurableTransactionManifest = lock.read_json(&manifest_path)?;
    if manifest.schema_version != GRAPH_STORE_SCHEMA_VERSION
        || manifest.transaction_id != pending.transaction_id
        || manifest.base_generation.saturating_add(1) != pending.generation
    {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: manifest.base_generation.saturating_add(1),
            observed_generation: pending.generation,
        });
    }
    let state_bytes = lock.read_bytes(&transaction_stage_path(lock, GRAPH_STORE_TXN_STATE_FILE))?;
    let head_bytes = lock.read_bytes(&transaction_stage_path(lock, GRAPH_STORE_TXN_HEAD_FILE))?;
    let high_water_bytes = lock.read_bytes(&transaction_stage_path(
        lock,
        GRAPH_STORE_TXN_HIGH_WATER_FILE,
    ))?;
    let high_water_tail_bytes = lock.read_bytes(&transaction_stage_path(
        lock,
        GRAPH_STORE_TXN_HIGH_WATER_TAIL_FILE,
    ))?;
    // A high-water append manifest belongs to the candidate transaction.  A
    // rollback must discard it before restoring the base tuple; otherwise a
    // later ordinary read could replay the rejected candidate after the base
    // tail was restored.
    clear_log_append_manifest(lock, &lock.namespace.path.join(GRAPH_STORE_HIGH_WATER_FILE))?;
    let rollback_path = transaction_stage_path(lock, GRAPH_STORE_TXN_ROLLBACK_FILE);
    let mut rollback = if rollback_path.exists() {
        lock.read_json::<DurableRollbackManifest>(&rollback_path)?
    } else {
        let manifest = DurableRollbackManifest {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            transaction_id: pending.transaction_id.clone(),
            base_generation: manifest.base_generation,
            base_digest: manifest.base_digest.clone(),
            next_component: 0,
        };
        lock.atomic_write_json(&rollback_path, &manifest)?;
        manifest
    };
    if rollback.schema_version != GRAPH_STORE_SCHEMA_VERSION
        || rollback.transaction_id != pending.transaction_id
        || rollback.base_generation != manifest.base_generation
        || rollback.base_digest != manifest.base_digest
        || rollback.next_component > 4
    {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: manifest.base_generation,
            observed_generation: rollback.base_generation,
        });
    }
    // The staged bytes are restored through the same descriptor-relative,
    // bounded atomic writer as normal commits.  The rollback pointer is
    // durable before the first replacement and advances after each verified
    // replacement, so a crash at any boundary is replayed idempotently.
    let components = [
        (GRAPH_STORE_STATE_FILE, state_bytes.as_slice()),
        (GRAPH_STORE_ANCHOR_FILE, head_bytes.as_slice()),
        (GRAPH_STORE_HIGH_WATER_FILE, high_water_bytes.as_slice()),
        (
            GRAPH_STORE_HIGH_WATER_TAIL_FILE,
            high_water_tail_bytes.as_slice(),
        ),
    ];
    for (index, (name, bytes)) in components.into_iter().enumerate() {
        if rollback.next_component
            > u8::try_from(index).map_err(|_| GraphStoreError::InvalidState {
                reason: "rollback component index overflow".to_string(),
            })?
        {
            continue;
        }
        let target = lock.namespace.path.join(name);
        lock.atomic_write_bytes(&target, bytes)?;
        if lock.read_bytes(&target)? != bytes {
            return Err(GraphStoreError::InvalidState {
                reason: "rollback replacement changed staged bytes".to_string(),
            });
        }
        #[cfg(test)]
        maybe_fail_commit(
            &lock.namespace.path,
            match index {
                0 => CommitFailureBoundary::RollbackState,
                1 => CommitFailureBoundary::RollbackHead,
                2 => CommitFailureBoundary::RollbackHighWater,
                _ => CommitFailureBoundary::RollbackHighWaterTail,
            },
        )?;
        rollback.next_component =
            u8::try_from(index + 1).map_err(|_| GraphStoreError::InvalidState {
                reason: "rollback component index overflow".to_string(),
            })?;
        lock.atomic_write_json(&rollback_path, &rollback)?;
    }
    let restored_state_bytes =
        lock.read_bytes(&lock.namespace.path.join(GRAPH_STORE_STATE_FILE))?;
    let restored_head_bytes =
        lock.read_bytes(&lock.namespace.path.join(GRAPH_STORE_ANCHOR_FILE))?;
    let restored_high_water_bytes =
        lock.read_bytes(&lock.namespace.path.join(GRAPH_STORE_HIGH_WATER_FILE))?;
    let restored_high_water_tail_bytes =
        lock.read_bytes(&lock.namespace.path.join(GRAPH_STORE_HIGH_WATER_TAIL_FILE))?;
    if restored_state_bytes != state_bytes
        || restored_head_bytes != head_bytes
        || restored_high_water_bytes != high_water_bytes
        || restored_high_water_tail_bytes != high_water_tail_bytes
    {
        return Err(GraphStoreError::InvalidState {
            reason: "restored transaction tuple changed during persistence".to_string(),
        });
    }
    let state_envelope: serde_json::Value =
        serde_json::from_slice(&restored_state_bytes).map_err(|source| GraphStoreError::Parse {
            path: lock.namespace.path.join(GRAPH_STORE_STATE_FILE),
            source,
        })?;
    let state_value = state_envelope
        .get("state")
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "restored state envelope has no state".to_string(),
        })?;
    let observed_generation = state_value
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "restored state has no generation".to_string(),
        })?;
    let observed_digest = state_envelope
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "restored state envelope has no digest".to_string(),
        })?;
    let computed_digest = sha256_hex(&canonical_json_bytes(state_value).map_err(|error| {
        GraphStoreError::Canonicalization {
            reason: error.to_string(),
        }
    })?);
    if observed_generation != manifest.base_generation
        || observed_digest != manifest.base_digest
        || computed_digest != manifest.base_digest
    {
        return Err(GraphStoreError::DigestMismatch {
            expected: manifest.base_digest,
            observed: observed_digest.to_string(),
        });
    }
    let restored_head: DurableStateHead =
        serde_json::from_slice(&restored_head_bytes).map_err(|source| GraphStoreError::Parse {
            path: lock.namespace.path.join(GRAPH_STORE_ANCHOR_FILE),
            source,
        })?;
    if restored_head.generation != manifest.base_generation
        || restored_head.digest != manifest.base_digest
    {
        return Err(GraphStoreError::AnchorMismatch {
            expected_generation: manifest.base_generation,
            expected_digest: manifest.base_digest,
            observed_generation: restored_head.generation,
            observed_digest: restored_head.digest,
        });
    }
    let restored_high_water = read_high_water(
        lock,
        &lock.namespace.path.join(GRAPH_STORE_HIGH_WATER_FILE),
        &lock.namespace.path.join(GRAPH_STORE_HIGH_WATER_TAIL_FILE),
    )?;
    if restored_high_water.generation != manifest.base_generation
        || restored_high_water.digest != manifest.base_digest
    {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: manifest.base_generation,
            observed_generation: restored_high_water.generation,
        });
    }
    clear_transaction_stage(lock)?;
    Ok(GraphStoreRevision::new(
        manifest.base_generation,
        manifest.base_digest,
    ))
}

/// The sibling anchor is a tiny write-ahead journal, rather than a second
/// overwriteable copy of the state head.  Sequence and predecessor digest are
/// signed so a valid older prefix (or a prefix with its first record removed)
/// cannot be mistaken for the current external high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalCommitPhase {
    Commit,
    Intent,
    Abort,
    Checkpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableExternalCommitRecord {
    pub schema_version: u32,
    pub state_kind: String,
    pub stream_id: String,
    pub generation: u64,
    pub digest: String,
    pub transaction_id: String,
    pub sequence: u64,
    pub phase: ExternalCommitPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_record_digest: Option<String>,
    pub record_digest: String,
    pub lock_generation: String,
    pub lock_identity: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableExternalCommitMaterial<'a> {
    schema_version: u32,
    state_kind: &'a str,
    stream_id: &'a str,
    generation: u64,
    digest: &'a str,
    transaction_id: &'a str,
    sequence: u64,
    phase: ExternalCommitPhase,
    predecessor_record_digest: &'a Option<String>,
    lock_generation: &'a str,
    lock_identity: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalJournalState {
    pub committed: DurableExternalCommitRecord,
    pub pending: Option<DurableExternalCommitRecord>,
    pub last_sequence: u64,
    pub last_record_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableJournalTail {
    schema_version: u32,
    sequence: u64,
    record_count: u64,
    record_digest: String,
}

/// A durable decision record for the two-file append protocol.  The data log
/// is written and synced before its overwriteable tail is replaced.  If the
/// process stops in that window, this manifest lets the next opener finish the
/// append (or refuse a partial/tampered append) before it validates the tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableLogAppendManifest {
    schema_version: u32,
    data_name: String,
    tail_name: String,
    prior_data_len: u64,
    prior_data_digest: String,
    expected_data_len: u64,
    expected_data_digest: String,
    record_count: u64,
    sequence: u64,
    record_digest: String,
    record_bytes: Vec<u8>,
    tail_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableRollbackManifest {
    schema_version: u32,
    transaction_id: String,
    base_generation: u64,
    base_digest: String,
    next_component: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableJournalRotationManifest {
    schema_version: u32,
    sequence: u64,
    record_digest: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_external_commit_record(
    state_kind: &str,
    stream_id: &str,
    generation: u64,
    digest: &str,
    sequence: u64,
    phase: ExternalCommitPhase,
    predecessor_record_digest: Option<String>,
    lock_generation: &str,
    lock_identity: &str,
    signer: &Keypair,
) -> Result<DurableExternalCommitRecord, GraphStoreError> {
    if state_kind.trim().is_empty() || stream_id.trim().is_empty() || digest.trim().is_empty() {
        return Err(GraphStoreError::InvalidState {
            reason: "external commit record identity is empty".to_string(),
        });
    }
    validate_lock_generation(lock_generation)?;
    validate_lock_identity(lock_identity)?;
    let transaction_id = sha256_hex(
        &canonical_json_bytes(&(state_kind, stream_id, generation, digest)).map_err(|error| {
            GraphStoreError::Canonicalization {
                reason: error.to_string(),
            }
        })?,
    );
    let material = DurableExternalCommitMaterial {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind,
        stream_id,
        generation,
        digest,
        transaction_id: &transaction_id,
        sequence,
        phase,
        predecessor_record_digest: &predecessor_record_digest,
        lock_generation,
        lock_identity,
    };
    let bytes =
        canonical_json_bytes(&material).map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    let record_digest = sha256_hex(&bytes);
    Ok(DurableExternalCommitRecord {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind: state_kind.to_string(),
        stream_id: stream_id.to_string(),
        generation,
        digest: digest.to_string(),
        transaction_id,
        sequence,
        phase,
        predecessor_record_digest,
        record_digest,
        lock_generation: lock_generation.to_string(),
        lock_identity: lock_identity.to_string(),
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: sha256_hex(signer.public_key().as_bytes()),
            public_key_hex: signer.public_key().to_hex(),
            signature_hex: signer.sign(&bytes).to_hex(),
        },
    })
}

fn verify_external_commit_record(
    record: &DurableExternalCommitRecord,
    state_kind: &str,
    stream_id: &str,
    expected_signer: &AgentId,
    expected_lock_generation: &str,
    expected_lock_identity: &str,
) -> Result<(), GraphStoreError> {
    if record.schema_version != GRAPH_STORE_SCHEMA_VERSION {
        return Err(GraphStoreError::UnsupportedSchema(record.schema_version));
    }
    if record.state_kind != state_kind || record.stream_id != stream_id {
        return Err(GraphStoreError::InvalidState {
            reason: "external commit record stream identity mismatch".to_string(),
        });
    }
    if record.lock_generation != expected_lock_generation
        || record.lock_identity != expected_lock_identity
    {
        return Err(GraphStoreError::LockBinding {
            path: PathBuf::from(stream_id),
            reason: "external commit record is bound to another lock".to_string(),
        });
    }
    validate_lock_generation(&record.lock_generation)?;
    validate_lock_identity(&record.lock_identity)?;
    let transaction_id = sha256_hex(
        &canonical_json_bytes(&(
            state_kind,
            stream_id,
            record.generation,
            record.digest.as_str(),
        ))
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?,
    );
    if record.transaction_id != transaction_id {
        return Err(GraphStoreError::DigestMismatch {
            expected: record.transaction_id.clone(),
            observed: transaction_id,
        });
    }
    let material = DurableExternalCommitMaterial {
        schema_version: record.schema_version,
        state_kind: &record.state_kind,
        stream_id: &record.stream_id,
        generation: record.generation,
        digest: &record.digest,
        transaction_id: &record.transaction_id,
        sequence: record.sequence,
        phase: record.phase,
        predecessor_record_digest: &record.predecessor_record_digest,
        lock_generation: &record.lock_generation,
        lock_identity: &record.lock_identity,
    };
    let bytes =
        canonical_json_bytes(&material).map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    let digest = sha256_hex(&bytes);
    if digest != record.record_digest {
        return Err(GraphStoreError::DigestMismatch {
            expected: record.record_digest.clone(),
            observed: digest,
        });
    }
    verify_detached_signature(&bytes, &record.signature).map_err(|error| {
        GraphStoreError::InvalidSignature {
            reason: error.to_string(),
        }
    })?;
    let observed = AgentId::from_public_key_hex(&record.signature.public_key_hex);
    if &observed != expected_signer {
        return Err(GraphStoreError::SignerMismatch {
            expected: expected_signer.clone(),
            observed,
        });
    }
    Ok(())
}

pub(crate) fn verify_external_journal(
    records: &[DurableExternalCommitRecord],
    state_kind: &str,
    stream_id: &str,
    expected_signer: &AgentId,
    expected_lock_generation: &str,
    expected_lock_identity: &str,
) -> Result<ExternalJournalState, GraphStoreError> {
    let first = records
        .first()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "external commit journal is empty".to_string(),
        })?;
    let mut committed_generation = first.generation;
    let mut pending_record: Option<&DurableExternalCommitRecord> = None;
    for (index, record) in records.iter().enumerate() {
        verify_external_commit_record(
            record,
            state_kind,
            stream_id,
            expected_signer,
            expected_lock_generation,
            expected_lock_identity,
        )?;
        let expected_sequence = first
            .sequence
            .checked_add(
                u64::try_from(index).map_err(|_| GraphStoreError::InvalidState {
                    reason: "external commit journal sequence overflow".to_string(),
                })?,
            )
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "external commit journal sequence overflow".to_string(),
            })?;
        if record.sequence != expected_sequence
            || record.predecessor_record_digest
                != records
                    .get(index.wrapping_sub(1))
                    .map(|prior| prior.record_digest.clone())
        {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation: expected_sequence,
                observed_generation: record.sequence,
            });
        }
        if index == 0 {
            if (record.phase != ExternalCommitPhase::Commit
                && record.phase != ExternalCommitPhase::Checkpoint)
                || (record.phase == ExternalCommitPhase::Commit && record.generation != 0)
                || record.predecessor_record_digest.is_some()
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "external journal must begin with committed generation zero"
                        .to_string(),
                });
            }
        } else {
            let prior = &records[index - 1];
            match record.phase {
                ExternalCommitPhase::Intent => {
                    if pending_record.is_some()
                        || record.generation != committed_generation.saturating_add(1)
                    {
                        return Err(GraphStoreError::ReplayDetected {
                            expected_generation: committed_generation.saturating_add(1),
                            observed_generation: record.generation,
                        });
                    }
                    pending_record = Some(record);
                }
                ExternalCommitPhase::Commit | ExternalCommitPhase::Abort => {
                    let intent = pending_record.ok_or_else(|| GraphStoreError::ReplayDetected {
                        expected_generation: committed_generation.saturating_add(1),
                        observed_generation: record.generation,
                    })?;
                    if prior.phase != ExternalCommitPhase::Intent
                        || record.generation != intent.generation
                        || (record.phase == ExternalCommitPhase::Commit
                            && record.digest != intent.digest)
                    {
                        return Err(GraphStoreError::ReplayDetected {
                            expected_generation: intent.generation,
                            observed_generation: record.generation,
                        });
                    }
                    if record.phase == ExternalCommitPhase::Commit {
                        committed_generation = record.generation;
                    }
                    pending_record = None;
                }
                ExternalCommitPhase::Checkpoint => {
                    return Err(GraphStoreError::InvalidState {
                        reason: "external checkpoint is only valid as a journal prefix".to_string(),
                    });
                }
            }
        }
    }
    // A valid prefix ending in an intent is a recoverable write-ahead record;
    // any root state other than that intent's generation is refused by the
    // root validation below.
    let pending = pending_record.cloned();
    let committed = records
        .iter()
        .rev()
        .find(|record| {
            record.phase == ExternalCommitPhase::Commit
                || record.phase == ExternalCommitPhase::Checkpoint
        })
        .cloned()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "external journal has no committed record".to_string(),
        })?;
    let last = records
        .last()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "external commit journal is empty".to_string(),
        })?;
    Ok(ExternalJournalState {
        committed,
        pending,
        last_sequence: last.sequence,
        last_record_digest: last.record_digest.clone(),
    })
}

pub(crate) fn validate_external_journal_against_state(
    journal: &ExternalJournalState,
    state_revision: &GraphStoreRevision,
) -> Result<(), GraphStoreError> {
    if let Some(intent) = &journal.pending {
        if intent.generation == state_revision.generation && intent.digest != state_revision.digest
        {
            return Err(GraphStoreError::AnchorMismatch {
                expected_generation: intent.generation,
                expected_digest: intent.digest.clone(),
                observed_generation: state_revision.generation,
                observed_digest: state_revision.digest.clone(),
            });
        }
        if intent.generation != state_revision.generation {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation: intent.generation,
                observed_generation: state_revision.generation,
            });
        }
        if journal.committed.generation + 1 != state_revision.generation {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation: journal.committed.generation + 1,
                observed_generation: state_revision.generation,
            });
        }
    } else if journal.committed.generation == state_revision.generation
        && journal.committed.digest != state_revision.digest
    {
        return Err(GraphStoreError::AnchorMismatch {
            expected_generation: journal.committed.generation,
            expected_digest: journal.committed.digest.clone(),
            observed_generation: state_revision.generation,
            observed_digest: state_revision.digest.clone(),
        });
    } else if journal.committed.generation != state_revision.generation {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: journal.committed.generation,
            observed_generation: state_revision.generation,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn recover_external_journal(
    anchor: &DurableMonotonicAnchor,
    root_lock: &DurableFileLock,
    state_kind: &str,
    stream_id: &str,
    signer: &Keypair,
    expected_signer: &AgentId,
    lock_generation: &str,
    lock_identity: &str,
    _state_revision: &GraphStoreRevision,
) -> Result<(ExternalJournalState, bool), GraphStoreError> {
    let mut records = anchor.read_records()?;
    anchor.validate_tail(&records)?;
    let mut journal = verify_external_journal(
        &records,
        state_kind,
        stream_id,
        expected_signer,
        lock_generation,
        lock_identity,
    )?;
    // An intent is written before the root state.  If the process dies in
    // that window, the intent is explicitly aborted on the next open.  This
    // preserves the append-only chain and makes the interrupted operation
    // unavailable rather than silently publishing an uncommitted state.
    let restored_base = if let Some(intent) = &journal.pending {
        let restored = restore_transaction_stage(root_lock, intent)?;
        let abort = sign_external_commit_record(
            state_kind,
            stream_id,
            intent.generation,
            &intent.digest,
            journal
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "external journal sequence overflow".to_string(),
                })?,
            ExternalCommitPhase::Abort,
            Some(journal.last_record_digest.clone()),
            lock_generation,
            lock_identity,
            signer,
        )?;
        anchor.append_external(&abort)?;
        records = anchor.read_records()?;
        anchor.validate_tail(&records)?;
        journal = verify_external_journal(
            &records,
            state_kind,
            stream_id,
            expected_signer,
            lock_generation,
            lock_identity,
        )?;
        Some(restored)
    } else {
        None
    };
    if let Some(base) = restored_base.as_ref() {
        validate_external_journal_against_state(&journal, base)?;
    }
    Ok((journal, restored_base.is_some()))
}

pub(crate) fn validate_high_water_against_revisions(
    high_water: &GraphStoreRevision,
    anchor: &GraphStoreRevision,
    persisted: &GraphStoreRevision,
    persisted_predecessor_digest: Option<&str>,
) -> Result<(), GraphStoreError> {
    high_water.validate()?;
    if high_water.generation > persisted.generation {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: high_water.generation,
            observed_generation: persisted.generation,
        });
    }
    if high_water.generation == persisted.generation && high_water.digest != persisted.digest {
        return Err(GraphStoreError::AnchorMismatch {
            expected_generation: high_water.generation,
            expected_digest: high_water.digest.clone(),
            observed_generation: persisted.generation,
            observed_digest: persisted.digest.clone(),
        });
    }
    if high_water.generation > anchor.generation {
        let expected_generation =
            anchor
                .generation
                .checked_add(1)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "anchor generation overflow".to_string(),
                })?;
        if high_water.generation != expected_generation
            || persisted.generation != high_water.generation
            || persisted_predecessor_digest != Some(anchor.digest.as_str())
        {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation,
                observed_generation: high_water.generation,
            });
        }
    }
    if high_water.generation == anchor.generation && high_water.digest != anchor.digest {
        return Err(GraphStoreError::AnchorMismatch {
            expected_generation: high_water.generation,
            expected_digest: high_water.digest.clone(),
            observed_generation: anchor.generation,
            observed_digest: anchor.digest.clone(),
        });
    }
    if high_water.generation < anchor.generation || high_water.generation < persisted.generation {
        let expected_generation =
            high_water
                .generation
                .checked_add(1)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "high-water generation overflow".to_string(),
                })?;
        if anchor.generation > expected_generation || persisted.generation > expected_generation {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation,
                observed_generation: anchor.generation.max(persisted.generation),
            });
        }
        if persisted_predecessor_digest != Some(high_water.digest.as_str()) {
            return Err(GraphStoreError::AnchorMismatch {
                expected_generation: high_water.generation,
                expected_digest: high_water.digest.clone(),
                observed_generation: persisted.generation,
                observed_digest: persisted.digest.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableStateHeadMaterial<'a> {
    schema_version: u32,
    state_kind: &'a str,
    stream_id: &'a str,
    generation: u64,
    digest: &'a str,
    lock_generation: &'a str,
    lock_identity: &'a str,
}

pub(crate) fn sign_state_head(
    state_kind: &str,
    stream_id: &str,
    revision: &GraphStoreRevision,
    lock_generation: &str,
    lock_identity: &str,
    signer: &Keypair,
) -> Result<DurableStateHead, GraphStoreError> {
    revision.validate()?;
    if state_kind.trim().is_empty() || stream_id.trim().is_empty() {
        return Err(GraphStoreError::InvalidState {
            reason: "state head kind and stream ID must be non-empty".to_string(),
        });
    }
    validate_lock_generation(lock_generation)?;
    validate_lock_identity(lock_identity)?;
    let material = DurableStateHeadMaterial {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind,
        stream_id,
        generation: revision.generation,
        digest: &revision.digest,
        lock_generation,
        lock_identity,
    };
    let bytes =
        canonical_json_bytes(&material).map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    Ok(DurableStateHead {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind: state_kind.to_string(),
        stream_id: stream_id.to_string(),
        generation: revision.generation,
        digest: revision.digest.clone(),
        lock_generation: lock_generation.to_string(),
        lock_identity: lock_identity.to_string(),
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: sha256_hex(signer.public_key().as_bytes()),
            public_key_hex: signer.public_key().to_hex(),
            signature_hex: signer.sign(&bytes).to_hex(),
        },
    })
}

pub(crate) fn verify_state_head(
    head: &DurableStateHead,
    state_kind: &str,
    stream_id: &str,
    expected_signer: &AgentId,
    expected_lock_generation: &str,
    expected_lock_identity: &str,
) -> Result<GraphStoreRevision, GraphStoreError> {
    if head.schema_version != GRAPH_STORE_SCHEMA_VERSION {
        return Err(GraphStoreError::UnsupportedSchema(head.schema_version));
    }
    if head.state_kind != state_kind || head.stream_id != stream_id {
        return Err(GraphStoreError::InvalidState {
            reason: "state head kind or stream ID does not match the store".to_string(),
        });
    }
    validate_lock_generation(expected_lock_generation)?;
    validate_lock_identity(expected_lock_identity)?;
    if head.lock_generation != expected_lock_generation {
        return Err(GraphStoreError::LockBinding {
            path: PathBuf::from(stream_id),
            reason: "signed state head is bound to another lock generation".to_string(),
        });
    }
    if head.lock_identity != expected_lock_identity {
        return Err(GraphStoreError::LockBinding {
            path: PathBuf::from(stream_id),
            reason: "signed state head is bound to another lock inode".to_string(),
        });
    }
    let revision = GraphStoreRevision::new(head.generation, head.digest.clone());
    revision.validate()?;
    let material = DurableStateHeadMaterial {
        schema_version: head.schema_version,
        state_kind: &head.state_kind,
        stream_id: &head.stream_id,
        generation: head.generation,
        digest: &head.digest,
        lock_generation: &head.lock_generation,
        lock_identity: &head.lock_identity,
    };
    let bytes =
        canonical_json_bytes(&material).map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    verify_detached_signature(&bytes, &head.signature).map_err(|error| {
        GraphStoreError::InvalidSignature {
            reason: error.to_string(),
        }
    })?;
    let observed = AgentId::from_public_key_hex(&head.signature.public_key_hex);
    if &observed != expected_signer {
        return Err(GraphStoreError::SignerMismatch {
            expected: expected_signer.clone(),
            observed,
        });
    }
    Ok(revision)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_state_head(
    anchor_path: &Path,
    writer: &DurableFileLock,
    anchored: &GraphStoreRevision,
    persisted: &GraphStoreRevision,
    persisted_predecessor_digest: Option<&str>,
    state_kind: &str,
    stream_id: &str,
    lock_generation: &str,
    lock_identity: &str,
    signer: &Keypair,
) -> Result<(), GraphStoreError> {
    if persisted.generation < anchored.generation {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: anchored.generation,
            observed_generation: persisted.generation,
        });
    }
    if persisted.generation == anchored.generation {
        if persisted.digest != anchored.digest {
            return Err(GraphStoreError::AnchorMismatch {
                expected_generation: anchored.generation,
                expected_digest: anchored.digest.clone(),
                observed_generation: persisted.generation,
                observed_digest: persisted.digest.clone(),
            });
        }
        return Ok(());
    }

    if persisted.generation != anchored.generation.saturating_add(1) {
        return Err(GraphStoreError::ReplayDetected {
            expected_generation: anchored.generation.saturating_add(1),
            observed_generation: persisted.generation,
        });
    }
    if persisted_predecessor_digest != Some(anchored.digest.as_str()) {
        return Err(GraphStoreError::AnchorMismatch {
            expected_generation: anchored.generation,
            expected_digest: anchored.digest.clone(),
            observed_generation: persisted.generation,
            observed_digest: persisted.digest.clone(),
        });
    }

    // A crash after the state rename but before the head rename leaves a
    // valid state one generation ahead.  Promote that state only after all
    // signatures and limits have been checked; never move the head backwards.
    let head = sign_state_head(
        state_kind,
        stream_id,
        persisted,
        lock_generation,
        lock_identity,
        signer,
    )?;
    writer.atomic_write_json(anchor_path, &head)
}

impl SignedGraphStoreState {
    fn revision(&self) -> Result<GraphStoreRevision, GraphStoreError> {
        Ok(GraphStoreRevision::new(
            self.state.generation,
            self.digest.clone(),
        ))
    }

    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
        Ok(GraphStoreSnapshot {
            state: self.state.clone(),
            revision: self.revision()?,
        })
    }
}

fn sign_state(
    state: GraphStoreState,
    signer: &Keypair,
    limits: &GraphResourceLimits,
) -> Result<SignedGraphStoreState, GraphStoreError> {
    state.validate_with_limits(limits)?;
    let digest = state.digest()?;
    let bytes = canonical_json_bytes(&GraphStateSigningMaterial {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind: GRAPH_STORE_STATE_KIND,
        stream_id: &state.graph_id,
        generation: state.generation,
        digest: &digest,
        state: &state,
    })
    .map_err(|error| GraphStoreError::Canonicalization {
        reason: error.to_string(),
    })?;
    if bytes.len() > persisted_json_limit() {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: persisted_json_limit(),
        });
    }
    let public_key_hex = signer.public_key().to_hex();
    let signature = signer.sign(&bytes);
    let envelope = SignedGraphStoreState {
        state,
        digest,
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: sha256_hex(signer.public_key().as_bytes()),
            public_key_hex,
            signature_hex: signature.to_hex(),
        },
    };
    let persisted = serde_json::to_vec(&envelope).map_err(|error| GraphStoreError::Serialize {
        path: PathBuf::from(GRAPH_STORE_STATE_FILE),
        source: error,
    })?;
    if persisted.len() > persisted_json_limit() {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: persisted_json_limit(),
        });
    }
    Ok(envelope)
}

fn verify_state(
    envelope: &SignedGraphStoreState,
    expected_graph_id: &GraphId,
    expected_signer: &AgentId,
    limits: &GraphResourceLimits,
    scheduler_policy: &SchedulerBudgetPolicy,
) -> Result<(), GraphStoreError> {
    envelope.state.validate_with_limits(limits)?;
    if let Some(budget) = &envelope.state.scheduler_budget {
        scheduler_policy.validate_budget(budget)?;
    }
    if envelope.state.graph_id != *expected_graph_id {
        return Err(GraphStoreError::InvalidState {
            reason: "persisted graph ID does not match the configured stream".to_string(),
        });
    }
    let computed_digest = envelope.state.digest()?;
    if computed_digest != envelope.digest {
        return Err(GraphStoreError::DigestMismatch {
            expected: envelope.digest.clone(),
            observed: computed_digest,
        });
    }
    let bytes = canonical_json_bytes(&GraphStateSigningMaterial {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind: GRAPH_STORE_STATE_KIND,
        stream_id: &envelope.state.graph_id,
        generation: envelope.state.generation,
        digest: &envelope.digest,
        state: &envelope.state,
    })
    .map_err(|error| GraphStoreError::Canonicalization {
        reason: error.to_string(),
    })?;
    verify_detached_signature(&bytes, &envelope.signature).map_err(|error| {
        GraphStoreError::InvalidSignature {
            reason: error.to_string(),
        }
    })?;
    let derived = AgentId::from_public_key_hex(&envelope.signature.public_key_hex);
    if &derived != expected_signer {
        return Err(GraphStoreError::SignerMismatch {
            expected: expected_signer.clone(),
            observed: derived,
        });
    }
    Ok(())
}

fn check_expected(
    actual: &GraphStoreRevision,
    expected: Option<&GraphStoreRevision>,
) -> Result<(), GraphStoreError> {
    if let Some(expected) = expected {
        expected.validate()?;
        if expected != actual {
            return Err(GraphStoreError::StalePredecessor {
                expected_generation: expected.generation,
                expected_digest: expected.digest.clone(),
                observed_generation: actual.generation,
                observed_digest: actual.digest.clone(),
            });
        }
    }
    Ok(())
}

struct AuthenticatedStateRead {
    envelope: SignedGraphStoreState,
}

fn parse_state_value<T: serde::de::DeserializeOwned>(
    path: &Path,
    value: serde_json::Value,
) -> Result<T, GraphStoreError> {
    serde_json::from_value(value).map_err(|source| GraphStoreError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Read and authenticate a state file without allowing current-state serde
/// defaults to participate in legacy signature verification. A marker is the
/// wire discriminator; a positive marker selects current parsing, while a
/// marker-less (or explicitly zero-marked) object is parsed as the exact
/// legacy shape unless it carries a non-default configured `limits` field.
/// That sole current-v0 exception is safe to distinguish because Plan 03 could
/// not emit the field and its signed canonical bytes include it.
fn read_authenticated_state(
    lock: &DurableFileLock,
    state_path: &Path,
    anchor_path: &Path,
    high_water_path: &Path,
    high_water_tail_path: &Path,
    signer_id: &AgentId,
    scheduler_policy: &SchedulerBudgetPolicy,
) -> Result<AuthenticatedStateRead, GraphStoreError> {
    let raw: serde_json::Value = lock.read_json(state_path)?;
    let state_object = raw
        .get("state")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "persisted state envelope has no state object".to_string(),
        })?;
    let has_nonlegacy_marker = state_object
        .get("migration_marker")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|marker| marker > u64::from(GRAPH_STATE_MIGRATION_LEGACY));
    let has_limits = state_object.contains_key("limits");

    if has_nonlegacy_marker {
        let envelope: SignedGraphStoreState = parse_state_value(state_path, raw.clone())?;
        let graph_id = envelope.state.graph_id.clone();
        let limits = envelope.state.graph.limits.clone();
        verify_state(&envelope, &graph_id, signer_id, &limits, scheduler_policy)?;
        return Ok(AuthenticatedStateRead { envelope });
    }
    if has_limits {
        let candidate: SignedGraphStoreState = parse_state_value(state_path, raw.clone())?;
        if candidate.state.limits != GraphResourceLimits::default() {
            let graph_id = candidate.state.graph_id.clone();
            let limits = candidate.state.graph.limits.clone();
            verify_state(&candidate, &graph_id, signer_id, &limits, scheduler_policy)?;
            return Ok(AuthenticatedStateRead {
                envelope: candidate,
            });
        }
    }

    // No marker and no non-default limits is the exact legacy branch. Any
    // newly introduced field (including an empty map) is rejected by the
    // deny-unknown-fields legacy parser instead of being silently normalized.
    let legacy: LegacySignedGraphStoreState = parse_state_value(state_path, raw)?;
    let state_bytes = legacy.state.canonical_bytes()?;
    let computed_digest = sha256_hex(&state_bytes);
    if computed_digest != legacy.digest {
        return Err(GraphStoreError::DigestMismatch {
            expected: legacy.digest,
            observed: computed_digest,
        });
    }
    let signing_bytes = canonical_json_bytes(&LegacyGraphStateSigningMaterial {
        schema_version: GRAPH_STORE_SCHEMA_VERSION,
        state_kind: GRAPH_STORE_STATE_KIND,
        stream_id: &legacy.state.graph_id,
        generation: legacy.state.generation,
        digest: &legacy.digest,
        state: &legacy.state,
    })
    .map_err(|error| GraphStoreError::Canonicalization {
        reason: error.to_string(),
    })?;
    verify_detached_signature(&signing_bytes, &legacy.signature).map_err(|error| {
        GraphStoreError::InvalidSignature {
            reason: error.to_string(),
        }
    })?;
    let observed = AgentId::from_public_key_hex(&legacy.signature.public_key_hex);
    if &observed != signer_id {
        return Err(GraphStoreError::SignerMismatch {
            expected: signer_id.clone(),
            observed,
        });
    }

    // Authenticate both local high-water replicas against the *legacy*
    // revision before constructing a current GraphStoreState with defaults.
    let persisted_revision = legacy.state.revision(legacy.digest.clone());
    let head: DurableStateHead = lock.read_json(anchor_path)?;
    let high_water = read_high_water(lock, high_water_path, high_water_tail_path)?;
    let head_revision = verify_state_head(
        &head,
        GRAPH_STORE_STATE_KIND,
        legacy.state.graph_id.as_str(),
        signer_id,
        lock.generation(),
        &lock.identity_token(),
    )?;
    let high_water_revision = verify_state_head(
        &high_water,
        GRAPH_STORE_STATE_KIND,
        legacy.state.graph_id.as_str(),
        signer_id,
        lock.generation(),
        &lock.identity_token(),
    )?;
    validate_high_water_against_revisions(
        &high_water_revision,
        &head_revision,
        &persisted_revision,
        legacy.state.predecessor_digest.as_deref(),
    )?;

    let LegacySignedGraphStoreState {
        state: legacy_state,
        digest: legacy_digest,
        signature: legacy_signature,
    } = legacy;
    let normalized = legacy_state.into_current();
    // Validate only after the signature, digest, and high-water proofs above;
    // this call is the first point at which defaults become visible.
    normalized.validate_with_limits(&normalized.graph.limits)?;
    Ok(AuthenticatedStateRead {
        envelope: SignedGraphStoreState {
            state: normalized,
            digest: legacy_digest,
            signature: legacy_signature,
        },
    })
}

/// Validate a direct reasoning CAS against the signed predecessor.  Ordinary
/// task mutations still use the existing task APIs; the only task replacement
/// admitted here is a terminal publication accompanied by its descriptor and
/// outbox entry.  This keeps the one-transition reasoning boundary while
/// retaining the durable monotonic fences from Plan 03.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialDecisionAdmission<'a> {
    Reject,
    AuthenticatedCoordinator(&'a AgentId),
}

fn validate_reasoning_cas_transition(
    current: &GraphStoreState,
    candidate: &GraphStoreState,
    limits: &GraphResourceLimits,
    scheduler_policy: &SchedulerBudgetPolicy,
    initial_decision_admission: InitialDecisionAdmission<'_>,
) -> Result<(), GraphStoreError> {
    if candidate.migration_marker < current.migration_marker {
        return Err(GraphStoreError::InvalidState {
            reason: "graph-state migration marker downgrade is forbidden".to_string(),
        });
    }
    validate_scheduler_budget_transition(current, candidate)?;
    if let Some(budget) = &candidate.scheduler_budget {
        scheduler_policy.validate_budget(budget)?;
    }
    if candidate.migration_marker < GRAPH_STATE_MIGRATION_HYPOTHESES
        && (candidate.tasks != current.tasks
            || candidate.logical_task_descriptors != current.logical_task_descriptors
            || candidate.terminal_outbox != current.terminal_outbox
            || candidate.task_failure_outbox != current.task_failure_outbox)
    {
        return Err(GraphStoreError::InvalidState {
            reason: "task replacement requires the reasoning-state migration marker".to_string(),
        });
    }

    if current.migration_marker == GRAPH_STATE_MIGRATION_LEGACY
        && candidate.migration_marker == GRAPH_STATE_MIGRATION_HYPOTHESES
    {
        // Marker promotion is a one-way schema migration, not a convenient
        // graph/task replacement API. The graph stream, fencing high-water,
        // and every legacy task/tombstone must be preserved exactly. The
        // reasoning projections may be populated, and new descriptor-bound
        // pending tasks may be admitted by `with_reasoning_state`.
        if candidate.graph != current.graph {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning-state migration rewrote or advanced the legacy graph"
                    .to_string(),
            });
        }
        if candidate.tasks != current.tasks {
            let existing_tasks_preserved = current
                .tasks
                .iter()
                .all(|(task_id, task)| candidate.tasks.get(task_id) == Some(task));
            if !existing_tasks_preserved {
                return Err(GraphStoreError::InvalidState {
                    reason: "reasoning-state migration rewrote or removed a legacy task"
                        .to_string(),
                });
            }
        }
        if candidate.task_tombstones != current.task_tombstones {
            let existing_tombstones_preserved =
                current.task_tombstones.iter().all(|(task_id, tombstone)| {
                    candidate.task_tombstones.get(task_id) == Some(tombstone)
                });
            if !existing_tombstones_preserved {
                return Err(GraphStoreError::InvalidState {
                    reason: "reasoning-state migration rewrote or removed a legacy task tombstone"
                        .to_string(),
                });
            }
        }
        if candidate.fencing_counter != current.fencing_counter {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning-state migration changed the legacy fencing high-water"
                    .to_string(),
            });
        }
    }

    validate_task_history_prefix(current, candidate)?;

    // The graph itself is append-only.  Existing signed records cannot be
    // removed or rewritten by a direct CAS, even when the candidate's graph
    // version was manually advanced.
    validate_append_only_map("nodes", &current.graph.nodes, &candidate.graph.nodes)?;
    validate_append_only_map(
        "evidence",
        &current.graph.evidence,
        &candidate.graph.evidence,
    )?;
    validate_append_only_map("edges", &current.graph.edges, &candidate.graph.edges)?;
    validate_append_only_map(
        "contradictions",
        &current.graph.contradictions,
        &candidate.graph.contradictions,
    )?;
    validate_append_only_map(
        "conflicts",
        &current.graph.conflicts,
        &candidate.graph.conflicts,
    )?;
    let graph_changed = candidate.graph.nodes != current.graph.nodes
        || candidate.graph.evidence != current.graph.evidence
        || candidate.graph.edges != current.graph.edges
        || candidate.graph.contradictions != current.graph.contradictions
        || candidate.graph.conflicts != current.graph.conflicts;
    if graph_changed && candidate.graph.version <= current.graph.version {
        return Err(GraphStoreError::InvalidState {
            reason: "graph records changed without advancing graph version".to_string(),
        });
    }
    if candidate.graph.version < current.graph.version {
        return Err(GraphStoreError::InvalidState {
            reason: "graph version regressed".to_string(),
        });
    }

    // Hypothesis records are durable epistemic alternatives.  Existing
    // alternatives remain queryable, and their decision histories can only
    // grow by appending the next sequence number.
    for (hypothesis_id, prior) in &current.hypotheses {
        let next = candidate.hypotheses.get(hypothesis_id).ok_or_else(|| {
            GraphStoreError::InvalidState {
                reason: "reasoning CAS removed an existing hypothesis".to_string(),
            }
        })?;
        if next.confidence != prior.confidence || next.uncertainty != prior.uncertainty {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS rewrote hypothesis confidence or uncertainty without a typed authenticated transition"
                    .to_string(),
            });
        }
        if next.hypothesis_id != prior.hypothesis_id
            || !prior.claims.is_subset(&next.claims)
            || !prior.contradiction_ids.is_subset(&next.contradiction_ids)
            || next.graph_version < prior.graph_version
            || next.decision_history.len() < prior.decision_history.len()
            || next
                .decision_history
                .iter()
                .zip(&prior.decision_history)
                .any(|(candidate_decision, prior_decision)| candidate_decision != prior_decision)
        {
            return Err(GraphStoreError::InvalidState {
                reason: "hypothesis state or decision history is not append-only".to_string(),
            });
        }
        if next.decision_history[prior.decision_history.len()..]
            .iter()
            .any(|decision| decision.decided_at < current.logical_time_high_water)
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS appended a decision below the predecessor logical-time high-water"
                    .to_string(),
            });
        }
    }
    for (hypothesis_id, hypothesis) in &candidate.hypotheses {
        if current.hypotheses.contains_key(hypothesis_id) {
            continue;
        }
        let descriptor_lineage =
            candidate
                .logical_task_descriptors
                .iter()
                .any(|(task_id, descriptor)| {
                    !current.logical_task_descriptors.contains_key(task_id)
                        && descriptor.kind == TaskKind::FalsifyHypothesis
                        && matches!(
                            &descriptor.target,
                            TaskTarget::Hypothesis {
                                hypothesis_id: target
                            } if target == hypothesis_id
                        )
                });
        let coordinator_shape = hypothesis.graph_version == 0
            && hypothesis.claims.is_empty()
            && hypothesis.contradiction_ids.is_empty()
            && hypothesis.confidence == ConfidenceDistribution::uniform_two()
            && hypothesis.uncertainty.iter().all(|reason| {
                matches!(
                    reason,
                    UncertaintyReason::InsufficientEvidence
                        | UncertaintyReason::ConflictingEvidence
                )
            });
        let initial_history_is_authenticated = match initial_decision_admission {
            InitialDecisionAdmission::Reject => {
                hypothesis.decision_history.is_empty()
                    && hypothesis.status == swarm_core::hypothesis_graph::HypothesisStatus::Live
            }
            InitialDecisionAdmission::AuthenticatedCoordinator(coordinator_identity) => {
                if hypothesis.decision_history.is_empty() {
                    hypothesis.status == swarm_core::hypothesis_graph::HypothesisStatus::Live
                } else {
                    hypothesis.decision_history.iter().all(|decision| {
                        let coordinator_scoped = decision.witness.as_ref().is_some_and(|witness| {
                            witness.scoped_agent_id == "hypothesis-coordinator"
                        });
                        coordinator_scoped && &decision.producer_identity == coordinator_identity
                    })
                }
            }
        };
        // A falsification decision closes its own alternative, so the
        // coordinator must not manufacture a task which can no longer run.
        // Every still-live alternative retains descriptor lineage.
        let task_lineage_is_complete = hypothesis.status
            == swarm_core::hypothesis_graph::HypothesisStatus::Falsified
            || descriptor_lineage;
        if !coordinator_shape || !initial_history_is_authenticated || !task_lineage_is_complete {
            return Err(GraphStoreError::InvalidState {
                reason: "new hypothesis lacks authenticated coordinator seed/task lineage"
                    .to_string(),
            });
        }
    }

    // Cross-graph links are bounded references, not a mutable side channel.
    if !current
        .cross_graph_links
        .is_subset(&candidate.cross_graph_links)
    {
        return Err(GraphStoreError::InvalidState {
            reason: "reasoning CAS removed an existing cross-graph link".to_string(),
        });
    }
    if candidate.cross_graph_links.len() > limits.max_tasks {
        return Err(GraphStoreError::ResourceLimit {
            resource: "reasoning.cross_graph_links".to_string(),
            limit: limits.max_tasks,
        });
    }

    // Descriptors and outbox publications are append-only and must remain
    // bound to the task map.  A new descriptor/task is admitted only as a
    // pending task; a changed existing task is admitted only as one terminal
    // task plus one new outbox entry.
    for (task_id, prior) in &current.logical_task_descriptors {
        let next = candidate
            .logical_task_descriptors
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "reasoning CAS removed an existing task descriptor".to_string(),
            })?;
        if next != prior {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS rewrote an existing task descriptor".to_string(),
            });
        }
    }
    for (task_id, descriptor) in &candidate.logical_task_descriptors {
        let task = candidate
            .tasks
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "candidate descriptor has no durable task".to_string(),
            })?;
        if descriptor.task_id != *task_id
            || descriptor.target != task.task.request.target
            || descriptor.kind != task.task.request.kind
        {
            return Err(GraphStoreError::InvalidState {
                reason: "candidate descriptor does not bind its task".to_string(),
            });
        }
    }
    for (task_id, prior) in &current.terminal_outbox {
        let next = candidate.terminal_outbox.get(task_id).ok_or_else(|| {
            GraphStoreError::InvalidState {
                reason: "reasoning CAS removed an existing terminal outbox entry".to_string(),
            }
        })?;
        if next != prior {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS rewrote an existing terminal outbox entry".to_string(),
            });
        }
    }
    for (task_id, prior) in &current.task_failure_outbox {
        let next = candidate.task_failure_outbox.get(task_id).ok_or_else(|| {
            GraphStoreError::InvalidState {
                reason: "reasoning CAS removed an existing task failure outbox entry".to_string(),
            }
        })?;
        if next != prior {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS rewrote an existing task failure outbox entry".to_string(),
            });
        }
    }
    for task_id in current.tasks.keys() {
        if !candidate.tasks.contains_key(task_id) {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS removed an existing task".to_string(),
            });
        }
    }
    for (task_id, prior) in &current.task_tombstones {
        let Some(next) = candidate.task_tombstones.get(task_id) else {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS removed an existing task tombstone".to_string(),
            });
        };
        if let Some(candidate_task) = candidate.tasks.get(task_id)
            && !tombstone_matches_record(next, candidate_task, candidate.migration_marker)?
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS task tombstone does not match its task".to_string(),
            });
        }
        if candidate.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
            && candidate.tasks.get(task_id) != current.tasks.get(task_id)
            && next.history_digest.is_empty()
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS changed task without binding its history digest".to_string(),
            });
        }
        if candidate.tasks.get(task_id) == current.tasks.get(task_id) && next != prior {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS rewrote an existing task tombstone".to_string(),
            });
        }
        next.compare_to(prior, task_id)?;
    }
    for (task_id, next) in &candidate.tasks {
        let prior = current.tasks.get(task_id);
        match prior {
            None => {
                if !matches!(next.task.state, TaskState::Pending)
                    || !next.history.is_empty()
                    || !candidate.logical_task_descriptors.contains_key(task_id)
                    || candidate.terminal_outbox.contains_key(task_id)
                    || candidate.task_failure_outbox.contains_key(task_id)
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "new reasoning task must be pending and descriptor-bound"
                            .to_string(),
                    });
                }
            }
            Some(prior) if next == prior => {}
            Some(prior) => {
                let prior_lease =
                    prior
                        .task
                        .lease
                        .as_ref()
                        .ok_or_else(|| GraphStoreError::InvalidState {
                            reason:
                                "terminal task replacement requires the prior task's active lease"
                                    .to_string(),
                        })?;
                if prior.task.state != TaskState::Claimed || prior.task.completion.is_some() {
                    return Err(GraphStoreError::InvalidState {
                        reason: "terminal task replacement requires a prior claimed task"
                            .to_string(),
                    });
                }
                if next.task.request != prior.task.request {
                    return Err(GraphStoreError::InvalidState {
                        reason: "terminal task replacement changed the claimed request identity"
                            .to_string(),
                    });
                }
                let completion_outbox = candidate.terminal_outbox.get(task_id);
                let failure_outbox = candidate.task_failure_outbox.get(task_id);
                let atomic_terminal_publication = match next.task.state {
                    TaskState::Completed => {
                        !current.terminal_outbox.contains_key(task_id)
                            && !current.task_failure_outbox.contains_key(task_id)
                            && completion_outbox.is_some()
                            && failure_outbox.is_none()
                    }
                    TaskState::Failed => {
                        !current.terminal_outbox.contains_key(task_id)
                            && !current.task_failure_outbox.contains_key(task_id)
                            && completion_outbox.is_none()
                            && failure_outbox.is_some()
                    }
                    _ => false,
                };
                if !atomic_terminal_publication {
                    return Err(GraphStoreError::InvalidState {
                        reason: "task replacement is not an atomic terminal outbox publication"
                            .to_string(),
                    });
                }
                let proof = next.task.terminal_history.last().ok_or_else(|| {
                    GraphStoreError::InvalidState {
                        reason: "terminal task replacement has no retained terminal proof"
                            .to_string(),
                    }
                })?;
                if proof.prior_state != TaskState::Claimed
                    || proof.prior_generation != prior.task.generation
                    || proof.prior_lease != *prior_lease
                {
                    return Err(GraphStoreError::InvalidState {
                        reason:
                            "terminal proof does not bind the prior claimed lease and generation"
                                .to_string(),
                    });
                }
                if proof.completed_at < prior_lease.issued_at
                    || proof.completed_at >= prior_lease.expires_at
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "terminal proof is outside the prior active lease window"
                            .to_string(),
                    });
                }
                if proof.completed_at < current.logical_time_high_water
                    || proof.completed_at < candidate.logical_time_high_water
                {
                    return Err(GraphStoreError::InvalidState {
                        reason:
                            "terminal completion logical time is below the durable graph high-water"
                                .to_string(),
                    });
                }
                if current.logical_time_high_water >= prior_lease.expires_at {
                    return Err(GraphStoreError::InvalidState {
                        reason: "prior claimed lease is expired at the durable logical high-water"
                            .to_string(),
                    });
                }
                let prior_high_water = current.task_tombstones.get(task_id).ok_or_else(|| {
                    GraphStoreError::InvalidState {
                        reason: "current task has no monotonic tombstone".to_string(),
                    }
                })?;
                let next_high_water = candidate.task_tombstones.get(task_id).ok_or_else(|| {
                    GraphStoreError::InvalidState {
                        reason: "candidate task has no monotonic tombstone".to_string(),
                    }
                })?;
                next_high_water.compare_to(prior_high_water, task_id)?;
                let descriptor =
                    candidate
                        .logical_task_descriptors
                        .get(task_id)
                        .ok_or_else(|| GraphStoreError::InvalidState {
                            reason: "terminal task replacement has no logical descriptor"
                                .to_string(),
                        })?;
                if let Some(outbox) = completion_outbox {
                    let envelope = &outbox.envelope;
                    if envelope.task_id != prior.task.request.task_id
                        || envelope.idempotency_key != prior.task.request.idempotency_key
                        || envelope.lease_id != prior_lease.lease_id
                        || envelope.fencing_token != prior_lease.fencing_token
                        || envelope.producer != prior_lease.holder
                        || envelope.capability.claimant != prior.task.request.claimant
                        || envelope.capability.kind != prior.task.request.kind
                        || envelope.capability.role != prior.task.request.role
                    {
                        return Err(GraphStoreError::InvalidState {
                            reason:
                                "terminal outbox is not bound to the prior claimed task identity"
                                    .to_string(),
                        });
                    }
                    // Re-run the publication against the claimed predecessor,
                    // not only the materialized terminal candidate.
                    outbox
                        .validate_for_task_at(
                            &prior.task,
                            descriptor,
                            limits,
                            current.logical_time_high_water,
                        )
                        .map_err(GraphStoreError::Admission)?;
                    outbox
                        .validate_graph_references(&current.graph, &current.hypotheses)
                        .map_err(GraphStoreError::Admission)?;
                    outbox
                        .validate_for_committed_task_at(
                            &next.task,
                            descriptor,
                            limits,
                            candidate.logical_time_high_water,
                        )
                        .map_err(GraphStoreError::Admission)?;
                } else if let Some(outbox) = failure_outbox {
                    outbox.validate_for_claimed_task(
                        &prior.task,
                        descriptor,
                        current.logical_time_high_water,
                    )?;
                    outbox.validate_for_failed_task(
                        &next.task,
                        descriptor,
                        candidate.logical_time_high_water,
                    )?;
                }
            }
        }
    }
    for (task_id, entry) in &candidate.terminal_outbox {
        if let Some(prior_entry) = current.terminal_outbox.get(task_id)
            && prior_entry != entry
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning CAS rewrote an existing terminal outbox entry".to_string(),
            });
        }
        if !current.terminal_outbox.contains_key(task_id)
            && current
                .tasks
                .get(task_id)
                .is_some_and(|prior| candidate.tasks.get(task_id) == Some(prior))
        {
            return Err(GraphStoreError::InvalidState {
                reason: "terminal outbox publication is not atomic with task transition"
                    .to_string(),
            });
        }
        let task = candidate
            .tasks
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "terminal outbox references an unknown task".to_string(),
            })?;
        let descriptor = candidate
            .logical_task_descriptors
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "terminal outbox task has no logical descriptor".to_string(),
            })?;
        entry
            .validate_for_committed_task_at(
                &task.task,
                descriptor,
                limits,
                candidate.logical_time_high_water,
            )
            .map_err(GraphStoreError::Admission)?;
    }
    for (task_id, entry) in &candidate.task_failure_outbox {
        if !current.task_failure_outbox.contains_key(task_id)
            && current
                .tasks
                .get(task_id)
                .is_some_and(|prior| candidate.tasks.get(task_id) == Some(prior))
        {
            return Err(GraphStoreError::InvalidState {
                reason: "task failure outbox publication is not atomic with task transition"
                    .to_string(),
            });
        }
        let task = candidate
            .tasks
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task failure outbox references an unknown task".to_string(),
            })?;
        let descriptor = candidate
            .logical_task_descriptors
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task failure outbox has no logical descriptor".to_string(),
            })?;
        entry.validate_for_failed_task(
            &task.task,
            descriptor,
            candidate.logical_time_high_water,
        )?;
    }
    // Generic CAS is not a scheduler-admission API. Once a reasoning stream
    // has a persisted budget, every task-map mutation must carry the exact
    // derived work delta for new pending tasks; terminalization carries no
    // scheduler delta. A caller cannot overcharge, reset, or move the budget
    // to an unrelated logical tick while smuggling a task mutation through
    // `compare_and_swap`.
    if !(current.migration_marker == GRAPH_STATE_MIGRATION_LEGACY
        && candidate.migration_marker == GRAPH_STATE_MIGRATION_HYPOTHESES
        && current.tasks == candidate.tasks)
    {
        validate_reasoning_task_scheduler_delta(current, candidate)?;
    }
    Ok(())
}

/// Scheduler usage is a durable high-water, not a process-local hint. A
/// candidate may advance to a newer logical tick (where core admission resets
/// per-tick counters), but it may not lower the tick, reset counters at the
/// same tick, or widen/change the config-bound ceilings. Legacy marker-0
/// states have no budget; attaching the first validated budget is the only
/// `None -> Some` transition permitted.
fn validate_scheduler_budget_transition(
    current: &GraphStoreState,
    candidate: &GraphStoreState,
) -> Result<(), GraphStoreError> {
    if current.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
        && current.scheduler_budget.is_none()
    {
        return Err(GraphStoreError::InvalidState {
            reason: "marker-1 predecessor has no persisted scheduler budget".to_string(),
        });
    }
    if candidate.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
        && candidate.scheduler_budget.is_none()
    {
        return Err(GraphStoreError::InvalidState {
            reason: "marker-1 candidate has no persisted scheduler budget".to_string(),
        });
    }
    match (&current.scheduler_budget, &candidate.scheduler_budget) {
        (None, None)
            if current.migration_marker == GRAPH_STATE_MIGRATION_LEGACY
                && candidate.migration_marker == GRAPH_STATE_MIGRATION_LEGACY =>
        {
            Ok(())
        }
        (None, Some(_))
            if current.migration_marker == GRAPH_STATE_MIGRATION_LEGACY
                && candidate.migration_marker == GRAPH_STATE_MIGRATION_HYPOTHESES =>
        {
            Ok(())
        }
        (None, None) | (None, Some(_)) => Err(GraphStoreError::InvalidState {
            reason: "scheduler budget attachment is only valid for one-way legacy migration"
                .to_string(),
        }),
        (Some(_), None) => Err(GraphStoreError::InvalidState {
            reason: "scheduler budget was removed or reset".to_string(),
        }),
        (Some(current_budget), Some(candidate_budget)) => {
            if current_budget.max_work_units != candidate_budget.max_work_units
                || current_budget.max_claims != candidate_budget.max_claims
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "scheduler budget policy identity/ceilings changed after attachment"
                        .to_string(),
                });
            }
            if candidate_budget.current_tick() < current_budget.current_tick() {
                return Err(GraphStoreError::InvalidState {
                    reason: "scheduler budget logical tick regressed".to_string(),
                });
            }
            if candidate_budget.current_tick() == current_budget.current_tick()
                && (candidate_budget.work_units_used() < current_budget.work_units_used()
                    || candidate_budget.claims_used() < current_budget.claims_used())
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "scheduler budget counters regressed within a logical tick".to_string(),
                });
            }
            Ok(())
        }
    }
}

fn validate_exact_scheduler_budget_delta(
    current: Option<&SchedulerBudget>,
    candidate: Option<&SchedulerBudget>,
    logical_tick: Option<GraphLogicalTime>,
    expected_work_units: u32,
    expected_claims: u16,
) -> Result<(), GraphStoreError> {
    if logical_tick.is_none() && expected_work_units == 0 && expected_claims == 0 {
        if current != candidate {
            return Err(GraphStoreError::InvalidState {
                reason: "scheduler budget changed without a derived task admission".to_string(),
            });
        }
        return Ok(());
    }

    let candidate_budget = candidate.ok_or_else(|| GraphStoreError::InvalidState {
        reason: "task admission changed without a persisted scheduler budget".to_string(),
    })?;
    let logical_tick = logical_tick.ok_or_else(|| GraphStoreError::InvalidState {
        reason: "scheduler task admission is missing its logical tick".to_string(),
    })?;
    if candidate_budget.current_tick() != logical_tick {
        return Err(GraphStoreError::InvalidState {
            reason: "scheduler budget logical tick does not match task admission".to_string(),
        });
    }

    let (expected_work, expected_claims) = match current {
        None => (expected_work_units, expected_claims),
        Some(current_budget) => {
            if logical_tick < current_budget.current_tick() {
                return Err(GraphStoreError::InvalidState {
                    reason: "scheduler task admission logical tick regressed".to_string(),
                });
            }
            if logical_tick == current_budget.current_tick() {
                (
                    current_budget
                        .work_units_used()
                        .checked_add(expected_work_units)
                        .ok_or_else(|| GraphStoreError::InvalidState {
                            reason: "scheduler work-unit delta overflow".to_string(),
                        })?,
                    current_budget
                        .claims_used()
                        .checked_add(expected_claims)
                        .ok_or_else(|| GraphStoreError::InvalidState {
                            reason: "scheduler claim delta overflow".to_string(),
                        })?,
                )
            } else {
                (expected_work_units, expected_claims)
            }
        }
    };
    if candidate_budget.work_units_used() != expected_work
        || candidate_budget.claims_used() != expected_claims
    {
        return Err(GraphStoreError::InvalidState {
            reason: format!(
                "scheduler budget delta is not exact: expected work {expected_work}, claims {expected_claims}, observed work {}, claims {}",
                candidate_budget.work_units_used(),
                candidate_budget.claims_used()
            ),
        });
    }
    Ok(())
}

fn validate_reasoning_task_scheduler_delta(
    current: &GraphStoreState,
    candidate: &GraphStoreState,
) -> Result<(), GraphStoreError> {
    let mut new_pending_tasks = 0_u32;
    let mut admission_tick = None;
    let mut task_map_changed = current.tasks != candidate.tasks;

    for (task_id, next) in &candidate.tasks {
        match current.tasks.get(task_id) {
            None => {
                task_map_changed = true;
                new_pending_tasks = new_pending_tasks.checked_add(1).ok_or_else(|| {
                    GraphStoreError::InvalidState {
                        reason: "scheduler pending-task delta overflow".to_string(),
                    }
                })?;
                if !matches!(next.task.state, TaskState::Pending) {
                    return Err(GraphStoreError::InvalidState {
                        reason: "scheduler work admission requires a new pending task".to_string(),
                    });
                }
                let requested_at = next.task.request.requested_at;
                if let Some(prior_tick) = admission_tick
                    && prior_tick != requested_at
                {
                    return Err(GraphStoreError::InvalidState {
                        reason: "new pending tasks in one CAS must share a logical tick"
                            .to_string(),
                    });
                }
                admission_tick = Some(requested_at);
            }
            Some(prior) if prior != next => {
                task_map_changed = true;
            }
            Some(_) => {}
        }
    }

    if !task_map_changed {
        return validate_exact_scheduler_budget_delta(
            current.scheduler_budget.as_ref(),
            candidate.scheduler_budget.as_ref(),
            None,
            0,
            0,
        );
    }
    if new_pending_tasks == 0 {
        // A valid direct CAS task replacement is terminalization, which has
        // no scheduler charge. Any other changed-task shape was rejected by
        // the terminal transition checks above.
        return validate_exact_scheduler_budget_delta(
            current.scheduler_budget.as_ref(),
            candidate.scheduler_budget.as_ref(),
            None,
            0,
            0,
        );
    }
    validate_exact_scheduler_budget_delta(
        current.scheduler_budget.as_ref(),
        candidate.scheduler_budget.as_ref(),
        admission_tick,
        new_pending_tasks,
        0,
    )
}

/// Retained wrapper history is an append-only log. A candidate may append the
/// next terminal attempt, but it may never rewrite an already persisted
/// prefix, including when the candidate keeps the same task generation and
/// tombstone high-water fields.
fn validate_task_history_prefix(
    current: &GraphStoreState,
    candidate: &GraphStoreState,
) -> Result<(), GraphStoreError> {
    for (task_id, prior) in &current.tasks {
        let next = candidate
            .tasks
            .get(task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: format!("task {task_id} was removed while validating history"),
            })?;
        if next.history.len() < prior.history.len()
            || next
                .history
                .iter()
                .zip(&prior.history)
                .any(|(candidate_record, prior_record)| candidate_record != prior_record)
        {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} history is not an append-only prefix"),
            });
        }
    }
    Ok(())
}

fn validate_append_only_map<K, V>(
    label: &str,
    current: &BTreeMap<K, V>,
    candidate: &BTreeMap<K, V>,
) -> Result<(), GraphStoreError>
where
    K: Ord,
    V: PartialEq,
{
    for (record_id, record) in current {
        match candidate.get(record_id) {
            Some(candidate_record) if candidate_record == record => {}
            Some(_) => {
                return Err(GraphStoreError::InvalidState {
                    reason: format!("reasoning CAS rewrote an existing {label} record"),
                });
            }
            None => {
                return Err(GraphStoreError::InvalidState {
                    reason: format!("reasoning CAS removed an existing {label} record"),
                });
            }
        }
    }
    Ok(())
}

struct StateMutation<R> {
    value: R,
    changed: bool,
}

fn refresh_changed_task_tombstones(
    current: &GraphStoreState,
    candidate: &mut GraphStoreState,
    preserve_legacy_tombstones: bool,
) -> Result<(), GraphStoreError> {
    let changed_task_ids: Vec<TaskId> = candidate
        .tasks
        .iter()
        .filter_map(|(task_id, record)| {
            (current.tasks.get(task_id) != Some(record)).then_some(task_id.clone())
        })
        .collect();
    for task_id in changed_task_ids {
        refresh_task_tombstone(candidate, &task_id, preserve_legacy_tombstones)?;
    }
    Ok(())
}

fn refresh_task_tombstone(
    state: &mut GraphStoreState,
    task_id: &TaskId,
    preserve_legacy_tombstone: bool,
) -> Result<(), GraphStoreError> {
    let record = state
        .tasks
        .get(task_id)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: format!("task tombstone refresh has no durable task {task_id}"),
        })?;
    let next = if state.migration_marker == GRAPH_STATE_MIGRATION_LEGACY
        || (preserve_legacy_tombstone
            && state
                .task_tombstones
                .get(task_id)
                .is_some_and(|tombstone| tombstone.history_digest.is_empty()))
    {
        TaskMonotonicity::from_record_legacy(record)?
    } else {
        TaskMonotonicity::from_record(record)?
    };
    if let Some(current) = state.task_tombstones.get(task_id) {
        next.compare_to(current, task_id)?;
    }
    state.task_tombstones.insert(task_id.clone(), next);
    Ok(())
}

fn transition<R, F>(
    current: &SignedGraphStoreState,
    expected: Option<&GraphStoreRevision>,
    signer: &Keypair,
    limits: &GraphResourceLimits,
    scheduler_policy: &SchedulerBudgetPolicy,
    operation: F,
) -> Result<(SignedGraphStoreState, R), GraphStoreError>
where
    F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
{
    let current_revision = current.revision()?;
    check_expected(&current_revision, expected)?;
    transition_after_predecessor_check(
        current,
        signer,
        limits,
        scheduler_policy,
        expected.is_none(),
        operation,
    )
}

fn transition_with_exact_retry<R, P, F>(
    current: &SignedGraphStoreState,
    expected: Option<&GraphStoreRevision>,
    signer: &Keypair,
    limits: &GraphResourceLimits,
    scheduler_policy: &SchedulerBudgetPolicy,
    exact_retry: P,
    operation: F,
) -> Result<(SignedGraphStoreState, R), GraphStoreError>
where
    P: FnOnce(&GraphStoreState) -> Result<Option<R>, GraphStoreError>,
    F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
{
    if let Some(value) = exact_retry(&current.state)? {
        return Ok((current.clone(), value));
    }
    let current_revision = current.revision()?;
    check_expected(&current_revision, expected)?;
    transition_after_predecessor_check(
        current,
        signer,
        limits,
        scheduler_policy,
        expected.is_none(),
        operation,
    )
}

fn transition_after_predecessor_check<R, F>(
    current: &SignedGraphStoreState,
    signer: &Keypair,
    limits: &GraphResourceLimits,
    scheduler_policy: &SchedulerBudgetPolicy,
    refresh_convenience_tombstones: bool,
    operation: F,
) -> Result<(SignedGraphStoreState, R), GraphStoreError>
where
    F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
{
    let mut next_state = current.state.clone();
    let result = operation(&mut next_state)?;
    if !result.changed {
        return Ok((current.clone(), result.value));
    }
    // CAS candidates already carry their explicitly validated tombstones.
    // Recomputing them here would normalize a tampered migration candidate
    // before the append-only validator could reject it. Convenience task
    // transitions refresh only the records changed by this operation, so an
    // unrelated legacy tombstone is never rewritten as a side effect.
    if refresh_convenience_tombstones {
        refresh_changed_task_tombstones(&current.state, &mut next_state, false)?;
    }
    validate_scheduler_budget_transition(&current.state, &next_state)?;
    if let Some(budget) = &next_state.scheduler_budget {
        scheduler_policy.validate_budget(budget)?;
    }
    next_state.validate_with_limits(limits)?;
    validate_task_history_prefix(&current.state, &next_state)?;
    next_state.generation =
        current
            .state
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "store generation overflow".to_string(),
            })?;
    next_state.predecessor_digest = Some(current.digest.clone());
    let signed = sign_state(next_state, signer, limits)?;
    Ok((signed, result.value))
}

fn next_fence(state: &mut GraphStoreState) -> Result<FencingToken, GraphStoreError> {
    state.fencing_counter =
        state
            .fencing_counter
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task fencing counter overflow".to_string(),
            })?;
    Ok(FencingToken::new(state.fencing_counter))
}

fn observe_logical_time(
    state: &mut GraphStoreState,
    now: GraphLogicalTime,
) -> Result<(), GraphStoreError> {
    now.validate().map_err(GraphStoreError::Admission)?;
    if now < state.logical_time_high_water {
        return Err(GraphStoreError::InvalidTransition {
            reason: format!(
                "logical clock regressed below persisted high-water {}",
                state.logical_time_high_water
            ),
        });
    }
    state.logical_time_high_water = now;
    Ok(())
}

fn lease_id(
    task_id: &str,
    claimant: &AgentId,
    fence: FencingToken,
    stream_id: &str,
) -> Result<LeaseId, GraphStoreError> {
    let material = (stream_id, task_id, claimant, fence.0);
    let bytes =
        canonical_json_bytes(&material).map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    Ok(LeaseId::new(format!("lease:{}", sha256_hex(&bytes))))
}

fn lease_for(
    stream_id: &str,
    task_id: &str,
    claimant: &AgentId,
    issued_at: GraphLogicalTime,
    duration_ms: u64,
    fence: FencingToken,
    limits: &GraphResourceLimits,
) -> Result<TaskLease, GraphStoreError> {
    if duration_ms == 0 || duration_ms > limits.max_task_lease_ms {
        return Err(GraphStoreError::InvalidLease {
            reason: format!(
                "duration must be between 1 and {} ms",
                limits.max_task_lease_ms
            ),
        });
    }
    let duration = i64::try_from(duration_ms).map_err(|_| GraphStoreError::InvalidLease {
        reason: "duration does not fit logical time".to_string(),
    })?;
    let expires_at =
        issued_at
            .checked_add(duration)
            .ok_or_else(|| GraphStoreError::InvalidLease {
                reason: "lease expiry overflows logical time".to_string(),
            })?;
    TaskLease::new(
        lease_id(task_id, claimant, fence, stream_id)?,
        claimant.clone(),
        issued_at,
        expires_at,
        fence,
    )
    .map_err(GraphStoreError::Admission)
}

fn validate_request(request: &TaskClaimRequest) -> Result<(), GraphStoreError> {
    request.validate().map_err(GraphStoreError::Admission)
}

fn ensure_reasoning_descriptor_for_request(
    state: &GraphStoreState,
    request: &TaskClaimRequest,
) -> Result<(), GraphStoreError> {
    if state.migration_marker < GRAPH_STATE_MIGRATION_HYPOTHESES {
        return Ok(());
    }
    let descriptor = state
        .logical_task_descriptors
        .get(&request.task_id)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "reasoning task admission requires a logical task descriptor".to_string(),
        })?;
    if descriptor.target != request.target || descriptor.kind != request.kind {
        return Err(GraphStoreError::InvalidState {
            reason: "logical task descriptor does not bind the claim request".to_string(),
        });
    }
    Ok(())
}

fn reject_reasoning_terminal_transition(state: &GraphStoreState) -> Result<(), GraphStoreError> {
    if state.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES {
        return Err(GraphStoreError::InvalidTransition {
            reason: "reasoning terminal transitions require a descriptor-bound outbox CAS"
                .to_string(),
        });
    }
    Ok(())
}

/// The legacy task entry points predate persisted scheduler admission. They
/// remain available for authenticated marker-0 streams, but may not mutate a
/// marker-1 reasoning stream without carrying the next budget in the same
/// operation-specific CAS.
fn reject_unbudgeted_reasoning_task_surface(
    state: &GraphStoreState,
    operation: &str,
) -> Result<(), GraphStoreError> {
    if state.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES {
        return Err(GraphStoreError::InvalidTransition {
            reason: format!("reasoning {operation} requires atomic scheduler budget admission"),
        });
    }
    Ok(())
}

/// Claim identity is the canonical idempotency key plus every immutable claim
/// field.  `requested_at` is deliberately excluded: a retry that reaches the
/// store at a later logical time must resolve to the original durable claim,
/// not create a second attempt or mutate its request timestamp.
fn same_claim_identity(left: &TaskClaimRequest, right: &TaskClaimRequest) -> bool {
    left.idempotency_key == right.idempotency_key
        && left.task_id == right.task_id
        && left.kind == right.kind
        && left.target == right.target
        && left.role == right.role
        && left.claimant == right.claimant
        && left.evidence_scope == right.evidence_scope
}

/// A pending descriptor is logical work, not a lease held by the coordinator's
/// initially selected worker. Before the first claim, another capable worker
/// may atomically bind its own claimant, request time, and capability digest;
/// the descriptor-bound task identity, target, role, and evidence scope remain
/// immutable.
fn same_pending_work_identity(left: &TaskClaimRequest, right: &TaskClaimRequest) -> bool {
    left.task_id == right.task_id
        && left.kind == right.kind
        && left.target == right.target
        && left.role == right.role
        && left.evidence_scope == right.evidence_scope
}

fn task_entry_mut<'a>(
    state: &'a mut GraphStoreState,
    task_id: &str,
) -> Result<&'a mut DurableTaskRecord, GraphStoreError> {
    state
        .tasks
        .get_mut(&TaskId::new(task_id))
        .ok_or_else(|| GraphStoreError::TaskNotFound {
            task_id: task_id.to_string(),
        })
}

fn ensure_task_generation(
    entry: &DurableTaskRecord,
    expected_generation: u64,
) -> Result<(), GraphStoreError> {
    if entry.generation != expected_generation {
        return Err(GraphStoreError::StaleTaskGeneration {
            task_id: entry.task.request.task_id.clone(),
            expected: expected_generation,
            observed: entry.generation,
        });
    }
    Ok(())
}

fn ensure_lease(
    entry: &DurableTaskRecord,
    lease_id: &LeaseId,
    fence: FencingToken,
) -> Result<TaskLease, GraphStoreError> {
    let lease = entry
        .task
        .lease
        .as_ref()
        .ok_or_else(|| GraphStoreError::LeaseMissing {
            task_id: entry.task.request.task_id.clone(),
        })?;
    if &lease.lease_id != lease_id {
        return Err(GraphStoreError::StaleLease {
            task_id: entry.task.request.task_id.clone(),
            expected: lease.lease_id.clone(),
            observed: lease_id.clone(),
        });
    }
    if lease.fencing_token != fence {
        return Err(GraphStoreError::StaleFence {
            task_id: entry.task.request.task_id.clone(),
            expected: lease.fencing_token,
            observed: fence,
        });
    }
    Ok(lease.clone())
}

fn create_task_op(
    state: &mut GraphStoreState,
    request: TaskClaimRequest,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    validate_request(&request)?;
    if state.migration_marker >= GRAPH_STATE_MIGRATION_HYPOTHESES
        && !state.tasks.contains_key(&request.task_id)
    {
        return Err(GraphStoreError::InvalidTransition {
            reason: "reasoning task creation requires a descriptor-bound CAS".to_string(),
        });
    }
    ensure_reasoning_descriptor_for_request(state, &request)?;
    if let Some(existing) = state.tasks.get(&request.task_id) {
        if same_claim_identity(&existing.task.request, &request) {
            return Ok(StateMutation {
                value: TaskMutationMarker {
                    task: existing.task.clone(),
                    idempotent: true,
                },
                changed: false,
            });
        }
        return Err(GraphStoreError::TaskExists {
            task_id: request.task_id,
        });
    }
    if state.tasks.len() >= limits.max_tasks {
        return Err(GraphStoreError::ResourceLimit {
            resource: "tasks".to_string(),
            limit: limits.max_tasks,
        });
    }
    observe_logical_time(state, request.requested_at)?;
    let task = TaskRecord {
        schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
        request,
        state: TaskState::Pending,
        generation: 1,
        attempts: 1,
        lease: None,
        completion: None,
        terminal_history: Vec::new(),
    };
    task.validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
        .map_err(GraphStoreError::Admission)?;
    state.tasks.insert(
        task.request.task_id.clone(),
        DurableTaskRecord {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            task: task.clone(),
            generation: 1,
            history: Vec::new(),
        },
    );
    Ok(StateMutation {
        value: TaskMutationMarker {
            task,
            idempotent: false,
        },
        changed: true,
    })
}

fn claim_task_op(
    state: &mut GraphStoreState,
    request: TaskClaimRequest,
    now: GraphLogicalTime,
    duration_ms: u64,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    validate_request(&request)?;
    ensure_reasoning_descriptor_for_request(state, &request)?;
    now.validate().map_err(GraphStoreError::Admission)?;
    if now < state.logical_time_high_water {
        return Err(GraphStoreError::InvalidTransition {
            reason: format!(
                "claim logical time regressed below persisted high-water {}",
                state.logical_time_high_water
            ),
        });
    }
    let existing = state.tasks.get(&request.task_id).cloned();
    if let Some(ref existing) = existing {
        let pending_rebind = existing.task.state == TaskState::Pending
            && same_pending_work_identity(&existing.task.request, &request);
        if !same_claim_identity(&existing.task.request, &request) && !pending_rebind {
            if existing.task.state == TaskState::Claimed {
                return Err(GraphStoreError::AlreadyClaimed {
                    task_id: request.task_id,
                    holder: existing
                        .task
                        .lease
                        .as_ref()
                        .map(|lease| lease.holder.clone()),
                });
            }
            return Err(GraphStoreError::TaskExists {
                task_id: request.task_id,
            });
        }
        if existing.task.state == TaskState::Claimed {
            if existing
                .task
                .lease
                .as_ref()
                .is_some_and(|lease| now >= lease.expires_at)
            {
                return Err(GraphStoreError::TaskExpiredNeedsReclaim {
                    task_id: request.task_id,
                });
            }
            return Ok(StateMutation {
                value: TaskMutationMarker {
                    task: existing.task.clone(),
                    idempotent: true,
                },
                changed: false,
            });
        }
        if matches!(
            existing.task.state,
            TaskState::Completed | TaskState::Failed
        ) {
            return Err(GraphStoreError::InvalidTransition {
                reason: "terminal tasks cannot be claimed".to_string(),
            });
        }
        if existing.task.state == TaskState::Expired {
            return Err(GraphStoreError::TaskExpiredNeedsReclaim {
                task_id: request.task_id,
            });
        }
    }
    observe_logical_time(state, now)?;
    let fence = next_fence(state)?;
    let lease = lease_for(
        state.graph_id.as_str(),
        request.task_id.as_str(),
        &request.claimant,
        now,
        duration_ms,
        fence,
        limits,
    )?;
    let claim_request = existing.as_ref().map_or_else(
        || request.clone(),
        |entry| {
            if entry.task.state == TaskState::Pending {
                request.clone()
            } else {
                entry.task.request.clone()
            }
        },
    );
    let task =
        if let Some(mut existing) = existing {
            if existing.task.state != TaskState::Pending {
                return Err(GraphStoreError::InvalidTransition {
                    reason: "only pending tasks can be newly claimed".to_string(),
                });
            }
            existing.task = TaskRecord::claimed_with_limits(
                claim_request,
                lease,
                limits.max_task_lease_ms,
                limits.max_task_retries,
            )
            .map_err(GraphStoreError::Admission)?;
            existing.generation = existing.generation.checked_add(1).ok_or_else(|| {
                GraphStoreError::InvalidState {
                    reason: "task generation overflow".to_string(),
                }
            })?;
            let task = existing.task.clone();
            state.tasks.insert(task.request.task_id.clone(), existing);
            task
        } else {
            let task = TaskRecord::claimed_with_limits(
                claim_request,
                lease,
                limits.max_task_lease_ms,
                limits.max_task_retries,
            )
            .map_err(GraphStoreError::Admission)?;
            state.tasks.insert(
                task.request.task_id.clone(),
                DurableTaskRecord {
                    schema_version: GRAPH_STORE_SCHEMA_VERSION,
                    task: task.clone(),
                    generation: 1,
                    history: Vec::new(),
                },
            );
            task
        };
    Ok(StateMutation {
        value: TaskMutationMarker {
            task,
            idempotent: false,
        },
        changed: true,
    })
}

fn claim_task_with_budget_op(
    state: &mut GraphStoreState,
    request: TaskClaimRequest,
    now: GraphLogicalTime,
    duration_ms: u64,
    scheduler_budget: SchedulerBudget,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    let task_id = request.task_id.clone();
    let prior_budget = state.scheduler_budget.clone();
    let result = claim_task_op(state, request, now, duration_ms, limits)?;
    if result.changed {
        validate_exact_scheduler_budget_delta(
            prior_budget.as_ref(),
            Some(&scheduler_budget),
            Some(now),
            0,
            1,
        )?;
        // CAS-bound callers bypass `transition`'s convenience-only tombstone
        // refresh.  Claiming an existing pending record therefore has to
        // refresh its derived monotonic witness here, before the budget and
        // task are published in the same signed generation.  This also binds
        // the history digest after a marker-0 -> marker-1 migration while
        // preserving the idempotent retry path below.
        // Only the claimed task is refreshed: direct reasoning CAS forbids
        // rewriting an untouched task's legacy tombstone as a side effect.
        refresh_task_tombstone(state, &task_id, false)?;
        state.scheduler_budget = Some(scheduler_budget);
    } else {
        validate_exact_scheduler_budget_delta(
            prior_budget.as_ref(),
            Some(&scheduler_budget),
            None,
            0,
            0,
        )?;
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn renew_task_op(
    state: &mut GraphStoreState,
    task_id: &str,
    expected_generation: u64,
    lease_id: &LeaseId,
    fence: FencingToken,
    now: GraphLogicalTime,
    duration_ms: u64,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    observe_logical_time(state, now)?;
    let entry = task_entry_mut(state, task_id)?;
    ensure_task_generation(entry, expected_generation)?;
    let old_lease = ensure_lease(entry, lease_id, fence)?;
    if entry.task.state != TaskState::Claimed {
        return Err(GraphStoreError::InvalidTransition {
            reason: "only claimed tasks can renew".to_string(),
        });
    }
    if now < old_lease.issued_at {
        return Err(GraphStoreError::InvalidTransition {
            reason: "renewal clock precedes lease issuance".to_string(),
        });
    }
    if now >= old_lease.expires_at {
        return Err(GraphStoreError::LeaseExpired {
            task_id: entry.task.request.task_id.clone(),
        });
    }
    let renewed = TaskLease::new(
        old_lease.lease_id.clone(),
        old_lease.holder.clone(),
        now,
        now.checked_add(
            i64::try_from(duration_ms).map_err(|_| GraphStoreError::InvalidLease {
                reason: "duration does not fit logical time".to_string(),
            })?,
        )
        .ok_or_else(|| GraphStoreError::InvalidLease {
            reason: "renewal expiry overflows logical time".to_string(),
        })?,
        old_lease.fencing_token,
    )
    .map_err(GraphStoreError::Admission)?;
    renewed
        .validate_with_limit(limits.max_task_lease_ms)
        .map_err(GraphStoreError::Admission)?;
    entry.task.lease = Some(renewed);
    entry.generation =
        entry
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: entry.task.clone(),
            idempotent: false,
        },
        changed: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn complete_task_op(
    state: &mut GraphStoreState,
    task_id: &str,
    expected_generation: u64,
    lease_id: &LeaseId,
    fence: FencingToken,
    now: GraphLogicalTime,
    completion: TaskCompletion,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    reject_reasoning_terminal_transition(state)?;
    observe_logical_time(state, now)?;
    let entry = task_entry_mut(state, task_id)?;
    ensure_task_generation(entry, expected_generation)?;
    let lease = ensure_lease(entry, lease_id, fence)?;
    if now < lease.issued_at {
        return Err(GraphStoreError::InvalidTransition {
            reason: "completion clock precedes lease issuance".to_string(),
        });
    }
    if now >= lease.expires_at {
        return Err(GraphStoreError::LeaseExpired {
            task_id: entry.task.request.task_id.clone(),
        });
    }
    if completion.completed_at > now {
        return Err(GraphStoreError::InvalidTransition {
            reason: "completion time is ahead of the injected logical clock".to_string(),
        });
    }
    let task = entry
        .task
        .clone()
        .complete(completion, fence, limits.max_task_lease_ms)
        .map_err(GraphStoreError::Admission)?;
    entry.task = task;
    entry.generation =
        entry
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: entry.task.clone(),
            idempotent: false,
        },
        changed: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn fail_task_op(
    state: &mut GraphStoreState,
    task_id: &str,
    expected_generation: u64,
    lease_id: &LeaseId,
    fence: FencingToken,
    now: GraphLogicalTime,
    failure: TaskFailure,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    reject_reasoning_terminal_transition(state)?;
    observe_logical_time(state, now)?;
    let entry = task_entry_mut(state, task_id)?;
    ensure_task_generation(entry, expected_generation)?;
    let lease = ensure_lease(entry, lease_id, fence)?;
    if entry.task.state != TaskState::Claimed {
        return Err(GraphStoreError::InvalidTransition {
            reason: "only claimed tasks can fail".to_string(),
        });
    }
    if now < lease.issued_at {
        return Err(GraphStoreError::InvalidTransition {
            reason: "failure clock precedes lease issuance".to_string(),
        });
    }
    if now >= lease.expires_at {
        return Err(GraphStoreError::LeaseExpired {
            task_id: entry.task.request.task_id.clone(),
        });
    }
    failure.validate()?;
    if failure.failed_at > now {
        return Err(GraphStoreError::InvalidTransition {
            reason: "failure time is ahead of the injected logical clock".to_string(),
        });
    }
    if failure.failed_at < lease.issued_at || failure.failed_at > lease.expires_at {
        return Err(GraphStoreError::InvalidTransition {
            reason: "failure time must fall within the active lease".to_string(),
        });
    }
    let proof = TaskTerminalProof::new(
        entry.task.generation,
        lease,
        TaskState::Failed,
        failure.failed_by,
        failure.failed_at,
        limits.max_task_lease_ms,
    )
    .map_err(GraphStoreError::Admission)?;
    entry.task.terminal_history.push(proof);
    entry.task.state = TaskState::Failed;
    entry.task.generation = entry.task.generation.saturating_add(1);
    entry.task.lease = None;
    entry.task.completion = None;
    entry.generation =
        entry
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: entry.task.clone(),
            idempotent: false,
        },
        changed: true,
    })
}

fn fail_reasoning_task_op(
    state: &mut GraphStoreState,
    expected_generation: u64,
    publication: TaskFailureOutboxEntry,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    if let Some(marker) = exact_reasoning_failure_retry(state, &publication)? {
        return Ok(StateMutation {
            value: marker,
            changed: false,
        });
    }
    if state.migration_marker < GRAPH_STATE_MIGRATION_HYPOTHESES {
        return Err(GraphStoreError::InvalidTransition {
            reason: "descriptor-bound reasoning failure requires a marker-1 graph".to_string(),
        });
    }
    let task_id = publication.task_id.clone();
    let descriptor = state
        .logical_task_descriptors
        .get(&task_id)
        .cloned()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "reasoning failure task has no logical descriptor".to_string(),
        })?;
    let prior =
        state
            .tasks
            .get(&task_id)
            .cloned()
            .ok_or_else(|| GraphStoreError::TaskNotFound {
                task_id: task_id.to_string(),
            })?;
    ensure_task_generation(&prior, expected_generation)?;
    publication.validate_for_claimed_task(
        &prior.task,
        &descriptor,
        state.logical_time_high_water,
    )?;
    observe_logical_time(state, publication.failure.failed_at)?;
    let lease = prior
        .task
        .lease
        .as_ref()
        .ok_or_else(|| GraphStoreError::InvalidTransition {
            reason: "reasoning failure requires an active lease".to_string(),
        })?;
    let proof = TaskTerminalProof::new_failed(
        prior.task.generation,
        lease.clone(),
        publication.failure.failed_by.clone(),
        publication.failure.failed_at,
        publication.failure.summary_digest.clone(),
        limits.max_task_lease_ms,
    )
    .map_err(GraphStoreError::Admission)?;
    let failed_task = {
        let entry = task_entry_mut(state, task_id.as_str())?;
        entry.task.terminal_history.push(proof);
        entry.task.state = TaskState::Failed;
        entry.task.generation = entry.task.generation.saturating_add(1);
        entry.task.lease = None;
        entry.task.completion = None;
        entry.generation =
            entry
                .generation
                .checked_add(1)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "task generation overflow".to_string(),
                })?;
        entry.task.clone()
    };
    refresh_task_tombstone(state, &task_id, false)?;
    if state
        .task_failure_outbox
        .insert(task_id, publication)
        .is_some()
    {
        return Err(GraphStoreError::InvalidState {
            reason: "reasoning failure attempted to replace its durable outbox".to_string(),
        });
    }
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: failed_task,
            idempotent: false,
        },
        changed: true,
    })
}

fn exact_reasoning_failure_retry(
    state: &GraphStoreState,
    publication: &TaskFailureOutboxEntry,
) -> Result<Option<TaskMutationMarker>, GraphStoreError> {
    let Some(committed) = state.task_failure_outbox.get(&publication.task_id) else {
        return Ok(None);
    };
    let task =
        state
            .tasks
            .get(&publication.task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "reasoning failure outbox has no retained durable task".to_string(),
            })?;
    let descriptor = state
        .logical_task_descriptors
        .get(&publication.task_id)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "reasoning failure outbox has no logical descriptor".to_string(),
        })?;
    committed.validate_for_failed_task(&task.task, descriptor, state.logical_time_high_water)?;
    if committed != publication {
        return Err(GraphStoreError::InvalidTransition {
            reason: "reasoning failure retry differs from the committed task publication"
                .to_string(),
        });
    }
    Ok(Some(TaskMutationMarker {
        task: task.task.clone(),
        idempotent: true,
    }))
}

fn expire_task_op(
    state: &mut GraphStoreState,
    task_id: &str,
    expected_generation: u64,
    now: GraphLogicalTime,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    observe_logical_time(state, now)?;
    {
        let entry = task_entry_mut(state, task_id)?;
        ensure_task_generation(entry, expected_generation)?;
        if entry.task.state != TaskState::Claimed {
            return Err(GraphStoreError::InvalidTransition {
                reason: "only claimed tasks can expire".to_string(),
            });
        }
        entry.task = entry
            .task
            .clone()
            .expire(now, limits.max_task_lease_ms)
            .map_err(GraphStoreError::Admission)?;
    }
    // Expiry is itself a fencing barrier.  Advance the durable counter before
    // publishing the expired record so the token of the expired lease can
    // never authorize a later operation, including after a restart.
    next_fence(state)?;
    let entry = task_entry_mut(state, task_id)?;
    entry.generation =
        entry
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: entry.task.clone(),
            idempotent: false,
        },
        changed: true,
    })
}

fn reclaim_task_op(
    state: &mut GraphStoreState,
    task_id: &str,
    request: TaskClaimRequest,
    now: GraphLogicalTime,
    duration_ms: u64,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    validate_request(&request)?;
    ensure_reasoning_descriptor_for_request(state, &request)?;
    observe_logical_time(state, now)?;
    if request.task_id.as_str() != task_id {
        return Err(GraphStoreError::InvalidTransition {
            reason: "reclaim request task ID differs from target".to_string(),
        });
    }
    let old = state
        .tasks
        .get(&TaskId::new(task_id))
        .ok_or_else(|| GraphStoreError::TaskNotFound {
            task_id: task_id.to_string(),
        })?
        .clone();
    if old.task.state != TaskState::Expired {
        return Err(GraphStoreError::InvalidTransition {
            reason: "reclaim requires an expired task".to_string(),
        });
    }
    if old.task.request.kind != request.kind
        || old.task.request.target != request.target
        || old.task.request.role != request.role
        || old.task.request.evidence_scope != request.evidence_scope
    {
        return Err(GraphStoreError::InvalidTransition {
            reason: "reclaim cannot change task target, role, or evidence scope".to_string(),
        });
    }
    if old.task.attempts >= limits.max_task_retries {
        return Err(GraphStoreError::ResourceLimit {
            resource: "task.retries".to_string(),
            limit: usize::from(limits.max_task_retries),
        });
    }
    let fence = next_fence(state)?;
    let lease = lease_for(
        state.graph_id.as_str(),
        task_id,
        &request.claimant,
        now,
        duration_ms,
        fence,
        limits,
    )?;
    let mut task = TaskRecord::claimed_with_limits(
        request,
        lease,
        limits.max_task_lease_ms,
        limits.max_task_retries,
    )
    .map_err(GraphStoreError::Admission)?;
    task.attempts = old.task.attempts.saturating_add(1);
    // A claimed core record cannot carry the prior terminal history by design;
    // it is retained in the spine wrapper instead.
    let entry = state.tasks.get_mut(&TaskId::new(task_id)).ok_or_else(|| {
        GraphStoreError::TaskNotFound {
            task_id: task_id.to_string(),
        }
    })?;
    entry.history.push(old.task);
    entry.task = task;
    entry.generation =
        entry
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: entry.task.clone(),
            idempotent: false,
        },
        changed: true,
    })
}

/// Reclaim is a new claim attempt: it consumes one claim-capacity unit, but
/// no work unit. The task history/tombstone and budget are committed in one
/// generation. An exact retry of an active reclaimed lease is idempotent and
/// therefore does not charge a second claim.
fn reclaim_task_with_budget_op(
    state: &mut GraphStoreState,
    task_id: &str,
    request: TaskClaimRequest,
    now: GraphLogicalTime,
    duration_ms: u64,
    scheduler_budget: SchedulerBudget,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    validate_request(&request)?;
    ensure_reasoning_descriptor_for_request(state, &request)?;
    now.validate().map_err(GraphStoreError::Admission)?;
    let prior_budget = state.scheduler_budget.clone();
    let task_key = TaskId::new(task_id);
    let idempotent = state.tasks.get(&task_key).is_some_and(|entry| {
        entry.task.state == TaskState::Claimed && same_claim_identity(&entry.task.request, &request)
    });
    if idempotent {
        let entry = state
            .tasks
            .get(&task_key)
            .ok_or_else(|| GraphStoreError::TaskNotFound {
                task_id: task_id.to_string(),
            })?;
        if entry
            .task
            .lease
            .as_ref()
            .is_some_and(|lease| now >= lease.expires_at)
        {
            return Err(GraphStoreError::TaskExpiredNeedsReclaim {
                task_id: task_key.clone(),
            });
        }
        validate_exact_scheduler_budget_delta(
            prior_budget.as_ref(),
            Some(&scheduler_budget),
            None,
            0,
            0,
        )?;
        let task = entry.task.clone();
        observe_logical_time(state, now)?;
        return Ok(StateMutation {
            value: TaskMutationMarker {
                task,
                idempotent: true,
            },
            changed: false,
        });
    }

    let result = reclaim_task_op(state, task_id, request, now, duration_ms, limits)?;
    if result.changed {
        validate_exact_scheduler_budget_delta(
            prior_budget.as_ref(),
            Some(&scheduler_budget),
            Some(now),
            0,
            1,
        )?;
        refresh_task_tombstone(state, &task_key, false)?;
        state.scheduler_budget = Some(scheduler_budget);
    }
    Ok(result)
}

#[derive(Debug, Clone)]
struct TaskMutationMarker {
    task: TaskRecord,
    idempotent: bool,
}

/// A failure is terminal just like completion, but deliberately does not
/// smuggle arbitrary error text into the graph ledger.  The summary is a
/// bounded digest/reference supplied by the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskFailure {
    pub failed_by: AgentId,
    pub failed_at: GraphLogicalTime,
    pub summary_digest: String,
}

impl TaskFailure {
    pub fn new(
        failed_by: AgentId,
        failed_at: GraphLogicalTime,
        summary_digest: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let failure = Self {
            failed_by,
            failed_at,
            summary_digest: summary_digest.into(),
        };
        failure.validate()?;
        Ok(failure)
    }

    pub fn validate(&self) -> Result<(), GraphStoreError> {
        if self.failed_by.0.trim().is_empty() || self.failed_by.0.len() > 256 {
            return Err(GraphStoreError::InvalidState {
                reason: "failure actor identity is invalid".to_string(),
            });
        }
        self.failed_at
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if self.summary_digest.trim().is_empty() || self.summary_digest.len() > 128 {
            return Err(GraphStoreError::InvalidState {
                reason: "failure summary digest is invalid".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskFailureOutboxEntry {
    pub task_id: TaskId,
    pub lease_id: LeaseId,
    pub fencing_token: FencingToken,
    pub failure: TaskFailure,
    pub capability: TaskCapabilityProof,
    pub witness: EvidenceWitness,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct TaskFailureOutboxMaterial<'a> {
    task_id: &'a TaskId,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    failure: &'a TaskFailure,
    capability: &'a TaskCapabilityProof,
    scope: &'a str,
}

impl TaskFailureOutboxEntry {
    pub fn new(
        task: &TaskRecord,
        descriptor: &LogicalTaskDescriptor,
        failure: TaskFailure,
        capability: TaskCapabilityProof,
        signer: &Keypair,
        scope: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "reasoning failure publication requires an active lease".to_string(),
            })?;
        let scope = scope.into();
        let material = TaskFailureOutboxMaterial {
            task_id: &task.request.task_id,
            lease_id: &lease.lease_id,
            fencing_token: lease.fencing_token,
            failure: &failure,
            capability: &capability,
            scope: &scope,
        };
        let bytes =
            canonical_json_bytes(&material).map_err(|error| GraphStoreError::Canonicalization {
                reason: error.to_string(),
            })?;
        let witness = EvidenceWitness::new(signer, task.request.role, scope, &bytes)
            .map_err(GraphStoreError::Admission)?;
        let entry = Self {
            task_id: task.request.task_id.clone(),
            lease_id: lease.lease_id.clone(),
            fencing_token: lease.fencing_token,
            failure,
            capability,
            witness,
        };
        entry.validate_for_claimed_task(task, descriptor, GraphLogicalTime::new(0))?;
        Ok(entry)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskFailureOutboxMaterial {
            task_id: &self.task_id,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            failure: &self.failure,
            capability: &self.capability,
            scope: &self.witness.scoped_agent_id,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn validate_common(
        &self,
        task: &TaskRecord,
        descriptor: &LogicalTaskDescriptor,
        logical_time_high_water: GraphLogicalTime,
    ) -> Result<(), GraphStoreError> {
        self.failure.validate()?;
        descriptor.validate().map_err(GraphStoreError::Admission)?;
        self.capability
            .validate_for_claim(&task.request)
            .map_err(GraphStoreError::Admission)?;
        if descriptor.task_id != self.task_id
            || descriptor.task_id != task.request.task_id
            || descriptor.target != task.request.target
            || descriptor.kind != task.request.kind
            || self.failure.failed_by != task.request.claimant
            || self.witness.producer_identity != task.request.claimant
            || self.witness.producer_role != task.request.role
            || self.failure.failed_at < logical_time_high_water
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning failure publication does not bind task, descriptor, claimant, or logical time"
                    .to_string(),
            });
        }
        self.witness
            .validate(&self.canonical_bytes()?)
            .map_err(GraphStoreError::Admission)
    }

    pub fn validate_for_claimed_task(
        &self,
        task: &TaskRecord,
        descriptor: &LogicalTaskDescriptor,
        logical_time_high_water: GraphLogicalTime,
    ) -> Result<(), GraphStoreError> {
        self.validate_common(task, descriptor, logical_time_high_water)?;
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "reasoning failure publication requires the prior active lease".to_string(),
            })?;
        if task.state != TaskState::Claimed
            || task.completion.is_some()
            || self.lease_id != lease.lease_id
            || self.fencing_token != lease.fencing_token
            || self.failure.failed_by != lease.holder
            || self.failure.failed_at < lease.issued_at
            || self.failure.failed_at >= lease.expires_at
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning failure publication does not bind the active lease".to_string(),
            });
        }
        Ok(())
    }

    pub fn validate_for_failed_task(
        &self,
        task: &TaskRecord,
        descriptor: &LogicalTaskDescriptor,
        logical_time_high_water: GraphLogicalTime,
    ) -> Result<(), GraphStoreError> {
        self.validate_common(task, descriptor, GraphLogicalTime::new(0))?;
        let proof = task
            .terminal_history
            .last()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "failed reasoning task has no terminal proof".to_string(),
            })?;
        if task.state != TaskState::Failed
            || task.lease.is_some()
            || task.completion.is_some()
            || proof.terminal_state != TaskState::Failed
            || proof.completer != self.failure.failed_by
            || proof.completed_at != self.failure.failed_at
            || proof.failure_summary_digest.as_ref() != Some(&self.failure.summary_digest)
            || proof.prior_lease.lease_id != self.lease_id
            || proof.prior_lease.fencing_token != self.fencing_token
            || self.failure.failed_at > logical_time_high_water
        {
            return Err(GraphStoreError::InvalidState {
                reason: "reasoning failure outbox does not match the durable failed task"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Result returned by task claims and every successful task mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskMutationResult {
    pub task: TaskRecord,
    pub lease: Option<TaskLease>,
    pub generation: u64,
    pub task_generation: u64,
    pub revision: GraphStoreRevision,
    pub idempotent: bool,
}

pub type TaskClaimResult = TaskMutationResult;
pub type TaskTerminalResult = TaskMutationResult;

/// Errors are intentionally explicit so callers can distinguish an ordinary
/// duplicate from a stale writer or stale worker and avoid doing evidence work
/// after a refused transition.
#[derive(Debug, thiserror::Error)]
pub enum GraphStoreError {
    #[error("store lock poisoned")]
    PoisonedLock,
    #[error("unsupported store schema version {0}")]
    UnsupportedSchema(u32),
    #[error("graph admission failed: {0}")]
    Admission(#[source] GraphAdmissionError),
    #[error("canonicalization failed: {reason}")]
    Canonicalization { reason: String },
    #[error("invalid persisted state: {reason}")]
    InvalidState { reason: String },
    #[error("resource `{resource}` exceeded limit {limit}")]
    ResourceLimit { resource: String, limit: usize },
    #[error("invalid signature: {reason}")]
    InvalidSignature { reason: String },
    #[error("store signer mismatch: expected `{expected}`, observed `{observed}`")]
    SignerMismatch {
        expected: AgentId,
        observed: AgentId,
    },
    #[error("persisted state digest mismatch: expected `{expected}`, observed `{observed}`")]
    DigestMismatch { expected: String, observed: String },
    #[error(
        "stale predecessor: expected generation {expected_generation} digest `{expected_digest}`, observed generation {observed_generation} digest `{observed_digest}`"
    )]
    StalePredecessor {
        expected_generation: u64,
        expected_digest: String,
        observed_generation: u64,
        observed_digest: String,
    },
    #[error("task `{task_id}` already exists")]
    TaskExists {
        task_id: swarm_core::hypothesis_graph::TaskId,
    },
    #[error("task `{task_id}` was not found")]
    TaskNotFound { task_id: String },
    #[error("task `{task_id}` is already claimed by {holder:?}")]
    AlreadyClaimed {
        task_id: swarm_core::hypothesis_graph::TaskId,
        holder: Option<AgentId>,
    },
    #[error("task `{task_id}` is expired and must be reclaimed")]
    TaskExpiredNeedsReclaim {
        task_id: swarm_core::hypothesis_graph::TaskId,
    },
    #[error("task `{task_id}` generation mismatch: expected {expected}, observed {observed}")]
    StaleTaskGeneration {
        task_id: swarm_core::hypothesis_graph::TaskId,
        expected: u64,
        observed: u64,
    },
    #[error("task `{task_id}` has no active lease")]
    LeaseMissing {
        task_id: swarm_core::hypothesis_graph::TaskId,
    },
    #[error("task `{task_id}` lease mismatch: expected `{expected}`, observed `{observed}`")]
    StaleLease {
        task_id: swarm_core::hypothesis_graph::TaskId,
        expected: LeaseId,
        observed: LeaseId,
    },
    #[error("task `{task_id}` fencing mismatch: expected {expected:?}, observed {observed:?}")]
    StaleFence {
        task_id: swarm_core::hypothesis_graph::TaskId,
        expected: FencingToken,
        observed: FencingToken,
    },
    #[error("task `{task_id}` lease has expired")]
    LeaseExpired {
        task_id: swarm_core::hypothesis_graph::TaskId,
    },
    #[error("invalid lease: {reason}")]
    InvalidLease { reason: String },
    #[error("task transition is invalid: {reason}")]
    InvalidTransition { reason: String },
    #[error("state file is missing at `{path}`")]
    MissingState { path: PathBuf },
    #[error("state high-water anchor is missing at `{path}`")]
    MissingAnchor { path: PathBuf },
    #[error("state external high-water mark is missing at `{path}`")]
    MissingHighWater { path: PathBuf },
    #[error(
        "state high-water anchor mismatch: expected generation {expected_generation} digest `{expected_digest}`, observed generation {observed_generation} digest `{observed_digest}`"
    )]
    AnchorMismatch {
        expected_generation: u64,
        expected_digest: String,
        observed_generation: u64,
        observed_digest: String,
    },
    #[error(
        "state replay detected: persisted generation {observed_generation} is behind anchored generation {expected_generation}"
    )]
    ReplayDetected {
        expected_generation: u64,
        observed_generation: u64,
    },
    #[error("state path `{path}` is not a regular file")]
    NotRegularFile { path: PathBuf },
    #[error("file-store lock is held at `{path}`")]
    LockContended { path: PathBuf },
    #[error("file-store lock binding changed at `{path}`: {reason}")]
    LockBinding { path: PathBuf, reason: String },
    #[error("insecure permissions on `{path}`: expected mode {expected:o}, observed {observed:o}")]
    InsecurePermissions {
        path: PathBuf,
        expected: u32,
        observed: u32,
    },
    #[error("failed to read `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to serialize `{path}`: {source}")]
    Serialize {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Durable graph/task store contract.  Every convenience mutation reads the
/// current signed state; the `_cas` variants additionally bind the operation
/// to a caller-supplied generation/digest predecessor.
pub trait HypothesisGraphStore: Send + Sync {
    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError>;
    fn compare_and_swap(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
    ) -> Result<GraphStoreSnapshot, GraphStoreError>;
    /// Commit one coordinator-built seed generation whose initial decision
    /// history is authenticated by coordinator-scoped record witnesses.
    /// Ordinary CAS deliberately rejects initial decision history so callers
    /// cannot bypass the runtime signer's admission boundary.
    fn compare_and_swap_coordinator_seed(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
        coordinator_identity: &AgentId,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let _ = (expected, state, coordinator_identity);
        Err(GraphStoreError::InvalidTransition {
            reason: "store backend does not implement authenticated coordinator seed admission"
                .to_string(),
        })
    }
    fn create_task(&self, request: TaskClaimRequest)
    -> Result<TaskMutationResult, GraphStoreError>;
    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError>;
    fn claim_task(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError>;
    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError>;
    /// Claim a task and publish the caller's next scheduler budget in one
    /// signed generation. The budget is charged only when the claim changes
    /// durable task state; an idempotent retry leaves it untouched.
    fn claim_task_with_budget(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let _ = (request, now, lease_duration_ms, scheduler_budget);
        Err(GraphStoreError::InvalidTransition {
            reason: "store backend does not implement atomic claim-plus-budget admission"
                .to_string(),
        })
    }
    /// CAS-bound variant of [`Self::claim_task_with_budget`].
    fn claim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let _ = (expected, request, now, lease_duration_ms, scheduler_budget);
        Err(GraphStoreError::InvalidTransition {
            reason: "store backend does not implement atomic claim-plus-budget admission"
                .to_string(),
        })
    }
    /// Reclaim an expired task and publish the caller's next scheduler budget
    /// in one signed generation. Reclaim consumes one claim-capacity unit and
    /// no work unit; an exact retry of the active reclaimed lease is
    /// idempotent and leaves the budget untouched.
    fn reclaim_task_with_budget(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let _ = (task_id, request, now, lease_duration_ms, scheduler_budget);
        Err(GraphStoreError::InvalidTransition {
            reason: "store backend does not implement atomic reclaim-plus-budget admission"
                .to_string(),
        })
    }
    /// CAS-bound variant of [`Self::reclaim_task_with_budget`].
    fn reclaim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let _ = (
            expected,
            task_id,
            request,
            now,
            lease_duration_ms,
            scheduler_budget,
        );
        Err(GraphStoreError::InvalidTransition {
            reason: "store backend does not implement atomic reclaim-plus-budget admission"
                .to_string(),
        })
    }
    fn renew_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskMutationResult, GraphStoreError>;
    fn complete_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        completion: TaskCompletion,
    ) -> Result<TaskTerminalResult, GraphStoreError>;
    fn fail_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        failure: TaskFailure,
    ) -> Result<TaskTerminalResult, GraphStoreError>;
    fn fail_reasoning_task_cas(
        &self,
        expected: &GraphStoreRevision,
        expected_generation: u64,
        publication: TaskFailureOutboxEntry,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let _ = (expected, expected_generation, publication);
        Err(GraphStoreError::InvalidTransition {
            reason: "store backend does not implement atomic reasoning failure publication"
                .to_string(),
        })
    }
    fn expire_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        now: GraphLogicalTime,
    ) -> Result<TaskTerminalResult, GraphStoreError>;
    fn reclaim_task(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError>;
}

pub trait TaskStore: HypothesisGraphStore {}

impl<T> TaskStore for T where T: HypothesisGraphStore + ?Sized {}

#[derive(Debug, Clone)]
pub struct MemoryHypothesisGraphStore {
    inner: Arc<RwLock<SignedGraphStoreState>>,
    signer: Keypair,
    limits: GraphResourceLimits,
    scheduler_policy: SchedulerBudgetPolicy,
    graph_id: GraphId,
    signer_id: AgentId,
}

impl MemoryHypothesisGraphStore {
    pub fn new(graph: HypothesisGraph, signer: Keypair) -> Result<Self, GraphStoreError> {
        Self::new_with_scheduler_policy(graph, signer, SchedulerBudgetPolicy::global())
    }

    pub fn new_with_config(
        graph: HypothesisGraph,
        signer: Keypair,
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphStoreError> {
        if graph.limits != config.resource_limits() {
            return Err(GraphStoreError::InvalidState {
                reason: "graph limits do not match the configured scheduler deployment".to_string(),
            });
        }
        let scheduler_policy =
            SchedulerBudgetPolicy::from_config(config).map_err(GraphStoreError::Admission)?;
        Self::new_with_scheduler_policy(graph, signer, scheduler_policy)
    }

    pub fn new_with_scheduler_policy(
        graph: HypothesisGraph,
        signer: Keypair,
        scheduler_policy: SchedulerBudgetPolicy,
    ) -> Result<Self, GraphStoreError> {
        let limits = graph.limits.clone();
        let graph_id = graph.graph_id.clone();
        let signer_id = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let state = GraphStoreState::new(graph)?;
        let signed = sign_state(state, &signer, &limits)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(signed)),
            signer,
            limits,
            scheduler_policy,
            graph_id,
            signer_id,
        })
    }

    pub fn from_graph(graph: HypothesisGraph, signer: Keypair) -> Result<Self, GraphStoreError> {
        Self::new(graph, signer)
    }

    pub fn open(
        graph_id: GraphId,
        limits: GraphResourceLimits,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        let graph = HypothesisGraph::new(graph_id, limits).map_err(GraphStoreError::Admission)?;
        Self::new(graph, signer)
    }

    pub fn open_with_config(
        graph_id: GraphId,
        limits: GraphResourceLimits,
        signer: Keypair,
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphStoreError> {
        let graph = HypothesisGraph::new(graph_id, limits).map_err(GraphStoreError::Admission)?;
        Self::new_with_config(graph, signer, config)
    }

    fn read_signed(&self) -> Result<SignedGraphStoreState, GraphStoreError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| GraphStoreError::PoisonedLock)?;
        verify_state(
            &guard,
            &self.graph_id,
            &self.signer_id,
            &self.limits,
            &self.scheduler_policy,
        )?;
        Ok(guard.clone())
    }

    fn mutate<R, F>(
        &self,
        expected: Option<&GraphStoreRevision>,
        operation: F,
    ) -> Result<(GraphStoreSnapshot, R), GraphStoreError>
    where
        F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
    {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| GraphStoreError::PoisonedLock)?;
        verify_state(
            &guard,
            &self.graph_id,
            &self.signer_id,
            &self.limits,
            &self.scheduler_policy,
        )?;
        let (next, value) = transition(
            &guard,
            expected,
            &self.signer,
            &self.limits,
            &self.scheduler_policy,
            operation,
        )?;
        if next != *guard {
            *guard = next;
        }
        Ok((guard.snapshot()?, value))
    }

    fn mutate_with_exact_retry<R, P, F>(
        &self,
        expected: Option<&GraphStoreRevision>,
        exact_retry: P,
        operation: F,
    ) -> Result<(GraphStoreSnapshot, R), GraphStoreError>
    where
        P: FnOnce(&GraphStoreState) -> Result<Option<R>, GraphStoreError>,
        F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
    {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| GraphStoreError::PoisonedLock)?;
        verify_state(
            &guard,
            &self.graph_id,
            &self.signer_id,
            &self.limits,
            &self.scheduler_policy,
        )?;
        let (next, value) = transition_with_exact_retry(
            &guard,
            expected,
            &self.signer,
            &self.limits,
            &self.scheduler_policy,
            exact_retry,
            operation,
        )?;
        if next != *guard {
            *guard = next;
        }
        Ok((guard.snapshot()?, value))
    }

    pub fn revision(&self) -> Result<GraphStoreRevision, GraphStoreError> {
        self.snapshot().map(|snapshot| snapshot.revision)
    }

    pub fn state_digest(&self) -> Result<String, GraphStoreError> {
        self.snapshot().map(|snapshot| snapshot.revision.digest)
    }

    pub fn signer_id(&self) -> &AgentId {
        &self.signer_id
    }

    fn result_from_marker(
        snapshot: GraphStoreSnapshot,
        marker: TaskMutationMarker,
    ) -> TaskMutationResult {
        let task_generation = snapshot
            .state
            .tasks
            .get(&marker.task.request.task_id)
            .map_or(0, |entry| entry.generation);
        TaskMutationResult {
            task: marker.task.clone(),
            lease: marker.task.lease.clone(),
            generation: snapshot.revision.generation,
            task_generation,
            revision: snapshot.revision,
            idempotent: marker.idempotent,
        }
    }

    fn compare_and_swap_reasoning(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
        initial_decision_admission: InitialDecisionAdmission<'_>,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let (snapshot, _) = self.mutate(Some(expected), |current| {
            if state.graph_id != self.graph_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "replacement graph ID differs from store stream".to_string(),
                });
            }
            if state.generation != current.generation
                || state.predecessor_digest != current.predecessor_digest
            {
                return Err(GraphStoreError::StalePredecessor {
                    expected_generation: current.generation,
                    expected_digest: current.digest()?,
                    observed_generation: state.generation,
                    observed_digest: state.digest()?,
                });
            }
            if state.fencing_counter < current.fencing_counter {
                return Err(GraphStoreError::InvalidState {
                    reason: "compare-and-swap candidate fencing counter regressed".to_string(),
                });
            }
            if state.logical_time_high_water < current.logical_time_high_water {
                return Err(GraphStoreError::InvalidState {
                    reason: "compare-and-swap candidate logical time high-water regressed"
                        .to_string(),
                });
            }
            state.validate_with_limits(&self.limits)?;
            validate_reasoning_cas_transition(
                current,
                &state,
                &self.limits,
                &self.scheduler_policy,
                initial_decision_admission,
            )?;
            current.graph = state.graph;
            current.hypotheses = state.hypotheses;
            current.tasks = state.tasks;
            current.logical_task_descriptors = state.logical_task_descriptors;
            current.task_tombstones = state.task_tombstones;
            current.terminal_outbox = state.terminal_outbox;
            current.task_failure_outbox = state.task_failure_outbox;
            current.fencing_counter = state.fencing_counter;
            current.limits = state.limits;
            current.cross_graph_links = state.cross_graph_links;
            current.scheduler_budget = state.scheduler_budget;
            current.migration_marker = state.migration_marker;
            current.result_projection_digest = state.result_projection_digest;
            current.operator_projection_digest = state.operator_projection_digest;
            current.logical_time_high_water = state.logical_time_high_water;
            Ok(StateMutation {
                value: (),
                changed: true,
            })
        })?;
        Ok(snapshot)
    }
}

impl HypothesisGraphStore for MemoryHypothesisGraphStore {
    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.read_signed()?.snapshot()
    }

    fn compare_and_swap(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.compare_and_swap_reasoning(expected, state, InitialDecisionAdmission::Reject)
    }

    fn compare_and_swap_coordinator_seed(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
        coordinator_identity: &AgentId,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.compare_and_swap_reasoning(
            expected,
            state,
            InitialDecisionAdmission::AuthenticatedCoordinator(coordinator_identity),
        )
    }

    fn create_task(
        &self,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) =
            self.mutate(None, |state| create_task_op(state, request, &self.limits))?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            create_task_op(state, request, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reject_unbudgeted_reasoning_task_surface(state, "claim")?;
            claim_task_op(state, request, now, lease_duration_ms, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            reject_unbudgeted_reasoning_task_surface(state, "claim")?;
            claim_task_op(state, request, now, lease_duration_ms, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_with_budget(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            claim_task_with_budget_op(
                state,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            claim_task_with_budget_op(
                state,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn renew_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            renew_task_op(
                state,
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                lease_duration_ms,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn complete_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        completion: TaskCompletion,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            complete_task_op(
                state,
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                completion,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn fail_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        failure: TaskFailure,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            fail_task_op(
                state,
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                failure,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn fail_reasoning_task_cas(
        &self,
        expected: &GraphStoreRevision,
        expected_generation: u64,
        publication: TaskFailureOutboxEntry,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let retry_publication = publication.clone();
        let (snapshot, marker) = self.mutate_with_exact_retry(
            Some(expected),
            |state| exact_reasoning_failure_retry(state, &retry_publication),
            |state| fail_reasoning_task_op(state, expected_generation, publication, &self.limits),
        )?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn expire_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        now: GraphLogicalTime,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            expire_task_op(state, task_id, expected_generation, now, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reject_unbudgeted_reasoning_task_surface(state, "reclaim")?;
            reclaim_task_op(
                state,
                task_id,
                request,
                now,
                lease_duration_ms,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task_with_budget(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reclaim_task_with_budget_op(
                state,
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            reclaim_task_with_budget_op(
                state,
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity;

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn ensure_private_file_mode(path: &Path) -> Result<(), GraphStoreError> {
    #[cfg(unix)]
    {
        let metadata = fs::symlink_metadata(path).map_err(|source| GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let observed = permission_mode(&metadata);
        if observed != 0o600 {
            return Err(GraphStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                expected: 0o600,
                observed,
            });
        }
    }
    Ok(())
}

fn ensure_private_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), GraphStoreError> {
    if !metadata.file_type().is_file() {
        return Err(GraphStoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        let observed = permission_mode(metadata);
        if observed != 0o600 {
            return Err(GraphStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                expected: 0o600,
                observed,
            });
        }
    }
    Ok(())
}

pub(crate) fn prepare_private_store_root(path: &Path) -> Result<(), GraphStoreError> {
    ensure_no_symlink_ancestors(path)?;
    ensure_path_not_symlink(path)?;
    let existed = fs::symlink_metadata(path).is_ok();
    fs::create_dir_all(path).map_err(|source| GraphStoreError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    if !existed {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    ensure_private_store_root_mode(path)
}

fn ensure_no_symlink_ancestors(path: &Path) -> Result<(), GraphStoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            // macOS commonly exposes `/var` (and therefore the system temp
            // directory) through this one top-level compatibility symlink.
            // Every other ancestor, including another top-level redirect, is
            // user-controlled for this protocol and is refused.
            if current == Path::new("/var") {
                continue;
            }
            return Err(GraphStoreError::InvalidState {
                reason: format!("symlink ancestor is refused: {}", current.display()),
            });
        }
    }
    Ok(())
}

fn ensure_private_store_root_mode(path: &Path) -> Result<(), GraphStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| GraphStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_dir() {
        return Err(GraphStoreError::InvalidState {
            reason: format!("store root is not a directory: {}", path.display()),
        });
    }
    #[cfg(unix)]
    {
        let observed = permission_mode(&metadata);
        if observed != 0o700 {
            return Err(GraphStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                expected: 0o700,
                observed,
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct DurableNamespaceLock {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
}

impl DurableNamespaceLock {
    #[cfg(unix)]
    fn acquire(path: &Path) -> Result<Self, GraphStoreError> {
        ensure_path_not_symlink(path)?;
        ensure_private_store_root_mode(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(|source| GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let identity = file_identity(&file.metadata().map_err(|source| GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        })?);
        let path_identity =
            file_identity(
                &fs::symlink_metadata(path).map_err(|source| GraphStoreError::Read {
                    path: path.to_path_buf(),
                    source,
                })?,
            );
        if identity != path_identity {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "namespace descriptor identity differs from pathname".to_string(),
            });
        }
        let result = unsafe {
            use std::os::fd::AsRawFd;
            libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
        };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::WouldBlock
                || source.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(GraphStoreError::LockContended {
                    path: path.to_path_buf(),
                });
            }
            return Err(GraphStoreError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
        let namespace = Self {
            file,
            path: path.to_path_buf(),
            identity,
        };
        namespace.revalidate()?;
        Ok(namespace)
    }

    #[cfg(not(unix))]
    fn acquire(path: &Path) -> Result<Self, GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires a Unix namespace lock for safe persistence: {}",
                path.display()
            ),
        })
    }

    #[cfg(unix)]
    fn revalidate(&self) -> Result<(), GraphStoreError> {
        ensure_path_not_symlink(&self.path)?;
        ensure_private_store_root_mode(&self.path)?;
        let path_identity = file_identity(&fs::symlink_metadata(&self.path).map_err(|source| {
            GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: format!("namespace pathname cannot be inspected: {source}"),
            }
        })?);
        let descriptor_identity = file_identity(&self.file.metadata().map_err(|source| {
            GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: format!("namespace descriptor cannot be inspected: {source}"),
            }
        })?);
        if path_identity != self.identity || descriptor_identity != self.identity {
            return Err(GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: "namespace pathname or descriptor identity changed".to_string(),
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn revalidate(&self) -> Result<(), GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: "file store requires a Unix namespace lock for safe persistence".to_string(),
        })
    }
}

#[cfg(unix)]
impl Drop for DurableNamespaceLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
impl Drop for DurableNamespaceLock {
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub(crate) struct DurableFileLock {
    namespace: DurableNamespaceLock,
    file: File,
    path: PathBuf,
    identity: FileIdentity,
    generation: String,
}

/// A short-lived lock on a per-store token in the parent namespace.  Locking
/// the parent directory itself creates false contention between unrelated
/// stores and, on some platforms, ignores `O_NONBLOCK` for `flock`.  The token
/// is stable for this root path and is acquired with `LOCK_NB`; root and parent
/// identities are still revalidated around the descriptor-relative rename.
#[cfg(unix)]
#[derive(Debug)]
struct ParentCommitLock {
    file: File,
    token_path: PathBuf,
    token_identity: FileIdentity,
    parent_path: PathBuf,
    parent_identity: FileIdentity,
}

#[cfg(unix)]
impl ParentCommitLock {
    fn acquire(root: &Path) -> Result<Self, GraphStoreError> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let parent = root.parent().ok_or_else(|| GraphStoreError::LockBinding {
            path: root.to_path_buf(),
            reason: "store root has no parent namespace".to_string(),
        })?;
        ensure_no_symlink_ancestors(parent)?;
        let parent_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)
            .map_err(|source| GraphStoreError::LockBinding {
                path: parent.to_path_buf(),
                reason: source.to_string(),
            })?;
        let parent_metadata =
            parent_file
                .metadata()
                .map_err(|source| GraphStoreError::LockBinding {
                    path: parent.to_path_buf(),
                    reason: source.to_string(),
                })?;
        if !parent_metadata.file_type().is_dir() {
            return Err(GraphStoreError::LockBinding {
                path: parent.to_path_buf(),
                reason: "store parent is not a directory".to_string(),
            });
        }
        let parent_identity = file_identity(&parent_metadata);
        let parent_path_identity =
            file_identity(&fs::symlink_metadata(parent).map_err(|source| {
                GraphStoreError::LockBinding {
                    path: parent.to_path_buf(),
                    reason: source.to_string(),
                }
            })?);
        if parent_identity != parent_path_identity {
            return Err(GraphStoreError::LockBinding {
                path: parent.to_path_buf(),
                reason: "parent descriptor identity differs from pathname".to_string(),
            });
        }
        drop(parent_file);
        let token_path = parent.join(format!(
            ".swarm-spine-commit-{}.lock",
            sha256_hex(root.to_string_lossy().as_bytes())
        ));
        ensure_path_not_symlink(&token_path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        options.mode(0o600);
        let file = options
            .open(&token_path)
            .map_err(|source| GraphStoreError::LockBinding {
                path: token_path.clone(),
                reason: source.to_string(),
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| GraphStoreError::LockBinding {
                path: token_path.clone(),
                reason: source.to_string(),
            })?;
        if !metadata.file_type().is_file() {
            return Err(GraphStoreError::LockBinding {
                path: token_path,
                reason: "per-store commit token is not a regular file".to_string(),
            });
        }
        ensure_private_file_metadata(&token_path, &metadata)?;
        let token_identity = file_identity(&metadata);
        let path_identity =
            file_identity(&fs::symlink_metadata(&token_path).map_err(|source| {
                GraphStoreError::LockBinding {
                    path: token_path.clone(),
                    reason: source.to_string(),
                }
            })?);
        if token_identity != path_identity {
            return Err(GraphStoreError::LockBinding {
                path: token_path.clone(),
                reason: "commit token descriptor identity differs from pathname".to_string(),
            });
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::WouldBlock
                || source.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(GraphStoreError::LockContended { path: token_path });
            }
            return Err(GraphStoreError::LockBinding {
                path: token_path,
                reason: source.to_string(),
            });
        }
        Ok(Self {
            file,
            token_path,
            token_identity,
            parent_path: parent.to_path_buf(),
            parent_identity,
        })
    }

    fn revalidate(&self) -> Result<(), GraphStoreError> {
        use std::os::fd::AsRawFd;
        let parent_metadata = fs::symlink_metadata(&self.parent_path).map_err(|source| {
            GraphStoreError::LockBinding {
                path: self.parent_path.clone(),
                reason: source.to_string(),
            }
        })?;
        let descriptor_metadata =
            self.file
                .metadata()
                .map_err(|source| GraphStoreError::LockBinding {
                    path: self.token_path.clone(),
                    reason: source.to_string(),
                })?;
        ensure_path_not_symlink(&self.token_path)?;
        ensure_private_file_metadata(&self.token_path, &descriptor_metadata)?;
        let token_path_metadata = fs::symlink_metadata(&self.token_path).map_err(|source| {
            GraphStoreError::LockBinding {
                path: self.token_path.clone(),
                reason: source.to_string(),
            }
        })?;
        if file_identity(&parent_metadata) != self.parent_identity
            || file_identity(&descriptor_metadata) != self.token_identity
            || file_identity(&token_path_metadata) != self.token_identity
        {
            return Err(GraphStoreError::LockBinding {
                path: self.token_path.clone(),
                reason: "parent or commit token identity changed".to_string(),
            });
        }
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || flags & libc::O_NONBLOCK == 0 {
            return Err(GraphStoreError::LockBinding {
                path: self.token_path.clone(),
                reason: "commit token descriptor is not nonblocking".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ParentCommitLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl DurableFileLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self, GraphStoreError> {
        let namespace_path = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
            reason: "lock path has no parent namespace".to_string(),
        })?;
        let namespace = DurableNamespaceLock::acquire(namespace_path)?;
        namespace.revalidate()?;
        ensure_path_not_symlink(path)?;
        if fs::symlink_metadata(path).is_ok() {
            ensure_regular_file(path)?;
            ensure_private_file_mode(path)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = options
            .open(path)
            .map_err(|source| GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        let file_metadata = file.metadata().map_err(|source| GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        ensure_private_file_metadata(path, &file_metadata)?;
        let identity = file_identity(&file_metadata);
        let path_identity =
            file_identity(
                &fs::symlink_metadata(path).map_err(|source| GraphStoreError::Read {
                    path: path.to_path_buf(),
                    source,
                })?,
            );
        if identity != path_identity {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "lock descriptor identity differs from pathname".to_string(),
            });
        }
        namespace.revalidate()?;
        ensure_private_file_mode(path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 || flags & libc::O_NONBLOCK == 0 {
                return Err(GraphStoreError::LockBinding {
                    path: path.to_path_buf(),
                    reason: "lock descriptor is not nonblocking".to_string(),
                });
            }
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let source = io::Error::last_os_error();
                if source.kind() == io::ErrorKind::WouldBlock
                    || source.raw_os_error() == Some(libc::EAGAIN)
                {
                    return Err(GraphStoreError::LockContended {
                        path: path.to_path_buf(),
                    });
                }
                return Err(GraphStoreError::Write {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        let existing_generation = read_lock_generation(&file, path)?;
        let generation = existing_generation
            .clone()
            .unwrap_or_else(|| sha256_hex(Keypair::generate().public_key().as_bytes()));
        let mut lock = Self {
            namespace,
            file,
            path: path.to_path_buf(),
            identity,
            generation,
        };
        if existing_generation.is_none() {
            lock.write_generation()?;
        }
        lock.revalidate()?;
        Ok(lock)
    }

    fn write_generation(&mut self) -> Result<(), GraphStoreError> {
        self.file
            .set_len(0)
            .map_err(|source| GraphStoreError::Write {
                path: self.path.clone(),
                source,
            })?;
        self.file
            .write_all(self.generation.as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|source| GraphStoreError::Write {
                path: self.path.clone(),
                source,
            })
    }

    pub(crate) fn revalidate(&self) -> Result<(), GraphStoreError> {
        self.namespace.revalidate()?;
        ensure_path_not_symlink(&self.path)?;
        ensure_private_file_mode(&self.path)?;
        let path_metadata =
            fs::symlink_metadata(&self.path).map_err(|source| GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: format!("lock pathname cannot be inspected: {source}"),
            })?;
        let descriptor_metadata =
            self.file
                .metadata()
                .map_err(|source| GraphStoreError::LockBinding {
                    path: self.path.clone(),
                    reason: format!("lock descriptor cannot be inspected: {source}"),
                })?;
        if file_identity(&path_metadata) != self.identity
            || file_identity(&descriptor_metadata) != self.identity
        {
            return Err(GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: "lock pathname or descriptor identity changed".to_string(),
            });
        }
        let expected_length =
            u64::try_from(self.generation.len()).map_err(|_| GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: "lock generation length overflow".to_string(),
            })?;
        if descriptor_metadata.len() != expected_length {
            return Err(GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: "lock generation file length changed".to_string(),
            });
        }
        let mut generation = vec![0_u8; self.generation.len()];
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let count = unsafe {
                libc::pread(
                    self.file.as_raw_fd(),
                    generation.as_mut_ptr().cast(),
                    generation.len(),
                    0,
                )
            };
            if count < 0 {
                return Err(GraphStoreError::LockBinding {
                    path: self.path.clone(),
                    reason: io::Error::last_os_error().to_string(),
                });
            }
            generation.truncate(usize::try_from(count).map_err(|_| {
                GraphStoreError::LockBinding {
                    path: self.path.clone(),
                    reason: "lock generation length overflow".to_string(),
                }
            })?);
        }
        #[cfg(not(unix))]
        {
            use std::io::Read;
            let mut file =
                self.file
                    .try_clone()
                    .map_err(|source| GraphStoreError::LockBinding {
                        path: self.path.clone(),
                        reason: source.to_string(),
                    })?;
            file.read_to_end(&mut generation)
                .map_err(|source| GraphStoreError::LockBinding {
                    path: self.path.clone(),
                    reason: source.to_string(),
                })?;
        }
        if generation != self.generation.as_bytes() {
            return Err(GraphStoreError::LockBinding {
                path: self.path.clone(),
                reason: "lock generation changed".to_string(),
            });
        }
        Ok(())
    }

    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }

    pub(crate) fn identity_token(&self) -> String {
        file_identity_token(self.identity)
    }

    #[cfg(unix)]
    pub(crate) fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<T, GraphStoreError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        self.revalidate()?;
        let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
            reason: "locked JSON path has no parent namespace".to_string(),
        })?;
        if parent != self.namespace.path {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "locked JSON path is outside the acquired namespace".to_string(),
            });
        }
        let name = path
            .file_name()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "locked JSON path has no file name".to_string(),
            })?;
        let name = CString::new(name.as_bytes()).map_err(|_| GraphStoreError::InvalidState {
            reason: "locked JSON file name contains NUL".to_string(),
        })?;
        let fd = unsafe {
            libc::openat(
                self.namespace.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(GraphStoreError::Read {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let result = read_json_from_file(path, file);
        let binding = self.revalidate();
        match (result, binding) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<T, GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative reads: {}",
                path.display()
            ),
        })
    }

    #[cfg(unix)]
    pub(crate) fn atomic_write_json<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<(), GraphStoreError> {
        let bytes = serde_json::to_vec(value).map_err(|source| GraphStoreError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
        if bytes.len() > MAX_PERSISTED_JSON_BYTES {
            return Err(GraphStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: MAX_PERSISTED_JSON_BYTES,
            });
        }
        self.revalidate()?;
        atomic_write_json_at(self, path, &bytes)?;
        self.revalidate()
    }

    #[cfg(unix)]
    pub(crate) fn atomic_write_bytes(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), GraphStoreError> {
        if bytes.len() > MAX_PERSISTED_JSON_BYTES {
            return Err(GraphStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: MAX_PERSISTED_JSON_BYTES,
            });
        }
        self.revalidate()?;
        atomic_write_json_at(self, path, bytes)?;
        self.revalidate()
    }

    #[cfg(not(unix))]
    pub(crate) fn atomic_write_bytes(
        &self,
        path: &Path,
        _bytes: &[u8],
    ) -> Result<(), GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative writes: {}",
                path.display()
            ),
        })
    }

    #[cfg(unix)]
    pub(crate) fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, GraphStoreError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        self.revalidate()?;
        let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
            reason: "locked byte path has no parent namespace".to_string(),
        })?;
        if parent != self.namespace.path {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "locked byte path is outside the acquired namespace".to_string(),
            });
        }
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "locked byte path has no file name".to_string(),
                })?
                .as_bytes(),
        )
        .map_err(|_| GraphStoreError::InvalidState {
            reason: "locked byte path contains NUL".to_string(),
        })?;
        let fd = unsafe {
            libc::openat(
                self.namespace.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(GraphStoreError::Read {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|source| GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        ensure_private_file_metadata(path, &metadata)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(MAX_PERSISTED_JSON_BYTES)
                .min(MAX_PERSISTED_JSON_BYTES),
        );
        let mut bounded = file.take(MAX_PERSISTED_JSON_BYTES as u64 + 1);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|source| GraphStoreError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes.len() > MAX_PERSISTED_JSON_BYTES {
            return Err(GraphStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: MAX_PERSISTED_JSON_BYTES,
            });
        }
        self.revalidate()?;
        Ok(bytes)
    }

    #[cfg(not(unix))]
    pub(crate) fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative reads: {}",
                path.display()
            ),
        })
    }

    #[cfg(unix)]
    pub(crate) fn remove_file(&self, path: &Path) -> Result<(), GraphStoreError> {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        self.revalidate()?;
        if path.parent() != Some(self.namespace.path.as_path()) {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "locked remove path is outside the acquired namespace".to_string(),
            });
        }
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "locked remove path has no file name".to_string(),
                })?
                .as_bytes(),
        )
        .map_err(|_| GraphStoreError::InvalidState {
            reason: "locked remove path contains NUL".to_string(),
        })?;
        let result = unsafe { libc::unlinkat(self.namespace.file.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::NotFound {
                return Err(GraphStoreError::Write {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
        if unsafe { libc::fsync(self.namespace.file.as_raw_fd()) } != 0 {
            return Err(GraphStoreError::Write {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn remove_file(&self, path: &Path) -> Result<(), GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative removes: {}",
                path.display()
            ),
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn atomic_write_json<T: Serialize>(
        &self,
        path: &Path,
        _value: &T,
    ) -> Result<(), GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative writes: {}",
                path.display()
            ),
        })
    }

    #[cfg(unix)]
    pub(crate) fn read_json_log<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<Vec<T>, GraphStoreError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        self.revalidate()?;
        let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
            reason: "locked JSON log path has no parent namespace".to_string(),
        })?;
        if parent != self.namespace.path {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "locked JSON log path is outside the acquired namespace".to_string(),
            });
        }
        let name = path
            .file_name()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "locked JSON log path has no file name".to_string(),
            })?;
        let name = CString::new(name.as_bytes()).map_err(|_| GraphStoreError::InvalidState {
            reason: "locked JSON log file name contains NUL".to_string(),
        })?;
        let fd = unsafe {
            libc::openat(
                self.namespace.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(GraphStoreError::Read {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let raw = read_bounded_json_string(path, file)?;
        if !raw.ends_with('\n') {
            return Err(GraphStoreError::InvalidState {
                reason: "JSON high-water log is missing its trailing newline".to_string(),
            });
        }
        let mut values = Vec::new();
        for line in raw.split_terminator('\n') {
            if line.trim().is_empty() {
                return Err(GraphStoreError::InvalidState {
                    reason: "JSON high-water log contains a blank record".to_string(),
                });
            }
            values.push(
                serde_json::from_str(line).map_err(|source| GraphStoreError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?,
            );
        }
        if values.is_empty() {
            return Err(GraphStoreError::InvalidState {
                reason: "JSON high-water log is empty".to_string(),
            });
        }
        self.revalidate()?;
        Ok(values)
    }

    #[cfg(not(unix))]
    pub(crate) fn read_json_log<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<Vec<T>, GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative JSON log reads: {}",
                path.display()
            ),
        })
    }

    /// Append one compact JSON record to a bounded, descriptor-relative log.
    #[cfg(unix)]
    pub(crate) fn append_json<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<(), GraphStoreError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let mut bytes = serde_json::to_vec(value).map_err(|source| GraphStoreError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
        bytes.push(b'\n');
        if bytes.len() > MAX_PERSISTED_JSON_BYTES {
            return Err(GraphStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: MAX_PERSISTED_JSON_BYTES,
            });
        }
        self.revalidate()?;
        let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
            reason: "locked JSON log path has no parent namespace".to_string(),
        })?;
        if parent != self.namespace.path {
            return Err(GraphStoreError::LockBinding {
                path: path.to_path_buf(),
                reason: "locked JSON log path is outside the acquired namespace".to_string(),
            });
        }
        let name = path
            .file_name()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "locked JSON log path has no file name".to_string(),
            })?;
        let name = CString::new(name.as_bytes()).map_err(|_| GraphStoreError::InvalidState {
            reason: "locked JSON log file name contains NUL".to_string(),
        })?;
        let fd = unsafe {
            libc::openat(
                self.namespace.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_APPEND
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(GraphStoreError::Write {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            let metadata = file.metadata().map_err(|source| GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            })?;
            ensure_private_file_metadata(path, &metadata)?;
            let current_len =
                usize::try_from(metadata.len()).map_err(|_| GraphStoreError::ResourceLimit {
                    resource: "persisted_file_bytes".to_string(),
                    limit: MAX_PERSISTED_JSON_BYTES,
                })?;
            if current_len > MAX_PERSISTED_JSON_BYTES
                || current_len.saturating_add(bytes.len()) > MAX_PERSISTED_JSON_BYTES
            {
                return Err(GraphStoreError::ResourceLimit {
                    resource: "persisted_file_bytes".to_string(),
                    limit: MAX_PERSISTED_JSON_BYTES,
                });
            }
            if current_len > 0 {
                let mut trailing = [0_u8; 1];
                let count = unsafe {
                    libc::pread(
                        file.as_raw_fd(),
                        trailing.as_mut_ptr().cast(),
                        1,
                        i64::try_from(current_len.saturating_sub(1)).map_err(|_| {
                            GraphStoreError::InvalidState {
                                reason: "JSON log offset overflow".to_string(),
                            }
                        })?,
                    )
                };
                if count != 1 || trailing[0] != b'\n' {
                    return Err(GraphStoreError::InvalidState {
                        reason: "JSON high-water log is not newline-delimited".to_string(),
                    });
                }
            }
            self.revalidate()?;
            file.write_all(&bytes)
                .map_err(|source| GraphStoreError::Write {
                    path: path.to_path_buf(),
                    source,
                })?;
            file.sync_all().map_err(|source| GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            })?;
            if unsafe { libc::fsync(self.namespace.file.as_raw_fd()) } != 0 {
                return Err(GraphStoreError::Write {
                    path: path.to_path_buf(),
                    source: io::Error::last_os_error(),
                });
            }
            self.revalidate()
        })();
        if result.is_err() {
            // O_APPEND prevents a partial record from being repaired by a
            // subsequent call.  The caller therefore fails closed on any
            // write or durability error.
            let _ = file.sync_all();
        }
        result
    }

    #[cfg(not(unix))]
    pub(crate) fn append_json<T: Serialize>(
        &self,
        path: &Path,
        _value: &T,
    ) -> Result<(), GraphStoreError> {
        Err(GraphStoreError::InvalidState {
            reason: format!(
                "file store requires Unix descriptor-relative JSON log writes: {}",
                path.display()
            ),
        })
    }
}

const LOCK_GENERATION_BYTES: u64 = 64;

fn validate_lock_generation(generation: &str) -> Result<(), GraphStoreError> {
    if generation.len() != LOCK_GENERATION_BYTES as usize
        || !generation.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(GraphStoreError::LockBinding {
            path: PathBuf::new(),
            reason: "lock generation is not a bounded hexadecimal token".to_string(),
        });
    }
    Ok(())
}

fn validate_lock_identity(identity: &str) -> Result<(), GraphStoreError> {
    if identity.trim().is_empty() || identity.len() > 128 {
        return Err(GraphStoreError::LockBinding {
            path: PathBuf::new(),
            reason: "lock identity is empty or unbounded".to_string(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn file_identity_token(identity: FileIdentity) -> String {
    format!("{}:{}", identity.device, identity.inode)
}

#[cfg(not(unix))]
fn file_identity_token(_identity: FileIdentity) -> String {
    "platform-lock-identity".to_string()
}

fn read_lock_generation(file: &File, path: &Path) -> Result<Option<String>, GraphStoreError> {
    let length = file
        .metadata()
        .map_err(|source| GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    if length == 0 {
        return Ok(None);
    }
    if length != LOCK_GENERATION_BYTES {
        return Err(GraphStoreError::LockBinding {
            path: path.to_path_buf(),
            reason: "lock generation file has an invalid length".to_string(),
        });
    }
    let mut clone = file
        .try_clone()
        .map_err(|source| GraphStoreError::LockBinding {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })?;
    clone
        .seek(SeekFrom::Start(0))
        .and_then(|_| {
            let mut bytes = Vec::with_capacity(LOCK_GENERATION_BYTES as usize + 1);
            clone
                .take(LOCK_GENERATION_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
        .map_err(|source| GraphStoreError::LockBinding {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })
        .and_then(|bytes| {
            let generation =
                String::from_utf8(bytes).map_err(|error| GraphStoreError::LockBinding {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                })?;
            validate_lock_generation(&generation)?;
            Ok(Some(generation))
        })
}

#[cfg(unix)]
impl Drop for DurableFileLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
impl Drop for DurableFileLock {
    fn drop(&mut self) {}
}

/// A monotonic anchor kept outside an individual store root.
///
/// The state/head files and the local high-water log are intentionally
/// recoverable within the store namespace.  This second append-only log is
/// the rollback boundary: restoring an older state/head/local-log tuple does
/// not restore the latest anchor, so restart observes the newer generation
/// and refuses the replay.  Its namespace and lock use the same descriptor
/// and inode checks as the store itself.
#[derive(Debug, Clone)]
pub(crate) struct DurableMonotonicAnchor {
    data_path: PathBuf,
    tail_path: PathBuf,
    lock_path: PathBuf,
    rotation_manifest_path: PathBuf,
    rotation_data_path: PathBuf,
    rotation_tail_path: PathBuf,
}

impl DurableMonotonicAnchor {
    pub(crate) fn new(root: &Path, state_kind: &str) -> Result<Self, GraphStoreError> {
        let parent = root.parent().ok_or_else(|| GraphStoreError::InvalidState {
            reason: "store root has no parent for monotonic anchor".to_string(),
        })?;
        ensure_no_symlink_ancestors(parent)?;
        let namespace_root = parent.join(".swarm-spine-monotonic-anchors");
        prepare_private_store_root(&namespace_root)?;
        let canonical_root = fs::canonicalize(root).map_err(|source| GraphStoreError::Read {
            path: root.to_path_buf(),
            source,
        })?;
        let token = sha256_hex(format!("{state_kind}\0{}", canonical_root.display()).as_bytes());
        let namespace = namespace_root.join(token);
        prepare_private_store_root(&namespace)?;
        let data_path = namespace.join("state.headlog");
        let tail_path = namespace.join("state.headtail");
        let lock_path = namespace.join("state.lock");
        let rotation_manifest_path = namespace.join(MONOTONIC_ROTATION_MANIFEST_FILE);
        let rotation_data_path = namespace.join(MONOTONIC_ROTATION_DATA_FILE);
        let rotation_tail_path = namespace.join(MONOTONIC_ROTATION_TAIL_FILE);
        ensure_path_not_symlink(&data_path)?;
        ensure_path_not_symlink(&tail_path)?;
        ensure_path_not_symlink(&lock_path)?;
        ensure_path_not_symlink(&rotation_manifest_path)?;
        ensure_path_not_symlink(&rotation_data_path)?;
        ensure_path_not_symlink(&rotation_tail_path)?;
        Ok(Self {
            data_path,
            tail_path,
            lock_path,
            rotation_manifest_path,
            rotation_data_path,
            rotation_tail_path,
        })
    }

    pub(crate) fn exists(&self) -> bool {
        fs::symlink_metadata(&self.data_path).is_ok()
            && fs::symlink_metadata(&self.tail_path).is_ok()
    }

    pub(crate) fn path(&self) -> &Path {
        &self.data_path
    }

    pub(crate) fn acquire_lock(&self) -> Result<DurableFileLock, GraphStoreError> {
        DurableFileLock::acquire(&self.lock_path)
    }

    /// Complete a rotation whose manifest was durably written before a
    /// process stopped.  The manifest is the recovery decision: until it is
    /// present the old data/tail pair remains authoritative, and after it is
    /// present replaying the staged pair is idempotent even if the process
    /// stopped between the two active-file replacements.
    fn recover_rotation_locked(&self, lock: &DurableFileLock) -> Result<(), GraphStoreError> {
        if fs::symlink_metadata(&self.rotation_manifest_path).is_err() {
            return Ok(());
        }
        let manifest: DurableJournalRotationManifest =
            lock.read_json(&self.rotation_manifest_path)?;
        if manifest.schema_version != GRAPH_STORE_SCHEMA_VERSION
            || manifest.record_digest.trim().is_empty()
        {
            return Err(GraphStoreError::InvalidState {
                reason: "external journal rotation manifest is invalid".to_string(),
            });
        }
        let staged_records: Vec<DurableExternalCommitRecord> =
            lock.read_json_log(&self.rotation_data_path)?;
        let staged_tail: DurableJournalTail = lock.read_json(&self.rotation_tail_path)?;
        let staged = staged_records
            .last()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "external journal rotation stage is empty".to_string(),
            })?;
        if staged_records.len() != 1
            || staged.sequence != manifest.sequence
            || staged.record_digest != manifest.record_digest
            || staged_tail.schema_version != GRAPH_STORE_SCHEMA_VERSION
            || staged_tail.sequence != staged.sequence
            || staged_tail.record_count != 1
            || staged_tail.record_digest != staged.record_digest
        {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation: manifest.sequence,
                observed_generation: staged.sequence,
            });
        }
        let staged_data = lock.read_bytes(&self.rotation_data_path)?;
        let staged_tail_bytes = lock.read_bytes(&self.rotation_tail_path)?;
        lock.atomic_write_bytes(&self.data_path, &staged_data)?;
        lock.atomic_write_bytes(&self.tail_path, &staged_tail_bytes)?;
        lock.remove_file(&self.rotation_manifest_path)?;
        lock.remove_file(&self.rotation_data_path)?;
        lock.remove_file(&self.rotation_tail_path)
    }

    pub(crate) fn read_records_locked<T: serde::de::DeserializeOwned>(
        &self,
        lock: &DurableFileLock,
    ) -> Result<Vec<T>, GraphStoreError> {
        self.recover_rotation_locked(lock)?;
        recover_log_append(lock, &self.data_path, &self.tail_path)?;
        lock.read_json_log(&self.data_path)
    }

    pub(crate) fn read_records<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<Vec<T>, GraphStoreError> {
        let lock = DurableFileLock::acquire(&self.lock_path)?;
        self.recover_rotation_locked(&lock)?;
        recover_log_append(&lock, &self.data_path, &self.tail_path)?;
        lock.read_json_log(&self.data_path)
    }

    pub(crate) fn validate_tail(
        &self,
        records: &[DurableExternalCommitRecord],
    ) -> Result<(), GraphStoreError> {
        let lock = DurableFileLock::acquire(&self.lock_path)?;
        recover_log_append(&lock, &self.data_path, &self.tail_path)?;
        let tail: DurableJournalTail = lock.read_json(&self.tail_path)?;
        let last = records
            .last()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "external commit journal is empty".to_string(),
            })?;
        if tail.schema_version != GRAPH_STORE_SCHEMA_VERSION
            || tail.sequence != last.sequence
            || tail.record_count
                != u64::try_from(records.len()).map_err(|_| GraphStoreError::InvalidState {
                    reason: "external journal record count overflow".to_string(),
                })?
            || tail.record_digest != last.record_digest
        {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation: tail.sequence,
                observed_generation: last.sequence,
            });
        }
        Ok(())
    }

    pub(crate) fn validate_tail_locked(
        &self,
        lock: &DurableFileLock,
        records: &[DurableExternalCommitRecord],
    ) -> Result<(), GraphStoreError> {
        recover_log_append(lock, &self.data_path, &self.tail_path)?;
        let tail: DurableJournalTail = lock.read_json(&self.tail_path)?;
        let last = records
            .last()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "external commit journal is empty".to_string(),
            })?;
        if tail.schema_version != GRAPH_STORE_SCHEMA_VERSION
            || tail.sequence != last.sequence
            || tail.record_count
                != u64::try_from(records.len()).map_err(|_| GraphStoreError::InvalidState {
                    reason: "external journal record count overflow".to_string(),
                })?
            || tail.record_digest != last.record_digest
        {
            return Err(GraphStoreError::ReplayDetected {
                expected_generation: tail.sequence,
                observed_generation: last.sequence,
            });
        }
        Ok(())
    }

    pub(crate) fn append_external(
        &self,
        record: &DurableExternalCommitRecord,
    ) -> Result<(), GraphStoreError> {
        let lock = DurableFileLock::acquire(&self.lock_path)?;
        self.recover_rotation_locked(&lock)?;
        recover_log_append(&lock, &self.data_path, &self.tail_path)?;
        let existing = if fs::symlink_metadata(&self.data_path).is_ok() {
            lock.read_json_log::<DurableExternalCommitRecord>(&self.data_path)?
        } else {
            Vec::new()
        };
        let tail = DurableJournalTail {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            sequence: record.sequence,
            record_count: u64::try_from(existing.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "external journal record count overflow".to_string(),
                })?,
            record_digest: record.record_digest.clone(),
        };
        append_json_with_tail(
            &lock,
            &self.data_path,
            &self.tail_path,
            record,
            &tail,
            tail.record_count,
        )
    }

    pub(crate) fn append_external_locked(
        &self,
        lock: &DurableFileLock,
        record: &DurableExternalCommitRecord,
    ) -> Result<(), GraphStoreError> {
        self.recover_rotation_locked(lock)?;
        recover_log_append(lock, &self.data_path, &self.tail_path)?;
        let existing = if fs::symlink_metadata(&self.data_path).is_ok() {
            lock.read_json_log::<DurableExternalCommitRecord>(&self.data_path)?
        } else {
            Vec::new()
        };
        let tail = DurableJournalTail {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            sequence: record.sequence,
            record_count: u64::try_from(existing.len())
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "external journal record count overflow".to_string(),
                })?,
            record_digest: record.record_digest.clone(),
        };
        append_json_with_tail(
            lock,
            &self.data_path,
            &self.tail_path,
            record,
            &tail,
            tail.record_count,
        )
    }

    pub(crate) fn rotate_if_needed_locked(
        &self,
        lock: &DurableFileLock,
        committed: &DurableExternalCommitRecord,
        signer: &Keypair,
    ) -> Result<bool, GraphStoreError> {
        self.rotate_locked(lock, committed, signer, false)
    }

    #[cfg(test)]
    pub(crate) fn rotate_for_test_locked(
        &self,
        lock: &DurableFileLock,
        committed: &DurableExternalCommitRecord,
        signer: &Keypair,
    ) -> Result<bool, GraphStoreError> {
        self.rotate_locked(lock, committed, signer, true)
    }

    #[cfg(test)]
    pub(crate) fn rotation_manifest_path_for_test(&self) -> &Path {
        &self.rotation_manifest_path
    }

    fn rotate_locked(
        &self,
        lock: &DurableFileLock,
        committed: &DurableExternalCommitRecord,
        signer: &Keypair,
        force: bool,
    ) -> Result<bool, GraphStoreError> {
        self.recover_rotation_locked(lock)?;
        let current_len = lock.read_bytes(&self.data_path)?.len();
        // Leave room for the next intent and its commit.  Rotation uses a
        // manifest plus staged data/tail pair.  A crash at either active-file
        // replacement is therefore replayed deterministically on reopen.
        if !force && current_len.saturating_add(8192) < MAX_PERSISTED_JSON_BYTES {
            return Ok(false);
        }
        let checkpoint = sign_external_commit_record(
            &committed.state_kind,
            &committed.stream_id,
            committed.generation,
            &committed.digest,
            committed.sequence,
            ExternalCommitPhase::Checkpoint,
            None,
            &committed.lock_generation,
            &committed.lock_identity,
            signer,
        )?;
        let mut bytes =
            serde_json::to_vec(&checkpoint).map_err(|source| GraphStoreError::Serialize {
                path: self.data_path.clone(),
                source,
            })?;
        bytes.push(b'\n');
        let tail = DurableJournalTail {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            sequence: checkpoint.sequence,
            record_count: 1,
            record_digest: checkpoint.record_digest.clone(),
        };
        let tail_bytes =
            serde_json::to_vec(&tail).map_err(|source| GraphStoreError::Serialize {
                path: self.rotation_tail_path.clone(),
                source,
            })?;
        let manifest = DurableJournalRotationManifest {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            sequence: checkpoint.sequence,
            record_digest: checkpoint.record_digest,
        };
        lock.atomic_write_bytes(&self.rotation_data_path, &bytes)?;
        lock.atomic_write_bytes(&self.rotation_tail_path, &tail_bytes)?;
        lock.atomic_write_json(&self.rotation_manifest_path, &manifest)?;
        #[cfg(test)]
        maybe_fail_rotation(&self.rotation_manifest_path)?;
        self.recover_rotation_locked(lock)?;
        Ok(true)
    }
}

pub(crate) fn ensure_path_not_symlink(path: &Path) -> Result<(), GraphStoreError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(GraphStoreError::InvalidState {
            reason: format!("symlink path is refused: {}", path.display()),
        });
    }
    Ok(())
}

fn ensure_regular_file(path: &Path) -> Result<(), GraphStoreError> {
    ensure_path_not_symlink(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|source| GraphStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(GraphStoreError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    ensure_private_file_mode(path)?;
    Ok(())
}

#[cfg(unix)]
fn atomic_write_json_at(
    lock: &DurableFileLock,
    path: &Path,
    bytes: &[u8],
) -> Result<(), GraphStoreError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
        reason: "locked JSON path has no parent namespace".to_string(),
    })?;
    if parent != lock.namespace.path {
        return Err(GraphStoreError::LockBinding {
            path: path.to_path_buf(),
            reason: "locked JSON path is outside the acquired namespace".to_string(),
        });
    }
    let parent_commit_lock = ParentCommitLock::acquire(&lock.namespace.path)?;
    parent_commit_lock.revalidate()?;
    lock.revalidate()?;
    let target = path
        .file_name()
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "locked JSON path has no file name".to_string(),
        })?;
    let target = CString::new(target.as_bytes()).map_err(|_| GraphStoreError::InvalidState {
        reason: "locked JSON file name contains NUL".to_string(),
    })?;
    let dir_fd = lock.namespace.file.as_raw_fd();
    let mut target_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let stat_result = unsafe {
        libc::fstatat(
            dir_fd,
            target.as_ptr(),
            target_stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_result == 0 {
        let target_stat = unsafe { target_stat.assume_init() };
        if (target_stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(GraphStoreError::NotRegularFile {
                path: path.to_path_buf(),
            });
        }
        let mode = target_stat.st_mode & 0o7777;
        if mode != 0o600 {
            return Err(GraphStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                expected: 0o600,
                observed: u32::from(mode),
            });
        }
    } else {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::NotFound {
            return Err(GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    }

    let suffix = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let target_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let temporary_name = CString::new(format!(
        ".{target_name}.tmp.{}.{}",
        std::process::id(),
        suffix
    ))
    .map_err(|_| GraphStoreError::InvalidState {
        reason: "temporary JSON file name contains NUL".to_string(),
    })?;
    let temporary_fd = unsafe {
        libc::openat(
            dir_fd,
            temporary_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if temporary_fd < 0 {
        return Err(GraphStoreError::Write {
            path: path.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }
    let mut temporary = unsafe { File::from_raw_fd(temporary_fd) };
    let write_result: Result<(), GraphStoreError> = (|| {
        temporary
            .write_all(bytes)
            .map_err(|source| GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        temporary
            .sync_all()
            .map_err(|source| GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        lock.revalidate()?;
        #[cfg(test)]
        wait_for_test_persistence_barrier(path).map_err(|source| GraphStoreError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        lock.revalidate()?;
        parent_commit_lock.revalidate()?;
        #[cfg(test)]
        wait_for_test_pre_rename_barrier(path).map_err(|source| GraphStoreError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        drop(temporary);
        let result =
            unsafe { libc::renameat(dir_fd, temporary_name.as_ptr(), dir_fd, target.as_ptr()) };
        if result != 0 {
            return Err(GraphStoreError::Write {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        if unsafe { libc::fsync(dir_fd) } != 0 {
            return Err(GraphStoreError::Write {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
        parent_commit_lock.revalidate()?;
        lock.revalidate()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        unsafe {
            libc::unlinkat(dir_fd, temporary_name.as_ptr(), 0);
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn read_json_file<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, GraphStoreError> {
    ensure_regular_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|source| GraphStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    read_json_from_file(path, file)
}

fn read_json_from_file<T: serde::de::DeserializeOwned>(
    path: &Path,
    file: File,
) -> Result<T, GraphStoreError> {
    let raw = read_bounded_json_string(path, file)?;
    serde_json::from_str(&raw).map_err(|source| GraphStoreError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn read_bounded_json_string(path: &Path, file: File) -> Result<String, GraphStoreError> {
    let metadata = file.metadata().map_err(|source| GraphStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    ensure_private_file_metadata(path, &metadata)?;
    let size = metadata.len();
    if size > MAX_PERSISTED_JSON_BYTES as u64 {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: MAX_PERSISTED_JSON_BYTES,
        });
    }
    let mut raw = String::with_capacity(
        usize::try_from(size)
            .unwrap_or(MAX_PERSISTED_JSON_BYTES)
            .min(MAX_PERSISTED_JSON_BYTES),
    );
    let mut bounded = file.take(MAX_PERSISTED_JSON_BYTES as u64 + 1);
    std::io::Read::read_to_string(&mut bounded, &mut raw).map_err(|source| {
        GraphStoreError::Read {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if raw.len() > MAX_PERSISTED_JSON_BYTES {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: MAX_PERSISTED_JSON_BYTES,
        });
    }
    Ok(raw)
}

#[cfg(test)]
pub(crate) fn atomic_write_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), GraphStoreError> {
    let parent = path.parent().ok_or_else(|| GraphStoreError::InvalidState {
        reason: "state path has no parent".to_string(),
    })?;
    ensure_path_not_symlink(path)?;
    if fs::symlink_metadata(path).is_ok() {
        ensure_private_file_mode(path)?;
    }
    let bytes = serde_json::to_vec(value).map_err(|source| GraphStoreError::Serialize {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() > MAX_PERSISTED_JSON_BYTES {
        return Err(GraphStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: MAX_PERSISTED_JSON_BYTES,
        });
    }
    let suffix = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temp_path = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id(),
        suffix
    ));
    match fs::symlink_metadata(&temp_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(GraphStoreError::InvalidState {
                reason: format!("temporary state path is a symlink: {}", temp_path.display()),
            });
        }
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(&temp_path).map_err(|source| GraphStoreError::Write {
                path: temp_path.clone(),
                source,
            })?;
        }
        Ok(_) => {
            return Err(GraphStoreError::InvalidState {
                reason: format!(
                    "temporary state path is not a regular file: {}",
                    temp_path.display()
                ),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(GraphStoreError::Write {
                path: temp_path.clone(),
                source,
            });
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp_path)
        .map_err(|source| GraphStoreError::Write {
            path: temp_path.clone(),
            source,
        })?;
    let write_result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        #[cfg(test)]
        wait_for_test_persistence_barrier(path)?;
        fs::rename(&temp_path, path)?;
        let directory = File::open(parent)?;
        directory.sync_all()
    })();
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(GraphStoreError::Write {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

#[cfg(test)]
type PersistenceBarrierSpec = (PathBuf, Sender<()>, Receiver<()>);

#[cfg(test)]
static TEST_PERSISTENCE_BARRIER: OnceLock<Mutex<Vec<PersistenceBarrierSpec>>> = OnceLock::new();

#[cfg(test)]
static TEST_PRE_RENAME_BARRIER: OnceLock<Mutex<Vec<PersistenceBarrierSpec>>> = OnceLock::new();

#[cfg(test)]
fn install_test_persistence_barrier(path: PathBuf, ready: Sender<()>, release: Receiver<()>) {
    let slot = TEST_PERSISTENCE_BARRIER.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = slot.lock() {
        guard.push((path, ready, release));
    }
}

#[cfg(test)]
fn clear_test_persistence_barrier(path: &Path) {
    if let Some(slot) = TEST_PERSISTENCE_BARRIER.get()
        && let Ok(mut guard) = slot.lock()
    {
        guard.retain(|(target, _, _)| target != path);
    }
}

#[cfg(test)]
fn install_test_pre_rename_barrier(path: PathBuf, ready: Sender<()>, release: Receiver<()>) {
    let slot = TEST_PRE_RENAME_BARRIER.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = slot.lock() {
        guard.push((path, ready, release));
    }
}

#[cfg(test)]
fn clear_test_pre_rename_barrier(path: &Path) {
    if let Some(slot) = TEST_PRE_RENAME_BARRIER.get()
        && let Ok(mut guard) = slot.lock()
    {
        guard.retain(|(target, _, _)| target != path);
    }
}

#[cfg(test)]
fn wait_for_test_persistence_barrier(path: &Path) -> io::Result<()> {
    let barrier = TEST_PERSISTENCE_BARRIER.get().and_then(|slot| {
        let mut guard = slot.lock().ok()?;
        let index = guard.iter().position(|(target, _, _)| target == path)?;
        let (_, ready, release) = guard.remove(index);
        Some((ready, release))
    });
    if let Some((ready, release)) = barrier {
        ready
            .send(())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "barrier receiver dropped"))?;
        release
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("persistence barrier release timed out: {error}"),
                )
            })?;
    }
    Ok(())
}

#[cfg(test)]
fn wait_for_test_pre_rename_barrier(path: &Path) -> io::Result<()> {
    let barrier = TEST_PRE_RENAME_BARRIER.get().and_then(|slot| {
        let mut guard = slot.lock().ok()?;
        let index = guard.iter().position(|(target, _, _)| target == path)?;
        let (_, ready, release) = guard.remove(index);
        Some((ready, release))
    });
    if let Some((ready, release)) = barrier {
        ready
            .send(())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "barrier receiver dropped"))?;
        release
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("persistence barrier release timed out: {error}"),
                )
            })?;
    }
    Ok(())
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitFailureBoundary {
    ExternalIntent,
    State,
    Head,
    HighWater,
    RollbackState,
    RollbackHead,
    RollbackHighWater,
    RollbackHighWaterTail,
    AppendTail,
}

#[cfg(test)]
static TEST_COMMIT_FAILURE: OnceLock<Mutex<BTreeMap<PathBuf, CommitFailureBoundary>>> =
    OnceLock::new();

#[cfg(test)]
pub(crate) fn install_test_commit_failure(root: PathBuf, boundary: CommitFailureBoundary) {
    let slot = TEST_COMMIT_FAILURE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(mut guard) = slot.lock() {
        guard.insert(root, boundary);
    }
}

#[cfg(test)]
pub(crate) fn maybe_fail_commit(
    root: &Path,
    boundary: CommitFailureBoundary,
) -> Result<(), GraphStoreError> {
    let should_fail = TEST_COMMIT_FAILURE.get().and_then(|slot| {
        slot.lock().ok().and_then(|mut guard| {
            (guard.get(root).copied() == Some(boundary))
                .then(|| guard.remove(root))
                .flatten()
        })
    });
    if should_fail.is_some() {
        return Err(GraphStoreError::Write {
            path: PathBuf::from("test-commit-boundary"),
            source: io::Error::new(io::ErrorKind::Interrupted, "injected commit boundary"),
        });
    }
    Ok(())
}

#[cfg(test)]
static TEST_ROTATION_FAILURE: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn install_test_rotation_failure(path: PathBuf) {
    let slot = TEST_ROTATION_FAILURE.get_or_init(|| Mutex::new(BTreeSet::new()));
    if let Ok(mut guard) = slot.lock() {
        guard.insert(path);
    }
}

#[cfg(test)]
fn maybe_fail_rotation(path: &Path) -> Result<(), GraphStoreError> {
    let should_fail = TEST_ROTATION_FAILURE.get().and_then(|slot| {
        slot.lock()
            .ok()
            .and_then(|mut guard| guard.remove(path).then_some(()))
    });
    if should_fail.is_some() {
        return Err(GraphStoreError::Write {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::Interrupted, "injected rotation boundary"),
        });
    }
    Ok(())
}

#[cfg(test)]
struct PersistenceBarrierGuard {
    release: Option<Sender<()>>,
    pre_rename: bool,
    path: PathBuf,
}

#[cfg(test)]
impl PersistenceBarrierGuard {
    fn new(path: PathBuf, release: Sender<()>) -> Self {
        Self {
            release: Some(release),
            pre_rename: false,
            path,
        }
    }

    fn new_pre_rename(path: PathBuf, release: Sender<()>) -> Self {
        Self {
            release: Some(release),
            pre_rename: true,
            path,
        }
    }

    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

#[cfg(test)]
impl Drop for PersistenceBarrierGuard {
    fn drop(&mut self) {
        self.release();
        if self.pre_rename {
            clear_test_pre_rename_barrier(&self.path);
        } else {
            clear_test_persistence_barrier(&self.path);
        }
    }
}

#[derive(Debug)]
pub struct FileHypothesisGraphStore {
    root: PathBuf,
    state_path: PathBuf,
    anchor_path: PathBuf,
    high_water_path: PathBuf,
    high_water_tail_path: PathBuf,
    monotonic_anchor: DurableMonotonicAnchor,
    #[allow(dead_code)]
    lock: DurableFileLock,
    mutation_lock: Mutex<()>,
    signer: Keypair,
    limits: GraphResourceLimits,
    scheduler_policy: SchedulerBudgetPolicy,
    graph_id: GraphId,
    signer_id: AgentId,
}

impl FileHypothesisGraphStore {
    pub fn new(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        Self::new_with_scheduler_policy(path, graph, signer, SchedulerBudgetPolicy::global())
    }

    pub fn new_with_config(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphStoreError> {
        if graph.limits != config.resource_limits() {
            return Err(GraphStoreError::InvalidState {
                reason: "graph limits do not match the configured scheduler deployment".to_string(),
            });
        }
        let scheduler_policy =
            SchedulerBudgetPolicy::from_config(config).map_err(GraphStoreError::Admission)?;
        Self::new_with_scheduler_policy(path, graph, signer, scheduler_policy)
    }

    pub fn new_with_scheduler_policy(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
        scheduler_policy: SchedulerBudgetPolicy,
    ) -> Result<Self, GraphStoreError> {
        Self::open_internal(path.as_ref(), Some(graph), signer, scheduler_policy)
    }

    pub fn open_with_graph(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        Self::new(path, graph, signer)
    }

    pub fn open_with_signer(
        path: impl AsRef<Path>,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        let path = path.as_ref().to_path_buf();
        Self::open_internal(&path, None, signer, SchedulerBudgetPolicy::global())
    }

    pub fn open_with_signer_and_config(
        path: impl AsRef<Path>,
        signer: Keypair,
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphStoreError> {
        let path = path.as_ref().to_path_buf();
        let scheduler_policy =
            SchedulerBudgetPolicy::from_config(config).map_err(GraphStoreError::Admission)?;
        let store = Self::open_internal(&path, None, signer, scheduler_policy)?;
        if store.limits != config.resource_limits() {
            return Err(GraphStoreError::InvalidState {
                reason: "persisted graph limits do not match the configured scheduler deployment"
                    .to_string(),
            });
        }
        Ok(store)
    }

    pub fn open_with_signer_and_scheduler_policy(
        path: impl AsRef<Path>,
        signer: Keypair,
        scheduler_policy: SchedulerBudgetPolicy,
    ) -> Result<Self, GraphStoreError> {
        let path = path.as_ref().to_path_buf();
        Self::open_internal(&path, None, signer, scheduler_policy)
    }

    fn open_internal(
        path: &Path,
        initial_graph: Option<HypothesisGraph>,
        signer: Keypair,
        scheduler_policy: SchedulerBudgetPolicy,
    ) -> Result<Self, GraphStoreError> {
        prepare_private_store_root(path)?;
        let lock_path = path.join(GRAPH_STORE_LOCK_FILE);
        let lock_existed = fs::symlink_metadata(&lock_path).is_ok();
        let lock = DurableFileLock::acquire(&lock_path)?;
        let state_path = path.join(GRAPH_STORE_STATE_FILE);
        let anchor_path = path.join(GRAPH_STORE_ANCHOR_FILE);
        let high_water_path = path.join(GRAPH_STORE_HIGH_WATER_FILE);
        let high_water_tail_path = path.join(GRAPH_STORE_HIGH_WATER_TAIL_FILE);
        let monotonic_anchor = DurableMonotonicAnchor::new(path, GRAPH_STORE_STATE_KIND)?;
        ensure_path_not_symlink(&state_path)?;
        ensure_path_not_symlink(&anchor_path)?;
        ensure_path_not_symlink(&high_water_path)?;
        ensure_path_not_symlink(&high_water_tail_path)?;
        let signer_id = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let (graph_id, limits) = if state_path.exists() {
            if !anchor_path.exists() {
                return Err(GraphStoreError::MissingAnchor { path: anchor_path });
            }
            if !high_water_path.exists() {
                return Err(GraphStoreError::MissingHighWater {
                    path: high_water_path,
                });
            }
            if !high_water_tail_path.exists() {
                return Err(GraphStoreError::MissingHighWater {
                    path: high_water_tail_path,
                });
            }
            if !monotonic_anchor.exists() {
                return Err(GraphStoreError::MissingHighWater {
                    path: monotonic_anchor.path().to_path_buf(),
                });
            }
            lock.revalidate()?;
            let authenticated = read_authenticated_state(
                &lock,
                &state_path,
                &anchor_path,
                &high_water_path,
                &high_water_tail_path,
                &signer_id,
                &scheduler_policy,
            )?;
            let mut envelope = authenticated.envelope;
            let limits = envelope.state.graph.limits.clone();
            let graph_id = envelope.state.graph_id.clone();
            let mut state_revision = envelope.revision()?;
            // Resolve a pending write-ahead intent before reading or
            // validating the ordinary state/head/high-water tuple.  Rollback
            // itself is resumable, so a crash between any replacements does
            // not turn a recoverable intent into a permanently invalid tuple.
            let (external_journal, recovered) = recover_external_journal(
                &monotonic_anchor,
                &lock,
                GRAPH_STORE_STATE_KIND,
                graph_id.as_str(),
                &signer,
                &signer_id,
                lock.generation(),
                &lock.identity_token(),
                &state_revision,
            )?;
            let mut head: DurableStateHead = lock.read_json(&anchor_path)?;
            let mut high_water = read_high_water(&lock, &high_water_path, &high_water_tail_path)?;
            let mut head_revision = verify_state_head(
                &head,
                GRAPH_STORE_STATE_KIND,
                graph_id.as_str(),
                &signer_id,
                lock.generation(),
                &lock.identity_token(),
            )?;
            let mut high_water_revision = verify_state_head(
                &high_water,
                GRAPH_STORE_STATE_KIND,
                graph_id.as_str(),
                &signer_id,
                lock.generation(),
                &lock.identity_token(),
            )?;
            if recovered {
                // Re-enter the wire-discriminated reader after recovery.  A
                // recovered legacy record must still be authenticated as the
                // exact legacy shape; routing this second read through
                // `SignedGraphStoreState` would reintroduce serde defaults
                // before the legacy digest/signature check.
                envelope = read_authenticated_state(
                    &lock,
                    &state_path,
                    &anchor_path,
                    &high_water_path,
                    &high_water_tail_path,
                    &signer_id,
                    &scheduler_policy,
                )?
                .envelope;
                state_revision = envelope.revision()?;
                head = lock.read_json(&anchor_path)?;
                head_revision = verify_state_head(
                    &head,
                    GRAPH_STORE_STATE_KIND,
                    graph_id.as_str(),
                    &signer_id,
                    lock.generation(),
                    &lock.identity_token(),
                )?;
                high_water = read_high_water(&lock, &high_water_path, &high_water_tail_path)?;
                high_water_revision = verify_state_head(
                    &high_water,
                    GRAPH_STORE_STATE_KIND,
                    graph_id.as_str(),
                    &signer_id,
                    lock.generation(),
                    &lock.identity_token(),
                )?;
                validate_high_water_against_revisions(
                    &high_water_revision,
                    &head_revision,
                    &state_revision,
                    envelope.state.predecessor_digest.as_deref(),
                )?;
            }
            validate_high_water_against_revisions(
                &high_water_revision,
                &head_revision,
                &state_revision,
                envelope.state.predecessor_digest.as_deref(),
            )?;
            validate_external_journal_against_state(&external_journal, &state_revision)?;
            lock.revalidate()?;
            reconcile_state_head(
                &anchor_path,
                &lock,
                &head_revision,
                &state_revision,
                envelope.state.predecessor_digest.as_deref(),
                GRAPH_STORE_STATE_KIND,
                graph_id.as_str(),
                lock.generation(),
                &lock.identity_token(),
                &signer,
            )?;
            if high_water_revision != state_revision {
                let promoted = sign_state_head(
                    GRAPH_STORE_STATE_KIND,
                    graph_id.as_str(),
                    &state_revision,
                    lock.generation(),
                    &lock.identity_token(),
                    &signer,
                )?;
                lock.revalidate()?;
                append_high_water(&lock, &high_water_path, &high_water_tail_path, &promoted)?;
            }
            if let Some(graph) = initial_graph
                && (graph.graph_id != graph_id || graph.limits != limits)
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "initial graph does not match persisted graph stream".to_string(),
                });
            }
            (graph_id, limits)
        } else {
            if lock_existed {
                return Err(GraphStoreError::MissingState { path: state_path });
            }
            if anchor_path.exists() {
                return Err(GraphStoreError::MissingState { path: state_path });
            }
            if high_water_path.exists()
                || high_water_tail_path.exists()
                || monotonic_anchor.exists()
            {
                return Err(GraphStoreError::MissingState { path: state_path });
            }
            let graph = if let Some(graph) = initial_graph {
                graph
            } else {
                let digest = sha256_hex(path.to_string_lossy().as_bytes());
                let graph_id = GraphId::new(format!("file:{digest}"));
                HypothesisGraph::new(graph_id, GraphResourceLimits::default())
                    .map_err(GraphStoreError::Admission)?
            };
            let limits = graph.limits.clone();
            let state = GraphStoreState::new(graph.clone())?;
            let signed = sign_state(state, &signer, &limits)?;
            let head = sign_state_head(
                GRAPH_STORE_STATE_KIND,
                graph.graph_id.as_str(),
                &signed.revision()?,
                lock.generation(),
                &lock.identity_token(),
                &signer,
            )?;
            let external_commit = sign_external_commit_record(
                GRAPH_STORE_STATE_KIND,
                graph.graph_id.as_str(),
                signed.state.generation,
                &signed.digest,
                0,
                ExternalCommitPhase::Commit,
                None,
                lock.generation(),
                &lock.identity_token(),
                &signer,
            )?;
            // The sibling commit is the first durable record.  If the process
            // dies before the root files exist, restart sees the orphaned
            // external commit and refuses to reinitialize the stream.
            let external_lock = monotonic_anchor.acquire_lock()?;
            monotonic_anchor.append_external_locked(&external_lock, &external_commit)?;
            lock.revalidate()?;
            lock.atomic_write_json(&state_path, &signed)?;
            lock.revalidate()?;
            lock.atomic_write_json(&anchor_path, &head)?;
            append_high_water(&lock, &high_water_path, &high_water_tail_path, &head)?;
            (graph.graph_id.clone(), limits)
        };
        Ok(Self {
            root: path.to_path_buf(),
            state_path,
            anchor_path,
            high_water_path,
            high_water_tail_path,
            monotonic_anchor,
            lock,
            mutation_lock: Mutex::new(()),
            signer,
            limits,
            scheduler_policy,
            graph_id,
            signer_id,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn anchor_path(&self) -> &Path {
        &self.anchor_path
    }

    pub fn revision(&self) -> Result<GraphStoreRevision, GraphStoreError> {
        self.snapshot().map(|snapshot| snapshot.revision)
    }

    pub fn state_digest(&self) -> Result<String, GraphStoreError> {
        self.snapshot().map(|snapshot| snapshot.revision.digest)
    }

    pub fn signer_id(&self) -> &AgentId {
        &self.signer_id
    }

    fn read_signed(&self) -> Result<SignedGraphStoreState, GraphStoreError> {
        self.lock.revalidate()?;
        if !self.state_path.exists() {
            return Err(GraphStoreError::MissingState {
                path: self.state_path.clone(),
            });
        }
        if !self.anchor_path.exists() {
            return Err(GraphStoreError::MissingAnchor {
                path: self.anchor_path.clone(),
            });
        }
        if !self.high_water_path.exists() {
            return Err(GraphStoreError::MissingHighWater {
                path: self.high_water_path.clone(),
            });
        }
        if !self.high_water_tail_path.exists() {
            return Err(GraphStoreError::MissingHighWater {
                path: self.high_water_tail_path.clone(),
            });
        }
        if !self.monotonic_anchor.exists() {
            return Err(GraphStoreError::MissingHighWater {
                path: self.monotonic_anchor.path().to_path_buf(),
            });
        }
        let authenticated = read_authenticated_state(
            &self.lock,
            &self.state_path,
            &self.anchor_path,
            &self.high_water_path,
            &self.high_water_tail_path,
            &self.signer_id,
            &self.scheduler_policy,
        )?;
        let mut envelope = authenticated.envelope;
        let mut state_revision = envelope.revision()?;
        // Pending rollback is a recovery decision, not an ordinary tuple
        // validation failure.  Resolve it before loading the head/high-water
        // files because recovery may have stopped between replacements.
        let (external_journal, recovered) = recover_external_journal(
            &self.monotonic_anchor,
            &self.lock,
            GRAPH_STORE_STATE_KIND,
            self.graph_id.as_str(),
            &self.signer,
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
            &state_revision,
        )?;
        let mut head: DurableStateHead = self.lock.read_json(&self.anchor_path)?;
        let mut high_water = read_high_water(
            &self.lock,
            &self.high_water_path,
            &self.high_water_tail_path,
        )?;
        let mut head_revision = verify_state_head(
            &head,
            GRAPH_STORE_STATE_KIND,
            self.graph_id.as_str(),
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
        )?;
        let mut high_water_revision = verify_state_head(
            &high_water,
            GRAPH_STORE_STATE_KIND,
            self.graph_id.as_str(),
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
        )?;
        if recovered {
            // Preserve the exact legacy-wire authentication boundary after a
            // recovered write, too.  Defaults are only allowed after the
            // marker-specific digest/signature/high-water checks complete.
            envelope = read_authenticated_state(
                &self.lock,
                &self.state_path,
                &self.anchor_path,
                &self.high_water_path,
                &self.high_water_tail_path,
                &self.signer_id,
                &self.scheduler_policy,
            )?
            .envelope;
            state_revision = envelope.revision()?;
            head = self.lock.read_json(&self.anchor_path)?;
            head_revision = verify_state_head(
                &head,
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                &self.signer_id,
                self.lock.generation(),
                &self.lock.identity_token(),
            )?;
            high_water = read_high_water(
                &self.lock,
                &self.high_water_path,
                &self.high_water_tail_path,
            )?;
            high_water_revision = verify_state_head(
                &high_water,
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                &self.signer_id,
                self.lock.generation(),
                &self.lock.identity_token(),
            )?;
            validate_high_water_against_revisions(
                &high_water_revision,
                &head_revision,
                &state_revision,
                envelope.state.predecessor_digest.as_deref(),
            )?;
        }
        validate_high_water_against_revisions(
            &high_water_revision,
            &head_revision,
            &state_revision,
            envelope.state.predecessor_digest.as_deref(),
        )?;
        validate_external_journal_against_state(&external_journal, &state_revision)?;
        self.lock.revalidate()?;
        reconcile_state_head(
            &self.anchor_path,
            &self.lock,
            &head_revision,
            &state_revision,
            envelope.state.predecessor_digest.as_deref(),
            GRAPH_STORE_STATE_KIND,
            self.graph_id.as_str(),
            self.lock.generation(),
            &self.lock.identity_token(),
            &self.signer,
        )?;
        if high_water_revision != state_revision {
            let promoted = sign_state_head(
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                &state_revision,
                self.lock.generation(),
                &self.lock.identity_token(),
                &self.signer,
            )?;
            self.lock.revalidate()?;
            append_high_water(
                &self.lock,
                &self.high_water_path,
                &self.high_water_tail_path,
                &promoted,
            )?;
        }
        Ok(envelope)
    }

    fn mutate<R, F>(
        &self,
        expected: Option<&GraphStoreRevision>,
        operation: F,
    ) -> Result<(GraphStoreSnapshot, R), GraphStoreError>
    where
        F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
    {
        self.mutate_with_exact_retry(expected, |_| Ok(None), operation)
    }

    fn mutate_with_exact_retry<R, P, F>(
        &self,
        expected: Option<&GraphStoreRevision>,
        exact_retry: P,
        operation: F,
    ) -> Result<(GraphStoreSnapshot, R), GraphStoreError>
    where
        P: FnOnce(&GraphStoreState) -> Result<Option<R>, GraphStoreError>,
        F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
    {
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| GraphStoreError::PoisonedLock)?;
        let current = self.read_signed()?;
        let (next, value) = transition_with_exact_retry(
            &current,
            expected,
            &self.signer,
            &self.limits,
            &self.scheduler_policy,
            exact_retry,
            operation,
        )?;
        if next != current {
            let external_lock = self.monotonic_anchor.acquire_lock()?;
            let external_records = self.monotonic_anchor.read_records_locked(&external_lock)?;
            self.monotonic_anchor
                .validate_tail_locked(&external_lock, &external_records)?;
            let mut journal = verify_external_journal(
                &external_records,
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                &self.signer_id,
                self.lock.generation(),
                &self.lock.identity_token(),
            )?;
            if journal.pending.is_some() {
                return Err(GraphStoreError::ReplayDetected {
                    expected_generation: next.state.generation,
                    observed_generation: journal.committed.generation,
                });
            }
            if self.monotonic_anchor.rotate_if_needed_locked(
                &external_lock,
                &journal.committed,
                &self.signer,
            )? {
                let rotated_records = self.monotonic_anchor.read_records_locked(&external_lock)?;
                self.monotonic_anchor
                    .validate_tail_locked(&external_lock, &rotated_records)?;
                journal = verify_external_journal(
                    &rotated_records,
                    GRAPH_STORE_STATE_KIND,
                    self.graph_id.as_str(),
                    &self.signer_id,
                    self.lock.generation(),
                    &self.lock.identity_token(),
                )?;
            }
            let next_revision = next.revision()?;
            let intent = sign_external_commit_record(
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                next_revision.generation,
                &next_revision.digest,
                journal.last_sequence.checked_add(1).ok_or_else(|| {
                    GraphStoreError::InvalidState {
                        reason: "external journal sequence overflow".to_string(),
                    }
                })?,
                ExternalCommitPhase::Intent,
                Some(journal.last_record_digest),
                self.lock.generation(),
                &self.lock.identity_token(),
                &self.signer,
            )?;
            let base_head: DurableStateHead = self.lock.read_json(&self.anchor_path)?;
            let _base_high_water = read_high_water(
                &self.lock,
                &self.high_water_path,
                &self.high_water_tail_path,
            )?;
            let base_high_water_tail = self.lock.read_bytes(&self.high_water_tail_path)?;
            let base_state_bytes =
                serde_json::to_vec(&current).map_err(|source| GraphStoreError::Serialize {
                    path: self.state_path.clone(),
                    source,
                })?;
            let base_head_bytes =
                serde_json::to_vec(&base_head).map_err(|source| GraphStoreError::Serialize {
                    path: self.anchor_path.clone(),
                    source,
                })?;
            let base_high_water_bytes = self.lock.read_bytes(&self.high_water_path)?;
            stage_transaction(
                &self.lock,
                &intent.transaction_id,
                &current.revision()?,
                &base_state_bytes,
                &base_head_bytes,
                &base_high_water_bytes,
                &base_high_water_tail,
            )?;
            self.monotonic_anchor
                .append_external_locked(&external_lock, &intent)?;
            #[cfg(test)]
            maybe_fail_commit(&self.root, CommitFailureBoundary::ExternalIntent)?;
            self.lock.revalidate()?;
            self.lock.atomic_write_json(&self.state_path, &next)?;
            #[cfg(test)]
            maybe_fail_commit(&self.root, CommitFailureBoundary::State)?;
            let head = sign_state_head(
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                &next.revision()?,
                self.lock.generation(),
                &self.lock.identity_token(),
                &self.signer,
            )?;
            self.lock.revalidate()?;
            self.lock.atomic_write_json(&self.anchor_path, &head)?;
            #[cfg(test)]
            maybe_fail_commit(&self.root, CommitFailureBoundary::Head)?;
            append_high_water(
                &self.lock,
                &self.high_water_path,
                &self.high_water_tail_path,
                &head,
            )?;
            #[cfg(test)]
            maybe_fail_commit(&self.root, CommitFailureBoundary::HighWater)?;
            let commit = sign_external_commit_record(
                GRAPH_STORE_STATE_KIND,
                self.graph_id.as_str(),
                next_revision.generation,
                &next_revision.digest,
                intent
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| GraphStoreError::InvalidState {
                        reason: "external journal sequence overflow".to_string(),
                    })?,
                ExternalCommitPhase::Commit,
                Some(intent.record_digest),
                self.lock.generation(),
                &self.lock.identity_token(),
                &self.signer,
            )?;
            self.monotonic_anchor
                .append_external_locked(&external_lock, &commit)?;
            let _ = clear_transaction_stage(&self.lock);
        }
        Ok((next.snapshot()?, value))
    }

    fn result_from_marker(
        snapshot: GraphStoreSnapshot,
        marker: TaskMutationMarker,
    ) -> TaskMutationResult {
        let task_generation = snapshot
            .state
            .tasks
            .get(&marker.task.request.task_id)
            .map_or(0, |entry| entry.generation);
        TaskMutationResult {
            task: marker.task.clone(),
            lease: marker.task.lease.clone(),
            generation: snapshot.revision.generation,
            task_generation,
            revision: snapshot.revision,
            idempotent: marker.idempotent,
        }
    }

    fn compare_and_swap_reasoning(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
        initial_decision_admission: InitialDecisionAdmission<'_>,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let (snapshot, _) = self.mutate(Some(expected), |current| {
            if state.graph_id != self.graph_id {
                return Err(GraphStoreError::InvalidState {
                    reason: "replacement graph ID differs from store stream".to_string(),
                });
            }
            if state.generation != current.generation
                || state.predecessor_digest != current.predecessor_digest
            {
                return Err(GraphStoreError::StalePredecessor {
                    expected_generation: current.generation,
                    expected_digest: current.digest()?,
                    observed_generation: state.generation,
                    observed_digest: state.digest()?,
                });
            }
            if state.fencing_counter < current.fencing_counter {
                return Err(GraphStoreError::InvalidState {
                    reason: "compare-and-swap candidate fencing counter regressed".to_string(),
                });
            }
            if state.logical_time_high_water < current.logical_time_high_water {
                return Err(GraphStoreError::InvalidState {
                    reason: "compare-and-swap candidate logical time high-water regressed"
                        .to_string(),
                });
            }
            state.validate_with_limits(&self.limits)?;
            validate_reasoning_cas_transition(
                current,
                &state,
                &self.limits,
                &self.scheduler_policy,
                initial_decision_admission,
            )?;
            current.graph = state.graph;
            current.hypotheses = state.hypotheses;
            current.tasks = state.tasks;
            current.logical_task_descriptors = state.logical_task_descriptors;
            current.task_tombstones = state.task_tombstones;
            current.terminal_outbox = state.terminal_outbox;
            current.task_failure_outbox = state.task_failure_outbox;
            current.fencing_counter = state.fencing_counter;
            current.limits = state.limits;
            current.cross_graph_links = state.cross_graph_links;
            current.scheduler_budget = state.scheduler_budget;
            current.migration_marker = state.migration_marker;
            current.result_projection_digest = state.result_projection_digest;
            current.operator_projection_digest = state.operator_projection_digest;
            current.logical_time_high_water = state.logical_time_high_water;
            Ok(StateMutation {
                value: (),
                changed: true,
            })
        })?;
        Ok(snapshot)
    }
}

impl HypothesisGraphStore for FileHypothesisGraphStore {
    fn fail_reasoning_task_cas(
        &self,
        expected: &GraphStoreRevision,
        expected_generation: u64,
        publication: TaskFailureOutboxEntry,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let retry_publication = publication.clone();
        let (snapshot, marker) = self.mutate_with_exact_retry(
            Some(expected),
            |state| exact_reasoning_failure_retry(state, &retry_publication),
            |state| fail_reasoning_task_op(state, expected_generation, publication, &self.limits),
        )?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.read_signed()?.snapshot()
    }

    fn compare_and_swap(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.compare_and_swap_reasoning(expected, state, InitialDecisionAdmission::Reject)
    }

    fn compare_and_swap_coordinator_seed(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
        coordinator_identity: &AgentId,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.compare_and_swap_reasoning(
            expected,
            state,
            InitialDecisionAdmission::AuthenticatedCoordinator(coordinator_identity),
        )
    }

    fn create_task(
        &self,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) =
            self.mutate(None, |state| create_task_op(state, request, &self.limits))?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            create_task_op(state, request, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reject_unbudgeted_reasoning_task_surface(state, "claim")?;
            claim_task_op(state, request, now, lease_duration_ms, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            reject_unbudgeted_reasoning_task_surface(state, "claim")?;
            claim_task_op(state, request, now, lease_duration_ms, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_with_budget(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            claim_task_with_budget_op(
                state,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            claim_task_with_budget_op(
                state,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn renew_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            renew_task_op(
                state,
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                lease_duration_ms,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn complete_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        completion: TaskCompletion,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            complete_task_op(
                state,
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                completion,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn fail_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        failure: TaskFailure,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            fail_task_op(
                state,
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                failure,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn expire_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        now: GraphLogicalTime,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            expire_task_op(state, task_id, expected_generation, now, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reject_unbudgeted_reasoning_task_surface(state, "reclaim")?;
            reclaim_task_op(
                state,
                task_id,
                request,
                now,
                lease_duration_ms,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task_with_budget(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reclaim_task_with_budget_op(
                state,
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            reclaim_task_with_budget_op(
                state,
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }
}

/// Runtime composition may choose memory or local files without changing the
/// logical operation API.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ConfiguredHypothesisGraphStore {
    Memory(MemoryHypothesisGraphStore),
    LocalFiles(FileHypothesisGraphStore),
}

impl ConfiguredHypothesisGraphStore {
    pub fn memory(graph: HypothesisGraph, signer: Keypair) -> Result<Self, GraphStoreError> {
        Ok(Self::Memory(MemoryHypothesisGraphStore::new(
            graph, signer,
        )?))
    }

    pub fn memory_with_config(
        graph: HypothesisGraph,
        signer: Keypair,
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self::Memory(MemoryHypothesisGraphStore::new_with_config(
            graph, signer, config,
        )?))
    }

    pub fn memory_with_scheduler_policy(
        graph: HypothesisGraph,
        signer: Keypair,
        scheduler_policy: SchedulerBudgetPolicy,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self::Memory(
            MemoryHypothesisGraphStore::new_with_scheduler_policy(graph, signer, scheduler_policy)?,
        ))
    }

    pub fn local_files(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self::LocalFiles(FileHypothesisGraphStore::new(
            path, graph, signer,
        )?))
    }

    pub fn local_files_with_config(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
        config: &swarm_core::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self::LocalFiles(FileHypothesisGraphStore::new_with_config(
            path, graph, signer, config,
        )?))
    }
}

impl HypothesisGraphStore for ConfiguredHypothesisGraphStore {
    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
        match self {
            Self::Memory(store) => store.snapshot(),
            Self::LocalFiles(store) => store.snapshot(),
        }
    }

    fn compare_and_swap(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        match self {
            Self::Memory(store) => store.compare_and_swap(expected, state),
            Self::LocalFiles(store) => store.compare_and_swap(expected, state),
        }
    }

    fn compare_and_swap_coordinator_seed(
        &self,
        expected: &GraphStoreRevision,
        state: GraphStoreState,
        coordinator_identity: &AgentId,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        match self {
            Self::Memory(store) => {
                store.compare_and_swap_coordinator_seed(expected, state, coordinator_identity)
            }
            Self::LocalFiles(store) => {
                store.compare_and_swap_coordinator_seed(expected, state, coordinator_identity)
            }
        }
    }

    fn create_task(
        &self,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.create_task(request),
            Self::LocalFiles(store) => store.create_task(request),
        }
    }

    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.create_task_cas(expected, request),
            Self::LocalFiles(store) => store.create_task_cas(expected, request),
        }
    }

    fn claim_task(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.claim_task(request, now, lease_duration_ms),
            Self::LocalFiles(store) => store.claim_task(request, now, lease_duration_ms),
        }
    }

    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.claim_task_cas(expected, request, now, lease_duration_ms),
            Self::LocalFiles(store) => {
                store.claim_task_cas(expected, request, now, lease_duration_ms)
            }
        }
    }

    fn claim_task_with_budget(
        &self,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => {
                store.claim_task_with_budget(request, now, lease_duration_ms, scheduler_budget)
            }
            Self::LocalFiles(store) => {
                store.claim_task_with_budget(request, now, lease_duration_ms, scheduler_budget)
            }
        }
    }

    fn claim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.claim_task_cas_with_budget(
                expected,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            ),
            Self::LocalFiles(store) => store.claim_task_cas_with_budget(
                expected,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            ),
        }
    }

    fn reclaim_task_with_budget(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.reclaim_task_with_budget(
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            ),
            Self::LocalFiles(store) => store.reclaim_task_with_budget(
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            ),
        }
    }

    fn reclaim_task_cas_with_budget(
        &self,
        expected: &GraphStoreRevision,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        scheduler_budget: SchedulerBudget,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.reclaim_task_cas_with_budget(
                expected,
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            ),
            Self::LocalFiles(store) => store.reclaim_task_cas_with_budget(
                expected,
                task_id,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            ),
        }
    }

    fn renew_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.renew_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                lease_duration_ms,
            ),
            Self::LocalFiles(store) => store.renew_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                lease_duration_ms,
            ),
        }
    }

    fn complete_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        completion: TaskCompletion,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.complete_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                completion,
            ),
            Self::LocalFiles(store) => store.complete_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                completion,
            ),
        }
    }

    fn fail_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        lease_id: &LeaseId,
        fence: FencingToken,
        now: GraphLogicalTime,
        failure: TaskFailure,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => {
                store.fail_task(task_id, expected_generation, lease_id, fence, now, failure)
            }
            Self::LocalFiles(store) => {
                store.fail_task(task_id, expected_generation, lease_id, fence, now, failure)
            }
        }
    }

    fn fail_reasoning_task_cas(
        &self,
        expected: &GraphStoreRevision,
        expected_generation: u64,
        publication: TaskFailureOutboxEntry,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => {
                store.fail_reasoning_task_cas(expected, expected_generation, publication)
            }
            Self::LocalFiles(store) => {
                store.fail_reasoning_task_cas(expected, expected_generation, publication)
            }
        }
    }

    fn expire_task(
        &self,
        task_id: &str,
        expected_generation: u64,
        now: GraphLogicalTime,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.expire_task(task_id, expected_generation, now),
            Self::LocalFiles(store) => store.expire_task(task_id, expected_generation, now),
        }
    }

    fn reclaim_task(
        &self,
        task_id: &str,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.reclaim_task(task_id, request, now, lease_duration_ms),
            Self::LocalFiles(store) => store.reclaim_task(task_id, request, now, lease_duration_ms),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::hypothesis_graph::{
        ActorNode, CausalEdge, CausalRelation, ConfidenceBucket, ConfidenceDistribution, EdgeState,
        EventNode, EvidenceId, EvidenceScope, EvidenceSourceFamily, GraphNode, GraphProducerRole,
        TaskCompletionKind, TaskId, TaskKind, TaskTarget, UncertaintyReason,
    };

    fn signer(byte: u8) -> Keypair {
        Keypair::from_seed(&[byte; 32])
    }

    fn graph() -> HypothesisGraph {
        HypothesisGraph::new(GraphId::new("graph:test"), GraphResourceLimits::default()).unwrap()
    }

    fn request_at(byte: u8, task_suffix: &str, requested_at: GraphLogicalTime) -> TaskClaimRequest {
        let key = signer(byte);
        TaskClaimRequest::new(
            TaskId::new(format!("task:{task_suffix}")),
            TaskKind::AcquireEvidence,
            TaskTarget::Evidence {
                evidence_id: EvidenceId::new(format!("evidence:{task_suffix}")),
            },
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&key.public_key().to_hex()),
            EvidenceScope::new(
                [EvidenceSourceFamily::Process],
                [EvidenceId::new(format!("evidence:{task_suffix}"))],
                std::iter::empty(),
            )
            .unwrap(),
            requested_at,
        )
        .unwrap()
    }

    fn request(byte: u8, task_suffix: &str) -> TaskClaimRequest {
        request_at(byte, task_suffix, GraphLogicalTime::new(100))
    }

    fn logical_request(byte: u8, task_suffix: &str) -> (LogicalTaskDescriptor, TaskClaimRequest) {
        let evidence_id = EvidenceId::new(format!("evidence:logical:{task_suffix}"));
        let target = TaskTarget::Evidence {
            evidence_id: evidence_id.clone(),
        };
        let descriptor = LogicalTaskDescriptor::new(
            GraphId::new("graph:test"),
            target.clone(),
            TaskKind::AcquireEvidence,
            "ab".repeat(32),
        )
        .unwrap();
        let claimant_key = signer(byte);
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target,
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&claimant_key.public_key().to_hex()),
            EvidenceScope::new([], [evidence_id], []).unwrap(),
            GraphLogicalTime::new(100),
        )
        .unwrap();
        (descriptor, request)
    }

    fn budget_at(logical_tick: GraphLogicalTime, work_units: u32, claims: u16) -> SchedulerBudget {
        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut budget = SchedulerBudget::new_with_config(&config, logical_tick).unwrap();
        budget
            .admit_at(&config, logical_tick, work_units, claims)
            .unwrap();
        budget
    }

    fn budget_policy() -> SchedulerBudgetPolicy {
        SchedulerBudgetPolicy::new(10, 2).unwrap()
    }

    fn migrate_with_budget(
        store: &dyn HypothesisGraphStore,
        budget: SchedulerBudget,
        logical_time_high_water: GraphLogicalTime,
    ) -> GraphStoreSnapshot {
        let initial = store.snapshot().unwrap();
        let candidate = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                logical_time_high_water,
            )
            .with_scheduler_budget(budget),
        )
        .unwrap();
        store
            .compare_and_swap(&initial.revision, candidate)
            .unwrap()
    }

    /// Build the important migration boundary for budgeted claims: a legacy
    /// pending task already has an authenticated v0 tombstone, so promotion
    /// must preserve its empty history digest until the first v1 transition
    /// refreshes it.
    fn migrate_legacy_pending_with_budget(
        store: &dyn HypothesisGraphStore,
        descriptor: LogicalTaskDescriptor,
        request: TaskClaimRequest,
        budget: SchedulerBudget,
    ) -> GraphStoreSnapshot {
        store.create_task(request.clone()).unwrap();
        let initial = store.snapshot().unwrap();
        let candidate = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                request.requested_at,
            )
            .with_tasks(initial.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )]))
            .with_scheduler_budget(budget),
        )
        .unwrap();
        let migrated = store
            .compare_and_swap(&initial.revision, candidate)
            .unwrap();
        assert!(
            migrated
                .state
                .task_tombstones
                .values()
                .all(|tombstone| tombstone.history_digest.is_empty())
        );
        migrated
    }

    fn migrate_legacy_expired_with_budget(
        store: &dyn HypothesisGraphStore,
        descriptor: LogicalTaskDescriptor,
        request: TaskClaimRequest,
        budget: SchedulerBudget,
    ) -> GraphStoreSnapshot {
        let claimed = store
            .claim_task(request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        store
            .expire_task(
                request.task_id.as_str(),
                claimed.task_generation,
                GraphLogicalTime::new(110),
            )
            .unwrap();
        let initial = store.snapshot().unwrap();
        let candidate = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(110),
            )
            .with_tasks(initial.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )]))
            .with_scheduler_budget(budget),
        )
        .unwrap();
        store
            .compare_and_swap(&initial.revision, candidate)
            .unwrap()
    }

    fn tamper_budget_field(
        budget: &SchedulerBudget,
        field: &str,
        value: serde_json::Value,
    ) -> SchedulerBudget {
        let mut wire = serde_json::to_value(budget).unwrap();
        wire[field] = value;
        serde_json::from_value(wire).unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("swarm-spine-{name}-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn legacy_signed_bytes_are_verified_before_reasoning_defaults() {
        let path = temp_dir("legacy-defaults");
        let key = signer(81);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let original_state = fs::read(store.state_path()).unwrap();
        drop(store);

        // Remove every optional reasoning field to model a signed v0 state.
        // These fields all default to the empty/legacy values, so the
        // canonical state digest and detached signature remain valid.
        let mut legacy: serde_json::Value = serde_json::from_slice(&original_state).unwrap();
        let state = legacy
            .get_mut("state")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        for field in [
            "hypotheses",
            "logical_task_descriptors",
            "terminal_outbox",
            "limits",
            "cross_graph_links",
            "scheduler_budget",
            "migration_marker",
            "result_projection_digest",
            "operator_projection_digest",
        ] {
            state.remove(field);
        }
        fs::write(
            path.join(GRAPH_STORE_STATE_FILE),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();

        // An attacker cannot add an empty reasoning map and rely on its
        // skip-serialization default to preserve the old signature. The
        // exact legacy parser rejects the field before normalization.
        let mut unknown_field = legacy.clone();
        unknown_field["state"]["hypotheses"] = serde_json::json!({});
        fs::write(
            path.join(GRAPH_STORE_STATE_FILE),
            serde_json::to_vec(&unknown_field).unwrap(),
        )
        .unwrap();
        assert!(FileHypothesisGraphStore::open_with_signer(&path, key.clone()).is_err());

        let mut zero_marker = legacy.clone();
        zero_marker["state"]["migration_marker"] = serde_json::json!(0);
        fs::write(
            path.join(GRAPH_STORE_STATE_FILE),
            serde_json::to_vec(&zero_marker).unwrap(),
        )
        .unwrap();
        assert!(FileHypothesisGraphStore::open_with_signer(&path, key.clone()).is_err());
        fs::write(path.join(GRAPH_STORE_STATE_FILE), original_state).unwrap();

        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key.clone()).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(snapshot.migration_marker(), GRAPH_STATE_MIGRATION_LEGACY);
        assert!(snapshot.scheduler_budget().is_none());
        assert_eq!(
            snapshot.state.logical_time_high_water,
            GraphLogicalTime::new(0)
        );
        drop(reopened);

        // A tampered value must fail signature verification; serde defaults
        // are never allowed to turn an unauthenticated legacy payload into a
        // reasoning state.
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join(GRAPH_STORE_STATE_FILE)).unwrap()).unwrap();
        tampered["state"]["logical_time_high_water"] = serde_json::json!(7);
        fs::write(
            path.join(GRAPH_STORE_STATE_FILE),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        assert!(FileHypothesisGraphStore::open_with_signer(&path, key).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn scheduler_budget_survives_file_reopen_and_state_deserialize() {
        let path = temp_dir("scheduler-budget-reopen");
        let key = signer(83);
        let store = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let budget = budget_at(GraphLogicalTime::new(7), 6, 1);
        let migrated = migrate_with_budget(&store, budget.clone(), GraphLogicalTime::new(7));
        assert_eq!(migrated.scheduler_budget(), Some(&budget));

        let encoded = serde_json::to_vec(migrated.state()).unwrap();
        let decoded: GraphStoreState = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.scheduler_budget, Some(budget.clone()));
        drop(migrated);
        drop(store);

        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        let reopened_snapshot = reopened.snapshot().unwrap();
        assert_eq!(reopened_snapshot.scheduler_budget(), Some(&budget));
        assert_eq!(reopened_snapshot.state().scheduler_budget, Some(budget));
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn scheduler_budget_cas_rejects_reset_rollback_overflow_and_tamper_without_mutation() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(84),
            budget_policy(),
        )
        .unwrap();
        let budget = budget_at(GraphLogicalTime::new(7), 6, 1);
        let migrated = migrate_with_budget(&store, budget.clone(), GraphLogicalTime::new(7));
        let baseline_state = migrated.state.clone();
        let baseline_revision = migrated.revision.clone();

        let mut reset = baseline_state.clone();
        reset.scheduler_budget = None;
        assert!(matches!(
            store.compare_and_swap(&baseline_revision, reset),
            Err(GraphStoreError::InvalidState { reason }) if reason.contains("budget")
        ));
        assert_eq!(store.snapshot().unwrap().state, baseline_state);

        let mut rollback = baseline_state.clone();
        rollback.scheduler_budget = Some(tamper_budget_field(
            &budget,
            "work_units_used",
            serde_json::json!(5),
        ));
        assert!(matches!(
            store.compare_and_swap(&baseline_revision, rollback),
            Err(GraphStoreError::InvalidState { reason }) if reason.contains("counters regressed")
        ));
        assert_eq!(store.snapshot().unwrap().state, baseline_state);

        let mut widened = baseline_state.clone();
        widened.scheduler_budget = Some(tamper_budget_field(
            &budget,
            "max_work_units",
            serde_json::json!(9),
        ));
        assert!(matches!(
            store.compare_and_swap(&baseline_revision, widened),
            Err(GraphStoreError::InvalidState { reason }) if reason.contains("ceilings changed")
        ));
        assert_eq!(store.snapshot().unwrap().state, baseline_state);

        let mut overflow_wire = serde_json::to_value(&budget).unwrap();
        overflow_wire["work_units_used"] = serde_json::json!(u32::MAX);
        assert!(serde_json::from_value::<SchedulerBudget>(overflow_wire).is_err());
        assert_eq!(store.snapshot().unwrap().state, baseline_state);
    }

    #[test]
    fn direct_cas_create_requires_exact_work_delta_and_tick() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(125),
            budget_policy(),
        )
        .unwrap();
        let migrated = migrate_with_budget(
            &store,
            budget_at(GraphLogicalTime::new(100), 0, 0),
            GraphLogicalTime::new(100),
        );
        let (descriptor, request) = logical_request(125, "direct-create-budget");
        let durable = DurableTaskRecord {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            task: TaskRecord {
                schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
                request: request.clone(),
                state: TaskState::Pending,
                generation: 1,
                attempts: 1,
                lease: None,
                completion: None,
                terminal_history: Vec::new(),
            },
            generation: 1,
            history: Vec::new(),
        };
        let mut candidate = migrated.state.clone();
        candidate
            .tasks
            .insert(request.task_id.clone(), durable.clone());
        candidate
            .logical_task_descriptors
            .insert(request.task_id.clone(), descriptor);
        candidate.task_tombstones.insert(
            request.task_id.clone(),
            TaskMonotonicity::from_record(&durable).unwrap(),
        );

        for bad_budget in [
            budget_at(GraphLogicalTime::new(100), 0, 0),
            budget_at(GraphLogicalTime::new(100), 2, 0),
            budget_at(GraphLogicalTime::new(101), 1, 0),
        ] {
            let mut bad_candidate = candidate.clone();
            bad_candidate.scheduler_budget = Some(bad_budget);
            let before = store.snapshot().unwrap();
            let error = store
                .compare_and_swap(&before.revision, bad_candidate)
                .unwrap_err();
            assert!(matches!(
                error,
                GraphStoreError::InvalidState { reason }
                    if reason.contains("scheduler budget")
            ));
            assert_eq!(store.snapshot().unwrap(), before);
        }

        candidate.scheduler_budget = Some(budget_at(GraphLogicalTime::new(100), 1, 0));
        let accepted = store
            .compare_and_swap(&migrated.revision, candidate)
            .unwrap();
        assert_eq!(
            accepted.scheduler_budget(),
            Some(&budget_at(GraphLogicalTime::new(100), 1, 0))
        );
        assert_eq!(
            accepted.state().tasks[&request.task_id].task.state,
            TaskState::Pending
        );
    }

    #[test]
    fn claim_with_budget_commits_task_and_budget_in_one_generation() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(85),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(86, "budget-claim");
        let task = TaskRecord {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            request: request.clone(),
            state: TaskState::Pending,
            generation: 1,
            attempts: 1,
            lease: None,
            completion: None,
            terminal_history: Vec::new(),
        };
        let durable = DurableTaskRecord {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            task,
            generation: 1,
            history: Vec::new(),
        };
        let mut tasks = BTreeMap::new();
        tasks.insert(descriptor.task_id.clone(), durable);
        let mut descriptors = BTreeMap::new();
        descriptors.insert(descriptor.task_id.clone(), descriptor);
        let initial = store.snapshot().unwrap();
        let initial_revision = initial.revision.clone();
        let migrated = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(100),
            )
            .with_tasks(tasks)
            .with_logical_task_descriptors(descriptors)
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(100), 1, 0)),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&initial_revision, migrated).unwrap();

        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut next_budget = budget_at(GraphLogicalTime::new(100), 1, 0);
        next_budget
            .admit_at(&config, GraphLogicalTime::new(100), 0, 1)
            .unwrap();
        let claimed = store
            .claim_task_with_budget(
                request.clone(),
                GraphLogicalTime::new(100),
                100,
                next_budget.clone(),
            )
            .unwrap();
        assert!(!claimed.idempotent);
        let after_claim = store.snapshot().unwrap();
        assert_eq!(
            after_claim.revision().generation,
            migrated.revision().generation + 1
        );
        assert_eq!(after_claim.scheduler_budget(), Some(&next_budget));
        assert_eq!(
            after_claim.state().tasks[&request.task_id].task.state,
            TaskState::Claimed
        );

        let mut failed_budget = next_budget.clone();
        failed_budget
            .admit_at(&config, GraphLogicalTime::new(100), 1, 0)
            .unwrap();
        let before_failed_cas = after_claim.state.clone();
        let before_failed_revision = after_claim.revision.clone();
        assert!(matches!(
            store.claim_task_cas_with_budget(
                &migrated.revision,
                request,
                GraphLogicalTime::new(100),
                100,
                failed_budget,
            ),
            Err(GraphStoreError::StalePredecessor { .. })
        ));
        let after_failed = store.snapshot().unwrap();
        assert_eq!(after_failed.state, before_failed_cas);
        assert_eq!(after_failed.revision, before_failed_revision);
    }

    #[test]
    fn claim_with_budget_refreshes_legacy_tombstone_atomically() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(100),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(101, "budget-legacy-tombstone");
        let migrated = migrate_legacy_pending_with_budget(
            &store,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let task_id = request.task_id.clone();
        let legacy_tombstone = migrated.state.task_tombstones[&task_id].clone();
        assert!(legacy_tombstone.history_digest.is_empty());

        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut next_budget = budget_at(GraphLogicalTime::new(100), 0, 0);
        next_budget
            .admit_at(&config, GraphLogicalTime::new(100), 0, 1)
            .unwrap();
        let claimed = store
            .claim_task_cas_with_budget(
                &migrated.revision,
                request,
                GraphLogicalTime::new(100),
                10,
                next_budget.clone(),
            )
            .unwrap();
        assert!(!claimed.idempotent);

        let after = store.snapshot().unwrap();
        let durable = after.state.tasks.get(&task_id).unwrap();
        let refreshed = after.state.task_tombstones.get(&task_id).unwrap();
        assert_eq!(refreshed, &TaskMonotonicity::from_record(durable).unwrap());
        assert!(!refreshed.history_digest.is_empty());
        assert_eq!(after.scheduler_budget(), Some(&next_budget));
        assert_eq!(
            after.revision.generation,
            migrated.revision.generation + 1,
            "task, tombstone, and budget must publish in one generation"
        );
    }

    #[test]
    fn claim_with_budget_preserves_untouched_legacy_tombstones() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(108),
            budget_policy(),
        )
        .unwrap();
        let (descriptor_one, request_one) = logical_request(109, "budget-tombstone-one");
        let (descriptor_two, request_two) = logical_request(110, "budget-tombstone-two");
        store.create_task(request_one.clone()).unwrap();
        store.create_task(request_two.clone()).unwrap();
        let initial = store.snapshot().unwrap();
        let candidate = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(100),
            )
            .with_tasks(initial.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([
                (descriptor_one.task_id.clone(), descriptor_one),
                (descriptor_two.task_id.clone(), descriptor_two),
            ]))
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(100), 0, 0)),
        )
        .unwrap();
        let migrated = store
            .compare_and_swap(&initial.revision, candidate)
            .unwrap();
        let untouched_tombstone = migrated.state.task_tombstones[&request_two.task_id].clone();
        assert!(untouched_tombstone.history_digest.is_empty());

        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut next_budget = budget_at(GraphLogicalTime::new(100), 0, 0);
        next_budget
            .admit_at(&config, GraphLogicalTime::new(100), 0, 1)
            .unwrap();
        store
            .claim_task_cas_with_budget(
                &migrated.revision,
                request_one.clone(),
                GraphLogicalTime::new(100),
                10,
                next_budget,
            )
            .unwrap();
        let after = store.snapshot().unwrap();
        assert_eq!(
            after.state.task_tombstones[&request_two.task_id], untouched_tombstone,
            "a claim must not rewrite an unrelated legacy tombstone"
        );
        assert!(
            !after.state.task_tombstones[&request_one.task_id]
                .history_digest
                .is_empty()
        );
    }

    #[test]
    fn claim_with_budget_retry_is_byte_identical_and_does_not_recharge() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(102),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(103, "budget-retry");
        let migrated = migrate_legacy_pending_with_budget(
            &store,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut charged_budget = budget_at(GraphLogicalTime::new(100), 0, 0);
        charged_budget
            .admit_at(&config, GraphLogicalTime::new(100), 0, 1)
            .unwrap();
        store
            .claim_task_with_budget(
                request.clone(),
                GraphLogicalTime::new(100),
                10,
                charged_budget.clone(),
            )
            .unwrap();
        let before_retry = store.snapshot().unwrap();
        let before_bytes = serde_json::to_vec(before_retry.state()).unwrap();

        // A retry carrying a different, higher local charge is not accepted:
        // callers cannot smuggle a budget delta through the idempotency path.
        let retry_budget = budget_at(GraphLogicalTime::new(100), 2, 2);
        let before_invalid_retry = store.snapshot().unwrap();
        assert!(matches!(
            store.claim_task_with_budget(
                request.clone(),
                GraphLogicalTime::new(100),
                10,
                retry_budget,
            ),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("scheduler budget changed")
        ));
        assert_eq!(store.snapshot().unwrap(), before_invalid_retry);
        let retry = store
            .claim_task_with_budget(
                request,
                GraphLogicalTime::new(100),
                10,
                charged_budget.clone(),
            )
            .unwrap();
        assert!(retry.idempotent);
        let after_retry = store.snapshot().unwrap();
        assert_eq!(after_retry.revision, before_retry.revision);
        assert_eq!(
            serde_json::to_vec(after_retry.state()).unwrap(),
            before_bytes
        );
        assert_eq!(after_retry.scheduler_budget(), Some(&charged_budget));
        assert_eq!(
            after_retry.revision.generation,
            before_retry.revision.generation
        );
        assert!(after_retry.revision.generation > migrated.revision.generation);
    }

    #[test]
    fn claim_with_budget_rejects_tombstone_regression_without_mutation() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(104),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(105, "budget-tombstone-regression");
        let task_id = request.task_id.clone();
        let migrated = migrate_legacy_pending_with_budget(
            &store,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut next_budget = budget_at(GraphLogicalTime::new(100), 0, 0);
        next_budget
            .admit_at(&config, GraphLogicalTime::new(100), 0, 1)
            .unwrap();
        store
            .claim_task_cas_with_budget(
                &migrated.revision,
                request,
                GraphLogicalTime::new(100),
                10,
                next_budget,
            )
            .unwrap();
        let before = store.snapshot().unwrap();
        let mut regressed = before.state.clone();
        regressed
            .task_tombstones
            .get_mut(&task_id)
            .unwrap()
            .history_digest
            .clear();
        let error = store
            .compare_and_swap(&before.revision, regressed)
            .unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::InvalidState { reason }
                if reason.contains("rewrote an existing task tombstone")
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn claim_with_budget_persist_failure_leaves_task_tombstone_and_budget_unchanged() {
        let path = temp_dir("budget-claim-persist-failure");
        let key = signer(106);
        let store = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(107, "budget-persist-failure");
        let migrated = migrate_legacy_pending_with_budget(
            &store,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let before_bytes = fs::read(store.state_path()).unwrap();
        let before = store.snapshot().unwrap();
        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let mut next_budget = budget_at(GraphLogicalTime::new(100), 0, 0);
        next_budget
            .admit_at(&config, GraphLogicalTime::new(100), 0, 1)
            .unwrap();
        install_test_commit_failure(path.clone(), CommitFailureBoundary::State);
        assert!(matches!(
            store.claim_task_cas_with_budget(
                &migrated.revision,
                request,
                GraphLogicalTime::new(100),
                10,
                next_budget,
            ),
            Err(GraphStoreError::Write { .. })
        ));

        // Reading the same handle performs the durable journal recovery. The
        // failed publication must roll back every part of the candidate, not
        // leave a charged budget beside an unclaimed or refreshed task.
        let after = store.snapshot().unwrap();
        assert_eq!(after, before);
        assert_eq!(fs::read(store.state_path()).unwrap(), before_bytes);
        drop(store);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(reopened.snapshot().unwrap(), before);
        drop(reopened);
        assert_eq!(migrated.revision, before.revision);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn legacy_graph_state_migrates_v0_to_v1_preserving_logical_time_high_water() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(82),
            budget_policy(),
        )
        .unwrap();
        let memory_initial = memory.snapshot().unwrap();
        let missing_budget = GraphStoreState::with_reasoning_state(
            memory_initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(42),
            ),
        );
        assert!(matches!(
            missing_budget,
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("persisted scheduler budget")
        ));
        let mut direct_marker_one = memory_initial.state.clone();
        direct_marker_one.migration_marker = GRAPH_STATE_MIGRATION_HYPOTHESES;
        assert!(matches!(
            memory.compare_and_swap(&memory_initial.revision, direct_marker_one),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("persisted scheduler budget")
        ));
        assert_eq!(memory.snapshot().unwrap(), memory_initial);
        let memory_candidate = GraphStoreState::with_reasoning_state(
            memory_initial.state,
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(42),
            )
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(42), 0, 0)),
        )
        .unwrap();
        let memory_migrated = memory
            .compare_and_swap(&memory_initial.revision, memory_candidate)
            .unwrap();
        assert_eq!(
            memory_migrated.migration_marker(),
            GRAPH_STATE_MIGRATION_HYPOTHESES
        );
        assert_eq!(
            memory_migrated.state.logical_time_high_water,
            GraphLogicalTime::new(42)
        );

        let path = temp_dir("legacy-migration");
        let key = signer(83);
        {
            let file = FileHypothesisGraphStore::new_with_scheduler_policy(
                &path,
                graph(),
                key.clone(),
                budget_policy(),
            )
            .unwrap();
            let initial = file.snapshot().unwrap();
            let candidate = GraphStoreState::with_reasoning_state(
                initial.state,
                ReasoningStateUpdate::migration_to_hypotheses(
                    GraphResourceLimits::default(),
                    GraphLogicalTime::new(42),
                )
                .with_scheduler_budget(budget_at(GraphLogicalTime::new(42), 0, 0)),
            )
            .unwrap();
            let migrated = file.compare_and_swap(&initial.revision, candidate).unwrap();
            assert_eq!(
                migrated.migration_marker(),
                GRAPH_STATE_MIGRATION_HYPOTHESES
            );
        }
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(
            snapshot.migration_marker(),
            GRAPH_STATE_MIGRATION_HYPOTHESES
        );
        assert_eq!(
            snapshot.state.logical_time_high_water,
            GraphLogicalTime::new(42)
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn scheduler_budget_policy_is_bound_to_store_configuration() {
        let config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..swarm_core::config::HypothesisGraphConfig::default()
        };
        let graph = HypothesisGraph::new(
            GraphId::new("graph:configured-budget"),
            config.resource_limits(),
        )
        .unwrap();
        let signing_key = signer(126);
        let store =
            MemoryHypothesisGraphStore::new_with_config(graph, signing_key, &config).unwrap();
        let migrated = migrate_with_budget(
            &store,
            budget_at(GraphLogicalTime::new(100), 0, 0),
            GraphLogicalTime::new(100),
        );
        let before = store.snapshot().unwrap();
        let mut widened = before.state().clone();
        widened.scheduler_budget = Some(tamper_budget_field(
            widened.scheduler_budget.as_ref().unwrap(),
            "max_work_units",
            serde_json::json!(11),
        ));
        let policy_error = store
            .compare_and_swap(before.revision(), widened)
            .unwrap_err();
        assert!(
            format!("{policy_error:?}").contains("policy identity"),
            "unexpected policy rejection: {policy_error:?}"
        );
        assert_eq!(store.snapshot().unwrap(), before);
        assert_eq!(migrated.scheduler_budget().unwrap().max_work_units, 10);

        let path = temp_dir("configured-budget-policy");
        let key = signer(127);
        let file = FileHypothesisGraphStore::new_with_config(
            &path,
            HypothesisGraph::new(
                GraphId::new("graph:configured-file-budget"),
                config.resource_limits(),
            )
            .unwrap(),
            key.clone(),
            &config,
        )
        .unwrap();
        let file_migrated = migrate_with_budget(
            &file,
            budget_at(GraphLogicalTime::new(100), 0, 0),
            GraphLogicalTime::new(100),
        );
        drop(file);
        let reopened =
            FileHypothesisGraphStore::open_with_signer_and_config(&path, key.clone(), &config)
                .unwrap();
        assert_eq!(reopened.snapshot().unwrap(), file_migrated);
        drop(reopened);
        let mismatched_config = swarm_core::config::HypothesisGraphConfig {
            max_work_units_per_tick: 11,
            max_claims_per_tick: 2,
            ..config
        };
        assert!(
            FileHypothesisGraphStore::open_with_signer_and_config(&path, key, &mismatched_config,)
                .is_err()
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn legacy_task_tombstone_wire_reopens_before_migration() {
        let path = temp_dir("legacy-task-wire");
        let key = signer(95);
        let original_state = {
            let file = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
            let claim = file
                .claim_task(request(95, "legacy-task"), GraphLogicalTime::new(100), 10)
                .unwrap();
            file.expire_task(
                "task:legacy-task",
                claim.task_generation,
                GraphLogicalTime::new(110),
            )
            .unwrap();
            file.reclaim_task(
                "task:legacy-task",
                request(96, "legacy-task"),
                GraphLogicalTime::new(111),
                10,
            )
            .unwrap();
            fs::read(file.state_path()).unwrap()
        };
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(reopened.snapshot().unwrap().migration_marker(), 0);
        assert_eq!(
            fs::read(path.join(GRAPH_STORE_STATE_FILE)).unwrap(),
            original_state
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unknown_graph_state_migration_marker_is_rejected() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(84)).unwrap();
        let before = store.snapshot().unwrap();
        let mut candidate = before.state.clone();
        candidate.migration_marker = GRAPH_STATE_MIGRATION_CURRENT + 1;
        assert!(matches!(
            store.compare_and_swap(&before.revision, candidate),
            Err(GraphStoreError::InvalidState { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn migration_marker_downgrade_is_rejected() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(87),
            budget_policy(),
        )
        .unwrap();
        let before = store.snapshot().unwrap();
        let migrated = store
            .compare_and_swap(
                &before.revision,
                GraphStoreState::with_reasoning_state(
                    before.state,
                    ReasoningStateUpdate::migration_to_hypotheses(
                        GraphResourceLimits::default(),
                        GraphLogicalTime::new(1),
                    )
                    .with_scheduler_budget(budget_at(
                        GraphLogicalTime::new(1),
                        0,
                        0,
                    )),
                )
                .unwrap(),
            )
            .unwrap();
        let mut downgraded = migrated.state.clone();
        downgraded.migration_marker = GRAPH_STATE_MIGRATION_LEGACY;
        downgraded.scheduler_budget = None;
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, downgraded),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("migration marker downgrade")
        ));
        assert_eq!(store.snapshot().unwrap(), migrated);
    }

    #[test]
    fn direct_cas_cannot_rewrite_hypothesis_confidence_or_uncertainty() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(124),
            budget_policy(),
        )
        .unwrap();
        let initial = store.snapshot().unwrap();
        let hypothesis_id = HypothesisId::new("hypothesis:direct-cas-audit");
        let hypothesis = Hypothesis::new(
            hypothesis_id.clone(),
            ConfidenceDistribution::uniform_two(),
            [UncertaintyReason::InsufficientEvidence],
            [],
        )
        .unwrap();
        let target = TaskTarget::Hypothesis {
            hypothesis_id: hypothesis_id.clone(),
        };
        let descriptor = LogicalTaskDescriptor::new(
            initial.state.graph_id.clone(),
            target.clone(),
            TaskKind::FalsifyHypothesis,
            "cd".repeat(32),
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            descriptor.kind,
            target,
            GraphProducerRole::Falsifier,
            AgentId::from_public_key_hex(&signer(124).public_key().to_hex()),
            EvidenceScope::new([], [EvidenceId::new("evidence:direct-cas-audit")], []).unwrap(),
            GraphLogicalTime::new(1),
        )
        .unwrap();
        let task = TaskRecord {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            request,
            state: TaskState::Pending,
            generation: 1,
            attempts: 1,
            lease: None,
            completion: None,
            terminal_history: Vec::new(),
        };
        let durable = DurableTaskRecord {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            task,
            generation: 1,
            history: Vec::new(),
        };
        let migrated = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(1),
            )
            .with_hypotheses(BTreeMap::from([(hypothesis_id.clone(), hypothesis)]))
            .with_tasks(BTreeMap::from([(descriptor.task_id.clone(), durable)]))
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )]))
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(1), 1, 0)),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&initial.revision, migrated).unwrap();
        let before_bytes = migrated.canonical_bytes().unwrap();

        let mut confidence_rewrite = migrated.state.clone();
        confidence_rewrite
            .hypotheses
            .get_mut(&hypothesis_id)
            .unwrap()
            .confidence = ConfidenceDistribution::new([
            (ConfidenceBucket::High, 6_000),
            (ConfidenceBucket::Low, 4_000),
        ])
        .unwrap();
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, confidence_rewrite),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("confidence or uncertainty")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );

        let mut uncertainty_rewrite = migrated.state.clone();
        uncertainty_rewrite
            .hypotheses
            .get_mut(&hypothesis_id)
            .unwrap()
            .uncertainty
            .insert(UncertaintyReason::PartialOrdering);
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, uncertainty_rewrite),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("confidence or uncertainty")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
    }

    #[test]
    fn direct_cas_cannot_drop_existing_task_or_tombstone() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(88),
            budget_policy(),
        )
        .unwrap();
        let claimed = store
            .claim_task(request(88, "drop"), GraphLogicalTime::new(100), 10)
            .unwrap();
        let before = store.snapshot().unwrap();
        let migration = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                claimed.task.request.requested_at,
            )
            .with_scheduler_budget(budget_at(claimed.task.request.requested_at, 0, 0))
            .with_tasks(before.state.tasks.clone()),
        );
        assert!(matches!(
            migration,
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("logical task descriptor")
        ));

        let mut dropped = before.state.clone();
        dropped.tasks.clear();
        dropped.task_tombstones.clear();
        assert!(matches!(
            store.compare_and_swap(&before.revision, dropped),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("task replacement requires the reasoning-state migration marker")
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn marker_one_requires_bidirectional_task_descriptor_binding() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(89),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(89, "descriptor-binding");
        let claimed = store
            .claim_task(request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        let before = store.snapshot().unwrap();
        let legacy_tasks = before.state.tasks.clone();
        let legacy_tombstones = before.state.task_tombstones.clone();
        let migrated = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(100),
            )
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(100), 0, 0))
            .with_tasks(before.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor.clone(),
            )])),
        )
        .unwrap();
        let mut migration_rewrite = migrated.clone();
        let migration_task_id = claimed.task.request.task_id.clone();
        let migration_task = migration_rewrite.tasks.get(&migration_task_id).unwrap();
        migration_rewrite.task_tombstones.insert(
            migration_task_id,
            TaskMonotonicity::from_record(migration_task).unwrap(),
        );
        assert!(matches!(
            store.compare_and_swap(&before.revision, migration_rewrite),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("rewrote or removed a legacy task tombstone")
        ));
        let migrated = store.compare_and_swap(&before.revision, migrated).unwrap();
        assert_eq!(migrated.state.tasks, legacy_tasks);
        assert_eq!(migrated.state.task_tombstones, legacy_tombstones);

        // Even a correctly recomputed v1 digest is a rewrite when supplied
        // directly at the marker boundary; only the typed migration helper
        // may preserve the legacy tombstone representation.
        let task_id = claimed.task.request.task_id.clone();
        let mut rewritten_tombstone = migrated.state.clone();
        let task = rewritten_tombstone.tasks.get(&task_id).unwrap();
        rewritten_tombstone
            .task_tombstones
            .insert(task_id, TaskMonotonicity::from_record(task).unwrap());
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, rewritten_tombstone),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("rewrote an existing task tombstone")
        ));

        // A marker-1 state with a task but no reverse descriptor binding is
        // invalid even when the task/tombstone pair itself is well formed.
        let (extra_descriptor, extra_request) = logical_request(90, "descriptorless");
        let extra_task = TaskRecord {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            request: extra_request,
            state: TaskState::Pending,
            generation: 1,
            attempts: 1,
            lease: None,
            completion: None,
            terminal_history: Vec::new(),
        };
        let extra_durable = DurableTaskRecord {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            task: extra_task.clone(),
            generation: 1,
            history: Vec::new(),
        };
        let mut descriptorless = migrated.state.clone();
        descriptorless
            .tasks
            .insert(extra_descriptor.task_id.clone(), extra_durable.clone());
        descriptorless.task_tombstones.insert(
            extra_descriptor.task_id.clone(),
            TaskMonotonicity::from_record(&extra_durable).unwrap(),
        );
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, descriptorless),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("no logical task descriptor")
        ));

        // The convenience create API has no descriptor argument and therefore
        // cannot introduce a marker-1 task. Runtime creation uses its typed
        // descriptor CAS instead.
        let before_unbound_create = store.snapshot().unwrap();
        assert!(matches!(
            store.create_task(logical_request(91, "create-without-descriptor").1),
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("descriptor-bound CAS")
        ));
        assert_eq!(store.snapshot().unwrap(), before_unbound_create);
        assert!(matches!(
            store.claim_task_with_budget(
                logical_request(92, "claim-without-descriptor").1,
                GraphLogicalTime::new(100),
                10,
                budget_at(GraphLogicalTime::new(100), 0, 0),
            ),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("logical task descriptor")
        ));

        // A low-level completion cannot terminalize a marker-1 task: the
        // capability, lineage, evidence, and outbox must be committed by one
        // reasoning CAS.
        let entry = migrated
            .state
            .tasks
            .get(&claimed.task.request.task_id)
            .unwrap();
        let lease = entry.task.lease.as_ref().unwrap();
        let completion = TaskCompletion::new(
            TaskCompletionKind::EvidenceAdded,
            lease.holder.clone(),
            GraphLogicalTime::new(105),
            [EvidenceId::new("evidence:logical:descriptor-binding")],
            "summary:low-level-terminal",
        )
        .unwrap();
        let before_terminal = store.snapshot().unwrap();
        assert!(matches!(
            store.complete_task(
                claimed.task.request.task_id.as_str(),
                entry.generation,
                &lease.lease_id,
                lease.fencing_token,
                GraphLogicalTime::new(105),
                completion,
            ),
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("outbox CAS")
        ));
        assert_eq!(store.snapshot().unwrap(), before_terminal);
    }

    #[test]
    fn marker_zero_to_one_cas_rejects_graph_rewrite_or_advance() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(92),
            budget_policy(),
        )
        .unwrap();
        let before = store.snapshot().unwrap();
        let mut candidate = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(1),
            )
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(1), 0, 0)),
        )
        .unwrap();
        candidate.graph.version = candidate.graph.version.saturating_add(1);
        assert!(matches!(
            store.compare_and_swap(&before.revision, candidate),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("rewrote or advanced the legacy graph")
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    fn assert_fabricated_claim_cas_is_rejected_without_mutation(
        store: &dyn HypothesisGraphStore,
        byte: u8,
    ) -> GraphStoreSnapshot {
        let (descriptor, request) = logical_request(byte, "fabricated-claim-cas");
        // Keep the task unclaimed through the typed marker-0 -> marker-1
        // migration. The forged candidate below is therefore a direct CAS
        // attempt to invent an active lease, rather than a public claim.
        store.create_task(request.clone()).unwrap();
        let initial = store.snapshot().unwrap();
        let migrated = GraphStoreState::with_reasoning_state(
            initial.state().clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(100),
            )
            .with_tasks(initial.state().tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )]))
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(100), 0, 0)),
        )
        .unwrap();
        let migrated = store
            .compare_and_swap(initial.revision(), migrated)
            .unwrap();
        let before = store.snapshot().unwrap();
        let before_bytes = before.canonical_bytes().unwrap();
        let task_id = request.task_id.clone();
        let mut fabricated = before.state().clone();
        let entry = fabricated.tasks.get_mut(&task_id).unwrap();
        let forged_lease = TaskLease::new(
            LeaseId::new("lease:forged-direct-cas"),
            request.claimant.clone(),
            GraphLogicalTime::new(100),
            GraphLogicalTime::new(110),
            FencingToken::new(1),
        )
        .unwrap();
        entry.task = TaskRecord::claimed_with_limits(
            request,
            forged_lease,
            GraphResourceLimits::default().max_task_lease_ms,
            GraphResourceLimits::default().max_task_retries,
        )
        .unwrap();
        fabricated.fencing_counter = 1;
        fabricated
            .task_tombstones
            .insert(task_id, TaskMonotonicity::from_record(entry).unwrap());
        let error = store
            .compare_and_swap(before.revision(), fabricated)
            .unwrap_err();
        assert!(
            matches!(
                &error,
                GraphStoreError::InvalidState { reason }
                    if reason.contains("prior task's active lease")
                        || reason.contains("prior claimed task")
            ),
            "unexpected fabricated claim rejection: {error:?}"
        );
        let after = store.snapshot().unwrap();
        assert_eq!(after.revision(), before.revision());
        assert_eq!(after.canonical_bytes().unwrap(), before_bytes);
        assert_eq!(after, before);
        assert_eq!(migrated.revision(), before.revision());
        before
    }

    #[test]
    fn direct_cas_rejects_fabricated_claim_clone_across_backends() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(122),
            budget_policy(),
        )
        .unwrap();
        let memory_before = assert_fabricated_claim_cas_is_rejected_without_mutation(&memory, 122);
        assert_eq!(
            memory.snapshot().unwrap().canonical_bytes().unwrap(),
            memory_before.canonical_bytes().unwrap()
        );

        let configured = ConfiguredHypothesisGraphStore::memory_with_scheduler_policy(
            graph(),
            signer(123),
            budget_policy(),
        )
        .unwrap();
        let configured_before =
            assert_fabricated_claim_cas_is_rejected_without_mutation(&configured, 123);
        assert_eq!(
            configured.snapshot().unwrap().canonical_bytes().unwrap(),
            configured_before.canonical_bytes().unwrap()
        );

        let path = temp_dir("fabricated-claim-cas-file");
        let key = signer(124);
        let file = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let file_before = assert_fabricated_claim_cas_is_rejected_without_mutation(&file, 124);
        let file_bytes = file_before.canonical_bytes().unwrap();
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            file_bytes
        );
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn direct_cas_rejects_terminal_task_without_outbox() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(93),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(93, "no-outbox");
        let claimed = store
            .claim_task(request, GraphLogicalTime::new(100), 10)
            .unwrap();
        let before = store.snapshot().unwrap();
        let migrated = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(100),
            )
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(100), 0, 0))
            .with_tasks(before.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )])),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&before.revision, migrated).unwrap();
        let task_id = claimed.task.request.task_id.clone();
        let mut terminal = migrated.state.clone();
        let entry = terminal.tasks.get_mut(&task_id).unwrap();
        let lease = entry.task.lease.clone().unwrap();
        entry.task = entry
            .task
            .clone()
            .complete(
                TaskCompletion::new(
                    TaskCompletionKind::EvidenceAdded,
                    lease.holder.clone(),
                    GraphLogicalTime::new(105),
                    [EvidenceId::new("evidence:logical:no-outbox")],
                    "summary:no-outbox",
                )
                .unwrap(),
                lease.fencing_token,
                GraphResourceLimits::default().max_task_lease_ms,
            )
            .unwrap();
        entry.generation = entry.generation.saturating_add(1);
        terminal.task_tombstones.insert(
            task_id.clone(),
            TaskMonotonicity::from_record(entry).unwrap(),
        );
        terminal.logical_time_high_water = GraphLogicalTime::new(105);
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, terminal.clone()),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("atomic terminal outbox publication")
        ));
        assert_eq!(store.snapshot().unwrap(), migrated);
    }

    #[test]
    fn direct_cas_rejects_wrong_completion_kind_in_outbox() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(97),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(96, "wrong-kind");
        let claimed = store
            .claim_task(request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        let before = store.snapshot().unwrap();
        let migrated = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(100),
            )
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(100), 0, 0))
            .with_tasks(before.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor.clone(),
            )])),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&before.revision, migrated).unwrap();
        let task_id = claimed.task.request.task_id.clone();
        let mut terminal = migrated.state.clone();
        let entry = terminal.tasks.get_mut(&task_id).unwrap();
        let lease = entry.task.lease.clone().unwrap();
        let claimant_key = signer(96);
        let claimant = entry.task.request.claimant.clone();
        let completion = TaskCompletion::new(
            TaskCompletionKind::NoFinding,
            claimant.clone(),
            GraphLogicalTime::new(105),
            std::iter::empty(),
            "summary:wrong-kind",
        )
        .unwrap();
        let terminal_task = entry
            .task
            .clone()
            .complete(
                completion.clone(),
                lease.fencing_token,
                GraphResourceLimits::default().max_task_lease_ms,
            )
            .unwrap();
        entry.task = terminal_task.clone();
        entry.generation = entry.generation.saturating_add(1);
        terminal.task_tombstones.insert(
            task_id.clone(),
            TaskMonotonicity::from_record(entry).unwrap(),
        );
        let capability = TaskCapabilityProof::signed_with(
            task_id.clone(),
            claimant.clone(),
            swarm_core::hypothesis_graph::GraphProducerRole::Hunter,
            TaskKind::AcquireEvidence,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "hunter-wrong-kind",
        )
        .unwrap();
        let envelope = TaskTerminalEnvelope::new(
            task_id.clone(),
            terminal_task.request.idempotency_key.clone(),
            lease.lease_id.clone(),
            lease.fencing_token,
            completion,
            None,
            claimant,
            capability,
        )
        .unwrap()
        .signed_with(&claimant_key, "terminal-wrong-kind")
        .unwrap();
        let valid_entry = TaskTerminalOutboxEntry {
            envelope,
            evidence: Vec::new(),
            decision: None,
            memory: None,
            memory_expiry: None,
            producer_key_id: AgentId::from_public_key_hex(&claimant_key.public_key().to_hex()),
        };
        valid_entry
            .validate_for_committed_task_at(
                &terminal_task,
                &descriptor,
                &GraphResourceLimits::default(),
                GraphLogicalTime::new(105),
            )
            .unwrap();
        terminal
            .terminal_outbox
            .insert(task_id.clone(), valid_entry);
        terminal.logical_time_high_water = GraphLogicalTime::new(105);
        let mut missing_history_digest = terminal.clone();
        missing_history_digest
            .task_tombstones
            .get_mut(&task_id)
            .unwrap()
            .history_digest
            .clear();
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, missing_history_digest),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("without binding its history digest")
        ));
        assert_eq!(store.snapshot().unwrap(), migrated);
        let mut mismatched_prior = terminal.clone();
        mismatched_prior
            .tasks
            .get_mut(&task_id)
            .unwrap()
            .task
            .terminal_history
            .last_mut()
            .unwrap()
            .prior_lease
            .fencing_token = FencingToken::new(99);
        let mismatched_task = mismatched_prior.tasks.get(&task_id).unwrap();
        mismatched_prior.task_tombstones.insert(
            task_id.clone(),
            TaskMonotonicity::from_record(mismatched_task).unwrap(),
        );
        mismatched_prior.fencing_counter = 99;
        let mismatched_error = store
            .compare_and_swap(&migrated.revision, mismatched_prior)
            .unwrap_err();
        let mismatched_error_debug = format!("{mismatched_error:?}");
        assert!(
            mismatched_error_debug.contains("terminal proof does not bind the prior claimed lease")
                || mismatched_error_debug
                    .contains("terminal outbox envelope does not bind the retained proof"),
            "unexpected terminal proof rejection: {mismatched_error:?}"
        );
        assert_eq!(store.snapshot().unwrap(), migrated);
        // The otherwise valid publication is tampered after construction.
        // Core validation must reject the wrong completion kind before CAS.
        terminal
            .terminal_outbox
            .get_mut(&task_id)
            .unwrap()
            .envelope
            .completion
            .kind = TaskCompletionKind::EdgeChallenged;
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, terminal.clone()),
            Err(GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason }))
                if reason.contains("task kind does not permit")
        ));
        assert_eq!(store.snapshot().unwrap(), migrated);
        let valid_terminal = {
            let mut candidate = terminal.clone();
            candidate
                .terminal_outbox
                .get_mut(&task_id)
                .unwrap()
                .envelope
                .completion
                .kind = TaskCompletionKind::NoFinding;
            candidate
        };
        let mut raised_state = migrated.state.clone();
        raised_state.logical_time_high_water = GraphLogicalTime::new(120);
        let raised = store
            .compare_and_swap(&migrated.revision, raised_state)
            .unwrap();
        let mut backdated_terminal = valid_terminal;
        backdated_terminal.generation = raised.revision().generation;
        backdated_terminal.predecessor_digest = raised.state().predecessor_digest.clone();
        backdated_terminal.logical_time_high_water = GraphLogicalTime::new(120);
        assert!(matches!(
            store.compare_and_swap(&raised.revision, backdated_terminal),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("below the durable graph high-water")
        ));
        assert_eq!(store.snapshot().unwrap(), raised);
    }

    #[test]
    fn direct_cas_rejects_history_replacement_even_with_matching_high_water() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(94),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(94, "history-prefix");
        let claimed = store
            .claim_task(request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        store
            .expire_task(
                claimed.task.request.task_id.as_str(),
                claimed.task_generation,
                GraphLogicalTime::new(110),
            )
            .unwrap();
        store
            .reclaim_task(
                claimed.task.request.task_id.as_str(),
                request,
                GraphLogicalTime::new(111),
                10,
            )
            .unwrap();
        let before = store.snapshot().unwrap();
        let migrated = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(111),
            )
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(111), 0, 0))
            .with_tasks(before.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )])),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&before.revision, migrated).unwrap();
        let mut rewritten = migrated.state.clone();
        rewritten
            .tasks
            .get_mut(&claimed.task.request.task_id)
            .unwrap()
            .history[0]
            .request
            .requested_at = GraphLogicalTime::new(101);
        let error = store
            .compare_and_swap(&migrated.revision, rewritten)
            .unwrap_err();
        assert!(
            matches!(
                &error,
                GraphStoreError::InvalidState { reason }
                    if reason.contains("history is not an append-only prefix")
            ),
            "unexpected history replacement error: {error:?}"
        );
        assert_eq!(store.snapshot().unwrap(), migrated);
    }

    #[test]
    fn marker_one_reclaim_appends_history_and_refreshes_its_digest() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(98),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(98, "marker-one-reclaim");
        let claimed = store
            .claim_task(request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        store
            .expire_task(
                claimed.task.request.task_id.as_str(),
                claimed.task_generation,
                GraphLogicalTime::new(110),
            )
            .unwrap();
        let before = store.snapshot().unwrap();
        let migrated = GraphStoreState::with_reasoning_state(
            before.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(110),
            )
            .with_tasks(before.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([(
                descriptor.task_id.clone(),
                descriptor,
            )]))
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(110), 0, 0)),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&before.revision, migrated).unwrap();
        let next_budget = budget_at(GraphLogicalTime::new(111), 0, 1);
        let reclaimed = store
            .reclaim_task_cas_with_budget(
                &migrated.revision,
                claimed.task.request.task_id.as_str(),
                request,
                GraphLogicalTime::new(111),
                10,
                next_budget.clone(),
            )
            .unwrap();
        assert_eq!(reclaimed.task.state, TaskState::Claimed);
        let current = store.snapshot().unwrap();
        let durable = current
            .state
            .tasks
            .get(&claimed.task.request.task_id)
            .unwrap();
        assert_eq!(durable.history.len(), 1);
        assert!(
            !current
                .state
                .task_tombstones
                .get(&claimed.task.request.task_id)
                .unwrap()
                .history_digest
                .is_empty()
        );
        assert_eq!(current.scheduler_budget(), Some(&next_budget));
        assert!(current.revision.generation > migrated.revision.generation);
    }

    fn assert_marker_one_raw_task_surfaces_are_quarantined(
        store: &dyn HypothesisGraphStore,
    ) -> GraphStoreSnapshot {
        let (pending_descriptor, pending_request) = logical_request(111, "raw-budget-pending");
        let (expired_descriptor, expired_request) = logical_request(112, "raw-budget-expired");
        store.create_task(pending_request.clone()).unwrap();
        let expired_claim = store
            .claim_task(expired_request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        store
            .expire_task(
                expired_request.task_id.as_str(),
                expired_claim.task_generation,
                GraphLogicalTime::new(110),
            )
            .unwrap();
        let initial = store.snapshot().unwrap();
        let migrated = GraphStoreState::with_reasoning_state(
            initial.state.clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                GraphResourceLimits::default(),
                GraphLogicalTime::new(110),
            )
            .with_tasks(initial.state.tasks.clone())
            .with_logical_task_descriptors(BTreeMap::from([
                (pending_descriptor.task_id.clone(), pending_descriptor),
                (expired_descriptor.task_id.clone(), expired_descriptor),
            ]))
            // The claim capacity is already exhausted. Raw marker-1 APIs
            // must still reject before touching the task or budget.
            .with_scheduler_budget(budget_at(GraphLogicalTime::new(110), 0, 2)),
        )
        .unwrap();
        let migrated = store.compare_and_swap(&initial.revision, migrated).unwrap();
        let before_bytes = migrated.canonical_bytes().unwrap();

        let raw_claim = store.claim_task(pending_request.clone(), GraphLogicalTime::new(111), 10);
        assert!(matches!(
            raw_claim,
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("atomic scheduler budget admission")
        ));
        let after_raw_claim = store.snapshot().unwrap();
        assert_eq!(after_raw_claim.canonical_bytes().unwrap(), before_bytes);
        assert_eq!(after_raw_claim.revision, migrated.revision);

        let raw_claim_cas = store.claim_task_cas(
            &migrated.revision,
            pending_request,
            GraphLogicalTime::new(111),
            10,
        );
        assert!(matches!(
            raw_claim_cas,
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("atomic scheduler budget admission")
        ));
        let raw_reclaim = store.reclaim_task(
            expired_request.task_id.clone().as_str(),
            expired_request,
            GraphLogicalTime::new(111),
            10,
        );
        assert!(matches!(
            raw_reclaim,
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("atomic scheduler budget admission")
        ));
        let after_raw_reclaim = store.snapshot().unwrap();
        assert_eq!(after_raw_reclaim.canonical_bytes().unwrap(), before_bytes);
        assert_eq!(after_raw_reclaim.revision, migrated.revision);
        after_raw_reclaim
    }

    #[test]
    fn marker_one_raw_claim_and_reclaim_are_quarantined_after_budget_exhaustion() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(113),
            budget_policy(),
        )
        .unwrap();
        let memory_baseline = assert_marker_one_raw_task_surfaces_are_quarantined(&memory);
        assert_eq!(
            memory.snapshot().unwrap().canonical_bytes().unwrap(),
            memory_baseline.canonical_bytes().unwrap()
        );

        let path = temp_dir("raw-budget-quarantine");
        let key = signer(114);
        let file = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let file_baseline = assert_marker_one_raw_task_surfaces_are_quarantined(&file);
        assert_eq!(
            file.snapshot().unwrap().canonical_bytes().unwrap(),
            file_baseline.canonical_bytes().unwrap()
        );
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            file_baseline.canonical_bytes().unwrap()
        );
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    fn assert_budgeted_reclaim_is_atomic_and_idempotent(
        store: &dyn HypothesisGraphStore,
    ) -> GraphStoreSnapshot {
        let (descriptor, request) = logical_request(115, "budgeted-reclaim");
        let migrated = migrate_legacy_expired_with_budget(
            store,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(110), 0, 0),
        );
        let next_budget = budget_at(GraphLogicalTime::new(111), 0, 1);
        let reclaimed = store
            .reclaim_task_cas_with_budget(
                &migrated.revision,
                request.task_id.as_str(),
                request.clone(),
                GraphLogicalTime::new(111),
                10,
                next_budget.clone(),
            )
            .unwrap();
        assert!(!reclaimed.idempotent);
        let after_reclaim = store.snapshot().unwrap();
        assert_eq!(after_reclaim.scheduler_budget(), Some(&next_budget));
        assert_eq!(after_reclaim.state.tasks[&request.task_id].history.len(), 1);
        assert_eq!(
            after_reclaim.revision.generation,
            migrated.revision.generation + 1
        );
        let before_retry_bytes = after_reclaim.canonical_bytes().unwrap();
        // A caller-supplied overcharge is rejected even for an idempotent
        // retry; the durable budget, not the retry payload, is authoritative.
        let before_invalid_retry = store.snapshot().unwrap();
        assert!(matches!(
            store.reclaim_task_with_budget(
                request.task_id.clone().as_str(),
                request.clone(),
                GraphLogicalTime::new(111),
                10,
                budget_at(GraphLogicalTime::new(111), 0, 2),
            ),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("scheduler budget changed")
        ));
        assert_eq!(store.snapshot().unwrap(), before_invalid_retry);
        let retry = store
            .reclaim_task_with_budget(
                request.task_id.clone().as_str(),
                request,
                GraphLogicalTime::new(111),
                10,
                next_budget.clone(),
            )
            .unwrap();
        assert!(retry.idempotent);
        let after_retry = store.snapshot().unwrap();
        assert_eq!(after_retry.revision, after_reclaim.revision);
        assert_eq!(after_retry.canonical_bytes().unwrap(), before_retry_bytes);
        assert_eq!(after_retry.scheduler_budget(), Some(&next_budget));
        after_retry
    }

    #[test]
    fn budgeted_reclaim_charges_claim_once_and_survives_file_restart() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(116),
            budget_policy(),
        )
        .unwrap();
        let memory_after = assert_budgeted_reclaim_is_atomic_and_idempotent(&memory);
        assert_eq!(
            memory.snapshot().unwrap().canonical_bytes().unwrap(),
            memory_after.canonical_bytes().unwrap()
        );

        let path = temp_dir("budgeted-reclaim-restart");
        let key = signer(117);
        let file = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let file_after = assert_budgeted_reclaim_is_atomic_and_idempotent(&file);
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            file_after.canonical_bytes().unwrap()
        );
        assert_eq!(
            reopened
                .snapshot()
                .unwrap()
                .scheduler_budget()
                .unwrap()
                .claims_used(),
            1
        );
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    fn assert_reasoning_expiry_and_budgeted_reclaim(
        store: &dyn HypothesisGraphStore,
        claimant_seed: u8,
    ) -> GraphStoreSnapshot {
        let (descriptor, request) = logical_request(claimant_seed, "reasoning-expiry");
        let migrated = migrate_legacy_pending_with_budget(
            store,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let claimed = store
            .claim_task_cas_with_budget(
                &migrated.revision,
                request.clone(),
                GraphLogicalTime::new(100),
                10,
                budget_at(GraphLogicalTime::new(100), 0, 1),
            )
            .expect("reasoning task claim");
        let expired = store
            .expire_task(
                request.task_id.as_str(),
                claimed.task_generation,
                GraphLogicalTime::new(110),
            )
            .expect("reasoning lease expiry");
        assert_eq!(expired.task.state, TaskState::Expired);
        assert!(expired.task.lease.is_none());
        let after_expiry = store.snapshot().expect("expired snapshot");
        assert_eq!(
            after_expiry.scheduler_budget(),
            Some(&budget_at(GraphLogicalTime::new(100), 0, 1))
        );

        let reclaimed = store
            .reclaim_task_cas_with_budget(
                &after_expiry.revision,
                request.task_id.as_str(),
                request.clone(),
                GraphLogicalTime::new(111),
                10,
                budget_at(GraphLogicalTime::new(111), 0, 1),
            )
            .expect("budgeted reasoning reclaim");
        assert_eq!(reclaimed.task.state, TaskState::Claimed);
        assert_eq!(reclaimed.task.attempts, 2);
        let after_reclaim = store.snapshot().expect("reclaimed snapshot");
        let durable = &after_reclaim.state.tasks[&request.task_id];
        assert_eq!(durable.history.len(), 1);
        assert_eq!(durable.history[0].state, TaskState::Expired);
        assert_eq!(
            after_reclaim.scheduler_budget(),
            Some(&budget_at(GraphLogicalTime::new(111), 0, 1))
        );
        after_reclaim
    }

    #[test]
    fn reasoning_leases_expire_and_reclaim_across_memory_and_file_backends() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(125),
            budget_policy(),
        )
        .unwrap();
        let memory_after = assert_reasoning_expiry_and_budgeted_reclaim(&memory, 125);
        assert_eq!(memory.snapshot().unwrap(), memory_after);

        let path = temp_dir("reasoning-expiry-reclaim");
        let key = signer(126);
        let file = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let file_after = assert_reasoning_expiry_and_budgeted_reclaim(&file, 126);
        let expected_bytes = file_after.canonical_bytes().unwrap();
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            expected_bytes
        );
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    fn assert_terminal_claim_retries_are_rejected_without_mutation(
        store: &dyn HypothesisGraphStore,
        claimant_seed: u8,
    ) -> GraphStoreSnapshot {
        let completed_request = request(claimant_seed, "completed-claim-retry");
        let completed_claim = store
            .claim_task(completed_request.clone(), GraphLogicalTime::new(100), 10)
            .expect("claim completed task");
        let completed_lease = completed_claim.task.lease.clone().expect("active lease");
        let completed_evidence = match &completed_request.target {
            TaskTarget::Evidence { evidence_id } => evidence_id.clone(),
            _ => unreachable!("fixture is evidence acquisition"),
        };
        store
            .complete_task(
                completed_request.task_id.as_str(),
                completed_claim.task_generation,
                &completed_lease.lease_id,
                completed_lease.fencing_token,
                GraphLogicalTime::new(105),
                TaskCompletion::new(
                    TaskCompletionKind::EvidenceAdded,
                    completed_request.claimant.clone(),
                    GraphLogicalTime::new(105),
                    [completed_evidence],
                    "completed-claim-retry",
                )
                .unwrap(),
            )
            .expect("complete task");
        let before_completed_retry = store.snapshot().unwrap();
        let before_completed_bytes = before_completed_retry.canonical_bytes().unwrap();
        assert!(matches!(
            store.claim_task(
                completed_request,
                GraphLogicalTime::new(106),
                10,
            ),
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("terminal tasks cannot be claimed")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_completed_bytes
        );

        let failed_request = request(claimant_seed.saturating_add(1), "failed-claim-retry");
        let failed_claim = store
            .claim_task(failed_request.clone(), GraphLogicalTime::new(200), 10)
            .expect("claim failed task");
        let failed_lease = failed_claim.task.lease.clone().expect("active lease");
        store
            .fail_task(
                failed_request.task_id.as_str(),
                failed_claim.task_generation,
                &failed_lease.lease_id,
                failed_lease.fencing_token,
                GraphLogicalTime::new(205),
                TaskFailure::new(
                    failed_request.claimant.clone(),
                    GraphLogicalTime::new(205),
                    "failed-claim-retry",
                )
                .unwrap(),
            )
            .expect("fail task");
        let before_failed_retry = store.snapshot().unwrap();
        let before_failed_bytes = before_failed_retry.canonical_bytes().unwrap();
        assert!(matches!(
            store.claim_task(failed_request, GraphLogicalTime::new(206), 10),
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("terminal tasks cannot be claimed")
        ));
        let after = store.snapshot().unwrap();
        assert_eq!(after.canonical_bytes().unwrap(), before_failed_bytes);
        after
    }

    #[test]
    fn terminal_claim_retries_fail_closed_across_memory_and_file_backends() {
        let memory = MemoryHypothesisGraphStore::new(graph(), signer(127)).unwrap();
        let memory_after =
            assert_terminal_claim_retries_are_rejected_without_mutation(&memory, 127);
        assert_eq!(memory.snapshot().unwrap(), memory_after);

        let path = temp_dir("terminal-claim-retry");
        let key = signer(129);
        let file = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let file_after = assert_terminal_claim_retries_are_rejected_without_mutation(&file, 129);
        let expected_bytes = file_after.canonical_bytes().unwrap();
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            expected_bytes
        );
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn budgeted_reclaim_failed_cas_and_persist_leave_state_unchanged() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(118),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(119, "budgeted-reclaim-failure-memory");
        let migrated = migrate_legacy_expired_with_budget(
            &memory,
            descriptor,
            request.clone(),
            budget_at(GraphLogicalTime::new(110), 0, 0),
        );
        let before = memory.snapshot().unwrap();
        let stale = GraphStoreRevision::new(
            migrated.revision.generation.saturating_sub(1),
            migrated.revision.digest.clone(),
        );
        assert!(matches!(
            memory.reclaim_task_cas_with_budget(
                &stale,
                request.task_id.as_str(),
                request.clone(),
                GraphLogicalTime::new(111),
                10,
                budget_at(GraphLogicalTime::new(111), 0, 1),
            ),
            Err(GraphStoreError::StalePredecessor { .. })
        ));
        assert_eq!(memory.snapshot().unwrap(), before);

        let path = temp_dir("budgeted-reclaim-persist-failure");
        let key = signer(120);
        let file = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            key.clone(),
            budget_policy(),
        )
        .unwrap();
        let (file_descriptor, file_request) = logical_request(121, "budgeted-reclaim-failure-file");
        let file_migrated = migrate_legacy_expired_with_budget(
            &file,
            file_descriptor,
            file_request.clone(),
            budget_at(GraphLogicalTime::new(110), 0, 0),
        );
        let file_before = file.snapshot().unwrap();
        let before_bytes = fs::read(file.state_path()).unwrap();
        install_test_commit_failure(path.clone(), CommitFailureBoundary::State);
        assert!(matches!(
            file.reclaim_task_cas_with_budget(
                &file_migrated.revision,
                file_request.task_id.clone().as_str(),
                file_request,
                GraphLogicalTime::new(111),
                10,
                budget_at(GraphLogicalTime::new(111), 0, 1),
            ),
            Err(GraphStoreError::Write { .. })
        ));
        assert_eq!(file.snapshot().unwrap(), file_before);
        assert_eq!(fs::read(file.state_path()).unwrap(), before_bytes);
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(reopened.snapshot().unwrap(), file_before);
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn spine_rejects_tampered_intrinsic_witness() {
        let key = signer(85);
        let actor = GraphNode::Actor(ActorNode::new("actor:intrinsic", "intrinsic").unwrap());
        let event = GraphNode::Event(
            EventNode::new("intrinsic", "source:intrinsic", GraphLogicalTime::new(100)).unwrap(),
        );
        let actor_id = actor.id().clone();
        let event_id = event.id().clone();
        let mut graph = graph();
        graph.admit_node(actor).unwrap();
        graph.admit_node(event).unwrap();
        let edge = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            5_000,
            [],
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&key.public_key().to_hex()),
            GraphLogicalTime::new(100),
            EdgeState::Unresolved,
        )
        .unwrap()
        .signed_with(&key, "hunter:intrinsic")
        .unwrap();
        let edge_id = edge.edge_id.clone();
        graph.admit_edge(edge).unwrap();
        let store = MemoryHypothesisGraphStore::new(graph, signer(86)).unwrap();
        let before = store.snapshot().unwrap();
        let mut candidate = before.state.clone();
        candidate
            .graph
            .edges
            .get_mut(&edge_id)
            .unwrap()
            .witness
            .as_mut()
            .unwrap()
            .signature_hex = "00".repeat(64);
        assert!(store.compare_and_swap(&before.revision, candidate).is_err());
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn operation_log_is_idempotent_and_fenced_across_reclaim() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(7)).unwrap();
        let first = store.claim_task(request(1, "one"), GraphLogicalTime::new(100), 10);
        let first = first.unwrap();
        let duplicate = store
            .claim_task(request(1, "one"), GraphLogicalTime::new(100), 10)
            .unwrap();
        assert!(duplicate.idempotent);
        assert_eq!(first.lease, duplicate.lease);
        let old = first.lease.clone().unwrap();
        let expired = store
            .expire_task("task:one", 1, GraphLogicalTime::new(110))
            .unwrap();
        assert_eq!(expired.task.state, TaskState::Expired);
        assert!(
            FencingToken::new(store.snapshot().unwrap().state.fencing_counter) > old.fencing_token
        );
        let reclaimed = store
            .reclaim_task(
                "task:one",
                request(2, "one"),
                GraphLogicalTime::new(111),
                20,
            )
            .unwrap();
        assert!(reclaimed.lease.as_ref().unwrap().fencing_token > old.fencing_token);
        let stale = store.complete_task(
            "task:one",
            2,
            &old.lease_id,
            old.fencing_token,
            GraphLogicalTime::new(112),
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                old.holder.clone(),
                GraphLogicalTime::new(112),
                [EvidenceId::new("evidence:one")],
                "summary:old",
            )
            .unwrap(),
        );
        assert!(matches!(
            stale,
            Err(GraphStoreError::StaleTaskGeneration { .. })
                | Err(GraphStoreError::StaleLease { .. })
                | Err(GraphStoreError::StaleFence { .. })
        ));
        let current = reclaimed.lease.unwrap();
        let done = store
            .complete_task(
                "task:one",
                reclaimed.revision.generation,
                &current.lease_id,
                current.fencing_token,
                GraphLogicalTime::new(112),
                TaskCompletion::new(
                    TaskCompletionKind::EvidenceAdded,
                    current.holder,
                    GraphLogicalTime::new(112),
                    [EvidenceId::new("evidence:one")],
                    "summary:new",
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(done.task.state, TaskState::Completed);
        assert_eq!(
            store.snapshot().unwrap().state.tasks[&TaskId::new("task:one")]
                .history
                .len(),
            1
        );
    }

    #[test]
    fn claim_retry_with_new_requested_at_is_idempotent() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(13)).unwrap();
        let first_request = request_at(1, "retry", GraphLogicalTime::new(100));
        let first = store
            .claim_task(first_request, GraphLogicalTime::new(100), 20)
            .unwrap();
        let retry = store
            .claim_task(
                request_at(1, "retry", GraphLogicalTime::new(105)),
                GraphLogicalTime::new(105),
                20,
            )
            .unwrap();
        assert!(retry.idempotent);
        assert_eq!(retry.revision, first.revision);
        assert_eq!(retry.task, first.task);
        assert_eq!(retry.task.request.requested_at, GraphLogicalTime::new(100));
    }

    #[test]
    fn generic_cas_rejects_stale_terminal_task_resurrection() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(44)).unwrap();
        let claimed = store
            .claim_task(request(45, "resurrection"), GraphLogicalTime::new(100), 20)
            .unwrap();
        let stale = store.snapshot().unwrap();
        let lease = claimed.lease.unwrap();
        store
            .complete_task(
                "task:resurrection",
                claimed.task_generation,
                &lease.lease_id,
                lease.fencing_token,
                GraphLogicalTime::new(110),
                TaskCompletion::new(
                    TaskCompletionKind::EvidenceAdded,
                    lease.holder,
                    GraphLogicalTime::new(110),
                    [EvidenceId::new("evidence:resurrection")],
                    "summary:resurrection",
                )
                .unwrap(),
            )
            .unwrap();
        let current = store.snapshot().unwrap();
        let mut candidate = stale.state;
        candidate.generation = current.state.generation;
        candidate.predecessor_digest = current.state.predecessor_digest.clone();
        let error = store
            .compare_and_swap(&current.revision, candidate)
            .unwrap_err();
        assert!(matches!(error, GraphStoreError::InvalidState { .. }));
        assert_eq!(store.snapshot().unwrap().state.tasks, current.state.tasks);
    }

    #[test]
    fn terminal_transition_barrier_rejects_expired_injected_clock() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(14)).unwrap();
        let claim = store
            .claim_task(
                request(1, "completion-barrier"),
                GraphLogicalTime::new(100),
                10,
            )
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let before = store.snapshot().unwrap();
        let completion = TaskCompletion::new(
            TaskCompletionKind::EvidenceAdded,
            lease.holder.clone(),
            GraphLogicalTime::new(109),
            [EvidenceId::new("evidence:completion-barrier")],
            "summary:completion-barrier",
        )
        .unwrap();
        assert!(matches!(
            store.complete_task(
                "task:completion-barrier",
                claim.task_generation,
                &lease.lease_id,
                lease.fencing_token,
                GraphLogicalTime::new(110),
                completion,
            ),
            Err(GraphStoreError::LeaseExpired { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let failure_request = request(2, "failure-barrier");
        let failure_claim = store
            .claim_task(failure_request.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        let failure_lease = failure_claim.lease.clone().unwrap();
        let before_failure = store.snapshot().unwrap();
        let failure = TaskFailure::new(
            failure_request.claimant,
            GraphLogicalTime::new(109),
            "summary:failure-barrier",
        )
        .unwrap();
        assert!(matches!(
            store.fail_task(
                "task:failure-barrier",
                failure_claim.task_generation,
                &failure_lease.lease_id,
                failure_lease.fencing_token,
                GraphLogicalTime::new(110),
                failure,
            ),
            Err(GraphStoreError::LeaseExpired { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before_failure);
    }

    #[test]
    fn stale_generation_cas_never_mutates_state() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(8)).unwrap();
        let before = store.snapshot().unwrap();
        let mut changed = before.state.clone();
        changed.graph.version = changed.graph.version.saturating_add(1);
        let committed = store.compare_and_swap(&before.revision, changed).unwrap();
        let stale = store.compare_and_swap(&before.revision, before.state);
        assert!(matches!(
            stale,
            Err(GraphStoreError::StalePredecessor { .. })
        ));
        assert_eq!(store.snapshot().unwrap().revision, committed.revision);
    }

    #[test]
    fn cas_rejects_fencing_counter_regression_without_mutation() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(18)).unwrap();
        store
            .claim_task(request(1, "cas-fence"), GraphLogicalTime::new(100), 20)
            .unwrap();
        let before = store.snapshot().unwrap();
        let mut candidate = before.state.clone();
        candidate.graph.version = candidate.graph.version.saturating_add(1);
        candidate.fencing_counter = before.state.fencing_counter.saturating_sub(1);
        assert!(matches!(
            store.compare_and_swap(&before.revision, candidate),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("fencing counter regressed")
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn renewal_rejects_backdated_logical_time_without_mutation() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(19)).unwrap();
        let claim = store
            .claim_task(
                request(1, "renew-backdated"),
                GraphLogicalTime::new(100),
                20,
            )
            .unwrap();
        let lease = claim.lease.unwrap();
        let before = store.snapshot().unwrap();
        assert!(matches!(
            store.renew_task(
                "task:renew-backdated",
                claim.task_generation,
                &lease.lease_id,
                lease.fencing_token,
                GraphLogicalTime::new(99),
                20,
            ),
            Err(GraphStoreError::InvalidTransition { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn file_store_refuses_reinitialization_after_state_and_head_loss() {
        let path = temp_dir("missing-high-water");
        let key = signer(24);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let high_water_path = path.join(GRAPH_STORE_HIGH_WATER_FILE);
        drop(store);
        fs::remove_file(&state_path).unwrap();
        fs::remove_file(&anchor_path).unwrap();
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, key.clone()),
            Err(GraphStoreError::MissingState { .. })
                | Err(GraphStoreError::MissingHighWater { .. })
        ));
        fs::remove_file(&high_water_path).unwrap();
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, key),
            Err(GraphStoreError::MissingState { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_store_refuses_full_root_snapshot_rollback_with_external_anchor() {
        let path = temp_dir("full-root-rollback");
        let key = signer(25);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let high_water_path = path.join(GRAPH_STORE_HIGH_WATER_FILE);
        let old_state = fs::read(&state_path).unwrap();
        let old_anchor = fs::read(&anchor_path).unwrap();
        let old_high_water = fs::read(&high_water_path).unwrap();
        let external_anchor_path = store.monotonic_anchor.path().to_path_buf();
        let old_external_anchor = fs::read(&external_anchor_path).unwrap();

        store.create_task(request(1, "full-root-rollback")).unwrap();
        let current_external_anchor = fs::read(&external_anchor_path).unwrap();
        assert_ne!(current_external_anchor, old_external_anchor);
        drop(store);

        // Restore every mutable generation-bearing file in the store root.
        // The sibling append-only anchor remains at the newer generation.
        fs::write(&state_path, old_state).unwrap();
        fs::write(&anchor_path, old_anchor).unwrap();
        fs::write(&high_water_path, old_high_water).unwrap();
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, key),
            Err(GraphStoreError::ReplayDetected { .. })
                | Err(GraphStoreError::AnchorMismatch { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_backend_reopens_with_identical_canonical_state_and_refuses_lock_contention() {
        let path = temp_dir("parity");
        let key = signer(9);
        let first = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let request = request(1, "file");
        let memory = MemoryHypothesisGraphStore::new(graph(), key.clone()).unwrap();
        let file_claim = first
            .claim_task(request.clone(), GraphLogicalTime::new(100), 20)
            .unwrap();
        let memory_claim = memory
            .claim_task(request, GraphLogicalTime::new(100), 20)
            .unwrap();
        assert_eq!(
            first.snapshot().unwrap().canonical_bytes().unwrap(),
            memory.snapshot().unwrap().canonical_bytes().unwrap()
        );
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, key.clone()),
            Err(GraphStoreError::LockContended { .. })
        ));
        drop(first);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            memory.snapshot().unwrap().canonical_bytes().unwrap()
        );
        assert_eq!(file_claim.task, memory_claim.task);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn memory_and_file_backends_match_for_one_logical_operation_vector() {
        let path = temp_dir("vector");
        let key = signer(11);
        let memory = MemoryHypothesisGraphStore::new(graph(), key.clone()).unwrap();
        let file = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        assert_eq!(
            memory.snapshot().unwrap().canonical_bytes().unwrap(),
            file.snapshot().unwrap().canonical_bytes().unwrap()
        );

        let claimed_memory = memory
            .claim_task(request(1, "vector"), GraphLogicalTime::new(100), 20)
            .unwrap();
        let claimed_file = file
            .claim_task(request(1, "vector"), GraphLogicalTime::new(100), 20)
            .unwrap();
        assert_eq!(claimed_memory.task, claimed_file.task);
        let lease = claimed_memory.lease.clone().unwrap();
        let renewed_memory = memory
            .renew_task(
                "task:vector",
                claimed_memory.task_generation,
                &lease.lease_id,
                lease.fencing_token,
                GraphLogicalTime::new(105),
                20,
            )
            .unwrap();
        let renewed_file = file
            .renew_task(
                "task:vector",
                claimed_file.task_generation,
                &lease.lease_id,
                lease.fencing_token,
                GraphLogicalTime::new(105),
                20,
            )
            .unwrap();
        assert_eq!(renewed_memory.task, renewed_file.task);
        let completion = TaskCompletion::new(
            TaskCompletionKind::EvidenceAdded,
            lease.holder.clone(),
            GraphLogicalTime::new(110),
            [EvidenceId::new("evidence:vector")],
            "summary:vector",
        )
        .unwrap();
        let renewed_lease = renewed_memory.lease.clone().unwrap();
        let done_memory = memory
            .complete_task(
                "task:vector",
                renewed_memory.task_generation,
                &renewed_lease.lease_id,
                renewed_lease.fencing_token,
                GraphLogicalTime::new(110),
                completion.clone(),
            )
            .unwrap();
        let done_file = file
            .complete_task(
                "task:vector",
                renewed_file.task_generation,
                &renewed_lease.lease_id,
                renewed_lease.fencing_token,
                GraphLogicalTime::new(110),
                completion,
            )
            .unwrap();
        assert_eq!(done_memory.task, done_file.task);
        assert_eq!(
            memory.snapshot().unwrap().canonical_bytes().unwrap(),
            file.snapshot().unwrap().canonical_bytes().unwrap()
        );
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            memory.snapshot().unwrap().canonical_bytes().unwrap()
        );
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_backend_rejects_missing_or_replayed_anchor() {
        let path = temp_dir("anchor");
        let key = signer(12);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let initial_state = fs::read(&state_path).unwrap();
        let initial_anchor = fs::read(&anchor_path).unwrap();
        fs::remove_file(&anchor_path).unwrap();
        assert!(matches!(
            store.snapshot(),
            Err(GraphStoreError::MissingAnchor { .. })
        ));
        drop(store);
        fs::write(&anchor_path, initial_anchor).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reopened = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        reopened
            .claim_task(request(1, "anchor"), GraphLogicalTime::new(100), 20)
            .unwrap();
        fs::write(&state_path, initial_state).unwrap();
        drop(reopened);
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, key),
            Err(GraphStoreError::ReplayDetected { .. })
                | Err(GraphStoreError::AnchorMismatch { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn tampered_file_state_fails_closed_on_restart() {
        let path = temp_dir("tamper");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(10)).unwrap();
        let state_path = store.state_path().to_path_buf();
        drop(store);
        let raw =
            fs::read_to_string(&state_path)
                .unwrap()
                .replacen("graph:test", "graph:tampered", 1);
        fs::write(&state_path, raw).unwrap();
        let error = FileHypothesisGraphStore::open_with_signer(&path, signer(10)).unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::DigestMismatch { .. }
                | GraphStoreError::InvalidSignature { .. }
                | GraphStoreError::InvalidState { .. }
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_store_requires_the_provisioned_signer_on_reopen() {
        let path = temp_dir("signer");
        let key = signer(15);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        drop(store);
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, signer(16)),
            Err(GraphStoreError::SignerMismatch { .. })
                | Err(GraphStoreError::InvalidSignature { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_store_rejects_state_generation_gaps_and_wrong_predecessors() {
        let gap_path = temp_dir("head-gap");
        let key = signer(17);
        let store = FileHypothesisGraphStore::new(&gap_path, graph(), key.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        let envelope: SignedGraphStoreState = read_json_file(&state_path).unwrap();
        let mut gap_state = envelope.state;
        gap_state.generation = 2;
        gap_state.predecessor_digest = Some("forged-predecessor".to_string());
        let signed_gap = sign_state(gap_state, &key, &graph().limits).unwrap();
        atomic_write_json(&state_path, &signed_gap).unwrap();
        drop(store);
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&gap_path, key.clone()),
            Err(GraphStoreError::ReplayDetected { .. })
        ));
        let _ = fs::remove_dir_all(gap_path);

        let predecessor_path = temp_dir("head-predecessor");
        let store = FileHypothesisGraphStore::new(&predecessor_path, graph(), key.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        let envelope: SignedGraphStoreState = read_json_file(&state_path).unwrap();
        let mut predecessor_state = envelope.state;
        predecessor_state.generation = 1;
        predecessor_state.predecessor_digest = Some("forged-predecessor".to_string());
        let signed_predecessor = sign_state(predecessor_state, &key, &graph().limits).unwrap();
        atomic_write_json(&state_path, &signed_predecessor).unwrap();
        drop(store);
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&predecessor_path, key),
            Err(GraphStoreError::AnchorMismatch { .. })
        ));
        let _ = fs::remove_dir_all(predecessor_path);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_revalidates_lock_path_before_persistence() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_dir("lock-replacement");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(18)).unwrap();
        let lock_path = path.join(GRAPH_STORE_LOCK_FILE);
        let displaced_path = path.join("state.lock.displaced");
        fs::rename(&lock_path, &displaced_path).unwrap();
        fs::write(&lock_path, vec![b'0'; 64]).unwrap();
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, signer(18)),
            Err(GraphStoreError::LockContended { .. })
        ));
        assert!(matches!(
            store.create_task(request(1, "lock-replacement")),
            Err(GraphStoreError::LockBinding { .. })
        ));
        drop(store);
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(unix)]
    #[test]
    fn file_store_requires_private_root_and_persisted_files() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_dir("permissions");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(19)).unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let lock_path = path.join(GRAPH_STORE_LOCK_FILE);
        let high_water_path = path.join(GRAPH_STORE_HIGH_WATER_FILE);
        drop(store);

        for file_path in [&state_path, &anchor_path, &lock_path, &high_water_path] {
            fs::set_permissions(file_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                FileHypothesisGraphStore::open_with_signer(&path, signer(19)),
                Err(GraphStoreError::InsecurePermissions {
                    expected: 0o600,
                    observed: 0o644,
                    ..
                })
            ));
            fs::set_permissions(file_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, signer(19)),
            Err(GraphStoreError::InsecurePermissions {
                expected: 0o700,
                observed: 0o755,
                ..
            })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(unix)]
    #[test]
    fn persisted_json_size_is_bounded_before_allocation() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_dir("oversized-json");
        fs::create_dir_all(&path).unwrap();
        let file_path = path.join("oversized.json");
        fs::write(&file_path, vec![b'0'; 16 * 1024 * 1024 + 1]).unwrap();
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_json_file::<serde_json::Value>(&file_path),
            Err(GraphStoreError::ResourceLimit {
                resource,
                ..
            }) if resource == "persisted_file_bytes"
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn serialized_output_bound_roundtrips_near_limit_and_preserves_state() {
        let path = temp_dir("serialized-bound");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(20)).unwrap();
        let near_path = path.join("near.json");
        let near = serde_json::json!({
            "payload": "x".repeat(MAX_PERSISTED_JSON_BYTES.saturating_sub(32)),
        });
        atomic_write_json(&near_path, &near).unwrap();
        assert!(fs::metadata(&near_path).unwrap().len() as usize <= MAX_PERSISTED_JSON_BYTES);
        let roundtripped: serde_json::Value = read_json_file(&near_path).unwrap();
        assert_eq!(roundtripped, near);

        let state_before = fs::read(store.state_path()).unwrap();
        let anchor_before = fs::read(store.anchor_path()).unwrap();
        let oversized = serde_json::json!({
            "payload": "x".repeat(MAX_PERSISTED_JSON_BYTES + 1),
        });
        assert!(matches!(
            atomic_write_json(store.state_path(), &oversized),
            Err(GraphStoreError::ResourceLimit {
                resource,
                ..
            }) if resource == "persisted_file_bytes"
        ));
        assert_eq!(fs::read(store.state_path()).unwrap(), state_before);
        assert_eq!(fs::read(store.anchor_path()).unwrap(), anchor_before);
        assert_eq!(store.snapshot().unwrap().state.tasks.len(), 0);
        drop(store);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn oversized_graph_envelope_has_memory_file_admission_parity_and_no_mutation() {
        // A valid graph transition is similarly far below 16 MiB. Measure
        // its signed envelope first, then use the thread-local test ceiling
        // to exercise boundary-1/boundary/boundary+1 deterministically.
        for (index, (offset, should_reject)) in [(0_usize, true), (1, false), (2, false)]
            .into_iter()
            .enumerate()
        {
            let path = temp_dir(&format!("oversized-graph-{index}"));
            let key = signer(54);
            let memory_store = MemoryHypothesisGraphStore::new(graph(), key.clone()).unwrap();
            let file_store = FileHypothesisGraphStore::new(&path, graph(), key).unwrap();
            let baseline = memory_store.snapshot().unwrap();
            let mut candidate_input = baseline.state.clone();
            candidate_input.graph.version = candidate_input.graph.version.saturating_add(1);
            let mut candidate_state = candidate_input.clone();
            candidate_state.generation = baseline.state.generation.checked_add(1).unwrap();
            candidate_state.predecessor_digest = Some(baseline.revision.digest.clone());
            let candidate =
                sign_state(candidate_state, &memory_store.signer, &memory_store.limits).unwrap();
            let candidate_bytes = serde_json::to_vec(&candidate).unwrap();
            let baseline_memory_bytes = {
                let state = memory_store.inner.read().unwrap().clone();
                serde_json::to_vec(&state).unwrap()
            };
            let baseline_file_bytes = fs::read(file_store.state_path()).unwrap();
            assert_eq!(baseline_memory_bytes, baseline_file_bytes);
            assert!(candidate_bytes.len() > baseline_memory_bytes.len());

            let before_files = fs::read_dir(&path)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (
                        entry.file_name().to_string_lossy().into_owned(),
                        fs::read(entry.path()).unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let limit = candidate_bytes.len().checked_sub(1).unwrap() + offset;
            let limit_guard = install_test_persisted_json_limit(limit);
            let memory_result =
                memory_store.compare_and_swap(&baseline.revision, candidate_input.clone());
            let file_result = file_store.compare_and_swap(&baseline.revision, candidate_input);
            if should_reject {
                let memory_error = match memory_result {
                    Err(GraphStoreError::ResourceLimit { resource, limit }) => (resource, limit),
                    Err(other) => {
                        panic!("expected persisted-size admission failure, got {other:?}")
                    }
                    Ok(_) => {
                        panic!("oversized graph candidate was accepted below its envelope size")
                    }
                };
                let file_error = match file_result {
                    Err(GraphStoreError::ResourceLimit { resource, limit }) => (resource, limit),
                    Err(other) => {
                        panic!("expected persisted-size admission failure, got {other:?}")
                    }
                    Ok(_) => {
                        panic!("oversized graph candidate was accepted below its envelope size")
                    }
                };
                assert_eq!(memory_error, file_error);
                assert_eq!(memory_error, ("persisted_file_bytes".to_string(), limit));
                let after_memory_bytes = {
                    let state = memory_store.inner.read().unwrap().clone();
                    serde_json::to_vec(&state).unwrap()
                };
                assert_eq!(after_memory_bytes, baseline_memory_bytes);
                assert_eq!(
                    fs::read(file_store.state_path()).unwrap(),
                    baseline_file_bytes
                );
                let after_files = fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (
                            entry.file_name().to_string_lossy().into_owned(),
                            fs::read(entry.path()).unwrap(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                assert_eq!(after_files, before_files);
                assert_eq!(
                    memory_store.state_digest().unwrap(),
                    file_store.state_digest().unwrap()
                );
            } else {
                let memory_result = memory_result.unwrap();
                let file_result = file_result.unwrap();
                assert_eq!(memory_result, file_result);
                let after_memory_bytes = {
                    let state = memory_store.inner.read().unwrap().clone();
                    serde_json::to_vec(&state).unwrap()
                };
                let after_file_bytes = fs::read(file_store.state_path()).unwrap();
                assert_eq!(after_memory_bytes, after_file_bytes);
                assert_ne!(after_memory_bytes, baseline_memory_bytes);
                assert_eq!(
                    memory_store.state_digest().unwrap(),
                    file_store.state_digest().unwrap()
                );
            }
            drop(limit_guard);
            drop(file_store);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn namespace_lock_blocks_replacement_writer_during_state_commit() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::mpsc;

        let path = temp_dir("namespace-barrier");
        let key = signer(21);
        let store = Arc::new(FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap());
        let state_path = store.state_path().to_path_buf();
        let lock_path = path.join(GRAPH_STORE_LOCK_FILE);
        let displaced_path = path.join("state.lock.displaced");
        let state_before = fs::read(&state_path).unwrap();
        let anchor_before = fs::read(store.anchor_path()).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        install_test_persistence_barrier(state_path.clone(), ready_tx, release_rx);
        let mut barrier_guard = PersistenceBarrierGuard::new(state_path.clone(), release_tx);

        let writer = Arc::clone(&store);
        let (result_tx, result_rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let result = writer.create_task(request(1, "namespace-barrier"));
            let _ = result_tx.send(result);
        });
        let ready = ready_rx.recv_timeout(Duration::from_secs(5));
        if ready.is_err() {
            barrier_guard.release();
            let writer_result = result_rx.recv_timeout(Duration::from_secs(6));
            if writer_result.is_ok() {
                let _ = join.join();
            } else {
                drop(join);
            }
            panic!("writer did not reach pre-rename barrier: {ready:?}; result={writer_result:?}");
        }

        let replacement = (|| {
            fs::rename(&lock_path, &displaced_path)?;
            fs::write(&lock_path, vec![b'0'; LOCK_GENERATION_BYTES as usize])?;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;
            Ok::<_, io::Error>(FileHypothesisGraphStore::open_with_signer(
                &path,
                key.clone(),
            ))
        })();
        barrier_guard.release();
        let mutation = result_rx.recv_timeout(Duration::from_secs(6));
        if mutation.is_err() {
            drop(join);
            panic!("writer did not finish after barrier release: {mutation:?}");
        }
        let join_result = join.join();
        assert!(join_result.is_ok());
        let mutation = mutation.expect("writer result disappeared after barrier release");
        let replacement = replacement.expect("lock replacement setup failed");
        assert!(matches!(
            replacement,
            Err(GraphStoreError::LockContended { .. })
        ));
        assert!(matches!(mutation, Err(GraphStoreError::LockBinding { .. })));
        assert_eq!(fs::read(&state_path).unwrap(), state_before);
        assert_eq!(fs::read(store.anchor_path()).unwrap(), anchor_before);

        drop(store);
        fs::remove_file(&lock_path).unwrap();
        fs::rename(&displaced_path, &lock_path).unwrap();
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert!(
            reopened
                .snapshot()
                .unwrap()
                .state
                .task("task:namespace-barrier")
                .is_none()
        );
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_transaction_stage_recovers_orphaned_intent_at_each_boundary() {
        for (index, boundary) in [
            CommitFailureBoundary::ExternalIntent,
            CommitFailureBoundary::State,
            CommitFailureBoundary::Head,
            CommitFailureBoundary::HighWater,
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_dir(&format!("txn-recovery-{index}"));
            let key = signer(31);
            let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
            install_test_commit_failure(path.clone(), boundary);
            assert!(matches!(
                store.create_task(request(32, &format!("txn-{index}"))),
                Err(GraphStoreError::Write { .. })
            ));
            drop(store);
            let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
            assert!(reopened.snapshot().unwrap().state.tasks.is_empty());
            drop(reopened);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn external_rotation_manifest_recovers_after_active_data_boundary() {
        let path = temp_dir("external-rotation-recovery");
        let key = signer(35);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let external_lock = store.monotonic_anchor.acquire_lock().unwrap();
        let records = store
            .monotonic_anchor
            .read_records_locked::<DurableExternalCommitRecord>(&external_lock)
            .unwrap();
        let journal = verify_external_journal(
            &records,
            GRAPH_STORE_STATE_KIND,
            store.graph_id.as_str(),
            &store.signer_id,
            store.lock.generation(),
            &store.lock.identity_token(),
        )
        .unwrap();
        install_test_rotation_failure(store.monotonic_anchor.rotation_manifest_path.clone());
        assert!(matches!(
            store
                .monotonic_anchor
                .rotate_for_test_locked(&external_lock, &journal.committed, &key,),
            Err(GraphStoreError::Write { .. })
        ));
        drop(external_lock);
        drop(store);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(reopened.snapshot().unwrap().revision.generation, 0);
        assert!(!reopened.monotonic_anchor.rotation_manifest_path.exists());
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn external_journal_tail_rejects_valid_prefix_truncation_with_root_rollback() {
        let path = temp_dir("external-prefix-truncation");
        let key = signer(33);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let high_water_path = path.join(GRAPH_STORE_HIGH_WATER_FILE);
        let high_water_tail_path = path.join(GRAPH_STORE_HIGH_WATER_TAIL_FILE);
        let old_state = fs::read(&state_path).unwrap();
        let old_anchor = fs::read(&anchor_path).unwrap();
        let old_high_water = fs::read(&high_water_path).unwrap();
        let old_high_water_tail = fs::read(&high_water_tail_path).unwrap();
        let external_path = store.monotonic_anchor.path().to_path_buf();
        let old_external = fs::read(&external_path).unwrap();
        store.create_task(request(34, "external-prefix")).unwrap();
        drop(store);
        fs::write(&state_path, old_state).unwrap();
        fs::write(&anchor_path, old_anchor).unwrap();
        fs::write(&high_water_path, old_high_water).unwrap();
        fs::write(&high_water_tail_path, old_high_water_tail).unwrap();
        fs::write(&external_path, old_external).unwrap();
        // The sibling tail still records the committed H1 journal length;
        // restoring only the valid H0 prefix must fail closed.
        assert!(matches!(
            FileHypothesisGraphStore::open_with_signer(&path, key),
            Err(GraphStoreError::ReplayDetected { .. })
                | Err(GraphStoreError::AnchorMismatch { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn append_manifest_recovers_data_before_tail_validation() {
        let path = temp_dir("append-manifest");
        let key = signer(53);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        let head: DurableStateHead = store.lock.read_json(store.anchor_path()).unwrap();
        install_test_commit_failure(path.clone(), CommitFailureBoundary::AppendTail);
        assert!(matches!(
            append_high_water(
                &store.lock,
                &store.high_water_path,
                &store.high_water_tail_path,
                &head,
            ),
            Err(GraphStoreError::Write { .. })
        ));
        let append_manifest = path.join(format!(
            "{}{}",
            GRAPH_STORE_HIGH_WATER_FILE, APPEND_MANIFEST_SUFFIX
        ));
        assert!(append_manifest.exists());
        drop(store);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(reopened.snapshot().unwrap().revision.generation, 0);
        assert!(!append_manifest.exists());
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn external_append_manifest_recovers_data_before_tail_validation() {
        let path = temp_dir("external-append-manifest");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(67)).unwrap();
        let external_lock = store.monotonic_anchor.acquire_lock().unwrap();
        let data_path = external_lock.namespace.path.join("test.external.log");
        let tail_path = external_lock.namespace.path.join("test.external.tail");
        let tail = DurableJournalTail {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            sequence: 1,
            record_count: 1,
            record_digest: "external-record".to_string(),
        };
        install_test_commit_failure(
            external_lock.namespace.path.clone(),
            CommitFailureBoundary::AppendTail,
        );
        assert!(matches!(
            append_json_with_tail(
                &external_lock,
                &data_path,
                &tail_path,
                &serde_json::json!({ "record": "external" }),
                &tail,
                1,
            ),
            Err(GraphStoreError::Write { .. })
        ));
        let manifest_path = external_lock
            .namespace
            .path
            .join(format!("test.external.log{APPEND_MANIFEST_SUFFIX}"));
        assert!(manifest_path.exists());
        drop(external_lock);
        let recovered_lock = store.monotonic_anchor.acquire_lock().unwrap();
        recover_log_append(&recovered_lock, &data_path, &tail_path).unwrap();
        let records: Vec<serde_json::Value> = recovered_lock.read_json_log(&data_path).unwrap();
        assert_eq!(records, vec![serde_json::json!({ "record": "external" })]);
        let recovered_tail: DurableJournalTail = recovered_lock.read_json(&tail_path).unwrap();
        assert_eq!(recovered_tail.record_count, 1);
        recovered_lock.remove_file(&data_path).unwrap();
        recovered_lock.remove_file(&tail_path).unwrap();
        drop(recovered_lock);
        drop(store);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn json_log_requires_a_trailing_delimiter() {
        let path = temp_dir("log-delimiter");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(54)).unwrap();
        let log_path = path.join("unterminated.log");
        atomic_write_json(&log_path, &serde_json::json!({ "record": 1 })).unwrap();
        assert!(matches!(
            store.lock.read_json_log::<serde_json::Value>(&log_path),
            Err(GraphStoreError::InvalidState { .. })
        ));
        drop(store);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn rollback_manifest_recovers_after_each_replacement() {
        for (index, boundary) in [
            CommitFailureBoundary::RollbackState,
            CommitFailureBoundary::RollbackHead,
            CommitFailureBoundary::RollbackHighWater,
            CommitFailureBoundary::RollbackHighWaterTail,
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_dir(&format!("rollback-manifest-{index}"));
            let key = signer(55);
            let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
            install_test_commit_failure(path.clone(), CommitFailureBoundary::State);
            assert!(matches!(
                store.create_task(request(56, &format!("rollback-{index}"))),
                Err(GraphStoreError::Write { .. })
            ));
            drop(store);
            install_test_commit_failure(path.clone(), boundary);
            assert!(matches!(
                FileHypothesisGraphStore::open_with_signer(&path, key.clone()),
                Err(GraphStoreError::Write { .. })
            ));
            let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
            assert!(reopened.snapshot().unwrap().state.tasks.is_empty());
            drop(reopened);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn parent_commit_tokens_are_parallel_per_store_and_nonblocking_same_store() {
        let parent = temp_dir("parent-tokens");
        fs::create_dir_all(&parent).unwrap();
        let first_path = parent.join("first");
        let second_path = parent.join("second");
        let first = FileHypothesisGraphStore::new(&first_path, graph(), signer(57)).unwrap();
        let second = FileHypothesisGraphStore::new(&second_path, graph(), signer(58)).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_root = first_path.clone();
        let first_thread = std::thread::spawn(move || {
            first_barrier.wait();
            ParentCommitLock::acquire(&first_root).map(|_| ())
        });
        let second_barrier = Arc::clone(&barrier);
        let second_root = second_path.clone();
        let second_thread = std::thread::spawn(move || {
            second_barrier.wait();
            ParentCommitLock::acquire(&second_root).map(|_| ())
        });
        barrier.wait();
        assert!(first_thread.join().unwrap().is_ok());
        assert!(second_thread.join().unwrap().is_ok());
        let held = ParentCommitLock::acquire(&first_path).unwrap();
        assert!(matches!(
            ParentCommitLock::acquire(&first_path),
            Err(GraphStoreError::LockContended { .. })
        ));
        drop(held);
        drop(first);
        drop(second);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn same_handle_mutations_serialize_before_reading_state() {
        let path = temp_dir("same-handle-mutations");
        let key = signer(59);
        let store = Arc::new(FileHypothesisGraphStore::new(&path, graph(), key).unwrap());
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        install_test_persistence_barrier(store.state_path().to_path_buf(), ready_tx, release_rx);
        let mut guard = PersistenceBarrierGuard::new(store.state_path().to_path_buf(), release_tx);
        let first_store = Arc::clone(&store);
        let first_thread =
            std::thread::spawn(move || first_store.create_task(request(60, "same-handle-first")));
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second_store = Arc::clone(&store);
        let (second_tx, second_rx) = mpsc::channel();
        let second_thread = std::thread::spawn(move || {
            let result = second_store.create_task(request(61, "same-handle-second"));
            let _ = second_tx.send(result);
        });
        assert!(second_rx.recv_timeout(Duration::from_millis(100)).is_err());
        guard.release();
        let first_result = first_thread.join().unwrap().unwrap();
        let second_result = second_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        second_thread.join().unwrap();
        drop(store);
        let _ = fs::remove_dir_all(path);
        assert_eq!(first_result.revision.generation, 1);
        assert_eq!(second_result.revision.generation, 2);
    }

    #[test]
    fn displaced_root_returned_error_is_rollback_only_after_restore() {
        let path = temp_dir("displaced-root");
        let displaced = path.with_extension("displaced");
        let key = signer(62);
        let store = Arc::new(FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap());
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        install_test_pre_rename_barrier(store.state_path().to_path_buf(), ready_tx, release_rx);
        let mut guard =
            PersistenceBarrierGuard::new_pre_rename(store.state_path().to_path_buf(), release_tx);
        let writer = Arc::clone(&store);
        let writer_thread =
            std::thread::spawn(move || writer.create_task(request(63, "displaced-root")));
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        fs::rename(&path, &displaced).unwrap();
        guard.release();
        let result = writer_thread.join().unwrap();
        assert!(matches!(
            result,
            Err(GraphStoreError::LockBinding { .. }) | Err(GraphStoreError::Read { .. })
        ));
        fs::rename(&displaced, &path).unwrap();
        drop(store);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert!(reopened.snapshot().unwrap().state.tasks.is_empty());
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn external_rotation_keeps_active_record_count_for_followup_append() {
        let path = temp_dir("external-rotation-count");
        let key = signer(64);
        let store = FileHypothesisGraphStore::new(&path, graph(), key.clone()).unwrap();
        store.create_task(request(65, "before-rotation")).unwrap();
        let external_lock = store.monotonic_anchor.acquire_lock().unwrap();
        let records = store
            .monotonic_anchor
            .read_records_locked::<DurableExternalCommitRecord>(&external_lock)
            .unwrap();
        let journal = verify_external_journal(
            &records,
            GRAPH_STORE_STATE_KIND,
            store.graph_id.as_str(),
            &store.signer_id,
            store.lock.generation(),
            &store.lock.identity_token(),
        )
        .unwrap();
        assert!(
            store
                .monotonic_anchor
                .rotate_for_test_locked(&external_lock, &journal.committed, &key)
                .unwrap()
        );
        drop(external_lock);
        store.create_task(request(66, "after-rotation")).unwrap();
        drop(store);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, key).unwrap();
        assert_eq!(reopened.snapshot().unwrap().revision.generation, 2);
        assert!(
            reopened
                .snapshot()
                .unwrap()
                .state
                .task("task:after-rotation")
                .is_some()
        );
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn direct_cas_rejects_uncoordinated_hypothesis_insertion() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(140),
            budget_policy(),
        )
        .unwrap();
        let migrated = migrate_with_budget(
            &store,
            budget_at(GraphLogicalTime::new(1), 0, 0),
            GraphLogicalTime::new(1),
        );
        let before_bytes = migrated.canonical_bytes().unwrap();
        let hypothesis_id = HypothesisId::new("hypothesis:uncoordinated");
        let mut candidate = migrated.state.clone();
        candidate.hypotheses.insert(
            hypothesis_id.clone(),
            Hypothesis::new(
                hypothesis_id,
                ConfidenceDistribution::uniform_two(),
                [UncertaintyReason::InsufficientEvidence],
                [],
            )
            .unwrap(),
        );
        assert!(matches!(
            store.compare_and_swap(&migrated.revision, candidate),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("coordinator seed/task lineage")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
    }

    #[test]
    fn direct_cas_rejects_initial_decision_history_even_with_task_lineage() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(145),
            budget_policy(),
        )
        .unwrap();
        let tick = GraphLogicalTime::new(1);
        let migrated = migrate_with_budget(&store, budget_at(tick, 0, 0), tick);
        let before_bytes = migrated.canonical_bytes().unwrap();
        let hypothesis_id = HypothesisId::new("hypothesis:forged-history");
        let decision_key = signer(146);
        let producer = AgentId::from_public_key_hex(&decision_key.public_key().to_hex());
        let decision = swarm_core::hypothesis_graph::DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Support,
            hypothesis_id.clone(),
            [],
            GraphProducerRole::Hunter,
            producer.clone(),
            tick,
            "caller-crafted initial decision",
        )
        .unwrap()
        .signed_with(&decision_key, "hypothesis-coordinator")
        .unwrap();
        let hypothesis = Hypothesis::new(
            hypothesis_id.clone(),
            ConfidenceDistribution::uniform_two(),
            [UncertaintyReason::InsufficientEvidence],
            [],
        )
        .unwrap()
        .append_decision(decision)
        .unwrap();
        let target = TaskTarget::Hypothesis {
            hypothesis_id: hypothesis_id.clone(),
        };
        let descriptor = LogicalTaskDescriptor::new(
            migrated.state().graph_id.clone(),
            target.clone(),
            TaskKind::FalsifyHypothesis,
            "46".repeat(32),
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::FalsifyHypothesis,
            target,
            GraphProducerRole::Falsifier,
            producer,
            EvidenceScope::new(
                [EvidenceSourceFamily::Process],
                [EvidenceId::new("evidence:forged-history-scope")],
                [],
            )
            .unwrap(),
            tick,
        )
        .unwrap();
        let durable = DurableTaskRecord {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            task: TaskRecord {
                schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
                request,
                state: TaskState::Pending,
                generation: 1,
                attempts: 1,
                lease: None,
                completion: None,
                terminal_history: Vec::new(),
            },
            generation: 1,
            history: Vec::new(),
        };
        let mut candidate = migrated.state.clone();
        candidate.hypotheses.insert(hypothesis_id, hypothesis);
        candidate.task_tombstones.insert(
            descriptor.task_id.clone(),
            TaskMonotonicity::from_record(&durable).unwrap(),
        );
        candidate.tasks.insert(descriptor.task_id.clone(), durable);
        candidate
            .logical_task_descriptors
            .insert(descriptor.task_id.clone(), descriptor);
        candidate.scheduler_budget = Some(budget_at(tick, 1, 0));

        assert!(matches!(
            store.compare_and_swap(&migrated.revision, candidate.clone()),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("authenticated coordinator seed/task lineage")
        ));
        let unrelated = AgentId::from_public_key_hex(&signer(149).public_key().to_hex());
        assert!(matches!(
            store.compare_and_swap_coordinator_seed(
                &migrated.revision,
                candidate.clone(),
                &unrelated,
            ),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("authenticated coordinator seed/task lineage")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );

        let coordinator_identity =
            AgentId::from_public_key_hex(&decision_key.public_key().to_hex());
        let admitted = store
            .compare_and_swap_coordinator_seed(&migrated.revision, candidate, &coordinator_identity)
            .unwrap();
        let mut raised_state = admitted.state.clone();
        raised_state.logical_time_high_water = GraphLogicalTime::new(100);
        let raised = store
            .compare_and_swap(&admitted.revision, raised_state)
            .unwrap();
        let backdated = swarm_core::hypothesis_graph::DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Support,
            HypothesisId::new("hypothesis:forged-history"),
            [],
            GraphProducerRole::Hunter,
            coordinator_identity,
            GraphLogicalTime::new(50),
            "valid signature below the predecessor high-water",
        )
        .unwrap()
        .signed_with(&decision_key, "generic-cas")
        .unwrap();
        let mut backdated_candidate = raised.state.clone();
        let updated = backdated_candidate.hypotheses
            [&HypothesisId::new("hypothesis:forged-history")]
            .clone()
            .append_decision(backdated)
            .unwrap();
        backdated_candidate
            .hypotheses
            .insert(updated.hypothesis_id.clone(), updated);
        let raised_bytes = raised.canonical_bytes().unwrap();
        assert!(matches!(
            store.compare_and_swap(&raised.revision, backdated_candidate),
            Err(GraphStoreError::InvalidState { reason })
                if reason.contains("predecessor logical-time high-water")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            raised_bytes
        );
    }

    #[test]
    fn pending_reasoning_task_binds_the_first_eligible_claimant() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(141),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, original_request) = logical_request(142, "pending-worker-rebind");
        let migrated = migrate_legacy_pending_with_budget(
            &store,
            descriptor,
            original_request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let claimant_key = signer(143);
        let claimant = AgentId::from_public_key_hex(&claimant_key.public_key().to_hex());
        let rebound = TaskClaimRequest::new(
            original_request.task_id.clone(),
            original_request.kind,
            original_request.target.clone(),
            original_request.role,
            claimant.clone(),
            original_request.evidence_scope.clone(),
            GraphLogicalTime::new(105),
        )
        .unwrap();
        let claimed = store
            .claim_task_cas_with_budget(
                &migrated.revision,
                rebound,
                GraphLogicalTime::new(105),
                10,
                budget_at(GraphLogicalTime::new(105), 0, 1),
            )
            .unwrap();
        assert_eq!(claimed.task.request.claimant, claimant);
        assert_eq!(
            claimed.task.request.requested_at,
            GraphLogicalTime::new(105)
        );
        assert_eq!(claimed.task.lease.as_ref().unwrap().holder, claimant);

        let before_steal = store.snapshot().unwrap();
        let third_key = signer(144);
        let third_claimant = AgentId::from_public_key_hex(&third_key.public_key().to_hex());
        let steal = TaskClaimRequest::new(
            original_request.task_id,
            original_request.kind,
            original_request.target,
            original_request.role,
            third_claimant,
            original_request.evidence_scope,
            GraphLogicalTime::new(106),
        )
        .unwrap();
        assert!(matches!(
            store.claim_task_cas_with_budget(
                &before_steal.revision,
                steal,
                GraphLogicalTime::new(106),
                10,
                before_steal.scheduler_budget().unwrap().clone(),
            ),
            Err(GraphStoreError::AlreadyClaimed { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before_steal);
    }

    #[test]
    fn reasoning_claim_rejects_time_below_durable_high_water_without_mutation() {
        let store = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(147),
            budget_policy(),
        )
        .unwrap();
        let (descriptor, request) = logical_request(148, "retrograde-claim");
        let high_water = GraphLogicalTime::new(100);
        let migrated = migrate_legacy_pending_with_budget(
            &store,
            descriptor,
            request.clone(),
            budget_at(high_water, 0, 0),
        );
        let before_bytes = migrated.canonical_bytes().unwrap();

        assert!(matches!(
            store.claim_task_cas_with_budget(
                &migrated.revision,
                request,
                GraphLogicalTime::new(99),
                10,
                budget_at(high_water, 0, 1),
            ),
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("claim logical time regressed")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
    }

    fn prepare_reasoning_failure(
        store: &dyn HypothesisGraphStore,
        claimant_seed: u8,
    ) -> (TaskClaimResult, TaskFailureOutboxEntry) {
        let (descriptor, request) = logical_request(claimant_seed, "atomic-reasoning-failure");
        let claimant_key = signer(claimant_seed);
        let migrated = migrate_legacy_pending_with_budget(
            store,
            descriptor.clone(),
            request.clone(),
            budget_at(GraphLogicalTime::new(100), 0, 0),
        );
        let claimed = store
            .claim_task_cas_with_budget(
                &migrated.revision,
                request.clone(),
                GraphLogicalTime::new(100),
                10,
                budget_at(GraphLogicalTime::new(100), 0, 1),
            )
            .unwrap();
        let capability = TaskCapabilityProof::new(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "atomic-failure-worker",
        )
        .unwrap();
        let failure = TaskFailure::new(
            request.claimant,
            GraphLogicalTime::new(105),
            "digest:atomic-reasoning-failure",
        )
        .unwrap();
        let publication = TaskFailureOutboxEntry::new(
            &claimed.task,
            &descriptor,
            failure,
            capability,
            &claimant_key,
            "atomic-failure-worker",
        )
        .unwrap();
        (claimed, publication)
    }

    fn assert_reasoning_failure_is_atomic(
        store: &dyn HypothesisGraphStore,
        claimant_seed: u8,
    ) -> GraphStoreSnapshot {
        let (claimed, publication) = prepare_reasoning_failure(store, claimant_seed);
        let task_id = publication.task_id.clone();
        let failed = store
            .fail_reasoning_task_cas(
                &claimed.revision,
                claimed.task_generation,
                publication.clone(),
            )
            .unwrap();
        assert_eq!(failed.task.state, TaskState::Failed);
        assert!(failed.task.lease.is_none());
        assert_eq!(
            failed
                .task
                .terminal_history
                .last()
                .unwrap()
                .failure_summary_digest
                .as_deref(),
            Some("digest:atomic-reasoning-failure")
        );
        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            snapshot.task_failure_outbox().get(&task_id),
            Some(&publication)
        );
        assert!(!snapshot.terminal_outbox().contains_key(&task_id));
        snapshot.state().validate().unwrap();
        let committed_bytes = snapshot.canonical_bytes().unwrap();
        for expected in [&claimed.revision, snapshot.revision()] {
            let replayed = store
                .fail_reasoning_task_cas(expected, claimed.task_generation, publication.clone())
                .unwrap();
            assert!(replayed.idempotent);
            assert_eq!(replayed.revision, *snapshot.revision());
            assert_eq!(replayed.task, failed.task);
        }
        let mut changed = publication;
        changed.failure.summary_digest = "digest:changed-reasoning-failure".to_string();
        assert!(matches!(
            store.fail_reasoning_task_cas(
                snapshot.revision(),
                claimed.task_generation,
                changed,
            ),
            Err(GraphStoreError::InvalidTransition { reason })
                if reason.contains("differs from the committed task publication")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            committed_bytes
        );
        snapshot
    }

    fn assert_concurrent_reasoning_failure_retry_is_atomic(
        store: Arc<dyn HypothesisGraphStore>,
        claimant_seed: u8,
    ) {
        let (claimed, publication) = prepare_reasoning_failure(store.as_ref(), claimant_seed);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let expected = claimed.revision.clone();
            let publication = publication.clone();
            let expected_generation = claimed.task_generation;
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.fail_reasoning_task_cas(&expected, expected_generation, publication)
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.idempotent).count(), 1);
        assert_eq!(
            results.iter().filter(|result| !result.idempotent).count(),
            1
        );

        let snapshot = store.snapshot().unwrap();
        assert_eq!(
            snapshot.revision.generation,
            claimed.revision.generation + 1
        );
        assert!(
            results
                .iter()
                .all(|result| result.revision == snapshot.revision)
        );
        assert_eq!(
            snapshot.task_failure_outbox().get(&publication.task_id),
            Some(&publication)
        );
        let committed_bytes = snapshot.canonical_bytes().unwrap();
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            committed_bytes
        );
    }

    #[test]
    fn concurrent_reasoning_failure_retries_are_atomic_for_memory_and_file() {
        let memory: Arc<dyn HypothesisGraphStore> = Arc::new(
            MemoryHypothesisGraphStore::new_with_scheduler_policy(
                graph(),
                signer(151),
                budget_policy(),
            )
            .unwrap(),
        );
        assert_concurrent_reasoning_failure_retry_is_atomic(memory, 152);

        let path = temp_dir("concurrent-reasoning-failure-retry");
        let file: Arc<dyn HypothesisGraphStore> = Arc::new(
            FileHypothesisGraphStore::new_with_scheduler_policy(
                &path,
                graph(),
                signer(153),
                budget_policy(),
            )
            .unwrap(),
        );
        assert_concurrent_reasoning_failure_retry_is_atomic(file, 154);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn reasoning_failure_outbox_is_atomic_across_memory_and_file_restart() {
        let memory = MemoryHypothesisGraphStore::new_with_scheduler_policy(
            graph(),
            signer(145),
            budget_policy(),
        )
        .unwrap();
        let memory_after = assert_reasoning_failure_is_atomic(&memory, 146);
        assert_eq!(memory.snapshot().unwrap(), memory_after);

        let path = temp_dir("atomic-reasoning-failure");
        let store_key = signer(147);
        let file = FileHypothesisGraphStore::new_with_scheduler_policy(
            &path,
            graph(),
            store_key.clone(),
            budget_policy(),
        )
        .unwrap();
        let file_after = assert_reasoning_failure_is_atomic(&file, 148);
        let expected_bytes = file_after.canonical_bytes().unwrap();
        drop(file);
        let reopened = FileHypothesisGraphStore::open_with_signer_and_scheduler_policy(
            &path,
            store_key,
            budget_policy(),
        )
        .unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().canonical_bytes().unwrap(),
            expected_bytes
        );
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }
}
