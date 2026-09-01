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
    EvidenceWitness, FencingToken, GraphAdmissionError, GraphId, GraphLogicalTime,
    GraphResourceLimits, HYPOTHESIS_GRAPH_SCHEMA_VERSION, HypothesisGraph, IdempotencyKey, LeaseId,
    TaskCapabilityProof, TaskClaimRequest, TaskId, TaskLease, TaskRecord, TaskState,
    TaskTerminalEnvelope, TaskTerminalProof, derive_logical_task_id,
};
use swarm_core::types::AgentId;
use swarm_crypto::{
    DetachedSignature, Keypair, canonical_json_bytes, sha256_hex, verify_detached_signature,
};

pub const GRAPH_STORE_SCHEMA_VERSION: u32 = 1;
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
}

impl TaskMonotonicity {
    fn from_record(record: &DurableTaskRecord) -> Result<Self, GraphStoreError> {
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
        })
    }

    fn compare_to(&self, current: &Self, task_id: &TaskId) -> Result<(), GraphStoreError> {
        if self.request_digest != current.request_digest {
            return Err(GraphStoreError::InvalidState {
                reason: format!("task {task_id} immutable request regressed or changed"),
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
    pub tasks: BTreeMap<TaskId, DurableTaskRecord>,
    #[serde(default)]
    pub task_tombstones: BTreeMap<TaskId, TaskMonotonicity>,
    pub fencing_counter: u64,
    pub logical_time_high_water: GraphLogicalTime,
}

impl GraphStoreState {
    pub fn new(graph: HypothesisGraph) -> Result<Self, GraphStoreError> {
        graph.validate().map_err(GraphStoreError::Admission)?;
        Ok(Self {
            schema_version: GRAPH_STORE_SCHEMA_VERSION,
            graph_id: graph.graph_id.clone(),
            generation: 0,
            predecessor_digest: None,
            graph,
            tasks: BTreeMap::new(),
            task_tombstones: BTreeMap::new(),
            fencing_counter: 0,
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
        if self.graph_id != self.graph.graph_id {
            return Err(GraphStoreError::InvalidState {
                reason: "store graph ID does not match graph payload".to_string(),
            });
        }
        self.logical_time_high_water
            .validate()
            .map_err(GraphStoreError::Admission)?;
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
            let expected_tombstone = TaskMonotonicity::from_record(task)?;
            let observed_tombstone =
                self.task_tombstones
                    .get(task_id)
                    .ok_or_else(|| GraphStoreError::InvalidState {
                        reason: "task map entry has no durable monotonic tombstone".to_string(),
                    })?;
            if observed_tombstone != &expected_tombstone {
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
        Ok(())
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphCasMaterial<'a> {
    expected: &'a GraphStoreRevision,
    state: &'a GraphStoreState,
    authority_scope: &'a str,
}

/// Scheduler-authorized append-only graph replacement bound to one exact
/// predecessor. Generic state CAS may add already validated graph records but
/// may not delete or rewrite durable graph contents, inject a version, or
/// mutate store-owned task and clock state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphCasEnvelope {
    pub expected: GraphStoreRevision,
    pub state: GraphStoreState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_witness: Option<EvidenceWitness>,
}

impl GraphCasEnvelope {
    pub fn new(
        expected: GraphStoreRevision,
        state: GraphStoreState,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            expected,
            state,
            authority_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn authorized_by(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let scoped_agent_id = scoped_agent_id.into();
        validate_authority_scope("graph CAS", &scoped_agent_id)?;
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.authority_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, authority_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&GraphCasMaterial {
            expected: &self.expected,
            state: &self.state,
            authority_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let authority_scope = self
            .authority_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(authority_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        self.expected.validate()?;
        validate_optional_scheduler_witness(
            self.authority_witness.as_ref(),
            &self.canonical_bytes_without_witness()?,
        )
    }

    fn validate_for_store(&self, authority: &AgentId) -> Result<(), GraphStoreError> {
        self.validate()?;
        require_configured_scheduler_witness(
            self.authority_witness.as_ref(),
            authority,
            &self.canonical_bytes_without_witness()?,
            "durable graph CAS requires scheduler authority",
        )
    }
}

/// Public read result used by runtime coordinators and parity tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphStoreSnapshot {
    pub state: GraphStoreState,
    pub revision: GraphStoreRevision,
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
    limits: &GraphResourceLimits,
) -> Result<(), GraphStoreError> {
    // Core owns structural, signature, exact-task, lease, fence, completion,
    // and lineage validation.  The spine supplies the configured persistence
    // boundary but does not reimplement those rules.
    envelope
        .validate_for_task(task, limits.max_task_lease_ms, limits.max_task_retries)
        .map_err(GraphStoreError::Admission)?;
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
    pub fn graph(&self) -> &HypothesisGraph {
        &self.state.graph
    }

    pub fn tasks(&self) -> impl Iterator<Item = &DurableTaskRecord> {
        self.state.tasks.values()
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
) -> Result<(), GraphStoreError> {
    envelope.state.validate_with_limits(limits)?;
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

struct StateMutation<R> {
    value: R,
    changed: bool,
}

fn refresh_task_tombstones(state: &mut GraphStoreState) -> Result<(), GraphStoreError> {
    for (task_id, record) in &state.tasks {
        let next = TaskMonotonicity::from_record(record)?;
        if let Some(current) = state.task_tombstones.get(task_id) {
            next.compare_to(current, task_id)?;
        }
        state.task_tombstones.insert(task_id.clone(), next);
    }
    Ok(())
}

fn transition<R, F>(
    current: &SignedGraphStoreState,
    expected: Option<&GraphStoreRevision>,
    signer: &Keypair,
    limits: &GraphResourceLimits,
    operation: F,
) -> Result<(SignedGraphStoreState, R), GraphStoreError>
where
    F: FnOnce(&mut GraphStoreState) -> Result<StateMutation<R>, GraphStoreError>,
{
    let current_revision = current.revision()?;
    check_expected(&current_revision, expected)?;
    let mut next_state = current.state.clone();
    let result = operation(&mut next_state)?;
    if !result.changed {
        return Ok((current.clone(), result.value));
    }
    refresh_task_tombstones(&mut next_state)?;
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

fn graph_map_extension_count<K, V>(
    label: &str,
    current: &BTreeMap<K, V>,
    candidate: &BTreeMap<K, V>,
) -> Result<usize, GraphStoreError>
where
    K: Ord,
    V: PartialEq,
{
    if current
        .iter()
        .any(|(key, value)| candidate.get(key) != Some(value))
    {
        return Err(GraphStoreError::InvalidState {
            reason: format!("graph CAS cannot delete or rewrite existing {label}"),
        });
    }
    candidate
        .len()
        .checked_sub(current.len())
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: format!("graph CAS {label} count regressed"),
        })
}

fn validate_graph_cas_successor(
    current: &HypothesisGraph,
    candidate: &HypothesisGraph,
) -> Result<bool, GraphStoreError> {
    if candidate.schema_version != current.schema_version
        || candidate.graph_id != current.graph_id
        || candidate.limits != current.limits
    {
        return Err(GraphStoreError::InvalidState {
            reason: "graph CAS cannot replace graph identity, schema, or limits".to_string(),
        });
    }
    let additions = [
        graph_map_extension_count("nodes", &current.nodes, &candidate.nodes)?,
        graph_map_extension_count("evidence", &current.evidence, &candidate.evidence)?,
        graph_map_extension_count("edges", &current.edges, &candidate.edges)?,
        graph_map_extension_count(
            "contradictions",
            &current.contradictions,
            &candidate.contradictions,
        )?,
        graph_map_extension_count("conflicts", &current.conflicts, &candidate.conflicts)?,
    ]
    .into_iter()
    .try_fold(0_usize, |total, count| total.checked_add(count))
    .ok_or_else(|| GraphStoreError::InvalidState {
        reason: "graph CAS addition count overflow".to_string(),
    })?;
    let addition_delta = u64::try_from(additions).map_err(|_| GraphStoreError::InvalidState {
        reason: "graph CAS addition count does not fit the version counter".to_string(),
    })?;
    let expected_version = current.version.checked_add(addition_delta).ok_or_else(|| {
        GraphStoreError::InvalidState {
            reason: "graph CAS version would overflow".to_string(),
        }
    })?;
    if candidate.version != expected_version {
        return Err(GraphStoreError::InvalidState {
            reason: format!(
                "graph CAS version must advance exactly once per appended record: expected {expected_version}, observed {}",
                candidate.version
            ),
        });
    }
    Ok(additions > 0)
}

fn graph_cas_op(
    current: &mut GraphStoreState,
    envelope: GraphCasEnvelope,
    graph_id: &GraphId,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<()>, GraphStoreError> {
    envelope.validate_for_store(authority)?;
    let state = envelope.state;
    if &state.graph_id != graph_id {
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
    if state.fencing_counter != current.fencing_counter {
        return Err(GraphStoreError::InvalidState {
            reason: "graph CAS cannot replace the store-owned fencing counter".to_string(),
        });
    }
    if state.logical_time_high_water != current.logical_time_high_water {
        return Err(GraphStoreError::InvalidState {
            reason: "graph CAS cannot replace the store-owned logical time high-water".to_string(),
        });
    }
    if state.tasks != current.tasks || state.task_tombstones != current.task_tombstones {
        return Err(GraphStoreError::InvalidState {
            reason: "graph CAS cannot replace task records or tombstones".to_string(),
        });
    }
    state.validate_with_limits(limits)?;
    let changed = validate_graph_cas_successor(&current.graph, &state.graph)?;
    if changed {
        current.graph = state.graph;
    }
    Ok(StateMutation { value: (), changed })
}

fn create_task_op(
    state: &mut GraphStoreState,
    envelope: TaskCreationEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    envelope.validate_for_store(authority)?;
    let request = envelope.request;
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
    envelope: TaskClaimEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    envelope.validate_for_store(authority, limits)?;
    let request = envelope.request;
    let now = envelope.claimed_at;
    let duration_ms = envelope.duration_ms;
    let existing = state.tasks.get(&request.task_id).cloned();
    if let Some(ref existing) = existing {
        if !same_claim_identity(&existing.task.request, &request) {
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
        if existing.task.state == TaskState::Claimed
            || matches!(
                existing.task.state,
                TaskState::Completed | TaskState::Failed
            )
        {
            if existing.task.state == TaskState::Claimed
                && existing
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
    let claim_request = existing
        .as_ref()
        .map_or_else(|| request.clone(), |entry| entry.task.request.clone());
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

fn renew_task_op(
    state: &mut GraphStoreState,
    envelope: TaskRenewalEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    let current = state
        .tasks
        .get(&envelope.task_id)
        .ok_or_else(|| GraphStoreError::TaskNotFound {
            task_id: envelope.task_id.to_string(),
        })?
        .clone();
    ensure_task_generation(&current, envelope.expected_generation)?;
    envelope.validate_for_task(&current.task, authority, limits)?;
    observe_logical_time(state, envelope.renewed_at)?;
    let entry = task_entry_mut(state, envelope.task_id.as_str())?;
    let old_lease = ensure_lease(entry, &envelope.lease_id, envelope.fencing_token)?;
    let renewed = TaskLease::new(
        old_lease.lease_id.clone(),
        old_lease.holder.clone(),
        envelope.renewed_at,
        envelope
            .renewed_at
            .checked_add(i64::try_from(envelope.duration_ms).map_err(|_| {
                GraphStoreError::InvalidLease {
                    reason: "duration does not fit logical time".to_string(),
                }
            })?)
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
    expected_generation: u64,
    clock: TaskTerminalClockEnvelope,
    envelope: TaskTerminalEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    {
        let entry =
            state
                .tasks
                .get(&envelope.task_id)
                .ok_or_else(|| GraphStoreError::TaskNotFound {
                    task_id: envelope.task_id.to_string(),
                })?;
        ensure_task_generation(entry, expected_generation)?;
        clock.validate_for_operation(
            &entry.task,
            expected_generation,
            TaskTerminalOperationKind::Complete,
            &envelope,
            authority,
        )?;
    }
    let now = clock.observed_at;
    observe_logical_time(state, now)?;
    let entry = task_entry_mut(state, envelope.task_id.as_str())?;
    ensure_task_generation(entry, expected_generation)?;
    let lease = ensure_lease(entry, &envelope.lease_id, envelope.fencing_token)?;
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
    if envelope.completion.completed_at > now {
        return Err(GraphStoreError::InvalidTransition {
            reason: "completion time is ahead of the injected logical clock".to_string(),
        });
    }
    validate_task_terminal_envelope(&entry.task, &envelope, limits)?;
    let task = entry
        .task
        .clone()
        .complete(
            envelope.completion,
            envelope.fencing_token,
            limits.max_task_lease_ms,
        )
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
    expected_generation: u64,
    clock: TaskTerminalClockEnvelope,
    envelope: TaskFailureEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    {
        let entry =
            state
                .tasks
                .get(&envelope.task_id)
                .ok_or_else(|| GraphStoreError::TaskNotFound {
                    task_id: envelope.task_id.to_string(),
                })?;
        ensure_task_generation(entry, expected_generation)?;
        clock.validate_for_operation(
            &entry.task,
            expected_generation,
            TaskTerminalOperationKind::Fail,
            &envelope,
            authority,
        )?;
    }
    let now = clock.observed_at;
    observe_logical_time(state, now)?;
    let entry = task_entry_mut(state, envelope.task_id.as_str())?;
    ensure_task_generation(entry, expected_generation)?;
    let lease = ensure_lease(entry, &envelope.lease_id, envelope.fencing_token)?;
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
    validate_task_failure_envelope(&entry.task, &envelope, limits)?;
    if envelope.failure.failed_at > now {
        return Err(GraphStoreError::InvalidTransition {
            reason: "failure time is ahead of the injected logical clock".to_string(),
        });
    }
    let next_task_generation =
        entry
            .task
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    let next_entry_generation =
        entry
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task generation overflow".to_string(),
            })?;
    let proof = TaskTerminalProof::new_failed(
        entry.task.generation,
        lease,
        envelope.failure.failed_by,
        envelope.failure.failed_at,
        envelope.failure.summary_digest,
        limits.max_task_lease_ms,
    )
    .map_err(GraphStoreError::Admission)?;
    entry.task.terminal_history.push(proof);
    entry.task.state = TaskState::Failed;
    entry.task.generation = next_task_generation;
    entry.task.lease = None;
    entry.task.completion = None;
    entry.generation = next_entry_generation;
    Ok(StateMutation {
        value: TaskMutationMarker {
            task: entry.task.clone(),
            idempotent: false,
        },
        changed: true,
    })
}

fn expire_task_op(
    state: &mut GraphStoreState,
    envelope: TaskExpiryEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    let current = state
        .tasks
        .get(&envelope.task_id)
        .ok_or_else(|| GraphStoreError::TaskNotFound {
            task_id: envelope.task_id.to_string(),
        })?
        .clone();
    ensure_task_generation(&current, envelope.expected_generation)?;
    envelope.validate_for_task(&current.task, authority, limits)?;
    observe_logical_time(state, envelope.observed_at)?;
    {
        let entry = task_entry_mut(state, envelope.task_id.as_str())?;
        entry.task = entry
            .task
            .clone()
            .expire(envelope.observed_at, limits.max_task_lease_ms)
            .map_err(GraphStoreError::Admission)?;
    }
    // Expiry is itself a fencing barrier.  Advance the durable counter before
    // publishing the expired record so the token of the expired lease can
    // never authorize a later operation, including after a restart.
    next_fence(state)?;
    let entry = task_entry_mut(state, envelope.task_id.as_str())?;
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
    envelope: TaskReclaimEnvelope,
    authority: &AgentId,
    limits: &GraphResourceLimits,
) -> Result<StateMutation<TaskMutationMarker>, GraphStoreError> {
    let old = state
        .tasks
        .get(&envelope.request.task_id)
        .ok_or_else(|| GraphStoreError::TaskNotFound {
            task_id: envelope.request.task_id.to_string(),
        })?
        .clone();
    ensure_task_generation(&old, envelope.expected_generation)?;
    envelope.validate_for_task(&old.task, authority, limits)?;
    observe_logical_time(state, envelope.reclaimed_at)?;
    let fence = next_fence(state)?;
    let lease = lease_for(
        state.graph_id.as_str(),
        envelope.request.task_id.as_str(),
        &envelope.request.claimant,
        envelope.reclaimed_at,
        envelope.duration_ms,
        fence,
        limits,
    )?;
    let mut task = TaskRecord::claimed_with_limits(
        envelope.request,
        lease,
        limits.max_task_lease_ms,
        limits.max_task_retries,
    )
    .map_err(GraphStoreError::Admission)?;
    task.attempts = old.task.attempts.saturating_add(1);
    // A claimed core record cannot carry the prior terminal history by design;
    // it is retained in the spine wrapper instead.
    let entry = state.tasks.get_mut(&task.request.task_id).ok_or_else(|| {
        GraphStoreError::TaskNotFound {
            task_id: task.request.task_id.to_string(),
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

#[derive(Debug, Clone)]
struct TaskMutationMarker {
    task: TaskRecord,
    idempotent: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskCreationMaterial<'a> {
    request: &'a TaskClaimRequest,
    capability: &'a TaskCapabilityProof,
    authority_scope: &'a str,
}

/// Dual-authority admission for a pending durable task. The claimant owns the
/// exact request and the configured scheduler/store authority owns admission
/// of its logical request time into the durable high-water mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCreationEnvelope {
    pub request: TaskClaimRequest,
    pub capability: TaskCapabilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_witness: Option<EvidenceWitness>,
}

impl TaskCreationEnvelope {
    pub fn new(
        request: TaskClaimRequest,
        capability: TaskCapabilityProof,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            request,
            capability,
            authority_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn authorized_by(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let scoped_agent_id = scoped_agent_id.into();
        validate_authority_scope("task creation", &scoped_agent_id)?;
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.authority_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, authority_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskCreationMaterial {
            request: &self.request,
            capability: &self.capability,
            authority_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let authority_scope = self
            .authority_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(authority_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        validate_request(&self.request)?;
        self.capability
            .validate_for_claim(&self.request)
            .map_err(GraphStoreError::Admission)?;
        validate_optional_scheduler_witness(
            self.authority_witness.as_ref(),
            &self.canonical_bytes_without_witness()?,
        )
    }

    fn validate_for_store(&self, authority: &AgentId) -> Result<(), GraphStoreError> {
        self.validate()?;
        require_configured_scheduler_witness(
            self.authority_witness.as_ref(),
            authority,
            &self.canonical_bytes_without_witness()?,
            "durable task creation requires scheduler authority",
        )
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskClaimMaterial<'a> {
    request: &'a TaskClaimRequest,
    claimed_at: GraphLogicalTime,
    duration_ms: u64,
    capability: &'a TaskCapabilityProof,
    authority_scope: &'a str,
}

/// Dual-authority admission for an exact task lease. The claimant proves
/// ownership of the request; the configured scheduler/store authority proves
/// the authoritative lease time and duration before either durable counter is
/// advanced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskClaimEnvelope {
    pub request: TaskClaimRequest,
    pub claimed_at: GraphLogicalTime,
    pub duration_ms: u64,
    pub capability: TaskCapabilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_witness: Option<EvidenceWitness>,
}

impl TaskClaimEnvelope {
    pub fn new(
        request: TaskClaimRequest,
        claimed_at: GraphLogicalTime,
        duration_ms: u64,
        capability: TaskCapabilityProof,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            request,
            claimed_at,
            duration_ms,
            capability,
            authority_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn authorized_by(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let scoped_agent_id = scoped_agent_id.into();
        validate_authority_scope("task claim", &scoped_agent_id)?;
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.authority_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, authority_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskClaimMaterial {
            request: &self.request,
            claimed_at: self.claimed_at,
            duration_ms: self.duration_ms,
            capability: &self.capability,
            authority_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let authority_scope = self
            .authority_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(authority_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        validate_request(&self.request)?;
        self.claimed_at
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if self.claimed_at < self.request.requested_at {
            return Err(GraphStoreError::InvalidTransition {
                reason: "task claim time precedes its signed request".to_string(),
            });
        }
        if self.duration_ms == 0 {
            return Err(GraphStoreError::InvalidLease {
                reason: "task claim duration must be positive".to_string(),
            });
        }
        self.capability
            .validate_for_claim(&self.request)
            .map_err(GraphStoreError::Admission)?;
        validate_optional_scheduler_witness(
            self.authority_witness.as_ref(),
            &self.canonical_bytes_without_witness()?,
        )
    }

    fn validate_for_store(
        &self,
        authority: &AgentId,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphStoreError> {
        self.validate()?;
        if self.duration_ms > limits.max_task_lease_ms {
            return Err(GraphStoreError::InvalidLease {
                reason: "task claim duration exceeds the graph lease limit".to_string(),
            });
        }
        require_configured_scheduler_witness(
            self.authority_witness.as_ref(),
            authority,
            &self.canonical_bytes_without_witness()?,
            "durable task claim requires scheduler authority",
        )
    }
}

fn validate_authority_scope(kind: &str, scope: &str) -> Result<(), GraphStoreError> {
    if scope.trim().is_empty() || scope.len() > 128 {
        return Err(GraphStoreError::InvalidState {
            reason: format!("{kind} authority scope is invalid"),
        });
    }
    Ok(())
}

fn validate_optional_scheduler_witness(
    witness: Option<&EvidenceWitness>,
    canonical_bytes: &[u8],
) -> Result<(), GraphStoreError> {
    if let Some(witness) = witness {
        if witness.producer_role != swarm_core::hypothesis_graph::GraphProducerRole::Planner {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "task scheduler authority must use the planner role".to_string(),
                },
            ));
        }
        witness
            .validate(canonical_bytes)
            .map_err(GraphStoreError::Admission)?;
    }
    Ok(())
}

fn require_configured_scheduler_witness(
    witness: Option<&EvidenceWitness>,
    authority: &AgentId,
    canonical_bytes: &[u8],
    missing_reason: &str,
) -> Result<(), GraphStoreError> {
    let Some(witness) = witness else {
        return Err(GraphStoreError::Admission(
            GraphAdmissionError::InvalidWitness {
                reason: missing_reason.to_string(),
            },
        ));
    };
    if &witness.producer_identity != authority {
        return Err(GraphStoreError::Admission(
            GraphAdmissionError::InvalidWitness {
                reason: "task scheduler witness does not match the configured store authority"
                    .to_string(),
            },
        ));
    }
    witness
        .validate(canonical_bytes)
        .map_err(GraphStoreError::Admission)
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskRenewalMaterial<'a> {
    task_id: &'a TaskId,
    idempotency_key: &'a IdempotencyKey,
    expected_generation: u64,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    renewed_at: GraphLogicalTime,
    duration_ms: u64,
    capability: &'a TaskCapabilityProof,
    renewal_scope: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskRenewalAuthorityMaterial<'a> {
    task_id: &'a TaskId,
    idempotency_key: &'a IdempotencyKey,
    expected_generation: u64,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    renewed_at: GraphLogicalTime,
    duration_ms: u64,
    capability: &'a TaskCapabilityProof,
    renewal_witness: &'a EvidenceWitness,
    authority_scope: &'a str,
}

/// Dual-authority request to extend one exact active lease. The claimant owns
/// the task capability; the configured scheduler/store authority owns the
/// authoritative renewal clock and duration. Both signatures cover the exact
/// durable generation, idempotency key, lease, and fencing token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRenewalEnvelope {
    pub task_id: TaskId,
    pub idempotency_key: IdempotencyKey,
    pub expected_generation: u64,
    pub lease_id: LeaseId,
    pub fencing_token: FencingToken,
    pub renewed_at: GraphLogicalTime,
    pub duration_ms: u64,
    pub capability: TaskCapabilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_witness: Option<EvidenceWitness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_witness: Option<EvidenceWitness>,
}

impl TaskRenewalEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        idempotency_key: IdempotencyKey,
        expected_generation: u64,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        renewed_at: GraphLogicalTime,
        duration_ms: u64,
        capability: TaskCapabilityProof,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            task_id,
            idempotency_key,
            expected_generation,
            lease_id,
            fencing_token,
            renewed_at,
            duration_ms,
            capability,
            renewal_witness: None,
            authority_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn signed_with(
        mut self,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let signer_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        if signer_identity != self.capability.claimant {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "renewal signer does not match the capability claimant".to_string(),
                },
            ));
        }
        let scoped_agent_id = scoped_agent_id.into();
        if scoped_agent_id.trim().is_empty() || scoped_agent_id.len() > 128 {
            return Err(GraphStoreError::InvalidState {
                reason: "renewal scope is invalid".to_string(),
            });
        }
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.renewal_witness = Some(
            EvidenceWitness::new(signer, self.capability.role, scoped_agent_id, &bytes)
                .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    pub fn authorized_by(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let renewal_witness = self.renewal_witness.as_ref().ok_or_else(|| {
            GraphStoreError::Admission(GraphAdmissionError::InvalidWitness {
                reason: "scheduler cannot authorize a renewal without claimant authority"
                    .to_string(),
            })
        })?;
        let scoped_agent_id = scoped_agent_id.into();
        validate_authority_scope("task renewal", &scoped_agent_id)?;
        let bytes = self.canonical_authority_bytes_for_scope(renewal_witness, &scoped_agent_id)?;
        self.authority_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, renewal_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskRenewalMaterial {
            task_id: &self.task_id,
            idempotency_key: &self.idempotency_key,
            expected_generation: self.expected_generation,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            renewed_at: self.renewed_at,
            duration_ms: self.duration_ms,
            capability: &self.capability,
            renewal_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let renewal_scope = self
            .renewal_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(renewal_scope)
    }

    fn canonical_authority_bytes_for_scope(
        &self,
        renewal_witness: &EvidenceWitness,
        authority_scope: &str,
    ) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskRenewalAuthorityMaterial {
            task_id: &self.task_id,
            idempotency_key: &self.idempotency_key,
            expected_generation: self.expected_generation,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            renewed_at: self.renewed_at,
            duration_ms: self.duration_ms,
            capability: &self.capability,
            renewal_witness,
            authority_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_authority_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let renewal_witness = self.renewal_witness.as_ref().ok_or_else(|| {
            GraphStoreError::Admission(GraphAdmissionError::InvalidWitness {
                reason: "renewal scheduler authority requires claimant authority".to_string(),
            })
        })?;
        let authority_scope = self
            .authority_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_authority_bytes_for_scope(renewal_witness, authority_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        self.renewed_at
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if self.expected_generation == 0 || self.duration_ms == 0 {
            return Err(GraphStoreError::InvalidLease {
                reason: "renewal generation and duration must be positive".to_string(),
            });
        }
        if self.capability.task_id != self.task_id {
            return Err(GraphStoreError::InvalidTransition {
                reason: "renewal capability task does not match envelope task".to_string(),
            });
        }
        if let Some(witness) = &self.renewal_witness {
            if witness.producer_identity != self.capability.claimant
                || witness.producer_role != self.capability.role
            {
                return Err(GraphStoreError::Admission(
                    GraphAdmissionError::InvalidWitness {
                        reason: "renewal witness does not bind claimant and capability role"
                            .to_string(),
                    },
                ));
            }
            witness
                .validate(&self.canonical_bytes_without_witness()?)
                .map_err(GraphStoreError::Admission)?;
        }
        if self.authority_witness.is_some() {
            validate_optional_scheduler_witness(
                self.authority_witness.as_ref(),
                &self.canonical_authority_bytes_without_witness()?,
            )?;
        }
        Ok(())
    }

    fn validate_for_task(
        &self,
        task: &TaskRecord,
        authority: &AgentId,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphStoreError> {
        self.validate()?;
        task.validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
            .map_err(GraphStoreError::Admission)?;
        if task.state != TaskState::Claimed || task.completion.is_some() {
            return Err(GraphStoreError::InvalidTransition {
                reason: "renewal envelope requires an active claimed task".to_string(),
            });
        }
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidTransition {
                reason: "renewal envelope requires the task's active lease".to_string(),
            })?;
        self.capability
            .validate_for_claim(&task.request)
            .map_err(GraphStoreError::Admission)?;
        if self.task_id != task.request.task_id
            || self.idempotency_key != task.request.idempotency_key
            || self.lease_id != lease.lease_id
            || self.fencing_token != lease.fencing_token
            || self.capability.claimant != lease.holder
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "renewal envelope does not bind the active task lease".to_string(),
            });
        }
        if self.renewed_at < lease.issued_at {
            return Err(GraphStoreError::InvalidTransition {
                reason: "renewal clock precedes lease issuance".to_string(),
            });
        }
        if self.renewed_at >= lease.expires_at {
            return Err(GraphStoreError::LeaseExpired {
                task_id: task.request.task_id.clone(),
            });
        }
        require_configured_scheduler_witness(
            self.authority_witness.as_ref(),
            authority,
            &self.canonical_authority_bytes_without_witness()?,
            "durable task renewal requires scheduler authority",
        )?;
        if self.duration_ms > limits.max_task_lease_ms {
            return Err(GraphStoreError::InvalidLease {
                reason: "renewal duration exceeds the graph lease limit".to_string(),
            });
        }
        let Some(witness) = self.renewal_witness.as_ref() else {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "durable task renewal requires a claimant signature".to_string(),
                },
            ));
        };
        witness
            .validate(&self.canonical_bytes_without_witness()?)
            .map_err(GraphStoreError::Admission)
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskExpiryMaterial<'a> {
    task_id: &'a TaskId,
    idempotency_key: &'a IdempotencyKey,
    expected_generation: u64,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    observed_at: GraphLogicalTime,
    expiry_scope: &'a str,
}

/// Scheduler-signed observation that one exact lease expired. The store only
/// accepts a witness from its configured signing identity, preventing callers
/// with a shared handle from advancing durable logical time themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskExpiryEnvelope {
    pub task_id: TaskId,
    pub idempotency_key: IdempotencyKey,
    pub expected_generation: u64,
    pub lease_id: LeaseId,
    pub fencing_token: FencingToken,
    pub observed_at: GraphLogicalTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_witness: Option<EvidenceWitness>,
}

impl TaskExpiryEnvelope {
    pub fn new(
        task_id: TaskId,
        idempotency_key: IdempotencyKey,
        expected_generation: u64,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        observed_at: GraphLogicalTime,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            task_id,
            idempotency_key,
            expected_generation,
            lease_id,
            fencing_token,
            observed_at,
            expiry_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn signed_with(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let scoped_agent_id = scoped_agent_id.into();
        if scoped_agent_id.trim().is_empty() || scoped_agent_id.len() > 128 {
            return Err(GraphStoreError::InvalidState {
                reason: "expiry scope is invalid".to_string(),
            });
        }
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.expiry_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, expiry_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskExpiryMaterial {
            task_id: &self.task_id,
            idempotency_key: &self.idempotency_key,
            expected_generation: self.expected_generation,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            observed_at: self.observed_at,
            expiry_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let expiry_scope = self
            .expiry_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(expiry_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        self.observed_at
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if self.expected_generation == 0 {
            return Err(GraphStoreError::InvalidTransition {
                reason: "expiry generation must be positive".to_string(),
            });
        }
        if let Some(witness) = &self.expiry_witness {
            if witness.producer_role != swarm_core::hypothesis_graph::GraphProducerRole::Planner {
                return Err(GraphStoreError::Admission(
                    GraphAdmissionError::InvalidWitness {
                        reason: "expiry witness must use the planner authority role".to_string(),
                    },
                ));
            }
            witness
                .validate(&self.canonical_bytes_without_witness()?)
                .map_err(GraphStoreError::Admission)?;
        }
        Ok(())
    }

    fn validate_for_task(
        &self,
        task: &TaskRecord,
        authority: &AgentId,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphStoreError> {
        self.validate()?;
        task.validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
            .map_err(GraphStoreError::Admission)?;
        if task.state != TaskState::Claimed || task.completion.is_some() {
            return Err(GraphStoreError::InvalidTransition {
                reason: "expiry envelope requires an active claimed task".to_string(),
            });
        }
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidTransition {
                reason: "expiry envelope requires the task's active lease".to_string(),
            })?;
        if self.task_id != task.request.task_id
            || self.idempotency_key != task.request.idempotency_key
            || self.lease_id != lease.lease_id
            || self.fencing_token != lease.fencing_token
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "expiry envelope does not bind the active task lease".to_string(),
            });
        }
        if self.observed_at < lease.expires_at {
            return Err(GraphStoreError::InvalidTransition {
                reason: "expiry observation precedes lease expiry".to_string(),
            });
        }
        let Some(witness) = self.expiry_witness.as_ref() else {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "durable task expiry requires an authority signature".to_string(),
                },
            ));
        };
        if &witness.producer_identity != authority {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "expiry witness does not match the configured store authority"
                        .to_string(),
                },
            ));
        }
        witness
            .validate(&self.canonical_bytes_without_witness()?)
            .map_err(GraphStoreError::Admission)
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskReclaimMaterial<'a> {
    prior_idempotency_key: &'a IdempotencyKey,
    expected_generation: u64,
    request: &'a TaskClaimRequest,
    reclaimed_at: GraphLogicalTime,
    duration_ms: u64,
    capability: &'a TaskCapabilityProof,
    authority_scope: &'a str,
}

/// Scheduler-authorized reassignment of one exact expired task generation.
/// The replacement claimant proves ownership of the new request while the
/// configured store authority separately admits the reassignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskReclaimEnvelope {
    pub prior_idempotency_key: IdempotencyKey,
    pub expected_generation: u64,
    pub request: TaskClaimRequest,
    pub reclaimed_at: GraphLogicalTime,
    pub duration_ms: u64,
    pub capability: TaskCapabilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_witness: Option<EvidenceWitness>,
}

impl TaskReclaimEnvelope {
    pub fn new(
        prior_idempotency_key: IdempotencyKey,
        expected_generation: u64,
        request: TaskClaimRequest,
        reclaimed_at: GraphLogicalTime,
        duration_ms: u64,
        capability: TaskCapabilityProof,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            prior_idempotency_key,
            expected_generation,
            request,
            reclaimed_at,
            duration_ms,
            capability,
            authority_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn authorized_by(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let scoped_agent_id = scoped_agent_id.into();
        if scoped_agent_id.trim().is_empty() || scoped_agent_id.len() > 128 {
            return Err(GraphStoreError::InvalidState {
                reason: "reclaim authority scope is invalid".to_string(),
            });
        }
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.authority_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, authority_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskReclaimMaterial {
            prior_idempotency_key: &self.prior_idempotency_key,
            expected_generation: self.expected_generation,
            request: &self.request,
            reclaimed_at: self.reclaimed_at,
            duration_ms: self.duration_ms,
            capability: &self.capability,
            authority_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let authority_scope = self
            .authority_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(authority_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        validate_request(&self.request)?;
        self.reclaimed_at
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if self.expected_generation == 0 || self.duration_ms == 0 {
            return Err(GraphStoreError::InvalidLease {
                reason: "reclaim generation and duration must be positive".to_string(),
            });
        }
        self.capability
            .validate_for_claim(&self.request)
            .map_err(GraphStoreError::Admission)?;
        if let Some(witness) = &self.authority_witness {
            if witness.producer_role != swarm_core::hypothesis_graph::GraphProducerRole::Planner {
                return Err(GraphStoreError::Admission(
                    GraphAdmissionError::InvalidWitness {
                        reason: "reclaim authority must use the planner role".to_string(),
                    },
                ));
            }
            witness
                .validate(&self.canonical_bytes_without_witness()?)
                .map_err(GraphStoreError::Admission)?;
        }
        Ok(())
    }

    fn validate_for_task(
        &self,
        task: &TaskRecord,
        authority: &AgentId,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphStoreError> {
        self.validate()?;
        task.validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
            .map_err(GraphStoreError::Admission)?;
        if task.state != TaskState::Expired {
            return Err(GraphStoreError::InvalidTransition {
                reason: "reclaim requires an expired task".to_string(),
            });
        }
        if self.prior_idempotency_key != task.request.idempotency_key
            || self.request.task_id != task.request.task_id
            || self.request.kind != task.request.kind
            || self.request.target != task.request.target
            || self.request.role != task.request.role
            || self.request.evidence_scope != task.request.evidence_scope
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "reclaim does not bind the exact expired task scope".to_string(),
            });
        }
        if self.request.requested_at > self.reclaimed_at
            || task
                .terminal_history
                .last()
                .is_none_or(|proof| proof.completed_at > self.reclaimed_at)
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "reclaim time precedes its request or expired-task proof".to_string(),
            });
        }
        if task.attempts >= limits.max_task_retries {
            return Err(GraphStoreError::ResourceLimit {
                resource: "task.retries".to_string(),
                limit: usize::from(limits.max_task_retries),
            });
        }
        if self.duration_ms > limits.max_task_lease_ms {
            return Err(GraphStoreError::InvalidLease {
                reason: "reclaim duration exceeds the graph lease limit".to_string(),
            });
        }
        let Some(witness) = self.authority_witness.as_ref() else {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "durable task reclaim requires scheduler authority".to_string(),
                },
            ));
        };
        if &witness.producer_identity != authority {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "reclaim witness does not match the configured store authority"
                        .to_string(),
                },
            ));
        }
        witness
            .validate(&self.canonical_bytes_without_witness()?)
            .map_err(GraphStoreError::Admission)
    }
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskFailureMaterial<'a> {
    task_id: &'a TaskId,
    idempotency_key: &'a IdempotencyKey,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    failure: &'a TaskFailure,
    capability: &'a TaskCapabilityProof,
    terminal_scope: &'a str,
}

/// A signed failure publication bound to one exact claim, capability, lease,
/// and fence. The structural constructor intentionally leaves the witness
/// absent so an assembled request cannot be mistaken for durable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskFailureEnvelope {
    pub task_id: TaskId,
    pub idempotency_key: IdempotencyKey,
    pub lease_id: LeaseId,
    pub fencing_token: FencingToken,
    pub failure: TaskFailure,
    pub capability: TaskCapabilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_witness: Option<EvidenceWitness>,
}

impl TaskFailureEnvelope {
    pub fn new(
        task_id: TaskId,
        idempotency_key: IdempotencyKey,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        failure: TaskFailure,
        capability: TaskCapabilityProof,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            task_id,
            idempotency_key,
            lease_id,
            fencing_token,
            failure,
            capability,
            terminal_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn signed_with(
        mut self,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let signer_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        if signer_identity != self.failure.failed_by || signer_identity != self.capability.claimant
        {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "failure signer does not match the claimant actor".to_string(),
                },
            ));
        }
        let scoped_agent_id = scoped_agent_id.into();
        if scoped_agent_id.trim().is_empty() || scoped_agent_id.len() > 128 {
            return Err(GraphStoreError::InvalidState {
                reason: "failure terminal scope is invalid".to_string(),
            });
        }
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.terminal_witness = Some(
            EvidenceWitness::new(signer, self.capability.role, scoped_agent_id, &bytes)
                .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, terminal_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskFailureMaterial {
            task_id: &self.task_id,
            idempotency_key: &self.idempotency_key,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            failure: &self.failure,
            capability: &self.capability,
            terminal_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let terminal_scope = self
            .terminal_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(terminal_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        self.failure.validate()?;
        if self.capability.task_id != self.task_id {
            return Err(GraphStoreError::InvalidTransition {
                reason: "failure capability task does not match envelope task".to_string(),
            });
        }
        if self.capability.claimant != self.failure.failed_by {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "failure actor and capability claimant must match".to_string(),
                },
            ));
        }
        if let Some(witness) = &self.terminal_witness {
            if witness.producer_identity != self.failure.failed_by
                || witness.producer_role != self.capability.role
            {
                return Err(GraphStoreError::Admission(
                    GraphAdmissionError::InvalidWitness {
                        reason: "failure witness does not bind actor and capability role"
                            .to_string(),
                    },
                ));
            }
            witness
                .validate(&self.canonical_bytes_without_witness()?)
                .map_err(GraphStoreError::Admission)?;
        }
        Ok(())
    }

    fn validate_for_task(
        &self,
        task: &TaskRecord,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphStoreError> {
        self.validate()?;
        task.validate_with_limits(limits.max_task_lease_ms, limits.max_task_retries)
            .map_err(GraphStoreError::Admission)?;
        if task.state != TaskState::Claimed || task.completion.is_some() {
            return Err(GraphStoreError::InvalidTransition {
                reason: "failure envelope requires an active claimed task".to_string(),
            });
        }
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidTransition {
                reason: "failure envelope requires the task's active lease".to_string(),
            })?;
        self.capability
            .validate_for_claim(&task.request)
            .map_err(GraphStoreError::Admission)?;
        if self.task_id != task.request.task_id
            || self.idempotency_key != task.request.idempotency_key
            || self.lease_id != lease.lease_id
            || self.fencing_token != lease.fencing_token
            || self.failure.failed_by != lease.holder
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "failure envelope does not bind the active task lease".to_string(),
            });
        }
        if self.failure.failed_at < lease.issued_at || self.failure.failed_at > lease.expires_at {
            return Err(GraphStoreError::InvalidTransition {
                reason: "failure time must fall within the active lease".to_string(),
            });
        }
        let Some(witness) = self.terminal_witness.as_ref() else {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidWitness {
                    reason: "durable task failure requires a signed terminal witness".to_string(),
                },
            ));
        };
        witness
            .validate(&self.canonical_bytes_without_witness()?)
            .map_err(GraphStoreError::Admission)
    }
}

/// Terminal transition selected by the claimant and explicitly admitted by
/// the scheduler authority. The discriminant is signed so one clock grant
/// cannot be replayed across completion and failure paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskTerminalOperationKind {
    Complete,
    Fail,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskTerminalClockMaterial<'a> {
    task_id: &'a TaskId,
    idempotency_key: &'a IdempotencyKey,
    expected_generation: u64,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    observed_at: GraphLogicalTime,
    operation_kind: TaskTerminalOperationKind,
    operation_digest: &'a str,
    authority_scope: &'a str,
}

/// Scheduler-signed clock grant for one exact terminal operation. This keeps
/// the durable logical high-water mark under coordinator authority while the
/// claimant's terminal envelope independently proves the completion/failure
/// payload. Binding the canonical terminal-envelope digest prevents a valid
/// clock grant from being reused for a different terminal publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskTerminalClockEnvelope {
    pub task_id: TaskId,
    pub idempotency_key: IdempotencyKey,
    pub expected_generation: u64,
    pub lease_id: LeaseId,
    pub fencing_token: FencingToken,
    pub observed_at: GraphLogicalTime,
    pub operation_kind: TaskTerminalOperationKind,
    pub operation_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_witness: Option<EvidenceWitness>,
}

impl TaskTerminalClockEnvelope {
    pub fn for_completion(
        expected_generation: u64,
        observed_at: GraphLogicalTime,
        envelope: &TaskTerminalEnvelope,
    ) -> Result<Self, GraphStoreError> {
        Self::new(
            envelope.task_id.clone(),
            envelope.idempotency_key.clone(),
            expected_generation,
            envelope.lease_id.clone(),
            envelope.fencing_token,
            observed_at,
            TaskTerminalOperationKind::Complete,
            terminal_operation_digest(envelope)?,
        )
    }

    pub fn for_failure(
        expected_generation: u64,
        observed_at: GraphLogicalTime,
        envelope: &TaskFailureEnvelope,
    ) -> Result<Self, GraphStoreError> {
        Self::new(
            envelope.task_id.clone(),
            envelope.idempotency_key.clone(),
            expected_generation,
            envelope.lease_id.clone(),
            envelope.fencing_token,
            observed_at,
            TaskTerminalOperationKind::Fail,
            terminal_operation_digest(envelope)?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        task_id: TaskId,
        idempotency_key: IdempotencyKey,
        expected_generation: u64,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        observed_at: GraphLogicalTime,
        operation_kind: TaskTerminalOperationKind,
        operation_digest: String,
    ) -> Result<Self, GraphStoreError> {
        let envelope = Self {
            task_id,
            idempotency_key,
            expected_generation,
            lease_id,
            fencing_token,
            observed_at,
            operation_kind,
            operation_digest,
            authority_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn authorized_by(
        mut self,
        authority: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphStoreError> {
        let scoped_agent_id = scoped_agent_id.into();
        validate_authority_scope("terminal clock", &scoped_agent_id)?;
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.authority_witness = Some(
            EvidenceWitness::new(
                authority,
                swarm_core::hypothesis_graph::GraphProducerRole::Planner,
                scoped_agent_id,
                &bytes,
            )
            .map_err(GraphStoreError::Admission)?,
        );
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_for_scope(&self, authority_scope: &str) -> Result<Vec<u8>, GraphStoreError> {
        canonical_json_bytes(&TaskTerminalClockMaterial {
            task_id: &self.task_id,
            idempotency_key: &self.idempotency_key,
            expected_generation: self.expected_generation,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            observed_at: self.observed_at,
            operation_kind: self.operation_kind,
            operation_digest: &self.operation_digest,
            authority_scope,
        })
        .map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphStoreError> {
        let authority_scope = self
            .authority_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(authority_scope)
    }

    fn validate(&self) -> Result<(), GraphStoreError> {
        self.observed_at
            .validate()
            .map_err(GraphStoreError::Admission)?;
        if self.expected_generation == 0 {
            return Err(GraphStoreError::InvalidTransition {
                reason: "terminal clock generation must be positive".to_string(),
            });
        }
        if self.operation_digest.len() != 64
            || !self
                .operation_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GraphStoreError::InvalidState {
                reason: "terminal operation digest must be lowercase SHA-256 hex".to_string(),
            });
        }
        validate_optional_scheduler_witness(
            self.authority_witness.as_ref(),
            &self.canonical_bytes_without_witness()?,
        )
    }

    fn validate_for_operation<T: Serialize>(
        &self,
        task: &TaskRecord,
        expected_generation: u64,
        operation_kind: TaskTerminalOperationKind,
        operation: &T,
        authority: &AgentId,
    ) -> Result<(), GraphStoreError> {
        self.validate()?;
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidTransition {
                reason: "terminal clock requires the task's active lease".to_string(),
            })?;
        if self.task_id != task.request.task_id
            || self.idempotency_key != task.request.idempotency_key
            || self.expected_generation != expected_generation
            || self.lease_id != lease.lease_id
            || self.fencing_token != lease.fencing_token
            || self.operation_kind != operation_kind
            || self.operation_digest != terminal_operation_digest(operation)?
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "terminal clock does not bind the exact task operation".to_string(),
            });
        }
        require_configured_scheduler_witness(
            self.authority_witness.as_ref(),
            authority,
            &self.canonical_bytes_without_witness()?,
            "durable terminal operation requires scheduler clock authority",
        )
    }
}

fn terminal_operation_digest<T: Serialize>(operation: &T) -> Result<String, GraphStoreError> {
    let bytes =
        canonical_json_bytes(operation).map_err(|error| GraphStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    Ok(sha256_hex(&bytes))
}

/// Validate a signed failure publication at the durable task-store boundary.
pub fn validate_task_failure_envelope(
    task: &TaskRecord,
    envelope: &TaskFailureEnvelope,
    limits: &GraphResourceLimits,
) -> Result<(), GraphStoreError> {
    envelope.validate_for_task(task, limits)
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

    fn validate(&self) -> Result<(), GraphStoreError> {
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
        envelope: GraphCasEnvelope,
    ) -> Result<GraphStoreSnapshot, GraphStoreError>;
    fn create_task(
        &self,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError>;
    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError>;
    fn claim_task(&self, envelope: TaskClaimEnvelope) -> Result<TaskClaimResult, GraphStoreError>;
    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskClaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError>;
    fn renew_task(
        &self,
        envelope: TaskRenewalEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError>;
    fn complete_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskTerminalEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError>;
    fn fail_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskFailureEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError>;
    fn expire_task(
        &self,
        envelope: TaskExpiryEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError>;
    fn reclaim_task(
        &self,
        envelope: TaskReclaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError>;
}

pub trait TaskStore: HypothesisGraphStore {}

impl<T> TaskStore for T where T: HypothesisGraphStore + ?Sized {}

#[derive(Debug, Clone)]
pub struct MemoryHypothesisGraphStore {
    inner: Arc<RwLock<SignedGraphStoreState>>,
    signer: Keypair,
    limits: GraphResourceLimits,
    graph_id: GraphId,
    signer_id: AgentId,
}

impl MemoryHypothesisGraphStore {
    pub fn new(graph: HypothesisGraph, signer: Keypair) -> Result<Self, GraphStoreError> {
        let limits = graph.limits.clone();
        let graph_id = graph.graph_id.clone();
        let signer_id = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let state = GraphStoreState::new(graph)?;
        let signed = sign_state(state, &signer, &limits)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(signed)),
            signer,
            limits,
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

    fn read_signed(&self) -> Result<SignedGraphStoreState, GraphStoreError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| GraphStoreError::PoisonedLock)?;
        verify_state(&guard, &self.graph_id, &self.signer_id, &self.limits)?;
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
        verify_state(&guard, &self.graph_id, &self.signer_id, &self.limits)?;
        let (next, value) = transition(&guard, expected, &self.signer, &self.limits, operation)?;
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
}

impl HypothesisGraphStore for MemoryHypothesisGraphStore {
    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.read_signed()?.snapshot()
    }

    fn compare_and_swap(
        &self,
        envelope: GraphCasEnvelope,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let expected = envelope.expected.clone();
        let (snapshot, _) = self.mutate(Some(&expected), |current| {
            graph_cas_op(
                current,
                envelope,
                &self.graph_id,
                &self.signer_id,
                &self.limits,
            )
        })?;
        Ok(snapshot)
    }

    fn create_task(
        &self,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            create_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            create_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task(&self, envelope: TaskClaimEnvelope) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            claim_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskClaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            claim_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn renew_task(
        &self,
        envelope: TaskRenewalEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            renew_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn complete_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskTerminalEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            complete_task_op(
                state,
                expected_generation,
                clock,
                envelope,
                &self.signer_id,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn fail_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskFailureEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            fail_task_op(
                state,
                expected_generation,
                clock,
                envelope,
                &self.signer_id,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn expire_task(
        &self,
        envelope: TaskExpiryEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            expire_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task(
        &self,
        envelope: TaskReclaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reclaim_task_op(state, envelope, &self.signer_id, &self.limits)
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
    let mut missing = Vec::new();
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        match fs::symlink_metadata(candidate) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
                cursor = candidate
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty());
            }
            Err(source) => {
                return Err(GraphStoreError::Write {
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        }
    }
    fs::create_dir_all(path).map_err(|source| GraphStoreError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    for created in missing.iter().rev() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(created, fs::Permissions::from_mode(0o700)).map_err(|source| {
                GraphStoreError::Write {
                    path: created.clone(),
                    source,
                }
            })?;
        }
        File::open(created)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| GraphStoreError::Write {
                path: created.clone(),
                source,
            })?;
        let parent = durability_parent(created);
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| GraphStoreError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
    }
    ensure_private_store_root_mode(path)
}

fn durability_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
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
        let mode = u64::from(target_stat.st_mode & 0o7777);
        if mode != 0o600 {
            return Err(GraphStoreError::InsecurePermissions {
                path: path.to_path_buf(),
                expected: 0o600,
                observed: u32::try_from(mode).unwrap_or(u32::MAX),
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

    let target_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let mut allocated = None;
    for _ in 0..64 {
        let suffix = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let restart_nonce = uuid::Uuid::new_v4().simple();
        let temporary_name = CString::new(format!(
            ".{target_name}.tmp.{}.{restart_nonce}.{suffix}",
            std::process::id()
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
        if temporary_fd >= 0 {
            allocated = Some((temporary_name, temporary_fd));
            break;
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(GraphStoreError::Write {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let Some((temporary_name, temporary_fd)) = allocated else {
        return Err(GraphStoreError::InvalidState {
            reason: "could not allocate a restart-unique temporary JSON file".to_string(),
        });
    };
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
    graph_id: GraphId,
    signer_id: AgentId,
}

impl FileHypothesisGraphStore {
    pub fn new(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        Self::open_internal(path.as_ref(), Some(graph), signer)
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
        Self::open_internal(&path, None, signer)
    }

    fn open_internal(
        path: &Path,
        initial_graph: Option<HypothesisGraph>,
        signer: Keypair,
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
            let mut envelope: SignedGraphStoreState = lock.read_json(&state_path)?;
            let limits = envelope.state.graph.limits.clone();
            let graph_id = envelope.state.graph_id.clone();
            verify_state(&envelope, &graph_id, &signer_id, &limits)?;
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
                envelope = lock.read_json(&state_path)?;
                verify_state(&envelope, &graph_id, &signer_id, &limits)?;
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
        let mut envelope: SignedGraphStoreState = self.lock.read_json(&self.state_path)?;
        verify_state(&envelope, &self.graph_id, &self.signer_id, &self.limits)?;
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
            envelope = self.lock.read_json(&self.state_path)?;
            verify_state(&envelope, &self.graph_id, &self.signer_id, &self.limits)?;
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
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| GraphStoreError::PoisonedLock)?;
        let current = self.read_signed()?;
        let (next, value) = transition(&current, expected, &self.signer, &self.limits, operation)?;
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
}

impl HypothesisGraphStore for FileHypothesisGraphStore {
    fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.read_signed()?.snapshot()
    }

    fn compare_and_swap(
        &self,
        envelope: GraphCasEnvelope,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let expected = envelope.expected.clone();
        let (snapshot, _) = self.mutate(Some(&expected), |current| {
            graph_cas_op(
                current,
                envelope,
                &self.graph_id,
                &self.signer_id,
                &self.limits,
            )
        })?;
        Ok(snapshot)
    }

    fn create_task(
        &self,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            create_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            create_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task(&self, envelope: TaskClaimEnvelope) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            claim_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskClaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(Some(expected), |state| {
            claim_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn renew_task(
        &self,
        envelope: TaskRenewalEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            renew_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn complete_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskTerminalEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            complete_task_op(
                state,
                expected_generation,
                clock,
                envelope,
                &self.signer_id,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn fail_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskFailureEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            fail_task_op(
                state,
                expected_generation,
                clock,
                envelope,
                &self.signer_id,
                &self.limits,
            )
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn expire_task(
        &self,
        envelope: TaskExpiryEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            expire_task_op(state, envelope, &self.signer_id, &self.limits)
        })?;
        Ok(Self::result_from_marker(snapshot, marker))
    }

    fn reclaim_task(
        &self,
        envelope: TaskReclaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        let (snapshot, marker) = self.mutate(None, |state| {
            reclaim_task_op(state, envelope, &self.signer_id, &self.limits)
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

    pub fn local_files(
        path: impl AsRef<Path>,
        graph: HypothesisGraph,
        signer: Keypair,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self::LocalFiles(FileHypothesisGraphStore::new(
            path, graph, signer,
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
        envelope: GraphCasEnvelope,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        match self {
            Self::Memory(store) => store.compare_and_swap(envelope),
            Self::LocalFiles(store) => store.compare_and_swap(envelope),
        }
    }

    fn create_task(
        &self,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.create_task(envelope),
            Self::LocalFiles(store) => store.create_task(envelope),
        }
    }

    fn create_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskCreationEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.create_task_cas(expected, envelope),
            Self::LocalFiles(store) => store.create_task_cas(expected, envelope),
        }
    }

    fn claim_task(&self, envelope: TaskClaimEnvelope) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.claim_task(envelope),
            Self::LocalFiles(store) => store.claim_task(envelope),
        }
    }

    fn claim_task_cas(
        &self,
        expected: &GraphStoreRevision,
        envelope: TaskClaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.claim_task_cas(expected, envelope),
            Self::LocalFiles(store) => store.claim_task_cas(expected, envelope),
        }
    }

    fn renew_task(
        &self,
        envelope: TaskRenewalEnvelope,
    ) -> Result<TaskMutationResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.renew_task(envelope),
            Self::LocalFiles(store) => store.renew_task(envelope),
        }
    }

    fn complete_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskTerminalEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.complete_task(expected_generation, clock, envelope),
            Self::LocalFiles(store) => store.complete_task(expected_generation, clock, envelope),
        }
    }

    fn fail_task(
        &self,
        expected_generation: u64,
        clock: TaskTerminalClockEnvelope,
        envelope: TaskFailureEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.fail_task(expected_generation, clock, envelope),
            Self::LocalFiles(store) => store.fail_task(expected_generation, clock, envelope),
        }
    }

    fn expire_task(
        &self,
        envelope: TaskExpiryEnvelope,
    ) -> Result<TaskTerminalResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.expire_task(envelope),
            Self::LocalFiles(store) => store.expire_task(envelope),
        }
    }

    fn reclaim_task(
        &self,
        envelope: TaskReclaimEnvelope,
    ) -> Result<TaskClaimResult, GraphStoreError> {
        match self {
            Self::Memory(store) => store.reclaim_task(envelope),
            Self::LocalFiles(store) => store.reclaim_task(envelope),
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
        ActorNode, EvidenceId, EvidenceScope, EvidenceSourceFamily, GraphNode, GraphProducerRole,
        TaskCapabilityProof, TaskCompletion, TaskCompletionKind, TaskId, TaskKind, TaskTarget,
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

    fn capability_for_request(
        request: &TaskClaimRequest,
        claimant_byte: u8,
    ) -> TaskCapabilityProof {
        let claimant = signer(claimant_byte);
        TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant,
            format!("task-capability:{}", request.task_id),
        )
        .unwrap()
    }

    fn signed_creation_envelope(
        request: TaskClaimRequest,
        claimant_byte: u8,
        authority_byte: u8,
    ) -> TaskCreationEnvelope {
        let capability = capability_for_request(&request, claimant_byte);
        let task_id = request.task_id.clone();
        TaskCreationEnvelope::new(request, capability)
            .unwrap()
            .authorized_by(&signer(authority_byte), format!("task-create:{task_id}"))
            .unwrap()
    }

    fn signed_graph_cas_envelope(
        expected: GraphStoreRevision,
        state: GraphStoreState,
        authority_byte: u8,
    ) -> GraphCasEnvelope {
        GraphCasEnvelope::new(expected, state)
            .unwrap()
            .authorized_by(&signer(authority_byte), "graph-cas:test")
            .unwrap()
    }

    fn claim_envelope(
        request: TaskClaimRequest,
        claimed_at: GraphLogicalTime,
        duration_ms: u64,
        claimant_byte: u8,
    ) -> TaskClaimEnvelope {
        let capability = capability_for_request(&request, claimant_byte);
        TaskClaimEnvelope::new(request, claimed_at, duration_ms, capability).unwrap()
    }

    fn signed_claim_envelope(
        request: TaskClaimRequest,
        claimed_at: GraphLogicalTime,
        duration_ms: u64,
        claimant_byte: u8,
        authority_byte: u8,
    ) -> TaskClaimEnvelope {
        let task_id = request.task_id.clone();
        claim_envelope(request, claimed_at, duration_ms, claimant_byte)
            .authorized_by(&signer(authority_byte), format!("task-claim:{task_id}"))
            .unwrap()
    }

    fn signed_terminal_envelope(
        request: &TaskClaimRequest,
        lease: &TaskLease,
        completion: TaskCompletion,
        signer_byte: u8,
    ) -> TaskTerminalEnvelope {
        let claimant = signer(signer_byte);
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant,
            format!("task-capability:{}", request.task_id),
        )
        .unwrap();
        TaskTerminalEnvelope::new(
            request.task_id.clone(),
            request.idempotency_key.clone(),
            lease.lease_id.clone(),
            lease.fencing_token,
            completion,
            None,
            request.claimant.clone(),
            capability,
        )
        .unwrap()
        .signed_with(&claimant, format!("task-terminal:{}", request.task_id))
        .unwrap()
    }

    fn signed_failure_envelope(
        request: &TaskClaimRequest,
        lease: &TaskLease,
        failed_at: GraphLogicalTime,
        summary_digest: &str,
        signer_byte: u8,
    ) -> TaskFailureEnvelope {
        let claimant = signer(signer_byte);
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant,
            format!("task-capability:{}", request.task_id),
        )
        .unwrap();
        TaskFailureEnvelope::new(
            request.task_id.clone(),
            request.idempotency_key.clone(),
            lease.lease_id.clone(),
            lease.fencing_token,
            TaskFailure::new(request.claimant.clone(), failed_at, summary_digest).unwrap(),
            capability,
        )
        .unwrap()
        .signed_with(&claimant, format!("task-failure:{}", request.task_id))
        .unwrap()
    }

    fn signed_completion_clock(
        expected_generation: u64,
        observed_at: GraphLogicalTime,
        envelope: &TaskTerminalEnvelope,
        authority_byte: u8,
    ) -> TaskTerminalClockEnvelope {
        TaskTerminalClockEnvelope::for_completion(expected_generation, observed_at, envelope)
            .unwrap()
            .authorized_by(
                &signer(authority_byte),
                format!("task-terminal-clock:{}", envelope.task_id),
            )
            .unwrap()
    }

    fn signed_failure_clock(
        expected_generation: u64,
        observed_at: GraphLogicalTime,
        envelope: &TaskFailureEnvelope,
        authority_byte: u8,
    ) -> TaskTerminalClockEnvelope {
        TaskTerminalClockEnvelope::for_failure(expected_generation, observed_at, envelope)
            .unwrap()
            .authorized_by(
                &signer(authority_byte),
                format!("task-failure-clock:{}", envelope.task_id),
            )
            .unwrap()
    }

    fn signed_renewal_envelope(
        request: &TaskClaimRequest,
        lease: &TaskLease,
        expected_generation: u64,
        renewed_at: GraphLogicalTime,
        duration_ms: u64,
        signer_byte: u8,
        authority_byte: u8,
    ) -> TaskRenewalEnvelope {
        let claimant = signer(signer_byte);
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant,
            format!("task-capability:{}", request.task_id),
        )
        .unwrap();
        TaskRenewalEnvelope::new(
            request.task_id.clone(),
            request.idempotency_key.clone(),
            expected_generation,
            lease.lease_id.clone(),
            lease.fencing_token,
            renewed_at,
            duration_ms,
            capability,
        )
        .unwrap()
        .signed_with(&claimant, format!("task-renewal:{}", request.task_id))
        .unwrap()
        .authorized_by(
            &signer(authority_byte),
            format!("task-renewal-authority:{}", request.task_id),
        )
        .unwrap()
    }

    fn signed_expiry_envelope(
        request: &TaskClaimRequest,
        lease: &TaskLease,
        expected_generation: u64,
        observed_at: GraphLogicalTime,
        authority_byte: u8,
    ) -> TaskExpiryEnvelope {
        TaskExpiryEnvelope::new(
            request.task_id.clone(),
            request.idempotency_key.clone(),
            expected_generation,
            lease.lease_id.clone(),
            lease.fencing_token,
            observed_at,
        )
        .unwrap()
        .signed_with(
            &signer(authority_byte),
            format!("task-expiry:{}", request.task_id),
        )
        .unwrap()
    }

    fn reclaim_envelope(
        prior_request: &TaskClaimRequest,
        expected_generation: u64,
        request: TaskClaimRequest,
        reclaimed_at: GraphLogicalTime,
        duration_ms: u64,
        claimant_byte: u8,
    ) -> TaskReclaimEnvelope {
        let claimant = signer(claimant_byte);
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant,
            format!("task-capability:{}", request.task_id),
        )
        .unwrap();
        TaskReclaimEnvelope::new(
            prior_request.idempotency_key.clone(),
            expected_generation,
            request,
            reclaimed_at,
            duration_ms,
            capability,
        )
        .unwrap()
    }

    fn signed_reclaim_envelope(
        prior_request: &TaskClaimRequest,
        expected_generation: u64,
        request: TaskClaimRequest,
        reclaimed_at: GraphLogicalTime,
        duration_ms: u64,
        claimant_byte: u8,
        authority_byte: u8,
    ) -> TaskReclaimEnvelope {
        let task_id = request.task_id.clone();
        reclaim_envelope(
            prior_request,
            expected_generation,
            request,
            reclaimed_at,
            duration_ms,
            claimant_byte,
        )
        .authorized_by(&signer(authority_byte), format!("task-reclaim:{task_id}"))
        .unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("swarm-spine-{name}-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn graph_atomic_write_ignores_stale_temps_from_a_prior_process_epoch() {
        let path = temp_dir("stale-atomic-temps");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(91)).unwrap();
        let first_counter = TEMP_FILE_COUNTER.load(std::sync::atomic::Ordering::Relaxed);
        for counter in first_counter..first_counter.saturating_add(64) {
            let stale = path.join(format!(
                ".{GRAPH_STORE_STATE_FILE}.tmp.{}.{counter}",
                std::process::id()
            ));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(stale)
                .unwrap();
        }

        store
            .create_task(signed_creation_envelope(
                request(92, "stale-temp-restart"),
                92,
                91,
            ))
            .unwrap();
        assert!(
            store
                .snapshot()
                .unwrap()
                .state
                .task("task:stale-temp-restart")
                .is_some()
        );
        drop(store);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn relative_top_level_store_root_syncs_the_working_directory() {
        assert_eq!(durability_parent(Path::new("graph-state")), Path::new("."));
        assert_eq!(
            durability_parent(Path::new("state/graph")),
            Path::new("state")
        );
    }

    #[test]
    fn operation_log_is_idempotent_and_fenced_across_reclaim() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(7)).unwrap();
        let first = store.claim_task(signed_claim_envelope(
            request(1, "one"),
            GraphLogicalTime::new(100),
            10,
            1,
            7,
        ));
        let first = first.unwrap();
        let duplicate = store
            .claim_task(signed_claim_envelope(
                request(1, "one"),
                GraphLogicalTime::new(100),
                10,
                1,
                7,
            ))
            .unwrap();
        assert!(duplicate.idempotent);
        assert_eq!(first.lease, duplicate.lease);
        let old = first.lease.clone().unwrap();
        let expired = store
            .expire_task(signed_expiry_envelope(
                &first.task.request,
                &old,
                first.task_generation,
                GraphLogicalTime::new(110),
                7,
            ))
            .unwrap();
        assert_eq!(expired.task.state, TaskState::Expired);
        assert!(
            FencingToken::new(store.snapshot().unwrap().state.fencing_counter) > old.fencing_token
        );
        let reclaimed = store
            .reclaim_task(signed_reclaim_envelope(
                &first.task.request,
                expired.task_generation,
                request(2, "one"),
                GraphLogicalTime::new(111),
                20,
                2,
                7,
            ))
            .unwrap();
        assert!(reclaimed.lease.as_ref().unwrap().fencing_token > old.fencing_token);
        let stale_envelope = signed_terminal_envelope(
            &first.task.request,
            &old,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                old.holder.clone(),
                GraphLogicalTime::new(112),
                [EvidenceId::new("evidence:one")],
                "summary:old",
            )
            .unwrap(),
            1,
        );
        let stale_clock =
            signed_completion_clock(2, GraphLogicalTime::new(112), &stale_envelope, 7);
        let stale = store.complete_task(2, stale_clock, stale_envelope);
        assert!(matches!(
            stale,
            Err(GraphStoreError::StaleTaskGeneration { .. })
                | Err(GraphStoreError::StaleLease { .. })
                | Err(GraphStoreError::StaleFence { .. })
        ));
        let current = reclaimed.lease.clone().unwrap();
        let current_envelope = signed_terminal_envelope(
            &reclaimed.task.request,
            &current,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                current.holder.clone(),
                GraphLogicalTime::new(112),
                [EvidenceId::new("evidence:one")],
                "summary:new",
            )
            .unwrap(),
            2,
        );
        let done = store
            .complete_task(
                reclaimed.revision.generation,
                signed_completion_clock(
                    reclaimed.revision.generation,
                    GraphLogicalTime::new(112),
                    &current_envelope,
                    7,
                ),
                current_envelope,
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
            .claim_task(signed_claim_envelope(
                first_request,
                GraphLogicalTime::new(100),
                20,
                1,
                13,
            ))
            .unwrap();
        let retry = store
            .claim_task(signed_claim_envelope(
                request_at(1, "retry", GraphLogicalTime::new(105)),
                GraphLogicalTime::new(105),
                20,
                1,
                13,
            ))
            .unwrap();
        assert!(retry.idempotent);
        assert_eq!(retry.revision, first.revision);
        assert_eq!(retry.task, first.task);
        assert_eq!(retry.task.request.requested_at, GraphLogicalTime::new(100));
    }

    #[test]
    fn creation_and_claim_require_configured_scheduler_clock_authority() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(40)).unwrap();
        let creation_request = request(41, "authorized-creation");
        let creation_capability = capability_for_request(&creation_request, 41);
        let claimant_only_creation =
            TaskCreationEnvelope::new(creation_request.clone(), creation_capability).unwrap();
        let before_creation = store.snapshot().unwrap();
        assert!(matches!(
            store.create_task(claimant_only_creation),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before_creation);

        let foreign_creation = signed_creation_envelope(creation_request.clone(), 41, 43);
        assert!(matches!(
            store.create_task(foreign_creation),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before_creation);

        let created = store
            .create_task(signed_creation_envelope(creation_request, 41, 40))
            .unwrap();
        assert_eq!(created.task.state, TaskState::Pending);
        assert_eq!(
            store.snapshot().unwrap().state.logical_time_high_water,
            GraphLogicalTime::new(100)
        );

        let claim_request = request(42, "authorized-claim");
        let claimant_only =
            claim_envelope(claim_request.clone(), GraphLogicalTime::new(100), 20, 42);
        let signed = signed_claim_envelope(
            claim_request.clone(),
            GraphLogicalTime::new(100),
            20,
            42,
            40,
        );
        let before_claim = store.snapshot().unwrap();
        assert!(matches!(
            store.claim_task(claimant_only),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before_claim);

        let foreign = signed_claim_envelope(claim_request, GraphLogicalTime::new(100), 20, 42, 43);
        assert!(matches!(
            store.claim_task(foreign),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before_claim);

        let mut poisoned_clock = signed.clone();
        poisoned_clock.claimed_at = GraphLogicalTime::new(i64::MAX);
        assert!(matches!(
            store.claim_task(poisoned_clock),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before_claim);

        let claimed = store.claim_task(signed).unwrap();
        assert_eq!(claimed.task.state, TaskState::Claimed);
        assert_eq!(
            store.snapshot().unwrap().state.logical_time_high_water,
            GraphLogicalTime::new(100)
        );
    }

    #[test]
    fn generic_cas_rejects_stale_terminal_task_resurrection() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(44)).unwrap();
        let claimed = store
            .claim_task(signed_claim_envelope(
                request(45, "resurrection"),
                GraphLogicalTime::new(100),
                20,
                45,
                44,
            ))
            .unwrap();
        let stale = store.snapshot().unwrap();
        let lease = claimed.lease.clone().unwrap();
        let envelope = signed_terminal_envelope(
            &claimed.task.request,
            &lease,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                lease.holder.clone(),
                GraphLogicalTime::new(110),
                [EvidenceId::new("evidence:resurrection")],
                "summary:resurrection",
            )
            .unwrap(),
            45,
        );
        store
            .complete_task(
                claimed.task_generation,
                signed_completion_clock(
                    claimed.task_generation,
                    GraphLogicalTime::new(110),
                    &envelope,
                    44,
                ),
                envelope,
            )
            .unwrap();
        let current = store.snapshot().unwrap();
        let mut candidate = stale.state;
        candidate.generation = current.state.generation;
        candidate.predecessor_digest = current.state.predecessor_digest.clone();
        let error = store
            .compare_and_swap(signed_graph_cas_envelope(
                current.revision.clone(),
                candidate,
                44,
            ))
            .unwrap_err();
        assert!(matches!(error, GraphStoreError::InvalidState { .. }));
        assert_eq!(store.snapshot().unwrap().state.tasks, current.state.tasks);
    }

    #[test]
    fn terminal_transition_barrier_rejects_expired_injected_clock() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(14)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(1, "completion-barrier"),
                GraphLogicalTime::new(100),
                10,
                1,
                14,
            ))
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
        let completion_envelope =
            signed_terminal_envelope(&claim.task.request, &lease, completion, 1);
        assert!(matches!(
            store.complete_task(
                claim.task_generation,
                signed_completion_clock(
                    claim.task_generation,
                    GraphLogicalTime::new(110),
                    &completion_envelope,
                    14,
                ),
                completion_envelope,
            ),
            Err(GraphStoreError::LeaseExpired { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let failure_request = request(2, "failure-barrier");
        let failure_claim = store
            .claim_task(signed_claim_envelope(
                failure_request.clone(),
                GraphLogicalTime::new(100),
                10,
                2,
                14,
            ))
            .unwrap();
        let failure_lease = failure_claim.lease.clone().unwrap();
        let before_failure = store.snapshot().unwrap();
        let failure = signed_failure_envelope(
            &failure_request,
            &failure_lease,
            GraphLogicalTime::new(109),
            "summary:failure-barrier",
            2,
        );
        assert!(matches!(
            store.fail_task(
                failure_claim.task_generation,
                signed_failure_clock(
                    failure_claim.task_generation,
                    GraphLogicalTime::new(110),
                    &failure,
                    14,
                ),
                failure,
            ),
            Err(GraphStoreError::LeaseExpired { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before_failure);
    }

    #[test]
    fn terminal_clock_requires_exact_scheduler_authority_and_payload_binding() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(31)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(32, "terminal-clock-authority"),
                GraphLogicalTime::new(100),
                20,
                32,
                31,
            ))
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let terminal = signed_terminal_envelope(
            &claim.task.request,
            &lease,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                lease.holder.clone(),
                GraphLogicalTime::new(110),
                [EvidenceId::new("evidence:terminal-clock-authority")],
                "summary:terminal-clock-authority",
            )
            .unwrap(),
            32,
        );
        let before = store.snapshot().unwrap();

        let unsigned = TaskTerminalClockEnvelope::for_completion(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &terminal,
        )
        .unwrap();
        assert!(matches!(
            store.complete_task(claim.task_generation, unsigned, terminal.clone()),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let foreign = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &terminal,
            33,
        );
        assert!(matches!(
            store.complete_task(claim.task_generation, foreign, terminal.clone()),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut tampered_clock = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &terminal,
            31,
        );
        tampered_clock.observed_at = GraphLogicalTime::new(119);
        assert!(matches!(
            store.complete_task(claim.task_generation, tampered_clock, terminal.clone()),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut wrong_operation = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &terminal,
            31,
        );
        wrong_operation.operation_kind = TaskTerminalOperationKind::Fail;
        assert!(matches!(
            store.complete_task(claim.task_generation, wrong_operation, terminal.clone()),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let failure = signed_failure_envelope(
            &claim.task.request,
            &lease,
            GraphLogicalTime::new(110),
            "summary:terminal-clock-authority",
            32,
        );
        let completion_only = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &terminal,
            31,
        );
        assert!(matches!(
            store.fail_task(claim.task_generation, completion_only, failure),
            Err(GraphStoreError::InvalidTransition { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let valid = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &terminal,
            31,
        );
        let completed = store
            .complete_task(claim.task_generation, valid, terminal)
            .unwrap();
        assert_eq!(completed.task.state, TaskState::Completed);
        assert_eq!(
            store.snapshot().unwrap().state.logical_time_high_water,
            GraphLogicalTime::new(110)
        );
    }

    #[test]
    fn durable_completion_requires_claimant_signature_and_compatible_kind() {
        let path = temp_dir("signed-terminal-completion");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(20)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(21, "signed-terminal"),
                GraphLogicalTime::new(100),
                20,
                21,
                20,
            ))
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let claimant = signer(21);
        let capability = TaskCapabilityProof::signed_with(
            claim.task.request.task_id.clone(),
            claim.task.request.claimant.clone(),
            claim.task.request.role,
            claim.task.request.kind,
            claim.task.request.canonical_digest().unwrap(),
            &claimant,
            "task-capability:signed-terminal",
        )
        .unwrap();
        let completion = TaskCompletion::new(
            TaskCompletionKind::EvidenceAdded,
            lease.holder.clone(),
            GraphLogicalTime::new(110),
            [EvidenceId::new("evidence:signed-terminal")],
            "summary:signed-terminal",
        )
        .unwrap();
        let unsigned = TaskTerminalEnvelope::new(
            claim.task.request.task_id.clone(),
            claim.task.request.idempotency_key.clone(),
            lease.lease_id.clone(),
            lease.fencing_token,
            completion,
            None,
            lease.holder.clone(),
            capability,
        )
        .unwrap();
        let before = store.snapshot().unwrap();
        let unsigned_clock = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &unsigned,
            20,
        );
        assert!(matches!(
            store.complete_task(claim.task_generation, unsigned_clock, unsigned),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut wrong_kind = signed_terminal_envelope(
            &claim.task.request,
            &lease,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                lease.holder.clone(),
                GraphLogicalTime::new(110),
                [EvidenceId::new("evidence:signed-terminal")],
                "summary:signed-terminal",
            )
            .unwrap(),
            21,
        );
        wrong_kind.completion.kind = TaskCompletionKind::EdgeChallenged;
        let wrong_kind_clock = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &wrong_kind,
            20,
        );
        assert!(matches!(
            store.complete_task(claim.task_generation, wrong_kind_clock, wrong_kind),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidTransition { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let valid = signed_terminal_envelope(
            &claim.task.request,
            &lease,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                lease.holder.clone(),
                GraphLogicalTime::new(110),
                [EvidenceId::new("evidence:signed-terminal")],
                "summary:signed-terminal",
            )
            .unwrap(),
            21,
        );
        let valid_clock = signed_completion_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &valid,
            20,
        );
        assert_eq!(
            store
                .complete_task(claim.task_generation, valid_clock, valid)
                .unwrap()
                .task
                .state,
            TaskState::Completed
        );
        drop(store);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn durable_failure_requires_claimant_signature_and_binds_exact_failure() {
        let path = temp_dir("signed-terminal-failure");
        let store = FileHypothesisGraphStore::new(&path, graph(), signer(22)).unwrap();
        let request = request(23, "signed-failure");
        let claim = store
            .claim_task(signed_claim_envelope(
                request.clone(),
                GraphLogicalTime::new(100),
                20,
                23,
                22,
            ))
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let claimant = signer(23);
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant,
            "task-capability:signed-failure",
        )
        .unwrap();
        let unsigned = TaskFailureEnvelope::new(
            request.task_id.clone(),
            request.idempotency_key.clone(),
            lease.lease_id.clone(),
            lease.fencing_token,
            TaskFailure::new(
                request.claimant.clone(),
                GraphLogicalTime::new(110),
                "summary:signed-failure",
            )
            .unwrap(),
            capability,
        )
        .unwrap();
        let before = store.snapshot().unwrap();
        let unsigned_clock = signed_failure_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &unsigned,
            22,
        );
        assert!(matches!(
            store.fail_task(claim.task_generation, unsigned_clock, unsigned.clone(),),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);
        assert!(matches!(
            unsigned.signed_with(&signer(24), "task-failure:signed-failure"),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));

        let mut tampered = signed_failure_envelope(
            &request,
            &lease,
            GraphLogicalTime::new(110),
            "summary:signed-failure",
            23,
        );
        tampered.failure.summary_digest = "summary:attacker-selected".to_string();
        let tampered_clock = signed_failure_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &tampered,
            22,
        );
        assert!(matches!(
            store.fail_task(claim.task_generation, tampered_clock, tampered,),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let valid = signed_failure_envelope(
            &request,
            &lease,
            GraphLogicalTime::new(110),
            "summary:signed-failure",
            23,
        );
        let valid_clock = signed_failure_clock(
            claim.task_generation,
            GraphLogicalTime::new(110),
            &valid,
            22,
        );
        let failed = store
            .fail_task(claim.task_generation, valid_clock, valid)
            .unwrap();
        assert_eq!(failed.task.state, TaskState::Failed);
        assert_eq!(
            failed
                .task
                .terminal_history
                .last()
                .unwrap()
                .failure_summary_digest,
            Some("summary:signed-failure".to_string())
        );
        drop(store);
        let reopened = FileHypothesisGraphStore::open_with_signer(&path, signer(22)).unwrap();
        assert_eq!(
            reopened.snapshot().unwrap().state.tasks[&TaskId::new("task:signed-failure")]
                .task
                .terminal_history
                .last()
                .unwrap()
                .failure_summary_digest,
            Some("summary:signed-failure".to_string())
        );
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn stale_generation_cas_never_mutates_state() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(8)).unwrap();
        let before = store.snapshot().unwrap();
        let mut changed = before.state.clone();
        changed
            .graph
            .admit_node(GraphNode::Actor(
                ActorNode::new("actor:cas", "CAS actor").unwrap(),
            ))
            .unwrap();
        let committed = store
            .compare_and_swap(signed_graph_cas_envelope(
                before.revision.clone(),
                changed,
                8,
            ))
            .unwrap();
        let stale = store.compare_and_swap(signed_graph_cas_envelope(
            before.revision.clone(),
            before.state,
            8,
        ));
        assert!(matches!(
            stale,
            Err(GraphStoreError::StalePredecessor { .. })
        ));
        assert_eq!(store.snapshot().unwrap().revision, committed.revision);
    }

    #[test]
    fn cas_rejects_store_owned_counter_changes_without_mutation() {
        fn assert_rejected(store: &dyn HypothesisGraphStore, authority_byte: u8) {
            store
                .claim_task(signed_claim_envelope(
                    request(1, "cas-counters"),
                    GraphLogicalTime::new(100),
                    20,
                    1,
                    authority_byte,
                ))
                .unwrap();
            let before = store.snapshot().unwrap();

            for fencing_counter in [before.state.fencing_counter.saturating_sub(1), u64::MAX] {
                let mut candidate = before.state.clone();
                candidate.graph.version = candidate.graph.version.saturating_add(1);
                candidate.fencing_counter = fencing_counter;
                assert!(matches!(
                    store.compare_and_swap(signed_graph_cas_envelope(
                        before.revision.clone(),
                        candidate,
                        authority_byte,
                    )),
                    Err(GraphStoreError::InvalidState { reason })
                        if reason.contains("store-owned fencing counter")
                ));
                assert_eq!(store.snapshot().unwrap(), before);
            }

            let mut future_clock = before.state.clone();
            future_clock.graph.version = future_clock.graph.version.saturating_add(1);
            future_clock.logical_time_high_water = GraphLogicalTime::new(1_000_000);
            assert!(matches!(
                store.compare_and_swap(signed_graph_cas_envelope(
                    before.revision.clone(),
                    future_clock,
                    authority_byte,
                )),
                Err(GraphStoreError::InvalidState { reason })
                    if reason.contains("store-owned logical time high-water")
            ));
            assert_eq!(store.snapshot().unwrap(), before);
        }

        let store = MemoryHypothesisGraphStore::new(graph(), signer(18)).unwrap();
        assert_rejected(&store, 18);

        let path = temp_dir("cas-store-owned-counters");
        let file = FileHypothesisGraphStore::new(&path, graph(), signer(19)).unwrap();
        assert_rejected(&file, 19);
        drop(file);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn generic_cas_still_updates_graph_without_changing_store_owned_counters() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(20)).unwrap();
        store
            .claim_task(signed_claim_envelope(
                request(1, "cas-graph-only"),
                GraphLogicalTime::new(100),
                20,
                1,
                20,
            ))
            .unwrap();
        let before = store.snapshot().unwrap();
        let mut candidate = before.state.clone();
        candidate
            .graph
            .admit_node(GraphNode::Actor(
                ActorNode::new("actor:graph-only", "Graph only actor").unwrap(),
            ))
            .unwrap();
        let committed = store
            .compare_and_swap(signed_graph_cas_envelope(
                before.revision.clone(),
                candidate,
                20,
            ))
            .unwrap();
        assert_eq!(
            committed.state.fencing_counter,
            before.state.fencing_counter
        );
        assert_eq!(
            committed.state.logical_time_high_water,
            before.state.logical_time_high_water
        );
        assert_eq!(
            committed.state.graph.version,
            before.state.graph.version.saturating_add(1)
        );
    }

    #[test]
    fn graph_cas_requires_authority_and_rejects_deletion_and_version_injection() {
        fn assert_rejected(store: &dyn HypothesisGraphStore, authority_byte: u8) {
            let baseline = store.snapshot().unwrap();
            let mut addition = baseline.state.clone();
            addition
                .graph
                .admit_node(GraphNode::Actor(
                    ActorNode::new("actor:cas-guard", "CAS guard actor").unwrap(),
                ))
                .unwrap();

            let unsigned =
                GraphCasEnvelope::new(baseline.revision.clone(), addition.clone()).unwrap();
            assert!(matches!(
                store.compare_and_swap(unsigned),
                Err(GraphStoreError::Admission(
                    swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
                ))
            ));
            assert_eq!(store.snapshot().unwrap(), baseline);

            assert!(matches!(
                store.compare_and_swap(signed_graph_cas_envelope(
                    baseline.revision.clone(),
                    addition.clone(),
                    authority_byte.saturating_add(1),
                )),
                Err(GraphStoreError::Admission(
                    swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
                ))
            ));
            assert_eq!(store.snapshot().unwrap(), baseline);

            let appended = store
                .compare_and_swap(signed_graph_cas_envelope(
                    baseline.revision,
                    addition,
                    authority_byte,
                ))
                .unwrap();
            assert_eq!(appended.state.graph.nodes.len(), 1);

            let mut deletion = appended.state.clone();
            deletion.graph = graph();
            assert!(matches!(
                store.compare_and_swap(signed_graph_cas_envelope(
                    appended.revision.clone(),
                    deletion,
                    authority_byte,
                )),
                Err(GraphStoreError::InvalidState { reason })
                    if reason.contains("cannot delete or rewrite existing nodes")
            ));
            assert_eq!(store.snapshot().unwrap(), appended);

            let mut exhausted = appended.state.clone();
            exhausted.graph.version = u64::MAX;
            assert!(matches!(
                store.compare_and_swap(signed_graph_cas_envelope(
                    appended.revision.clone(),
                    exhausted,
                    authority_byte,
                )),
                Err(GraphStoreError::InvalidState { reason })
                    if reason.contains("version must advance exactly once")
            ));
            assert_eq!(store.snapshot().unwrap(), appended);
        }

        let memory = MemoryHypothesisGraphStore::new(graph(), signer(45)).unwrap();
        assert_rejected(&memory, 45);

        let path = temp_dir("graph-cas-guard");
        let file = FileHypothesisGraphStore::new(&path, graph(), signer(46)).unwrap();
        assert_rejected(&file, 46);
        drop(file);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn renewal_rejects_backdated_logical_time_without_mutation() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(19)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(1, "renew-backdated"),
                GraphLogicalTime::new(100),
                20,
                1,
                19,
            ))
            .unwrap();
        let lease = claim.lease.unwrap();
        let before = store.snapshot().unwrap();
        assert!(matches!(
            store.renew_task(signed_renewal_envelope(
                &claim.task.request,
                &lease,
                claim.task_generation,
                GraphLogicalTime::new(99),
                20,
                1,
                19,
            )),
            Err(GraphStoreError::InvalidTransition { .. })
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }

    #[test]
    fn durable_renewal_requires_claimant_and_scheduler_authority_and_binds_clock() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(30)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(31, "signed-renewal"),
                GraphLogicalTime::new(100),
                20,
                31,
                30,
            ))
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let signed = signed_renewal_envelope(
            &claim.task.request,
            &lease,
            claim.task_generation,
            GraphLogicalTime::new(105),
            20,
            31,
            30,
        );
        let before = store.snapshot().unwrap();

        let mut claimant_only = signed.clone();
        claimant_only.authority_witness = None;
        assert!(matches!(
            store.renew_task(claimant_only.clone()),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let foreign_authority = claimant_only
            .authorized_by(&signer(32), "task-renewal-authority:signed-renewal")
            .unwrap();
        assert!(matches!(
            store.renew_task(foreign_authority),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut unsigned = signed.clone();
        unsigned.renewal_witness = None;
        assert!(matches!(
            store.renew_task(unsigned),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut poisoned_clock = signed.clone();
        poisoned_clock.renewed_at = GraphLogicalTime::new(119);
        assert!(matches!(
            store.renew_task(poisoned_clock),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut tampered = signed.clone();
        tampered.duration_ms = 21;
        assert!(matches!(
            store.renew_task(tampered),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut foreign = signed.clone();
        foreign.renewal_witness = None;
        assert!(matches!(
            foreign.signed_with(&signer(32), "task-renewal:signed-renewal"),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let renewed = store.renew_task(signed).unwrap();
        assert_eq!(renewed.task.state, TaskState::Claimed);
        assert_eq!(
            renewed.lease.unwrap().expires_at,
            GraphLogicalTime::new(125)
        );
    }

    #[test]
    fn durable_expiry_requires_configured_authority_and_binds_observed_time() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(33)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(34, "signed-expiry"),
                GraphLogicalTime::new(100),
                20,
                34,
                33,
            ))
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let signed = signed_expiry_envelope(
            &claim.task.request,
            &lease,
            claim.task_generation,
            GraphLogicalTime::new(120),
            33,
        );
        let before = store.snapshot().unwrap();

        let mut unsigned = signed.clone();
        unsigned.expiry_witness = None;
        assert!(matches!(
            store.expire_task(unsigned),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let foreign = signed_expiry_envelope(
            &claim.task.request,
            &lease,
            claim.task_generation,
            GraphLogicalTime::new(120),
            35,
        );
        assert!(matches!(
            store.expire_task(foreign),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut tampered = signed.clone();
        tampered.observed_at = GraphLogicalTime::new(121);
        assert!(matches!(
            store.expire_task(tampered),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let expired = store.expire_task(signed).unwrap();
        assert_eq!(expired.task.state, TaskState::Expired);
        assert!(
            store.snapshot().unwrap().state.logical_time_high_water >= GraphLogicalTime::new(120)
        );
    }

    #[test]
    fn durable_reclaim_requires_claimant_and_configured_authority_signatures() {
        let store = MemoryHypothesisGraphStore::new(graph(), signer(36)).unwrap();
        let claim = store
            .claim_task(signed_claim_envelope(
                request(37, "signed-reclaim"),
                GraphLogicalTime::new(100),
                20,
                37,
                36,
            ))
            .unwrap();
        let lease = claim.lease.clone().unwrap();
        let expired = store
            .expire_task(signed_expiry_envelope(
                &claim.task.request,
                &lease,
                claim.task_generation,
                GraphLogicalTime::new(120),
                36,
            ))
            .unwrap();
        let replacement = request_at(38, "signed-reclaim", GraphLogicalTime::new(121));
        let claimant_only = reclaim_envelope(
            &claim.task.request,
            expired.task_generation,
            replacement.clone(),
            GraphLogicalTime::new(121),
            20,
            38,
        );
        let signed = signed_reclaim_envelope(
            &claim.task.request,
            expired.task_generation,
            replacement,
            GraphLogicalTime::new(121),
            20,
            38,
            36,
        );
        let before = store.snapshot().unwrap();

        assert!(matches!(
            store.reclaim_task(claimant_only),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let foreign = signed_reclaim_envelope(
            &claim.task.request,
            expired.task_generation,
            request_at(38, "signed-reclaim", GraphLogicalTime::new(121)),
            GraphLogicalTime::new(121),
            20,
            38,
            39,
        );
        assert!(matches!(
            store.reclaim_task(foreign),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let mut tampered = signed.clone();
        tampered.duration_ms = 21;
        assert!(matches!(
            store.reclaim_task(tampered),
            Err(GraphStoreError::Admission(
                swarm_core::hypothesis_graph::GraphAdmissionError::InvalidWitness { .. }
            ))
        ));
        assert_eq!(store.snapshot().unwrap(), before);

        let reclaimed = store.reclaim_task(signed).unwrap();
        let claimant = AgentId::from_public_key_hex(&signer(38).public_key().to_hex());
        assert_eq!(reclaimed.task.state, TaskState::Claimed);
        assert_eq!(reclaimed.task.request.claimant, claimant);
        assert_eq!(
            reclaimed.lease.unwrap().holder,
            reclaimed.task.request.claimant
        );
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

        store
            .create_task(signed_creation_envelope(
                request(1, "full-root-rollback"),
                1,
                25,
            ))
            .unwrap();
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
            .claim_task(signed_claim_envelope(
                request.clone(),
                GraphLogicalTime::new(100),
                20,
                1,
                9,
            ))
            .unwrap();
        let memory_claim = memory
            .claim_task(signed_claim_envelope(
                request,
                GraphLogicalTime::new(100),
                20,
                1,
                9,
            ))
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
            .claim_task(signed_claim_envelope(
                request(1, "vector"),
                GraphLogicalTime::new(100),
                20,
                1,
                11,
            ))
            .unwrap();
        let claimed_file = file
            .claim_task(signed_claim_envelope(
                request(1, "vector"),
                GraphLogicalTime::new(100),
                20,
                1,
                11,
            ))
            .unwrap();
        assert_eq!(claimed_memory.task, claimed_file.task);
        let lease = claimed_memory.lease.clone().unwrap();
        let renewal = signed_renewal_envelope(
            &claimed_memory.task.request,
            &lease,
            claimed_memory.task_generation,
            GraphLogicalTime::new(105),
            20,
            1,
            11,
        );
        let renewed_memory = memory.renew_task(renewal.clone()).unwrap();
        let renewed_file = file
            .renew_task(TaskRenewalEnvelope {
                expected_generation: claimed_file.task_generation,
                ..renewal
            })
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
        let envelope =
            signed_terminal_envelope(&renewed_memory.task.request, &renewed_lease, completion, 1);
        let memory_clock = signed_completion_clock(
            renewed_memory.task_generation,
            GraphLogicalTime::new(110),
            &envelope,
            11,
        );
        let file_clock = signed_completion_clock(
            renewed_file.task_generation,
            GraphLogicalTime::new(110),
            &envelope,
            11,
        );
        let done_memory = memory
            .complete_task(
                renewed_memory.task_generation,
                memory_clock,
                envelope.clone(),
            )
            .unwrap();
        let done_file = file
            .complete_task(renewed_file.task_generation, file_clock, envelope)
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
            .claim_task(signed_claim_envelope(
                request(1, "anchor"),
                GraphLogicalTime::new(100),
                20,
                1,
                12,
            ))
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
            store.create_task(signed_creation_envelope(
                request(1, "lock-replacement"),
                1,
                18,
            )),
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
            candidate_input
                .graph
                .admit_node(GraphNode::Actor(
                    ActorNode::new("actor:oversized", "Oversized envelope actor").unwrap(),
                ))
                .unwrap();
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
            let memory_result = memory_store.compare_and_swap(signed_graph_cas_envelope(
                baseline.revision.clone(),
                candidate_input.clone(),
                54,
            ));
            let file_result = file_store.compare_and_swap(signed_graph_cas_envelope(
                baseline.revision.clone(),
                candidate_input,
                54,
            ));
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
            let result = writer.create_task(signed_creation_envelope(
                request(1, "namespace-barrier"),
                1,
                21,
            ));
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
                store.create_task(signed_creation_envelope(
                    request(32, &format!("txn-{index}")),
                    32,
                    31,
                )),
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
        store
            .create_task(signed_creation_envelope(
                request(34, "external-prefix"),
                34,
                33,
            ))
            .unwrap();
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
                store.create_task(signed_creation_envelope(
                    request(56, &format!("rollback-{index}")),
                    56,
                    55,
                )),
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
        let first_thread = std::thread::spawn(move || {
            first_store.create_task(signed_creation_envelope(
                request(60, "same-handle-first"),
                60,
                59,
            ))
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let second_store = Arc::clone(&store);
        let (second_tx, second_rx) = mpsc::channel();
        let second_thread = std::thread::spawn(move || {
            let result = second_store.create_task(signed_creation_envelope(
                request(61, "same-handle-second"),
                61,
                59,
            ));
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
        let writer_thread = std::thread::spawn(move || {
            writer.create_task(signed_creation_envelope(
                request(63, "displaced-root"),
                63,
                62,
            ))
        });
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
        store
            .create_task(signed_creation_envelope(
                request(65, "before-rotation"),
                65,
                64,
            ))
            .unwrap();
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
        store
            .create_task(signed_creation_envelope(
                request(66, "after-rotation"),
                66,
                64,
            ))
            .unwrap();
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
}
