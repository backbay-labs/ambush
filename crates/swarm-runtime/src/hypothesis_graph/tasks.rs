//! Durable reasoning-task admission and the single terminal publication path.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::GraphRecordSigner;
use super::hypotheses::{
    HypothesisDisposition, HypothesisSeedInput, competing_hypotheses, coordination_task_targets,
    seed_task_digest,
};
use swarm_core::config::HypothesisGraphConfig;
use swarm_core::hypothesis_graph::{
    CausalEdge, DecisionKind, DecisionRecord, EvidenceEnvelope, EvidenceScope, FencingToken,
    GraphAdmissionError, GraphLogicalTime, GraphNode, GraphProducerRole, GraphResourceLimits,
    Hypothesis, HypothesisId, LogicalTaskDescriptor, SchedulerBudget, StrategyMemory,
    StrategyMemoryExpiryEnvelope, TaskCapabilityProof, TaskClaimRequest, TaskId, TaskKind,
    TaskRecord, TaskState, TaskTarget, TaskTerminalEnvelope, TaskTerminalOutboxEntry,
    validate_completion_kind,
};
use swarm_core::types::AgentId;
use swarm_spine::hypothesis_graph_store::{
    DurableTaskRecord, GraphStoreError, GraphStoreRevision, GraphStoreSnapshot, GraphStoreState,
    HypothesisGraphStore, ReasoningStateUpdate, TaskMonotonicity,
};

/// A runtime claim is ephemeral.  Its capability proof and the persisted
/// descriptor are the only values allowed to cross the durable terminal seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskClaim {
    pub task_id: swarm_core::hypothesis_graph::TaskId,
    pub idempotency_key: swarm_core::hypothesis_graph::IdempotencyKey,
    pub claimant: AgentId,
    pub capability: TaskKind,
    pub capability_proof: TaskCapabilityProof,
    pub lease_id: swarm_core::hypothesis_graph::LeaseId,
    pub fencing_token: FencingToken,
}

impl TaskClaim {
    pub fn from_task(
        task: &TaskRecord,
        capability_proof: TaskCapabilityProof,
    ) -> Result<Self, GraphStoreError> {
        let lease = task
            .lease
            .as_ref()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "a runtime claim requires an active lease".to_string(),
            })?;
        if capability_proof.task_id != task.request.task_id
            || capability_proof.claimant != task.request.claimant
            || capability_proof.kind != task.request.kind
        {
            return Err(GraphStoreError::InvalidState {
                reason: "claim capability is not bound to the task".to_string(),
            });
        }
        Ok(Self {
            task_id: task.request.task_id.clone(),
            idempotency_key: task.request.idempotency_key.clone(),
            claimant: task.request.claimant.clone(),
            capability: task.request.kind,
            capability_proof,
            lease_id: lease.lease_id.clone(),
            fencing_token: lease.fencing_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HypothesisTaskLedger {
    limits: GraphResourceLimits,
    scheduler_budget: SchedulerBudget,
    config: HypothesisGraphConfig,
}

impl HypothesisTaskLedger {
    pub fn from_config(
        config: &HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        let limits = config.resource_limits();
        limits.validate()?;
        let scheduler_budget = SchedulerBudget::new_with_config(config, logical_tick)?;
        Ok(Self {
            limits,
            scheduler_budget,
            config: config.clone(),
        })
    }

    /// Open a ledger against an authenticated graph store. The persisted
    /// budget is authoritative for a restart; `logical_tick` only seeds the
    /// budget when the graph is still a legacy stream without one.
    pub fn from_store(
        config: &HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
        store: &dyn HypothesisGraphStore,
    ) -> Result<Self, GraphStoreError> {
        let snapshot = store.snapshot()?;
        let mut ledger =
            Self::from_config(config, logical_tick).map_err(GraphStoreError::Admission)?;
        ledger.restore_local_budget(&snapshot)?;
        Ok(ledger)
    }

    /// Re-read the authenticated generation after a process restart or store
    /// reopen. The local budget changes only from a successful snapshot read.
    pub fn restore_from_store(
        &mut self,
        store: &dyn HypothesisGraphStore,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let snapshot = store.snapshot()?;
        self.restore_local_budget(&snapshot)?;
        Ok(snapshot)
    }

    pub fn scheduler_budget(&self) -> &SchedulerBudget {
        &self.scheduler_budget
    }

    pub fn limits(&self) -> &GraphResourceLimits {
        &self.limits
    }

    /// Restore the config-bound budget carried by the authenticated graph
    /// generation. A legacy state has no budget yet; in that case construct a
    /// zero-usage candidate only for the pending durable admission that will
    /// attach it to the same generation.
    fn budget_for_snapshot(
        &self,
        snapshot: &GraphStoreSnapshot,
        logical_tick: GraphLogicalTime,
    ) -> Result<SchedulerBudget, GraphStoreError> {
        budget_from_snapshot(&self.config, snapshot, logical_tick)
    }

    /// Synchronize local read state only after a successful durable read or
    /// idempotent replay. Failed/CAS-refused operations never call this path.
    fn restore_local_budget(
        &mut self,
        snapshot: &GraphStoreSnapshot,
    ) -> Result<(), GraphStoreError> {
        if let Some(budget) = snapshot.scheduler_budget() {
            budget
                .validate_for_config(&self.config)
                .map_err(GraphStoreError::Admission)?;
            self.scheduler_budget = budget.clone();
        } else if !snapshot.state().tasks.is_empty()
            || !snapshot.state().logical_task_descriptors.is_empty()
        {
            return Err(GraphStoreError::InvalidState {
                reason: "durable tasks require a persisted scheduler budget".to_string(),
            });
        }
        Ok(())
    }

    /// Create a descriptor-bound pending task.  Fresh stores are migrated to
    /// the current reasoning marker in this same state transition; retries of
    /// an identical descriptor return the existing state without another CAS.
    pub fn create_task(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        descriptor: LogicalTaskDescriptor,
        request: TaskClaimRequest,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        descriptor.validate().map_err(GraphStoreError::Admission)?;
        request.validate().map_err(GraphStoreError::Admission)?;
        if descriptor.task_id != request.task_id
            || descriptor.target != request.target
            || descriptor.kind != request.kind
        {
            return Err(GraphStoreError::InvalidState {
                reason: "logical descriptor does not bind task request".to_string(),
            });
        }
        let snapshot = store.snapshot()?;
        if snapshot.revision() != revision {
            return Err(GraphStoreError::StalePredecessor {
                expected_generation: revision.generation,
                expected_digest: revision.digest.clone(),
                observed_generation: snapshot.revision().generation,
                observed_digest: snapshot.revision().digest.clone(),
            });
        }
        if descriptor.graph_id != snapshot.state().graph_id {
            return Err(GraphStoreError::InvalidState {
                reason: "logical task descriptor graph ID differs from durable graph".to_string(),
            });
        }
        if let Some(existing_descriptor) = snapshot
            .state()
            .logical_task_descriptors
            .get(&descriptor.task_id)
        {
            if !same_logical_descriptor(existing_descriptor, &descriptor) {
                return Err(GraphStoreError::InvalidState {
                    reason: "logical task descriptor mutation is rejected".to_string(),
                });
            }
            snapshot
                .state()
                .tasks
                .get(&descriptor.task_id)
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "logical descriptor has no durable task".to_string(),
                })?;
            // The descriptor is the claimant-independent identity.  The
            // request's claimant, arrival time, and claimant-scoped
            // idempotency key are intentionally not compared here: those
            // fields belong to retry/lease admission, not logical identity.
            self.restore_local_budget(&snapshot)?;
            return Ok(snapshot);
        }
        if snapshot.state().tasks.contains_key(&descriptor.task_id) {
            return Err(GraphStoreError::InvalidState {
                reason: "task exists without a descriptor and is quarantined".to_string(),
            });
        }
        if request.requested_at < snapshot.state().logical_time_high_water {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidTransition {
                    reason: "task request logical time is below the durable graph high-water"
                        .to_string(),
                },
            ));
        }
        // Admission is transactional with durable task creation.  Probe a
        // clone before the CAS, then publish the counters only after the CAS
        // succeeds.  A stale predecessor, validation error, or forced CAS
        // refusal therefore cannot consume budget.
        let mut next_budget = self.budget_for_snapshot(&snapshot, request.requested_at)?;
        next_budget
            .admit_at(&self.config, request.requested_at, 1, 0)
            .map_err(GraphStoreError::Admission)?;
        let task = TaskRecord {
            schema_version: swarm_core::hypothesis_graph::HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            request,
            state: TaskState::Pending,
            generation: 1,
            attempts: 1,
            lease: None,
            completion: None,
            terminal_history: Vec::new(),
        };
        task.validate_with_limits(self.limits.max_task_lease_ms, self.limits.max_task_retries)
            .map_err(GraphStoreError::Admission)?;
        let durable = DurableTaskRecord {
            schema_version: swarm_spine::hypothesis_graph_store::GRAPH_STORE_SCHEMA_VERSION,
            task: task.clone(),
            generation: 1,
            history: Vec::new(),
        };
        let mut tasks = snapshot.state().tasks.clone();
        tasks.insert(descriptor.task_id.clone(), durable);
        let mut descriptors = snapshot.state().logical_task_descriptors.clone();
        descriptors.insert(descriptor.task_id.clone(), descriptor);
        let predecessor_digest = snapshot.state().predecessor_digest.clone();
        let mut next = if snapshot.state().migration_marker
            == swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_LEGACY
        {
            if !snapshot.state().tasks.is_empty() {
                return Err(GraphStoreError::InvalidState {
                    reason: "legacy tasks require signed descriptor backfill before migration"
                        .to_string(),
                });
            }
            GraphStoreState::with_reasoning_state(
                snapshot.state().clone(),
                ReasoningStateUpdate::migration_to_hypotheses(
                    self.limits.clone(),
                    task.request.requested_at,
                )
                .with_hypotheses(BTreeMap::<
                    swarm_core::hypothesis_graph::HypothesisId,
                    Hypothesis,
                >::new())
                .with_tasks(tasks)
                .with_logical_task_descriptors(descriptors)
                .with_scheduler_budget(next_budget.clone()),
            )?
        } else {
            let mut state = snapshot.state().clone();
            state.tasks = tasks;
            state.logical_task_descriptors = descriptors;
            state.migration_marker =
                swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_HYPOTHESES;
            state.limits = self.limits.clone();
            state.scheduler_budget = Some(next_budget.clone());
            state.logical_time_high_water =
                state.logical_time_high_water.max(task.request.requested_at);
            let inserted = state.tasks.get(&task.request.task_id).ok_or_else(|| {
                GraphStoreError::InvalidState {
                    reason: "inserted task disappeared before tombstone admission".to_string(),
                }
            })?;
            state.task_tombstones.insert(
                task.request.task_id.clone(),
                TaskMonotonicity::from_record(inserted)?,
            );
            state
        };
        next.generation = revision.generation;
        next.predecessor_digest = predecessor_digest;
        let result = store.compare_and_swap(revision, next)?;
        self.scheduler_budget = result.scheduler_budget().cloned().unwrap_or(next_budget);
        Ok(result)
    }

    /// Durably admit competing hypotheses and every deterministic task needed
    /// to resolve their still-open claims.  The seed, hypotheses, task
    /// descriptors, and task records are assembled from one snapshot and
    /// published with one CAS; retries discover the existing descriptors and
    /// do not consume work budget or create a second task.
    pub fn coordinate_seed(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimant: AgentId,
        evidence_scope: EvidenceScope,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        let claimants = [
            TaskKind::AcquireEvidence,
            TaskKind::ChallengeEdge,
            TaskKind::FalsifyHypothesis,
        ]
        .into_iter()
        .map(|kind| (kind, claimant.clone()))
        .collect();
        self.coordinate_seed_for_claimants(store, revision, seed, &claimants, evidence_scope)
    }

    /// Assign each durable task kind to the identity that will actually sign
    /// its claim and terminal publication. Missing capability registrations
    /// fail before any candidate state is committed.
    pub fn coordinate_seed_for_claimants(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimants: &BTreeMap<TaskKind, AgentId>,
        evidence_scope: EvidenceScope,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        coordinate_seed_once(CoordinatorContext {
            scheduler_budget: &mut self.scheduler_budget,
            config: &self.config,
            limits: &self.limits,
            store,
            revision,
            seed,
            claimants: claimants.clone(),
            evidence_scope,
            signer: None,
            decisions: Vec::new(),
            graph_records: None,
        })
    }

    /// Atomically admit normalized graph records together with the competing
    /// hypotheses and deterministic tasks derived from the same replay.
    pub(crate) fn coordinate_graph_seed_for_claimants(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimants: &BTreeMap<TaskKind, AgentId>,
        evidence_scope: EvidenceScope,
        graph_records: GraphSeedRecords,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        coordinate_seed_once(CoordinatorContext {
            scheduler_budget: &mut self.scheduler_budget,
            config: &self.config,
            limits: &self.limits,
            store,
            revision,
            seed,
            claimants: claimants.clone(),
            evidence_scope,
            signer: None,
            decisions: Vec::new(),
            graph_records: Some(graph_records),
        })
    }

    /// Variant of [`Self::coordinate_seed`] for explicit support, challenge,
    /// and falsification requests. The injected signer signs and verifies each
    /// request before it can enter durable hypothesis history; callers cannot
    /// supply a pre-witnessed record. No disposition is inferred from the
    /// normalized seed.
    pub(crate) fn coordinate_seed_with_decisions(
        &mut self,
        input: CoordinatorDecisionInput<'_>,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        let claimants = [
            TaskKind::AcquireEvidence,
            TaskKind::ChallengeEdge,
            TaskKind::FalsifyHypothesis,
        ]
        .into_iter()
        .map(|kind| (kind, input.claimant.clone()))
        .collect();
        coordinate_seed_once(CoordinatorContext {
            scheduler_budget: &mut self.scheduler_budget,
            config: &self.config,
            limits: &self.limits,
            store: input.store,
            revision: input.revision,
            seed: input.seed,
            claimants,
            evidence_scope: input.evidence_scope,
            signer: Some(input.signer),
            decisions: input.decisions,
            graph_records: None,
        })
    }

    /// Claim through the existing fenced store API, retaining one exact
    /// capability proof for the eventual terminal operation.
    pub fn claim_task(
        &mut self,
        store: &dyn HypothesisGraphStore,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        capability_proof: TaskCapabilityProof,
    ) -> Result<TaskClaim, GraphStoreError> {
        request.validate().map_err(GraphStoreError::Admission)?;
        capability_proof
            .validate_for_claim(&request)
            .map_err(GraphStoreError::Admission)?;
        let snapshot = store.snapshot()?;
        let revision = snapshot.revision().clone();
        let persisted_budget = self.budget_for_snapshot(&snapshot, now)?;
        let idempotent = claim_request_is_idempotent(&snapshot, &request);
        // Probe a candidate only for a new durable claim. An idempotent retry
        // is allowed to succeed even when the current tick is exhausted, but
        // the spine receives the persisted budget unchanged and therefore
        // cannot recharge or reset it.
        let mut next_budget = persisted_budget.clone();
        if !idempotent {
            // Creating a task consumes work; claiming an admitted task
            // consumes only one claim slot. Keep those ceilings independent
            // so a claim cannot bypass work accounting or spend work twice
            // for the same task.
            next_budget
                .admit_at(&self.config, now, 0, 1)
                .map_err(GraphStoreError::Admission)?;
        }
        // The budget-bearing CAS is the only production claim path. Custom
        // backends that do not implement it fail closed through the trait's
        // default error rather than mutating a task without its budget.
        let result = store.claim_task_cas_with_budget(
            &revision,
            request,
            now,
            lease_duration_ms,
            next_budget.clone(),
        )?;
        // Do not publish the local counter until the durable result has also
        // passed the runtime claim-boundary conversion. A malformed custom
        // backend result must be treated as a failed admission, with local
        // usage remaining byte-for-byte unchanged even if the backend
        // reported success.
        let claim = TaskClaim::from_task(&result.task, capability_proof)?;
        if result.idempotent {
            self.restore_local_budget(&snapshot)?;
        } else {
            self.scheduler_budget = next_budget;
        }
        Ok(claim)
    }

    /// Claim pending work or recover the same logical task after its fenced
    /// lease expires. Expiry remains a distinct fencing barrier, while expiry,
    /// replacement lease, and configured claim-budget charge commit in one
    /// durable store generation.
    pub fn claim_or_reclaim_task(
        &mut self,
        store: &dyn HypothesisGraphStore,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        capability_proof: TaskCapabilityProof,
    ) -> Result<TaskClaim, GraphStoreError> {
        request.validate().map_err(GraphStoreError::Admission)?;
        capability_proof
            .validate_for_claim(&request)
            .map_err(GraphStoreError::Admission)?;
        let snapshot = store.snapshot()?;
        let entry = snapshot
            .state()
            .tasks
            .get(&request.task_id)
            .ok_or_else(|| GraphStoreError::TaskNotFound {
                task_id: request.task_id.to_string(),
            })?;
        match entry.task.state {
            TaskState::Pending => {
                self.claim_task(store, request, now, lease_duration_ms, capability_proof)
            }
            TaskState::Claimed
                if entry
                    .task
                    .lease
                    .as_ref()
                    .is_some_and(|lease| now >= lease.expires_at) =>
            {
                self.reclaim_expired_task(store, request, now, lease_duration_ms, capability_proof)
            }
            TaskState::Expired => {
                self.reclaim_expired_task(store, request, now, lease_duration_ms, capability_proof)
            }
            TaskState::Claimed | TaskState::Completed | TaskState::Failed => {
                self.claim_task(store, request, now, lease_duration_ms, capability_proof)
            }
        }
    }

    fn reclaim_expired_task(
        &mut self,
        store: &dyn HypothesisGraphStore,
        request: TaskClaimRequest,
        now: GraphLogicalTime,
        lease_duration_ms: u64,
        capability_proof: TaskCapabilityProof,
    ) -> Result<TaskClaim, GraphStoreError> {
        let snapshot = store.snapshot()?;
        let revision = snapshot.revision().clone();
        let persisted_budget = self.budget_for_snapshot(&snapshot, now)?;
        let mut next_budget = persisted_budget.clone();
        next_budget
            .admit_at(&self.config, now, 0, 1)
            .map_err(GraphStoreError::Admission)?;
        let task_id = request.task_id.to_string();
        let result = store.reclaim_task_cas_with_budget(
            &revision,
            &task_id,
            request,
            now,
            lease_duration_ms,
            next_budget.clone(),
        )?;
        let claim = TaskClaim::from_task(&result.task, capability_proof)?;
        if result.idempotent {
            self.restore_local_budget(&snapshot)?;
        } else {
            self.scheduler_budget = next_budget;
        }
        Ok(claim)
    }

    /// Validate and commit a terminal task plus all reasoning publications in
    /// one graph-store CAS.  No memory or external publication store is
    /// touched by this operation.  This compatibility name delegates to the
    /// explicit production seam [`Self::accept_terminal_once`].
    #[allow(clippy::too_many_arguments)]
    pub fn complete_task(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        claim: &TaskClaim,
        envelope: TaskTerminalEnvelope,
        evidence: Vec<swarm_core::hypothesis_graph::EvidenceEnvelope>,
        decision: Option<swarm_core::hypothesis_graph::DecisionRecord>,
        memory: Option<StrategyMemory>,
        memory_expiry: Option<StrategyMemoryExpiryEnvelope>,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        self.accept_terminal_once(
            store,
            revision,
            claim,
            envelope,
            evidence,
            decision,
            memory,
            memory_expiry,
        )
    }

    /// The production terminal admission seam.  All validation occurs before
    /// [`commit_terminal_once`] constructs a candidate state, and exactly one
    /// graph-store CAS is attempted for a valid publication.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_terminal_once(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        claim: &TaskClaim,
        envelope: TaskTerminalEnvelope,
        evidence: Vec<swarm_core::hypothesis_graph::EvidenceEnvelope>,
        decision: Option<DecisionRecord>,
        memory: Option<StrategyMemory>,
        memory_expiry: Option<StrategyMemoryExpiryEnvelope>,
    ) -> Result<GraphStoreSnapshot, GraphStoreError> {
        let snapshot = store.snapshot()?;
        if snapshot.revision() != revision {
            return Err(GraphStoreError::StalePredecessor {
                expected_generation: revision.generation,
                expected_digest: revision.digest.clone(),
                observed_generation: snapshot.revision().generation,
                observed_digest: snapshot.revision().digest.clone(),
            });
        }
        let entry = snapshot.state().tasks.get(&claim.task_id).ok_or_else(|| {
            GraphStoreError::TaskNotFound {
                task_id: claim.task_id.to_string(),
            }
        })?;
        let descriptor = snapshot
            .state()
            .logical_task_descriptors
            .get(&claim.task_id)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task has no persisted logical descriptor".to_string(),
            })?;
        let lease =
            entry
                .task
                .lease
                .as_ref()
                .ok_or_else(|| GraphStoreError::InvalidTransition {
                    reason: "terminal admission requires the active task lease".to_string(),
                })?;
        if claim.idempotency_key != entry.task.request.idempotency_key
            || claim.claimant != entry.task.request.claimant
            || claim.capability != entry.task.request.kind
            || claim.lease_id != lease.lease_id
            || claim.fencing_token != lease.fencing_token
        {
            return Err(GraphStoreError::InvalidTransition {
                reason: "runtime claim does not bind the active durable task".to_string(),
            });
        }
        claim
            .capability_proof
            .validate_for_claim(&entry.task.request)
            .map_err(GraphStoreError::Admission)?;
        envelope
            .validate_for_task(
                &entry.task,
                self.limits.max_task_lease_ms,
                self.limits.max_task_retries,
            )
            .map_err(GraphStoreError::Admission)?;
        validate_completion_kind(entry.task.request.kind, envelope.completion.kind.clone())
            .map_err(GraphStoreError::Admission)?;
        if envelope.capability != claim.capability_proof {
            return Err(GraphStoreError::InvalidState {
                reason: "terminal capability differs from claimed capability".to_string(),
            });
        }
        validate_configured_terminal_time(
            &snapshot,
            &envelope,
            memory.as_ref(),
            memory_expiry.as_ref(),
            &self.config,
        )?;
        let publication = TaskTerminalOutboxEntry::new(
            &entry.task,
            descriptor,
            envelope.clone(),
            evidence,
            decision.clone(),
            memory,
            memory_expiry,
            claim.claimant.clone(),
            &self.limits,
        )
        .map_err(GraphStoreError::Admission)?;
        publication
            .validate_for_task_at(
                &entry.task,
                descriptor,
                &self.limits,
                snapshot.state().logical_time_high_water,
            )
            .map_err(GraphStoreError::Admission)?;
        commit_terminal_once(store, revision, claim, publication)
    }
}

/// Durable result returned by the seed coordinator.  The snapshot is the
/// exact value returned by the store's CAS, rather than a process-local map or
/// a reconstructed projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypothesisCoordinationResult {
    pub snapshot: GraphStoreSnapshot,
    pub hypothesis_ids: Vec<HypothesisId>,
    pub task_ids: Vec<TaskId>,
}

/// Normalized graph records that must become visible in the same durable
/// generation as their competing hypotheses and reasoning tasks. Keeping
/// these records inside the coordinator transaction prevents a budget or
/// validation failure from publishing orphan evidence without its work.
#[derive(Debug, Clone)]
pub(crate) struct GraphSeedRecords {
    evidence: EvidenceEnvelope,
    nodes: Vec<GraphNode>,
    edges: Vec<CausalEdge>,
}

impl GraphSeedRecords {
    pub(crate) fn new(
        evidence: EvidenceEnvelope,
        nodes: Vec<GraphNode>,
        edges: Vec<CausalEdge>,
    ) -> Self {
        Self {
            evidence,
            nodes,
            edges,
        }
    }

    fn admit_into(self, state: &mut GraphStoreState) -> Result<bool, GraphStoreError> {
        let prior_version = state.graph.version;
        state
            .graph
            .admit_evidence(self.evidence)
            .map_err(GraphStoreError::Admission)?;
        for node in self.nodes {
            state
                .graph
                .admit_node(node)
                .map_err(GraphStoreError::Admission)?;
        }
        for edge in self.edges {
            state
                .graph
                .admit_edge(edge)
                .map_err(GraphStoreError::Admission)?;
        }
        Ok(state.graph.version != prior_version)
    }
}

/// Runtime coordinator for seed admission. It owns the config-bound ledger and
/// the admitted record signer; graph state remains in the injected durable
/// store. Decision requests cannot bypass this signer.
#[derive(Clone)]
pub struct DurableHypothesisCoordinator {
    ledger: HypothesisTaskLedger,
    signer: Arc<dyn GraphRecordSigner>,
}

impl DurableHypothesisCoordinator {
    pub fn new<S: GraphRecordSigner + 'static>(
        config: &HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
        signer: S,
    ) -> Result<Self, GraphAdmissionError> {
        Ok(Self {
            ledger: HypothesisTaskLedger::from_config(config, logical_tick)?,
            signer: Arc::new(signer),
        })
    }

    /// Construct a coordinator around an already shared signer capability.
    /// The signer remains the sole authority for support/challenge/falsify
    /// records submitted through [`Self::coordinate_seed_with_decisions`].
    pub fn new_with_signer(
        config: &HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
        signer: Arc<dyn GraphRecordSigner>,
    ) -> Result<Self, GraphAdmissionError> {
        Ok(Self {
            ledger: HypothesisTaskLedger::from_config(config, logical_tick)?,
            signer,
        })
    }

    /// Open a coordinator against an authenticated store, restoring the
    /// durable scheduler budget before the first candidate admission.
    pub fn new_with_store<S: GraphRecordSigner + 'static>(
        config: &HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
        store: &dyn HypothesisGraphStore,
        signer: S,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self {
            ledger: HypothesisTaskLedger::from_store(config, logical_tick, store)?,
            signer: Arc::new(signer),
        })
    }

    /// `Arc` variant of [`Self::new_with_store`] for shared signer
    /// capabilities owned by a runtime admission service.
    pub fn new_with_store_and_signer(
        config: &HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
        store: &dyn HypothesisGraphStore,
        signer: Arc<dyn GraphRecordSigner>,
    ) -> Result<Self, GraphStoreError> {
        Ok(Self {
            ledger: HypothesisTaskLedger::from_store(config, logical_tick, store)?,
            signer,
        })
    }

    pub fn ledger(&self) -> &HypothesisTaskLedger {
        &self.ledger
    }

    pub fn ledger_mut(&mut self) -> &mut HypothesisTaskLedger {
        &mut self.ledger
    }

    pub fn coordinate_seed(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimant: AgentId,
        evidence_scope: EvidenceScope,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        self.ledger
            .coordinate_seed(store, revision, seed, claimant, evidence_scope)
    }

    pub fn coordinate_seed_for_claimants(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimants: &BTreeMap<TaskKind, AgentId>,
        evidence_scope: EvidenceScope,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        self.ledger
            .coordinate_seed_for_claimants(store, revision, seed, claimants, evidence_scope)
    }

    pub(crate) fn coordinate_graph_seed_for_claimants(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimants: &BTreeMap<TaskKind, AgentId>,
        evidence_scope: EvidenceScope,
        graph_records: GraphSeedRecords,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        self.ledger.coordinate_graph_seed_for_claimants(
            store,
            revision,
            seed,
            claimants,
            evidence_scope,
            graph_records,
        )
    }

    pub fn coordinate_seed_with_decisions(
        &mut self,
        store: &dyn HypothesisGraphStore,
        revision: &GraphStoreRevision,
        seed: &HypothesisSeedInput,
        claimant: AgentId,
        evidence_scope: EvidenceScope,
        decisions: Vec<DecisionRecord>,
    ) -> Result<HypothesisCoordinationResult, GraphStoreError> {
        self.ledger
            .coordinate_seed_with_decisions(CoordinatorDecisionInput {
                store,
                revision,
                seed,
                claimant,
                evidence_scope,
                signer: self.signer.as_ref(),
                decisions,
            })
    }
}

fn budget_from_snapshot(
    config: &HypothesisGraphConfig,
    snapshot: &GraphStoreSnapshot,
    logical_tick: GraphLogicalTime,
) -> Result<SchedulerBudget, GraphStoreError> {
    match snapshot.scheduler_budget() {
        Some(budget) => {
            budget
                .validate_for_config(config)
                .map_err(GraphStoreError::Admission)?;
            Ok(budget.clone())
        }
        None => {
            // Once a task or descriptor exists, the stream has already
            // admitted scheduler work. Reconstructing a zero-usage budget
            // from deployment config would make a restart silently reset
            // that history. Empty legacy/reasoning streams may still attach
            // their first budget in the same pending CAS.
            if !snapshot.state().tasks.is_empty()
                || !snapshot.state().logical_task_descriptors.is_empty()
            {
                return Err(GraphStoreError::InvalidState {
                    reason: "durable tasks require a persisted scheduler budget".to_string(),
                });
            }
            SchedulerBudget::new_with_config(config, logical_tick)
                .map_err(GraphStoreError::Admission)
        }
    }
}

pub(crate) struct CoordinatorDecisionInput<'a> {
    store: &'a dyn HypothesisGraphStore,
    revision: &'a GraphStoreRevision,
    seed: &'a HypothesisSeedInput,
    claimant: AgentId,
    evidence_scope: EvidenceScope,
    signer: &'a dyn GraphRecordSigner,
    decisions: Vec<DecisionRecord>,
}

struct CoordinatorContext<'a> {
    scheduler_budget: &'a mut SchedulerBudget,
    config: &'a HypothesisGraphConfig,
    limits: &'a GraphResourceLimits,
    store: &'a dyn HypothesisGraphStore,
    revision: &'a GraphStoreRevision,
    seed: &'a HypothesisSeedInput,
    claimants: BTreeMap<TaskKind, AgentId>,
    evidence_scope: EvidenceScope,
    signer: Option<&'a dyn GraphRecordSigner>,
    decisions: Vec<DecisionRecord>,
    graph_records: Option<GraphSeedRecords>,
}

fn validate_decisive_assessment_decisions(
    seed: &HypothesisSeedInput,
    decisions: &[DecisionRecord],
) -> Result<(), GraphStoreError> {
    for assessment in &seed.assessments {
        let accepted_kinds: &[DecisionKind] = match assessment.disposition {
            HypothesisDisposition::Supports => &[DecisionKind::Support],
            HypothesisDisposition::Refutes => &[DecisionKind::Challenge, DecisionKind::Falsify],
            HypothesisDisposition::Contradicts | HypothesisDisposition::Unresolved => continue,
        };
        let assessment_evidence = assessment
            .evidence_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let has_corresponding_decision = decisions.iter().any(|decision| {
            decision.hypothesis_id == assessment.hypothesis_id
                && accepted_kinds.contains(&decision.kind)
                && decision.evidence_ids == assessment_evidence
                && decision.witness.is_some()
        });
        if !has_corresponding_decision {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidTransition {
                    reason: format!(
                        "{:?} seed assessment for {} requires a corresponding signed decision over the same evidence",
                        assessment.disposition,
                        assessment.hypothesis_id.as_str()
                    ),
                },
            ));
        }
    }
    Ok(())
}

fn coordinate_seed_once(
    context: CoordinatorContext<'_>,
) -> Result<HypothesisCoordinationResult, GraphStoreError> {
    let CoordinatorContext {
        scheduler_budget,
        config,
        limits,
        store,
        revision,
        seed,
        claimants,
        evidence_scope,
        signer,
        decisions,
        graph_records,
    } = context;
    let snapshot = store.snapshot()?;
    if snapshot.revision() != revision {
        return Err(GraphStoreError::StalePredecessor {
            expected_generation: revision.generation,
            expected_digest: revision.digest.clone(),
            observed_generation: snapshot.revision().generation,
            observed_digest: snapshot.revision().digest.clone(),
        });
    }
    if snapshot.state().graph_id != seed.graph_id {
        return Err(GraphStoreError::InvalidState {
            reason: "hypothesis seed graph ID differs from durable graph".to_string(),
        });
    }
    if graph_records.is_some()
        && snapshot.state().migration_marker
            == swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_LEGACY
    {
        return Err(GraphStoreError::InvalidState {
            reason: "atomic graph seed admission requires an initialized reasoning store"
                .to_string(),
        });
    }
    let mut next_budget = budget_from_snapshot(config, &snapshot, seed.logical_time)?;
    if seed.logical_time < snapshot.state().logical_time_high_water {
        return Err(GraphStoreError::Admission(
            GraphAdmissionError::InvalidTransition {
                reason: "hypothesis seed logical time is below the durable graph high-water"
                    .to_string(),
            },
        ));
    }
    seed.validate_against_limits(limits)
        .map_err(GraphStoreError::Admission)?;
    evidence_scope
        .validate()
        .map_err(GraphStoreError::Admission)?;
    let mut next = snapshot.state().clone();
    let mut changed = match graph_records {
        Some(records) => records.admit_into(&mut next)?,
        None => false,
    };
    let seed_evidence_ids = seed
        .assessments
        .iter()
        .flat_map(|assessment| assessment.evidence_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let edge_ids = next
        .graph
        .edges
        .values()
        .filter(|edge| !edge.source_evidence_ids.is_disjoint(&seed_evidence_ids))
        .map(|edge| edge.edge_id.clone())
        .collect::<BTreeSet<_>>();
    let candidate_hypotheses = competing_hypotheses(seed, limits)
        .map_err(GraphStoreError::Admission)?
        .into_iter()
        .map(|(hypothesis_id, hypothesis)| {
            (
                hypothesis_id,
                hypothesis.with_claims(edge_ids.iter().cloned()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut hypothesis_ids = candidate_hypotheses.keys().cloned().collect::<Vec<_>>();
    hypothesis_ids.sort();
    for (hypothesis_id, candidate) in candidate_hypotheses {
        match next.hypotheses.get(&hypothesis_id) {
            Some(existing) if existing != &candidate => {
                // An existing hypothesis is durable history, not a projection
                // to be overwritten by a later seed. Preserve its decisions,
                // confidence, and status while monotonically attaching causal
                // edges admitted for this evidence-scoped retry.
                let mut updated = existing.clone();
                let prior_claim_count = updated.claims.len();
                updated.claims.extend(candidate.claims);
                if updated.claims.len() != prior_claim_count {
                    next.hypotheses.insert(hypothesis_id, updated);
                    changed = true;
                }
            }
            Some(_) => {}
            None => {
                next.hypotheses.insert(hypothesis_id, candidate);
                changed = true;
            }
        }
    }

    // Decisions are independently signed facts.  Sort them before assigning
    // append-only sequence numbers so arrival order cannot affect durable
    // history.  Duplicate decision IDs are idempotent; a new decision must
    // target one of the seed's candidate alternatives.
    let mut ordered_decisions = sign_coordinator_decisions(signer, decisions)?;
    validate_decisive_assessment_decisions(seed, &ordered_decisions)?;
    ordered_decisions.sort_by(|left, right| {
        left.decided_at
            .cmp(&right.decided_at)
            .then_with(|| left.hypothesis_id.cmp(&right.hypothesis_id))
            .then_with(|| left.decision_id.cmp(&right.decision_id))
    });
    for decision in ordered_decisions {
        decision.validate().map_err(GraphStoreError::Admission)?;
        if !seed
            .candidate_hypothesis_ids
            .iter()
            .any(|candidate| candidate == &decision.hypothesis_id)
        {
            return Err(GraphStoreError::InvalidState {
                reason: "decision targets a hypothesis outside the seed alternatives".to_string(),
            });
        }
        decision
            .validate_identity_admission(&next.graph.evidence)
            .map_err(GraphStoreError::Admission)?;
        let current = next
            .hypotheses
            .get(&decision.hypothesis_id)
            .cloned()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "decision target has no durable hypothesis".to_string(),
            })?;
        if current
            .decision_history
            .iter()
            .any(|existing| existing.decision_id == decision.decision_id)
        {
            continue;
        }
        let decision_time = decision.decided_at;
        if decision_time < seed.logical_time {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidTransition {
                    reason: "retrograde decision logical time precedes the hypothesis seed"
                        .to_string(),
                },
            ));
        }
        if decision_time < next.logical_time_high_water
            || current
                .decision_history
                .last()
                .is_some_and(|prior| decision_time < prior.decided_at)
        {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidTransition {
                    reason: "decision logical time is retrograde relative to durable history"
                        .to_string(),
                },
            ));
        }
        let updated = current
            .append_decision(decision)
            .map_err(GraphStoreError::Admission)?;
        next.hypotheses
            .insert(updated.hypothesis_id.clone(), updated);
        next.logical_time_high_water = next.logical_time_high_water.max(decision_time);
        changed = true;
    }

    let task_targets =
        coordination_task_targets(seed, &edge_ids).map_err(GraphStoreError::Admission)?;
    let mut task_ids = Vec::with_capacity(task_targets.len());
    let mut new_tasks = 0_usize;
    for (kind, target) in task_targets {
        let seed_digest =
            seed_task_digest(seed, kind, &target).map_err(GraphStoreError::Admission)?;
        let descriptor =
            LogicalTaskDescriptor::new(seed.graph_id.clone(), target.clone(), kind, seed_digest)
                .map_err(GraphStoreError::Admission)?;
        task_ids.push(descriptor.task_id.clone());
        if let Some(existing) = next.logical_task_descriptors.get(&descriptor.task_id) {
            if !same_logical_descriptor(existing, &descriptor) {
                return Err(GraphStoreError::InvalidState {
                    reason: "logical descriptor mutation is rejected".to_string(),
                });
            }
            if !next.tasks.contains_key(&descriptor.task_id) {
                return Err(GraphStoreError::InvalidState {
                    reason: "logical descriptor has no durable task".to_string(),
                });
            }
            continue;
        }
        if next.tasks.contains_key(&descriptor.task_id) {
            return Err(GraphStoreError::InvalidState {
                reason: "task exists without a descriptor and is quarantined".to_string(),
            });
        }
        let role = role_for_task_kind(kind);
        let claimant =
            claimants
                .get(&kind)
                .cloned()
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: format!("no claimant is registered for {kind:?} tasks"),
                })?;
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            kind,
            target,
            role,
            claimant,
            evidence_scope.clone(),
            seed.logical_time,
        )
        .map_err(GraphStoreError::Admission)?;
        let task = TaskRecord {
            schema_version: swarm_core::hypothesis_graph::HYPOTHESIS_GRAPH_SCHEMA_VERSION,
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
        let durable = DurableTaskRecord {
            schema_version: swarm_spine::hypothesis_graph_store::GRAPH_STORE_SCHEMA_VERSION,
            task,
            generation: 1,
            history: Vec::new(),
        };
        next.tasks.insert(descriptor.task_id.clone(), durable);
        next.logical_task_descriptors
            .insert(descriptor.task_id.clone(), descriptor);
        new_tasks = new_tasks.saturating_add(1);
        changed = true;
    }
    task_ids.sort();

    if next.migration_marker == swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_LEGACY
        && (!snapshot.state().tasks.is_empty()
            || !snapshot.state().logical_task_descriptors.is_empty())
    {
        return Err(GraphStoreError::InvalidState {
            reason: "legacy tasks require signed descriptor backfill before migration".to_string(),
        });
    }
    next.logical_time_high_water = next.logical_time_high_water.max(seed.logical_time);
    if next.migration_marker == swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_LEGACY {
        let mut update = ReasoningStateUpdate::migration_to_hypotheses(
            limits.clone(),
            next.logical_time_high_water,
        )
        .with_hypotheses(next.hypotheses)
        .with_tasks(next.tasks)
        .with_logical_task_descriptors(next.logical_task_descriptors)
        .with_terminal_outbox(next.terminal_outbox)
        .with_cross_graph_links(next.cross_graph_links)
        .with_projection_digests(
            next.result_projection_digest,
            next.operator_projection_digest,
        )
        .with_scheduler_budget(next_budget.clone());
        update = update.with_migration_marker(
            swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_HYPOTHESES,
        );
        next = GraphStoreState::with_reasoning_state(snapshot.state().clone(), update)?;
        changed = true;
    } else {
        for (task_id, task) in &next.tasks {
            if !next.task_tombstones.contains_key(task_id) {
                next.task_tombstones
                    .insert(task_id.clone(), TaskMonotonicity::from_record(task)?);
            }
        }
        next.migration_marker =
            swarm_spine::hypothesis_graph_store::GRAPH_STATE_MIGRATION_HYPOTHESES;
        next.limits = limits.clone();
    }
    next.generation = revision.generation;
    next.predecessor_digest = snapshot.state().predecessor_digest.clone();
    if new_tasks > 0 {
        let work_units = u32::try_from(new_tasks).map_err(|_| GraphStoreError::ResourceLimit {
            resource: "reasoning.tasks".to_string(),
            limit: u32::MAX as usize,
        })?;
        next_budget
            .admit_at(config, seed.logical_time, work_units, 0)
            .map_err(GraphStoreError::Admission)?;
        next.scheduler_budget = Some(next_budget.clone());
    }
    next.validate_with_limits(limits)?;
    if !changed && next != *snapshot.state() {
        changed = true;
    }
    if !changed {
        if snapshot.scheduler_budget().is_some() {
            *scheduler_budget = next_budget;
        }
        return Ok(HypothesisCoordinationResult {
            snapshot,
            hypothesis_ids,
            task_ids,
        });
    }
    let committed = store.compare_and_swap(revision, next)?;
    if let Some(budget) = committed.scheduler_budget() {
        *scheduler_budget = budget.clone();
    }
    Ok(HypothesisCoordinationResult {
        snapshot: committed,
        hypothesis_ids,
        task_ids,
    })
}

fn role_for_task_kind(kind: TaskKind) -> GraphProducerRole {
    match kind {
        TaskKind::AcquireEvidence => GraphProducerRole::Hunter,
        TaskKind::ChallengeEdge => GraphProducerRole::Challenger,
        TaskKind::FalsifyHypothesis => GraphProducerRole::Falsifier,
    }
}

fn same_logical_descriptor(left: &LogicalTaskDescriptor, right: &LogicalTaskDescriptor) -> bool {
    left.graph_id == right.graph_id
        && left.target == right.target
        && left.kind == right.kind
        && left.seed_digest == right.seed_digest
}

/// Mirror the spine's claim idempotency predicate without guessing from the
/// local ledger. This read-only hint lets an exhausted retry return the
/// durable lease without probing or charging scheduler usage.
fn claim_request_is_idempotent(snapshot: &GraphStoreSnapshot, request: &TaskClaimRequest) -> bool {
    let Some(existing) = snapshot.state().tasks.get(&request.task_id) else {
        return false;
    };
    let same_request = existing.task.request.idempotency_key == request.idempotency_key
        && existing.task.request.task_id == request.task_id
        && existing.task.request.kind == request.kind
        && existing.task.request.target == request.target
        && existing.task.request.role == request.role
        && existing.task.request.claimant == request.claimant
        && existing.task.request.evidence_scope == request.evidence_scope;
    same_request
        && matches!(
            existing.task.state,
            TaskState::Claimed | TaskState::Completed | TaskState::Failed
        )
}

/// Coordinator callers submit unsigned decision requests.  The injected
/// signer is the only production authority that can turn those requests into
/// durable facts.  A pre-witnessed value is rejected rather than accepted or
/// re-signed: accepting caller-signed records would let an unadmitted key
/// smuggle a decision through the coordinator's admission boundary.
fn sign_coordinator_decisions(
    signer: Option<&dyn GraphRecordSigner>,
    decisions: Vec<DecisionRecord>,
) -> Result<Vec<DecisionRecord>, GraphStoreError> {
    if decisions.is_empty() {
        return Ok(Vec::new());
    }
    let signer = signer.ok_or_else(|| {
        GraphStoreError::Admission(GraphAdmissionError::InvalidWitness {
            reason: "coordinator decisions require an injected admitted signer".to_string(),
        })
    })?;
    decisions
        .into_iter()
        .map(|decision| {
            if decision.witness.is_some() {
                return Err(GraphStoreError::Admission(
                    GraphAdmissionError::InvalidWitness {
                        reason: "coordinator accepts unsigned decision requests only".to_string(),
                    },
                ));
            }
            let signed = signer
                .sign_decision(decision, "hypothesis-coordinator")
                .map_err(GraphStoreError::Admission)?;
            signer
                .verify_decision(&signed)
                .map_err(GraphStoreError::Admission)?;
            Ok(signed)
        })
        .collect()
}

/// Validate the deployment-scoped logical-time and strategy-memory bounds at
/// the runtime boundary.  Core's DTO validator deliberately uses the global
/// wire maximum so it remains crate-independent; a configured runtime must
/// apply the narrower deployment value before attempting its CAS.
fn validate_configured_terminal_time(
    snapshot: &GraphStoreSnapshot,
    envelope: &TaskTerminalEnvelope,
    memory: Option<&StrategyMemory>,
    memory_expiry: Option<&StrategyMemoryExpiryEnvelope>,
    config: &HypothesisGraphConfig,
) -> Result<(), GraphStoreError> {
    config
        .validate_reasoning_limits()
        .map_err(GraphStoreError::Admission)?;
    let high_water = snapshot.state().logical_time_high_water;
    if envelope.completion.completed_at < high_water {
        return Err(GraphStoreError::Admission(
            GraphAdmissionError::InvalidTransition {
                reason: "terminal completion logical time is below the durable graph high-water"
                    .to_string(),
            },
        ));
    }
    match (memory, memory_expiry) {
        (Some(memory), Some(expiry)) => {
            memory.validate().map_err(GraphStoreError::Admission)?;
            expiry
                .validate_for_config(config)
                .map_err(GraphStoreError::Admission)?;
            expiry
                .validate_for(memory)
                .map_err(GraphStoreError::Admission)?;
            if expiry.created_at < high_water
                || expiry.created_at > envelope.completion.completed_at
            {
                return Err(GraphStoreError::Admission(
                    GraphAdmissionError::InvalidTransition {
                        reason: "strategy-memory expiry creation time is outside the terminal"
                            .to_string(),
                    },
                ));
            }
        }
        (Some(_), None) => {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidField {
                    field: "terminal_outbox.memory_expiry".to_string(),
                    reason: "strategy memory requires a configured expiry envelope".to_string(),
                },
            ));
        }
        (None, Some(_)) => {
            return Err(GraphStoreError::Admission(
                GraphAdmissionError::InvalidTransition {
                    reason: "strategy-memory expiry cannot exist without memory".to_string(),
                },
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

/// Commit one already-validated terminal publication.  This is intentionally
/// a public production seam so role adapters and independent tests exercise
/// the same one-CAS path.  The function never writes an external memory store:
/// evidence, decision history, task terminal proof, and outbox are assembled
/// from one snapshot and become visible together.
pub fn commit_terminal_once(
    store: &dyn HypothesisGraphStore,
    revision: &GraphStoreRevision,
    claim: &TaskClaim,
    mut publication: TaskTerminalOutboxEntry,
) -> Result<GraphStoreSnapshot, GraphStoreError> {
    let snapshot = store.snapshot()?;
    if snapshot.revision() != revision {
        return Err(GraphStoreError::StalePredecessor {
            expected_generation: revision.generation,
            expected_digest: revision.digest.clone(),
            observed_generation: snapshot.revision().generation,
            observed_digest: snapshot.revision().digest.clone(),
        });
    }
    let entry = snapshot.state().tasks.get(&claim.task_id).ok_or_else(|| {
        GraphStoreError::TaskNotFound {
            task_id: claim.task_id.to_string(),
        }
    })?;
    let descriptor = snapshot
        .state()
        .logical_task_descriptors
        .get(&claim.task_id)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "task has no persisted logical descriptor".to_string(),
        })?;
    let lease = entry
        .task
        .lease
        .as_ref()
        .ok_or_else(|| GraphStoreError::InvalidTransition {
            reason: "terminal admission requires the active task lease".to_string(),
        })?;
    if claim.idempotency_key != entry.task.request.idempotency_key
        || claim.claimant != entry.task.request.claimant
        || claim.capability != entry.task.request.kind
        || claim.lease_id != lease.lease_id
        || claim.fencing_token != lease.fencing_token
    {
        return Err(GraphStoreError::InvalidTransition {
            reason: "runtime claim does not bind the active durable task".to_string(),
        });
    }
    claim
        .capability_proof
        .validate_for_claim(&entry.task.request)
        .map_err(GraphStoreError::Admission)?;
    publication
        .validate_for_task_at(
            &entry.task,
            descriptor,
            &snapshot.state().limits,
            snapshot.state().logical_time_high_water,
        )
        .map_err(GraphStoreError::Admission)?;
    validate_completion_kind(
        entry.task.request.kind,
        publication.envelope.completion.kind.clone(),
    )
    .map_err(GraphStoreError::Admission)?;
    if publication.envelope.capability != claim.capability_proof {
        return Err(GraphStoreError::InvalidState {
            reason: "terminal capability differs from claimed capability".to_string(),
        });
    }
    if publication.producer_key_id != claim.claimant {
        return Err(GraphStoreError::InvalidState {
            reason: "terminal outbox producer is not the claimed key".to_string(),
        });
    }

    let mut next = snapshot.state().clone();
    let mut durable = entry.clone();
    durable.task = entry
        .task
        .clone()
        .complete(
            publication.envelope.completion.clone(),
            publication.envelope.fencing_token,
            next.limits.max_task_lease_ms,
        )
        .map_err(GraphStoreError::Admission)?;
    durable.generation =
        durable
            .generation
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "task wrapper generation overflow".to_string(),
            })?;
    next.tasks.insert(claim.task_id.clone(), durable);
    let updated = next
        .tasks
        .get(&claim.task_id)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "updated task disappeared before tombstone admission".to_string(),
        })?;
    next.task_tombstones.insert(
        claim.task_id.clone(),
        TaskMonotonicity::from_record(updated)?,
    );

    for item in &publication.evidence {
        next.graph
            .admit_evidence(item.clone())
            .map_err(GraphStoreError::Admission)?;
    }
    if let Some(decision) = publication.decision.clone() {
        if let Some(link) = &publication.envelope.decision_link {
            match &link.target {
                TaskTarget::Edge { edge_id } => {
                    if !next.graph.edges.contains_key(edge_id) {
                        return Err(GraphStoreError::Admission(
                            GraphAdmissionError::InvalidTransition {
                                reason: "terminal challenge targets an unknown edge".to_string(),
                            },
                        ));
                    }
                    let hypothesis =
                        next.hypotheses
                            .get(&decision.hypothesis_id)
                            .ok_or_else(|| GraphStoreError::InvalidState {
                                reason: "terminal decision targets an unknown hypothesis"
                                    .to_string(),
                            })?;
                    if !hypothesis.claims.contains(edge_id) {
                        return Err(GraphStoreError::Admission(
                            GraphAdmissionError::InvalidTransition {
                                reason: "challenged edge is not claimed by the decision hypothesis"
                                    .to_string(),
                            },
                        ));
                    }
                }
                TaskTarget::Hypothesis { hypothesis_id } => {
                    if hypothesis_id != &decision.hypothesis_id {
                        return Err(GraphStoreError::InvalidState {
                            reason: "terminal decision hypothesis does not match task target"
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
        // `publication.validate_for_task_at` above authenticates the worker
        // decision through the claimed capability, producer key, lease, and
        // fence. Evidence-witness admission applies to coordinator decisions;
        // a terminal challenger/falsifier is intentionally a different actor.
        let hypothesis = next
            .hypotheses
            .get(&decision.hypothesis_id)
            .cloned()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "terminal decision targets an unknown hypothesis".to_string(),
            })?;
        let updated = hypothesis
            .append_decision(decision)
            .map_err(GraphStoreError::Admission)?;
        // `append_decision` assigns the durable sequence number.  Retain the
        // exact sequenced value in the outbox as well; storing the caller's
        // pre-append sequence-zero value would make reload validation report
        // that the publication is absent from hypothesis history.
        publication.decision = updated.decision_history.last().cloned();
        next.hypotheses
            .insert(updated.hypothesis_id.clone(), updated);
    }
    next.terminal_outbox
        .insert(claim.task_id.clone(), publication);
    next.logical_time_high_water = next
        .logical_time_high_water
        .max(updated_completion_time(&next, claim.task_id.as_str())?);
    next.generation = revision.generation;
    next.predecessor_digest = snapshot.state().predecessor_digest.clone();
    store.compare_and_swap(revision, next)
}

fn updated_completion_time(
    state: &GraphStoreState,
    task_id: &str,
) -> Result<GraphLogicalTime, GraphStoreError> {
    state
        .task(task_id)
        .and_then(|task| task.task.completion.as_ref())
        .map(|completion| completion.completed_at)
        .ok_or_else(|| GraphStoreError::InvalidState {
            reason: "terminal task has no completion after transition".to_string(),
        })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hypothesis_graph::{
        HypothesisDisposition, HypothesisSeedAssessment, KeypairGraphRecordSigner, WitnessAdmission,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use swarm_core::hypothesis_graph::{
        EvidenceClock, EvidenceEnvelope, EvidenceSourceFamily, EvidenceUtility, HypothesisDelta,
        MemoryOutcome, MemoryProvenance, OrderingClaim, SourceLineage, StrategyMemory,
        StrategyMemoryExpiryEnvelope, TaskCompletion, TaskCompletionKind, TypedEvidencePayload,
    };
    use swarm_spine::HypothesisGraphStore;
    use swarm_spine::hypothesis_graph_store::{
        MemoryHypothesisGraphStore, TaskClaimResult, TaskFailure, TaskMutationResult,
        TaskTerminalResult,
    };

    fn key(seed: u8) -> swarm_crypto::Keypair {
        swarm_crypto::Keypair::from_seed(&[seed; 32])
    }

    fn evidence_task_request(
        graph_id: &swarm_core::hypothesis_graph::GraphId,
        label: &str,
        claimant_seed: u8,
        logical_tick: i64,
    ) -> (
        LogicalTaskDescriptor,
        TaskClaimRequest,
        swarm_crypto::Keypair,
    ) {
        let evidence_id =
            swarm_core::hypothesis_graph::EvidenceId::new(format!("evidence:{label}"));
        let target = TaskTarget::Evidence {
            evidence_id: evidence_id.clone(),
        };
        let descriptor = LogicalTaskDescriptor::new(
            graph_id.clone(),
            target.clone(),
            TaskKind::AcquireEvidence,
            "00".repeat(32),
        )
        .unwrap();
        let claimant_key = key(claimant_seed);
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target,
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&claimant_key.public_key().to_hex()),
            EvidenceScope::new([], [evidence_id], []).unwrap(),
            GraphLogicalTime::new(logical_tick),
        )
        .unwrap();
        (descriptor, request, claimant_key)
    }

    struct ForcedCasStore {
        inner: MemoryHypothesisGraphStore,
        cas_attempts: Arc<AtomicUsize>,
        reject_cas: Arc<std::sync::atomic::AtomicBool>,
    }

    impl ForcedCasStore {
        fn new(
            graph: swarm_core::hypothesis_graph::HypothesisGraph,
            signer: swarm_crypto::Keypair,
            config: &HypothesisGraphConfig,
        ) -> Self {
            Self {
                inner: MemoryHypothesisGraphStore::new_with_config(graph, signer, config).unwrap(),
                cas_attempts: Arc::new(AtomicUsize::new(0)),
                reject_cas: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            }
        }

        fn cas_attempts(&self) -> usize {
            self.cas_attempts.load(Ordering::SeqCst)
        }

        fn set_reject_cas(&self, reject: bool) {
            self.reject_cas.store(reject, Ordering::SeqCst);
        }
    }

    impl HypothesisGraphStore for ForcedCasStore {
        fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
            self.inner.snapshot()
        }

        fn compare_and_swap(
            &self,
            expected: &GraphStoreRevision,
            _state: GraphStoreState,
        ) -> Result<GraphStoreSnapshot, GraphStoreError> {
            self.cas_attempts.fetch_add(1, Ordering::SeqCst);
            if !self.reject_cas.load(Ordering::SeqCst) {
                return self.inner.compare_and_swap(expected, _state);
            }
            Err(GraphStoreError::StalePredecessor {
                expected_generation: expected.generation,
                expected_digest: expected.digest.clone(),
                observed_generation: expected.generation,
                observed_digest: expected.digest.clone(),
            })
        }

        fn create_task(
            &self,
            request: TaskClaimRequest,
        ) -> Result<TaskMutationResult, GraphStoreError> {
            self.inner.create_task(request)
        }

        fn create_task_cas(
            &self,
            expected: &GraphStoreRevision,
            request: TaskClaimRequest,
        ) -> Result<TaskMutationResult, GraphStoreError> {
            self.inner.create_task_cas(expected, request)
        }

        fn claim_task(
            &self,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner.claim_task(request, now, lease_duration_ms)
        }

        fn claim_task_cas(
            &self,
            expected: &GraphStoreRevision,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner
                .claim_task_cas(expected, request, now, lease_duration_ms)
        }

        fn claim_task_with_budget(
            &self,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
            scheduler_budget: SchedulerBudget,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner
                .claim_task_with_budget(request, now, lease_duration_ms, scheduler_budget)
        }

        fn claim_task_cas_with_budget(
            &self,
            expected: &GraphStoreRevision,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
            scheduler_budget: SchedulerBudget,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.cas_attempts.fetch_add(1, Ordering::SeqCst);
            if self.reject_cas.load(Ordering::SeqCst) {
                return Err(GraphStoreError::StalePredecessor {
                    expected_generation: expected.generation,
                    expected_digest: expected.digest.clone(),
                    observed_generation: expected.generation,
                    observed_digest: expected.digest.clone(),
                });
            }
            self.inner.claim_task_cas_with_budget(
                expected,
                request,
                now,
                lease_duration_ms,
                scheduler_budget,
            )
        }

        fn renew_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            lease_id: &swarm_core::hypothesis_graph::LeaseId,
            fence: FencingToken,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskMutationResult, GraphStoreError> {
            self.inner.renew_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                lease_duration_ms,
            )
        }

        fn complete_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            lease_id: &swarm_core::hypothesis_graph::LeaseId,
            fence: FencingToken,
            now: GraphLogicalTime,
            completion: swarm_core::hypothesis_graph::TaskCompletion,
        ) -> Result<TaskTerminalResult, GraphStoreError> {
            self.inner.complete_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                completion,
            )
        }

        fn fail_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            lease_id: &swarm_core::hypothesis_graph::LeaseId,
            fence: FencingToken,
            now: GraphLogicalTime,
            failure: TaskFailure,
        ) -> Result<TaskTerminalResult, GraphStoreError> {
            self.inner
                .fail_task(task_id, expected_generation, lease_id, fence, now, failure)
        }

        fn expire_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            now: GraphLogicalTime,
        ) -> Result<TaskTerminalResult, GraphStoreError> {
            self.inner.expire_task(task_id, expected_generation, now)
        }

        fn reclaim_task(
            &self,
            task_id: &str,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner
                .reclaim_task(task_id, request, now, lease_duration_ms)
        }
    }

    /// Deliberately omits the budget-bearing methods so the trait's fail-closed
    /// defaults are exercised against a custom backend.
    struct UnsupportedBudgetStore {
        inner: ForcedCasStore,
    }

    impl UnsupportedBudgetStore {
        fn new(
            graph: swarm_core::hypothesis_graph::HypothesisGraph,
            signer: swarm_crypto::Keypair,
            config: &HypothesisGraphConfig,
        ) -> Self {
            Self {
                inner: ForcedCasStore::new(graph, signer, config),
            }
        }

        fn set_reject_cas(&self, reject: bool) {
            self.inner.set_reject_cas(reject);
        }
    }

    impl HypothesisGraphStore for UnsupportedBudgetStore {
        fn snapshot(&self) -> Result<GraphStoreSnapshot, GraphStoreError> {
            self.inner.snapshot()
        }

        fn compare_and_swap(
            &self,
            expected: &GraphStoreRevision,
            state: GraphStoreState,
        ) -> Result<GraphStoreSnapshot, GraphStoreError> {
            self.inner.compare_and_swap(expected, state)
        }

        fn create_task(
            &self,
            request: TaskClaimRequest,
        ) -> Result<TaskMutationResult, GraphStoreError> {
            self.inner.create_task(request)
        }

        fn create_task_cas(
            &self,
            expected: &GraphStoreRevision,
            request: TaskClaimRequest,
        ) -> Result<TaskMutationResult, GraphStoreError> {
            self.inner.create_task_cas(expected, request)
        }

        fn claim_task(
            &self,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner.claim_task(request, now, lease_duration_ms)
        }

        fn claim_task_cas(
            &self,
            expected: &GraphStoreRevision,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner
                .claim_task_cas(expected, request, now, lease_duration_ms)
        }

        fn renew_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            lease_id: &swarm_core::hypothesis_graph::LeaseId,
            fence: FencingToken,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskMutationResult, GraphStoreError> {
            self.inner.renew_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                lease_duration_ms,
            )
        }

        fn complete_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            lease_id: &swarm_core::hypothesis_graph::LeaseId,
            fence: FencingToken,
            now: GraphLogicalTime,
            completion: swarm_core::hypothesis_graph::TaskCompletion,
        ) -> Result<TaskTerminalResult, GraphStoreError> {
            self.inner.complete_task(
                task_id,
                expected_generation,
                lease_id,
                fence,
                now,
                completion,
            )
        }

        fn fail_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            lease_id: &swarm_core::hypothesis_graph::LeaseId,
            fence: FencingToken,
            now: GraphLogicalTime,
            failure: TaskFailure,
        ) -> Result<TaskTerminalResult, GraphStoreError> {
            self.inner
                .fail_task(task_id, expected_generation, lease_id, fence, now, failure)
        }

        fn expire_task(
            &self,
            task_id: &str,
            expected_generation: u64,
            now: GraphLogicalTime,
        ) -> Result<TaskTerminalResult, GraphStoreError> {
            self.inner.expire_task(task_id, expected_generation, now)
        }

        fn reclaim_task(
            &self,
            task_id: &str,
            request: TaskClaimRequest,
            now: GraphLogicalTime,
            lease_duration_ms: u64,
        ) -> Result<TaskClaimResult, GraphStoreError> {
            self.inner
                .reclaim_task(task_id, request, now, lease_duration_ms)
        }
    }

    #[test]
    fn failed_budget_probe_is_byte_identical() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 3,
            max_claims_per_tick: 1,
            ..HypothesisGraphConfig::default()
        };
        let tick = GraphLogicalTime::new(10);
        let ledger = HypothesisTaskLedger::from_config(&config, tick).unwrap();
        let before = ledger.scheduler_budget().clone();
        let mut probe = before.clone();
        assert!(probe.admit_at(&config, tick, 4, 0).is_err());
        assert_eq!(ledger.scheduler_budget(), &before);
    }

    #[test]
    fn custom_scheduler_store_rejects_mismatched_deployment_policy() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 3,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let mismatched_config = HypothesisGraphConfig {
            max_work_units_per_tick: 5,
            max_claims_per_tick: 3,
            ..config.clone()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:policy-mismatch");
        let graph =
            swarm_core::hypothesis_graph::HypothesisGraph::new(graph_id, config.resource_limits())
                .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(70), &config).unwrap();
        let initial = store.snapshot().unwrap();
        let candidate = GraphStoreState::with_reasoning_state(
            initial.state().clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                config.resource_limits(),
                GraphLogicalTime::new(10),
            )
            .with_scheduler_budget(
                SchedulerBudget::new_with_config(&mismatched_config, GraphLogicalTime::new(10))
                    .unwrap(),
            ),
        )
        .unwrap();
        let initial_bytes = initial.canonical_bytes().unwrap();
        let error = store
            .compare_and_swap(initial.revision(), candidate)
            .unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::InvalidState { reason }
                if reason.contains("scheduler budget policy identity")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            initial_bytes
        );
    }

    #[test]
    fn restart_and_state_deserialize_restore_budget_without_reset() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 3,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:budget-restart");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(50), &config).unwrap();
        let (descriptor_one, request_one, _) =
            evidence_task_request(&graph_id, "budget-restart-one", 51, 10);
        let (descriptor_two, request_two, _) =
            evidence_task_request(&graph_id, "budget-restart-two", 52, 10);
        let (descriptor_three, request_three, _) =
            evidence_task_request(&graph_id, "budget-restart-three", 53, 10);
        let (descriptor_four, request_four, _) =
            evidence_task_request(&graph_id, "budget-restart-four", 54, 10);

        let initial = store.snapshot().unwrap();
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let first = ledger
            .create_task(&store, initial.revision(), descriptor_one, request_one)
            .unwrap();
        let persisted_budget = first.scheduler_budget().cloned().unwrap();
        assert_eq!(persisted_budget.current_tick(), GraphLogicalTime::new(10));
        assert_eq!(persisted_budget.work_units_used(), 1);

        // The wire round-trip carries usage, rather than reconstructing a
        // fresh zeroed budget from the deployment config.
        let encoded = serde_json::to_vec(first.state()).unwrap();
        let decoded: GraphStoreState = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.scheduler_budget, Some(persisted_budget.clone()));

        let mut restarted =
            HypothesisTaskLedger::from_store(&config, GraphLogicalTime::new(10), &store).unwrap();
        assert_eq!(restarted.scheduler_budget(), &persisted_budget);
        let restored = restarted.restore_from_store(&store).unwrap();
        assert_eq!(restored.scheduler_budget(), Some(&persisted_budget));

        let second = restarted
            .create_task(&store, first.revision(), descriptor_two, request_two)
            .unwrap();
        assert_eq!(second.scheduler_budget().unwrap().work_units_used(), 2);
        let third = restarted
            .create_task(&store, second.revision(), descriptor_three, request_three)
            .unwrap();
        assert_eq!(third.scheduler_budget().unwrap().work_units_used(), 3);
        let before_exhausted = third.canonical_bytes().unwrap();
        let budget_before_exhausted = restarted.scheduler_budget().clone();
        assert!(
            restarted
                .create_task(&store, third.revision(), descriptor_four, request_four,)
                .is_err()
        );
        assert_eq!(restarted.scheduler_budget(), &budget_before_exhausted);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_exhausted
        );

        // A newer logical tick resets usage only as part of a successful
        // durable admission; the reset and the new unit share one CAS.
        let (descriptor_next_tick, request_next_tick, _) =
            evidence_task_request(&graph_id, "budget-restart-next-tick", 55, 11);
        let reset = restarted
            .create_task(
                &store,
                third.revision(),
                descriptor_next_tick,
                request_next_tick,
            )
            .unwrap();
        let reset_budget = reset.scheduler_budget().unwrap();
        assert_eq!(reset_budget.current_tick(), GraphLogicalTime::new(11));
        assert_eq!(reset_budget.work_units_used(), 1);
        assert_eq!(restarted.scheduler_budget(), reset_budget);
    }

    #[test]
    fn restart_preserves_claim_usage_and_idempotent_retry_does_not_recharge() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 8,
            max_claims_per_tick: 1,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:claim-restart");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(55), &config).unwrap();
        let (descriptor_one, request_one, claimant_one_key) =
            evidence_task_request(&graph_id, "claim-restart-one", 56, 10);
        let (descriptor_two, request_two, claimant_two_key) =
            evidence_task_request(&graph_id, "claim-restart-two", 57, 10);
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let initial = store.snapshot().unwrap();
        let first = ledger
            .create_task(
                &store,
                initial.revision(),
                descriptor_one,
                request_one.clone(),
            )
            .unwrap();
        let second = ledger
            .create_task(
                &store,
                first.revision(),
                descriptor_two,
                request_two.clone(),
            )
            .unwrap();
        let created_budget = second.scheduler_budget().cloned().unwrap();
        assert_eq!(created_budget.work_units_used(), 2);
        assert_eq!(created_budget.claims_used(), 0);
        let capability_one = TaskCapabilityProof::signed_with(
            request_one.task_id.clone(),
            request_one.claimant.clone(),
            request_one.role,
            request_one.kind,
            request_one.canonical_digest().unwrap(),
            &claimant_one_key,
            "hunter:claim-restart-one",
        )
        .unwrap();
        let claimed = ledger
            .claim_task(
                &store,
                request_one.clone(),
                GraphLogicalTime::new(10),
                1_000,
                capability_one.clone(),
            )
            .unwrap();
        let persisted = store.snapshot().unwrap();
        let persisted_budget = persisted.scheduler_budget().cloned().unwrap();
        assert_eq!(
            persisted_budget.work_units_used(),
            created_budget.work_units_used()
        );
        assert_eq!(
            persisted_budget.claims_used(),
            created_budget.claims_used() + 1
        );

        let mut restarted =
            HypothesisTaskLedger::from_store(&config, GraphLogicalTime::new(10), &store).unwrap();
        assert_eq!(restarted.scheduler_budget(), &persisted_budget);
        let before_retry = persisted.canonical_bytes().unwrap();
        let retried = restarted
            .claim_task(
                &store,
                request_one,
                GraphLogicalTime::new(10),
                1_000,
                capability_one,
            )
            .unwrap();
        assert_eq!(retried, claimed);
        assert_eq!(restarted.scheduler_budget(), &persisted_budget);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_retry
        );

        let capability_two = TaskCapabilityProof::signed_with(
            request_two.task_id.clone(),
            request_two.claimant.clone(),
            request_two.role,
            request_two.kind,
            request_two.canonical_digest().unwrap(),
            &claimant_two_key,
            "hunter:claim-restart-two",
        )
        .unwrap();
        let before_exhausted = store.snapshot().unwrap().canonical_bytes().unwrap();
        let budget_before_exhausted = restarted.scheduler_budget().clone();
        assert!(
            restarted
                .claim_task(
                    &store,
                    request_two,
                    GraphLogicalTime::new(10),
                    1_000,
                    capability_two,
                )
                .is_err()
        );
        assert_eq!(restarted.scheduler_budget(), &budget_before_exhausted);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_exhausted
        );
        assert_eq!(second.state().tasks.len(), 2);
    }

    #[test]
    fn unsupported_budget_backend_fails_closed_without_mutation() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 4,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:unsupported-budget");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = UnsupportedBudgetStore::new(graph, key(58), &config);
        store.set_reject_cas(false);
        let (descriptor, request, claimant_key) =
            evidence_task_request(&graph_id, "unsupported-budget", 59, 10);
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let initial = store.snapshot().unwrap();
        let created = ledger
            .create_task(&store, initial.revision(), descriptor, request.clone())
            .unwrap();
        let before = created.canonical_bytes().unwrap();
        let budget_before = ledger.scheduler_budget().clone();
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "hunter:unsupported-budget",
        )
        .unwrap();
        let error = ledger
            .claim_task(
                &store,
                request,
                GraphLogicalTime::new(10),
                1_000,
                capability,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::InvalidTransition { reason }
                if reason.contains("atomic claim-plus-budget")
        ));
        assert_eq!(ledger.scheduler_budget(), &budget_before);
        assert_eq!(store.snapshot().unwrap().canonical_bytes().unwrap(), before);
    }

    #[test]
    fn forced_task_cas_refusal_rolls_back_budget() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 4,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:cas-budget");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = ForcedCasStore::new(graph, key(22), &config);
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        // The store rejects its CAS after the scheduler probe, proving
        // counters publish only after durable admission succeeds.
        let target = TaskTarget::Evidence {
            evidence_id: swarm_core::hypothesis_graph::EvidenceId::new("evidence:cas-budget"),
        };
        let descriptor = LogicalTaskDescriptor::new(
            graph_id.clone(),
            target.clone(),
            TaskKind::AcquireEvidence,
            "00".repeat(32),
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target,
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&key(23).public_key().to_hex()),
            EvidenceScope::new(
                [],
                [swarm_core::hypothesis_graph::EvidenceId::new(
                    "evidence:cas-budget",
                )],
                [],
            )
            .unwrap(),
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let before = store.snapshot().unwrap();
        let before_bytes = before.canonical_bytes().unwrap();
        let budget_before = ledger.scheduler_budget().clone();
        assert!(
            ledger
                .create_task(&store, before.revision(), descriptor, request)
                .is_err()
        );
        assert_eq!(ledger.scheduler_budget(), &budget_before);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
    }

    #[test]
    fn forced_claim_cas_refusal_rolls_back_budget() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 4,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:cas-claim-budget");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = ForcedCasStore::new(graph, key(60), &config);
        let (descriptor, request, claimant_key) =
            evidence_task_request(&graph_id, "cas-claim-budget", 61, 10);
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let initial = store.snapshot().unwrap();
        store.set_reject_cas(false);
        ledger
            .create_task(&store, initial.revision(), descriptor, request.clone())
            .unwrap();
        let before = store.snapshot().unwrap();
        let before_bytes = before.canonical_bytes().unwrap();
        let budget_before = ledger.scheduler_budget().clone();
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "hunter:cas-claim-budget",
        )
        .unwrap();
        store.set_reject_cas(true);
        let error = ledger
            .claim_task(
                &store,
                request,
                GraphLogicalTime::new(10),
                1_000,
                capability,
            )
            .unwrap_err();
        assert!(matches!(error, GraphStoreError::StalePredecessor { .. }));
        assert_eq!(ledger.scheduler_budget(), &budget_before);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
    }

    #[test]
    fn forced_terminal_cas_refusal_after_validation_is_byte_identical() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 8,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:terminal-cas-refusal");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = ForcedCasStore::new(graph, key(32), &config);
        let claimant_key = key(33);
        let claimant = AgentId::from_public_key_hex(&claimant_key.public_key().to_hex());
        let evidence = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "process-sensor",
            SourceLineage::new("normalizer", "terminal:evidence").unwrap(),
            EvidenceClock::observed(GraphLogicalTime::new(150)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Process {
                signal_kind: "process_start".to_string(),
                process_digest: "process:digest".to_string(),
                parent_process_digest: None,
                entity_ids: Vec::new(),
                content_digest: "content:digest".to_string(),
            },
        )
        .unwrap()
        .sign_with(
            &claimant_key,
            GraphProducerRole::Normalizer,
            "normalizer:terminal",
        )
        .unwrap();
        let target = TaskTarget::Evidence {
            evidence_id: evidence.evidence_id.clone(),
        };
        let descriptor = LogicalTaskDescriptor::new(
            graph_id.clone(),
            target.clone(),
            TaskKind::AcquireEvidence,
            "00".repeat(32),
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target,
            GraphProducerRole::Hunter,
            claimant.clone(),
            EvidenceScope::new(
                [EvidenceSourceFamily::Process],
                [evidence.evidence_id.clone()],
                [],
            )
            .unwrap(),
            GraphLogicalTime::new(100),
        )
        .unwrap();
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(100)).unwrap();

        // Allow only setup CAS operations.  The terminal operation below is
        // forced to refuse after all runtime and publication validation has
        // completed, so this is not a stale-before-validation control.
        let initial = store.snapshot().unwrap();
        store.set_reject_cas(false);
        ledger
            .create_task(&store, initial.revision(), descriptor, request.clone())
            .unwrap();
        store.set_reject_cas(false);
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "hunter:terminal",
        )
        .unwrap();
        let claim = ledger
            .claim_task(
                &store,
                request.clone(),
                GraphLogicalTime::new(100),
                1_000,
                capability,
            )
            .unwrap();
        store.set_reject_cas(true);
        let before = store.snapshot().unwrap();
        let before_bytes = before.canonical_bytes().unwrap();
        let cas_before = store.cas_attempts();

        let provenance = MemoryProvenance::new(claimant.clone(), [evidence.evidence_id.clone()])
            .signed_with(
                &claimant_key,
                GraphProducerRole::Hunter,
                "hunter:memory-provenance",
            )
            .unwrap();
        let memory = StrategyMemory::new(
            graph_id,
            swarm_core::hypothesis_graph::HypothesisId::new("hypothesis:memory"),
            HypothesisDelta::new([], [], []),
            [EvidenceUtility::new(evidence.evidence_id.clone(), 5_000)],
            [],
            MemoryOutcome::Inconclusive,
            provenance,
        )
        .unwrap()
        .signed_with(&claimant_key, GraphProducerRole::Hunter, "hunter:memory")
        .unwrap();
        let expiry = StrategyMemoryExpiryEnvelope::new_with_config(
            &memory,
            GraphLogicalTime::new(200),
            10,
            &config,
            &claimant_key,
        )
        .unwrap();
        let envelope = TaskTerminalEnvelope::new(
            claim.task_id.clone(),
            claim.idempotency_key.clone(),
            claim.lease_id.clone(),
            claim.fencing_token,
            TaskCompletion::new(
                TaskCompletionKind::EvidenceAdded,
                claimant.clone(),
                GraphLogicalTime::new(200),
                [evidence.evidence_id.clone()],
                "00".repeat(32),
            )
            .unwrap(),
            None,
            claimant,
            claim.capability_proof.clone(),
        )
        .unwrap()
        .signed_with(&claimant_key, "hunter:terminal")
        .unwrap();

        let error = ledger
            .accept_terminal_once(
                &store,
                before.revision(),
                &claim,
                envelope,
                vec![evidence.clone()],
                None,
                Some(memory.clone()),
                Some(expiry.clone()),
            )
            .unwrap_err();
        assert!(matches!(error, GraphStoreError::StalePredecessor { .. }));
        assert_eq!(store.cas_attempts(), cas_before + 1);

        let after = store.snapshot().unwrap();
        assert_eq!(after.canonical_bytes().unwrap(), before_bytes);
        let durable_task = after.state().tasks.get(&claim.task_id).unwrap();
        assert_eq!(durable_task.task.state, TaskState::Claimed);
        assert!(durable_task.task.terminal_history.is_empty());
        assert!(after.state().graph.evidence.is_empty());
        assert!(after.state().terminal_outbox.is_empty());
        // The publication carried real evidence and memory.  Their absence
        // after the forced CAS refusal proves they were not admitted early.
        assert_eq!(memory.evidence_utility.len(), 1);
        assert_eq!(expiry.expires_at, GraphLogicalTime::new(210));
    }

    #[test]
    fn rejected_claim_does_not_charge_budget() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 4,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:claim-budget");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(24), &config).unwrap();
        let claimant_key = key(25);
        let target = TaskTarget::Evidence {
            evidence_id: swarm_core::hypothesis_graph::EvidenceId::new("evidence:claim-budget"),
        };
        let descriptor = LogicalTaskDescriptor::new(
            graph_id,
            target.clone(),
            TaskKind::AcquireEvidence,
            "00".repeat(32),
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target,
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&claimant_key.public_key().to_hex()),
            EvidenceScope::new(
                [],
                [swarm_core::hypothesis_graph::EvidenceId::new(
                    "evidence:claim-budget",
                )],
                [],
            )
            .unwrap(),
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let initial = store.snapshot().unwrap();
        let created = ledger
            .create_task(&store, initial.revision(), descriptor, request.clone())
            .unwrap();
        let budget_before = ledger.scheduler_budget().clone();
        let state_before = created.canonical_bytes().unwrap();
        let capability = TaskCapabilityProof::signed_with(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "hunter:claim-budget",
        )
        .unwrap();
        assert!(
            ledger
                .claim_task(&store, request, GraphLogicalTime::new(10), 0, capability,)
                .is_err()
        );
        assert_eq!(ledger.scheduler_budget(), &budget_before);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            state_before
        );
    }

    #[test]
    fn descriptor_identity_excludes_claimant_retry_fields() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 8,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:descriptor");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(19), &config).unwrap();
        let evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:descriptor");
        let target = TaskTarget::Evidence {
            evidence_id: evidence_id.clone(),
        };
        let descriptor = LogicalTaskDescriptor::new(
            graph_id,
            target.clone(),
            TaskKind::AcquireEvidence,
            "00".repeat(32),
        )
        .unwrap();
        let first_request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target.clone(),
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&key(20).public_key().to_hex()),
            EvidenceScope::new([], [evidence_id.clone()], []).unwrap(),
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let retry_request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            TaskKind::AcquireEvidence,
            target,
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&key(21).public_key().to_hex()),
            EvidenceScope::new([], [evidence_id], []).unwrap(),
            GraphLogicalTime::new(11),
        )
        .unwrap();
        assert_ne!(
            first_request.idempotency_key, retry_request.idempotency_key,
            "retry keys remain claimant-scoped, not logical identity"
        );
        let initial = store.snapshot().unwrap();
        let admitted =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let mut ledger = admitted;
        let first = ledger
            .create_task(
                &store,
                initial.revision(),
                descriptor.clone(),
                first_request,
            )
            .unwrap();
        let budget_after_first = ledger.scheduler_budget().clone();
        let retried = ledger
            .create_task(&store, first.revision(), descriptor, retry_request)
            .unwrap();
        assert_eq!(retried, first);
        assert_eq!(ledger.scheduler_budget(), &budget_after_first);
    }

    #[test]
    fn coordinator_durably_commits_competing_tasks_once() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 3,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:coordinator-unit");
        let mut graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let coordinator_key = key(17);
        let actor = swarm_core::hypothesis_graph::ActorNode::new("actor:digest", "actor").unwrap();
        let asset = swarm_core::hypothesis_graph::AssetNode::new("asset:digest", "asset").unwrap();
        graph
            .admit_node(swarm_core::hypothesis_graph::GraphNode::Actor(
                actor.clone(),
            ))
            .unwrap();
        graph
            .admit_node(swarm_core::hypothesis_graph::GraphNode::Asset(
                asset.clone(),
            ))
            .unwrap();
        let evidence = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "coordinator-sensor",
            SourceLineage::new("normalizer", "coordinator:evidence").unwrap(),
            EvidenceClock::observed(GraphLogicalTime::new(10)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Process {
                signal_kind: "process_start".to_string(),
                process_digest: "coordinator:process".to_string(),
                parent_process_digest: None,
                entity_ids: vec![actor.node_id.clone(), asset.node_id.clone()],
                content_digest: "coordinator:content".to_string(),
            },
        )
        .unwrap()
        .sign_with(
            &coordinator_key,
            GraphProducerRole::Normalizer,
            "normalizer:coordinator",
        )
        .unwrap();
        let evidence_id = evidence.evidence_id.clone();
        graph.admit_evidence(evidence).unwrap();
        let edge = swarm_core::hypothesis_graph::CausalEdge::new(
            &actor.node_id,
            &asset.node_id,
            swarm_core::hypothesis_graph::CausalRelation::Contacts,
            5_000,
            [evidence_id.clone()],
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&coordinator_key.public_key().to_hex()),
            GraphLogicalTime::new(10),
            swarm_core::hypothesis_graph::EdgeState::Proposed,
        )
        .unwrap()
        .signed_with(&coordinator_key, "hunter:coordinator")
        .unwrap();
        graph.admit_edge(edge).unwrap();
        let store =
            MemoryHypothesisGraphStore::new_with_config(graph, coordinator_key, &config).unwrap();
        let first_hypothesis = HypothesisId::new("hypothesis:one");
        let second_hypothesis = HypothesisId::new("hypothesis:two");
        let seed = HypothesisSeedInput::new(
            graph_id,
            vec![first_hypothesis.clone(), second_hypothesis.clone()],
            vec![
                HypothesisSeedAssessment {
                    hypothesis_id: first_hypothesis,
                    evidence_ids: vec![evidence_id.clone()],
                    disposition: HypothesisDisposition::Unresolved,
                    provenance: evidence_id.clone(),
                },
                HypothesisSeedAssessment {
                    hypothesis_id: second_hypothesis,
                    evidence_ids: vec![evidence_id.clone()],
                    disposition: HypothesisDisposition::Contradicts,
                    provenance: evidence_id.clone(),
                },
            ],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [evidence_id],
            [actor.node_id, asset.node_id],
        )
        .unwrap();
        let signer_key = key(18);
        let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
        let signer = KeypairGraphRecordSigner::with_admission(
            signer_key.clone(),
            &WitnessAdmission::from_key(&signer_key),
        )
        .unwrap();
        let mut coordinator =
            DurableHypothesisCoordinator::new(&config, GraphLogicalTime::new(10), signer).unwrap();
        let initial = store.snapshot().unwrap();
        let first = coordinator
            .coordinate_seed(
                &store,
                initial.revision(),
                &seed,
                claimant.clone(),
                scope.clone(),
            )
            .unwrap();
        assert_eq!(first.hypothesis_ids.len(), 2);
        assert_eq!(first.task_ids.len(), 3);
        assert_eq!(first.snapshot.state().hypotheses.len(), 2);
        assert_eq!(first.snapshot.state().tasks.len(), 3);
        let task_kinds = first
            .snapshot
            .state()
            .tasks
            .values()
            .map(|entry| entry.task.request.kind)
            .collect::<BTreeSet<_>>();
        assert!(task_kinds.contains(&TaskKind::AcquireEvidence));
        assert!(task_kinds.contains(&TaskKind::ChallengeEdge));
        assert!(task_kinds.contains(&TaskKind::FalsifyHypothesis));
        assert_eq!(coordinator.ledger().scheduler_budget().work_units_used(), 3);

        let retried = coordinator
            .coordinate_seed(&store, first.snapshot.revision(), &seed, claimant, scope)
            .unwrap();
        assert_eq!(retried.snapshot.revision(), first.snapshot.revision());
        assert_eq!(coordinator.ledger().scheduler_budget().work_units_used(), 3);

        // A fresh process restores the three consumed units from the signed
        // generation. A retry remains idempotent, while a distinct seed at
        // the same tick is rejected before its CAS because the restored
        // budget is exhausted.
        let restarted_key = key(47);
        let restarted_signer = KeypairGraphRecordSigner::with_admission(
            restarted_key.clone(),
            &WitnessAdmission::from_key(&restarted_key),
        )
        .unwrap();
        let mut restarted = DurableHypothesisCoordinator::new_with_store(
            &config,
            GraphLogicalTime::new(10),
            &store,
            restarted_signer,
        )
        .unwrap();
        assert_eq!(
            restarted.ledger().scheduler_budget(),
            first.snapshot.scheduler_budget().unwrap()
        );
        let second_retry = restarted
            .coordinate_seed(
                &store,
                first.snapshot.revision(),
                &seed,
                AgentId::from_public_key_hex(&restarted_key.public_key().to_hex()),
                EvidenceScope::new(
                    [],
                    [swarm_core::hypothesis_graph::EvidenceId::new(
                        "evidence:unit",
                    )],
                    [],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(second_retry.snapshot.revision(), first.snapshot.revision());
        let alternate_seed = HypothesisSeedInput::from_normalized_evidence(
            first.snapshot.state().graph_id.clone(),
            vec![
                HypothesisId::new("hypothesis:alternate-one"),
                HypothesisId::new("hypothesis:alternate-two"),
            ],
            vec![swarm_core::hypothesis_graph::EvidenceId::new(
                "evidence:alternate",
            )],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let before_exhausted = store.snapshot().unwrap();
        let before_exhausted_bytes = before_exhausted.canonical_bytes().unwrap();
        let budget_before_exhausted = restarted.ledger().scheduler_budget().clone();
        assert!(
            restarted
                .coordinate_seed(
                    &store,
                    before_exhausted.revision(),
                    &alternate_seed,
                    AgentId::from_public_key_hex(&restarted_key.public_key().to_hex()),
                    EvidenceScope::new(
                        [],
                        [swarm_core::hypothesis_graph::EvidenceId::new(
                            "evidence:alternate",
                        )],
                        [],
                    )
                    .unwrap(),
                )
                .is_err()
        );
        assert_eq!(
            restarted.ledger().scheduler_budget(),
            &budget_before_exhausted
        );
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_exhausted_bytes
        );

        // A newer logical tick resets the restored coordinator budget only
        // inside the successful durable candidate generation.
        let next_tick_seed = HypothesisSeedInput::from_normalized_evidence(
            first.snapshot.state().graph_id.clone(),
            vec![
                HypothesisId::new("hypothesis:next-tick-one"),
                HypothesisId::new("hypothesis:next-tick-two"),
            ],
            vec![swarm_core::hypothesis_graph::EvidenceId::new(
                "evidence:next-tick",
            )],
            GraphLogicalTime::new(11),
        )
        .unwrap();
        let next_tick = restarted
            .coordinate_seed(
                &store,
                before_exhausted.revision(),
                &next_tick_seed,
                AgentId::from_public_key_hex(&restarted_key.public_key().to_hex()),
                EvidenceScope::new(
                    [],
                    [swarm_core::hypothesis_graph::EvidenceId::new(
                        "evidence:next-tick",
                    )],
                    [],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            next_tick
                .snapshot
                .scheduler_budget()
                .unwrap()
                .current_tick(),
            GraphLogicalTime::new(11)
        );
        assert_eq!(
            next_tick
                .snapshot
                .scheduler_budget()
                .unwrap()
                .work_units_used(),
            1
        );
    }

    #[test]
    fn forced_coordinator_cas_refusal_rolls_back_budget() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 8,
            max_claims_per_tick: 2,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:cas-coordinator-budget");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = ForcedCasStore::new(graph, key(62), &config);
        let claimant = AgentId::from_public_key_hex(&key(63).public_key().to_hex());
        let evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:cas-coordinator");
        let seed = HypothesisSeedInput::from_normalized_evidence(
            graph_id,
            vec![
                HypothesisId::new("hypothesis:cas-one"),
                HypothesisId::new("hypothesis:cas-two"),
            ],
            vec![evidence_id.clone()],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let scope = EvidenceScope::new([], [evidence_id], []).unwrap();
        let mut ledger =
            HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(10)).unwrap();
        let before = store.snapshot().unwrap();
        let before_bytes = before.canonical_bytes().unwrap();
        let budget_before = ledger.scheduler_budget().clone();
        let cas_before = store.cas_attempts();
        let error = ledger
            .coordinate_seed(&store, before.revision(), &seed, claimant, scope)
            .unwrap_err();
        assert!(matches!(error, GraphStoreError::StalePredecessor { .. }));
        assert_eq!(store.cas_attempts(), cas_before + 1);
        assert_eq!(ledger.scheduler_budget(), &budget_before);
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
    }

    #[test]
    fn coordinator_rejects_caller_signed_decision_before_cas() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 16,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:signer-boundary");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(40), &config).unwrap();
        let signer_key = key(41);
        let signer = KeypairGraphRecordSigner::with_admission(
            signer_key.clone(),
            &WitnessAdmission::from_key(&signer_key),
        )
        .unwrap();
        let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
        let attacker_key = key(42);
        let attacker = AgentId::from_public_key_hex(&attacker_key.public_key().to_hex());
        let evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:signer-boundary");
        let seed = HypothesisSeedInput::from_normalized_evidence(
            graph_id,
            vec![
                HypothesisId::new("hypothesis:one"),
                HypothesisId::new("hypothesis:two"),
            ],
            vec![evidence_id.clone()],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let scope = EvidenceScope::new([], [evidence_id], []).unwrap();
        let caller_signed = DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Support,
            HypothesisId::new("hypothesis:one"),
            [],
            GraphProducerRole::Hunter,
            attacker,
            GraphLogicalTime::new(10),
            "caller supplied support",
        )
        .unwrap()
        .signed_with(&attacker_key, "caller")
        .unwrap();
        let mut coordinator =
            DurableHypothesisCoordinator::new(&config, GraphLogicalTime::new(10), signer).unwrap();
        let initial = store.snapshot().unwrap();
        let initial_bytes = initial.canonical_bytes().unwrap();
        let budget_before = coordinator.ledger().scheduler_budget().clone();
        assert!(
            coordinator
                .coordinate_seed_with_decisions(
                    &store,
                    initial.revision(),
                    &seed,
                    claimant,
                    scope,
                    vec![caller_signed],
                )
                .is_err()
        );
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            initial_bytes
        );
        assert_eq!(coordinator.ledger().scheduler_budget(), &budget_before);
    }

    #[test]
    fn coordinator_signs_empty_support_with_admitted_signer() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 16,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:empty-support");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(43), &config).unwrap();
        let signer_key = key(44);
        let signer = KeypairGraphRecordSigner::with_admission(
            signer_key.clone(),
            &WitnessAdmission::from_key(&signer_key),
        )
        .unwrap();
        let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
        let evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:empty-support");
        let seed = HypothesisSeedInput::from_normalized_evidence(
            graph_id,
            vec![
                HypothesisId::new("hypothesis:one"),
                HypothesisId::new("hypothesis:two"),
            ],
            vec![evidence_id.clone()],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let scope = EvidenceScope::new([], [evidence_id], []).unwrap();
        let unsigned_support = DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Support,
            HypothesisId::new("hypothesis:one"),
            [],
            GraphProducerRole::Hunter,
            claimant.clone(),
            GraphLogicalTime::new(10),
            "empty evidence is explicit, not inferred",
        )
        .unwrap();
        let mut coordinator =
            DurableHypothesisCoordinator::new(&config, GraphLogicalTime::new(10), signer).unwrap();
        let initial = store.snapshot().unwrap();
        let result = coordinator
            .coordinate_seed_with_decisions(
                &store,
                initial.revision(),
                &seed,
                claimant.clone(),
                scope,
                vec![unsigned_support],
            )
            .unwrap();
        let decision = result.snapshot.state().hypotheses[&HypothesisId::new("hypothesis:one")]
            .decision_history
            .first()
            .unwrap();
        assert!(decision.evidence_ids.is_empty());
        assert!(decision.witness.is_some());
        assert_eq!(decision.producer_identity, claimant);
        assert_eq!(result.snapshot.state().tasks.len(), 1);
    }

    #[test]
    fn coordinator_persists_signed_support_challenge_and_falsify_histories() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 16,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:decision-histories");
        let signer_key = key(64);
        let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
        let evidence = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "decision-sensor",
            SourceLineage::new("normalizer", "decision:evidence").unwrap(),
            EvidenceClock::observed(GraphLogicalTime::new(10)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Process {
                signal_kind: "process_start".to_string(),
                process_digest: "decision:process".to_string(),
                parent_process_digest: None,
                entity_ids: Vec::new(),
                content_digest: "decision:content".to_string(),
            },
        )
        .unwrap()
        .sign_with(
            &signer_key,
            GraphProducerRole::Normalizer,
            "normalizer:decision",
        )
        .unwrap();
        let mut graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        graph.admit_evidence(evidence.clone()).unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(65), &config).unwrap();
        let signer = KeypairGraphRecordSigner::with_admission(
            signer_key.clone(),
            &WitnessAdmission::from_key(&signer_key),
        )
        .unwrap();
        let seed = HypothesisSeedInput::from_normalized_evidence(
            graph_id,
            vec![
                HypothesisId::new("hypothesis:support-challenge"),
                HypothesisId::new("hypothesis:falsify"),
            ],
            vec![evidence.evidence_id.clone()],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let support = DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Support,
            HypothesisId::new("hypothesis:support-challenge"),
            [evidence.evidence_id.clone()],
            GraphProducerRole::Hunter,
            claimant.clone(),
            GraphLogicalTime::new(10),
            "explicit support witness",
        )
        .unwrap();
        let challenge = DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Challenge,
            HypothesisId::new("hypothesis:support-challenge"),
            [evidence.evidence_id.clone()],
            GraphProducerRole::Challenger,
            claimant.clone(),
            GraphLogicalTime::new(10),
            "explicit challenge witness",
        )
        .unwrap();
        let falsify = DecisionRecord::new(
            swarm_core::hypothesis_graph::DecisionKind::Falsify,
            HypothesisId::new("hypothesis:falsify"),
            [evidence.evidence_id.clone()],
            GraphProducerRole::Falsifier,
            claimant.clone(),
            GraphLogicalTime::new(10),
            "explicit falsification witness",
        )
        .unwrap();
        let mut coordinator =
            DurableHypothesisCoordinator::new(&config, GraphLogicalTime::new(10), signer).unwrap();
        let initial = store.snapshot().unwrap();
        let result = coordinator
            .coordinate_seed_with_decisions(
                &store,
                initial.revision(),
                &seed,
                claimant,
                EvidenceScope::new([], [evidence.evidence_id], []).unwrap(),
                vec![falsify, challenge, support],
            )
            .unwrap();
        let support_history = &result.snapshot.state().hypotheses
            [&HypothesisId::new("hypothesis:support-challenge")]
            .decision_history;
        assert_eq!(support_history.len(), 2);
        assert!(support_history.iter().any(|decision| {
            decision.kind == swarm_core::hypothesis_graph::DecisionKind::Support
        }));
        assert!(support_history.iter().any(|decision| {
            decision.kind == swarm_core::hypothesis_graph::DecisionKind::Challenge
        }));
        assert!(
            support_history
                .iter()
                .all(|decision| decision.witness.is_some())
        );
        let falsify_history = &result.snapshot.state().hypotheses
            [&HypothesisId::new("hypothesis:falsify")]
            .decision_history;
        assert_eq!(falsify_history.len(), 1);
        assert_eq!(
            falsify_history[0].kind,
            swarm_core::hypothesis_graph::DecisionKind::Falsify
        );
        assert!(falsify_history[0].witness.is_some());
        assert_eq!(
            result.snapshot.state().hypotheses[&HypothesisId::new("hypothesis:falsify")].status,
            swarm_core::hypothesis_graph::HypothesisStatus::Falsified
        );
    }

    #[test]
    fn decisionless_decisive_seed_is_rejected_without_store_or_budget_mutation() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 16,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:decisive-seed");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(125), &config).unwrap();
        let signer_key = key(126);
        let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
        let signer = KeypairGraphRecordSigner::with_admission(
            signer_key.clone(),
            &WitnessAdmission::from_key(&signer_key),
        )
        .unwrap();
        let evidence = swarm_core::hypothesis_graph::EvidenceId::new("evidence:decisive-seed");
        let first = HypothesisId::new("hypothesis:supported");
        let second = HypothesisId::new("hypothesis:unresolved");
        let seed = HypothesisSeedInput::new(
            graph_id,
            vec![first.clone(), second.clone()],
            vec![
                HypothesisSeedAssessment {
                    hypothesis_id: first,
                    evidence_ids: vec![evidence.clone()],
                    disposition: HypothesisDisposition::Supports,
                    provenance: evidence.clone(),
                },
                HypothesisSeedAssessment {
                    hypothesis_id: second,
                    evidence_ids: vec![evidence.clone()],
                    disposition: HypothesisDisposition::Unresolved,
                    provenance: evidence.clone(),
                },
            ],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let mut coordinator =
            DurableHypothesisCoordinator::new(&config, GraphLogicalTime::new(10), signer).unwrap();
        let before = store.snapshot().unwrap();
        let before_bytes = before.canonical_bytes().unwrap();
        let budget_before = coordinator.ledger().scheduler_budget().clone();

        let error = coordinator
            .coordinate_seed(
                &store,
                before.revision(),
                &seed,
                claimant,
                EvidenceScope::new([], [evidence], []).unwrap(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason })
                if reason.contains("corresponding signed decision")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
        assert_eq!(coordinator.ledger().scheduler_budget(), &budget_before);
    }

    #[test]
    fn coordinator_orders_decisions_by_time_and_rejects_retrograde_append() {
        let config = HypothesisGraphConfig {
            enabled: true,
            max_work_units_per_tick: 16,
            max_claims_per_tick: 4,
            ..HypothesisGraphConfig::default()
        };
        let graph_id = swarm_core::hypothesis_graph::GraphId::new("graph:decision-order");
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )
        .unwrap();
        let store = MemoryHypothesisGraphStore::new_with_config(graph, key(127), &config).unwrap();
        let signer_key = key(128);
        let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
        let signer = KeypairGraphRecordSigner::with_admission(
            signer_key.clone(),
            &WitnessAdmission::from_key(&signer_key),
        )
        .unwrap();
        let evidence = swarm_core::hypothesis_graph::EvidenceId::new("evidence:decision-order");
        let hypothesis_id = HypothesisId::new("hypothesis:decision-order");
        let seed = HypothesisSeedInput::from_normalized_evidence(
            graph_id,
            vec![
                hypothesis_id.clone(),
                HypothesisId::new("hypothesis:decision-order-control"),
            ],
            vec![evidence.clone()],
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let later = DecisionRecord::new(
            DecisionKind::Support,
            hypothesis_id.clone(),
            [],
            GraphProducerRole::Hunter,
            claimant.clone(),
            GraphLogicalTime::new(12),
            "later support",
        )
        .unwrap();
        let earlier = DecisionRecord::new(
            DecisionKind::Support,
            hypothesis_id.clone(),
            [],
            GraphProducerRole::Hunter,
            claimant.clone(),
            GraphLogicalTime::new(11),
            "earlier support",
        )
        .unwrap();
        let mut coordinator =
            DurableHypothesisCoordinator::new(&config, GraphLogicalTime::new(10), signer).unwrap();
        let initial = store.snapshot().unwrap();
        let initial_bytes = initial.canonical_bytes().unwrap();
        let initial_budget = coordinator.ledger().scheduler_budget().clone();
        let pre_seed = DecisionRecord::new(
            DecisionKind::Support,
            hypothesis_id.clone(),
            [],
            GraphProducerRole::Hunter,
            claimant.clone(),
            GraphLogicalTime::new(9),
            "support predating its seed",
        )
        .unwrap();
        let error = coordinator
            .coordinate_seed_with_decisions(
                &store,
                initial.revision(),
                &seed,
                claimant.clone(),
                EvidenceScope::new([], [evidence.clone()], []).unwrap(),
                vec![pre_seed],
            )
            .unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason })
                if reason.contains("precedes the hypothesis seed")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            initial_bytes
        );
        assert_eq!(coordinator.ledger().scheduler_budget(), &initial_budget);

        let first = coordinator
            .coordinate_seed_with_decisions(
                &store,
                initial.revision(),
                &seed,
                claimant.clone(),
                EvidenceScope::new([], [evidence.clone()], []).unwrap(),
                vec![later, earlier],
            )
            .unwrap();
        let history = &first.snapshot.state().hypotheses[&hypothesis_id].decision_history;
        assert_eq!(
            history
                .iter()
                .map(|decision| decision.decided_at)
                .collect::<Vec<_>>(),
            vec![GraphLogicalTime::new(11), GraphLogicalTime::new(12)]
        );

        let retrograde = DecisionRecord::new(
            DecisionKind::Support,
            hypothesis_id,
            [],
            GraphProducerRole::Hunter,
            claimant.clone(),
            GraphLogicalTime::new(11),
            "new but retrograde support",
        )
        .unwrap();
        let mut retry_seed = seed;
        retry_seed.logical_time = GraphLogicalTime::new(12);
        let before_bytes = first.snapshot.canonical_bytes().unwrap();
        let budget_before = coordinator.ledger().scheduler_budget().clone();
        let error = coordinator
            .coordinate_seed_with_decisions(
                &store,
                first.snapshot.revision(),
                &retry_seed,
                claimant,
                EvidenceScope::new([], [evidence], []).unwrap(),
                vec![retrograde],
            )
            .unwrap_err();
        assert!(matches!(
            error,
            GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason })
                if reason.contains("retrograde")
        ));
        assert_eq!(
            store.snapshot().unwrap().canonical_bytes().unwrap(),
            before_bytes
        );
        assert_eq!(coordinator.ledger().scheduler_budget(), &budget_before);
    }

    #[test]
    fn unadmitted_signer_cannot_construct_coordinator_authority() {
        let signer_key = key(45);
        let unrelated_admission = WitnessAdmission::from_key(&key(46));
        assert!(
            KeypairGraphRecordSigner::with_admission(signer_key, &unrelated_admission).is_err()
        );
    }
}
