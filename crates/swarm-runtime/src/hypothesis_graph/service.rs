//! Enabled-runtime composition for collective hypothesis reasoning.
//!
//! Critical-path detection and replay persistence happen before this service
//! is invoked. Graph failures are therefore visible degradation of the
//! reasoning lane; they never roll back a persisted detection or grant
//! response authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use swarm_core::config::{BundleStoreConfig, HypothesisGraphConfig};
use swarm_core::hypothesis_graph::{
    AssetNode, CausalEdge, CausalRelation, DecisionKind, DecisionRecord, EdgeState, EvidenceId,
    EvidenceScope, GraphAdmissionError, GraphId, GraphLogicalTime, GraphNode, GraphProducerRole,
    Hypothesis, HypothesisDelta, HypothesisId, HypothesisStatus, MemoryOutcome, MemoryProvenance,
    SchedulerBudget, StrategyMemory, StrategyMemoryExpiryEnvelope, TaskCapabilityProof,
    TaskClaimRequest, TaskCompletion, TaskCompletionKind, TaskDecisionLink, TaskId, TaskKind,
    TaskRecord, TaskState, TaskTarget, TaskTerminalEnvelope,
};
use swarm_core::types::AgentId;
use swarm_crypto::{Keypair, sha256_hex};
use swarm_spine::hypothesis_graph_store::{
    ConfiguredHypothesisGraphStore, GRAPH_STATE_MIGRATION_HYPOTHESES, GRAPH_STATE_MIGRATION_LEGACY,
    GraphStoreError, GraphStoreSnapshot, GraphStoreState, HypothesisGraphStore,
    ReasoningStateUpdate,
};
use swarm_spine::{
    FileStrategyMemoryStore, MemoryStrategyMemoryStore, ReplayBundle, StrategyMemoryRecord,
    StrategyMemoryStore, StrategyMemoryStoreError,
};

use super::clock::FixedGraphClock;
use super::hypotheses::{HypothesisDisposition, HypothesisSeedAssessment, HypothesisSeedInput};
use super::memory::{MemoryPriorityProjection, StrategyMemoryProjector};
use super::normalize::normalize_telemetry_event;
use super::tasks::GraphSeedRecords;
use super::{DurableHypothesisCoordinator, KeypairGraphRecordSigner, TaskClaim, WitnessAdmission};
use crate::detection::metrics::CriticalPathMetrics;

const GRAPH_LEASE_MS: u64 = 30_000;

#[derive(Debug, thiserror::Error)]
pub enum GraphServiceError {
    #[error(transparent)]
    Admission(#[from] GraphAdmissionError),

    #[error(transparent)]
    Store(#[from] GraphStoreError),

    #[error(transparent)]
    Memory(#[from] StrategyMemoryStoreError),

    #[error("collective hypothesis service mutex poisoned")]
    Poisoned,

    #[error(
        "an enabled shipped collective hypothesis service requires a durable local-files store"
    )]
    NonDurableEnabledStore,

    #[error("worker lacks the required `{0:?}` graph capability")]
    MissingCapability(TaskKind),

    #[error("no worker identity is registered for `{0:?}` graph tasks")]
    MissingWorkerRegistration(TaskKind),

    #[error("a graph worker must register at least one capability")]
    EmptyWorkerCapabilities,

    #[error(
        "graph capability `{kind:?}` is already bound to `{existing}` and cannot be rebound to `{observed}`"
    )]
    WorkerCapabilityConflict {
        kind: TaskKind,
        existing: AgentId,
        observed: AgentId,
    },

    #[error("graph worker identity `{observed}` does not match agent identity `{expected}`")]
    WorkerIdentityMismatch {
        expected: AgentId,
        observed: AgentId,
    },

    #[error("graph task `{0}` is not available for this worker")]
    TaskUnavailable(TaskId),

    #[error("graph `{observed}` does not match configured graph `{expected}`")]
    GraphMismatch {
        expected: GraphId,
        observed: GraphId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSubmission {
    pub graph_id: GraphId,
    pub evidence_id: EvidenceId,
    pub hypothesis_ids: Vec<HypothesisId>,
    pub task_ids: Vec<TaskId>,
    pub generation: u64,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphServiceMetricsSnapshot {
    pub submissions: u64,
    pub submission_failures: u64,
    pub completed_acquisitions: u64,
    pub completed_challenges: u64,
    pub completed_falsifications: u64,
    pub falsification_no_findings: u64,
    pub memory_records_projected: u64,
    pub memory_projection_failures: u64,
}

#[derive(Debug, Clone, Default)]
struct GraphServiceMetrics {
    snapshot: GraphServiceMetricsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphOperatorProjection {
    pub graph_id: GraphId,
    pub generation: u64,
    pub digest: String,
    pub graph: swarm_core::hypothesis_graph::HypothesisGraph,
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    pub tasks: Vec<TaskRecord>,
    pub terminal_publications: usize,
    pub memory: Vec<StrategyMemoryRecord>,
    pub logical_time_high_water: GraphLogicalTime,
    pub metrics: GraphServiceMetricsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSummaryProjection {
    pub graph_id: GraphId,
    pub generation: u64,
    pub graph_version: u64,
    pub evidence_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub contradiction_count: usize,
    pub hypothesis_count: usize,
    pub pending_task_count: usize,
    pub completed_task_count: usize,
    pub memory_count: usize,
    pub logical_time_high_water: GraphLogicalTime,
    pub metrics: GraphServiceMetricsSnapshot,
}

struct CollectiveHypothesisState {
    coordinator: DurableHypothesisCoordinator,
    metrics: GraphServiceMetrics,
    worker_claimants: BTreeMap<TaskKind, AgentId>,
    memory_projection_dirty: bool,
}

pub struct CollectiveHypothesisService {
    graph_id: GraphId,
    config: HypothesisGraphConfig,
    store: Arc<dyn HypothesisGraphStore>,
    memory: StrategyMemoryProjector,
    signer: Keypair,
    /// Serialize shipped graph mutations across replay admission and worker
    /// terminal publication. The durable store remains the final CAS/fencing
    /// authority; this guard prevents a newer replay from advancing logical
    /// high-water between a worker's time clamp and its signed terminal.
    operation: Mutex<()>,
    state: Mutex<CollectiveHypothesisState>,
    prometheus: Option<CriticalPathMetrics>,
}

/// Promote a freshly created or authenticated legacy graph envelope before
/// the service accepts replay work. The promotion changes no graph content;
/// it only installs the current reasoning marker and config-bound scheduler
/// budget. Every later replay can therefore publish graph records,
/// hypotheses, and tasks through one ordinary CAS.
fn initialize_reasoning_store(
    store: &dyn HypothesisGraphStore,
    config: &HypothesisGraphConfig,
) -> Result<GraphStoreSnapshot, GraphServiceError> {
    let initial = store.snapshot()?;
    if initial.state().migration_marker == GRAPH_STATE_MIGRATION_HYPOTHESES {
        return Ok(initial);
    }
    if initial.state().migration_marker != GRAPH_STATE_MIGRATION_LEGACY {
        return Err(GraphStoreError::InvalidState {
            reason: "unsupported hypothesis graph reasoning migration marker".to_string(),
        }
        .into());
    }
    let scheduler_budget =
        SchedulerBudget::new_with_config(config, initial.state().logical_time_high_water)?;
    let update = ReasoningStateUpdate::migration_to_hypotheses(
        config.resource_limits(),
        initial.state().logical_time_high_water,
    )
    .with_scheduler_budget(scheduler_budget);
    let mut candidate = GraphStoreState::with_reasoning_state(initial.state().clone(), update)?;
    candidate.generation = initial.revision().generation;
    candidate.predecessor_digest = initial.state().predecessor_digest.clone();
    Ok(store.compare_and_swap(initial.revision(), candidate)?)
}

impl CollectiveHypothesisService {
    /// Construct only when the feature is enabled. The caller retains an
    /// explicit `None` for the legacy path rather than a partially active
    /// service with hidden global state.
    pub fn from_config(
        config: &HypothesisGraphConfig,
        signer: Keypair,
        prometheus: Option<CriticalPathMetrics>,
    ) -> Result<Option<Arc<Self>>, GraphServiceError> {
        if !config.enabled {
            return Ok(None);
        }
        if matches!(&config.state_store, BundleStoreConfig::Memory) {
            return Err(GraphServiceError::NonDurableEnabledStore);
        }
        Self::new(config, signer, prometheus).map(|service| Some(Arc::new(service)))
    }

    pub fn new(
        config: &HypothesisGraphConfig,
        signer: Keypair,
        prometheus: Option<CriticalPathMetrics>,
    ) -> Result<Self, GraphServiceError> {
        config.resource_limits().validate()?;
        config.validate_reasoning_limits()?;
        let graph_id = graph_id_for_key(&signer);
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            graph_id.clone(),
            config.resource_limits(),
        )?;
        let (store, memory_store): (Arc<dyn HypothesisGraphStore>, Arc<dyn StrategyMemoryStore>) =
            match &config.state_store {
                BundleStoreConfig::Memory => (
                    Arc::new(ConfiguredHypothesisGraphStore::memory_with_config(
                        graph,
                        signer.clone(),
                        config,
                    )?),
                    Arc::new(MemoryStrategyMemoryStore::new_with_config(
                        signer.clone(),
                        config,
                    )?),
                ),
                BundleStoreConfig::LocalFiles { directory } => {
                    let root = Path::new(directory);
                    let graph_root = root.join("graph");
                    let memory_root = root.join("strategy-memory");
                    (
                        Arc::new(ConfiguredHypothesisGraphStore::local_files_with_config(
                            graph_root,
                            graph,
                            signer.clone(),
                            config,
                        )?),
                        Arc::new(FileStrategyMemoryStore::new_with_config(
                            memory_root,
                            signer.clone(),
                            config,
                        )?),
                    )
                }
            };
        let admission = WitnessAdmission::from_key(&signer);
        let record_signer = KeypairGraphRecordSigner::with_admission(signer.clone(), &admission)?;
        let initial = initialize_reasoning_store(store.as_ref(), config)?;
        let coordinator = DurableHypothesisCoordinator::new_with_store(
            config,
            initial.state().logical_time_high_water,
            store.as_ref(),
            record_signer,
        )?;
        let service = Self {
            graph_id,
            config: config.clone(),
            store,
            memory: StrategyMemoryProjector::new(memory_store),
            signer,
            operation: Mutex::new(()),
            state: Mutex::new(CollectiveHypothesisState {
                coordinator,
                metrics: GraphServiceMetrics::default(),
                worker_claimants: BTreeMap::new(),
                memory_projection_dirty: false,
            }),
            prometheus,
        };
        let snapshot = service.store.snapshot()?;
        let projection = service.memory.project_committed(&snapshot)?;
        {
            let mut state = service
                .state
                .lock()
                .map_err(|_| GraphServiceError::Poisoned)?;
            state.metrics.snapshot.memory_records_projected =
                u64::try_from(projection.inserted).unwrap_or(u64::MAX);
        }
        service.observe_state(snapshot.state());
        Ok(service)
    }

    pub fn graph_id(&self) -> &GraphId {
        &self.graph_id
    }

    pub fn store(&self) -> &Arc<dyn HypothesisGraphStore> {
        &self.store
    }

    /// Prove the enabled service has every production worker identity before
    /// the daemon begins accepting telemetry. An admitted-but-inert graph is
    /// a startup failure, not a runtime mode.
    pub fn ensure_workers_registered(&self) -> Result<(), GraphServiceError> {
        let state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        for kind in required_worker_kinds() {
            if !state.worker_claimants.contains_key(&kind) {
                return Err(GraphServiceError::MissingWorkerRegistration(kind));
            }
        }
        Ok(())
    }

    pub fn worker(
        self: &Arc<Self>,
        capabilities: impl IntoIterator<Item = TaskKind>,
        signer: Keypair,
    ) -> Result<GraphWorkerAdapter, GraphServiceError> {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() {
            return Err(GraphServiceError::EmptyWorkerCapabilities);
        }
        let claimant = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        let snapshot = self.store.snapshot()?;
        for kind in &capabilities {
            if let Some(existing) = state.worker_claimants.get(kind)
                && existing != &claimant
            {
                return Err(GraphServiceError::WorkerCapabilityConflict {
                    kind: *kind,
                    existing: existing.clone(),
                    observed: claimant.clone(),
                });
            }
            if let Some(existing) = snapshot
                .tasks()
                .find(|task| {
                    task.task.request.kind == *kind
                        && task_blocks_worker_rebind(task.task.state)
                        && task.task.request.claimant != claimant
                })
                .map(|task| &task.task.request.claimant)
            {
                return Err(GraphServiceError::WorkerCapabilityConflict {
                    kind: *kind,
                    existing: existing.clone(),
                    observed: claimant.clone(),
                });
            }
        }
        for kind in &capabilities {
            state.worker_claimants.insert(*kind, claimant.clone());
        }
        drop(state);
        Ok(GraphWorkerAdapter {
            service: Arc::clone(self),
            capabilities,
            claimant,
            signer,
        })
    }

    /// Admit normalized evidence, a minimal evidence-linked edge, competing
    /// alternatives, and bounded reasoning tasks. The replay has already
    /// crossed the critical-path persistence boundary before this call.
    pub fn submit_replay(
        &self,
        replay: &ReplayBundle,
    ) -> Result<GraphSubmission, GraphServiceError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let result = self.submit_replay_inner(replay);
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        match &result {
            Ok(_) => {
                state.metrics.snapshot.submissions =
                    state.metrics.snapshot.submissions.saturating_add(1);
                if let Some(metrics) = &self.prometheus {
                    metrics.observe_hypothesis_graph_submission(true);
                }
            }
            Err(_) => {
                state.metrics.snapshot.submission_failures =
                    state.metrics.snapshot.submission_failures.saturating_add(1);
                if let Some(metrics) = &self.prometheus {
                    metrics.observe_hypothesis_graph_submission(false);
                }
            }
        }
        result
    }

    fn submit_replay_inner(
        &self,
        replay: &ReplayBundle,
    ) -> Result<GraphSubmission, GraphServiceError> {
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        for kind in required_worker_kinds() {
            if !state.worker_claimants.contains_key(&kind) {
                return Err(GraphServiceError::MissingWorkerRegistration(kind));
            }
        }
        let worker_claimants = state.worker_claimants.clone();
        let initial = self.store.snapshot()?;
        let replay_ingested_at = GraphLogicalTime::new(replay.audit.created_at_ms);
        replay_ingested_at.validate()?;
        let logical_time = GraphLogicalTime::new(
            replay
                .audit
                .created_at_ms
                .max(initial.state().logical_time_high_water.as_millis()),
        );
        logical_time.validate()?;
        // Evidence identity must remain stable when the same durable replay is
        // retried after later task decisions advance graph logical time. The
        // high-water mark orders coordination; it is not the replay's ingest
        // timestamp.
        let clock = FixedGraphClock::new(replay_ingested_at);
        let evidence = normalize_telemetry_event(
            &replay.event,
            &clock,
            &self.signer,
            GraphProducerRole::Normalizer,
            "runtime-replay-normalizer",
        )?;
        let evidence_id = evidence.evidence_id.clone();
        let already_present = initial.graph().evidence.contains_key(&evidence_id);

        let event_node = swarm_core::hypothesis_graph::EventNode::new(
            "runtime_replay",
            replay.event.event_id.clone(),
            evidence.clock.observed_at,
        )?;
        let asset_kind = if replay.event.host_id.is_some() {
            "host"
        } else {
            "telemetry_source"
        };
        let asset_material = replay
            .event
            .host_id
            .as_deref()
            .unwrap_or(replay.event.source.as_str());
        let asset_node = AssetNode::new(sha256_hex(asset_material.as_bytes()), asset_kind)?;
        let event_node_id = event_node.node_id.clone();
        let asset_node_id = asset_node.node_id.clone();
        let confidence_basis_points = replay
            .findings
            .iter()
            .map(|finding| (finding.confidence.clamp(0.0, 1.0) * 10_000.0).round() as u16)
            .max()
            .unwrap_or(5_000);
        let edge = CausalEdge::new(
            &event_node_id,
            &asset_node_id,
            CausalRelation::ObservedIn,
            confidence_basis_points,
            [evidence_id.clone()],
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&self.signer.public_key().to_hex()),
            evidence.clock.observed_at,
            EdgeState::Proposed,
        )?
        .signed_with(&self.signer, "runtime-replay-edge")?;
        let graph_records = GraphSeedRecords::new(
            evidence.clone(),
            vec![GraphNode::Event(event_node), GraphNode::Asset(asset_node)],
            edge,
        );

        let malicious = scoped_hypothesis_id("malicious-activity", &evidence_id);
        let benign = scoped_hypothesis_id("benign-authorized-activity", &evidence_id);
        let assessments = vec![
            HypothesisSeedAssessment {
                hypothesis_id: malicious.clone(),
                evidence_ids: vec![evidence_id.clone()],
                disposition: HypothesisDisposition::Unresolved,
                provenance: evidence_id.clone(),
            },
            HypothesisSeedAssessment {
                hypothesis_id: benign.clone(),
                evidence_ids: vec![evidence_id.clone()],
                disposition: HypothesisDisposition::Contradicts,
                provenance: evidence_id.clone(),
            },
        ];
        let seed = HypothesisSeedInput::new(
            self.graph_id.clone(),
            vec![malicious, benign],
            assessments,
            logical_time,
        )?;
        let scope = EvidenceScope::new(
            [evidence.source_family],
            [evidence_id.clone()],
            [event_node_id, asset_node_id],
        )?;
        let result = state.coordinator.coordinate_graph_seed_for_claimants(
            self.store.as_ref(),
            initial.revision(),
            &seed,
            &worker_claimants,
            scope,
            graph_records,
        )?;
        self.observe_state(result.snapshot.state());
        Ok(GraphSubmission {
            graph_id: self.graph_id.clone(),
            evidence_id,
            hypothesis_ids: result.hypothesis_ids,
            task_ids: result.task_ids,
            generation: result.snapshot.revision().generation,
            idempotent: already_present,
        })
    }

    pub fn summary(&self) -> Result<GraphSummaryProjection, GraphServiceError> {
        self.repair_memory_projection()?;
        let snapshot = self.store.snapshot()?;
        let memory_count = self
            .memory
            .store()
            .list(self.config.max_memory_records)?
            .len();
        let metrics = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .metrics
            .snapshot;
        let pending_task_count = snapshot
            .tasks()
            .filter(|task| task.task.state == TaskState::Pending)
            .count();
        let completed_task_count = snapshot
            .tasks()
            .filter(|task| task.task.state == TaskState::Completed)
            .count();
        Ok(GraphSummaryProjection {
            graph_id: self.graph_id.clone(),
            generation: snapshot.revision().generation,
            graph_version: snapshot.graph().version,
            evidence_count: snapshot.graph().evidence.len(),
            node_count: snapshot.graph().nodes.len(),
            edge_count: snapshot.graph().edges.len(),
            contradiction_count: snapshot.graph().contradictions.len()
                + snapshot.graph().conflicts.len(),
            hypothesis_count: snapshot.hypotheses().len(),
            pending_task_count,
            completed_task_count,
            memory_count,
            logical_time_high_water: snapshot.state().logical_time_high_water,
            metrics,
        })
    }

    pub fn operator_projection(&self) -> Result<GraphOperatorProjection, GraphServiceError> {
        self.repair_memory_projection()?;
        let snapshot = self.store.snapshot()?;
        let memory = self.memory.store().list(self.config.max_memory_records)?;
        let metrics = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .metrics
            .snapshot;
        Ok(GraphOperatorProjection {
            graph_id: self.graph_id.clone(),
            generation: snapshot.revision().generation,
            digest: snapshot.revision().digest.clone(),
            graph: snapshot.graph().clone(),
            hypotheses: snapshot.hypotheses().clone(),
            tasks: snapshot.tasks().map(|task| task.task.clone()).collect(),
            terminal_publications: snapshot.terminal_outbox().len(),
            memory,
            logical_time_high_water: snapshot.state().logical_time_high_water,
            metrics,
        })
    }

    pub fn operator_projection_for(
        &self,
        graph_id: &GraphId,
    ) -> Result<GraphOperatorProjection, GraphServiceError> {
        self.ensure_graph(graph_id)?;
        self.operator_projection()
    }

    pub fn operator_tasks_for(
        &self,
        graph_id: &GraphId,
    ) -> Result<Vec<TaskRecord>, GraphServiceError> {
        self.ensure_graph(graph_id)?;
        Ok(self
            .store
            .snapshot()?
            .tasks()
            .map(|task| task.task.clone())
            .collect())
    }

    pub fn operator_memory_for(
        &self,
        graph_id: &GraphId,
    ) -> Result<Vec<StrategyMemoryRecord>, GraphServiceError> {
        self.ensure_graph(graph_id)?;
        self.repair_memory_projection()?;
        Ok(self.memory.store().list(self.config.max_memory_records)?)
    }

    fn ensure_graph(&self, graph_id: &GraphId) -> Result<(), GraphServiceError> {
        if graph_id != &self.graph_id {
            return Err(GraphServiceError::GraphMismatch {
                expected: self.graph_id.clone(),
                observed: graph_id.clone(),
            });
        }
        Ok(())
    }

    fn repair_memory_projection(&self) -> Result<(), GraphServiceError> {
        let dirty = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .memory_projection_dirty;
        if !dirty {
            return Ok(());
        }
        let snapshot = self.store.snapshot()?;
        let projection = self.memory.project_committed(&snapshot)?;
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        state.metrics.snapshot.memory_records_projected = state
            .metrics
            .snapshot
            .memory_records_projected
            .saturating_add(u64::try_from(projection.inserted).unwrap_or(u64::MAX));
        state.memory_projection_dirty = false;
        Ok(())
    }

    fn observe_state(&self, state: &swarm_spine::GraphStoreState) {
        if let Some(metrics) = &self.prometheus {
            let pending = state
                .tasks
                .values()
                .filter(|task| task.task.state == TaskState::Pending)
                .count();
            metrics.observe_hypothesis_graph_state(
                state.hypotheses.len(),
                pending,
                state.terminal_outbox.len(),
            );
        }
    }

    fn priority_for_task(
        &self,
        task: &TaskRecord,
        snapshot: &GraphStoreSnapshot,
        now: GraphLogicalTime,
    ) -> Result<MemoryPriorityProjection, GraphServiceError> {
        let base = match task.request.kind {
            TaskKind::AcquireEvidence => 7_000,
            TaskKind::ChallengeEdge => 6_000,
            TaskKind::FalsifyHypothesis => 8_000,
        };
        let candidates: Vec<HypothesisId> = match &task.request.target {
            TaskTarget::Hypothesis { hypothesis_id } => vec![hypothesis_id.clone()],
            TaskTarget::Evidence { .. } | TaskTarget::Edge { .. } => {
                snapshot.hypotheses().keys().cloned().collect()
            }
        };
        let mut best = MemoryPriorityProjection::unchanged(base);
        for hypothesis_id in candidates {
            let projected = self.memory.priority_for_context(
                &self.graph_id,
                &hypothesis_id,
                &task.request.evidence_scope.evidence_ids,
                now,
                base,
            )?;
            if projected.adjusted_priority_basis_points > best.adjusted_priority_basis_points
                || (projected.adjusted_priority_basis_points == best.adjusted_priority_basis_points
                    && projected.memory_id < best.memory_id)
            {
                best = projected;
            }
        }
        Ok(best)
    }

    fn nonretrograde_time(
        &self,
        requested: GraphLogicalTime,
    ) -> Result<GraphLogicalTime, GraphServiceError> {
        requested.validate()?;
        Ok(requested.max(self.store.snapshot()?.state().logical_time_high_water))
    }
}

#[derive(Debug, Clone)]
pub struct ClaimedGraphTask {
    pub claim: TaskClaim,
    pub request: swarm_core::hypothesis_graph::TaskClaimRequest,
    pub task_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphChallengeContext {
    pub task_id: TaskId,
    pub hunt_id: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StalkerGraphCompletion {
    pub acquisitions: usize,
    pub falsifications: usize,
    pub falsification_no_findings: usize,
    pub memory_records_projected: usize,
}

struct TerminalPublication {
    kind: TaskCompletionKind,
    evidence: Vec<swarm_core::hypothesis_graph::EvidenceEnvelope>,
    decision: Option<DecisionRecord>,
    memory: Option<(StrategyMemory, StrategyMemoryExpiryEnvelope)>,
}

#[derive(Clone)]
pub struct GraphWorkerAdapter {
    service: Arc<CollectiveHypothesisService>,
    capabilities: BTreeSet<TaskKind>,
    claimant: AgentId,
    signer: Keypair,
}

impl GraphWorkerAdapter {
    pub fn graph_id(&self) -> &GraphId {
        self.service.graph_id()
    }

    pub fn capabilities(&self) -> &BTreeSet<TaskKind> {
        &self.capabilities
    }

    pub fn claimant(&self) -> &AgentId {
        &self.claimant
    }

    /// Reconcile an already durable replay through the same idempotent graph
    /// admission used by live ingest. Stalker calls this before consuming a
    /// hunt so a transient post-persistence graph failure cannot strand the
    /// replay outside collective reasoning.
    pub fn ensure_replay_admitted(
        &self,
        replay: &ReplayBundle,
    ) -> Result<GraphSubmission, GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::AcquireEvidence) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        self.service.submit_replay(replay)
    }

    /// Return durable Stalker work independently of the ephemeral pheromone
    /// window. This is the restart/recovery trigger used when a replay and its
    /// graph tasks survive longer than the detection deposit that created
    /// them.
    pub fn outstanding_stalker_hunts(&self) -> Result<Vec<String>, GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::AcquireEvidence)
            && !self.capabilities.contains(&TaskKind::FalsifyHypothesis)
        {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        let snapshot = self.service.store.snapshot()?;
        let mut hunts = BTreeSet::new();
        for task in snapshot.tasks().filter(|task| {
            task.task.request.claimant == self.claimant
                && self.capabilities.contains(&task.task.request.kind)
                && matches!(
                    task.task.state,
                    TaskState::Pending | TaskState::Claimed | TaskState::Expired
                )
        }) {
            if let Some(hunt_id) = hunt_for_evidence_scope(
                &task.task.request.evidence_scope.evidence_ids,
                snapshot.graph(),
            ) {
                hunts.insert(hunt_id);
            }
        }
        Ok(hunts.into_iter().collect())
    }

    pub fn claim_next(
        &self,
        now: GraphLogicalTime,
    ) -> Result<Option<ClaimedGraphTask>, GraphServiceError> {
        self.claim_matching(now, |_, _| true)
    }

    fn claim_matching<F>(
        &self,
        now: GraphLogicalTime,
        predicate: F,
    ) -> Result<Option<ClaimedGraphTask>, GraphServiceError>
    where
        F: Fn(&TaskRecord, &GraphStoreSnapshot) -> bool,
    {
        self.service.repair_memory_projection()?;
        let mut state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let snapshot = self.service.store.snapshot()?;
        let mut candidates = snapshot
            .tasks()
            .filter(|task| {
                task_is_claimable_at(&task.task, now)
                    && self.capabilities.contains(&task.task.request.kind)
                    && predicate(&task.task, &snapshot)
            })
            .map(|task| {
                let priority = self.service.priority_for_task(&task.task, &snapshot, now)?;
                let key = swarm_core::hypothesis_graph::GraphSchedulerKey::new(
                    task.task.request.requested_at,
                    task.task.request.kind,
                    priority.adjusted_priority_basis_points,
                    task.task.request.task_id.clone(),
                )?;
                Ok((key, task.task.clone()))
            })
            .collect::<Result<Vec<_>, GraphServiceError>>()?;
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let Some((_, task)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        let request = if task.request.claimant == self.claimant {
            task.request.clone()
        } else if task.state == TaskState::Expired
            || (task.state == TaskState::Claimed
                && task
                    .lease
                    .as_ref()
                    .is_some_and(|lease| now >= lease.expires_at))
        {
            TaskClaimRequest::new(
                task.request.task_id.clone(),
                task.request.kind,
                task.request.target.clone(),
                task.request.role,
                self.claimant.clone(),
                task.request.evidence_scope.clone(),
                task.request.requested_at,
            )?
        } else {
            return Err(GraphServiceError::WorkerIdentityMismatch {
                expected: task.request.claimant,
                observed: self.claimant.clone(),
            });
        };
        let proof = TaskCapabilityProof::new(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest()?,
            &self.signer,
            worker_scope(request.kind),
        )?;
        let lease_ms = GRAPH_LEASE_MS.min(self.service.config.max_lease_ms).max(1);
        let claim = state.coordinator.ledger_mut().claim_or_reclaim_task(
            self.service.store.as_ref(),
            request.clone(),
            now,
            lease_ms,
            proof,
        )?;
        let claimed_snapshot = self.service.store.snapshot()?;
        let task_generation = claimed_snapshot
            .state()
            .tasks
            .get(&claim.task_id)
            .ok_or_else(|| GraphServiceError::TaskUnavailable(claim.task_id.clone()))?
            .generation;
        self.service.observe_state(claimed_snapshot.state());
        Ok(Some(ClaimedGraphTask {
            claim,
            request,
            task_generation,
        }))
    }

    pub fn renew(
        &self,
        claimed: &ClaimedGraphTask,
        now: GraphLogicalTime,
    ) -> Result<(), GraphServiceError> {
        if !self.capabilities.contains(&claimed.request.kind) {
            return Err(GraphServiceError::MissingCapability(claimed.request.kind));
        }
        let _guard = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        self.service.store.renew_task(
            claimed.claim.task_id.as_str(),
            claimed.task_generation,
            &claimed.claim.lease_id,
            claimed.claim.fencing_token,
            now,
            GRAPH_LEASE_MS.min(self.service.config.max_lease_ms).max(1),
        )?;
        Ok(())
    }

    pub fn complete_stalker_hunt(
        &self,
        hunt_id: &str,
        completed_at: GraphLogicalTime,
        final_confidence_basis_points: u16,
        ambiguous: bool,
        selected_malicious_interpretation: bool,
    ) -> Result<StalkerGraphCompletion, GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let completed_at = self.service.nonretrograde_time(completed_at)?;
        if !self.capabilities.contains(&TaskKind::AcquireEvidence) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        let mut report = StalkerGraphCompletion::default();
        while let Some(claimed) = self.claim_matching(completed_at, |task, snapshot| {
            task.request.kind == TaskKind::AcquireEvidence
                && task_matches_hunt(task, hunt_id, snapshot)
        })? {
            let projected = self.complete_acquisition(claimed, completed_at)?;
            report.acquisitions = report.acquisitions.saturating_add(1);
            report.memory_records_projected =
                report.memory_records_projected.saturating_add(projected);
        }
        if selected_malicious_interpretation
            && !ambiguous
            && final_confidence_basis_points >= 7_000
            && self.capabilities.contains(&TaskKind::FalsifyHypothesis)
        {
            while let Some(claimed) = self.claim_matching(completed_at, |task, snapshot| {
                task.request.kind == TaskKind::FalsifyHypothesis
                    && task_matches_hunt(task, hunt_id, snapshot)
            })? {
                let projected = self.complete_falsification(claimed, completed_at)?;
                report.falsifications = report.falsifications.saturating_add(1);
                report.memory_records_projected =
                    report.memory_records_projected.saturating_add(projected);
            }
        } else if self.capabilities.contains(&TaskKind::FalsifyHypothesis) {
            while let Some(claimed) = self.claim_matching(completed_at, |task, snapshot| {
                task.request.kind == TaskKind::FalsifyHypothesis
                    && task_matches_hunt(task, hunt_id, snapshot)
            })? {
                let projected = self.complete_falsification_no_finding(claimed, completed_at)?;
                report.falsification_no_findings =
                    report.falsification_no_findings.saturating_add(1);
                report.memory_records_projected =
                    report.memory_records_projected.saturating_add(projected);
            }
        }
        Ok(report)
    }

    pub fn next_challenge_context(
        &self,
        now: GraphLogicalTime,
    ) -> Result<Option<GraphChallengeContext>, GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::ChallengeEdge) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::ChallengeEdge,
            ));
        }
        self.service.repair_memory_projection()?;
        let snapshot = self.service.store.snapshot()?;
        let mut candidates = snapshot
            .tasks()
            .filter(|task| {
                task_is_claimable_at(&task.task, now)
                    && task.task.request.kind == TaskKind::ChallengeEdge
            })
            .map(|task| {
                let priority = self.service.priority_for_task(&task.task, &snapshot, now)?;
                let key = swarm_core::hypothesis_graph::GraphSchedulerKey::new(
                    task.task.request.requested_at,
                    task.task.request.kind,
                    priority.adjusted_priority_basis_points,
                    task.task.request.task_id.clone(),
                )?;
                Ok((key, task.task.clone()))
            })
            .collect::<Result<Vec<_>, GraphServiceError>>()?;
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let Some((_, task)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        let hunt_id =
            hunt_for_evidence_scope(&task.request.evidence_scope.evidence_ids, snapshot.graph())
                .unwrap_or_else(|| task.request.task_id.to_string());
        Ok(Some(GraphChallengeContext {
            task_id: task.request.task_id,
            hunt_id,
            evidence_ids: task.request.evidence_scope.evidence_ids,
        }))
    }

    pub fn complete_challenge(
        &self,
        task_id: &TaskId,
        completed_at: GraphLogicalTime,
    ) -> Result<bool, GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let completed_at = self.service.nonretrograde_time(completed_at)?;
        let Some(claimed) = self.claim_matching(completed_at, |task, _| {
            task.request.kind == TaskKind::ChallengeEdge && &task.request.task_id == task_id
        })?
        else {
            return Ok(false);
        };
        self.complete_edge_challenge(claimed, completed_at)?;
        Ok(true)
    }

    fn complete_acquisition(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Evidence { evidence_id } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        let snapshot = self.service.store.snapshot()?;
        let evidence = snapshot
            .graph()
            .evidence
            .get(evidence_id)
            .cloned()
            .ok_or(GraphAdmissionError::UnknownEvidence)?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::EvidenceAdded,
                evidence: vec![evidence],
                decision: None,
                memory: None,
            },
        )
    }

    fn complete_edge_challenge(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let evidence = evidence_for_scope(&evidence_ids, &self.service.store.snapshot()?)?;
        let evidence_id = evidence_ids
            .iter()
            .next()
            .ok_or(GraphAdmissionError::UnknownEvidence)?;
        let decision = DecisionRecord::new(
            DecisionKind::Challenge,
            scoped_hypothesis_id("malicious-activity", evidence_id),
            evidence_ids.iter().cloned(),
            GraphProducerRole::Challenger,
            AgentId::from_public_key_hex(&self.service.signer.public_key().to_hex()),
            completed_at,
            "correlation review challenged the event-to-asset causal edge",
        )?
        .signed_with(&self.service.signer, "weaver-edge-challenge-adjudication")?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::EdgeChallenged,
                evidence,
                decision: Some(decision),
                memory: None,
            },
        )
    }

    fn complete_falsification(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Hypothesis { hypothesis_id } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let decision = DecisionRecord::new(
            DecisionKind::Falsify,
            hypothesis_id.clone(),
            evidence_ids.iter().cloned(),
            GraphProducerRole::Falsifier,
            AgentId::from_public_key_hex(&self.service.signer.public_key().to_hex()),
            completed_at,
            "completed investigation falsified the benign authorized alternative",
        )?
        .with_resulting_status(HypothesisStatus::Falsified)?
        .signed_with(
            &self.service.signer,
            "stalker-hypothesis-falsifier-adjudication",
        )?;
        let provenance = MemoryProvenance::new(
            claimed.request.claimant.clone(),
            evidence_ids.iter().cloned(),
        )
        .signed_with(
            &self.signer,
            GraphProducerRole::Falsifier,
            "stalker-memory-provenance",
        )?;
        let snapshot = self.service.store.snapshot()?;
        let evidence = evidence_for_scope(&evidence_ids, &snapshot)?;
        let evidence_id = evidence_ids
            .iter()
            .next()
            .ok_or(GraphAdmissionError::UnknownEvidence)?;
        let related_edges = snapshot
            .graph()
            .edges
            .values()
            .filter(|edge| !edge.source_evidence_ids.is_disjoint(&evidence_ids))
            .map(|edge| edge.edge_id.clone())
            .collect::<Vec<_>>();
        let memory = StrategyMemory::new(
            self.service.graph_id.clone(),
            scoped_hypothesis_id("malicious-activity", evidence_id),
            HypothesisDelta::new(related_edges, [], []),
            evidence_ids.iter().cloned().map(|evidence_id| {
                swarm_core::hypothesis_graph::EvidenceUtility::new(evidence_id, 9_000)
            }),
            [hypothesis_id.clone()],
            MemoryOutcome::Confirmed,
            provenance,
        )?
        .signed_with(
            &self.signer,
            GraphProducerRole::Falsifier,
            "stalker-strategy-memory",
        )?;
        let expiry = StrategyMemoryExpiryEnvelope::new_with_config(
            &memory,
            completed_at,
            self.service.config.max_memory_ttl_ticks,
            &self.service.config,
            &self.signer,
        )?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::HypothesisFalsified,
                evidence,
                decision: Some(decision),
                memory: Some((memory, expiry)),
            },
        )
    }

    fn complete_falsification_no_finding(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Hypothesis { .. } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let evidence = evidence_for_scope(&evidence_ids, &self.service.store.snapshot()?)?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::NoFinding,
                evidence,
                decision: None,
                memory: None,
            },
        )
    }

    fn accept_terminal(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
        publication: TerminalPublication,
    ) -> Result<usize, GraphServiceError> {
        let TerminalPublication {
            kind,
            evidence,
            decision,
            memory,
        } = publication;
        let completion_kind = kind.clone();
        if !self.capabilities.contains(&claimed.request.kind) {
            return Err(GraphServiceError::MissingCapability(claimed.request.kind));
        }
        let task_id = claimed.claim.task_id.clone();
        let task_kind = claimed.request.kind;
        let mut state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let snapshot = self.service.store.snapshot()?;
        let evidence_ids = match kind {
            TaskCompletionKind::EvidenceAdded => evidence
                .iter()
                .map(|item| item.evidence_id.clone())
                .collect::<BTreeSet<_>>(),
            TaskCompletionKind::EdgeChallenged | TaskCompletionKind::HypothesisFalsified => {
                claimed.request.evidence_scope.evidence_ids.clone()
            }
            TaskCompletionKind::NoFinding if claimed.request.kind == TaskKind::AcquireEvidence => {
                BTreeSet::new()
            }
            TaskCompletionKind::NoFinding => claimed.request.evidence_scope.evidence_ids.clone(),
        };
        let summary_digest = sha256_hex(format!("{:?}:{}", kind, claimed.claim.task_id).as_bytes());
        let completion = TaskCompletion::new(
            kind,
            claimed.request.claimant.clone(),
            completed_at,
            evidence_ids.iter().cloned(),
            summary_digest,
        )?;
        let decision_link = decision
            .as_ref()
            .map(|decision| {
                TaskDecisionLink::new(
                    claimed.claim.task_id.clone(),
                    claimed.request.target.clone(),
                    evidence_ids.iter().cloned(),
                    Some(decision.decision_id.clone()),
                )
            })
            .transpose()?;
        let envelope = TaskTerminalEnvelope::new(
            claimed.claim.task_id.clone(),
            claimed.claim.idempotency_key.clone(),
            claimed.claim.lease_id.clone(),
            claimed.claim.fencing_token,
            completion,
            decision_link,
            claimed.request.claimant.clone(),
            claimed.claim.capability_proof.clone(),
        )?
        .signed_with(&self.signer, worker_terminal_scope(claimed.request.kind))?;
        let (memory, memory_expiry) = memory
            .map(|(memory, expiry)| (Some(memory), Some(expiry)))
            .unwrap_or((None, None));
        let committed = state.coordinator.ledger_mut().accept_terminal_once(
            self.service.store.as_ref(),
            snapshot.revision(),
            &claimed.claim,
            envelope,
            evidence,
            decision,
            memory,
            memory_expiry,
        )?;
        match task_kind {
            TaskKind::AcquireEvidence => {
                state.metrics.snapshot.completed_acquisitions = state
                    .metrics
                    .snapshot
                    .completed_acquisitions
                    .saturating_add(1);
            }
            TaskKind::ChallengeEdge => {
                state.metrics.snapshot.completed_challenges = state
                    .metrics
                    .snapshot
                    .completed_challenges
                    .saturating_add(1);
            }
            TaskKind::FalsifyHypothesis => {
                state.metrics.snapshot.completed_falsifications = state
                    .metrics
                    .snapshot
                    .completed_falsifications
                    .saturating_add(1);
                if completion_kind == TaskCompletionKind::NoFinding {
                    state.metrics.snapshot.falsification_no_findings = state
                        .metrics
                        .snapshot
                        .falsification_no_findings
                        .saturating_add(1);
                }
            }
        }
        drop(state);
        if let Some(metrics) = &self.service.prometheus {
            metrics.observe_hypothesis_graph_completion(task_kind, &completion_kind);
        }

        let projection = match self
            .service
            .memory
            .project_committed_task(&committed, &task_id)
        {
            Ok(projection) => projection,
            Err(error) => {
                let mut state = self
                    .service
                    .state
                    .lock()
                    .map_err(|_| GraphServiceError::Poisoned)?;
                state.memory_projection_dirty = true;
                state.metrics.snapshot.memory_projection_failures = state
                    .metrics
                    .snapshot
                    .memory_projection_failures
                    .saturating_add(1);
                if let Some(metrics) = &self.service.prometheus {
                    metrics.observe_hypothesis_graph_memory_projection_failure();
                }
                return Err(error.into());
            }
        };
        let mut state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        state.metrics.snapshot.memory_records_projected = state
            .metrics
            .snapshot
            .memory_records_projected
            .saturating_add(u64::try_from(projection.inserted).unwrap_or(u64::MAX));
        drop(state);
        let current = self.service.store.snapshot()?;
        self.service.observe_state(current.state());
        Ok(projection.inserted)
    }
}

fn task_blocks_worker_rebind(state: TaskState) -> bool {
    matches!(state, TaskState::Pending | TaskState::Claimed)
}

fn task_is_claimable_at(task: &TaskRecord, now: GraphLogicalTime) -> bool {
    task.state == TaskState::Pending
        || task.state == TaskState::Expired
        || (task.state == TaskState::Claimed
            && task
                .lease
                .as_ref()
                .is_some_and(|lease| now >= lease.expires_at))
}

fn required_worker_kinds() -> [TaskKind; 3] {
    [
        TaskKind::AcquireEvidence,
        TaskKind::ChallengeEdge,
        TaskKind::FalsifyHypothesis,
    ]
}

fn graph_id_for_key(key: &Keypair) -> GraphId {
    GraphId::new(format!(
        "graph:runtime:{}",
        sha256_hex(key.public_key().as_bytes())
    ))
}

fn scoped_hypothesis_id(kind: &str, evidence_id: &EvidenceId) -> HypothesisId {
    HypothesisId::new(format!(
        "hypothesis:{kind}:{}",
        sha256_hex(evidence_id.as_str().as_bytes())
    ))
}

fn worker_scope(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::AcquireEvidence => "stalker-acquire-capability",
        TaskKind::ChallengeEdge => "weaver-challenge-capability",
        TaskKind::FalsifyHypothesis => "stalker-falsify-capability",
    }
}

fn worker_terminal_scope(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::AcquireEvidence => "stalker-acquire-terminal",
        TaskKind::ChallengeEdge => "weaver-challenge-terminal",
        TaskKind::FalsifyHypothesis => "stalker-falsify-terminal",
    }
}

fn task_matches_hunt(task: &TaskRecord, hunt_id: &str, snapshot: &GraphStoreSnapshot) -> bool {
    task.request
        .evidence_scope
        .evidence_ids
        .iter()
        .filter_map(|evidence_id| snapshot.graph().evidence.get(evidence_id))
        .any(|evidence| evidence.lineage.source_record_id == hunt_id)
}

fn hunt_for_evidence_scope(
    evidence_ids: &BTreeSet<EvidenceId>,
    graph: &swarm_core::hypothesis_graph::HypothesisGraph,
) -> Option<String> {
    evidence_ids
        .iter()
        .filter_map(|evidence_id| graph.evidence.get(evidence_id))
        .map(|evidence| evidence.lineage.source_record_id.clone())
        .next()
}

fn evidence_for_scope(
    evidence_ids: &BTreeSet<EvidenceId>,
    snapshot: &GraphStoreSnapshot,
) -> Result<Vec<swarm_core::hypothesis_graph::EvidenceEnvelope>, GraphServiceError> {
    evidence_ids
        .iter()
        .map(|evidence_id| {
            snapshot
                .graph()
                .evidence
                .get(evidence_id)
                .cloned()
                .ok_or_else(|| GraphAdmissionError::UnknownEvidence.into())
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_constructs_no_service() {
        let config = HypothesisGraphConfig::default();
        let service =
            CollectiveHypothesisService::from_config(&config, Keypair::from_seed(&[1; 32]), None)
                .unwrap();
        assert!(service.is_none());
    }

    #[test]
    fn shipped_factory_rejects_enabled_memory_store() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        assert!(matches!(
            CollectiveHypothesisService::from_config(&config, Keypair::from_seed(&[11; 32]), None,),
            Err(GraphServiceError::NonDurableEnabledStore)
        ));
    }

    #[test]
    fn worker_capabilities_are_key_bound_and_cannot_be_reassigned() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        let service = Arc::new(
            CollectiveHypothesisService::new(&config, Keypair::from_seed(&[2; 32]), None).unwrap(),
        );
        assert!(matches!(
            service.ensure_workers_registered(),
            Err(GraphServiceError::MissingWorkerRegistration(
                TaskKind::AcquireEvidence
            ))
        ));
        assert!(matches!(
            service.worker([], Keypair::from_seed(&[3; 32])),
            Err(GraphServiceError::EmptyWorkerCapabilities)
        ));
        let first = service
            .worker([TaskKind::ChallengeEdge], Keypair::from_seed(&[4; 32]))
            .unwrap();
        let retry = service
            .worker([TaskKind::ChallengeEdge], Keypair::from_seed(&[4; 32]))
            .unwrap();
        assert_eq!(first.claimant(), retry.claimant());
        assert!(matches!(
            service.worker([TaskKind::ChallengeEdge], Keypair::from_seed(&[5; 32])),
            Err(GraphServiceError::WorkerCapabilityConflict {
                kind: TaskKind::ChallengeEdge,
                ..
            })
        ));
        service
            .worker(
                [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
                Keypair::from_seed(&[6; 32]),
            )
            .unwrap();
        service.ensure_workers_registered().unwrap();
    }

    #[test]
    fn only_outstanding_tasks_block_worker_rebind_after_restart() {
        assert!(task_blocks_worker_rebind(TaskState::Pending));
        assert!(task_blocks_worker_rebind(TaskState::Claimed));
        assert!(!task_blocks_worker_rebind(TaskState::Completed));
        assert!(!task_blocks_worker_rebind(TaskState::Failed));
        assert!(!task_blocks_worker_rebind(TaskState::Expired));
    }
}
