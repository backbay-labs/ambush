//! Pure, simulation-only containment ranking.

use std::collections::{BTreeMap, BTreeSet};

use swarm_core::hypothesis_graph::{
    CausalEdge, ContainmentOption, ContainmentSimulation, EdgeId, EvidenceId, GraphAdmissionError,
    GraphId, GraphLogicalTime, GraphNodeId, GraphResourceLimits, Hypothesis, HypothesisId,
};
use swarm_spine::hypothesis_graph_store::GraphStoreSnapshot;

use super::kill_chain::KillChainReconstruction;

/// The immutable, validated ID view used to build a containment simulation.
///
/// A caller may not manufacture this view from labels or target IDs: the only
/// public constructor reads a signed [`GraphStoreSnapshot`].  The owned ID
/// sets make the resulting planning input independent of a mutable store,
/// while the edge map retains enough lineage to check that every kill-chain
/// edge is supported by the claim's evidence and nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentSnapshotView {
    graph_id: GraphId,
    node_ids: BTreeSet<GraphNodeId>,
    edge_ids: BTreeSet<EdgeId>,
    evidence_ids: BTreeSet<EvidenceId>,
    hypothesis_ids: BTreeSet<HypothesisId>,
    edges: BTreeMap<EdgeId, CausalEdge>,
}

impl ContainmentSnapshotView {
    /// Build a view only from an already authenticated and validated durable
    /// snapshot.  Rechecking the graph and hypothesis records here keeps this
    /// boundary fail-closed if a future store implementation returns a view
    /// assembled from untrusted bytes.
    pub fn from_snapshot(snapshot: &GraphStoreSnapshot) -> Result<Self, GraphAdmissionError> {
        let state = snapshot.state();
        state
            .validate()
            .map_err(|error| GraphAdmissionError::InvalidTransition {
                reason: format!("persisted graph snapshot failed state validation: {error}"),
            })?;
        let derived_revision =
            state
                .revision()
                .map_err(|error| GraphAdmissionError::InvalidTransition {
                    reason: format!("persisted graph snapshot revision failed validation: {error}"),
                })?;
        if derived_revision != *snapshot.revision() {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "persisted graph snapshot revision does not match its state".to_string(),
            });
        }
        let graph = snapshot.graph();
        graph.validate()?;
        if state.graph_id != graph.graph_id {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "persisted snapshot graph ID does not match its graph payload".to_string(),
            });
        }
        if state.limits != graph.limits {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "persisted snapshot limits do not match its graph limits".to_string(),
            });
        }

        let mut hypothesis_ids = BTreeSet::new();
        for (map_id, hypothesis) in &state.hypotheses {
            validate_hypothesis_entry(map_id, hypothesis, &graph.limits, &graph.edges)?;
            hypothesis_ids.insert(map_id.clone());
        }

        Ok(Self {
            graph_id: graph.graph_id.clone(),
            node_ids: graph.nodes.keys().cloned().collect(),
            edge_ids: graph.edges.keys().cloned().collect(),
            evidence_ids: graph.evidence.keys().cloned().collect(),
            hypothesis_ids,
            edges: graph.edges.clone(),
        })
    }

    pub fn graph_id(&self) -> &GraphId {
        &self.graph_id
    }

    pub fn node_ids(&self) -> &BTreeSet<GraphNodeId> {
        &self.node_ids
    }

    pub fn edge_ids(&self) -> &BTreeSet<EdgeId> {
        &self.edge_ids
    }

    pub fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence_ids
    }

    pub fn hypothesis_ids(&self) -> &BTreeSet<HypothesisId> {
        &self.hypothesis_ids
    }
}

fn validate_hypothesis_entry(
    map_id: &HypothesisId,
    hypothesis: &Hypothesis,
    limits: &GraphResourceLimits,
    edges: &BTreeMap<EdgeId, CausalEdge>,
) -> Result<(), GraphAdmissionError> {
    if map_id != &hypothesis.hypothesis_id {
        return Err(GraphAdmissionError::IdCollision {
            id: map_id.to_string(),
        });
    }
    hypothesis.validate(limits)?;
    for edge_id in &hypothesis.claims {
        if !edges.contains_key(edge_id) {
            return Err(GraphAdmissionError::InvalidField {
                field: "snapshot.hypotheses.claims".to_string(),
                reason: format!("unknown persisted edge {edge_id}"),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentPlanningInput {
    graph_id: GraphId,
    hypothesis_ids: Vec<HypothesisId>,
    edge_ids: Vec<EdgeId>,
    evidence_ids: Vec<EvidenceId>,
    available_node_ids: BTreeSet<GraphNodeId>,
    kill_chain: KillChainReconstruction,
    options: Vec<ContainmentOption>,
    logical_time: GraphLogicalTime,
    provenance: ContainmentSnapshotView,
    support_complete: bool,
}

impl ContainmentPlanningInput {
    /// Construct planning input from the same authenticated snapshot that
    /// supplies the graph objects. IDs are copied from the snapshot only
    /// after its maps and intrinsic records have been revalidated; callers
    /// cannot use this path to add a synthetic node or an unknown lineage ID.
    #[allow(clippy::too_many_arguments)]
    pub fn from_snapshot(
        snapshot: &GraphStoreSnapshot,
        hypothesis_ids: Vec<HypothesisId>,
        edge_ids: Vec<EdgeId>,
        evidence_ids: Vec<EvidenceId>,
        kill_chain: KillChainReconstruction,
        options: Vec<ContainmentOption>,
        logical_time: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        let view = ContainmentSnapshotView::from_snapshot(snapshot)?;
        Self::from_view(
            &view,
            hypothesis_ids,
            edge_ids,
            evidence_ids,
            kill_chain,
            options,
            logical_time,
        )
    }

    /// Explicit alias for adapters whose input is named a persisted view
    /// rather than a store snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn from_persisted_snapshot(
        snapshot: &GraphStoreSnapshot,
        hypothesis_ids: Vec<HypothesisId>,
        edge_ids: Vec<EdgeId>,
        evidence_ids: Vec<EvidenceId>,
        kill_chain: KillChainReconstruction,
        options: Vec<ContainmentOption>,
        logical_time: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        Self::from_snapshot(
            snapshot,
            hypothesis_ids,
            edge_ids,
            evidence_ids,
            kill_chain,
            options,
            logical_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_view(
        view: &ContainmentSnapshotView,
        hypothesis_ids: Vec<HypothesisId>,
        edge_ids: Vec<EdgeId>,
        evidence_ids: Vec<EvidenceId>,
        kill_chain: KillChainReconstruction,
        options: Vec<ContainmentOption>,
        logical_time: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        let input = Self::from_validated_view(
            view,
            hypothesis_ids,
            edge_ids,
            evidence_ids,
            kill_chain,
            options,
            logical_time,
        )?;
        input.validate_against_view(view)?;
        Ok(input)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_validated_view(
        view: &ContainmentSnapshotView,
        hypothesis_ids: Vec<HypothesisId>,
        edge_ids: Vec<EdgeId>,
        evidence_ids: Vec<EvidenceId>,
        kill_chain: KillChainReconstruction,
        options: Vec<ContainmentOption>,
        logical_time: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        validate_input_parts(
            &view.graph_id,
            &hypothesis_ids,
            &edge_ids,
            &evidence_ids,
            &view.node_ids,
            &kill_chain,
            &options,
            logical_time,
        )?;
        let support_complete = kill_chain.support_complete();
        Ok(Self {
            graph_id: view.graph_id.clone(),
            hypothesis_ids,
            edge_ids,
            evidence_ids,
            available_node_ids: view.node_ids.clone(),
            kill_chain,
            options,
            logical_time,
            provenance: view.clone(),
            support_complete,
        })
    }

    fn validate_parts(&self) -> Result<(), GraphAdmissionError> {
        validate_input_parts(
            &self.graph_id,
            &self.hypothesis_ids,
            &self.edge_ids,
            &self.evidence_ids,
            &self.available_node_ids,
            &self.kill_chain,
            &self.options,
            self.logical_time,
        )
        .and_then(|()| {
            if self.support_complete != self.kill_chain.support_complete() {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "containment support-completeness provenance was mutated".to_string(),
                });
            }
            Ok(())
        })
    }

    pub fn graph_id(&self) -> &GraphId {
        &self.graph_id
    }

    pub fn hypothesis_ids(&self) -> &[HypothesisId] {
        &self.hypothesis_ids
    }

    pub fn edge_ids(&self) -> &[EdgeId] {
        &self.edge_ids
    }

    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence_ids
    }

    pub fn available_node_ids(&self) -> &BTreeSet<GraphNodeId> {
        &self.available_node_ids
    }

    pub fn kill_chain(&self) -> &KillChainReconstruction {
        &self.kill_chain
    }

    pub fn options(&self) -> &[ContainmentOption] {
        &self.options
    }

    pub fn logical_time(&self) -> GraphLogicalTime {
        self.logical_time
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        self.validate_parts()?;
        self.validate_against_view(&self.provenance)
    }

    /// Revalidate this input against the exact persisted object maps used to
    /// construct it. The provenance view is private and immutable, so a
    /// planner cannot swap it for an arbitrary ID-only view after admission.
    pub fn validate_against_view(
        &self,
        view: &ContainmentSnapshotView,
    ) -> Result<(), GraphAdmissionError> {
        self.validate_parts()?;
        if self.provenance != *view {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "containment input provenance differs from its admitted snapshot view"
                    .to_string(),
            });
        }
        if self.graph_id != view.graph_id {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "containment input graph ID differs from persisted snapshot".to_string(),
            });
        }
        if self.available_node_ids != view.node_ids {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "containment node set is not the persisted snapshot node map".to_string(),
            });
        }
        ensure_membership(&self.hypothesis_ids, &view.hypothesis_ids, |id| {
            GraphAdmissionError::InvalidField {
                field: "containment.hypothesis_ids".to_string(),
                reason: format!("unknown persisted hypothesis {id}"),
            }
        })?;
        ensure_membership(&self.edge_ids, &view.edge_ids, |id| {
            GraphAdmissionError::InvalidField {
                field: "containment.edge_ids".to_string(),
                reason: format!("unknown persisted edge {id}"),
            }
        })?;
        ensure_membership(&self.evidence_ids, &view.evidence_ids, |_| {
            GraphAdmissionError::UnknownEvidence
        })?;
        if self
            .evidence_ids
            .iter()
            .any(|id| self.kill_chain.withheld_evidence_ids().contains(id))
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "containment input cannot re-admit withheld kill-chain evidence"
                    .to_string(),
            });
        }
        for withheld in self.kill_chain.withheld_evidence_ids() {
            if !view.evidence_ids.contains(withheld) {
                return Err(GraphAdmissionError::UnknownEvidence);
            }
        }
        validate_kill_chain_lineage(&self.kill_chain, view)?;
        for option in &self.options {
            option.validate()?;
            if let Some(unknown) = option.target_node_ids.difference(&view.node_ids).next() {
                return Err(GraphAdmissionError::UnknownNode {
                    id: unknown.to_string(),
                });
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_input_parts(
    graph_id: &GraphId,
    hypothesis_ids: &[HypothesisId],
    edge_ids: &[EdgeId],
    evidence_ids: &[EvidenceId],
    available_node_ids: &BTreeSet<GraphNodeId>,
    kill_chain: &KillChainReconstruction,
    options: &[ContainmentOption],
    logical_time: GraphLogicalTime,
) -> Result<(), GraphAdmissionError> {
    if graph_id.as_str().trim().is_empty() {
        return Err(GraphAdmissionError::InvalidField {
            field: "containment.graph_id".to_string(),
            reason: "graph ID must be non-empty".to_string(),
        });
    }
    logical_time.validate()?;
    validate_ids("containment.hypothesis_ids", hypothesis_ids)?;
    validate_ids("containment.edge_ids", edge_ids)?;
    validate_ids("containment.evidence_ids", evidence_ids)?;
    if available_node_ids.is_empty() {
        return Err(GraphAdmissionError::InvalidField {
            field: "containment.available_node_ids".to_string(),
            reason: "the planner requires real graph nodes".to_string(),
        });
    }
    for node_id in available_node_ids {
        if node_id.as_str().trim().is_empty() {
            return Err(GraphAdmissionError::InvalidIdentifier {
                field: "containment.available_node_id".to_string(),
            });
        }
    }
    kill_chain.validate()?;
    if !kill_chain.support_complete() {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "containment requires a kill-chain reconstruction with complete support"
                .to_string(),
        });
    }
    let edge_ids = edge_ids.iter().cloned().collect::<BTreeSet<_>>();
    let evidence_ids = evidence_ids.iter().cloned().collect::<BTreeSet<_>>();
    for claim in &kill_chain.claims {
        if !claim.node_ids.is_subset(available_node_ids)
            || !claim.edge_ids.is_subset(&edge_ids)
            || !claim.evidence_ids.is_subset(&evidence_ids)
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "kill-chain lineage references an unadmitted graph object".to_string(),
            });
        }
    }
    if options.is_empty() {
        return Err(GraphAdmissionError::InvalidField {
            field: "containment.options".to_string(),
            reason: "at least one simulation option is required".to_string(),
        });
    }
    let mut option_ids = BTreeSet::new();
    for option in options {
        option.validate()?;
        if !option_ids.insert(option.option_id.clone()) {
            return Err(GraphAdmissionError::IdCollision {
                id: option.option_id.clone(),
            });
        }
        if !option.target_node_ids.is_subset(available_node_ids) {
            return Err(GraphAdmissionError::UnknownNode {
                id: option
                    .target_node_ids
                    .difference(available_node_ids)
                    .next()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".to_string()),
            });
        }
    }
    Ok(())
}

fn validate_ids<T: AsRef<str> + Ord>(field: &str, ids: &[T]) -> Result<(), GraphAdmissionError> {
    if ids.is_empty() || ids.len() > 256 || ids.iter().any(|id| id.as_ref().trim().is_empty()) {
        return Err(GraphAdmissionError::InvalidField {
            field: field.to_string(),
            reason: "must contain between one and 256 non-empty IDs".to_string(),
        });
    }
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(GraphAdmissionError::InvalidField {
            field: field.to_string(),
            reason: "duplicate IDs are not allowed".to_string(),
        });
    }
    Ok(())
}

fn ensure_membership<T, F>(
    ids: &[T],
    admitted: &BTreeSet<T>,
    error: F,
) -> Result<(), GraphAdmissionError>
where
    T: Ord + Clone + std::fmt::Display,
    F: Fn(&T) -> GraphAdmissionError,
{
    for id in ids {
        if !admitted.contains(id) {
            return Err(error(id));
        }
    }
    Ok(())
}

fn validate_kill_chain_lineage(
    kill_chain: &KillChainReconstruction,
    view: &ContainmentSnapshotView,
) -> Result<(), GraphAdmissionError> {
    kill_chain.validate()?;
    if !kill_chain.support_complete() {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "kill-chain support is incomplete and cannot enter containment".to_string(),
        });
    }
    if !kill_chain.has_exact_edge_support()
        && kill_chain
            .claims
            .iter()
            .any(|claim| !claim.edge_ids.is_empty())
    {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "persisted-edge containment requires exact edge support provenance".to_string(),
        });
    }
    for claim in &kill_chain.claims {
        if let Some(unknown) = claim.node_ids.difference(&view.node_ids).next() {
            return Err(GraphAdmissionError::UnknownNode {
                id: unknown.to_string(),
            });
        }
        if let Some(unknown) = claim.edge_ids.difference(&view.edge_ids).next() {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain.edge_ids".to_string(),
                reason: format!("unknown persisted edge {unknown}"),
            });
        }
        if claim
            .evidence_ids
            .difference(&view.evidence_ids)
            .next()
            .is_some()
        {
            return Err(GraphAdmissionError::UnknownEvidence);
        }
        if claim
            .narration_evidence_ids
            .difference(&view.evidence_ids)
            .next()
            .is_some()
        {
            return Err(GraphAdmissionError::UnknownEvidence);
        }
        for edge_id in &claim.edge_ids {
            let edge =
                view.edges
                    .get(edge_id)
                    .ok_or_else(|| GraphAdmissionError::InvalidField {
                        field: "kill_chain.edge_ids".to_string(),
                        reason: format!("unknown persisted edge {edge_id}"),
                    })?;
            if !claim.node_ids.contains(&edge.from) || !claim.node_ids.contains(&edge.to) {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: format!(
                        "kill-chain claim {} does not retain both endpoints of edge {edge_id}",
                        claim.claim_id
                    ),
                });
            }
            if !edge.source_evidence_ids.is_subset(&claim.evidence_ids) {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: format!(
                        "kill-chain claim {} does not retain evidence for edge {edge_id}",
                        claim.claim_id
                    ),
                });
            }
            let support = claim.edge_evidence_ids().get(edge_id).ok_or_else(|| {
                GraphAdmissionError::InvalidTransition {
                    reason: format!(
                        "kill-chain claim {} has no exact support record for edge {edge_id}",
                        claim.claim_id
                    ),
                }
            })?;
            if support != &edge.source_evidence_ids {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: format!(
                        "kill-chain edge {edge_id} support differs from persisted edge"
                    ),
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ContainmentPlanner {
    limits: GraphResourceLimits,
}

impl ContainmentPlanner {
    pub fn new(limits: GraphResourceLimits) -> Result<Self, GraphAdmissionError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    pub fn limits(&self) -> &GraphResourceLimits {
        &self.limits
    }

    pub fn simulate_input(
        &self,
        input: &ContainmentPlanningInput,
    ) -> Result<ContainmentSimulation, GraphAdmissionError> {
        input.validate()?;
        if input.options.len() > self.limits.max_tasks {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "containment.options".to_string(),
                limit: self.limits.max_tasks,
            });
        }
        let simulation = ContainmentSimulation::new(input.graph_id.clone(), input.options.clone())?;
        simulation.validate()?;
        validate_simulation_preserves_options(input, &simulation)?;
        Ok(simulation)
    }
}

fn validate_simulation_preserves_options(
    input: &ContainmentPlanningInput,
    simulation: &ContainmentSimulation,
) -> Result<(), GraphAdmissionError> {
    if simulation.graph_id != input.graph_id || !simulation.simulation_only {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "containment simulation changed graph identity or authority mode".to_string(),
        });
    }
    let expected = input
        .options
        .iter()
        .map(|option| (option.option_id.clone(), option))
        .collect::<BTreeMap<_, _>>();
    let actual = simulation
        .options
        .iter()
        .map(|option| (option.option_id.clone(), option))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != input.options.len()
        || actual.len() != simulation.options.len()
        || expected.len() != actual.len()
    {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "containment simulation dropped or duplicated an option".to_string(),
        });
    }
    for (option_id, source) in expected {
        let Some(projected) = actual.get(&option_id) else {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: format!("containment simulation dropped option {option_id}"),
            });
        };
        if source.kind != projected.kind
            || source.target_node_ids != projected.target_node_ids
            || source.predicted_blast_radius_basis_points
                != projected.predicted_blast_radius_basis_points
            || source.reversibility_basis_points != projected.reversibility_basis_points
            || source.evidence_support_basis_points != projected.evidence_support_basis_points
            || source.required_approval != projected.required_approval
            || source.rollback_expected != projected.rollback_expected
            || source.option_id != projected.option_id
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: format!(
                    "containment simulation changed core option kind, target, score, or identity for {option_id}"
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use swarm_core::hypothesis_graph::{
        ActorNode, ApprovalClass, CausalEdge, CausalRelation, ConfidenceDistribution,
        ContainmentOptionKind, EdgeState, EventNode, EvidenceClock, EvidenceEnvelope,
        EvidenceSourceFamily, GraphNode, GraphProducerRole, Hypothesis, HypothesisGraph,
        KillChainClaim as CoreKillChainClaim, KillChainStage, OrderingClaim, SourceLineage,
        TypedEvidencePayload, UncertaintyReason,
    };
    use swarm_core::types::AgentId;
    use swarm_spine::hypothesis_graph_store::{
        GraphStoreState, HypothesisGraphStore, MemoryHypothesisGraphStore, ReasoningStateUpdate,
    };

    struct SnapshotFixture {
        snapshot: GraphStoreSnapshot,
        hypothesis_id: HypothesisId,
        edge_id: EdgeId,
        evidence_id: EvidenceId,
        unrelated_evidence_id: EvidenceId,
        node_ids: BTreeSet<GraphNodeId>,
        claim: CoreKillChainClaim,
    }

    fn snapshot_fixture() -> SnapshotFixture {
        let signer = swarm_crypto::Keypair::from_seed(&[29_u8; 32]);
        let config = swarm_core::config::HypothesisGraphConfig::default();
        let producer = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let actor = GraphNode::Actor(
            ActorNode::new("actor:containment", "containment actor").expect("actor must be valid"),
        );
        let event = GraphNode::Event(
            EventNode::new("process", "source:containment", GraphLogicalTime::new(1))
                .expect("event must be valid"),
        );
        let actor_id = actor.id().clone();
        let event_id = event.id().clone();
        let node_ids = BTreeSet::from([actor_id.clone(), event_id.clone()]);
        let mut graph =
            HypothesisGraph::new(GraphId::new("graph:containment"), config.resource_limits())
                .expect("graph must be valid");
        graph.admit_node(actor).expect("actor must be admitted");
        graph.admit_node(event).expect("event must be admitted");

        let evidence = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "source:containment",
            SourceLineage::new("fixture", "containment:evidence").expect("lineage"),
            EvidenceClock::observed(GraphLogicalTime::new(1)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Process {
                signal_kind: "process_start".to_string(),
                process_digest: "process:containment".to_string(),
                parent_process_digest: None,
                entity_ids: vec![actor_id.clone(), event_id.clone()],
                content_digest: "digest:containment".to_string(),
            },
        )
        .expect("evidence must be valid")
        .sign_with(
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer:containment",
        )
        .expect("evidence must be signed");
        let evidence_id = evidence.evidence_id.clone();
        graph
            .admit_evidence(evidence)
            .expect("evidence must be admitted");
        let unrelated_evidence = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "source:containment-unrelated",
            SourceLineage::new("fixture", "containment:unrelated")
                .expect("unrelated lineage must be valid"),
            EvidenceClock::observed(GraphLogicalTime::new(1)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Process {
                signal_kind: "process_exit".to_string(),
                process_digest: "process:unrelated".to_string(),
                parent_process_digest: None,
                entity_ids: vec![actor_id.clone(), event_id.clone()],
                content_digest: "digest:unrelated".to_string(),
            },
        )
        .expect("unrelated evidence must be valid")
        .sign_with(
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer:containment-unrelated",
        )
        .expect("unrelated evidence must be signed");
        let unrelated_evidence_id = unrelated_evidence.evidence_id.clone();
        graph
            .admit_evidence(unrelated_evidence)
            .expect("unrelated evidence must be admitted");

        let edge = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            8_000,
            [evidence_id.clone()],
            GraphProducerRole::Hunter,
            producer,
            GraphLogicalTime::new(1),
            EdgeState::Proposed,
        )
        .expect("edge must be valid")
        .signed_with(&signer, "hunter:containment")
        .expect("edge must be signed");
        let edge_id = edge.edge_id.clone();
        graph.admit_edge(edge).expect("edge must be admitted");

        let claim = CoreKillChainClaim::new(
            KillChainStage::Execution,
            node_ids.clone(),
            [edge_id.clone()],
            [evidence_id.clone()],
            [],
            "execution is supported",
            [evidence_id.clone()],
        )
        .expect("claim must be valid");
        let hypothesis_id = HypothesisId::new("hypothesis:containment");
        let hypothesis = Hypothesis::new(
            hypothesis_id.clone(),
            ConfidenceDistribution::uniform_two(),
            [UncertaintyReason::InsufficientEvidence],
            [],
        )
        .expect("hypothesis must be valid")
        .with_claims([edge_id.clone()]);
        let store = MemoryHypothesisGraphStore::new_with_config(graph, signer, &config)
            .expect("store must be valid");
        let initial = HypothesisGraphStore::snapshot(&store).expect("initial snapshot");
        let state = GraphStoreState::with_reasoning_state(
            initial.state().clone(),
            ReasoningStateUpdate::migration_to_hypotheses(
                config.resource_limits(),
                GraphLogicalTime::new(1),
            )
            .with_hypotheses(BTreeMap::from([(hypothesis_id.clone(), hypothesis)]))
            .with_scheduler_budget(
                swarm_core::hypothesis_graph::SchedulerBudget::new_with_config(
                    &config,
                    GraphLogicalTime::new(1),
                )
                .expect("scheduler budget must be valid"),
            ),
        )
        .expect("reasoning state must be valid");
        let snapshot = store
            .compare_and_swap(initial.revision(), state)
            .expect("persisted snapshot must be valid");
        SnapshotFixture {
            snapshot,
            hypothesis_id,
            edge_id,
            evidence_id,
            unrelated_evidence_id,
            node_ids,
            claim,
        }
    }

    fn option(target: GraphNodeId) -> ContainmentOption {
        ContainmentOption::new(
            ContainmentOptionKind::IsolateAsset,
            [target],
            100,
            9_000,
            8_000,
            ApprovalClass::Analyst,
            true,
        )
        .expect("test option must be valid")
    }

    fn exact_chain(
        fixture: &SnapshotFixture,
        claims: impl IntoIterator<Item = CoreKillChainClaim>,
    ) -> KillChainReconstruction {
        KillChainReconstruction::new_with_edge_support(
            claims,
            BTreeMap::from([(
                fixture.edge_id.clone(),
                BTreeSet::from([fixture.evidence_id.clone()]),
            )]),
            [],
        )
        .expect("exact persisted edge support must be valid")
    }

    fn input() -> (SnapshotFixture, ContainmentPlanningInput) {
        let fixture = snapshot_fixture();
        let target = fixture
            .node_ids
            .first()
            .expect("fixture must have a target")
            .clone();
        let input = ContainmentPlanningInput::from_snapshot(
            &fixture.snapshot,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            exact_chain(&fixture, [fixture.claim.clone()]),
            vec![option(target)],
            GraphLogicalTime::new(1),
        )
        .expect("input must be valid");
        (fixture, input)
    }

    #[test]
    fn duplicate_lineage_ids_are_rejected() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone(), fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            exact_chain(&fixture, [fixture.claim.clone()]),
            vec![option(fixture.node_ids.first().expect("target").clone())],
            GraphLogicalTime::new(1),
        );
        assert!(
            result.is_err(),
            "duplicate hypothesis IDs must not collapse"
        );
    }

    #[test]
    fn duplicate_options_are_rejected() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let same = option(fixture.node_ids.first().expect("target").clone());
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            exact_chain(&fixture, [fixture.claim.clone()]),
            vec![same.clone(), same],
            GraphLogicalTime::new(1),
        );
        assert!(result.is_err(), "duplicate options must not collapse");
    }

    #[test]
    fn simulation_preserves_core_option_fields() {
        let (_, input) = input();
        let simulation = ContainmentPlanner::new(GraphResourceLimits::default())
            .expect("limits must be valid")
            .simulate_input(&input)
            .expect("simulation must be valid");
        let source = &input.options[0];
        let projected = &simulation.options[0];
        assert_eq!(projected.kind, source.kind);
        assert_eq!(projected.target_node_ids, source.target_node_ids);
        assert_eq!(projected.score_key(), source.score_key());
        assert_eq!(projected.option_id, source.option_id);
    }

    #[test]
    fn legacy_claim_wide_support_is_ineligible_for_persisted_edge_containment() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let legacy = KillChainReconstruction::new([fixture.claim.clone()], [])
            .expect("legacy chain remains readable for reporting");
        assert!(!legacy.support_complete());
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            legacy,
            vec![option(fixture.node_ids.first().expect("target").clone())],
            GraphLogicalTime::new(1),
        );
        assert!(
            result.is_err(),
            "claim-wide legacy support must be explicitly incomplete for containment"
        );
    }

    #[test]
    fn exact_edge_support_must_equal_persisted_snapshot_support() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let mismatched_claim = CoreKillChainClaim::new(
            KillChainStage::Execution,
            fixture.node_ids.clone(),
            [fixture.edge_id.clone()],
            [
                fixture.evidence_id.clone(),
                fixture.unrelated_evidence_id.clone(),
            ],
            [],
            "execution has mismatched persisted support",
            [
                fixture.evidence_id.clone(),
                fixture.unrelated_evidence_id.clone(),
            ],
        )
        .expect("mismatched claim must remain intrinsically valid");
        let mismatched_chain = KillChainReconstruction::new_with_edge_support(
            [mismatched_claim],
            BTreeMap::from([(
                fixture.edge_id.clone(),
                BTreeSet::from([fixture.unrelated_evidence_id.clone()]),
            )]),
            [],
        )
        .expect("exact but adversarial support map must construct");
        assert!(
            validate_input_parts(
                view.graph_id(),
                std::slice::from_ref(&fixture.hypothesis_id),
                std::slice::from_ref(&fixture.edge_id),
                &[
                    fixture.evidence_id.clone(),
                    fixture.unrelated_evidence_id.clone()
                ],
                view.node_ids(),
                &mismatched_chain,
                &[option(fixture.node_ids.first().expect("target").clone())],
                GraphLogicalTime::new(1),
            )
            .is_ok()
        );
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![
                fixture.evidence_id.clone(),
                fixture.unrelated_evidence_id.clone(),
            ],
            mismatched_chain,
            vec![option(fixture.node_ids.first().expect("target").clone())],
            GraphLogicalTime::new(1),
        );
        assert!(
            matches!(result, Err(GraphAdmissionError::InvalidTransition { reason }) if reason.contains("support differs")),
            "weakening exact snapshot-support equality would admit this adversarial chain"
        );
    }

    #[test]
    fn output_mutations_with_valid_recomputed_ids_fail_preservation() {
        let (fixture, input) = input();
        let planner =
            ContainmentPlanner::new(GraphResourceLimits::default()).expect("limits must be valid");
        let target = fixture
            .node_ids
            .iter()
            .nth(1)
            .expect("fixture must have two targets")
            .clone();
        let source = &input.options[0];
        let mutations = [
            ContainmentOption::new(
                source.kind,
                source.target_node_ids.clone(),
                source.predicted_blast_radius_basis_points + 1,
                source.reversibility_basis_points,
                source.evidence_support_basis_points,
                source.required_approval,
                source.rollback_expected,
            )
            .expect("score mutation must be valid"),
            ContainmentOption::new(
                ContainmentOptionKind::RestrictNetwork,
                source.target_node_ids.clone(),
                source.predicted_blast_radius_basis_points,
                source.reversibility_basis_points,
                source.evidence_support_basis_points,
                source.required_approval,
                source.rollback_expected,
            )
            .expect("kind mutation must be valid"),
            ContainmentOption::new(
                source.kind,
                [target],
                source.predicted_blast_radius_basis_points,
                source.reversibility_basis_points,
                source.evidence_support_basis_points,
                source.required_approval,
                source.rollback_expected,
            )
            .expect("target mutation must be valid"),
        ];
        for mutation in mutations {
            let simulation = ContainmentSimulation::new(input.graph_id.clone(), [mutation])
                .expect("mutated output must remain a valid simulation");
            simulation.validate().expect("simulation must remain valid");
            assert!(
                validate_simulation_preserves_options(&input, &simulation).is_err(),
                "valid adversarial output mutation must reach preservation guard"
            );
        }
        planner
            .simulate_input(&input)
            .expect("unmutated input must remain simulatable");
    }

    #[test]
    fn snapshot_view_comes_from_validated_store_snapshot() {
        let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
            GraphId::new("graph:empty"),
            GraphResourceLimits::default(),
        )
        .expect("graph must be valid");
        let store = swarm_spine::hypothesis_graph_store::MemoryHypothesisGraphStore::new(
            graph,
            swarm_crypto::Keypair::from_seed(&[7_u8; 32]),
        )
        .expect("memory store must be valid");
        let snapshot = swarm_spine::hypothesis_graph_store::HypothesisGraphStore::snapshot(&store)
            .expect("store snapshot must be valid");
        let view = ContainmentSnapshotView::from_snapshot(&snapshot)
            .expect("empty signed snapshot view must be valid");
        assert!(view.node_ids().is_empty());
        assert!(view.edge_ids().is_empty());
        assert!(view.evidence_ids().is_empty());
        assert!(view.hypothesis_ids().is_empty());
    }

    #[test]
    fn synthetic_target_is_rejected_after_valid_lineage_is_admitted() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            exact_chain(&fixture, [fixture.claim.clone()]),
            vec![
                ContainmentOption::new(
                    ContainmentOptionKind::IsolateAsset,
                    [GraphNodeId::new("node:synthetic")],
                    100,
                    9_000,
                    8_000,
                    ApprovalClass::Analyst,
                    true,
                )
                .expect("synthetic target option itself is well formed"),
            ],
            GraphLogicalTime::new(1),
        );
        assert!(result.is_err(), "synthetic targets must fail membership");
    }

    #[test]
    fn malformed_view_cannot_replace_admitted_provenance() {
        let (fixture, input) = input();
        let mut malformed = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        malformed
            .hypothesis_ids
            .insert(HypothesisId::new("hypothesis:synthetic"));
        assert!(input.validate_against_view(&malformed).is_err());
    }

    #[test]
    fn withheld_evidence_cannot_be_reintroduced_into_containment() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let chain = crate::hypothesis_graph::kill_chain::reconstruct_kill_chain(
            [fixture.claim.clone()],
            [fixture.evidence_id.clone()],
        )
        .expect("withheld chain must be explicit");
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            chain,
            vec![option(fixture.node_ids.first().expect("target").clone())],
            GraphLogicalTime::new(1),
        );
        assert!(result.is_err(), "withheld evidence must remain suppressed");
    }

    #[test]
    fn omitted_withheld_support_plus_unrelated_valid_evidence_is_rejected() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let chain = crate::hypothesis_graph::kill_chain::reconstruct_kill_chain(
            [fixture.claim.clone()],
            [fixture.evidence_id.clone()],
        )
        .expect("withheld chain must carry an explicit gap");
        let result = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.unrelated_evidence_id.clone()],
            chain,
            vec![option(fixture.node_ids.first().expect("target").clone())],
            GraphLogicalTime::new(1),
        );
        assert!(
            result.is_err(),
            "omitting withheld support must not become complete merely by supplying unrelated evidence"
        );
    }

    #[test]
    fn multi_claim_order_is_validated_against_persisted_lineage() {
        let (fixture, _) = input();
        let view = ContainmentSnapshotView::from_snapshot(&fixture.snapshot)
            .expect("persisted view must be valid");
        let second = CoreKillChainClaim::new(
            KillChainStage::CredentialAccess,
            fixture.node_ids.clone(),
            [fixture.edge_id.clone()],
            [fixture.evidence_id.clone()],
            [fixture.claim.claim_id.clone()],
            "persistence is supported",
            [fixture.evidence_id.clone()],
        )
        .expect("second claim must be valid");
        let chain = exact_chain(&fixture, [fixture.claim.clone(), second]);
        let input = ContainmentPlanningInput::from_view(
            &view,
            vec![fixture.hypothesis_id.clone()],
            vec![fixture.edge_id.clone()],
            vec![fixture.evidence_id.clone()],
            chain,
            vec![option(fixture.node_ids.first().expect("target").clone())],
            GraphLogicalTime::new(1),
        )
        .expect("multi-claim lineage must remain admissible");
        assert_eq!(input.kill_chain.claims.len(), 2);
        assert_eq!(input.kill_chain.claims[1].predecessor_claim_ids.len(), 1);
    }
}
