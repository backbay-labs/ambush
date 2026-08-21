//! Strict, bounded contracts for collective cyber reasoning.
//!
//! This module owns typed epistemic records only.  Persistence and runtime
//! orchestration are deliberately kept in higher-level crates.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AgentId;
    use swarm_crypto::{Keypair, Signer};

    fn signer() -> Keypair {
        Keypair::from_seed(&[7_u8; 32])
    }

    fn witness(role: GraphProducerRole) -> EvidenceWitness {
        let key = signer();
        EvidenceWitness::from_signer(&key, role, "hunter-a").expect("witness")
    }

    fn envelope(id: &str, role: GraphProducerRole) -> EvidenceEnvelope {
        EvidenceEnvelope::new_signed(
            EvidenceSourceFamily::Process,
            id,
            SourceLineage::new("fixture", id).expect("lineage"),
            EvidenceClock::observed(GraphLogicalTime::new(1_700_000_000_100)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Signal {
                signal_kind: "test_signal".to_string(),
                entity_ids: vec![GraphNodeId::new("node:event:test")],
                relation_ids: vec![],
                supports: vec![HypothesisId::new("hypothesis:compromise")],
                refutes: vec![HypothesisId::new("hypothesis:automation")],
                content_digest: "digest:test".to_string(),
            },
            witness(role),
        )
        .expect("signed envelope")
    }

    #[test]
    fn hypothesis_graph_strictly_admits_typed_nodes_evidence_and_edges() {
        let limits = GraphResourceLimits::default();
        let mut graph = HypothesisGraph::new(GraphId::new("graph:test"), limits).expect("graph");
        let actor = GraphNode::Actor(
            ActorNode::new("principal:digest", "principal-a").expect("actor"),
        );
        let event = GraphNode::Event(
            EventNode::new("seed", GraphLogicalTime::new(1_700_000_000_100)).expect("event"),
        );
        let actor_id = actor.id().clone();
        let event_id = event.id().clone();
        graph.admit_node(actor).expect("actor admission");
        graph.admit_node(event).expect("event admission");
        let evidence = envelope("record:test", GraphProducerRole::Hunter);
        let evidence_id = evidence.evidence_id.clone();
        graph.admit_evidence(evidence).expect("evidence admission");
        let edge = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            8_000,
            [evidence_id],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(1_700_000_000_100),
            EdgeState::Proposed,
        )
        .expect("edge");
        graph.admit_edge(edge).expect("edge admission");
        let encoded = serde_json::to_string(&graph).expect("strict graph serialization");
        let decoded: HypothesisGraph = serde_json::from_str(&encoded).expect("strict round trip");
        assert_eq!(decoded, graph);
        assert!(serde_json::from_str::<HypothesisGraph>(
            &encoded.replace("\"schema_version\":1", "\"schema_version\":1,\"extra\":true")
        )
        .is_err());
    }

    #[test]
    fn hypothesis_graph_rejects_unproven_edges_and_id_collisions() {
        let limits = GraphResourceLimits::default();
        let mut graph = HypothesisGraph::new(GraphId::new("graph:test"), limits).expect("graph");
        let actor = GraphNode::Actor(ActorNode::new("principal:digest", "principal-a").unwrap());
        let event = GraphNode::Event(EventNode::new("seed", GraphLogicalTime::new(100)).unwrap());
        let actor_id = actor.id().clone();
        let event_id = event.id().clone();
        graph.admit_node(actor).unwrap();
        graph.admit_node(event).unwrap();
        let no_evidence = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            5_000,
            [],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(100),
            EdgeState::Proposed,
        );
        assert!(no_evidence.is_err());
        let evidence = envelope("record:test", GraphProducerRole::Hunter);
        let evidence_id = evidence.evidence_id.clone();
        graph.admit_evidence(evidence).unwrap();
        let edge = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            5_000,
            [evidence_id],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(100),
            EdgeState::Proposed,
        )
        .unwrap();
        let mut changed = edge.clone();
        changed.confidence_basis_points = 5_001;
        assert!(graph.admit_edge(edge).is_ok());
        assert!(matches!(
            graph.admit_edge(changed),
            Err(GraphAdmissionError::IdCollision { .. })
        ));
    }

    #[test]
    fn hypothesis_graph_preserves_competing_hypotheses_and_append_only_decisions() {
        let confidence = ConfidenceDistribution::new([
            (ConfidenceBucket::High, 5_000),
            (ConfidenceBucket::Medium, 3_000),
            (ConfidenceBucket::Low, 1_000),
            (ConfidenceBucket::Unknown, 1_000),
        ])
        .expect("basis points sum");
        let contradiction = ContradictionRecord::new(
            ContradictionKind::EvidenceConflict,
            [EvidenceId::new("evidence:a"), EvidenceId::new("evidence:b")],
            "source observations disagree",
        )
        .expect("contradiction");
        let first = Hypothesis::new(
            HypothesisId::new("hypothesis:compromise"),
            confidence.clone(),
            [UncertaintyReason::ConflictingEvidence],
            [contradiction.contradiction_id.clone()],
        )
        .expect("first hypothesis");
        let second = Hypothesis::new(
            HypothesisId::new("hypothesis:automation"),
            ConfidenceDistribution::uniform_two(),
            [UncertaintyReason::InsufficientEvidence],
            [],
        )
        .expect("second hypothesis");
        assert_eq!(confidence.total_basis_points(), 10_000);
        assert_eq!(first.status, HypothesisStatus::Live);
        assert_eq!(second.status, HypothesisStatus::Live);
        let decision = DecisionRecord::new(
            DecisionKind::Support,
            first.hypothesis_id.clone(),
            [EvidenceId::new("evidence:a")],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(101),
            "supporting signal",
        )
        .expect("decision");
        let updated = first.append_decision(decision).expect("append");
        assert_eq!(updated.decision_history.len(), 1);
        assert_eq!(updated.status, HypothesisStatus::Live);
        assert_eq!(updated.contradiction_ids, first.contradiction_ids);
    }

    #[test]
    fn hypothesis_graph_tasks_kill_chain_memory_and_metrics_are_bounded_and_typed() {
        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:a")],
            [GraphNodeId::new("node:event:a")],
        )
        .expect("scope");
        let request = TaskClaimRequest::new(
            TaskId::new("task:a"),
            TaskKind::AcquireEvidence,
            TaskTarget::Evidence(EvidenceId::new("evidence:a")),
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            scope.clone(),
            GraphLogicalTime::new(100),
        )
        .expect("claim request");
        assert_eq!(request.idempotency_key, request.derive_idempotency_key().unwrap());
        let lease = TaskLease::new(
            LeaseId::new("lease:a"),
            request.claimant.clone(),
            GraphLogicalTime::new(100),
            GraphLogicalTime::new(200),
            FencingToken::new(1),
        )
        .expect("lease");
        let task = TaskRecord::claimed(request, lease).expect("task");
        assert_eq!(task.state, TaskState::Claimed);

        let claim = KillChainClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:process:a")],
            [EdgeId::new("edge:process:a")],
            [EvidenceId::new("evidence:a")],
            [],
            "process execution observed",
            [EvidenceId::new("evidence:a")],
        )
        .expect("kill chain claim");
        let reconstruction = KillChainReconstruction::new([claim], []).expect("chain");
        assert_eq!(reconstruction.claims.len(), 1);

        let memory = StrategyMemory::new(
            GraphId::new("graph:test"),
            HypothesisId::new("hypothesis:compromise"),
            HypothesisDelta::new([EdgeId::new("edge:process:a")], [], []),
            [EvidenceUtility::new(EvidenceId::new("evidence:a"), 8_000)],
            [HypothesisId::new("hypothesis:automation")],
            MemoryOutcome::Confirmed,
            MemoryProvenance::new(AgentId::new("hunter", "a"), [EvidenceId::new("evidence:a")]),
        )
        .expect("memory");
        assert!(!serde_json::to_string(&memory).unwrap().contains("raw"));

        let report = CollectiveMetricReport::new(
            MetricDenominators::new(2, 5, 6, 100, 16).unwrap(),
            MetricResults::new(4_000, 8_000, 500, 200, 9_500, 10_000).unwrap(),
        )
        .expect("metrics");
        assert_eq!(report.results.evidence_coverage_basis_points, 9_500);
        assert_eq!(task.state, TaskState::Claimed);
    }
}
