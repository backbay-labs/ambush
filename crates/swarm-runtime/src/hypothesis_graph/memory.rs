//! Post-commit strategy-memory projection and advisory task prioritization.
//!
//! The graph outbox is the authority boundary. This module only copies an
//! already committed typed memory into the query store and turns a relevant
//! match into a bounded scheduling hint. It cannot change confidence,
//! hypothesis status, task capability, or response authority.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use swarm_core::hypothesis_graph::{
    EvidenceId, GraphId, GraphLogicalTime, HypothesisId, MemoryId, TaskId, TaskTerminalOutboxEntry,
};
use swarm_spine::{
    GraphStoreSnapshot, RetrievedStrategyMemory, StrategyMemoryStore, StrategyMemoryStoreError,
};

const MAX_MEMORY_PRIORITY_BOOST_BASIS_POINTS: u16 = 2_000;
const MEMORY_RELEVANCE_DIVISOR: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPriorityProjection {
    pub base_priority_basis_points: u16,
    pub adjusted_priority_basis_points: u16,
    pub relevance_basis_points: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_id: Option<MemoryId>,
}

impl MemoryPriorityProjection {
    pub const fn unchanged(base_priority_basis_points: u16) -> Self {
        Self {
            base_priority_basis_points,
            adjusted_priority_basis_points: base_priority_basis_points,
            relevance_basis_points: 0,
            memory_id: None,
        }
    }
}

/// Apply exactly one best applicable memory. Matches are ordered by relevance
/// descending and memory ID ascending, so input order cannot affect priority.
pub fn project_memory_priority(
    base_priority_basis_points: u16,
    matches: &[RetrievedStrategyMemory],
) -> MemoryPriorityProjection {
    let best = matches.iter().max_by(|left, right| {
        left.matched
            .relevance_basis_points
            .cmp(&right.matched.relevance_basis_points)
            .then_with(|| {
                right
                    .record
                    .memory
                    .memory_id
                    .cmp(&left.record.memory.memory_id)
            })
    });
    let Some(best) = best else {
        return MemoryPriorityProjection::unchanged(base_priority_basis_points);
    };
    let relevance = best.matched.relevance_basis_points;
    let boost = (relevance / MEMORY_RELEVANCE_DIVISOR).min(MAX_MEMORY_PRIORITY_BOOST_BASIS_POINTS);
    MemoryPriorityProjection {
        base_priority_basis_points,
        adjusted_priority_basis_points: base_priority_basis_points
            .saturating_add(boost)
            .min(10_000),
        relevance_basis_points: relevance,
        memory_id: Some(best.record.memory.memory_id.clone()),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProjectionReport {
    pub examined: usize,
    pub inserted: usize,
    pub idempotent: usize,
}

#[derive(Clone)]
pub struct StrategyMemoryProjector {
    store: Arc<dyn StrategyMemoryStore>,
}

impl StrategyMemoryProjector {
    pub fn new(store: Arc<dyn StrategyMemoryStore>) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &Arc<dyn StrategyMemoryStore> {
        &self.store
    }

    /// Copy committed memories into the retrieval store. Re-scanning the
    /// append-only outbox is safe because `append_at` is content-idempotent.
    pub fn project_committed(
        &self,
        snapshot: &GraphStoreSnapshot,
    ) -> Result<MemoryProjectionReport, StrategyMemoryStoreError> {
        let mut report = MemoryProjectionReport::default();
        for entry in snapshot.terminal_outbox().values() {
            report.merge(self.project_entry(entry)?);
        }
        Ok(report)
    }

    /// Project only the terminal publication that just committed. Full
    /// outbox replay is reserved for startup recovery, avoiding quadratic
    /// rescans as the durable task history grows.
    pub fn project_committed_task(
        &self,
        snapshot: &GraphStoreSnapshot,
        task_id: &TaskId,
    ) -> Result<MemoryProjectionReport, StrategyMemoryStoreError> {
        let entry = snapshot.terminal_outbox().get(task_id).ok_or_else(|| {
            StrategyMemoryStoreError::InvalidState {
                reason: format!("committed task `{task_id}` has no terminal outbox entry"),
            }
        })?;
        self.project_entry(entry)
    }

    fn project_entry(
        &self,
        entry: &TaskTerminalOutboxEntry,
    ) -> Result<MemoryProjectionReport, StrategyMemoryStoreError> {
        let (Some(memory), Some(expiry)) = (&entry.memory, &entry.memory_expiry) else {
            return Ok(MemoryProjectionReport::default());
        };
        let ttl = expiry
            .expires_at
            .as_millis()
            .checked_sub(expiry.created_at.as_millis())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| StrategyMemoryStoreError::InvalidState {
                reason: "committed strategy-memory expiry is not ordered".to_string(),
            })?;
        let result = self
            .store
            .append_at(memory.clone(), expiry.created_at, ttl)?;
        Ok(MemoryProjectionReport {
            examined: 1,
            inserted: usize::from(!result.idempotent),
            idempotent: usize::from(result.idempotent),
        })
    }

    pub fn priority_for_context(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        now: GraphLogicalTime,
        base_priority_basis_points: u16,
    ) -> Result<MemoryPriorityProjection, StrategyMemoryStoreError> {
        let matches = self
            .store
            .retrieve_at(graph_id, hypothesis_id, evidence_ids, now, 16)?;
        Ok(project_memory_priority(
            base_priority_basis_points,
            &matches,
        ))
    }
}

impl MemoryProjectionReport {
    fn merge(&mut self, other: Self) {
        self.examined = self.examined.saturating_add(other.examined);
        self.inserted = self.inserted.saturating_add(other.inserted);
        self.idempotent = self.idempotent.saturating_add(other.idempotent);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use swarm_core::hypothesis_graph::{
        EvidenceUtility, GraphProducerRole, GraphResourceLimits, HypothesisDelta, MemoryOutcome,
        MemoryProvenance, StrategyMemory,
    };
    use swarm_core::types::AgentId;
    use swarm_crypto::Keypair;
    use swarm_spine::{MemoryStrategyMemoryStore, StrategyMemoryStore};

    #[test]
    fn priority_uses_one_best_memory_and_caps_the_boost() {
        let key = Keypair::from_seed(&[42; 32]);
        let graph_id = GraphId::new("graph:priority");
        let hypothesis_id = HypothesisId::new("hypothesis:malicious");
        let evidence_id = EvidenceId::new("evidence:priority");
        let identity = AgentId::from_public_key_hex(&key.public_key().to_hex());
        let provenance = MemoryProvenance::new(identity, [evidence_id.clone()])
            .signed_with(&key, GraphProducerRole::Falsifier, "memory-priority")
            .unwrap();
        let memory = StrategyMemory::new(
            graph_id.clone(),
            hypothesis_id.clone(),
            HypothesisDelta::new([], [], []),
            [EvidenceUtility::new(evidence_id.clone(), 10_000)],
            [],
            MemoryOutcome::Confirmed,
            provenance,
        )
        .unwrap()
        .signed_with(&key, GraphProducerRole::Falsifier, "memory-priority")
        .unwrap();
        let store = MemoryStrategyMemoryStore::new(key, GraphResourceLimits::default()).unwrap();
        store
            .append_at(memory, GraphLogicalTime::new(10), 100)
            .unwrap();
        let matches = store
            .retrieve_at(
                &graph_id,
                &hypothesis_id,
                &BTreeSet::from([evidence_id]),
                GraphLogicalTime::new(11),
                16,
            )
            .unwrap();

        let projected = project_memory_priority(8_500, &matches);
        assert_eq!(projected.adjusted_priority_basis_points, 10_000);
        assert!(projected.memory_id.is_some());
    }
}
