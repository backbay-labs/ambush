//! Runtime seams for the collective hypothesis graph.
//!
//! The typed records and their intrinsic validation live in `swarm-core`.
//! Runtime owns deterministic scheduling, source normalization, and the
//! witness/source-record admission index that makes idempotency and conflicts
//! explicit without changing the core record model.

pub mod clock;
pub mod containment_plan;
pub mod hypotheses;
pub mod kill_chain;
pub mod normalize;
pub mod tasks;

use std::collections::{BTreeMap, BTreeSet};

use swarm_core::config::HypothesisGraphConfig;
use swarm_core::hypothesis_graph::{
    CausalEdge, ConflictRecord, ContradictionId, ContradictionKind, DecisionRecord,
    EvidenceEnvelope, EvidenceId, EvidenceSourceFamily, GraphAdmissionError, GraphLogicalTime,
    GraphResourceLimits, GraphSchedulerKey, HypothesisGraph, SchedulerBudget,
};
use swarm_core::types::AgentId;
use swarm_crypto::Keypair;

pub use clock::{
    DeterministicScheduler, FixedGraphClock, GraphClock, ScheduledGraphTask, SystemObservationClock,
};
pub use containment_plan::{ContainmentPlanner, ContainmentPlanningInput};
pub use hypotheses::{
    HypothesisDisposition, HypothesisSeedAssessment, HypothesisSeedInput, competing_hypotheses,
    unresolved_task_targets,
};
pub use kill_chain::reconstruct_kill_chain;
pub use normalize::{
    MAX_RAW_PROJECTION_BYTES, MAX_RAW_PROJECTION_DEPTH, MAX_RAW_PROJECTION_NODES,
    MAX_SOURCE_TEXT_BYTES, SourceTimestampUnit, TETRAGON_FALLBACK_TIME_EVENT_ID_PREFIX,
    TETRAGON_FALLBACK_TIME_SOURCE_MARKER, normalize_source_timestamp, normalize_telemetry,
    normalize_telemetry_event, normalize_telemetry_event_with_unit, normalize_telemetry_with_unit,
    normalize_threat_intel, normalize_threat_intel_at, normalize_threat_intel_entry,
};
pub use tasks::{
    DurableHypothesisCoordinator, HypothesisCoordinationResult, HypothesisTaskLedger, TaskClaim,
    commit_terminal_once,
};

/// Runtime signing and verification seam for graph records produced after
/// evidence normalization.
///
/// The concrete implementation below owns an admitted key capability.  Role
/// and scoped labels are cryptographically bound witness metadata; the core
/// record derives its producer identity from the public key, and verification
/// requires that same admitted key.
pub trait GraphRecordSigner: Send + Sync {
    /// Return the key-derived identity admitted when this signer capability
    /// was constructed. Coordinator commits bind every initial decision to
    /// this identity at the durable store boundary.
    fn admitted_identity(&self) -> Result<AgentId, GraphAdmissionError>;

    fn sign_edge(
        &self,
        edge: CausalEdge,
        scoped_agent_id: &str,
    ) -> Result<CausalEdge, GraphAdmissionError>;

    fn sign_decision(
        &self,
        decision: DecisionRecord,
        scoped_agent_id: &str,
    ) -> Result<DecisionRecord, GraphAdmissionError>;

    fn verify_edge(&self, edge: &CausalEdge) -> Result<(), GraphAdmissionError>;

    fn verify_decision(&self, decision: &DecisionRecord) -> Result<(), GraphAdmissionError>;
}

/// Repository implementation of [`GraphRecordSigner`] backed by one admitted
/// Ed25519 keypair.
#[derive(Clone, Debug)]
pub struct KeypairGraphRecordSigner {
    key: Keypair,
    admitted_identity: Option<AgentId>,
}

impl KeypairGraphRecordSigner {
    pub fn new(key: Keypair) -> Self {
        Self {
            key,
            admitted_identity: None,
        }
    }

    /// Construct a signer only when its key-derived identity is present in
    /// the runtime admission allowlist.  The allowlist is snapshotted so a
    /// later external mutation cannot silently grant signing capability.
    pub fn with_admission(
        key: Keypair,
        admission: &WitnessAdmission,
    ) -> Result<Self, GraphAdmissionError> {
        let identity = AgentId::from_public_key_hex(&key.public_key().to_hex());
        if !admission.contains(&identity) {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "graph record signer key is not admitted".to_string(),
            });
        }
        Ok(Self {
            key,
            admitted_identity: Some(identity),
        })
    }

    pub fn new_with_admission(
        key: Keypair,
        admission: &WitnessAdmission,
    ) -> Result<Self, GraphAdmissionError> {
        Self::with_admission(key, admission)
    }

    pub fn key(&self) -> &Keypair {
        &self.key
    }

    fn ensure_admitted(&self) -> Result<(), GraphAdmissionError> {
        let identity = AgentId::from_public_key_hex(&self.key.public_key().to_hex());
        if self.admitted_identity.as_ref() != Some(&identity) {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "graph record signer key is not admitted".to_string(),
            });
        }
        Ok(())
    }
}

impl GraphRecordSigner for KeypairGraphRecordSigner {
    fn admitted_identity(&self) -> Result<AgentId, GraphAdmissionError> {
        self.ensure_admitted()?;
        Ok(AgentId::from_public_key_hex(
            &self.key.public_key().to_hex(),
        ))
    }

    fn sign_edge(
        &self,
        edge: CausalEdge,
        scoped_agent_id: &str,
    ) -> Result<CausalEdge, GraphAdmissionError> {
        self.ensure_admitted()?;
        edge.signed_with(&self.key, scoped_agent_id)
    }

    fn sign_decision(
        &self,
        decision: DecisionRecord,
        scoped_agent_id: &str,
    ) -> Result<DecisionRecord, GraphAdmissionError> {
        self.ensure_admitted()?;
        decision.signed_with(&self.key, scoped_agent_id)
    }

    fn verify_edge(&self, edge: &CausalEdge) -> Result<(), GraphAdmissionError> {
        self.ensure_admitted()?;
        verify_key_bound_identity(&self.key, &edge.producer_identity, edge.witness.as_ref())?;
        edge.validate(&GraphResourceLimits::default())
    }

    fn verify_decision(&self, decision: &DecisionRecord) -> Result<(), GraphAdmissionError> {
        self.ensure_admitted()?;
        verify_key_bound_identity(
            &self.key,
            &decision.producer_identity,
            decision.witness.as_ref(),
        )?;
        decision.validate()
    }
}

fn verify_key_bound_identity(
    key: &Keypair,
    producer_identity: &AgentId,
    witness: Option<&swarm_core::hypothesis_graph::EvidenceWitness>,
) -> Result<(), GraphAdmissionError> {
    let public_key_hex = key.public_key().to_hex();
    let expected_identity = AgentId::from_public_key_hex(&public_key_hex);
    if producer_identity != &expected_identity {
        return Err(GraphAdmissionError::InvalidWitness {
            reason: "record producer identity is not bound to the admitted key".to_string(),
        });
    }
    let witness = witness.ok_or(GraphAdmissionError::InvalidWitness {
        reason: "graph record requires a signed witness".to_string(),
    })?;
    if witness.public_key_hex != public_key_hex || witness.producer_identity != expected_identity {
        return Err(GraphAdmissionError::InvalidWitness {
            reason: "graph record witness is not bound to the admitted key".to_string(),
        });
    }
    Ok(())
}

/// Admission failures specific to the runtime witness/source-record index.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceAdmissionError {
    #[error(transparent)]
    Graph(#[from] GraphAdmissionError),

    #[error("evidence witness identity `{identity}` is not admitted")]
    UnadmittedWitness { identity: AgentId },

    #[error("evidence ID `{evidence_id}` was reused with different content")]
    SameIdDifferentContent { evidence_id: EvidenceId },
}

/// Result of admitting one signed envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceAdmissionOutcome {
    /// The envelope was newly admitted and did not conflict with a prior
    /// source record.
    Inserted { evidence_id: EvidenceId },
    /// The exact envelope was already present.  No state changed.
    Idempotent { evidence_id: EvidenceId },
    /// A new envelope was admitted and a deterministic visible conflict was
    /// recorded against an earlier envelope for the same source record.
    Conflict {
        evidence_id: EvidenceId,
        conflict: ConflictRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceRecordKey {
    family: EvidenceSourceFamily,
    source_id: String,
    source_record_id: String,
}

impl SourceRecordKey {
    fn from_envelope(envelope: &EvidenceEnvelope) -> Self {
        Self {
            family: envelope.source_family,
            source_id: envelope.source_id.clone(),
            source_record_id: envelope.lineage.source_record_id.clone(),
        }
    }
}

/// Base identities that may witness graph evidence.
///
/// Scoped role labels are intentionally absent from this set.  Two witnesses
/// signed by one base key therefore count as one independent source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WitnessAdmission {
    admitted: BTreeSet<AgentId>,
}

impl WitnessAdmission {
    pub fn new<I>(identities: I) -> Self
    where
        I: IntoIterator<Item = AgentId>,
    {
        Self {
            admitted: identities.into_iter().collect(),
        }
    }

    pub fn from_key(key: &Keypair) -> Self {
        Self::new([AgentId::from_public_key_hex(&key.public_key().to_hex())])
    }

    pub fn admit_identity(&mut self, identity: AgentId) -> bool {
        self.admitted.insert(identity)
    }

    pub fn admit_key(&mut self, key: &Keypair) -> AgentId {
        let identity = AgentId::from_public_key_hex(&key.public_key().to_hex());
        self.admitted.insert(identity.clone());
        identity
    }

    pub fn contains(&self, identity: &AgentId) -> bool {
        self.admitted.contains(identity)
    }

    pub fn identities(&self) -> &BTreeSet<AgentId> {
        &self.admitted
    }
}

/// Bounded in-memory evidence admission index.
///
/// Core admission already rejects malformed signatures and exact canonical-ID
/// collisions.  This layer adds the configured base-key allowlist and indexes
/// source lineage so a source record that changes facts or observation time
/// creates a visible deterministic conflict instead of silently overwriting a
/// prior record.
#[derive(Debug, Clone, Default)]
pub struct EvidenceRegistry {
    evidence: BTreeMap<EvidenceId, EvidenceEnvelope>,
    conflicts: BTreeMap<ContradictionId, ConflictRecord>,
    source_records: BTreeMap<SourceRecordKey, BTreeSet<EvidenceId>>,
    /// The constructor-time capability snapshot used for every admission
    /// decision.  This field is deliberately distinct from the legacy
    /// mutable accessor below: changing a caller-owned compatibility view
    /// must never widen the registry's trust boundary.
    witnesses: WitnessAdmission,
    /// Kept only so the historical mutable accessor remains source-compatible
    /// for downstream callers while being incapable of granting admission.
    /// Runtime admission never reads this field.
    legacy_witnesses: WitnessAdmission,
    limits: GraphResourceLimits,
    evidence_bytes: usize,
}

impl EvidenceRegistry {
    pub fn new(witnesses: WitnessAdmission) -> Self {
        Self {
            legacy_witnesses: witnesses.clone(),
            witnesses,
            limits: GraphResourceLimits::default(),
            evidence_bytes: 0,
            ..Self::default()
        }
    }

    /// Construct an index with the same bounded resource policy as a core
    /// graph.  Runtime-only aggregate caps map to the existing graph limits:
    /// `max_nodes` bounds evidence records, `max_hypotheses` bounds admitted
    /// witness identities, and `max_graph_fan_out` bounds one source record.
    pub fn with_limits(
        witnesses: WitnessAdmission,
        limits: GraphResourceLimits,
    ) -> Result<Self, EvidenceAdmissionError> {
        limits.validate()?;
        if witnesses.identities().len() > limits.max_hypotheses {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "witnesses".to_string(),
                    limit: limits.max_hypotheses,
                },
            ));
        }
        Ok(Self {
            legacy_witnesses: witnesses.clone(),
            witnesses,
            limits,
            evidence_bytes: 0,
            ..Self::default()
        })
    }

    pub fn new_with_limits(
        witnesses: WitnessAdmission,
        limits: GraphResourceLimits,
    ) -> Result<Self, EvidenceAdmissionError> {
        Self::with_limits(witnesses, limits)
    }

    pub fn with_identities<I>(identities: I) -> Self
    where
        I: IntoIterator<Item = AgentId>,
    {
        Self::new(WitnessAdmission::new(identities))
    }

    pub fn with_key(key: &Keypair) -> Self {
        Self::new(WitnessAdmission::from_key(key))
    }

    pub fn with_key_and_limits(
        key: &Keypair,
        limits: GraphResourceLimits,
    ) -> Result<Self, EvidenceAdmissionError> {
        Self::with_limits(WitnessAdmission::from_key(key), limits)
    }

    pub fn with_identities_and_limits<I>(
        identities: I,
        limits: GraphResourceLimits,
    ) -> Result<Self, EvidenceAdmissionError>
    where
        I: IntoIterator<Item = AgentId>,
    {
        Self::with_limits(WitnessAdmission::new(identities), limits)
    }

    pub fn limits(&self) -> &GraphResourceLimits {
        &self.limits
    }

    pub fn evidence(&self) -> &BTreeMap<EvidenceId, EvidenceEnvelope> {
        &self.evidence
    }

    pub fn conflicts(&self) -> &BTreeMap<ContradictionId, ConflictRecord> {
        &self.conflicts
    }

    pub fn witness_admission(&self) -> &WitnessAdmission {
        &self.witnesses
    }

    /// Return the historical mutable compatibility view.
    ///
    /// This view is not consulted by [`Self::admit`] or
    /// [`Self::admit_into_graph`].  New code should construct a new registry
    /// when its key-derived allowlist changes; mutating this value can never
    /// grant a producer capability to an existing registry.
    pub fn witness_admission_mut(&mut self) -> &mut WitnessAdmission {
        &mut self.legacy_witnesses
    }

    pub fn get(&self, evidence_id: &EvidenceId) -> Option<&EvidenceEnvelope> {
        self.evidence.get(evidence_id)
    }

    /// Admit one envelope after validating its canonical bytes and base key.
    pub fn admit(
        &mut self,
        envelope: EvidenceEnvelope,
    ) -> Result<EvidenceAdmissionOutcome, EvidenceAdmissionError> {
        match self.preflight(&envelope)? {
            AdmissionPlan::Idempotent => Ok(EvidenceAdmissionOutcome::Idempotent {
                evidence_id: envelope.evidence_id,
            }),
            AdmissionPlan::Insert {
                source_key,
                predecessor,
                successor,
                size,
            } => self.apply_insert(envelope, source_key, predecessor, successor, size),
        }
    }

    /// Admit an envelope into both the registry and a core graph.
    ///
    /// Both sides are validated on clones before either live value is changed,
    /// so an unadmitted witness or graph-limit failure cannot leave a partial
    /// cross-store mutation.
    pub fn admit_into_graph(
        &mut self,
        graph: &mut HypothesisGraph,
        envelope: EvidenceEnvelope,
    ) -> Result<EvidenceAdmissionOutcome, EvidenceAdmissionError> {
        // Perform all registry/resource checks before cloning either store.
        let plan = self.preflight(&envelope)?;
        let evidence_id = envelope.evidence_id.clone();
        let mut candidate_registry = self.clone();
        let outcome = candidate_registry.admit(envelope.clone())?;
        let new_conflict_ids = match &plan {
            AdmissionPlan::Insert {
                predecessor,
                successor,
                ..
            } => {
                let mut ids = Vec::with_capacity(2);
                if let Some(predecessor) = predecessor {
                    ids.push(
                        candidate_registry
                            .conflict_for_ids(predecessor, &evidence_id)?
                            .conflict_id,
                    );
                }
                if let Some(successor) = successor {
                    ids.push(
                        candidate_registry
                            .conflict_for_ids(&evidence_id, successor)?
                            .conflict_id,
                    );
                }
                ids
            }
            AdmissionPlan::Idempotent => Vec::new(),
        };
        let mut candidate_graph = graph.clone();
        candidate_graph.admit_evidence(envelope)?;
        for conflict_id in new_conflict_ids {
            let conflict = candidate_registry
                .conflicts
                .get(&conflict_id)
                .ok_or(EvidenceAdmissionError::Graph(
                    GraphAdmissionError::InvalidTransition {
                        reason: "candidate conflict index is incomplete".to_string(),
                    },
                ))?
                .clone();
            candidate_graph.admit_conflict(conflict)?;
        }
        *self = candidate_registry;
        *graph = candidate_graph;
        Ok(outcome)
    }

    /// Return the number of independent key-derived witnesses represented by
    /// all admitted evidence, ignoring scoped role aliases.
    pub fn independent_witness_count(&self) -> usize {
        self.evidence
            .values()
            .map(|evidence| evidence.witness.producer_identity.clone())
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn validate(&self) -> Result<(), EvidenceAdmissionError> {
        self.limits.validate()?;
        if self.evidence.len() > self.limits.max_nodes {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "evidence".to_string(),
                    limit: self.limits.max_nodes,
                },
            ));
        }
        if self.witnesses.identities().len() > self.limits.max_hypotheses {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "witnesses".to_string(),
                    limit: self.limits.max_hypotheses,
                },
            ));
        }
        if self.conflicts.len() > self.limits.max_contradictions {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "conflicts".to_string(),
                    limit: self.limits.max_contradictions,
                },
            ));
        }
        let mut evidence_bytes = 0_usize;
        for evidence in self.evidence.values() {
            evidence.validate()?;
            evidence_bytes = evidence_bytes.saturating_add(evidence.canonical_bytes()?.len());
            if !self.witnesses.contains(&evidence.witness.producer_identity) {
                return Err(EvidenceAdmissionError::UnadmittedWitness {
                    identity: evidence.witness.producer_identity.clone(),
                });
            }
        }
        if evidence_bytes != self.evidence_bytes {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::InvalidTransition {
                    reason: "evidence byte accounting is inconsistent".to_string(),
                },
            ));
        }
        if evidence_bytes > self.limits.max_evidence_bytes {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "evidence_bytes".to_string(),
                    limit: self.limits.max_evidence_bytes,
                },
            ));
        }
        for conflict in self.conflicts.values() {
            conflict.validate()?;
            if !self.evidence.contains_key(&conflict.left_evidence_id)
                || !self.evidence.contains_key(&conflict.right_evidence_id)
            {
                return Err(EvidenceAdmissionError::Graph(
                    GraphAdmissionError::UnknownEvidence,
                ));
            }
        }
        for (source_key, evidence_ids) in &self.source_records {
            if evidence_ids.len() > self.limits.max_graph_fan_out {
                return Err(EvidenceAdmissionError::Graph(
                    GraphAdmissionError::ResourceLimitExceeded {
                        resource: "source_record_evidence".to_string(),
                        limit: self.limits.max_graph_fan_out,
                    },
                ));
            }
            for evidence_id in evidence_ids {
                let evidence =
                    self.evidence
                        .get(evidence_id)
                        .ok_or(EvidenceAdmissionError::Graph(
                            GraphAdmissionError::UnknownEvidence,
                        ))?;
                if SourceRecordKey::from_envelope(evidence) != *source_key {
                    return Err(EvidenceAdmissionError::Graph(
                        GraphAdmissionError::InvalidTransition {
                            reason: "source-record index does not match evidence lineage"
                                .to_string(),
                        },
                    ));
                }
            }
        }
        for (evidence_id, evidence) in &self.evidence {
            let source_key = SourceRecordKey::from_envelope(evidence);
            if !self
                .source_records
                .get(&source_key)
                .is_some_and(|evidence_ids| evidence_ids.contains(evidence_id))
            {
                return Err(EvidenceAdmissionError::Graph(
                    GraphAdmissionError::InvalidTransition {
                        reason: "evidence is absent from source-record index".to_string(),
                    },
                ));
            }
        }
        for (source_key, evidence_ids) in &self.source_records {
            let ids = evidence_ids.iter().collect::<Vec<_>>();
            for pair in ids.windows(2) {
                let conflict = self.conflict_for_ids(pair[0], pair[1])?;
                if !self.conflicts.contains_key(&conflict.conflict_id) {
                    return Err(EvidenceAdmissionError::Graph(
                        GraphAdmissionError::InvalidTransition {
                            reason: format!(
                                "missing adjacent conflict for source record {:?}:{}:{}",
                                source_key.family,
                                source_key.source_id,
                                source_key.source_record_id
                            ),
                        },
                    ));
                }
            }
        }
        Ok(())
    }

    fn preflight(
        &self,
        envelope: &EvidenceEnvelope,
    ) -> Result<AdmissionPlan, EvidenceAdmissionError> {
        envelope.validate()?;
        let identity = envelope.witness.producer_identity.clone();
        if !self.witnesses.contains(&identity) {
            return Err(EvidenceAdmissionError::UnadmittedWitness { identity });
        }
        if let Some(existing) = self.evidence.get(&envelope.evidence_id) {
            if existing.deterministic_content_bytes()? == envelope.deterministic_content_bytes()? {
                return Ok(AdmissionPlan::Idempotent);
            }
            return Err(EvidenceAdmissionError::SameIdDifferentContent {
                evidence_id: envelope.evidence_id.clone(),
            });
        }
        if self.evidence.len() >= self.limits.max_nodes {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "evidence".to_string(),
                    limit: self.limits.max_nodes,
                },
            ));
        }
        if self.witnesses.identities().len() > self.limits.max_hypotheses {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "witnesses".to_string(),
                    limit: self.limits.max_hypotheses,
                },
            ));
        }
        let size = envelope.canonical_bytes()?.len();
        if self.evidence_bytes.saturating_add(size) > self.limits.max_evidence_bytes {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "evidence_bytes".to_string(),
                    limit: self.limits.max_evidence_bytes,
                },
            ));
        }
        let source_key = SourceRecordKey::from_envelope(envelope);
        let existing_ids = self.source_records.get(&source_key);
        let source_len = existing_ids.map_or(0, BTreeSet::len);
        if source_len >= self.limits.max_graph_fan_out {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "source_record_evidence".to_string(),
                    limit: self.limits.max_graph_fan_out,
                },
            ));
        }
        let (predecessor, successor) = existing_ids.map_or((None, None), |ids| {
            (
                ids.range(..&envelope.evidence_id).next_back().cloned(),
                ids.range(envelope.evidence_id.clone()..).next().cloned(),
            )
        });
        let added = usize::from(predecessor.is_some()) + usize::from(successor.is_some());
        if self.conflicts.len().saturating_add(added) > self.limits.max_contradictions {
            return Err(EvidenceAdmissionError::Graph(
                GraphAdmissionError::ResourceLimitExceeded {
                    resource: "conflicts".to_string(),
                    limit: self.limits.max_contradictions,
                },
            ));
        }
        Ok(AdmissionPlan::Insert {
            source_key,
            predecessor,
            successor,
            size,
        })
    }

    fn apply_insert(
        &mut self,
        envelope: EvidenceEnvelope,
        source_key: SourceRecordKey,
        predecessor: Option<EvidenceId>,
        successor: Option<EvidenceId>,
        size: usize,
    ) -> Result<EvidenceAdmissionOutcome, EvidenceAdmissionError> {
        let evidence_id = envelope.evidence_id.clone();
        self.evidence.insert(evidence_id.clone(), envelope);
        self.evidence_bytes = self.evidence_bytes.saturating_add(size);
        self.source_records
            .entry(source_key)
            .or_default()
            .insert(evidence_id.clone());

        let mut new_conflicts = Vec::with_capacity(2);
        if let Some(predecessor) = predecessor {
            new_conflicts.push(self.conflict_for_ids(&predecessor, &evidence_id)?);
        }
        if let Some(successor) = successor {
            new_conflicts.push(self.conflict_for_ids(&evidence_id, &successor)?);
        }
        for conflict in &new_conflicts {
            self.conflicts
                .insert(conflict.conflict_id.clone(), conflict.clone());
        }
        if let Some(conflict) = new_conflicts.into_iter().next() {
            Ok(EvidenceAdmissionOutcome::Conflict {
                evidence_id,
                conflict,
            })
        } else {
            Ok(EvidenceAdmissionOutcome::Inserted { evidence_id })
        }
    }

    fn conflict_for_ids(
        &self,
        left_id: &EvidenceId,
        right_id: &EvidenceId,
    ) -> Result<ConflictRecord, EvidenceAdmissionError> {
        let left = self
            .evidence
            .get(left_id)
            .ok_or(EvidenceAdmissionError::Graph(
                GraphAdmissionError::UnknownEvidence,
            ))?;
        let right = self
            .evidence
            .get(right_id)
            .ok_or(EvidenceAdmissionError::Graph(
                GraphAdmissionError::UnknownEvidence,
            ))?;
        let kind = if left.clock.observed_at != right.clock.observed_at {
            ContradictionKind::SourceTimeConflict
        } else {
            ContradictionKind::EvidenceConflict
        };
        let comparison_basis = if kind == ContradictionKind::SourceTimeConflict {
            "same source record has conflicting observed times"
        } else {
            "same source record has conflicting typed facts"
        };
        Ok(ConflictRecord::new(
            left_id.clone(),
            right_id.clone(),
            kind,
            comparison_basis,
        )?)
    }
}

#[derive(Debug, Clone)]
enum AdmissionPlan {
    Idempotent,
    Insert {
        source_key: SourceRecordKey,
        predecessor: Option<EvidenceId>,
        successor: Option<EvidenceId>,
        size: usize,
    },
}

/// The runtime state needed by the stable core slice.  Durable persistence,
/// hypothesis adjudication, and response authority are intentionally owned by
/// later plans; this type only composes the injected clock, scheduler, and
/// signed evidence registry.
#[derive(Debug, Clone)]
pub struct HypothesisGraphRuntime<C: GraphClock> {
    pub clock: C,
    pub scheduler: DeterministicScheduler,
    pub evidence: EvidenceRegistry,
    /// Optional per-logical-tick budget.  Legacy/default constructors leave
    /// this disabled so existing scheduling behavior remains unchanged;
    /// `with_config` enables it only for an explicitly enabled graph config.
    pub budget: Option<SchedulerBudget>,
    /// The validated deployment configuration that owns `budget`'s ceilings.
    /// It is private so callers cannot widen the active reasoning limits by
    /// mutating a runtime-owned configuration after construction.
    budget_config: Option<HypothesisGraphConfig>,
}

impl<C: GraphClock> HypothesisGraphRuntime<C> {
    pub fn new(clock: C, evidence: EvidenceRegistry) -> Self {
        let scheduler_limits = evidence.limits().clone();
        Self {
            clock,
            scheduler: DeterministicScheduler::from_validated_limits(scheduler_limits),
            evidence,
            budget: None,
            budget_config: None,
        }
    }

    /// Construct runtime orchestration with one explicit resource policy.
    /// Callers should pass the same limits to [`EvidenceRegistry::with_limits`]
    /// so the queue and evidence index enforce one bounded graph contract.
    pub fn with_limits(
        clock: C,
        evidence: EvidenceRegistry,
        limits: GraphResourceLimits,
    ) -> Result<Self, GraphAdmissionError> {
        limits.validate()?;
        if evidence.limits() != &limits {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "runtime registry and scheduler limits must match".to_string(),
            });
        }
        Ok(Self {
            clock,
            scheduler: DeterministicScheduler::with_limits(limits)?,
            evidence,
            budget: None,
            budget_config: None,
        })
    }

    pub fn new_with_limits(
        clock: C,
        evidence: EvidenceRegistry,
        limits: GraphResourceLimits,
    ) -> Result<Self, GraphAdmissionError> {
        Self::with_limits(clock, evidence, limits)
    }

    /// Construct a runtime bound to one validated collective-reasoning config.
    /// The injected clock supplies the initial logical budget tick; callers
    /// that already own a replay tick can use [`Self::with_config_at`].
    pub fn with_config(
        clock: C,
        evidence: EvidenceRegistry,
        config: &HypothesisGraphConfig,
    ) -> Result<Self, GraphAdmissionError> {
        let current_tick = GraphLogicalTime::new(clock.now_ms());
        Self::with_config_at(clock, evidence, config, current_tick)
    }

    /// Construct a runtime with an explicit logical budget tick.  Resource
    /// limits are checked against the registry before any scheduler or budget
    /// state is published, and the per-tick budget is created only after the
    /// config's reasoning ceilings validate.
    pub fn with_config_at(
        clock: C,
        evidence: EvidenceRegistry,
        config: &HypothesisGraphConfig,
        current_tick: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        config.validate_reasoning_limits()?;
        let limits = config.resource_limits();
        limits.validate()?;
        let budget = if config.enabled {
            Some(SchedulerBudget::new_with_config(config, current_tick)?)
        } else {
            None
        };
        let mut runtime = Self::with_limits(clock, evidence, limits)?;
        runtime.budget = budget;
        runtime.budget_config = config.enabled.then(|| config.clone());
        Ok(runtime)
    }

    pub fn new_with_config(
        clock: C,
        evidence: EvidenceRegistry,
        config: &HypothesisGraphConfig,
    ) -> Result<Self, GraphAdmissionError> {
        Self::with_config(clock, evidence, config)
    }

    pub fn new_with_config_at(
        clock: C,
        evidence: EvidenceRegistry,
        config: &HypothesisGraphConfig,
        current_tick: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        Self::with_config_at(clock, evidence, config, current_tick)
    }

    /// Admit scheduler work at an explicit logical time.  Disabled/default
    /// runtimes validate the time but retain the historical no-budget path.
    pub fn admit_scheduler_work(
        &mut self,
        logical_tick: GraphLogicalTime,
        work_units: u32,
        claims: u16,
    ) -> Result<(), GraphAdmissionError> {
        logical_tick.validate()?;
        match (&mut self.budget, &self.budget_config) {
            (Some(budget), Some(config)) => {
                budget.admit_at(config, logical_tick, work_units, claims)?;
            }
            (None, None) => {}
            (Some(_), None) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "scheduler budget is not bound to an active config".to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "active scheduler budget is missing".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Pop one ready task while atomically admitting its logical work/claim
    /// cost.  A future or absent task does not consume budget or scheduler
    /// state; an over-limit admission leaves both byte-identical.
    pub fn pop_ready_budgeted(
        &mut self,
        now: GraphLogicalTime,
        work_units: u32,
        claims: u16,
    ) -> Result<Option<GraphSchedulerKey>, GraphAdmissionError> {
        now.validate()?;
        let Some(next) = self.scheduler.peek() else {
            return Ok(None);
        };
        if next.ready_at > now {
            return Ok(None);
        }

        let mut candidate_budget = self.budget.clone();
        match (&mut candidate_budget, &self.budget_config) {
            (Some(budget), Some(config)) => {
                budget.admit_at(config, now, work_units, claims)?;
            }
            (None, None) => {}
            (Some(_), None) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "scheduler budget is not bound to an active config".to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "active scheduler budget is missing".to_string(),
                });
            }
        }
        let popped = self.scheduler.pop_ready(now)?;
        if popped.is_some() {
            self.budget = candidate_budget;
        }
        Ok(popped)
    }

    pub fn now(&self) -> Result<GraphLogicalTime, GraphAdmissionError> {
        let now = GraphLogicalTime::new(self.clock.now_ms());
        now.validate()?;
        Ok(now)
    }

    pub fn limits_default() -> GraphResourceLimits {
        GraphResourceLimits::default()
    }
}
