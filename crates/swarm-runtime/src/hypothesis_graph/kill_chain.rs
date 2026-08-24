//! Evidence-linked kill-chain reconstruction.

use std::collections::{BTreeMap, BTreeSet};

use swarm_core::hypothesis_graph::{
    CausalEdge, EdgeId, EvidenceId, GraphAdmissionError, GraphNodeId,
    KillChainClaim as AdmittedKillChainClaim, KillChainClaimId, KillChainOrder, KillChainStage,
    MissingEvidence,
};

/// Evidence retained for each causal edge in a kill-chain claim.
///
/// The core claim only carries the edge IDs and the claim-wide evidence set;
/// this runtime map preserves the exact edge-to-evidence relation needed to
/// remove one withheld support without discarding an independently supported
/// edge.
pub type EdgeEvidenceSupport = BTreeMap<EdgeId, BTreeSet<EvidenceId>>;

/// A retained projection of one admitted claim after evidence withholding.
///
/// The source claim is kept privately so the projection can retain the real
/// claim identity and ordering without pretending that the content-addressed
/// claim was re-issued after support was removed. Public fields are the
/// support actually available to downstream runtime consumers: withheld
/// evidence, narration links, and only unsupported edge lineage are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillChainClaim {
    pub schema_version: u32,
    pub claim_id: KillChainClaimId,
    pub stage: KillChainStage,
    pub node_ids: BTreeSet<GraphNodeId>,
    pub edge_ids: BTreeSet<EdgeId>,
    pub edge_evidence_ids: EdgeEvidenceSupport,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub predecessor_claim_ids: BTreeSet<KillChainClaimId>,
    pub order: KillChainOrder,
    pub narration: String,
    pub narration_evidence_ids: BTreeSet<EvidenceId>,
    source: AdmittedKillChainClaim,
    source_edge_supports: EdgeEvidenceSupport,
    withheld_evidence_ids: BTreeSet<EvidenceId>,
}

impl KillChainClaim {
    fn from_source(
        source: AdmittedKillChainClaim,
        edge_support: &EdgeEvidenceSupport,
        withheld_evidence_ids: &BTreeSet<EvidenceId>,
    ) -> Result<Self, GraphAdmissionError> {
        let mut edge_ids = BTreeSet::new();
        let mut edge_evidence_ids = BTreeMap::new();
        for edge_id in &source.edge_ids {
            let support =
                edge_support
                    .get(edge_id)
                    .ok_or_else(|| GraphAdmissionError::InvalidField {
                        field: "kill_chain.edge_evidence_ids".to_string(),
                        reason: format!("missing support for source edge {edge_id}"),
                    })?;
            let retained_support = support
                .difference(withheld_evidence_ids)
                .cloned()
                .collect::<BTreeSet<_>>();
            if !retained_support.is_empty() {
                edge_ids.insert(edge_id.clone());
                edge_evidence_ids.insert(edge_id.clone(), retained_support);
            }
        }
        Ok(Self {
            schema_version: source.schema_version,
            claim_id: source.claim_id.clone(),
            stage: source.stage,
            node_ids: source.node_ids.clone(),
            edge_ids,
            edge_evidence_ids,
            evidence_ids: source
                .evidence_ids
                .difference(withheld_evidence_ids)
                .cloned()
                .collect(),
            predecessor_claim_ids: source.predecessor_claim_ids.clone(),
            order: source.order,
            narration: source.narration.clone(),
            narration_evidence_ids: source
                .narration_evidence_ids
                .difference(withheld_evidence_ids)
                .cloned()
                .collect(),
            source,
            source_edge_supports: edge_support.clone(),
            withheld_evidence_ids: withheld_evidence_ids.clone(),
        })
    }

    /// Validate that public projection fields still match the admitted claim
    /// and the exact withheld set captured at construction time.
    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        self.source.validate()?;
        let edge_support = self.source_edge_supports.clone();
        let expected = Self::from_source(
            self.source.clone(),
            &edge_support,
            &self.withheld_evidence_ids,
        )?;
        if self != &expected {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: format!(
                    "retained kill-chain claim {} was mutated after admission",
                    self.claim_id
                ),
            });
        }
        Ok(())
    }

    pub fn withheld_evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.withheld_evidence_ids
    }

    /// Return the exact support retained for each projected edge.
    pub fn edge_evidence_ids(&self) -> &EdgeEvidenceSupport {
        &self.edge_evidence_ids
    }
}

/// Runtime reconstruction with an immutable provenance anchor.
///
/// `swarm-core`'s [`AdmittedKillChainClaim`] is content-addressed: changing
/// evidence or links necessarily changes its derived ID. This production
/// wrapper therefore retains each real admitted claim ID/order in a private
/// source anchor while exposing a support-removed projection to containment.
/// A caller can mutate public fields for a negative test, but [`validate`]
/// rejects the mutation against that anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillChainReconstruction {
    pub claims: Vec<KillChainClaim>,
    pub missing_evidence: Vec<MissingEvidence>,
    source_claims: Vec<AdmittedKillChainClaim>,
    edge_support: EdgeEvidenceSupport,
    withheld_evidence_ids: BTreeSet<EvidenceId>,
    expected_missing_evidence: Vec<MissingEvidence>,
    edge_support_exact: bool,
    expected_edge_support_exact: bool,
}

impl KillChainReconstruction {
    /// Build an unwithheld runtime reconstruction from already admitted core
    /// claims. Persisted containment still must use the snapshot-bound
    /// constructor on [`ContainmentPlanningInput`].
    pub fn new<I, J>(claims: I, missing_evidence: J) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = AdmittedKillChainClaim>,
        J: IntoIterator<Item = MissingEvidence>,
    {
        let source_claims = claims.into_iter().collect::<Vec<_>>();
        let missing_evidence = missing_evidence.into_iter().collect::<Vec<_>>();
        if !missing_evidence.is_empty() {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "missing evidence must be produced by reconstruct_kill_chain withholding"
                    .to_string(),
            });
        }
        let source = swarm_core::hypothesis_graph::KillChainReconstruction::new(
            source_claims.clone(),
            missing_evidence.clone(),
        )?;
        let edge_support = default_edge_support(&source_claims)?;
        Self::from_admitted_source(
            source_claims,
            edge_support,
            BTreeSet::new(),
            missing_evidence,
            false,
            &source,
        )
    }

    /// Build an unwithheld reconstruction while retaining exact support for
    /// every edge. The map must contain exactly one non-empty support set for
    /// each edge referenced by the admitted claims.
    pub fn new_with_edge_support<I, J>(
        claims: I,
        edge_support: EdgeEvidenceSupport,
        missing_evidence: J,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = AdmittedKillChainClaim>,
        J: IntoIterator<Item = MissingEvidence>,
    {
        let source_claims = claims.into_iter().collect::<Vec<_>>();
        let missing_evidence = missing_evidence.into_iter().collect::<Vec<_>>();
        if !missing_evidence.is_empty() {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "missing evidence must be produced by reconstruct_kill_chain withholding"
                    .to_string(),
            });
        }
        let source =
            swarm_core::hypothesis_graph::KillChainReconstruction::new(source_claims.clone(), [])?;
        validate_edge_support(&source_claims, &edge_support)?;
        Self::from_admitted_source(
            source_claims,
            edge_support,
            BTreeSet::new(),
            missing_evidence,
            true,
            &source,
        )
    }

    fn from_withheld(
        source_claims: Vec<AdmittedKillChainClaim>,
        edge_support: EdgeEvidenceSupport,
        withheld_evidence_ids: BTreeSet<EvidenceId>,
        edge_support_exact: bool,
    ) -> Result<Self, GraphAdmissionError> {
        let admitted_evidence = source_claims
            .iter()
            .flat_map(|claim| claim.evidence_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        if let Some(unknown) = withheld_evidence_ids.difference(&admitted_evidence).next() {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain.withheld_evidence_ids".to_string(),
                reason: format!("withheld evidence {unknown} is not linked to an admitted claim"),
            });
        }
        let source =
            swarm_core::hypothesis_graph::KillChainReconstruction::new(source_claims.clone(), [])?;
        if edge_support_exact {
            validate_edge_support(&source_claims, &edge_support)?;
        }
        let mut expected_missing_evidence = Vec::new();
        for claim in &source_claims {
            let removed = claim
                .evidence_ids
                .intersection(&withheld_evidence_ids)
                .cloned()
                .collect::<Vec<_>>();
            if !removed.is_empty() {
                expected_missing_evidence.push(MissingEvidence::new(
                    claim.claim_id.clone(),
                    expected_support_scope(&claim.claim_id, &removed),
                    format!(
                        "supporting evidence was withheld: {}",
                        removed
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                )?);
            }
        }
        Self::from_admitted_source(
            source_claims,
            edge_support,
            withheld_evidence_ids,
            expected_missing_evidence.clone(),
            edge_support_exact,
            &source,
        )
    }

    fn from_admitted_source(
        source_claims: Vec<AdmittedKillChainClaim>,
        edge_support: EdgeEvidenceSupport,
        withheld_evidence_ids: BTreeSet<EvidenceId>,
        missing_evidence: Vec<MissingEvidence>,
        edge_support_exact: bool,
        source: &swarm_core::hypothesis_graph::KillChainReconstruction,
    ) -> Result<Self, GraphAdmissionError> {
        validate_edge_support(&source_claims, &edge_support)?;
        let claims = source_claims
            .iter()
            .cloned()
            .map(|claim| KillChainClaim::from_source(claim, &edge_support, &withheld_evidence_ids))
            .collect::<Result<Vec<_>, GraphAdmissionError>>()?;
        let reconstruction = Self {
            claims,
            missing_evidence: missing_evidence.clone(),
            source_claims,
            edge_support,
            withheld_evidence_ids,
            expected_missing_evidence: missing_evidence,
            edge_support_exact,
            expected_edge_support_exact: edge_support_exact,
        };
        reconstruction.validate_against_source(source)?;
        Ok(reconstruction)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        let source = swarm_core::hypothesis_graph::KillChainReconstruction::new(
            self.source_claims.clone(),
            self.expected_missing_evidence.clone(),
        )?;
        self.validate_against_source(&source)
    }

    fn validate_against_source(
        &self,
        source: &swarm_core::hypothesis_graph::KillChainReconstruction,
    ) -> Result<(), GraphAdmissionError> {
        if self.claims.len() != self.source_claims.len()
            || self.missing_evidence != self.expected_missing_evidence
            || self.edge_support_exact != self.expected_edge_support_exact
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "kill-chain reconstruction was mutated after admission".to_string(),
            });
        }
        validate_edge_support(&self.source_claims, &self.edge_support)?;
        for (retained, admitted) in self.claims.iter().zip(&self.source_claims) {
            if retained.source != *admitted {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "kill-chain source provenance was mutated".to_string(),
                });
            }
            retained.validate()?;
        }
        for missing in &self.missing_evidence {
            missing.validate()?;
            if !self
                .source_claims
                .iter()
                .any(|claim| claim.claim_id == missing.claim_id)
            {
                return Err(GraphAdmissionError::InvalidField {
                    field: "missing_evidence.claim_id".to_string(),
                    reason: "missing evidence must reference an admitted claim".to_string(),
                });
            }
        }
        source.validate()
    }

    pub fn withheld_evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.withheld_evidence_ids
    }

    /// A chain is complete only when no withheld support or explicit missing
    /// evidence remains and exact persisted support provenance is present.
    /// The claim-wide compatibility constructor remains available for legacy
    /// reporting, but it is explicitly incomplete and cannot enter
    /// snapshot-bound containment.
    pub fn support_complete(&self) -> bool {
        self.withheld_evidence_ids.is_empty()
            && self.missing_evidence.is_empty()
            && self.edge_support_exact
    }

    /// Whether the reconstruction was built with an exact edge-to-evidence
    /// map rather than the compatibility fallback that associates every edge
    /// with all claim evidence.
    pub fn has_exact_edge_support(&self) -> bool {
        self.edge_support_exact
    }
}

/// Reconstruct a chain from already-admitted claims. Withheld support is
/// removed from the retained projection while each real claim ID and its
/// supported order remain anchored to the admitted source claim.
pub fn reconstruct_kill_chain<I, J>(
    claims: I,
    withheld_evidence_ids: J,
) -> Result<KillChainReconstruction, GraphAdmissionError>
where
    I: IntoIterator<Item = AdmittedKillChainClaim>,
    J: IntoIterator<Item = EvidenceId>,
{
    let withheld_evidence_ids = withheld_evidence_ids.into_iter().collect::<Vec<_>>();
    let withheld_set = withheld_evidence_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if withheld_set.len() != withheld_evidence_ids.len() {
        return Err(GraphAdmissionError::InvalidField {
            field: "kill_chain.withheld_evidence_ids".to_string(),
            reason: "duplicate withheld evidence IDs are not allowed".to_string(),
        });
    }
    let source_claims = claims.into_iter().collect::<Vec<_>>();
    let edge_support = default_edge_support(&source_claims)?;
    KillChainReconstruction::from_withheld(source_claims, edge_support, withheld_set, false)
}

/// Reconstruct a chain using exact edge support from the persisted graph.
/// Withholding removes only edges whose complete support was withheld; edges
/// retaining independent evidence stay in the projection with their retained
/// support map.
pub fn reconstruct_kill_chain_with_edge_support<I, J>(
    claims: I,
    edge_support: EdgeEvidenceSupport,
    withheld_evidence_ids: J,
) -> Result<KillChainReconstruction, GraphAdmissionError>
where
    I: IntoIterator<Item = AdmittedKillChainClaim>,
    J: IntoIterator<Item = EvidenceId>,
{
    let withheld_evidence_ids = withheld_evidence_ids.into_iter().collect::<Vec<_>>();
    let withheld_set = withheld_evidence_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if withheld_set.len() != withheld_evidence_ids.len() {
        return Err(GraphAdmissionError::InvalidField {
            field: "kill_chain.withheld_evidence_ids".to_string(),
            reason: "duplicate withheld evidence IDs are not allowed".to_string(),
        });
    }
    KillChainReconstruction::from_withheld(
        claims.into_iter().collect(),
        edge_support,
        withheld_set,
        true,
    )
}

/// Convenience adapter for a persisted edge map.
pub fn reconstruct_kill_chain_with_edges<I, J, K>(
    claims: I,
    edges: K,
    withheld_evidence_ids: J,
) -> Result<KillChainReconstruction, GraphAdmissionError>
where
    I: IntoIterator<Item = AdmittedKillChainClaim>,
    J: IntoIterator<Item = EvidenceId>,
    K: IntoIterator<Item = CausalEdge>,
{
    let edges = edges.into_iter().collect::<Vec<_>>();
    let mut edge_ids = BTreeSet::new();
    for edge in &edges {
        if !edge_ids.insert(edge.edge_id.clone()) {
            return Err(GraphAdmissionError::IdCollision {
                id: edge.edge_id.to_string(),
            });
        }
    }
    let edge_support = edges
        .into_iter()
        .map(|edge| (edge.edge_id, edge.source_evidence_ids))
        .collect::<EdgeEvidenceSupport>();
    reconstruct_kill_chain_with_edge_support(claims, edge_support, withheld_evidence_ids)
}

fn default_edge_support(
    source_claims: &[AdmittedKillChainClaim],
) -> Result<EdgeEvidenceSupport, GraphAdmissionError> {
    let mut edge_support = EdgeEvidenceSupport::new();
    for claim in source_claims {
        for edge_id in &claim.edge_ids {
            if let Some(previous) = edge_support.insert(edge_id.clone(), claim.evidence_ids.clone())
                && previous != claim.evidence_ids
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: format!("edge {edge_id} has conflicting claim evidence support"),
                });
            }
        }
    }
    Ok(edge_support)
}

fn validate_edge_support(
    source_claims: &[AdmittedKillChainClaim],
    edge_support: &EdgeEvidenceSupport,
) -> Result<(), GraphAdmissionError> {
    let expected_edges = source_claims
        .iter()
        .flat_map(|claim| claim.edge_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let actual_edges = edge_support.keys().cloned().collect::<BTreeSet<_>>();
    if expected_edges != actual_edges {
        return Err(GraphAdmissionError::InvalidField {
            field: "kill_chain.edge_evidence_ids".to_string(),
            reason: "edge support must cover exactly the admitted claim edges".to_string(),
        });
    }
    for claim in source_claims {
        for edge_id in &claim.edge_ids {
            let support =
                edge_support
                    .get(edge_id)
                    .ok_or_else(|| GraphAdmissionError::InvalidField {
                        field: "kill_chain.edge_evidence_ids".to_string(),
                        reason: format!("missing support for edge {edge_id}"),
                    })?;
            if support.is_empty() || !support.is_subset(&claim.evidence_ids) {
                return Err(GraphAdmissionError::InvalidField {
                    field: "kill_chain.edge_evidence_ids".to_string(),
                    reason: format!(
                        "support for edge {edge_id} must be non-empty and belong to its claim"
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Stable, auditable scope for a withheld support record.
fn expected_support_scope(claim_id: &KillChainClaimId, evidence_ids: &[EvidenceId]) -> String {
    format!(
        "kill_chain.claim:{claim_id}.supporting_evidence:{}",
        evidence_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use swarm_core::hypothesis_graph::{
        CausalRelation, EdgeId, EdgeState, GraphLogicalTime, GraphNodeId, GraphProducerRole,
        KillChainClaim as CoreClaim,
    };
    use swarm_core::types::AgentId;
    use swarm_crypto::Keypair;

    fn claim() -> CoreClaim {
        CoreClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:process")],
            [EdgeId::new("edge:execution")],
            [EvidenceId::new("evidence:execution")],
            [],
            "execution is supported",
            [EvidenceId::new("evidence:execution")],
        )
        .expect("test claim must be valid")
    }

    fn signed_edge(evidence_id: EvidenceId) -> CausalEdge {
        let signer = Keypair::from_seed(&[77_u8; 32]);
        CausalEdge::new(
            &GraphNodeId::new("node:from"),
            &GraphNodeId::new("node:to"),
            CausalRelation::ObservedIn,
            8_000,
            [evidence_id],
            GraphProducerRole::Hunter,
            AgentId::from_public_key_hex(&signer.public_key().to_hex()),
            GraphLogicalTime::new(1),
            EdgeState::Proposed,
        )
        .expect("edge must be constructible")
        .signed_with(&signer, "hunter:kill-chain-test")
        .expect("edge must be signed")
    }

    #[test]
    fn withholding_removes_support_and_edges_but_retains_real_id_and_order() {
        let original = claim();
        let original_id = original.claim_id.clone();
        let original_order = original.order;
        let reconstruction =
            reconstruct_kill_chain([original], [EvidenceId::new("evidence:execution")])
                .expect("withholding should produce an explicit gap");

        let retained = &reconstruction.claims[0];
        assert_eq!(retained.claim_id, original_id);
        assert_eq!(retained.order, original_order);
        assert!(retained.evidence_ids.is_empty());
        assert!(retained.narration_evidence_ids.is_empty());
        assert!(retained.edge_ids.is_empty());
        assert_eq!(
            reconstruction.missing_evidence[0].expected_scope,
            format!("kill_chain.claim:{original_id}.supporting_evidence:evidence:execution")
        );
        reconstruction
            .validate()
            .expect("real claim ID and projection must remain valid");

        let mut tampered = reconstruction;
        tampered.claims[0].claim_id = KillChainClaimId::new("kill-chain:unknown");
        assert!(
            tampered.validate().is_err(),
            "unknown claim ID mutation must fail"
        );
    }

    #[test]
    fn unknown_withheld_evidence_is_rejected() {
        let result = reconstruct_kill_chain([claim()], [EvidenceId::new("evidence:not-in-claims")]);
        assert!(matches!(
            result,
            Err(GraphAdmissionError::InvalidField { field, .. })
                if field == "kill_chain.withheld_evidence_ids"
        ));
    }

    #[test]
    fn duplicate_withheld_evidence_is_rejected() {
        let evidence = EvidenceId::new("evidence:execution");
        let result = reconstruct_kill_chain([claim()], [evidence.clone(), evidence]);
        assert!(matches!(
            result,
            Err(GraphAdmissionError::InvalidField { field, .. })
                if field == "kill_chain.withheld_evidence_ids"
        ));
    }

    #[test]
    fn duplicate_edge_ids_are_rejected_before_support_map_construction() {
        let evidence = EvidenceId::new("evidence:duplicate-edge");
        let edge = signed_edge(evidence.clone());
        let claim = CoreClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:from"), GraphNodeId::new("node:to")],
            [edge.edge_id.clone()],
            [evidence.clone()],
            [],
            "duplicate edge control",
            [evidence.clone()],
        )
        .expect("claim must be valid");
        let expected_edge_id = edge.edge_id.to_string();
        let result = reconstruct_kill_chain_with_edges(
            [claim],
            [edge.clone(), edge],
            std::iter::empty::<EvidenceId>(),
        );
        assert!(matches!(
            result,
            Err(GraphAdmissionError::IdCollision { id }) if id == expected_edge_id
        ));
    }

    #[test]
    fn claim_wide_legacy_support_is_explicitly_incomplete() {
        let reconstruction = KillChainReconstruction::new([claim()], [])
            .expect("legacy projection remains constructible for reporting");
        assert!(!reconstruction.has_exact_edge_support());
        assert!(!reconstruction.support_complete());
    }

    #[test]
    fn multi_claim_order_is_retained_while_only_supported_claim_is_projected() {
        let first = claim();
        let second = CoreClaim::new(
            KillChainStage::CredentialAccess,
            [GraphNodeId::new("node:process")],
            [EdgeId::new("edge:persistence")],
            [EvidenceId::new("evidence:persistence")],
            [first.claim_id.clone()],
            "persistence is supported",
            [EvidenceId::new("evidence:persistence")],
        )
        .expect("second claim must be valid");
        let reconstruction = reconstruct_kill_chain(
            [first.clone(), second.clone()],
            [EvidenceId::new("evidence:execution")],
        )
        .expect("withholding should retain the chain order");
        assert_eq!(reconstruction.claims[0].claim_id, first.claim_id);
        assert_eq!(reconstruction.claims[1].claim_id, second.claim_id);
        assert!(reconstruction.claims[0].evidence_ids.is_empty());
        assert_eq!(reconstruction.claims[1].evidence_ids, second.evidence_ids);
        reconstruction.validate().expect("order must remain valid");
    }

    #[test]
    fn exact_edge_support_preserves_independent_edge_after_partial_withholding() {
        let evidence_a = EvidenceId::new("evidence:edge-a");
        let evidence_b = EvidenceId::new("evidence:edge-b");
        let edge_multi = EdgeId::new("edge:multi");
        let edge_independent = EdgeId::new("edge:independent");
        let edge_withheld = EdgeId::new("edge:withheld");
        let claim = CoreClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:process")],
            [
                edge_multi.clone(),
                edge_independent.clone(),
                edge_withheld.clone(),
            ],
            [evidence_a.clone(), evidence_b.clone()],
            [],
            "execution has independently supported links",
            [evidence_a.clone(), evidence_b.clone()],
        )
        .expect("multi-edge claim must be valid");
        let edge_support = BTreeMap::from([
            (
                edge_multi.clone(),
                BTreeSet::from([evidence_a.clone(), evidence_b.clone()]),
            ),
            (
                edge_independent.clone(),
                BTreeSet::from([evidence_b.clone()]),
            ),
            (edge_withheld, BTreeSet::from([evidence_a.clone()])),
        ]);
        let reconstruction = reconstruct_kill_chain_with_edge_support(
            [claim.clone()],
            edge_support,
            [evidence_a.clone()],
        )
        .expect("partial withholding must retain independently supported edge");
        let retained = &reconstruction.claims[0];
        assert_eq!(retained.claim_id, claim.claim_id);
        assert_eq!(
            retained.edge_ids,
            BTreeSet::from([edge_multi.clone(), edge_independent.clone()])
        );
        assert_eq!(
            retained.edge_evidence_ids,
            BTreeMap::from([
                (edge_multi, BTreeSet::from([evidence_b.clone()])),
                (edge_independent, BTreeSet::from([evidence_b.clone()])),
            ])
        );
        assert_eq!(retained.evidence_ids, BTreeSet::from([evidence_b]));
        assert!(!retained.narration_evidence_ids.is_empty());
        reconstruction
            .validate()
            .expect("exact edge support projection must validate");
    }
}
