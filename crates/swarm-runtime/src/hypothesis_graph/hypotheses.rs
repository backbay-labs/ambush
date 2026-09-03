//! Deterministic seed and competing-hypothesis contracts.
//!
//! Normalization supplies facts, not epistemic labels.  This module keeps the
//! distinction explicit: a plain evidence seed is unresolved, while support,
//! refutation, and contradiction must arrive as an independently admitted
//! assessment.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use swarm_core::hypothesis_graph::{
    ConfidenceDistribution, EdgeId, EvidenceId, GraphAdmissionError, GraphId, GraphLogicalTime,
    GraphResourceLimits, Hypothesis, HypothesisId, TaskKind, TaskTarget, UncertaintyReason,
};
use swarm_crypto::{canonical_json_bytes, sha256_hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisDisposition {
    Supports,
    Refutes,
    Unresolved,
    Contradicts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisSeedAssessment {
    pub hypothesis_id: HypothesisId,
    pub evidence_ids: Vec<EvidenceId>,
    pub disposition: HypothesisDisposition,
    pub provenance: EvidenceId,
}

impl HypothesisSeedAssessment {
    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        if self.hypothesis_id.as_str().trim().is_empty()
            || self.provenance.as_str().trim().is_empty()
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "hypothesis_seed.assessment".to_string(),
                reason: "hypothesis and provenance IDs must be non-empty".to_string(),
            });
        }
        if self.evidence_ids.len() > 256 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "hypothesis_seed.evidence_ids".to_string(),
                limit: 256,
            });
        }
        let ids = self.evidence_ids.iter().cloned().collect::<BTreeSet<_>>();
        if !ids.contains(&self.provenance) {
            return Err(GraphAdmissionError::InvalidField {
                field: "hypothesis_seed.provenance".to_string(),
                reason: "provenance must be one of the assessment evidence IDs".to_string(),
            });
        }
        if matches!(
            self.disposition,
            HypothesisDisposition::Supports
                | HypothesisDisposition::Refutes
                | HypothesisDisposition::Contradicts
        ) && ids.is_empty()
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "hypothesis_seed.evidence_ids".to_string(),
                reason: "non-neutral assessments require explicit evidence".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisSeedInput {
    pub graph_id: GraphId,
    pub candidate_hypothesis_ids: Vec<HypothesisId>,
    pub assessments: Vec<HypothesisSeedAssessment>,
    pub logical_time: GraphLogicalTime,
}

impl HypothesisSeedInput {
    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        Self::new(
            self.graph_id.clone(),
            self.candidate_hypothesis_ids.clone(),
            self.assessments.clone(),
            self.logical_time,
        )
        .map(|_| ())
    }

    pub fn new(
        graph_id: GraphId,
        mut candidate_hypothesis_ids: Vec<HypothesisId>,
        mut assessments: Vec<HypothesisSeedAssessment>,
        logical_time: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        if graph_id.as_str().trim().is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "hypothesis_seed.graph_id".to_string(),
                reason: "graph ID must be non-empty".to_string(),
            });
        }
        logical_time.validate()?;
        candidate_hypothesis_ids.sort();
        let candidates = candidate_hypothesis_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if candidates.len() < 2 {
            return Err(GraphAdmissionError::InvalidField {
                field: "hypothesis_seed.candidate_hypothesis_ids".to_string(),
                reason: "at least two competing hypothesis IDs are required".to_string(),
            });
        }
        if candidates.len() != candidate_hypothesis_ids.len() {
            return Err(GraphAdmissionError::IdCollision {
                id: "hypothesis_seed.candidate_hypothesis_ids".to_string(),
            });
        }
        for id in &candidate_hypothesis_ids {
            if id.as_str().trim().is_empty() || id.as_str().len() > 256 {
                return Err(GraphAdmissionError::InvalidIdentifier {
                    field: "hypothesis_seed.candidate_hypothesis_id".to_string(),
                });
            }
        }
        if assessments.len() > 512 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "hypothesis_seed.assessments".to_string(),
                limit: 512,
            });
        }
        for assessment in &mut assessments {
            assessment.evidence_ids.sort();
            assessment.evidence_ids.dedup();
            assessment.validate()?;
            if !candidates.contains(&assessment.hypothesis_id) {
                return Err(GraphAdmissionError::InvalidField {
                    field: "hypothesis_seed.assessment.hypothesis_id".to_string(),
                    reason: "assessment targets a non-candidate hypothesis".to_string(),
                });
            }
        }
        assessments.sort_by(|left, right| {
            left.hypothesis_id
                .cmp(&right.hypothesis_id)
                .then_with(|| left.disposition.cmp(&right.disposition))
                .then_with(|| left.provenance.cmp(&right.provenance))
                .then_with(|| left.evidence_ids.cmp(&right.evidence_ids))
        });
        assessments.dedup();
        let assessed_candidates = assessments
            .iter()
            .map(|assessment| assessment.hypothesis_id.clone())
            .collect::<BTreeSet<_>>();
        if assessed_candidates != candidates {
            return Err(GraphAdmissionError::InvalidField {
                field: "hypothesis_seed.assessments".to_string(),
                reason: "every candidate hypothesis requires at least one assessment".to_string(),
            });
        }
        Ok(Self {
            graph_id,
            candidate_hypothesis_ids,
            assessments,
            logical_time,
        })
    }

    /// Construct a neutral seed from normalized evidence.  No payload field,
    /// source family, or event order is interpreted as support or refutation.
    pub fn from_normalized_evidence(
        graph_id: GraphId,
        candidate_hypothesis_ids: Vec<HypothesisId>,
        evidence_ids: Vec<EvidenceId>,
        logical_time: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        let assessments = candidate_hypothesis_ids
            .iter()
            .map(|hypothesis_id| {
                let provenance = evidence_ids.first().cloned().ok_or_else(|| {
                    GraphAdmissionError::InvalidField {
                        field: "hypothesis_seed.evidence_ids".to_string(),
                        reason: "an unresolved seed still needs acquisition scope".to_string(),
                    }
                })?;
                Ok(HypothesisSeedAssessment {
                    hypothesis_id: hypothesis_id.clone(),
                    evidence_ids: evidence_ids.clone(),
                    disposition: HypothesisDisposition::Unresolved,
                    provenance,
                })
            })
            .collect::<Result<Vec<_>, GraphAdmissionError>>()?;
        Self::new(
            graph_id,
            candidate_hypothesis_ids,
            assessments,
            logical_time,
        )
    }
}

/// Create the durable alternatives for a seed.  The returned map is a
/// projection input; committing it remains the graph-store's responsibility.
pub fn competing_hypotheses(
    seed: &HypothesisSeedInput,
    limits: &GraphResourceLimits,
) -> Result<BTreeMap<HypothesisId, Hypothesis>, GraphAdmissionError> {
    seed.validate_against_limits(limits)?;
    let mut hypotheses = BTreeMap::new();
    for id in &seed.candidate_hypothesis_ids {
        let mut uncertainty = BTreeSet::new();
        if seed.assessments.iter().any(|assessment| {
            assessment.hypothesis_id == *id
                && matches!(
                    assessment.disposition,
                    HypothesisDisposition::Unresolved | HypothesisDisposition::Contradicts
                )
        }) {
            uncertainty.insert(UncertaintyReason::InsufficientEvidence);
        }
        if seed.assessments.iter().any(|assessment| {
            assessment.hypothesis_id == *id
                && assessment.disposition == HypothesisDisposition::Contradicts
        }) {
            uncertainty.insert(UncertaintyReason::ConflictingEvidence);
        }
        let hypothesis = Hypothesis::new(
            id.clone(),
            ConfidenceDistribution::uniform_two(),
            uncertainty,
            [],
        )?;
        hypotheses.insert(id.clone(), hypothesis);
    }
    Ok(hypotheses)
}

impl HypothesisSeedInput {
    pub fn validate_against_limits(
        &self,
        limits: &GraphResourceLimits,
    ) -> Result<(), GraphAdmissionError> {
        limits.validate()?;
        self.validate()?;
        if self.candidate_hypothesis_ids.len() > limits.max_hypotheses {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "hypothesis_seed.candidate_hypothesis_ids".to_string(),
                limit: limits.max_hypotheses,
            });
        }
        Ok(())
    }
}

/// Stable task targets generated from unresolved seed assessments.
pub fn unresolved_task_targets(
    seed: &HypothesisSeedInput,
) -> Result<Vec<(TaskKind, TaskTarget)>, GraphAdmissionError> {
    seed.validate()?;
    let mut targets = BTreeSet::new();
    for assessment in &seed.assessments {
        match assessment.disposition {
            HypothesisDisposition::Unresolved => {
                for evidence_id in &assessment.evidence_ids {
                    targets.insert((
                        TaskKind::AcquireEvidence,
                        TaskTarget::Evidence {
                            evidence_id: evidence_id.clone(),
                        },
                    ));
                }
            }
            HypothesisDisposition::Contradicts => {
                targets.insert((
                    TaskKind::FalsifyHypothesis,
                    TaskTarget::Hypothesis {
                        hypothesis_id: assessment.hypothesis_id.clone(),
                    },
                ));
            }
            HypothesisDisposition::Supports | HypothesisDisposition::Refutes => {}
        }
    }
    Ok(targets.into_iter().collect())
}

/// Deterministic target expansion used by the durable coordinator.  The
/// legacy [`unresolved_task_targets`] helper remains the narrow evidence-only
/// projection used by callers that do not own a graph; this operation also
/// emits challenge work for every already-admitted edge and a falsification
/// task for each unresolved/contradictory alternative.  No edge ID is ever
/// synthesized from telemetry or a hypothesis label.
pub(crate) fn coordination_task_targets(
    seed: &HypothesisSeedInput,
    edge_ids: &BTreeSet<EdgeId>,
) -> Result<Vec<(TaskKind, TaskTarget)>, GraphAdmissionError> {
    seed.validate()?;
    let mut targets = BTreeSet::new();
    for assessment in &seed.assessments {
        // Every durable alternative carries an explicit falsification task,
        // including an alternative that arrives with an initial support or
        // refutation decision. Besides keeping all reasoning falsifiable,
        // this is the marker-1 store's structural proof that a newly admitted
        // hypothesis came through coordinated seed expansion rather than a
        // caller-crafted direct CAS.
        targets.insert((
            TaskKind::FalsifyHypothesis,
            TaskTarget::Hypothesis {
                hypothesis_id: assessment.hypothesis_id.clone(),
            },
        ));
        if matches!(
            assessment.disposition,
            HypothesisDisposition::Unresolved | HypothesisDisposition::Contradicts
        ) {
            for evidence_id in &assessment.evidence_ids {
                targets.insert((
                    TaskKind::AcquireEvidence,
                    TaskTarget::Evidence {
                        evidence_id: evidence_id.clone(),
                    },
                ));
            }
            for edge_id in edge_ids {
                targets.insert((
                    TaskKind::ChallengeEdge,
                    TaskTarget::Edge {
                        edge_id: edge_id.clone(),
                    },
                ));
            }
        }
    }
    Ok(targets.into_iter().collect())
}

/// Return the canonical seed digest for one task descriptor.  The digest is
/// derived from the full neutral seed plus the typed operation target and
/// kind; it cannot be replaced by a claimant's retry idempotency key.
pub(crate) fn seed_task_digest(
    seed: &HypothesisSeedInput,
    kind: TaskKind,
    target: &TaskTarget,
) -> Result<String, GraphAdmissionError> {
    // Seed vectors are input order, not logical identity. Canonicalize every
    // set-like collection before hashing so retries that arrive with the same
    // alternatives/evidence in a different order derive the same descriptor.
    let mut candidate_hypothesis_ids = seed.candidate_hypothesis_ids.clone();
    candidate_hypothesis_ids.sort();
    let mut assessments = seed.assessments.clone();
    for assessment in &mut assessments {
        assessment.evidence_ids.sort();
        assessment.evidence_ids.dedup();
    }
    assessments.sort_by(|left, right| {
        left.hypothesis_id
            .cmp(&right.hypothesis_id)
            .then_with(|| left.disposition.cmp(&right.disposition))
            .then_with(|| left.provenance.cmp(&right.provenance))
            .then_with(|| left.evidence_ids.cmp(&right.evidence_ids))
    });
    assessments.dedup();
    let bytes = canonical_json_bytes(&(
        &seed.graph_id,
        &candidate_hypothesis_ids,
        &assessments,
        kind,
        target,
    ))
    .map_err(|error| GraphAdmissionError::Canonicalization {
        reason: error.to_string(),
    })?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn seed() -> HypothesisSeedInput {
        HypothesisSeedInput::from_normalized_evidence(
            GraphId::new("graph:hypothesis-unit"),
            vec![
                HypothesisId::new("hypothesis:first"),
                HypothesisId::new("hypothesis:second"),
            ],
            vec![EvidenceId::new("evidence:seed")],
            GraphLogicalTime::new(10),
        )
        .expect("normalized evidence must produce a neutral seed")
    }

    #[test]
    fn neutral_seed_preserves_competing_live_alternatives() {
        let hypotheses = competing_hypotheses(&seed(), &GraphResourceLimits::default())
            .expect("bounded seed must admit competing alternatives");
        assert_eq!(hypotheses.len(), 2);
        assert!(hypotheses.values().all(|hypothesis| {
            hypothesis.status == swarm_core::hypothesis_graph::HypothesisStatus::Live
                && hypothesis
                    .uncertainty
                    .contains(&UncertaintyReason::InsufficientEvidence)
        }));
    }

    #[test]
    fn unresolved_seed_never_infers_support_or_refutation() {
        let seed = seed();
        assert!(
            seed.assessments
                .iter()
                .all(|assessment| { assessment.disposition == HypothesisDisposition::Unresolved })
        );
        let targets = unresolved_task_targets(&seed).expect("neutral task targets must validate");
        assert!(
            targets
                .iter()
                .all(|(kind, _)| *kind == TaskKind::AcquireEvidence)
        );
    }

    #[test]
    fn logical_seed_digest_ignores_arrival_order_and_time() {
        let first = seed();
        let mut retried = first.clone();
        retried.candidate_hypothesis_ids.reverse();
        retried.assessments.reverse();
        retried.logical_time = GraphLogicalTime::new(11);
        retried.assessments[0].evidence_ids.reverse();
        retried.assessments[0]
            .evidence_ids
            .push(EvidenceId::new("evidence:seed"));
        retried.assessments.push(retried.assessments[0].clone());
        let target = TaskTarget::Evidence {
            evidence_id: EvidenceId::new("evidence:seed"),
        };
        assert_eq!(
            seed_task_digest(&first, TaskKind::AcquireEvidence, &target)
                .expect("first seed digest must be canonical"),
            seed_task_digest(&retried, TaskKind::AcquireEvidence, &target)
                .expect("retry seed digest must be canonical")
        );
    }

    #[test]
    fn seed_constructor_canonicalizes_duplicate_assessments_and_evidence() {
        let first = HypothesisId::new("hypothesis:first");
        let second = HypothesisId::new("hypothesis:second");
        let evidence = EvidenceId::new("evidence:seed");
        let assessment = HypothesisSeedAssessment {
            hypothesis_id: first.clone(),
            evidence_ids: vec![evidence.clone(), evidence.clone()],
            disposition: HypothesisDisposition::Unresolved,
            provenance: evidence.clone(),
        };
        let second_assessment = HypothesisSeedAssessment {
            hypothesis_id: second.clone(),
            evidence_ids: vec![evidence.clone()],
            disposition: HypothesisDisposition::Unresolved,
            provenance: evidence.clone(),
        };
        let seed = HypothesisSeedInput::new(
            GraphId::new("graph:hypothesis-unit"),
            vec![second.clone(), first.clone()],
            vec![assessment.clone(), assessment, second_assessment],
            GraphLogicalTime::new(10),
        )
        .expect("set-like seed input must canonicalize");

        assert_eq!(seed.candidate_hypothesis_ids, vec![first, second]);
        assert_eq!(seed.assessments.len(), 2);
        assert_eq!(seed.assessments[0].evidence_ids, vec![evidence]);
    }

    #[test]
    fn every_candidate_requires_an_assessment() {
        let first = HypothesisId::new("hypothesis:first");
        let second = HypothesisId::new("hypothesis:second");
        let evidence = EvidenceId::new("evidence:seed");
        let result = HypothesisSeedInput::new(
            GraphId::new("graph:hypothesis-unit"),
            vec![first.clone(), second],
            vec![HypothesisSeedAssessment {
                hypothesis_id: first,
                evidence_ids: vec![evidence.clone()],
                disposition: HypothesisDisposition::Unresolved,
                provenance: evidence,
            }],
            GraphLogicalTime::new(10),
        );
        assert!(matches!(
            result,
            Err(GraphAdmissionError::InvalidField { field, reason })
                if field == "hypothesis_seed.assessments"
                    && reason.contains("every candidate")
        ));
    }

    #[test]
    fn durable_target_expansion_contains_every_open_operation_kind() {
        let seed = seed();
        let targets =
            coordination_task_targets(&seed, &BTreeSet::from([EdgeId::new("edge:admitted")]))
                .expect("neutral seed targets must validate");
        assert!(
            targets
                .iter()
                .any(|(kind, _)| *kind == TaskKind::AcquireEvidence)
        );
        assert!(
            targets
                .iter()
                .any(|(kind, _)| *kind == TaskKind::ChallengeEdge)
        );
        assert!(
            targets
                .iter()
                .any(|(kind, _)| *kind == TaskKind::FalsifyHypothesis)
        );
    }
}
