//! Deterministic causal inference over normalized evidence.
//!
//! Rules consume typed signal semantics and normalized entity positions. They
//! never consume expected edge IDs: callers can therefore compare the
//! resulting endpoint/relation triples with an independent oracle.

use swarm_core::hypothesis_graph::{
    CausalRelation, GraphAdmissionError, GraphNodeId, TypedEvidencePayload,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferredCausalRelation {
    pub from: GraphNodeId,
    pub to: GraphNodeId,
    pub relation: CausalRelation,
}

fn inferred(
    entity_ids: &[GraphNodeId],
    from: usize,
    to: usize,
    relation: CausalRelation,
    signal_kind: &str,
) -> Result<InferredCausalRelation, GraphAdmissionError> {
    let from = entity_ids
        .get(from)
        .ok_or_else(|| GraphAdmissionError::InvalidField {
            field: "payload.entity_ids".to_string(),
            reason: format!("signal `{signal_kind}` is missing its causal source entity"),
        })?;
    let to = entity_ids
        .get(to)
        .ok_or_else(|| GraphAdmissionError::InvalidField {
            field: "payload.entity_ids".to_string(),
            reason: format!("signal `{signal_kind}` is missing its causal target entity"),
        })?;
    if from == to {
        return Err(GraphAdmissionError::InvalidField {
            field: "payload.entity_ids".to_string(),
            reason: format!("signal `{signal_kind}` has identical causal endpoints"),
        });
    }
    Ok(InferredCausalRelation {
        from: from.clone(),
        to: to.clone(),
        relation,
    })
}

/// Infer bounded causal candidates from one already-normalized evidence
/// payload. Generic signals are keyed by their semantic signal kind; their
/// `relation_ids` remain output references and are deliberately ignored.
pub fn infer_causal_relations(
    payload: &TypedEvidencePayload,
) -> Result<Vec<InferredCausalRelation>, GraphAdmissionError> {
    let (signal_kind, entity_ids) = match payload {
        TypedEvidencePayload::Signal {
            signal_kind,
            entity_ids,
            ..
        }
        | TypedEvidencePayload::Process {
            signal_kind,
            entity_ids,
            ..
        }
        | TypedEvidencePayload::Identity {
            signal_kind,
            entity_ids,
            ..
        }
        | TypedEvidencePayload::KubernetesAudit {
            signal_kind,
            entity_ids,
            ..
        }
        | TypedEvidencePayload::Cloudtrail {
            signal_kind,
            entity_ids,
            ..
        }
        | TypedEvidencePayload::Network {
            signal_kind,
            entity_ids,
            ..
        }
        | TypedEvidencePayload::ThreatIntelligence {
            signal_kind,
            entity_ids,
            ..
        } => (signal_kind.as_str(), entity_ids.as_slice()),
    };

    let candidates = match payload {
        TypedEvidencePayload::Signal { .. } => match signal_kind {
            "unsigned_parent_child_execution" | "interpreter_spawn" => vec![inferred(
                entity_ids,
                0,
                1,
                CausalRelation::Uses,
                signal_kind,
            )?],
            "anomalous_role_assumption"
            | "role_used_from_new_source"
            | "anomalous_service_authentication"
            | "secret_read_after_role_assumption" => vec![inferred(
                entity_ids,
                0,
                1,
                CausalRelation::Assumes,
                signal_kind,
            )?],
            "privileged_workload_creation" => vec![inferred(
                entity_ids,
                0,
                1,
                CausalRelation::Creates,
                signal_kind,
            )?],
            "rare_egress_destination" | "periodic_encrypted_egress" => vec![
                inferred(entity_ids, 0, 1, CausalRelation::Spawns, signal_kind)?,
                inferred(entity_ids, 1, 2, CausalRelation::Contacts, signal_kind)?,
            ],
            "active_campaign_indicator_match" => vec![inferred(
                entity_ids,
                0,
                1,
                CausalRelation::MatchesIndicator,
                signal_kind,
            )?],
            _ => Vec::new(),
        },
        TypedEvidencePayload::Process {
            parent_process_digest,
            ..
        } if signal_kind == "process_memory_access" && parent_process_digest.is_some() => {
            vec![inferred(
                entity_ids,
                0,
                1,
                CausalRelation::DependsOn,
                signal_kind,
            )?]
        }
        TypedEvidencePayload::Process { .. } if entity_ids.len() >= 3 => vec![inferred(
            entity_ids,
            2,
            0,
            CausalRelation::Uses,
            signal_kind,
        )?],
        TypedEvidencePayload::Identity {
            credential_digest: Some(_),
            ..
        }
        | TypedEvidencePayload::Cloudtrail { .. } => vec![inferred(
            entity_ids,
            0,
            1,
            CausalRelation::Assumes,
            signal_kind,
        )?],
        TypedEvidencePayload::KubernetesAudit { .. } => vec![inferred(
            entity_ids,
            0,
            1,
            CausalRelation::Creates,
            signal_kind,
        )?],
        TypedEvidencePayload::Network { .. } => vec![inferred(
            entity_ids,
            0,
            1,
            CausalRelation::Contacts,
            signal_kind,
        )?],
        TypedEvidencePayload::ThreatIntelligence { .. } => vec![inferred(
            entity_ids,
            0,
            1,
            CausalRelation::MatchesIndicator,
            signal_kind,
        )?],
        TypedEvidencePayload::Process { .. } | TypedEvidencePayload::Identity { .. } => Vec::new(),
    };
    Ok(candidates)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::hypothesis_graph::{EdgeId, HypothesisId};

    #[test]
    fn signal_inference_ignores_caller_supplied_relation_ids() {
        let payload = TypedEvidencePayload::Signal {
            signal_kind: "interpreter_spawn".to_string(),
            entity_ids: vec![GraphNodeId::new("credential"), GraphNodeId::new("process")],
            relation_ids: vec![EdgeId::new("edge:wrong")],
            supports: vec![HypothesisId::new("hypothesis:attack")],
            refutes: Vec::new(),
            content_digest: "0".repeat(64),
        };
        let inferred = infer_causal_relations(&payload).expect("inference should succeed");
        assert_eq!(inferred.len(), 1);
        assert_eq!(inferred[0].from, GraphNodeId::new("credential"));
        assert_eq!(inferred[0].to, GraphNodeId::new("process"));
        assert_eq!(inferred[0].relation, CausalRelation::Uses);
    }
}
