//! Deterministic causal inference over normalized evidence.
//!
//! Rules consume typed signal semantics and normalized entity positions. They
//! never consume expected edge IDs: callers can therefore compare the
//! resulting endpoint/relation triples with an independent oracle.

use swarm_core::hypothesis_graph::{
    CausalRelation, GraphAdmissionError, GraphNodeId, ProcessNode, TypedEvidencePayload,
    canonical_digest,
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
    let expected_parent_node_id = match payload {
        TypedEvidencePayload::Process {
            signal_kind,
            parent_process_digest: Some(parent_process_digest),
            ..
        } if signal_kind == "process_start" => {
            let executable_digest =
                canonical_digest(&("parent_executable", parent_process_digest))?;
            Some(ProcessNode::new(parent_process_digest, executable_digest)?.node_id)
        }
        _ => None,
    };
    let expected_process_correlation_node_id = match payload {
        TypedEvidencePayload::Process {
            signal_kind,
            process_digest,
            parent_process_digest: Some(_),
            ..
        } if signal_kind == "process_start" => {
            Some(ProcessNode::new(process_digest, process_digest)?.node_id)
        }
        _ => None,
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
        TypedEvidencePayload::Process {
            parent_process_digest: Some(_),
            ..
        } if signal_kind == "process_start"
            && entity_ids.get(2) == expected_parent_node_id.as_ref() =>
        {
            let mut relations = vec![inferred(
                entity_ids,
                2,
                0,
                CausalRelation::Spawns,
                signal_kind,
            )?];
            if entity_ids.get(3) == expected_process_correlation_node_id.as_ref() {
                // The parent-bound process instance preserves exact lineage;
                // the correlation node is the stable source/host/process
                // identity used by less expressive network telemetry. This
                // explicit bridge keeps spawn-to-contact paths connected.
                relations.push(inferred(
                    entity_ids,
                    0,
                    3,
                    CausalRelation::DependsOn,
                    signal_kind,
                )?);
                if entity_ids.len() >= 5 {
                    relations.push(inferred(
                        entity_ids,
                        4,
                        0,
                        CausalRelation::Uses,
                        signal_kind,
                    )?);
                }
            }
            relations
        }
        TypedEvidencePayload::Process { .. }
            if signal_kind == "process_start" && entity_ids.len() >= 3 =>
        {
            vec![inferred(
                entity_ids,
                2,
                0,
                CausalRelation::Uses,
                signal_kind,
            )?]
        }
        TypedEvidencePayload::Identity {
            credential_digest: Some(_),
            success: Some(true),
            ..
        } => vec![inferred(
            entity_ids,
            0,
            1,
            CausalRelation::Assumes,
            signal_kind,
        )?],
        TypedEvidencePayload::Cloudtrail {
            event_name,
            error_code: None,
            ..
        } if event_name.eq_ignore_ascii_case("AssumeRole") => vec![inferred(
            entity_ids,
            0,
            1,
            CausalRelation::Assumes,
            signal_kind,
        )?],
        TypedEvidencePayload::KubernetesAudit { verb, .. }
            if verb.eq_ignore_ascii_case("create") =>
        {
            vec![inferred(
                entity_ids,
                0,
                1,
                CausalRelation::Creates,
                signal_kind,
            )?]
        }
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
        TypedEvidencePayload::Process { .. }
        | TypedEvidencePayload::Identity { .. }
        | TypedEvidencePayload::KubernetesAudit { .. }
        | TypedEvidencePayload::Cloudtrail { .. } => Vec::new(),
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

    #[test]
    fn kubernetes_creation_inference_rejects_non_creating_verbs() {
        let payload = |verb: &str| TypedEvidencePayload::KubernetesAudit {
            signal_kind: "kubernetes_audit".to_string(),
            audit_id: format!("audit:{verb}"),
            verb: verb.to_string(),
            resource_digest: "resource".to_string(),
            entity_ids: vec![GraphNodeId::new("actor"), GraphNodeId::new("resource")],
            content_digest: "0".repeat(64),
        };

        let create = infer_causal_relations(&payload("create")).expect("create should infer");
        assert_eq!(create.len(), 1);
        assert_eq!(create[0].relation, CausalRelation::Creates);
        for verb in ["get", "list", "watch", "update", "patch", "delete"] {
            assert!(
                infer_causal_relations(&payload(verb))
                    .expect("non-creating verb should be valid")
                    .is_empty(),
                "verb `{verb}` must not infer a creates edge"
            );
        }
    }

    #[test]
    fn authentication_inference_requires_a_successful_outcome() {
        let payload = |success| TypedEvidencePayload::Identity {
            signal_kind: "authentication_event".to_string(),
            principal_digest: "principal".to_string(),
            credential_digest: Some("credential".to_string()),
            success,
            entity_ids: vec![GraphNodeId::new("actor"), GraphNodeId::new("credential")],
            content_digest: "0".repeat(64),
        };

        let success = infer_causal_relations(&payload(Some(true))).expect("success should infer");
        assert_eq!(success.len(), 1);
        assert_eq!(success[0].relation, CausalRelation::Assumes);
        for outcome in [Some(false), None] {
            assert!(
                infer_causal_relations(&payload(outcome))
                    .expect("non-success outcome should remain valid evidence")
                    .is_empty(),
                "failed or legacy-unknown authentication must not assert credential assumption"
            );
        }
    }

    #[test]
    fn process_start_inference_preserves_parent_lineage_with_or_without_actor() {
        let parent_digest = "parent";
        let parent_executable_digest = canonical_digest(&("parent_executable", parent_digest))
            .expect("fixture parent executable digest should be canonical");
        let parent_node_id = ProcessNode::new(parent_digest, parent_executable_digest)
            .expect("fixture parent process should be valid")
            .node_id;
        let payload = |entity_ids| TypedEvidencePayload::Process {
            signal_kind: "process_start".to_string(),
            process_digest: "child".to_string(),
            parent_process_digest: Some(parent_digest.to_string()),
            entity_ids,
            content_digest: "0".repeat(64),
        };

        let correlation_node_id = ProcessNode::new("child", "child")
            .expect("fixture correlation process should be valid")
            .node_id;
        let without_actor = infer_causal_relations(&payload(vec![
            GraphNodeId::new("child"),
            GraphNodeId::new("event"),
            parent_node_id.clone(),
            correlation_node_id.clone(),
        ]))
        .expect("parented process should infer");
        assert_eq!(without_actor.len(), 2);
        assert_eq!(without_actor[0].from, parent_node_id);
        assert_eq!(without_actor[0].to, GraphNodeId::new("child"));
        assert_eq!(without_actor[0].relation, CausalRelation::Spawns);
        assert_eq!(without_actor[1].from, GraphNodeId::new("child"));
        assert_eq!(without_actor[1].to, correlation_node_id);
        assert_eq!(without_actor[1].relation, CausalRelation::DependsOn);

        let with_actor = infer_causal_relations(&payload(vec![
            GraphNodeId::new("child"),
            GraphNodeId::new("event"),
            parent_node_id,
            ProcessNode::new("child", "child")
                .expect("fixture correlation process should be valid")
                .node_id,
            GraphNodeId::new("actor"),
        ]))
        .expect("parented process with actor should infer");
        assert_eq!(with_actor.len(), 3);
        assert_eq!(with_actor[0].relation, CausalRelation::Spawns);
        assert_eq!(with_actor[1].relation, CausalRelation::DependsOn);
        assert_eq!(with_actor[2].from, GraphNodeId::new("actor"));
        assert_eq!(with_actor[2].to, GraphNodeId::new("child"));
        assert_eq!(with_actor[2].relation, CausalRelation::Uses);

        let legacy_with_actor = infer_causal_relations(&payload(vec![
            GraphNodeId::new("legacy-child"),
            GraphNodeId::new("legacy-event"),
            GraphNodeId::new("legacy-actor"),
        ]))
        .expect("legacy parented process should retain its actor edge");
        assert_eq!(legacy_with_actor.len(), 1);
        assert_eq!(legacy_with_actor[0].from, GraphNodeId::new("legacy-actor"));
        assert_eq!(legacy_with_actor[0].to, GraphNodeId::new("legacy-child"));
        assert_eq!(legacy_with_actor[0].relation, CausalRelation::Uses);
    }

    #[test]
    fn cloudtrail_inference_requires_a_successful_assume_role_event() {
        let payload =
            |event_name: &str, error_code: Option<&str>| TypedEvidencePayload::Cloudtrail {
                signal_kind: "cloudtrail".to_string(),
                event_id: format!("event:{event_name}"),
                event_name: event_name.to_string(),
                event_source: "sts.amazonaws.com".to_string(),
                principal_digest: "principal".to_string(),
                account_digest: "account".to_string(),
                source_ip_digest: None,
                request_digest: "1".repeat(64),
                response_digest: "2".repeat(64),
                mfa_authenticated: None,
                region: Some("us-east-1".to_string()),
                error_code: error_code.map(str::to_string),
                error_message: None,
                entity_ids: vec![GraphNodeId::new("actor"), GraphNodeId::new("account")],
                content_digest: "0".repeat(64),
            };

        let assumed = infer_causal_relations(&payload("AssumeRole", None))
            .expect("successful AssumeRole should infer");
        assert_eq!(assumed.len(), 1);
        assert_eq!(assumed[0].relation, CausalRelation::Assumes);
        for candidate in [
            payload("CreateAccessKey", None),
            payload("ConsoleLogin", None),
            payload("RunInstances", None),
            payload("GetSecretValue", None),
            payload("AssumeRole", Some("AccessDenied")),
        ] {
            assert!(
                infer_causal_relations(&candidate)
                    .expect("non-assumption evidence should remain valid")
                    .is_empty(),
                "only a successful AssumeRole event may assert an Assumes edge"
            );
        }
    }
}
