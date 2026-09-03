//! Stable runtime behavior for the collective-hypothesis graph core slice.
//!
//! This target is intentionally separate from the sealed oracle target.  It
//! exercises normalization, witness admission, idempotency, and explicit
//! source conflicts without changing the oracle's truth fixtures.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use swarm_core::config::{
    BundleStoreConfig, HypothesisGraphConfig, MIN_HYPOTHESIS_GRAPH_EVIDENCE_BYTES,
};
use swarm_core::hypothesis_graph::{
    ActorNode, CausalEdge, CausalRelation, ConfidenceDistribution, DecisionKind, DecisionRecord,
    EdgeState, EventNode, EvidenceClock, EvidenceEnvelope, EvidenceScope, EvidenceSourceFamily,
    EvidenceUtility, GraphAdmissionError, GraphId, GraphLogicalTime, GraphNode, GraphNodeId,
    GraphProducerRole, GraphResourceLimits, Hypothesis, HypothesisDelta, HypothesisGraph,
    HypothesisId, KillChainClaim as CoreKillChainClaim, KillChainStage, LogicalTaskDescriptor,
    MemoryOutcome, MemoryProvenance, OrderingClaim, SchedulerBudget, SourceLineage, StrategyMemory,
    StrategyMemoryExpiryEnvelope, TaskCapabilityProof, TaskClaimRequest, TaskCompletion,
    TaskCompletionKind, TaskDecisionLink, TaskId, TaskKind, TaskTarget, TaskTerminalEnvelope,
    TypedEvidencePayload, UncertaintyReason,
};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_core::{
    AuthenticationEventData, CloudTrailEvent, DnsQueryEvent, KubernetesAuditEvent,
    NetworkConnectEvent, ProcessStartEvent, TelemetryEvent, TelemetryPayload, ThreatIntelEntry,
    ThreatIntelIndicatorType,
};
use swarm_crypto::Keypair;
use swarm_runtime::detection::metrics::{CriticalPathMetrics, encode_metrics};
use swarm_runtime::hypothesis_graph::{
    CollectiveHypothesisService, DeterministicScheduler, DurableHypothesisCoordinator,
    EvidenceAdmissionError, EvidenceAdmissionOutcome, EvidenceRegistry, FixedGraphClock,
    GraphRecordSigner, HypothesisGraphRuntime, HypothesisTaskLedger, KeypairGraphRecordSigner,
    MAX_RAW_PROJECTION_BYTES, MAX_RAW_PROJECTION_DEPTH, MAX_RAW_PROJECTION_NODES,
    MAX_SOURCE_TEXT_BYTES, SourceTimestampUnit, WitnessAdmission, normalize_source_timestamp,
    normalize_telemetry_event, normalize_telemetry_event_with_unit, normalize_threat_intel_entry,
    project_memory_priority, run_collective_benchmark,
};
use swarm_spine::hypothesis_graph_store::GraphStoreError;
use swarm_spine::{
    AuditResponseRecord, AuditTrail, FileHypothesisGraphStore, GraphStoreRevision,
    GraphStoreSnapshot, GraphStoreState, HypothesisGraphStore, MemoryHypothesisGraphStore,
    MemoryStrategyMemoryStore, PolicyRecord, ReasoningStateUpdate, ReplayBundle,
    StrategyMemoryStore,
};

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn clock() -> FixedGraphClock {
    FixedGraphClock::new(GraphLogicalTime::new(1_700_000_010_000))
}

fn json_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn registry_state_bytes(registry: &EvidenceRegistry) -> Vec<u8> {
    json_bytes(&(
        registry.evidence(),
        registry.conflicts(),
        registry.witness_admission().identities(),
        registry.limits(),
    ))
}

fn signer_edge(signer: &Keypair) -> CausalEdge {
    CausalEdge::new(
        &GraphNodeId::new("node:process"),
        &GraphNodeId::new("node:asset"),
        CausalRelation::Contacts,
        8_000,
        [],
        GraphProducerRole::Hunter,
        AgentId::from_public_key_hex(&signer.public_key().to_hex()),
        GraphLogicalTime::new(1_700_000_000_000),
        EdgeState::Unresolved,
    )
    .unwrap()
}

fn process_event(event_id: &str, command_line: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "tetragon".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("legacy-host-field-must-not-be-causal".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: "systemd".to_string(),
            process_name: "curl".to_string(),
            command_line: command_line.to_string(),
            user: Some("alice".to_string()),
            executable_path: Some("/usr/bin/curl".to_string()),
            signer: Some("vendor".to_string()),
            signature_valid: Some(true),
        }),
    }
}

fn identity_event(event_id: &str, success: bool) -> TelemetryEvent {
    TelemetryEvent {
        source: "authd".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host-do-not-use".to_string()),
        payload: TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
            auth_type: "ssh".to_string(),
            source_host: Some("workstation".to_string()),
            target_host: Some("server".to_string()),
            target_service: Some("sshd".to_string()),
            process_name: Some("sshd".to_string()),
            success,
            user: Some("alice".to_string()),
        }),
    }
}

fn kubernetes_event(event_id: &str, verb: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "kube-audit".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("aws-account-must-not-be-host".to_string()),
        payload: TelemetryPayload::KubernetesAudit(KubernetesAuditEvent {
            verb: verb.to_string(),
            stage: Some("ResponseComplete".to_string()),
            username: Some("alice".to_string()),
            user_groups: vec!["system:authenticated".to_string()],
            source_ips: vec!["198.51.100.10".to_string()],
            user_agent: Some("kubectl".to_string()),
            namespace: Some("prod".to_string()),
            resource: "deployments".to_string(),
            subresource: None,
            resource_name: Some("api".to_string()),
            api_group: Some("apps".to_string()),
            response_code: Some(200),
            annotations: serde_json::json!({"owner":"fixture"}),
            request_object: serde_json::json!({"metadata":{"name":"api"}}),
            impersonated_username: None,
        }),
    }
}

fn cloudtrail_event(event_id: &str, event_name: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "cloudtrail".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host:cloudtrail-not-account".to_string()),
        payload: TelemetryPayload::CloudTrail(CloudTrailEvent {
            event_name: event_name.to_string(),
            event_source: "iam.amazonaws.com".to_string(),
            aws_account_id: Some("123456789012".to_string()),
            principal_arn: Some("arn:aws:iam::123456789012:user/alice".to_string()),
            principal_id: None,
            principal_name: None,
            principal_type: Some("User".to_string()),
            source_ip_address: Some("198.51.100.10".to_string()),
            aws_region: Some("us-east-1".to_string()),
            user_agent: Some("fixture".to_string()),
            mfa_authenticated: Some(false),
            request_parameters: serde_json::json!({
                "policy": {"Statement": [{"Action":"iam:PassRole"}]},
                "secretAccessKey": "never-export-this-value"
            }),
            response_elements: serde_json::json!({"status":"ok"}),
            error_code: None,
            error_message: None,
        }),
    }
}

fn network_event(event_id: &str, destination_ip: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "network-sensor".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("host-id-is-not-a-source-identity".to_string()),
        payload: TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: "curl".to_string(),
            destination_ip: destination_ip.to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
        }),
    }
}

fn dns_event(event_id: &str, query_name: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "dns-sensor".to_string(),
        event_id: event_id.to_string(),
        timestamp: 1_700_000_000,
        host_id: Some("legacy-dns-host-is-not-causal".to_string()),
        payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
            query_name: query_name.to_string(),
            query_type: "A".to_string(),
            source_ip: Some("198.51.100.10".to_string()),
            process_name: Some("curl".to_string()),
            response_code: Some("NOERROR".to_string()),
        }),
    }
}

fn threat_entry(value: &str) -> ThreatIntelEntry {
    ThreatIntelEntry {
        indicator_type: ThreatIntelIndicatorType::Domain,
        value: value.to_string(),
        source: "taxii-feed".to_string(),
        indicator_id: Some("indicator:fixture".to_string()),
        confidence: 0.9,
        expires_at: 1_800_000_000_000,
    }
}

fn admit_telemetry(
    registry: &mut EvidenceRegistry,
    event: &TelemetryEvent,
    signer: &Keypair,
    scoped_agent_id: &str,
) -> EvidenceAdmissionOutcome {
    let envelope = normalize_telemetry_event(
        event,
        &clock(),
        signer,
        GraphProducerRole::Normalizer,
        scoped_agent_id,
    )
    .unwrap();
    registry.admit(envelope).unwrap()
}

fn admit_threat(
    registry: &mut EvidenceRegistry,
    entry: &ThreatIntelEntry,
    source_record_id: &str,
    signer: &Keypair,
    scoped_agent_id: &str,
) -> EvidenceAdmissionOutcome {
    let envelope = normalize_threat_intel_entry(
        entry,
        source_record_id,
        GraphLogicalTime::new(1_700_000_000_000),
        &clock(),
        signer,
        GraphProducerRole::Normalizer,
        scoped_agent_id,
    )
    .unwrap();
    registry.admit(envelope).unwrap()
}

#[test]
fn cross_telemetry_fixture_preserves_conflicts() {
    let signer = key(11);
    let mut registry = EvidenceRegistry::new(WitnessAdmission::from_key(&signer));

    // Each family has one corroborating record with a distinct source ID and
    // one same-record conflict.  Distinct scoped labels still share one base
    // signing identity and never inflate independent source diversity.
    let telemetry_pairs = [
        (
            admit_telemetry(
                &mut registry,
                &process_event("process:a", "curl https://same.example/a"),
                &signer,
                "normalizer:process-a",
            ),
            admit_telemetry(
                &mut registry,
                &process_event("process:b", "curl https://same.example/a"),
                &signer,
                "normalizer:process-b",
            ),
        ),
        (
            admit_telemetry(
                &mut registry,
                &identity_event("identity:a", true),
                &signer,
                "normalizer:identity-a",
            ),
            admit_telemetry(
                &mut registry,
                &identity_event("identity:b", true),
                &signer,
                "normalizer:identity-b",
            ),
        ),
        (
            admit_telemetry(
                &mut registry,
                &kubernetes_event("kubernetes:a", "create"),
                &signer,
                "normalizer:kubernetes-a",
            ),
            admit_telemetry(
                &mut registry,
                &kubernetes_event("kubernetes:b", "create"),
                &signer,
                "normalizer:kubernetes-b",
            ),
        ),
        (
            admit_telemetry(
                &mut registry,
                &cloudtrail_event("cloudtrail:a", "AssumeRole"),
                &signer,
                "normalizer:cloudtrail-a",
            ),
            admit_telemetry(
                &mut registry,
                &cloudtrail_event("cloudtrail:b", "AssumeRole"),
                &signer,
                "normalizer:cloudtrail-b",
            ),
        ),
        (
            admit_telemetry(
                &mut registry,
                &network_event("network:a", "203.0.113.10"),
                &signer,
                "normalizer:network-a",
            ),
            admit_telemetry(
                &mut registry,
                &network_event("network:b", "203.0.113.10"),
                &signer,
                "normalizer:network-b",
            ),
        ),
    ];
    assert!(telemetry_pairs.iter().all(|(_, corroborating)| matches!(
        corroborating,
        EvidenceAdmissionOutcome::Inserted { .. }
    )));
    assert!(matches!(
        admit_threat(
            &mut registry,
            &threat_entry("evil.example"),
            "threat:a",
            &signer,
            "normalizer:threat-a",
        ),
        EvidenceAdmissionOutcome::Inserted { .. }
    ));

    let conflicts = [
        admit_telemetry(
            &mut registry,
            &process_event("process:a", "curl https://different.example/a"),
            &signer,
            "role-alias-that-is-not-a-new-source",
        ),
        admit_telemetry(
            &mut registry,
            &identity_event("identity:a", false),
            &signer,
            "role-alias-that-is-not-a-new-source",
        ),
        admit_telemetry(
            &mut registry,
            &kubernetes_event("kubernetes:a", "delete"),
            &signer,
            "role-alias-that-is-not-a-new-source",
        ),
        admit_telemetry(
            &mut registry,
            &cloudtrail_event("cloudtrail:a", "DeleteRolePolicy"),
            &signer,
            "role-alias-that-is-not-a-new-source",
        ),
        admit_telemetry(
            &mut registry,
            &network_event("network:a", "203.0.113.11"),
            &signer,
            "role-alias-that-is-not-a-new-source",
        ),
    ];
    // The threat record above is a corroborating baseline; the second one is
    // the same source record with changed facts.
    let threat_conflict = admit_threat(
        &mut registry,
        &threat_entry("other.example"),
        "threat:a",
        &signer,
        "role-alias-that-is-not-a-new-source",
    );

    assert_eq!(conflicts.len(), 5);
    assert!(
        conflicts
            .iter()
            .all(|outcome| matches!(outcome, EvidenceAdmissionOutcome::Conflict { .. }))
    );
    assert!(matches!(
        threat_conflict,
        EvidenceAdmissionOutcome::Conflict { .. }
    ));
    assert_eq!(registry.conflicts().len(), 6);
    assert_eq!(registry.independent_witness_count(), 1);
    registry.validate().unwrap();

    let families = registry
        .evidence()
        .values()
        .map(|evidence| evidence.source_family)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        families,
        BTreeSet::from([
            EvidenceSourceFamily::Process,
            EvidenceSourceFamily::Identity,
            EvidenceSourceFamily::Kubernetes,
            EvidenceSourceFamily::Cloudtrail,
            EvidenceSourceFamily::Network,
            EvidenceSourceFamily::ThreatIntelligence,
        ])
    );
}

#[test]
fn exact_envelope_is_idempotent_but_same_id_different_content_is_rejected() {
    let signer = key(21);
    let mut registry = EvidenceRegistry::with_key(&signer);
    let event = process_event("process:idempotent", "curl https://same.example/a");
    let envelope = normalize_telemetry_event(
        &event,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-a",
    )
    .unwrap();
    let mut tampered = envelope.clone();
    if let TypedEvidencePayload::Process { signal_kind, .. } = &mut tampered.payload {
        *signal_kind = "tampered-process".to_string();
    }
    assert!(matches!(
        registry.admit(envelope.clone()),
        Ok(EvidenceAdmissionOutcome::Inserted { .. })
    ));
    assert!(matches!(
        registry.admit(envelope.clone()),
        Ok(EvidenceAdmissionOutcome::Idempotent { .. })
    ));
    assert!(matches!(
        registry.admit(tampered),
        Err(EvidenceAdmissionError::Graph(_))
    ));
    let mut tampered_signature = normalize_telemetry_event(
        &event,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-a",
    )
    .unwrap();
    tampered_signature.witness.signature_hex = "00".repeat(64);
    assert!(matches!(
        registry.admit(tampered_signature),
        Err(EvidenceAdmissionError::Graph(_))
    ));
    let mut tampered_scope = envelope.clone();
    tampered_scope.witness.scoped_agent_id = "normalizer-tampered".to_string();
    assert!(matches!(
        registry.admit(tampered_scope),
        Err(EvidenceAdmissionError::Graph(_))
    ));
    let mut tampered_role = envelope.clone();
    tampered_role.witness.producer_role = GraphProducerRole::Planner;
    assert!(matches!(
        registry.admit(tampered_role),
        Err(EvidenceAdmissionError::Graph(_))
    ));
}

#[test]
fn kubernetes_resource_identity_is_stable_across_operations() {
    let signer = key(110);
    let create = normalize_telemetry_event(
        &kubernetes_event("kube:stable:create", "create"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-kubernetes",
    )
    .unwrap();
    let mut update_event = kubernetes_event("kube:stable:update", "update");
    update_event.payload = match update_event.payload {
        TelemetryPayload::KubernetesAudit(mut payload) => {
            payload.request_object = serde_json::json!({
                "metadata": {"name": "api"},
                "spec": {"replicas": 3}
            });
            TelemetryPayload::KubernetesAudit(payload)
        }
        _ => unreachable!(),
    };
    let update = normalize_telemetry_event(
        &update_event,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-kubernetes",
    )
    .unwrap();
    let identity = |envelope: &EvidenceEnvelope| match &envelope.payload {
        TypedEvidencePayload::KubernetesAudit {
            resource_digest,
            entity_ids,
            content_digest,
            ..
        } => (
            resource_digest.clone(),
            entity_ids[1].clone(),
            content_digest.clone(),
        ),
        other => panic!("expected Kubernetes payload, got {other:?}"),
    };
    let create_identity = identity(&create);
    let update_identity = identity(&update);

    assert_eq!(create_identity.0, update_identity.0);
    assert_eq!(create_identity.1, update_identity.1);
    assert_ne!(create_identity.2, update_identity.2);
    assert_ne!(create.evidence_id, update.evidence_id);
}

#[test]
fn wrong_or_unadmitted_witness_key_fails_closed() {
    let admitted_key = key(31);
    let unadmitted_key = key(32);
    let envelope = normalize_telemetry_event(
        &process_event("process:wrong-key", "curl https://same.example/a"),
        &clock(),
        &unadmitted_key,
        GraphProducerRole::Normalizer,
        "scoped-role-alias",
    )
    .unwrap();
    let mut registry = EvidenceRegistry::with_key(&admitted_key);
    assert!(matches!(
        registry.admit(envelope),
        Err(EvidenceAdmissionError::UnadmittedWitness { .. })
    ));
}

#[test]
fn unadmitted_graph_signer_is_rejected() {
    let admitted_key = key(70);
    let unadmitted_key = key(71);
    let admission = WitnessAdmission::from_key(&admitted_key);

    assert!(matches!(
        KeypairGraphRecordSigner::with_admission(unadmitted_key.clone(), &admission),
        Err(GraphAdmissionError::InvalidWitness { .. })
    ));

    // The same key must fail before either side of a registry/graph
    // transaction changes.  The serialized graph bytes are the failure spy;
    // a hidden partial node/evidence/version mutation fails this assertion.
    let envelope = normalize_telemetry_event(
        &process_event("process:unadmitted-graph", "curl https://same.example"),
        &clock(),
        &unadmitted_key,
        GraphProducerRole::Normalizer,
        "normalizer:unadmitted",
    )
    .unwrap();
    let mut registry = EvidenceRegistry::with_key(&admitted_key);
    let mut graph = HypothesisGraph::new(
        GraphId::new("graph:unadmitted-graph"),
        GraphResourceLimits::default(),
    )
    .unwrap();
    let before_graph = json_bytes(&graph);
    let before_evidence = registry.evidence().clone();
    let before_conflicts = registry.conflicts().clone();
    assert!(matches!(
        registry.admit_into_graph(&mut graph, envelope),
        Err(EvidenceAdmissionError::UnadmittedWitness { .. })
    ));
    assert_eq!(json_bytes(&graph), before_graph);
    assert_eq!(registry.evidence(), &before_evidence);
    assert_eq!(registry.conflicts(), &before_conflicts);
}

#[test]
fn new_signer_cannot_sign_without_admission() {
    let signer_key = key(72);
    let signer = KeypairGraphRecordSigner::new(signer_key.clone());

    assert!(matches!(
        signer.sign_edge(signer_edge(&signer_key), "hunter:unadmitted"),
        Err(GraphAdmissionError::InvalidWitness { .. })
    ));
}

#[test]
fn role_scope_mutation_invalidates_witness() {
    let signer = key(73);
    let envelope = normalize_telemetry_event(
        &process_event("process:witness-mutation", "curl https://same.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:trusted",
    )
    .unwrap();
    let mut registry = EvidenceRegistry::with_key(&signer);
    let before_evidence = registry.evidence().clone();
    let before_conflicts = registry.conflicts().clone();

    let mut role_mutated = envelope.clone();
    role_mutated.witness.producer_role = GraphProducerRole::Planner;
    assert!(matches!(
        registry.admit(role_mutated),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::InvalidWitness { .. }
        ))
    ));
    let mut scope_mutated = envelope;
    scope_mutated.witness.scoped_agent_id = "normalizer:forged".to_string();
    assert!(matches!(
        registry.admit(scope_mutated),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::InvalidWitness { .. }
        ))
    ));
    assert_eq!(registry.evidence(), &before_evidence);
    assert_eq!(registry.conflicts(), &before_conflicts);
}

#[test]
fn scoped_alias_cannot_grant_capability() {
    let signer = key(74);
    let scoped_alias = AgentId::new("normalizer", "alias-only");
    let envelope = normalize_telemetry_event(
        &process_event("process:scoped-alias", "curl https://same.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:alias-only",
    )
    .unwrap();
    let mut registry = EvidenceRegistry::with_identities([scoped_alias]);

    assert!(matches!(
        registry.admit(envelope),
        Err(EvidenceAdmissionError::UnadmittedWitness { identity })
            if identity == AgentId::from_public_key_hex(&signer.public_key().to_hex())
    ));
}

#[test]
fn allowlist_is_snapshotted() {
    let admitted = key(75);
    let newly_allowed = key(76);
    let mut admission = WitnessAdmission::from_key(&admitted);
    let mut registry = EvidenceRegistry::new(admission.clone());
    admission.admit_key(&newly_allowed);
    let envelope = normalize_telemetry_event(
        &process_event(
            "process:external-allowlist-mutation",
            "curl https://same.example",
        ),
        &clock(),
        &newly_allowed,
        GraphProducerRole::Normalizer,
        "normalizer:newly-allowed",
    )
    .unwrap();

    assert!(matches!(
        registry.admit(envelope),
        Err(EvidenceAdmissionError::UnadmittedWitness { .. })
    ));
    assert_eq!(registry.witness_admission().identities().len(), 1);
}

#[test]
fn registry_allowlist_cannot_change_after_construction() {
    let admitted = key(77);
    let newly_allowed = key(78);
    let mut registry = EvidenceRegistry::with_key(&admitted);
    let mut graph = HypothesisGraph::new(
        GraphId::new("graph:registry-allowlist-snapshot"),
        GraphResourceLimits::default(),
    )
    .unwrap();
    let before_registry_evidence = registry.evidence().clone();
    let before_registry_conflicts = registry.conflicts().clone();
    let before_graph = json_bytes(&graph);

    registry.witness_admission_mut().admit_key(&newly_allowed);
    let envelope = normalize_telemetry_event(
        &process_event(
            "process:registry-allowlist-mutation",
            "curl https://same.example",
        ),
        &clock(),
        &newly_allowed,
        GraphProducerRole::Normalizer,
        "normalizer:mutated-view",
    )
    .unwrap();
    assert!(matches!(
        registry.admit_into_graph(&mut graph, envelope),
        Err(EvidenceAdmissionError::UnadmittedWitness { .. })
    ));
    assert_eq!(registry.evidence(), &before_registry_evidence);
    assert_eq!(registry.conflicts(), &before_registry_conflicts);
    assert_eq!(json_bytes(&graph), before_graph);
    assert!(
        !registry
            .witness_admission()
            .contains(&AgentId::from_public_key_hex(
                &newly_allowed.public_key().to_hex()
            ))
    );
}

#[test]
fn source_time_conflicts_remain_visible_and_legacy_host_id_is_ignored() {
    let signer = key(41);
    let mut registry = EvidenceRegistry::with_key(&signer);
    let first = process_event("process:time", "curl https://same.example/a");
    let mut second = first.clone();
    second.timestamp = 1_700_000_001;
    let first_envelope = normalize_telemetry_event(
        &first,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-a",
    )
    .unwrap();
    let second_envelope = normalize_telemetry_event(
        &second,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-b",
    )
    .unwrap();
    assert_eq!(
        first_envelope.lineage.source_record_id,
        second_envelope.lineage.source_record_id
    );
    assert_ne!(
        first_envelope.clock.observed_at,
        second_envelope.clock.observed_at
    );
    registry.admit(first_envelope).unwrap();
    let outcome = registry.admit(second_envelope).unwrap();
    assert!(matches!(
        outcome,
        EvidenceAdmissionOutcome::Conflict { conflict, .. }
            if conflict.kind == swarm_core::hypothesis_graph::ContradictionKind::SourceTimeConflict
    ));
    let serialized = serde_json::to_string(registry.evidence().values().next().unwrap()).unwrap();
    assert!(!serialized.contains("legacy-host-field-must-not-be-causal"));
}

#[test]
fn conflict_detection_preserves_canonical_adjacencies_and_append_only_history() {
    let signer = key(51);
    let events = [
        process_event("process:order", "curl https://one.example/a"),
        process_event("process:order", "curl https://two.example/a"),
        process_event("process:order", "curl https://three.example/a"),
    ];
    let mut first = EvidenceRegistry::with_key(&signer);
    for event in &events {
        admit_telemetry(&mut first, event, &signer, "alias-a");
    }
    let mut second = EvidenceRegistry::with_key(&signer);
    for event in events.iter().rev() {
        admit_telemetry(&mut second, event, &signer, "alias-b");
    }
    assert_eq!(
        first.evidence().keys().collect::<Vec<_>>(),
        second.evidence().keys().collect::<Vec<_>>()
    );
    first.validate().unwrap();
    second.validate().unwrap();

    // The durable graph is append-only, so a conflict observed before a
    // canonical middle record arrives remains historical evidence. Every
    // insertion order must nevertheless contain the same final adjacent
    // conflicts required by the source-record index.
    let evidence_ids = first.evidence().keys().collect::<Vec<_>>();
    for pair in evidence_ids.windows(2) {
        for registry in [&first, &second] {
            assert!(registry.conflicts().values().any(|conflict| {
                &conflict.left_evidence_id == pair[0] && &conflict.right_evidence_id == pair[1]
            }));
        }
    }
}

#[test]
fn explicit_timestamp_units_cover_boundary_without_magic_inference() {
    let boundary = 100_000_000_000;
    let (seconds, second_precision, second_uncertainty) =
        normalize_source_timestamp(boundary, SourceTimestampUnit::Seconds).unwrap();
    let (milliseconds, millisecond_precision, millisecond_uncertainty) =
        normalize_source_timestamp(boundary, SourceTimestampUnit::Milliseconds).unwrap();
    assert_eq!(seconds, GraphLogicalTime::new(boundary * 1_000));
    assert_eq!(milliseconds, GraphLogicalTime::new(boundary));
    assert_eq!(
        second_precision,
        swarm_core::hypothesis_graph::ClockPrecision::Second
    );
    assert_eq!(
        millisecond_precision,
        swarm_core::hypothesis_graph::ClockPrecision::Millisecond
    );
    assert_eq!(second_uncertainty, 999);
    assert_eq!(millisecond_uncertainty, 0);
    assert!(normalize_source_timestamp(-1, SourceTimestampUnit::Seconds).is_err());
    assert!(normalize_source_timestamp(i64::MAX, SourceTimestampUnit::Seconds).is_err());

    let signer = key(60);
    let mut invalid_event = process_event("process:timestamp-invalid", "curl https://example.test");
    invalid_event.timestamp = i64::MIN;
    assert!(
        normalize_telemetry_event(
            &invalid_event,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer-invalid-timestamp",
        )
        .is_err()
    );
    let mut event = process_event("process:timestamp-unit", "curl https://example.test");
    event.timestamp = boundary;
    let seconds_event = normalize_telemetry_event_with_unit(
        &event,
        SourceTimestampUnit::Seconds,
        &FixedGraphClock::new(GraphLogicalTime::new(boundary * 1_000 + 1_000)),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-seconds",
    )
    .unwrap();
    let milliseconds_event = normalize_telemetry_event_with_unit(
        &event,
        SourceTimestampUnit::Milliseconds,
        &FixedGraphClock::new(GraphLogicalTime::new(boundary + 1_000)),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-milliseconds",
    )
    .unwrap();
    assert_eq!(seconds_event.clock.observed_at, seconds);
    assert_eq!(milliseconds_event.clock.observed_at, milliseconds);
}

#[test]
fn host_clock_perturbation_is_operational_not_evidence_identity() {
    let signer = key(61);
    let event = process_event("process:clock", "curl https://same.example/a");
    let first = normalize_telemetry_event(
        &event,
        &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-clock",
    )
    .unwrap();
    let second = normalize_telemetry_event(
        &event,
        &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_002_000)),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-clock",
    )
    .unwrap();
    assert_eq!(first.evidence_id, second.evidence_id);
    assert_ne!(first.clock.ingested_at, second.clock.ingested_at);
    let mut registry = EvidenceRegistry::with_key(&signer);
    registry.admit(first).unwrap();
    assert!(matches!(
        registry.admit(second),
        Ok(EvidenceAdmissionOutcome::Idempotent { .. })
    ));
}

#[test]
fn cross_source_ids_do_not_conflict_but_adapter_variation_cannot_evade_conflict() {
    let signer = key(62);
    let first = normalize_telemetry_event(
        &process_event("shared:event", "curl https://same.example/a"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-a",
    )
    .unwrap();
    let mut other_source = process_event("shared:event", "curl https://same.example/a");
    other_source.source = "other-vendor".to_string();
    let second = normalize_telemetry_event(
        &other_source,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-b",
    )
    .unwrap();
    let first_event_node = match &first.payload {
        TypedEvidencePayload::Process { entity_ids, .. } => entity_ids[1].clone(),
        other => panic!("expected process payload, got {other:?}"),
    };
    let second_event_node = match &second.payload {
        TypedEvidencePayload::Process { entity_ids, .. } => entity_ids[1].clone(),
        other => panic!("expected process payload, got {other:?}"),
    };
    assert_ne!(
        first_event_node, second_event_node,
        "source-scoped record IDs must not alias event nodes"
    );
    let mut registry = EvidenceRegistry::with_key(&signer);
    assert!(matches!(
        registry.admit(first.clone()),
        Ok(EvidenceAdmissionOutcome::Inserted { .. })
    ));
    assert!(matches!(
        registry.admit(second),
        Ok(EvidenceAdmissionOutcome::Inserted { .. })
    ));

    let mut alternate_lineage = first.lineage.clone();
    alternate_lineage.adapter = "untrusted-alternate-adapter".to_string();
    let alternate = EvidenceEnvelope::new(
        first.source_family,
        first.source_id.clone(),
        alternate_lineage,
        first.clock.clone(),
        first.ordering.clone(),
        first.payload.clone(),
    )
    .unwrap()
    .sign_with(
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-alternate",
    )
    .unwrap();
    assert!(matches!(
        registry.admit(alternate),
        Ok(EvidenceAdmissionOutcome::Conflict { .. })
    ));
    assert_eq!(registry.conflicts().len(), 1);
}

#[test]
fn event_node_same_time_different_source_records_are_distinct() {
    let signer = key(79);
    let first = normalize_telemetry_event(
        &process_event("process:source-record-a", "curl https://same.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:event-a",
    )
    .unwrap();
    let second = normalize_telemetry_event(
        &process_event("process:source-record-b", "curl https://same.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:event-b",
    )
    .unwrap();
    let event_node = |envelope: &EvidenceEnvelope| match &envelope.payload {
        TypedEvidencePayload::Process { entity_ids, .. } => entity_ids[1].clone(),
        other => panic!("expected process payload, got {other:?}"),
    };

    assert_eq!(first.clock.observed_at, second.clock.observed_at);
    assert_ne!(event_node(&first), event_node(&second));
    assert_ne!(first.evidence_id, second.evidence_id);

    let mut registry = EvidenceRegistry::with_key(&signer);
    assert!(matches!(
        registry.admit(first.clone()),
        Ok(EvidenceAdmissionOutcome::Inserted { .. })
    ));
    assert!(matches!(
        registry.admit(second),
        Ok(EvidenceAdmissionOutcome::Inserted { .. })
    ));
    assert!(matches!(
        registry.admit(first),
        Ok(EvidenceAdmissionOutcome::Idempotent { .. })
    ));
}

#[test]
fn source_record_identity_is_required_and_bounded() {
    let signer = key(80);
    let mut missing = process_event(
        "process:source-record-required",
        "curl https://same.example",
    );
    missing.event_id.clear();
    assert!(matches!(
        normalize_telemetry_event(
            &missing,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer:missing-record",
        ),
        Err(GraphAdmissionError::InvalidField { field, .. }) if field == "telemetry.event_id"
    ));

    let mut oversized = process_event(
        "process:source-record-oversized",
        "curl https://same.example",
    );
    oversized.event_id = "x".repeat(257);
    assert!(matches!(
        normalize_telemetry_event(
            &oversized,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer:oversized-record",
        ),
        Err(GraphAdmissionError::ResourceLimitExceeded { resource, .. })
            if resource == "telemetry.event_id"
    ));
}

#[test]
fn cloudtrail_unknown_identity_is_event_scoped() {
    let signer = key(81);
    let mut first = cloudtrail_event("cloudtrail:unknown-a", "AssumeRole");
    first.payload = match first.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.aws_account_id = None;
            payload.principal_arn = None;
            payload.principal_id = None;
            payload.principal_name = None;
            payload.principal_type = None;
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    let mut second = first.clone();
    second.event_id = "cloudtrail:unknown-b".to_string();
    let first = normalize_telemetry_event(
        &first,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:cloudtrail",
    )
    .unwrap();
    let second = normalize_telemetry_event(
        &second,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:cloudtrail",
    )
    .unwrap();
    let digests = |envelope: &EvidenceEnvelope| match &envelope.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest,
            account_digest,
            ..
        } => (principal_digest.clone(), account_digest.clone()),
        other => panic!("expected CloudTrail payload, got {other:?}"),
    };
    assert_ne!(digests(&first), digests(&second));

    let mut lower_priority_a = cloudtrail_event("cloudtrail:lower-priority", "AssumeRole");
    lower_priority_a.payload = match lower_priority_a.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.principal_id = Some("AIDAEXAMPLE".to_string());
            payload.principal_name = Some("alice".to_string());
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    let mut lower_priority_b = lower_priority_a.clone();
    lower_priority_b.payload = match lower_priority_b.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.principal_type = Some("Role".to_string());
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    let lower_priority_a = normalize_telemetry_event(
        &lower_priority_a,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:cloudtrail",
    )
    .unwrap();
    let lower_priority_b = normalize_telemetry_event(
        &lower_priority_b,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:cloudtrail",
    )
    .unwrap();
    assert_ne!(digests(&lower_priority_a), digests(&lower_priority_b));
    assert_ne!(lower_priority_a.evidence_id, lower_priority_b.evidence_id);
}

#[test]
fn cloudtrail_dns_expiry_and_typed_metadata_are_preserved_without_host_aliasing() {
    let signer = key(63);
    let cloudtrail = normalize_telemetry_event(
        &cloudtrail_event("cloud:typed", "AssumeRole"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    match &cloudtrail.payload {
        TypedEvidencePayload::Cloudtrail {
            event_source,
            request_digest,
            response_digest,
            mfa_authenticated,
            region,
            entity_ids,
            ..
        } => {
            assert_eq!(event_source, "iam.amazonaws.com");
            assert_eq!(request_digest.len(), 64);
            assert_eq!(response_digest.len(), 64);
            assert_eq!(*mfa_authenticated, Some(false));
            assert_eq!(region.as_deref(), Some("us-east-1"));
            assert_eq!(entity_ids.len(), 3);
        }
        other => panic!("expected typed cloudtrail payload, got {other:?}"),
    }
    let serialized = serde_json::to_string(&cloudtrail).unwrap();
    assert!(!serialized.contains("123456789012"));
    assert!(serialized.contains("iam.amazonaws.com"));
    let mut host_variant = cloudtrail_event("cloud:typed", "AssumeRole");
    host_variant.host_id = Some("host:another-cloudtrail-machine".to_string());
    let host_variant = normalize_telemetry_event(
        &host_variant,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    assert_eq!(cloudtrail.evidence_id, host_variant.evidence_id);

    // Known identities are reusable graph entities across events; event IDs
    // only scope an absent principal/account.  The evidence records still
    // differ because their event facts and event nodes are distinct.
    let known_identity_a = cloudtrail_event("cloud:known-a", "AssumeRole");
    let mut known_identity_b = known_identity_a.clone();
    known_identity_b.event_id = "cloud:known-b".to_string();
    let known_identity_a = normalize_telemetry_event(
        &known_identity_a,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    let known_identity_b = normalize_telemetry_event(
        &known_identity_b,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    let known_entities_a = match &known_identity_a.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest,
            account_digest,
            ..
        } => (principal_digest.clone(), account_digest.clone()),
        other => panic!("expected typed CloudTrail payload, got {other:?}"),
    };
    let known_entities_b = match &known_identity_b.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest,
            account_digest,
            ..
        } => (principal_digest.clone(), account_digest.clone()),
        other => panic!("expected typed CloudTrail payload, got {other:?}"),
    };
    assert_eq!(known_entities_a, known_entities_b);
    assert_ne!(known_identity_a.evidence_id, known_identity_b.evidence_id);

    // Missing identities must remain event-scoped.  Otherwise unrelated
    // identity-less CloudTrail events would alias one global `unknown`
    // actor/account node.
    let mut missing_identity_a = cloudtrail_event("cloud:missing-a", "AssumeRole");
    missing_identity_a.payload = match missing_identity_a.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.aws_account_id = None;
            payload.principal_arn = None;
            payload.principal_id = None;
            payload.principal_name = None;
            payload.principal_type = None;
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    let mut missing_identity_b = missing_identity_a.clone();
    missing_identity_b.event_id = "cloud:missing-b".to_string();
    let missing_identity_a = normalize_telemetry_event(
        &missing_identity_a,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    let missing_identity_b = normalize_telemetry_event(
        &missing_identity_b,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    let missing_principal_a = match &missing_identity_a.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest,
            account_digest,
            ..
        } => (principal_digest.clone(), account_digest.clone()),
        other => panic!("expected typed CloudTrail payload, got {other:?}"),
    };
    let missing_principal_b = match &missing_identity_b.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest,
            account_digest,
            ..
        } => (principal_digest.clone(), account_digest.clone()),
        other => panic!("expected typed CloudTrail payload, got {other:?}"),
    };
    assert_ne!(missing_principal_a, missing_principal_b);

    // Every supplied principal field is part of the causal digest, including
    // lower-priority fields that accompany an ARN.
    let mut principal_name_a = cloudtrail_event("cloud:principal-fields", "AssumeRole");
    principal_name_a.payload = match principal_name_a.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.principal_id = Some("AIDAEXAMPLE".to_string());
            payload.principal_name = Some("alice".to_string());
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    let mut principal_name_b = principal_name_a.clone();
    principal_name_b.payload = match principal_name_b.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.principal_name = Some("bob".to_string());
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    let principal_name_a = normalize_telemetry_event(
        &principal_name_a,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    let principal_name_b = normalize_telemetry_event(
        &principal_name_b,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-cloud",
    )
    .unwrap();
    let principal_digest_a = match &principal_name_a.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest, ..
        } => principal_digest,
        other => panic!("expected typed CloudTrail payload, got {other:?}"),
    };
    let principal_digest_b = match &principal_name_b.payload {
        TypedEvidencePayload::Cloudtrail {
            principal_digest, ..
        } => principal_digest,
        other => panic!("expected typed CloudTrail payload, got {other:?}"),
    };
    assert_ne!(principal_digest_a, principal_digest_b);
    assert_ne!(principal_name_a.evidence_id, principal_name_b.evidence_id);

    let dns = normalize_telemetry_event(
        &dns_event("dns:typed", "evil.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-dns",
    )
    .unwrap();
    assert!(matches!(
        dns.payload,
        TypedEvidencePayload::Network {
            protocol,
            ..
        } if protocol == "A"
    ));

    let threat = normalize_threat_intel_entry(
        &threat_entry("evil.example"),
        "threat:expiry",
        GraphLogicalTime::new(1_700_000_000_000),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-threat",
    )
    .unwrap();
    assert_eq!(
        threat.payload.expires_at(),
        Some(GraphLogicalTime::new(1_800_000_000_000))
    );
    assert_eq!(
        threat
            .payload
            .is_active_at(GraphLogicalTime::new(1_800_000_000_000))
            .unwrap(),
        Some(false)
    );
    assert_eq!(
        threat
            .payload
            .is_active_at(GraphLogicalTime::new(1_799_999_999_999))
            .unwrap(),
        Some(true)
    );
}

#[test]
fn typed_evidence_payload_direct_deserialize_is_validated() {
    let signer = key(82);
    let envelope = normalize_telemetry_event(
        &process_event("process:payload-wire", "curl https://same.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:payload-wire",
    )
    .unwrap();
    let before = json_bytes(&envelope.payload);
    let mut tampered = serde_json::to_value(&envelope.payload).unwrap();
    tampered["signal_kind"] = serde_json::Value::String(String::new());

    assert!(serde_json::from_value::<TypedEvidencePayload>(tampered).is_err());
    assert_eq!(json_bytes(&envelope.payload), before);
}

#[test]
fn graph_version_overflow_is_fail_closed() {
    let signer = key(83);
    let envelope = normalize_telemetry_event(
        &process_event(
            "process:graph-version-overflow",
            "curl https://same.example",
        ),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:graph-version",
    )
    .unwrap();
    let mut graph = HypothesisGraph::new(
        GraphId::new("graph:version-overflow"),
        GraphResourceLimits::default(),
    )
    .unwrap();
    graph.version = u64::MAX;
    let before = json_bytes(&graph);

    assert!(matches!(
        graph.admit_evidence(envelope),
        Err(GraphAdmissionError::InvalidTransition { reason })
            if reason == "graph version is exhausted"
    ));
    assert_eq!(json_bytes(&graph), before);
    assert!(graph.evidence.is_empty());
}

#[test]
fn runtime_with_limits_rejects_registry_scheduler_mismatch_without_mutation() {
    let signer = key(84);
    let registry_limits = GraphResourceLimits::default();
    let registry = EvidenceRegistry::with_key_and_limits(&signer, registry_limits.clone()).unwrap();
    let before = registry_state_bytes(&registry);
    let mut scheduler_limits = registry_limits;
    scheduler_limits.max_tasks += 1;

    let result = HypothesisGraphRuntime::with_limits(clock(), registry.clone(), scheduler_limits);

    assert!(matches!(
        result,
        Err(GraphAdmissionError::InvalidTransition { reason })
            if reason == "runtime registry and scheduler limits must match"
    ));
    assert_eq!(registry_state_bytes(&registry), before);
}

#[test]
fn config_bound_runtime_budget_gates_logical_pop_and_admission() {
    let signer = key(85);
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 5,
        max_claims_per_tick: 1,
        ..HypothesisGraphConfig::default()
    };
    let registry =
        EvidenceRegistry::with_key_and_limits(&signer, config.resource_limits()).unwrap();
    let mut runtime = HypothesisGraphRuntime::with_config_at(
        FixedGraphClock::new(GraphLogicalTime::new(100)),
        registry,
        &config,
        GraphLogicalTime::new(100),
    )
    .unwrap();

    let budget = runtime.budget.as_ref().unwrap();
    assert_eq!(budget.max_work_units, config.max_work_units_per_tick);
    assert_eq!(budget.max_claims, config.max_claims_per_tick);
    assert_eq!(budget.current_tick(), GraphLogicalTime::new(100));

    let future_task = TaskId::new("task:budget-future");
    runtime
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(110),
            TaskKind::AcquireEvidence,
            100,
            future_task.clone(),
        )
        .unwrap();
    let before_future_tasks = json_bytes(&runtime.scheduler.ordered());
    let before_future_budget = runtime.budget.clone();
    assert!(
        runtime
            .pop_ready_budgeted(GraphLogicalTime::new(109), 2, 1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        json_bytes(&runtime.scheduler.ordered()),
        before_future_tasks
    );
    assert_eq!(runtime.budget, before_future_budget);
    assert!(runtime.scheduler.contains(&future_task));

    runtime
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(100),
            TaskKind::AcquireEvidence,
            100,
            TaskId::new("task:budget-ready-first"),
        )
        .unwrap();
    assert!(
        runtime
            .pop_ready_budgeted(GraphLogicalTime::new(100), 5, 1)
            .unwrap()
            .is_some()
    );
    let used_budget = runtime.budget.as_ref().unwrap();
    assert_eq!(used_budget.work_units_used(), 5);
    assert_eq!(used_budget.claims_used(), 1);

    let second_task = TaskId::new("task:budget-ready-second");
    runtime
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(100),
            TaskKind::FalsifyHypothesis,
            100,
            second_task.clone(),
        )
        .unwrap();
    let before_failed_pop_tasks = json_bytes(&runtime.scheduler.ordered());
    let before_failed_pop_budget = runtime.budget.clone();
    assert!(matches!(
        runtime.pop_ready_budgeted(GraphLogicalTime::new(100), 1, 0),
        Err(GraphAdmissionError::ResourceLimitExceeded { resource, .. })
            if resource == "scheduler.work_units_per_tick"
    ));
    assert_eq!(
        json_bytes(&runtime.scheduler.ordered()),
        before_failed_pop_tasks
    );
    assert_eq!(runtime.budget, before_failed_pop_budget);
    assert!(runtime.scheduler.contains(&second_task));

    let before_failed_admission = runtime.budget.clone();
    assert!(matches!(
        runtime.admit_scheduler_work(GraphLogicalTime::new(100), 0, 1),
        Err(GraphAdmissionError::ResourceLimitExceeded { resource, .. })
            if resource == "scheduler.claims_per_tick"
    ));
    assert_eq!(runtime.budget, before_failed_admission);
}

#[test]
fn serde_mutated_budget_above_active_config_is_rejected_without_pop() {
    let signer = key(86);
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 5,
        max_claims_per_tick: 1,
        ..HypothesisGraphConfig::default()
    };
    let registry =
        EvidenceRegistry::with_key_and_limits(&signer, config.resource_limits()).unwrap();
    let mut runtime = HypothesisGraphRuntime::with_config_at(
        FixedGraphClock::new(GraphLogicalTime::new(200)),
        registry,
        &config,
        GraphLogicalTime::new(200),
    )
    .unwrap();
    runtime
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(200),
            TaskKind::AcquireEvidence,
            100,
            TaskId::new("task:budget-tampered"),
        )
        .unwrap();

    let mut tampered_wire = serde_json::to_value(runtime.budget.as_ref().unwrap()).unwrap();
    tampered_wire["max_work_units"] = serde_json::json!(6);
    let tampered_budget: SchedulerBudget = serde_json::from_value(tampered_wire).unwrap();
    runtime.budget = Some(tampered_budget);
    let before_tasks = json_bytes(&runtime.scheduler.ordered());
    let before_budget = runtime.budget.clone();

    assert!(matches!(
        runtime.pop_ready_budgeted(GraphLogicalTime::new(200), 0, 0),
        Err(GraphAdmissionError::InvalidLimit { field, .. })
            if field == "scheduler.max_work_units"
    ));
    assert_eq!(json_bytes(&runtime.scheduler.ordered()), before_tasks);
    assert_eq!(runtime.budget, before_budget);
}

#[test]
fn disabled_config_and_legacy_runtime_keep_unbudgeted_scheduler_behavior() {
    let signer = key(87);
    let config = HypothesisGraphConfig::default();
    assert!(!config.enabled);
    let registry =
        EvidenceRegistry::with_key_and_limits(&signer, config.resource_limits()).unwrap();
    let mut configured = HypothesisGraphRuntime::with_config_at(
        FixedGraphClock::new(GraphLogicalTime::new(300)),
        registry,
        &config,
        GraphLogicalTime::new(300),
    )
    .unwrap();
    assert!(configured.budget.is_none());
    configured
        .admit_scheduler_work(GraphLogicalTime::new(300), u32::MAX, u16::MAX)
        .unwrap();
    configured
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(300),
            TaskKind::AcquireEvidence,
            100,
            TaskId::new("task:disabled-config"),
        )
        .unwrap();
    assert!(
        configured
            .pop_ready_budgeted(GraphLogicalTime::new(300), u32::MAX, u16::MAX)
            .unwrap()
            .is_some()
    );

    let mut legacy = HypothesisGraphRuntime::new(clock(), EvidenceRegistry::with_key(&signer));
    assert!(legacy.budget.is_none());
    legacy
        .admit_scheduler_work(GraphLogicalTime::new(1), u32::MAX, u16::MAX)
        .unwrap();
}

#[test]
fn bounded_raw_inputs_and_parent_sentinels_fail_closed() {
    let signer = key(64);
    let oversized = process_event(
        "process:oversized",
        &"x".repeat(MAX_SOURCE_TEXT_BYTES.saturating_add(1)),
    );
    assert!(matches!(
        normalize_telemetry_event(
            &oversized,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer-bounds",
        ),
        Err(GraphAdmissionError::ResourceLimitExceeded { .. })
    ));

    let mut node_heavy = cloudtrail_event("cloud:nodes", "AssumeRole");
    node_heavy.payload = match node_heavy.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.request_parameters = serde_json::Value::Array(
                (0..=MAX_RAW_PROJECTION_NODES)
                    .map(|_| serde_json::Value::Bool(true))
                    .collect(),
            );
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        normalize_telemetry_event(
            &node_heavy,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer-bounds",
        ),
        Err(GraphAdmissionError::ResourceLimitExceeded { .. })
    ));

    let mut cloud = cloudtrail_event("cloud:oversized", "AssumeRole");
    cloud.payload = match cloud.payload {
        TelemetryPayload::CloudTrail(mut payload) => {
            payload.request_parameters = serde_json::json!({
                "nested": "x".repeat(MAX_RAW_PROJECTION_BYTES.saturating_add(1))
            });
            TelemetryPayload::CloudTrail(payload)
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        normalize_telemetry_event(
            &cloud,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer-bounds",
        ),
        Err(GraphAdmissionError::ResourceLimitExceeded { .. })
    ));

    let mut deep = serde_json::json!("leaf");
    for _ in 0..=MAX_RAW_PROJECTION_DEPTH {
        deep = serde_json::json!([deep]);
    }
    let mut kube = kubernetes_event("kube:deep", "create");
    kube.payload = match kube.payload {
        TelemetryPayload::KubernetesAudit(mut payload) => {
            payload.annotations = deep;
            payload.user_groups = vec!["group".to_string(); 65];
            TelemetryPayload::KubernetesAudit(payload)
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        normalize_telemetry_event(
            &kube,
            &clock(),
            &signer,
            GraphProducerRole::Normalizer,
            "normalizer-bounds",
        ),
        Err(GraphAdmissionError::ResourceLimitExceeded { .. })
    ));

    let mut parentless = process_event("process:parentless", "curl https://example.test");
    parentless.payload = match parentless.payload {
        TelemetryPayload::ProcessStart(mut payload) => {
            payload.parent_process = "<none>".to_string();
            TelemetryPayload::ProcessStart(payload)
        }
        _ => unreachable!(),
    };
    let envelope = normalize_telemetry_event(
        &parentless,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-parentless",
    )
    .unwrap();
    assert!(matches!(
        envelope.payload,
        TypedEvidencePayload::Process {
            parent_process_digest: None,
            ..
        }
    ));
}

#[test]
fn registry_limits_and_graph_transaction_cover_aggregate_bytes_witnesses_and_conflicts() {
    let signer = key(65);
    let first = normalize_telemetry_event(
        &process_event("process:limits", "curl https://one.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-limits",
    )
    .unwrap();
    let second = normalize_telemetry_event(
        &process_event("process:limits", "curl https://two.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-limits",
    )
    .unwrap();

    let count_limits = GraphResourceLimits {
        max_nodes: 1,
        max_edges: 1,
        ..GraphResourceLimits::default()
    };
    let mut count_registry = EvidenceRegistry::with_key_and_limits(&signer, count_limits).unwrap();
    count_registry.admit(first.clone()).unwrap();
    assert!(matches!(
        count_registry.admit(second.clone()),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::ResourceLimitExceeded { resource, .. }
        )) if resource == "evidence"
    ));

    let byte_limits = GraphResourceLimits {
        max_evidence_bytes: first.canonical_bytes().unwrap().len().saturating_sub(1),
        ..GraphResourceLimits::default()
    };
    let mut byte_registry = EvidenceRegistry::with_key_and_limits(&signer, byte_limits).unwrap();
    assert!(matches!(
        byte_registry.admit(first.clone()),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::ResourceLimitExceeded { resource, .. }
        )) if resource == "evidence_bytes"
    ));

    let source_limits = GraphResourceLimits {
        max_graph_fan_out: 1,
        ..GraphResourceLimits::default()
    };
    let mut source_registry =
        EvidenceRegistry::with_key_and_limits(&signer, source_limits).unwrap();
    source_registry.admit(first.clone()).unwrap();
    assert!(matches!(
        source_registry.admit(second.clone()),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::ResourceLimitExceeded { resource, .. }
        )) if resource == "source_record_evidence"
    ));

    let conflict_limits = GraphResourceLimits {
        max_contradictions: 1,
        ..GraphResourceLimits::default()
    };
    let third = normalize_telemetry_event(
        &process_event("process:limits", "curl https://three.example"),
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-limits",
    )
    .unwrap();
    let mut conflict_registry =
        EvidenceRegistry::with_key_and_limits(&signer, conflict_limits).unwrap();
    conflict_registry.admit(first.clone()).unwrap();
    conflict_registry.admit(second.clone()).unwrap();
    assert!(matches!(
        conflict_registry.admit(third.clone()),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::ResourceLimitExceeded { resource, .. }
        )) if resource == "conflicts"
    ));

    let second_signer = key(68);
    let witness_limits = GraphResourceLimits {
        max_hypotheses: 1,
        ..GraphResourceLimits::default()
    };
    let witness_error = EvidenceRegistry::with_identities_and_limits(
        [
            AgentId::from_public_key_hex(&signer.public_key().to_hex()),
            AgentId::from_public_key_hex(&second_signer.public_key().to_hex()),
        ],
        witness_limits,
    )
    .unwrap_err();
    assert!(matches!(
        witness_error,
        EvidenceAdmissionError::Graph(GraphAdmissionError::ResourceLimitExceeded {
            resource,
            ..
        }) if resource == "witnesses"
    ));

    let mut graph_registry = EvidenceRegistry::with_key(&signer);
    let mut graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
        GraphId::new("graph:transaction"),
        GraphResourceLimits::default(),
    )
    .unwrap();
    graph_registry
        .admit_into_graph(&mut graph, first.clone())
        .unwrap();
    graph_registry
        .admit_into_graph(&mut graph, second.clone())
        .unwrap();
    assert_eq!(graph.evidence.len(), 2);
    assert_eq!(graph.conflicts.len(), 1);
    graph_registry
        .admit_into_graph(&mut graph, third.clone())
        .unwrap();
    assert_eq!(graph.evidence.len(), 3);
    assert_eq!(graph.conflicts.len(), graph_registry.conflicts().len());
    assert_eq!(
        graph.conflicts.keys().collect::<Vec<_>>(),
        graph_registry.conflicts().keys().collect::<Vec<_>>()
    );
    graph_registry.validate().unwrap();

    let conflict_id = graph
        .conflicts
        .keys()
        .next()
        .cloned()
        .expect("the graph transaction must retain a conflict");
    let conflict_before = graph.conflicts.get(&conflict_id).cloned();
    graph.version = u64::MAX;
    assert!(matches!(
        graph.remove_conflict(&conflict_id),
        Err(GraphAdmissionError::InvalidTransition { .. })
    ));
    assert_eq!(graph.conflicts.get(&conflict_id).cloned(), conflict_before);

    let bounded_graph_limits = GraphResourceLimits {
        max_contradictions: 1,
        ..GraphResourceLimits::default()
    };
    let mut bounded_graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
        GraphId::new("graph:transaction-boundary"),
        bounded_graph_limits,
    )
    .unwrap();
    let mut bounded_registry = EvidenceRegistry::with_key(&signer);
    bounded_registry
        .admit_into_graph(&mut bounded_graph, first.clone())
        .unwrap();
    bounded_registry
        .admit_into_graph(&mut bounded_graph, second.clone())
        .unwrap();
    let before_registry = bounded_registry.clone();
    let before_graph = bounded_graph.clone();
    assert!(matches!(
        bounded_registry.admit_into_graph(&mut bounded_graph, third.clone()),
        Err(EvidenceAdmissionError::Graph(
            GraphAdmissionError::ResourceLimitExceeded { resource, .. }
        )) if resource == "conflicts"
    ));
    assert_eq!(bounded_registry.evidence(), before_registry.evidence());
    assert_eq!(bounded_registry.conflicts(), before_registry.conflicts());
    assert_eq!(bounded_graph.evidence, before_graph.evidence);
    assert_eq!(bounded_graph.conflicts, before_graph.conflicts);
}

#[test]
fn middle_evidence_append_preserves_durable_historical_conflict() {
    let evidence_signer = key(69);
    let authority = key(70);
    let mut envelopes = [
        "curl https://one.example",
        "curl https://two.example",
        "curl https://three.example",
    ]
    .into_iter()
    .map(|command_line| {
        normalize_telemetry_event(
            &process_event("process:durable-middle", command_line),
            &clock(),
            &evidence_signer,
            GraphProducerRole::Normalizer,
            "normalizer-durable-middle",
        )
        .unwrap()
    })
    .collect::<Vec<_>>();
    envelopes.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    let low = envelopes[0].clone();
    let middle = envelopes[1].clone();
    let high = envelopes[2].clone();

    let mut registry = EvidenceRegistry::with_key(&evidence_signer);
    let mut graph = HypothesisGraph::new(
        GraphId::new("graph:durable-middle"),
        GraphResourceLimits::default(),
    )
    .unwrap();
    registry.admit_into_graph(&mut graph, low).unwrap();
    registry.admit_into_graph(&mut graph, high).unwrap();
    let historical_conflict_id = graph
        .conflicts
        .keys()
        .next()
        .cloned()
        .expect("two conflicting envelopes must create one durable conflict");

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "swarm-hypothesis-middle-cas-{}-{unique}",
        std::process::id()
    ));
    let store = FileHypothesisGraphStore::new(&path, graph.clone(), authority.clone()).unwrap();
    let baseline = store.snapshot().unwrap();

    registry.admit_into_graph(&mut graph, middle).unwrap();
    registry.validate().unwrap();
    assert_eq!(graph.conflicts.len(), 3);
    assert!(graph.conflicts.contains_key(&historical_conflict_id));
    assert_eq!(graph.conflicts, registry.conflicts().clone());

    let mut candidate = baseline.state().clone();
    candidate.graph = graph;
    store
        .compare_and_swap(baseline.revision(), candidate)
        .unwrap();
    drop(store);

    let reopened = FileHypothesisGraphStore::open_with_signer(&path, authority).unwrap();
    let persisted = reopened.snapshot().unwrap().state().graph.clone();
    assert_eq!(persisted.conflicts.len(), 3);
    assert!(persisted.conflicts.contains_key(&historical_conflict_id));
    drop(reopened);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn registry_value_name_and_value_data_remain_distinct_facts() {
    let signer = key(66);
    let mut first = process_event("process:registry", "reg.exe");
    let mut second = first.clone();
    first.payload = TelemetryPayload::RegistryPersistence(swarm_core::RegistryPersistenceEvent {
        process_name: "reg.exe".to_string(),
        registry_path: "HKCU\\Run".to_string(),
        value_name: Some("Updater".to_string()),
        value_data: Some("one".to_string()),
        access_type: "set".to_string(),
    });
    second.payload = TelemetryPayload::RegistryPersistence(swarm_core::RegistryPersistenceEvent {
        process_name: "reg.exe".to_string(),
        registry_path: "HKCU\\Run".to_string(),
        value_name: Some("Updater".to_string()),
        value_data: Some("two".to_string()),
        access_type: "set".to_string(),
    });
    let first = normalize_telemetry_event(
        &first,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-registry",
    )
    .unwrap();
    let second = normalize_telemetry_event(
        &second,
        &clock(),
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer-registry",
    )
    .unwrap();
    assert_ne!(first.evidence_id, second.evidence_id);
    let first_serialized = serde_json::to_string(&first).unwrap();
    let second_serialized = serde_json::to_string(&second).unwrap();
    assert!(!first_serialized.contains("Updater"));
    assert!(!first_serialized.contains("one"));
    assert!(!second_serialized.contains("two"));
}

#[test]
fn runtime_construction_threads_registry_task_limit_into_scheduler() {
    let signer = key(65);
    let limits = GraphResourceLimits {
        max_tasks: 1,
        ..GraphResourceLimits::default()
    };
    let registry = EvidenceRegistry::with_key_and_limits(&signer, limits).unwrap();
    let mut runtime = HypothesisGraphRuntime::new(clock(), registry);
    runtime
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(1),
            swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
            1,
            swarm_core::hypothesis_graph::TaskId::new("task:runtime:one"),
        )
        .unwrap();
    let error = runtime
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(2),
            swarm_core::hypothesis_graph::TaskKind::AcquireEvidence,
            1,
            swarm_core::hypothesis_graph::TaskId::new("task:runtime:two"),
        )
        .expect_err("runtime scheduler must inherit the registry task ceiling");
    assert!(matches!(
        error,
        GraphAdmissionError::ResourceLimitExceeded { resource, limit }
            if resource == "scheduler.tasks" && limit == 1
    ));
}

#[test]
fn graph_record_signer_binds_edge_and_decision() {
    let signer = key(67);
    let admission = WitnessAdmission::from_key(&signer);
    let record_signer = KeypairGraphRecordSigner::with_admission(signer.clone(), &admission)
        .expect("signer key must be admitted before capability construction");
    let producer = AgentId::from_public_key_hex(&signer.public_key().to_hex());
    let edge = CausalEdge::new(
        &GraphNodeId::new("node:process"),
        &GraphNodeId::new("node:asset"),
        CausalRelation::Contacts,
        8_000,
        [],
        GraphProducerRole::Hunter,
        producer.clone(),
        GraphLogicalTime::new(1_700_000_000_000),
        EdgeState::Unresolved,
    )
    .unwrap();
    let first = record_signer.sign_edge(edge.clone(), "hunter:one").unwrap();
    let second = record_signer.sign_edge(edge, "hunter:two").unwrap();
    record_signer.verify_edge(&first).unwrap();
    record_signer.verify_edge(&second).unwrap();
    assert_ne!(
        first.witness.as_ref().unwrap().scoped_agent_id,
        second.witness.as_ref().unwrap().scoped_agent_id
    );
    assert_eq!(first.producer_identity, producer);
    assert!(
        KeypairGraphRecordSigner::new(key(68))
            .verify_edge(&first)
            .is_err()
    );
    assert!(KeypairGraphRecordSigner::with_admission(key(68), &admission).is_err());
    let mut tampered = first.clone();
    tampered.confidence_basis_points = 8_001;
    assert!(record_signer.verify_edge(&tampered).is_err());

    let decision = DecisionRecord::new(
        DecisionKind::Support,
        HypothesisId::new("hypothesis:signer"),
        [],
        GraphProducerRole::Hunter,
        producer,
        GraphLogicalTime::new(1_700_000_000_000),
        "typed evidence supports the candidate",
    )
    .unwrap();
    let decision = record_signer
        .sign_decision(decision, "hunter:decision")
        .unwrap();
    record_signer.verify_decision(&decision).unwrap();
    let mut tampered_decision = decision.clone();
    tampered_decision.rationale = "tampered decision rationale".to_string();
    assert!(record_signer.verify_decision(&tampered_decision).is_err());
    let mut scope_tampered_edge = first.clone();
    scope_tampered_edge
        .witness
        .as_mut()
        .expect("signed edge witness")
        .scoped_agent_id = "hunter:tampered".to_string();
    assert!(record_signer.verify_edge(&scope_tampered_edge).is_err());
    let mut role_tampered_decision = decision;
    role_tampered_decision
        .witness
        .as_mut()
        .expect("signed decision witness")
        .producer_role = GraphProducerRole::Challenger;
    assert!(
        record_signer
            .verify_decision(&role_tampered_decision)
            .is_err()
    );
}

#[test]
fn future_task_is_not_consumed_before_ready_time() {
    let task_id = TaskId::new("task:future-not-ready");
    let mut scheduler = DeterministicScheduler::new();
    scheduler
        .schedule_task(
            GraphLogicalTime::new(20),
            TaskKind::AcquireEvidence,
            500,
            task_id.clone(),
        )
        .unwrap();
    let before = json_bytes(&scheduler.ordered());

    assert!(
        scheduler
            .pop_ready(GraphLogicalTime::new(19))
            .unwrap()
            .is_none()
    );
    assert_eq!(json_bytes(&scheduler.ordered()), before);
    assert_eq!(scheduler.len(), 1);
    assert!(scheduler.contains(&task_id));
    assert_eq!(scheduler.tombstone_len(), 0);
    assert_eq!(scheduler.retained_len(), 1);
}

#[test]
fn future_task_survives_earlier_pop() {
    let future_id = TaskId::new("task:future-survives");
    let mut scheduler = DeterministicScheduler::new();
    scheduler
        .schedule_task(
            GraphLogicalTime::new(20),
            TaskKind::FalsifyHypothesis,
            1,
            future_id.clone(),
        )
        .unwrap();
    scheduler
        .schedule_task(
            GraphLogicalTime::new(10),
            TaskKind::AcquireEvidence,
            1,
            TaskId::new("task:ready-now"),
        )
        .unwrap();
    let before_future = json_bytes(
        &scheduler
            .ordered()
            .into_iter()
            .find(|key| key.task_id == future_id)
            .unwrap(),
    );

    let popped = scheduler
        .pop_ready(GraphLogicalTime::new(10))
        .unwrap()
        .unwrap();
    assert_eq!(popped.task_id, TaskId::new("task:ready-now"));
    let future = scheduler
        .ordered()
        .into_iter()
        .find(|key| key.task_id == future_id)
        .unwrap();
    assert_eq!(json_bytes(&future), before_future);
    assert!(scheduler.contains(&future_id));
    assert_eq!(scheduler.tombstone_len(), 1);
}

#[test]
fn scheduler_pop_is_logical_time_only() {
    let task_id = TaskId::new("task:logical-time-only");
    let mut scheduler = DeterministicScheduler::new();
    scheduler
        .schedule_task(
            GraphLogicalTime::new(30),
            TaskKind::AcquireEvidence,
            10,
            task_id.clone(),
        )
        .unwrap();
    let before = json_bytes(&scheduler.ordered());

    // The scheduler receives an explicit logical instant.  Host-clock
    // observations are intentionally absent from this API and cannot move
    // the task ahead of its declared ready time.
    for now in [GraphLogicalTime::new(0), GraphLogicalTime::new(29)] {
        assert!(scheduler.pop_ready(now).unwrap().is_none());
        assert_eq!(json_bytes(&scheduler.ordered()), before);
    }
    assert_eq!(
        scheduler
            .pop_ready(GraphLogicalTime::new(30))
            .unwrap()
            .unwrap()
            .task_id,
        task_id
    );
    assert_eq!(scheduler.len(), 0);
    assert_eq!(scheduler.tombstone_len(), 1);
}

#[test]
fn ambiguous_seed_retains_competing_hypotheses() {
    let seed = swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
        GraphId::new("graph:ambiguous"),
        vec![
            HypothesisId::new("hypothesis:credential"),
            HypothesisId::new("hypothesis:automation"),
        ],
        vec![swarm_core::hypothesis_graph::EvidenceId::new(
            "evidence:seed",
        )],
        GraphLogicalTime::new(10),
    )
    .unwrap();
    let hypotheses = swarm_runtime::hypothesis_graph::competing_hypotheses(
        &seed,
        &GraphResourceLimits::default(),
    )
    .unwrap();
    assert_eq!(hypotheses.len(), 2);
    assert!(hypotheses.values().all(|hypothesis| {
        hypothesis.status == swarm_core::hypothesis_graph::HypothesisStatus::Live
    }));
}

#[test]
fn normalized_seed_remains_unresolved() {
    let seed = swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
        GraphId::new("graph:neutral"),
        vec![
            HypothesisId::new("hypothesis:one"),
            HypothesisId::new("hypothesis:two"),
        ],
        vec![swarm_core::hypothesis_graph::EvidenceId::new(
            "evidence:neutral",
        )],
        GraphLogicalTime::new(10),
    )
    .unwrap();
    assert!(seed.assessments.iter().all(|assessment| {
        assessment.disposition == swarm_runtime::hypothesis_graph::HypothesisDisposition::Unresolved
    }));
}

struct ContainmentFixture {
    snapshot: GraphStoreSnapshot,
    hypothesis_id: HypothesisId,
    edge_id: swarm_core::hypothesis_graph::EdgeId,
    evidence_id: swarm_core::hypothesis_graph::EvidenceId,
    unrelated_evidence_id: swarm_core::hypothesis_graph::EvidenceId,
    node_ids: BTreeSet<GraphNodeId>,
    claim: CoreKillChainClaim,
}

fn containment_fixture() -> ContainmentFixture {
    let signer = key(29);
    let config = HypothesisGraphConfig::default();
    let producer = AgentId::from_public_key_hex(&signer.public_key().to_hex());
    let actor = GraphNode::Actor(ActorNode::new("actor:containment", "containment actor").unwrap());
    let event = GraphNode::Event(
        EventNode::new("process", "source:containment", GraphLogicalTime::new(1)).unwrap(),
    );
    let actor_id = actor.id().clone();
    let event_id = event.id().clone();
    let node_ids = BTreeSet::from([actor_id.clone(), event_id.clone()]);
    let mut graph =
        HypothesisGraph::new(GraphId::new("graph:containment"), config.resource_limits()).unwrap();
    graph.admit_node(actor).unwrap();
    graph.admit_node(event).unwrap();

    let evidence = EvidenceEnvelope::new(
        EvidenceSourceFamily::Process,
        "source:containment",
        SourceLineage::new("fixture", "containment:evidence").unwrap(),
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
    .unwrap()
    .sign_with(
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:containment",
    )
    .unwrap();
    let evidence_id = evidence.evidence_id.clone();
    graph.admit_evidence(evidence).unwrap();
    let unrelated_evidence = EvidenceEnvelope::new(
        EvidenceSourceFamily::Process,
        "source:containment-unrelated",
        SourceLineage::new("fixture", "containment:unrelated").unwrap(),
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
    .unwrap()
    .sign_with(
        &signer,
        GraphProducerRole::Normalizer,
        "normalizer:containment-unrelated",
    )
    .unwrap();
    let unrelated_evidence_id = unrelated_evidence.evidence_id.clone();
    graph.admit_evidence(unrelated_evidence).unwrap();

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
    .unwrap()
    .signed_with(&signer, "hunter:containment")
    .unwrap();
    let edge_id = edge.edge_id.clone();
    graph.admit_edge(edge).unwrap();

    let claim = CoreKillChainClaim::new(
        KillChainStage::Execution,
        node_ids.clone(),
        [edge_id.clone()],
        [evidence_id.clone()],
        [],
        "execution is supported",
        [evidence_id.clone()],
    )
    .unwrap();
    let hypothesis_id = HypothesisId::new("hypothesis:containment");
    let hypothesis = Hypothesis::new(
        hypothesis_id.clone(),
        ConfidenceDistribution::uniform_two(),
        [UncertaintyReason::InsufficientEvidence],
        [],
    )
    .unwrap()
    .with_claims([edge_id.clone()]);
    let store = MemoryHypothesisGraphStore::new_with_config(graph, signer, &config).unwrap();
    let initial = store.snapshot().unwrap();
    let state = GraphStoreState::with_reasoning_state(
        initial.state().clone(),
        ReasoningStateUpdate::migration_to_hypotheses(
            config.resource_limits(),
            GraphLogicalTime::new(1),
        )
        .with_hypotheses(BTreeMap::from([(hypothesis_id.clone(), hypothesis)]))
        .with_scheduler_budget(
            SchedulerBudget::new_with_config(&config, GraphLogicalTime::new(1)).unwrap(),
        ),
    )
    .unwrap();
    let snapshot = store.compare_and_swap(initial.revision(), state).unwrap();
    ContainmentFixture {
        snapshot,
        hypothesis_id,
        edge_id,
        evidence_id,
        unrelated_evidence_id,
        node_ids,
        claim,
    }
}

fn containment_option(target: GraphNodeId) -> swarm_core::hypothesis_graph::ContainmentOption {
    swarm_core::hypothesis_graph::ContainmentOption::new(
        swarm_core::hypothesis_graph::ContainmentOptionKind::IsolateAsset,
        [target],
        100,
        9_000,
        8_000,
        swarm_core::hypothesis_graph::ApprovalClass::Analyst,
        true,
    )
    .unwrap()
}

fn exact_kill_chain(
    fixture: &ContainmentFixture,
    claims: impl IntoIterator<Item = CoreKillChainClaim>,
) -> swarm_runtime::hypothesis_graph::kill_chain::KillChainReconstruction {
    swarm_runtime::hypothesis_graph::kill_chain::KillChainReconstruction::new_with_edge_support(
        claims,
        BTreeMap::from([(
            fixture.edge_id.clone(),
            BTreeSet::from([fixture.evidence_id.clone()]),
        )]),
        [],
    )
    .unwrap()
}

fn plan04_containment_input() -> (
    ContainmentFixture,
    swarm_runtime::hypothesis_graph::ContainmentPlanningInput,
) {
    let fixture = containment_fixture();
    let target = fixture.node_ids.first().unwrap().clone();
    let input = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id.clone()],
        vec![fixture.edge_id.clone()],
        vec![fixture.evidence_id.clone()],
        exact_kill_chain(&fixture, [fixture.claim.clone()]),
        vec![containment_option(target)],
        GraphLogicalTime::new(1),
    )
    .unwrap();
    (fixture, input)
}

#[test]
fn withheld_kill_chain_reports_missing_evidence() {
    let (fixture, _) = plan04_containment_input();
    let claim_id = fixture.claim.claim_id.clone();
    let reconstruction = swarm_runtime::hypothesis_graph::kill_chain::reconstruct_kill_chain(
        [fixture.claim.clone()],
        [fixture.evidence_id.clone()],
    )
    .unwrap();
    let retained = &reconstruction.claims[0];
    assert_eq!(retained.claim_id, claim_id);
    assert_eq!(retained.node_ids, fixture.claim.node_ids);
    assert!(retained.edge_ids.is_empty());
    assert!(retained.evidence_ids.is_empty());
    assert!(retained.narration_evidence_ids.is_empty());
    assert_eq!(reconstruction.missing_evidence[0].claim_id, claim_id);
    assert!(reconstruction.validate().is_ok());
    let suppressed = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id.clone()],
        vec![fixture.edge_id.clone()],
        vec![fixture.evidence_id.clone()],
        reconstruction.clone(),
        vec![containment_option(
            fixture.node_ids.first().unwrap().clone(),
        )],
        GraphLogicalTime::new(1),
    );
    assert!(
        suppressed.is_err(),
        "withheld support must suppress downstream options"
    );
    let mut tampered = reconstruction;
    tampered.missing_evidence[0].claim_id =
        swarm_core::hypothesis_graph::KillChainClaimId::new("kill-chain:unknown");
    assert!(tampered.validate().is_err());
}

#[test]
fn containment_rejects_omitted_withheld_support_with_unrelated_valid_evidence() {
    let (fixture, _) = plan04_containment_input();
    let reconstruction = swarm_runtime::hypothesis_graph::kill_chain::reconstruct_kill_chain(
        [fixture.claim.clone()],
        [fixture.evidence_id.clone()],
    )
    .unwrap();
    let result = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id],
        vec![fixture.edge_id],
        vec![fixture.unrelated_evidence_id],
        reconstruction,
        vec![containment_option(
            fixture.node_ids.first().unwrap().clone(),
        )],
        GraphLogicalTime::new(1),
    );
    assert!(
        result.is_err(),
        "a caller cannot hide missing support by omitting it and supplying unrelated valid evidence"
    );
}

#[test]
fn containment_plan_is_simulation_only() {
    let (_, input) = plan04_containment_input();
    let planner =
        swarm_runtime::hypothesis_graph::ContainmentPlanner::new(GraphResourceLimits::default())
            .unwrap();
    let simulation = planner.simulate_input(&input).unwrap();
    assert!(simulation.simulation_only);
    assert_eq!(simulation.graph_id, GraphId::new("graph:containment"));
    assert_eq!(simulation.options.len(), input.options().len());
    let source = &input.options()[0];
    let projected = &simulation.options[0];
    assert_eq!(projected.kind, source.kind);
    assert_eq!(projected.target_node_ids, source.target_node_ids);
    assert_eq!(
        projected.predicted_blast_radius_basis_points,
        source.predicted_blast_radius_basis_points
    );
    assert_eq!(
        projected.reversibility_basis_points,
        source.reversibility_basis_points
    );
    assert_eq!(
        projected.evidence_support_basis_points,
        source.evidence_support_basis_points
    );
    assert_eq!(projected.required_approval, source.required_approval);
    assert_eq!(projected.rollback_expected, source.rollback_expected);
    assert_eq!(projected.option_id, source.option_id);
}

#[test]
fn containment_rejects_exact_edge_support_mismatch() {
    let (fixture, _) = plan04_containment_input();
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
    .unwrap();
    let mismatched_chain =
        swarm_runtime::hypothesis_graph::kill_chain::KillChainReconstruction::new_with_edge_support(
            [mismatched_claim],
            BTreeMap::from([(
                fixture.edge_id.clone(),
                BTreeSet::from([fixture.unrelated_evidence_id.clone()]),
            )]),
            [],
        )
        .unwrap();
    let result = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id],
        vec![fixture.edge_id],
        vec![fixture.evidence_id, fixture.unrelated_evidence_id],
        mismatched_chain,
        vec![containment_option(
            fixture.node_ids.first().unwrap().clone(),
        )],
        GraphLogicalTime::new(1),
    );
    assert!(matches!(
        result,
        Err(GraphAdmissionError::InvalidTransition { reason }) if reason.contains("support differs")
    ));
}

#[test]
fn containment_rejects_synthetic_target_node() {
    let (fixture, _) = plan04_containment_input();
    let result = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id.clone()],
        vec![fixture.edge_id.clone()],
        vec![fixture.evidence_id.clone()],
        exact_kill_chain(&fixture, [fixture.claim.clone()]),
        vec![containment_option(GraphNodeId::new("node:synthetic"))],
        GraphLogicalTime::new(1),
    );
    assert!(matches!(
        result,
        Err(GraphAdmissionError::UnknownNode { .. })
    ));
}

#[test]
fn containment_rejects_duplicate_unknown_and_malformed_ids() {
    let (fixture, _) = plan04_containment_input();
    let valid_chain = || exact_kill_chain(&fixture, [fixture.claim.clone()]);
    let target = fixture.node_ids.first().unwrap().clone();
    let duplicate = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id.clone(), fixture.hypothesis_id.clone()],
        vec![fixture.edge_id.clone()],
        vec![fixture.evidence_id.clone()],
        valid_chain(),
        vec![containment_option(target.clone())],
        GraphLogicalTime::new(1),
    );
    assert!(matches!(
        duplicate,
        Err(GraphAdmissionError::InvalidField { .. })
    ));
    let malformed = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![HypothesisId::new("")],
        vec![fixture.edge_id.clone()],
        vec![fixture.evidence_id.clone()],
        valid_chain(),
        vec![containment_option(target.clone())],
        GraphLogicalTime::new(1),
    );
    assert!(matches!(
        malformed,
        Err(GraphAdmissionError::InvalidField { .. })
    ));
    let unknown_edge_id = swarm_core::hypothesis_graph::EdgeId::new("edge:synthetic");
    let unknown_edge_claim = CoreKillChainClaim::new(
        KillChainStage::Execution,
        fixture.claim.node_ids.clone(),
        [unknown_edge_id.clone()],
        [fixture.evidence_id.clone()],
        [],
        "execution is supported",
        [fixture.evidence_id.clone()],
    )
    .unwrap();
    let unknown_edge = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id.clone()],
        vec![unknown_edge_id.clone()],
        vec![fixture.evidence_id.clone()],
        swarm_runtime::hypothesis_graph::kill_chain::KillChainReconstruction::new_with_edge_support(
            [unknown_edge_claim],
            BTreeMap::from([(
                unknown_edge_id.clone(),
                BTreeSet::from([fixture.evidence_id.clone()]),
            )]),
            [],
        )
        .unwrap(),
        vec![containment_option(target.clone())],
        GraphLogicalTime::new(1),
    );
    assert!(matches!(
        unknown_edge,
        Err(GraphAdmissionError::InvalidField { .. })
    ));
    let unknown_evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:synthetic");
    let unknown_evidence_claim = CoreKillChainClaim::new(
        KillChainStage::Execution,
        fixture.claim.node_ids.clone(),
        [fixture.edge_id.clone()],
        [unknown_evidence_id.clone()],
        [],
        "execution is supported",
        [unknown_evidence_id.clone()],
    )
    .unwrap();
    let unknown_evidence = swarm_runtime::hypothesis_graph::ContainmentPlanningInput::from_snapshot(
        &fixture.snapshot,
        vec![fixture.hypothesis_id.clone()],
        vec![fixture.edge_id.clone()],
        vec![unknown_evidence_id.clone()],
        swarm_runtime::hypothesis_graph::kill_chain::KillChainReconstruction::new_with_edge_support(
            [unknown_evidence_claim],
            BTreeMap::from([(
                fixture.edge_id.clone(),
                BTreeSet::from([unknown_evidence_id.clone()]),
            )]),
            [],
        )
        .unwrap(),
        vec![containment_option(target)],
        GraphLogicalTime::new(1),
    );
    assert!(matches!(
        unknown_evidence,
        Err(GraphAdmissionError::UnknownEvidence)
    ));
}

struct TerminalTaskFixture {
    claimant_key: Keypair,
    store: MemoryHypothesisGraphStore,
    ledger: HypothesisTaskLedger,
    request: TaskClaimRequest,
    evidence: EvidenceEnvelope,
}

fn terminal_task_fixture() -> TerminalTaskFixture {
    let claimant_key = key(91);
    let evidence = normalize_telemetry_event(
        &process_event("terminal:evidence", "curl https://terminal.example"),
        &clock(),
        &claimant_key,
        GraphProducerRole::Normalizer,
        "normalizer:terminal",
    )
    .unwrap();
    let graph_id = GraphId::new("graph:terminal-cas");
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 100,
        max_claims_per_tick: 10,
        ..HypothesisGraphConfig::default()
    };
    let limits = config.resource_limits();
    let mut graph = HypothesisGraph::new(graph_id.clone(), limits).unwrap();
    graph.admit_evidence(evidence.clone()).unwrap();
    let store = MemoryHypothesisGraphStore::new_with_config(graph, key(92), &config).unwrap();
    let target = TaskTarget::Evidence {
        evidence_id: evidence.evidence_id.clone(),
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
    let initial = store.snapshot().unwrap();
    ledger
        .create_task(&store, initial.revision(), descriptor, request.clone())
        .unwrap();
    TerminalTaskFixture {
        claimant_key,
        store,
        ledger,
        request,
        evidence,
    }
}

fn terminal_envelope(
    fixture: &TerminalTaskFixture,
    claim: &swarm_runtime::hypothesis_graph::TaskClaim,
) -> TaskTerminalEnvelope {
    let capability = TaskCapabilityProof::signed_with(
        claim.task_id.clone(),
        claim.claimant.clone(),
        GraphProducerRole::Hunter,
        TaskKind::AcquireEvidence,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    assert_eq!(capability, claim.capability_proof);
    TaskTerminalEnvelope::new(
        claim.task_id.clone(),
        claim.idempotency_key.clone(),
        claim.lease_id.clone(),
        claim.fencing_token,
        TaskCompletion::new(
            TaskCompletionKind::EvidenceAdded,
            claim.claimant.clone(),
            GraphLogicalTime::new(200),
            [fixture.evidence.evidence_id.clone()],
            "00".repeat(32),
        )
        .unwrap(),
        None,
        claim.claimant.clone(),
        claim.capability_proof.clone(),
    )
    .unwrap()
    .signed_with(&fixture.claimant_key, "hunter:terminal")
    .unwrap()
}

fn terminal_memory(
    fixture: &TerminalTaskFixture,
) -> (StrategyMemory, StrategyMemoryExpiryEnvelope) {
    let graph_id = GraphId::new("graph:terminal-cas");
    let hypothesis_id = HypothesisId::new("hypothesis:memory");
    let producer = AgentId::from_public_key_hex(&fixture.claimant_key.public_key().to_hex());
    let provenance = MemoryProvenance::new(producer, [fixture.evidence.evidence_id.clone()])
        .signed_with(
            &fixture.claimant_key,
            GraphProducerRole::Hunter,
            "hunter:memory-provenance",
        )
        .unwrap();
    let memory = StrategyMemory::new(
        graph_id,
        hypothesis_id,
        HypothesisDelta::new([], [], []),
        [EvidenceUtility::new(
            fixture.evidence.evidence_id.clone(),
            5000,
        )],
        [],
        MemoryOutcome::Inconclusive,
        provenance,
    )
    .unwrap()
    .signed_with(
        &fixture.claimant_key,
        GraphProducerRole::Hunter,
        "hunter:memory",
    )
    .unwrap();
    let config = HypothesisGraphConfig::default();
    let expiry = StrategyMemoryExpiryEnvelope::new_with_config(
        &memory,
        GraphLogicalTime::new(200),
        10,
        &config,
        &fixture.claimant_key,
    )
    .unwrap();
    (memory, expiry)
}

#[test]
fn terminal_publication_is_atomic() {
    let mut fixture = terminal_task_fixture();
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    let claim = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap();
    let before = fixture.store.snapshot().unwrap();
    let after = fixture
        .ledger
        .complete_task(
            &fixture.store,
            before.revision(),
            &claim,
            terminal_envelope(&fixture, &claim),
            vec![fixture.evidence.clone()],
            None,
            None,
            None,
        )
        .unwrap();
    let task = after.state().task(claim.task_id.as_str()).unwrap();
    assert_eq!(
        task.task.state,
        swarm_core::hypothesis_graph::TaskState::Completed
    );
    assert_eq!(after.state().graph.evidence.len(), 1);
    assert_eq!(after.terminal_outbox().len(), 1);
    assert_eq!(
        after.terminal_outbox()[&claim.task_id].evidence,
        vec![fixture.evidence]
    );
}

#[test]
fn production_complete_task_enforces_signed_lineage() {
    let mut fixture = terminal_task_fixture();
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    let claim = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap();
    let before = fixture.store.snapshot().unwrap();
    let before_bytes = before.canonical_bytes().unwrap();
    let mut unsigned = terminal_envelope(&fixture, &claim);
    unsigned.terminal_witness = None;
    assert!(
        fixture
            .ledger
            .complete_task(
                &fixture.store,
                before.revision(),
                &claim,
                unsigned,
                vec![fixture.evidence.clone()],
                None,
                None,
                None,
            )
            .is_err()
    );
    assert_eq!(
        fixture.store.snapshot().unwrap().canonical_bytes().unwrap(),
        before_bytes
    );
}

#[test]
fn coordinator_uses_config_bound_budget_per_logical_tick() {
    let config = HypothesisGraphConfig {
        enabled: false,
        max_work_units_per_tick: 3,
        max_claims_per_tick: 1,
        ..HypothesisGraphConfig::default()
    };
    let tick = GraphLogicalTime::new(500);
    let graph_id = GraphId::new("graph:durable-budget");
    let coordinator_key = key(98);
    let producer = AgentId::from_public_key_hex(&coordinator_key.public_key().to_hex());
    let mut graph = HypothesisGraph::new(graph_id.clone(), config.resource_limits()).unwrap();
    let actor = ActorNode::new("actor:budget", "budget actor").unwrap();
    let asset = swarm_core::hypothesis_graph::AssetNode::new("asset:budget", "host").unwrap();
    let actor_id = actor.node_id.clone();
    let asset_id = asset.node_id.clone();
    graph.admit_node(GraphNode::Actor(actor)).unwrap();
    graph.admit_node(GraphNode::Asset(asset)).unwrap();
    let edge = CausalEdge::new(
        &actor_id,
        &asset_id,
        CausalRelation::Contacts,
        8_000,
        [],
        GraphProducerRole::Hunter,
        producer,
        tick,
        EdgeState::Unresolved,
    )
    .unwrap()
    .signed_with(&coordinator_key, "hunter:budget")
    .unwrap();
    graph.admit_edge(edge).unwrap();
    let store = MemoryHypothesisGraphStore::new_with_config(graph, key(99), &config).unwrap();
    let evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:budget");
    let seed = swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
        graph_id.clone(),
        vec![
            HypothesisId::new("hypothesis:budget-one"),
            HypothesisId::new("hypothesis:budget-two"),
        ],
        vec![evidence_id.clone()],
        tick,
    )
    .unwrap();
    let scope = EvidenceScope::new([], [evidence_id], []).unwrap();
    let signer_key = key(100);
    let signer = KeypairGraphRecordSigner::with_admission(
        signer_key.clone(),
        &WitnessAdmission::from_key(&signer_key),
    )
    .unwrap();
    let claimant = AgentId::from_public_key_hex(&signer_key.public_key().to_hex());
    let mut coordinator =
        DurableHypothesisCoordinator::new_with_store(&config, tick, &store, signer).unwrap();

    let initial = store.snapshot().unwrap();
    assert_eq!(coordinator.ledger().scheduler_budget().max_work_units, 3);
    assert_eq!(coordinator.ledger().scheduler_budget().max_claims, 1);
    let first = coordinator
        .coordinate_seed(
            &store,
            initial.revision(),
            &seed,
            claimant.clone(),
            scope.clone(),
        )
        .unwrap();
    assert_eq!(first.task_ids.len(), 1);
    assert_eq!(first.snapshot.state().tasks.len(), 1);
    let persisted_budget = first.snapshot.scheduler_budget().unwrap().clone();
    assert_eq!(persisted_budget.current_tick(), tick);
    assert_eq!(persisted_budget.work_units_used(), 1);
    assert_eq!(persisted_budget.claims_used(), 0);
    assert_eq!(coordinator.ledger().scheduler_budget(), &persisted_budget);

    let claim_entry = first
        .snapshot
        .state()
        .tasks
        .values()
        .find(|entry| entry.task.request.kind == TaskKind::AcquireEvidence)
        .unwrap();
    let claim_request = claim_entry.task.request.clone();
    let capability = TaskCapabilityProof::signed_with(
        claim_request.task_id.clone(),
        claim_request.claimant.clone(),
        claim_request.role,
        claim_request.kind,
        claim_request.canonical_digest().unwrap(),
        &signer_key,
        "hunter:budget-claim",
    )
    .unwrap();
    let claimed = coordinator
        .ledger_mut()
        .claim_task(
            &store,
            claim_request.clone(),
            tick,
            1_000,
            capability.clone(),
        )
        .unwrap();
    let claimed_snapshot = store.snapshot().unwrap();
    let claimed_budget = claimed_snapshot.scheduler_budget().unwrap().clone();
    assert_eq!(claimed.task_id, claim_request.task_id);
    assert_eq!(claimed_budget.work_units_used(), 1);
    assert_eq!(claimed_budget.claims_used(), 1);
    assert_eq!(coordinator.ledger().scheduler_budget(), &claimed_budget);

    let before_claim_retry = claimed_snapshot.canonical_bytes().unwrap();
    let retry_claim = coordinator
        .ledger_mut()
        .claim_task(&store, claim_request, tick, 1_000, capability)
        .unwrap();
    assert_eq!(retry_claim, claimed);
    assert_eq!(
        store.snapshot().unwrap().canonical_bytes().unwrap(),
        before_claim_retry
    );
    assert_eq!(coordinator.ledger().scheduler_budget(), &claimed_budget);

    let before_retry = claimed_snapshot.canonical_bytes().unwrap();
    let retried = coordinator
        .coordinate_seed(&store, claimed_snapshot.revision(), &seed, claimant, scope)
        .unwrap();
    assert_eq!(retried.snapshot.revision(), claimed_snapshot.revision());
    assert_eq!(retried.snapshot.canonical_bytes().unwrap(), before_retry);
    assert_eq!(coordinator.ledger().scheduler_budget(), &claimed_budget);

    let restarted_key = key(101);
    let restarted_signer = KeypairGraphRecordSigner::with_admission(
        restarted_key.clone(),
        &WitnessAdmission::from_key(&restarted_key),
    )
    .unwrap();
    let mut restarted =
        DurableHypothesisCoordinator::new_with_store(&config, tick, &store, restarted_signer)
            .unwrap();
    assert_eq!(restarted.ledger().scheduler_budget(), &claimed_budget);

    let alternate_seed =
        swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
            graph_id.clone(),
            vec![
                HypothesisId::new("hypothesis:alternate-one"),
                HypothesisId::new("hypothesis:alternate-two"),
            ],
            vec![swarm_core::hypothesis_graph::EvidenceId::new(
                "evidence:alternate",
            )],
            tick,
        )
        .unwrap();
    let after_alternate = restarted
        .coordinate_seed(
            &store,
            store.snapshot().unwrap().revision(),
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
        .unwrap();
    assert_eq!(
        after_alternate
            .snapshot
            .scheduler_budget()
            .unwrap()
            .work_units_used(),
        2
    );

    let final_admitted_seed =
        swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
            graph_id.clone(),
            vec![
                HypothesisId::new("hypothesis:final-admitted-one"),
                HypothesisId::new("hypothesis:final-admitted-two"),
            ],
            vec![swarm_core::hypothesis_graph::EvidenceId::new(
                "evidence:final-admitted",
            )],
            tick,
        )
        .unwrap();
    let fully_consumed = restarted
        .coordinate_seed(
            &store,
            after_alternate.snapshot.revision(),
            &final_admitted_seed,
            AgentId::from_public_key_hex(&restarted_key.public_key().to_hex()),
            EvidenceScope::new(
                [],
                [swarm_core::hypothesis_graph::EvidenceId::new(
                    "evidence:final-admitted",
                )],
                [],
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        fully_consumed
            .snapshot
            .scheduler_budget()
            .unwrap()
            .work_units_used(),
        3
    );

    let exhausted_seed =
        swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
            graph_id.clone(),
            vec![
                HypothesisId::new("hypothesis:exhausted-one"),
                HypothesisId::new("hypothesis:exhausted-two"),
            ],
            vec![swarm_core::hypothesis_graph::EvidenceId::new(
                "evidence:exhausted",
            )],
            tick,
        )
        .unwrap();
    let before_exhausted = fully_consumed.snapshot;
    let before_exhausted_bytes = before_exhausted.canonical_bytes().unwrap();
    let budget_before_exhausted = restarted.ledger().scheduler_budget().clone();
    assert!(
        restarted
            .coordinate_seed(
                &store,
                before_exhausted.revision(),
                &exhausted_seed,
                AgentId::from_public_key_hex(&restarted_key.public_key().to_hex()),
                EvidenceScope::new(
                    [],
                    [swarm_core::hypothesis_graph::EvidenceId::new(
                        "evidence:exhausted",
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

    let next_tick_seed =
        swarm_runtime::hypothesis_graph::HypothesisSeedInput::from_normalized_evidence(
            graph_id,
            vec![
                HypothesisId::new("hypothesis:next-tick-one"),
                HypothesisId::new("hypothesis:next-tick-two"),
            ],
            vec![swarm_core::hypothesis_graph::EvidenceId::new(
                "evidence:next-tick",
            )],
            GraphLogicalTime::new(501),
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
    let reset_budget = next_tick.snapshot.scheduler_budget().unwrap();
    assert_eq!(reset_budget.current_tick(), GraphLogicalTime::new(501));
    assert_eq!(reset_budget.work_units_used(), 1);
}

#[test]
fn terminal_memory_is_not_visible_before_outbox_cas() {
    let mut fixture = terminal_task_fixture();
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    let claim = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap();
    let stale = fixture.store.snapshot().unwrap();
    let current = fixture.store.snapshot().unwrap();
    let (memory, expiry) = terminal_memory(&fixture);
    assert!(
        fixture
            .ledger
            .complete_task(
                &fixture.store,
                &GraphStoreRevision::new(
                    stale.revision().generation.saturating_sub(1),
                    stale.revision().digest.clone(),
                ),
                &claim,
                terminal_envelope(&fixture, &claim),
                vec![fixture.evidence.clone()],
                None,
                Some(memory),
                Some(expiry),
            )
            .is_err()
    );
    let after = fixture.store.snapshot().unwrap();
    assert_eq!(after, current);
    assert!(after.terminal_outbox().is_empty());
}

#[test]
fn dangling_terminal_memory_is_rejected_before_cas() {
    let mut fixture = terminal_task_fixture();
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    let claim = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap();
    let before = fixture.store.snapshot().unwrap();
    let before_bytes = before.canonical_bytes().unwrap();
    let (memory, expiry) = terminal_memory(&fixture);
    let error = fixture
        .ledger
        .complete_task(
            &fixture.store,
            before.revision(),
            &claim,
            terminal_envelope(&fixture, &claim),
            vec![fixture.evidence.clone()],
            None,
            Some(memory),
            Some(expiry),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason })
            if reason.contains("unknown hypothesis")
    ));
    assert_eq!(
        fixture.store.snapshot().unwrap().canonical_bytes().unwrap(),
        before_bytes
    );
}

#[test]
fn stale_terminal_publishes_nothing() {
    let mut fixture = terminal_task_fixture();
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    let claim = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap();
    let current = fixture.store.snapshot().unwrap();
    let stale = GraphStoreRevision::new(
        current.revision().generation.saturating_sub(1),
        "00".repeat(32),
    );
    assert!(
        fixture
            .ledger
            .complete_task(
                &fixture.store,
                &stale,
                &claim,
                terminal_envelope(&fixture, &claim),
                vec![fixture.evidence.clone()],
                None,
                None,
                None,
            )
            .is_err()
    );
    assert_eq!(fixture.store.snapshot().unwrap(), current);
}

#[test]
fn claimant_key_and_completion_kind_are_checked() {
    let mut fixture = terminal_task_fixture();
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "hunter:terminal",
    )
    .unwrap();
    let claim = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap();
    let before = fixture.store.snapshot().unwrap();
    let attacker_key = key(97);
    let attacker = AgentId::from_public_key_hex(&attacker_key.public_key().to_hex());
    let attacker_capability = TaskCapabilityProof::signed_with(
        claim.task_id.clone(),
        attacker.clone(),
        GraphProducerRole::Hunter,
        TaskKind::AcquireEvidence,
        fixture.request.canonical_digest().unwrap(),
        &attacker_key,
        "attacker:terminal",
    )
    .unwrap();
    let wrong_key = TaskTerminalEnvelope::new(
        claim.task_id.clone(),
        claim.idempotency_key.clone(),
        claim.lease_id.clone(),
        claim.fencing_token,
        TaskCompletion::new(
            TaskCompletionKind::EvidenceAdded,
            attacker.clone(),
            GraphLogicalTime::new(200),
            [fixture.evidence.evidence_id.clone()],
            "00".repeat(32),
        )
        .unwrap(),
        None,
        attacker,
        attacker_capability,
    )
    .unwrap()
    .signed_with(&attacker_key, "attacker:terminal")
    .unwrap();
    assert!(
        fixture
            .ledger
            .complete_task(
                &fixture.store,
                before.revision(),
                &claim,
                wrong_key,
                vec![fixture.evidence.clone()],
                None,
                None,
                None,
            )
            .is_err()
    );
    let mut wrong_kind = terminal_envelope(&fixture, &claim);
    wrong_kind.completion.kind = TaskCompletionKind::EdgeChallenged;
    assert!(
        fixture
            .ledger
            .complete_task(
                &fixture.store,
                before.revision(),
                &claim,
                wrong_kind,
                vec![fixture.evidence.clone()],
                None,
                None,
                None,
            )
            .is_err()
    );
    assert_eq!(fixture.store.snapshot().unwrap(), before);
}

#[test]
fn logical_task_descriptor_is_persisted_and_verified() {
    let fixture = terminal_task_fixture();
    let before = fixture.store.snapshot().unwrap();
    let descriptor = before
        .logical_task_descriptors()
        .get(&fixture.request.task_id)
        .unwrap();
    assert_eq!(descriptor.task_id, fixture.request.task_id);
    assert_eq!(descriptor.derive_task_id().unwrap(), descriptor.task_id);
    let mut tampered = before.state().clone();
    tampered
        .logical_task_descriptors
        .get_mut(&fixture.request.task_id)
        .unwrap()
        .seed_digest = "11".repeat(32);
    assert!(
        fixture
            .store
            .compare_and_swap(before.revision(), tampered)
            .is_err()
    );
    assert_eq!(fixture.store.snapshot().unwrap(), before);
}

#[test]
fn same_logical_descriptor_is_idempotent() {
    let mut fixture = terminal_task_fixture();
    let before = fixture.store.snapshot().unwrap();
    let descriptor = LogicalTaskDescriptor::new(
        GraphId::new("graph:terminal-cas"),
        fixture.request.target.clone(),
        fixture.request.kind,
        "00".repeat(32),
    )
    .unwrap();
    let retried = fixture
        .ledger
        .create_task(
            &fixture.store,
            before.revision(),
            descriptor,
            fixture.request.clone(),
        )
        .unwrap();
    assert_eq!(retried.revision(), before.revision());
    assert_eq!(fixture.store.snapshot().unwrap(), before);
}

#[test]
fn different_seed_creates_distinct_task() {
    let mut fixture = terminal_task_fixture();
    let before = fixture.store.snapshot().unwrap();
    let second = LogicalTaskDescriptor::new(
        GraphId::new("graph:terminal-cas"),
        fixture.request.target.clone(),
        fixture.request.kind,
        "11".repeat(32),
    )
    .unwrap();
    assert_ne!(second.task_id, fixture.request.task_id);
    let second_request = TaskClaimRequest::new(
        second.task_id.clone(),
        fixture.request.kind,
        fixture.request.target.clone(),
        fixture.request.role,
        fixture.request.claimant.clone(),
        fixture.request.evidence_scope.clone(),
        fixture.request.requested_at,
    )
    .unwrap();
    fixture
        .ledger
        .create_task(&fixture.store, before.revision(), second, second_request)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .snapshot()
            .unwrap()
            .logical_task_descriptors()
            .len(),
        2
    );
}

#[test]
fn logical_task_id_is_not_claimant_idempotency() {
    let fixture = terminal_task_fixture();
    let descriptor = fixture.store.snapshot().unwrap().logical_task_descriptors()
        [&fixture.request.task_id]
        .clone();
    assert_ne!(
        descriptor.task_id.as_str(),
        fixture.request.idempotency_key.as_str()
    );
    assert_ne!(
        descriptor.seed_digest,
        fixture.request.idempotency_key.as_str()
    );
}

struct DecisionTaskFixture {
    claimant_key: Keypair,
    store: MemoryHypothesisGraphStore,
    ledger: HypothesisTaskLedger,
    request: TaskClaimRequest,
    evidence: EvidenceEnvelope,
    target: TaskTarget,
    hypothesis_id: HypothesisId,
    edge_id: swarm_core::hypothesis_graph::EdgeId,
}

fn decision_task_fixture(kind: TaskKind, role: GraphProducerRole) -> DecisionTaskFixture {
    let claimant_key = key(95);
    let claimant = AgentId::from_public_key_hex(&claimant_key.public_key().to_hex());
    let evidence = normalize_telemetry_event(
        &process_event("decision:evidence", "curl https://decision.example"),
        &clock(),
        &claimant_key,
        GraphProducerRole::Normalizer,
        "normalizer:decision",
    )
    .unwrap();
    let graph_id = GraphId::new("graph:decision-cas");
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 100,
        max_claims_per_tick: 10,
        ..HypothesisGraphConfig::default()
    };
    let mut graph = HypothesisGraph::new(graph_id.clone(), config.resource_limits()).unwrap();
    let actor = GraphNode::Actor(ActorNode::new("actor:decision", "decision-actor").unwrap());
    let event = GraphNode::Event(
        EventNode::new("process", "source:decision", evidence.clock.observed_at).unwrap(),
    );
    let actor_id = actor.id().clone();
    let event_id = event.id().clone();
    graph.admit_node(actor).unwrap();
    graph.admit_node(event).unwrap();
    graph.admit_evidence(evidence.clone()).unwrap();
    let edge = CausalEdge::new(
        &actor_id,
        &event_id,
        CausalRelation::ObservedIn,
        7_500,
        [evidence.evidence_id.clone()],
        GraphProducerRole::Hunter,
        claimant.clone(),
        evidence.clock.observed_at,
        EdgeState::Proposed,
    )
    .unwrap()
    .signed_with(&claimant_key, "hunter:decision-edge")
    .unwrap();
    let edge_id = edge.edge_id.clone();
    graph.admit_edge(edge).unwrap();

    let hypothesis_id = HypothesisId::new("hypothesis:decision");
    let target = match kind {
        TaskKind::ChallengeEdge => TaskTarget::Edge {
            edge_id: edge_id.clone(),
        },
        TaskKind::FalsifyHypothesis => TaskTarget::Hypothesis {
            hypothesis_id: hypothesis_id.clone(),
        },
        TaskKind::AcquireEvidence => panic!("decision fixture requires a decision task"),
    };
    let descriptor =
        LogicalTaskDescriptor::new(graph_id, target.clone(), kind, "22".repeat(32)).unwrap();
    let request = TaskClaimRequest::new(
        descriptor.task_id.clone(),
        kind,
        target.clone(),
        role,
        claimant,
        EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [evidence.evidence_id.clone()],
            [],
        )
        .unwrap(),
        GraphLogicalTime::new(100),
    )
    .unwrap();
    let store = MemoryHypothesisGraphStore::new_with_config(graph, key(96), &config).unwrap();
    let mut ledger =
        HypothesisTaskLedger::from_config(&config, GraphLogicalTime::new(100)).unwrap();
    let hypothesis = Hypothesis::new(
        hypothesis_id.clone(),
        ConfidenceDistribution::uniform_two(),
        [],
        [],
    )
    .unwrap()
    .with_claims([edge_id.clone()]);
    let unrelated_hypothesis_id = HypothesisId::new("hypothesis:unrelated-decision");
    let unrelated_hypothesis = Hypothesis::new(
        unrelated_hypothesis_id.clone(),
        ConfidenceDistribution::uniform_two(),
        [],
        [],
    )
    .unwrap();
    let initial = store.snapshot().unwrap();
    let reasoning_state = GraphStoreState::with_reasoning_state(
        initial.state().clone(),
        ReasoningStateUpdate::migration_to_hypotheses(
            config.resource_limits(),
            GraphLogicalTime::new(100),
        )
        .with_hypotheses(BTreeMap::from([
            (hypothesis_id.clone(), hypothesis),
            (unrelated_hypothesis_id, unrelated_hypothesis),
        ]))
        .with_scheduler_budget(
            SchedulerBudget::new_with_config(&config, GraphLogicalTime::new(100)).unwrap(),
        ),
    )
    .unwrap();
    let reasoning_snapshot = store
        .compare_and_swap(initial.revision(), reasoning_state)
        .unwrap();
    ledger
        .create_task(
            &store,
            reasoning_snapshot.revision(),
            descriptor,
            request.clone(),
        )
        .unwrap();
    DecisionTaskFixture {
        claimant_key,
        store,
        ledger,
        request,
        evidence,
        target,
        hypothesis_id,
        edge_id,
    }
}

fn claim_decision_task(
    fixture: &mut DecisionTaskFixture,
) -> swarm_runtime::hypothesis_graph::TaskClaim {
    let proof = TaskCapabilityProof::signed_with(
        fixture.request.task_id.clone(),
        fixture.request.claimant.clone(),
        fixture.request.role,
        fixture.request.kind,
        fixture.request.canonical_digest().unwrap(),
        &fixture.claimant_key,
        "decision:claimant",
    )
    .unwrap();
    fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(100),
            1_000,
            proof,
        )
        .unwrap()
}

fn decision_terminal(
    fixture: &DecisionTaskFixture,
    claim: &swarm_runtime::hypothesis_graph::TaskClaim,
) -> (TaskTerminalEnvelope, DecisionRecord) {
    let (kind, completion_kind) = match fixture.request.kind {
        TaskKind::ChallengeEdge => (DecisionKind::Challenge, TaskCompletionKind::EdgeChallenged),
        TaskKind::FalsifyHypothesis => (
            DecisionKind::Falsify,
            TaskCompletionKind::HypothesisFalsified,
        ),
        TaskKind::AcquireEvidence => panic!("decision fixture requires a decision task"),
    };
    let decision = DecisionRecord::new(
        kind,
        fixture.hypothesis_id.clone(),
        [fixture.evidence.evidence_id.clone()],
        fixture.request.role,
        fixture.request.claimant.clone(),
        GraphLogicalTime::new(200),
        "explicit decision evidence retains lineage",
    )
    .unwrap()
    .signed_with(&fixture.claimant_key, "decision:producer")
    .unwrap();
    let link = TaskDecisionLink::new(
        claim.task_id.clone(),
        fixture.target.clone(),
        [fixture.evidence.evidence_id.clone()],
        Some(decision.decision_id.clone()),
    )
    .unwrap();
    let envelope = TaskTerminalEnvelope::new(
        claim.task_id.clone(),
        claim.idempotency_key.clone(),
        claim.lease_id.clone(),
        claim.fencing_token,
        TaskCompletion::new(
            completion_kind,
            claim.claimant.clone(),
            GraphLogicalTime::new(200),
            [fixture.evidence.evidence_id.clone()],
            "00".repeat(32),
        )
        .unwrap(),
        Some(link),
        claim.claimant.clone(),
        claim.capability_proof.clone(),
    )
    .unwrap()
    .signed_with(&fixture.claimant_key, "decision:terminal")
    .unwrap();
    (envelope, decision)
}

fn decision_terminal_with(
    fixture: &DecisionTaskFixture,
    claim: &swarm_runtime::hypothesis_graph::TaskClaim,
    decision_kind: DecisionKind,
    decision_role: GraphProducerRole,
    decided_at: GraphLogicalTime,
) -> (TaskTerminalEnvelope, DecisionRecord) {
    let completion_kind = match fixture.request.kind {
        TaskKind::ChallengeEdge => TaskCompletionKind::EdgeChallenged,
        TaskKind::FalsifyHypothesis => TaskCompletionKind::HypothesisFalsified,
        TaskKind::AcquireEvidence => panic!("decision fixture requires a decision task"),
    };
    let decision = DecisionRecord::new(
        decision_kind,
        fixture.hypothesis_id.clone(),
        [fixture.evidence.evidence_id.clone()],
        decision_role,
        fixture.request.claimant.clone(),
        decided_at,
        "explicit decision evidence retains lineage",
    )
    .unwrap()
    .signed_with(&fixture.claimant_key, "decision:producer")
    .unwrap();
    let link = TaskDecisionLink::new(
        claim.task_id.clone(),
        fixture.target.clone(),
        [fixture.evidence.evidence_id.clone()],
        Some(decision.decision_id.clone()),
    )
    .unwrap();
    let envelope = TaskTerminalEnvelope::new(
        claim.task_id.clone(),
        claim.idempotency_key.clone(),
        claim.lease_id.clone(),
        claim.fencing_token,
        TaskCompletion::new(
            completion_kind,
            claim.claimant.clone(),
            GraphLogicalTime::new(200),
            [fixture.evidence.evidence_id.clone()],
            "00".repeat(32),
        )
        .unwrap(),
        Some(link),
        claim.claimant.clone(),
        claim.capability_proof.clone(),
    )
    .unwrap()
    .signed_with(&fixture.claimant_key, "decision:terminal")
    .unwrap();
    (envelope, decision)
}

#[test]
fn terminal_decision_kind_and_time_fail_closed_before_cas() {
    let mut wrong_kind_fixture =
        decision_task_fixture(TaskKind::FalsifyHypothesis, GraphProducerRole::Falsifier);
    let wrong_kind_claim = claim_decision_task(&mut wrong_kind_fixture);
    let before_wrong_kind = wrong_kind_fixture.store.snapshot().unwrap();
    let before_wrong_kind_bytes = before_wrong_kind.canonical_bytes().unwrap();
    let (wrong_kind_envelope, wrong_kind_decision) = decision_terminal_with(
        &wrong_kind_fixture,
        &wrong_kind_claim,
        DecisionKind::Support,
        GraphProducerRole::Hunter,
        GraphLogicalTime::new(150),
    );
    assert!(matches!(
        wrong_kind_fixture.ledger.complete_task(
            &wrong_kind_fixture.store,
            before_wrong_kind.revision(),
            &wrong_kind_claim,
            wrong_kind_envelope,
            vec![wrong_kind_fixture.evidence.clone()],
            Some(wrong_kind_decision),
            None,
            None,
        ),
        Err(GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason }))
            if reason.contains("decision kind")
    ));
    assert_eq!(
        wrong_kind_fixture
            .store
            .snapshot()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        before_wrong_kind_bytes
    );

    let mut wrong_challenge_fixture =
        decision_task_fixture(TaskKind::ChallengeEdge, GraphProducerRole::Challenger);
    let wrong_challenge_claim = claim_decision_task(&mut wrong_challenge_fixture);
    let before_wrong_challenge = wrong_challenge_fixture.store.snapshot().unwrap();
    let before_wrong_challenge_bytes = before_wrong_challenge.canonical_bytes().unwrap();
    let (wrong_challenge_envelope, wrong_challenge_decision) = decision_terminal_with(
        &wrong_challenge_fixture,
        &wrong_challenge_claim,
        DecisionKind::Falsify,
        GraphProducerRole::Falsifier,
        GraphLogicalTime::new(150),
    );
    assert!(matches!(
        wrong_challenge_fixture.ledger.complete_task(
            &wrong_challenge_fixture.store,
            before_wrong_challenge.revision(),
            &wrong_challenge_claim,
            wrong_challenge_envelope,
            vec![wrong_challenge_fixture.evidence.clone()],
            Some(wrong_challenge_decision),
            None,
            None,
        ),
        Err(GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason }))
            if reason.contains("decision kind")
    ));
    assert_eq!(
        wrong_challenge_fixture
            .store
            .snapshot()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        before_wrong_challenge_bytes
    );

    let mut backdated_fixture =
        decision_task_fixture(TaskKind::FalsifyHypothesis, GraphProducerRole::Falsifier);
    let backdated_claim = claim_decision_task(&mut backdated_fixture);
    let before_backdated = backdated_fixture.store.snapshot().unwrap();
    let before_backdated_bytes = before_backdated.canonical_bytes().unwrap();
    let (backdated_envelope, backdated_decision) = decision_terminal_with(
        &backdated_fixture,
        &backdated_claim,
        DecisionKind::Falsify,
        GraphProducerRole::Falsifier,
        GraphLogicalTime::new(99),
    );
    assert!(matches!(
        backdated_fixture.ledger.complete_task(
            &backdated_fixture.store,
            before_backdated.revision(),
            &backdated_claim,
            backdated_envelope,
            vec![backdated_fixture.evidence.clone()],
            Some(backdated_decision),
            None,
            None,
        ),
        Err(GraphStoreError::Admission(GraphAdmissionError::InvalidTransition { reason }))
            if reason.contains("back-dated")
    ));
    assert_eq!(
        backdated_fixture
            .store
            .snapshot()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        before_backdated_bytes
    );
}

#[test]
fn terminal_claim_retry_is_rejected_without_budget_or_store_mutation() {
    let mut fixture = decision_task_fixture(TaskKind::ChallengeEdge, GraphProducerRole::Challenger);
    let claim = claim_decision_task(&mut fixture);
    let before_terminal = fixture.store.snapshot().unwrap();
    let (envelope, decision) = decision_terminal(&fixture, &claim);
    fixture
        .ledger
        .complete_task(
            &fixture.store,
            before_terminal.revision(),
            &claim,
            envelope,
            vec![fixture.evidence.clone()],
            Some(decision),
            None,
            None,
        )
        .unwrap();
    let before_retry = fixture.store.snapshot().unwrap();
    let before_retry_bytes = before_retry.canonical_bytes().unwrap();
    let budget_before = fixture.ledger.scheduler_budget().clone();
    let error = fixture
        .ledger
        .claim_task(
            &fixture.store,
            fixture.request.clone(),
            GraphLogicalTime::new(200),
            1_000,
            claim.capability_proof,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        GraphStoreError::InvalidTransition { reason }
            if reason.contains("terminal tasks cannot be claimed")
    ));
    assert_eq!(fixture.ledger.scheduler_budget(), &budget_before);
    assert_eq!(
        fixture.store.snapshot().unwrap().canonical_bytes().unwrap(),
        before_retry_bytes
    );
}

#[test]
fn challenge_completion_retains_edge_lineage() {
    let mut fixture = decision_task_fixture(TaskKind::ChallengeEdge, GraphProducerRole::Challenger);
    let claim = claim_decision_task(&mut fixture);
    let before = fixture.store.snapshot().unwrap();
    let (envelope, decision) = decision_terminal(&fixture, &claim);
    let after = fixture
        .ledger
        .complete_task(
            &fixture.store,
            before.revision(),
            &claim,
            envelope,
            vec![fixture.evidence.clone()],
            Some(decision),
            None,
            None,
        )
        .unwrap();
    let hypothesis = &after.hypotheses()[&fixture.hypothesis_id];
    assert_eq!(hypothesis.decision_history.len(), 1);
    assert_eq!(hypothesis.decision_history[0].kind, DecisionKind::Challenge);
    assert_eq!(
        after.terminal_outbox()[&claim.task_id]
            .envelope
            .decision_link
            .as_ref()
            .unwrap()
            .target,
        fixture.target
    );
    assert_eq!(
        fixture.target,
        TaskTarget::Edge {
            edge_id: fixture.edge_id
        }
    );
}

#[test]
fn challenge_completion_rejects_unrelated_hypothesis_without_mutation() {
    let mut fixture = decision_task_fixture(TaskKind::ChallengeEdge, GraphProducerRole::Challenger);
    fixture.hypothesis_id = HypothesisId::new("hypothesis:unrelated-decision");
    let claim = claim_decision_task(&mut fixture);
    let before = fixture.store.snapshot().unwrap();
    let before_bytes = before.canonical_bytes().unwrap();
    let budget_before = fixture.ledger.scheduler_budget().clone();
    let (envelope, decision) = decision_terminal(&fixture, &claim);

    assert!(matches!(
        fixture.ledger.complete_task(
            &fixture.store,
            before.revision(),
            &claim,
            envelope,
            vec![fixture.evidence.clone()],
            Some(decision),
            None,
            None,
        ),
        Err(GraphStoreError::Admission(GraphAdmissionError::InvalidTransition {
            ref reason
        })) if reason.contains("challenged edge is not claimed")
    ));
    assert_eq!(fixture.ledger.scheduler_budget(), &budget_before);
    assert_eq!(
        fixture.store.snapshot().unwrap().canonical_bytes().unwrap(),
        before_bytes
    );
}

#[test]
fn falsification_completion_retains_hypothesis_lineage() {
    let mut fixture =
        decision_task_fixture(TaskKind::FalsifyHypothesis, GraphProducerRole::Falsifier);
    let claim = claim_decision_task(&mut fixture);
    let before = fixture.store.snapshot().unwrap();
    let (envelope, decision) = decision_terminal(&fixture, &claim);
    let after = fixture
        .ledger
        .complete_task(
            &fixture.store,
            before.revision(),
            &claim,
            envelope,
            vec![fixture.evidence.clone()],
            Some(decision),
            None,
            None,
        )
        .unwrap();
    let hypothesis = &after.hypotheses()[&fixture.hypothesis_id];
    assert_eq!(
        hypothesis.status,
        swarm_core::hypothesis_graph::HypothesisStatus::Falsified
    );
    assert_eq!(hypothesis.decision_history[0].kind, DecisionKind::Falsify);
    assert_eq!(
        after.terminal_outbox()[&claim.task_id]
            .envelope
            .decision_link
            .as_ref()
            .unwrap()
            .target,
        TaskTarget::Hypothesis {
            hypothesis_id: fixture.hypothesis_id,
        }
    );
}

fn production_replay_bundle(hunt_id: &str, created_at_ms: i64) -> ReplayBundle {
    let event = process_event(hunt_id, "curl https://phase286.example/payload");
    let finding = swarm_whisker::DetectionFinding {
        finding_id: format!("finding:{hunt_id}"),
        event_id: hunt_id.to_string(),
        threat_class: swarm_core::ThreatClass::Execution,
        severity: Severity::Critical,
        confidence: 0.97,
        evidence: serde_json::json!({
            "event_id": hunt_id,
            "host_id": event.host_id,
            "signal": "phase286-production-path",
        }),
        strategy_id: "phase286_collective_reasoning".to_string(),
    };
    ReplayBundle {
        bundle_id: format!("bundle:{hunt_id}"),
        event,
        findings: vec![finding.clone()],
        deposits: Vec::new(),
        action_request: swarm_policy::ActionRequest {
            hunt_id: HuntId(hunt_id.to_string()),
            requested_by: AgentId("whisker:phase286".to_string()),
            action: ResponseAction::Escalate {
                summary: format!("investigate {hunt_id}"),
                urgency: Severity::Critical,
            },
            severity: Severity::Critical,
            evidence: serde_json::json!({"event_id": hunt_id}),
        },
        rehearsal: None,
        audit: AuditTrail {
            trail_id: format!("trail:{hunt_id}"),
            hunt_id: hunt_id.to_string(),
            related_receipt_ids: Vec::new(),
            detection: finding,
            policy: PolicyRecord {
                verdict: swarm_policy::PolicyVerdict::Allow,
                rule_name: "phase286.test.allow".to_string(),
                reason: "production graph acceptance fixture".to_string(),
                lease: None,
            },
            response: AuditResponseRecord::Skipped {
                reason: "collective reasoning remains response-advisory".to_string(),
            },
            created_at_ms,
        },
    }
}

#[test]
fn duplicate_claim_fixture_100() {
    let logical_tick = GraphLogicalTime::new(1_700_000_010_000);
    let config = HypothesisGraphConfig {
        enabled: true,
        max_tasks: 128,
        max_work_units_per_tick: 100,
        max_claims_per_tick: 100,
        ..HypothesisGraphConfig::default()
    };
    let claimant_key = key(110);
    let claimant = AgentId::from_public_key_hex(&claimant_key.public_key().to_hex());
    let evidence = normalize_telemetry_event(
        &process_event("duplicate-claim-evidence", "curl https://fixture.example"),
        &FixedGraphClock::new(logical_tick),
        &claimant_key,
        GraphProducerRole::Normalizer,
        "normalizer:duplicate-claim",
    )
    .unwrap();
    let graph_id = GraphId::new("graph:duplicate-claim-100");
    let mut graph = HypothesisGraph::new(graph_id.clone(), config.resource_limits()).unwrap();
    graph.admit_evidence(evidence.clone()).unwrap();
    let store = MemoryHypothesisGraphStore::new_with_config(graph, key(111), &config).unwrap();
    let scope = EvidenceScope::new(
        [EvidenceSourceFamily::Process],
        [evidence.evidence_id.clone()],
        [],
    )
    .unwrap();
    let target = TaskTarget::Evidence {
        evidence_id: evidence.evidence_id.clone(),
    };
    let mut ledger = HypothesisTaskLedger::from_config(&config, logical_tick).unwrap();
    let mut requests = Vec::new();
    for index in 0_u64..100 {
        let descriptor = LogicalTaskDescriptor::new(
            graph_id.clone(),
            target.clone(),
            TaskKind::AcquireEvidence,
            format!("{:064x}", index + 1),
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            descriptor.task_id.clone(),
            descriptor.kind,
            descriptor.target.clone(),
            GraphProducerRole::Hunter,
            claimant.clone(),
            scope.clone(),
            logical_tick,
        )
        .unwrap();
        let before = store.snapshot().unwrap();
        ledger
            .create_task(&store, before.revision(), descriptor, request.clone())
            .unwrap();
        requests.push(request);
    }
    assert_eq!(store.snapshot().unwrap().tasks().count(), 100);

    for request in requests {
        let proof = TaskCapabilityProof::new(
            request.task_id.clone(),
            request.claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &claimant_key,
            "hunter:duplicate-claim",
        )
        .unwrap();
        let first = ledger
            .claim_task(&store, request.clone(), logical_tick, 1_000, proof.clone())
            .unwrap();
        let replay = ledger
            .claim_task(&store, request, logical_tick, 1_000, proof)
            .unwrap();
        assert_eq!(first, replay);
    }
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.tasks().count(), 100);
    assert!(
        snapshot
            .tasks()
            .all(|task| task.task.state == swarm_core::hypothesis_graph::TaskState::Claimed)
    );
    assert_eq!(snapshot.scheduler_budget().unwrap().claims_used(), 100);
}

#[test]
fn memory_replay_changes_priority_deterministically() {
    let signer = key(112);
    let graph_id = GraphId::new("graph:memory-replay");
    let hypothesis_id = HypothesisId::new("hypothesis:memory-replay");
    let evidence_id = swarm_core::hypothesis_graph::EvidenceId::new("evidence:memory-replay");
    let provenance = MemoryProvenance::new(
        AgentId::from_public_key_hex(&signer.public_key().to_hex()),
        [evidence_id.clone()],
    )
    .signed_with(&signer, GraphProducerRole::Falsifier, "memory:replay")
    .unwrap();
    let memory = StrategyMemory::new(
        graph_id.clone(),
        hypothesis_id.clone(),
        HypothesisDelta::new([], [], []),
        [EvidenceUtility::new(evidence_id.clone(), 9_000)],
        [],
        MemoryOutcome::Confirmed,
        provenance,
    )
    .unwrap()
    .signed_with(&signer, GraphProducerRole::Falsifier, "memory:replay")
    .unwrap();
    let expected_memory_id = memory.memory_id.clone();
    let store = MemoryStrategyMemoryStore::new(signer, GraphResourceLimits::default()).unwrap();
    let first_append = store
        .append_at(memory.clone(), GraphLogicalTime::new(10), 1_000)
        .unwrap();
    let replay_append = store
        .append_at(memory, GraphLogicalTime::new(10), 1_000)
        .unwrap();
    assert!(!first_append.idempotent);
    assert!(replay_append.idempotent);
    let evidence_scope = BTreeSet::from([evidence_id]);
    let first_matches = store
        .retrieve_at(
            &graph_id,
            &hypothesis_id,
            &evidence_scope,
            GraphLogicalTime::new(11),
            16,
        )
        .unwrap();
    let replay_matches = store
        .retrieve_at(
            &graph_id,
            &hypothesis_id,
            &evidence_scope,
            GraphLogicalTime::new(11),
            16,
        )
        .unwrap();
    let first_priority = project_memory_priority(6_000, &first_matches);
    let replay_priority = project_memory_priority(6_000, &replay_matches);
    assert_eq!(first_priority, replay_priority);
    assert!(first_priority.adjusted_priority_basis_points > 6_000);
    assert_eq!(first_priority.memory_id, Some(expected_memory_id));
}

#[test]
fn failed_coordination_does_not_publish_partial_graph() {
    let config = HypothesisGraphConfig {
        enabled: true,
        // One parented process replay creates five distinct reasoning
        // tasks. Admit exactly one replay, then prove the service fails closed
        // when the next replay requires rotation while work is outstanding.
        max_tasks: 5,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(135), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(136),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(137)).unwrap();
    let admitted = production_replay_bundle("hunt:phase286:atomic-admitted", 1_700_000_080_000);
    service.submit_replay(&admitted).unwrap();
    let before = service.operator_projection().unwrap();
    let rejected = production_replay_bundle("hunt:phase286:atomic-rejected", 1_700_000_080_001);

    let rejection = service.submit_replay(&rejected);
    assert!(
        matches!(
            &rejection,
            Err(
                swarm_runtime::hypothesis_graph::GraphServiceError::CampaignRotationBlocked {
                    outstanding_tasks: 5,
                    ..
                }
            )
        ),
        "unexpected rejection: {rejection:?}"
    );

    let after = service.operator_projection().unwrap();
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.digest, before.digest);
    assert_eq!(after.graph, before.graph);
    assert_eq!(after.hypotheses, before.hypotheses);
    assert_eq!(after.tasks, before.tasks);
    assert_eq!(
        after.logical_time_high_water,
        before.logical_time_high_water
    );
    assert_eq!(after.metrics.submissions, before.metrics.submissions);
    assert_eq!(
        after.metrics.submission_failures,
        before.metrics.submission_failures + 1
    );
}

#[test]
fn seed_signal_converges_through_real_runtime() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_nodes: 5,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(113), None).unwrap());
    let replay = production_replay_bundle("hunt:phase286:e2e", 1_700_000_010_000);
    assert!(matches!(
        service.submit_replay(&replay),
        Err(
            swarm_runtime::hypothesis_graph::GraphServiceError::MissingWorkerRegistration(
                TaskKind::AcquireEvidence
            )
        )
    ));
    assert_eq!(service.summary().unwrap().evidence_count, 0);
    let weaver_key = key(116);
    let weaver_id = AgentId::from_public_key_hex(&weaver_key.public_key().to_hex());
    let weaver = service
        .worker([TaskKind::ChallengeEdge], weaver_key)
        .unwrap();
    let stalker_key = key(117);
    let stalker_id = AgentId::from_public_key_hex(&stalker_key.public_key().to_hex());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key,
        )
        .unwrap();
    let first = service.submit_replay(&replay).unwrap();
    let duplicate = service.submit_replay(&replay).unwrap();
    assert_eq!(first.evidence_id, duplicate.evidence_id);
    assert!(duplicate.idempotent);

    let mut completed_challenges = 0;
    while let Some(challenge) = weaver
        .next_challenge_context(GraphLogicalTime::new(1_700_000_010_001))
        .unwrap()
    {
        assert_eq!(challenge.hunt_id, replay.audit.hunt_id);
        assert!(
            weaver
                .complete_challenge(&challenge.task_id, GraphLogicalTime::new(1_700_000_010_001),)
                .unwrap()
        );
        completed_challenges += 1;
    }
    assert_eq!(completed_challenges, 3);

    let completion = stalker
        .complete_stalker_hunt(
            &replay.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_010_002),
            9_700,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 1);
    assert_eq!(completion.falsification_no_findings, 0);
    assert_eq!(completion.memory_records_projected, 1);

    let projection = service.operator_projection().unwrap();
    assert_eq!(projection.graph.evidence.len(), 1);
    assert_eq!(projection.graph.nodes.len(), 5);
    for entity_id in projection.graph.evidence[&first.evidence_id].entity_ids() {
        assert!(
            projection.graph.nodes.contains_key(&entity_id),
            "normalized evidence entity {entity_id} must be navigable"
        );
    }
    assert_eq!(projection.graph.edges.len(), 3);
    for relation in [
        CausalRelation::DependsOn,
        CausalRelation::Spawns,
        CausalRelation::Uses,
    ] {
        assert!(
            projection
                .graph
                .edges
                .values()
                .any(|edge| edge.relation == relation)
        );
    }
    assert!(projection.graph.edges.values().all(|edge| {
        projection.graph.nodes.contains_key(&edge.from)
            && projection.graph.nodes.contains_key(&edge.to)
    }));
    assert_eq!(projection.tasks.len(), 5);
    assert!(
        projection
            .tasks
            .iter()
            .all(|task| task.state == swarm_core::hypothesis_graph::TaskState::Completed)
    );
    assert_eq!(projection.terminal_publications, 5);
    assert_eq!(projection.memory.len(), 1);
    assert_eq!(projection.hypotheses.len(), 2);
    assert!(projection.hypotheses.values().all(|hypothesis| {
        projection
            .graph
            .edges
            .keys()
            .all(|edge_id| hypothesis.claims.contains(edge_id))
    }));
    let benign_hypothesis_id = projection
        .tasks
        .iter()
        .find_map(|task| match (&task.request.kind, &task.request.target) {
            (TaskKind::FalsifyHypothesis, TaskTarget::Hypothesis { hypothesis_id }) => {
                Some(hypothesis_id)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        projection.hypotheses[benign_hypothesis_id].status,
        swarm_core::hypothesis_graph::HypothesisStatus::Falsified
    );
    assert_eq!(projection.metrics.completed_acquisitions, 1);
    assert_eq!(projection.metrics.completed_challenges, 3);
    assert_eq!(projection.metrics.completed_falsifications, 1);
    assert_eq!(projection.metrics.falsification_no_findings, 0);
    for task in &projection.tasks {
        let expected = if task.request.kind == TaskKind::ChallengeEdge {
            &weaver_id
        } else {
            &stalker_id
        };
        assert_eq!(&task.request.claimant, expected);
        assert_eq!(
            task.completion.as_ref().unwrap().completed_by,
            expected.clone()
        );
    }
    let terminal_decisions = projection
        .hypotheses
        .values()
        .flat_map(|hypothesis| hypothesis.decision_history.iter())
        .filter(|decision| {
            matches!(
                decision.kind,
                swarm_core::hypothesis_graph::DecisionKind::Challenge
                    | swarm_core::hypothesis_graph::DecisionKind::Falsify
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(terminal_decisions.len(), 2);
    for decision in terminal_decisions {
        let expected = if decision.kind == swarm_core::hypothesis_graph::DecisionKind::Challenge {
            &weaver_id
        } else {
            &stalker_id
        };
        assert_eq!(&decision.producer_identity, expected);
        decision.validate().unwrap();
    }

    let replay_after_completion = service.submit_replay(&replay).unwrap();
    assert!(replay_after_completion.idempotent);
    assert_eq!(replay_after_completion.evidence_id, first.evidence_id);
    assert_eq!(replay_after_completion.task_ids, first.task_ids);
    let after_retry = service.operator_projection().unwrap();
    assert_eq!(after_retry.graph.evidence.len(), 1);
    assert_eq!(after_retry.graph.edges.len(), 3);
    assert_eq!(after_retry.tasks.len(), 5);
    assert_eq!(after_retry.terminal_publications, 5);
    assert_eq!(after_retry.memory.len(), 1);
}

#[test]
fn enabled_minimum_node_limit_admits_parented_process_with_user() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_nodes: 5,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(138), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(139),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(140)).unwrap();

    let replay = production_replay_bundle(
        "hunt:phase286:parented-process-with-user",
        1_700_000_090_000,
    );
    assert!(matches!(
        &replay.event.payload,
        TelemetryPayload::ProcessStart(process)
            if process.parent_process != "<none>" && process.user.is_some()
    ));

    let submission = service.submit_replay(&replay).unwrap();
    let projection = service.operator_projection().unwrap();
    assert_eq!(projection.graph.nodes.len(), 5);
    let evidence = &projection.graph.evidence[&submission.evidence_id];
    assert_eq!(evidence.entity_ids().len(), 5);
    assert!(
        evidence
            .entity_ids()
            .iter()
            .all(|node_id| projection.graph.nodes.contains_key(node_id))
    );
    let edge = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::Spawns)
        .unwrap();
    assert!(evidence.entity_ids().contains(&edge.from));
    assert!(evidence.entity_ids().contains(&edge.to));
    assert!(matches!(
        projection.graph.nodes[&edge.from],
        GraphNode::Process(_)
    ));
    assert!(matches!(
        projection.graph.nodes[&edge.to],
        GraphNode::Process(_)
    ));
    let GraphNode::Process(child) = &projection.graph.nodes[&edge.to] else {
        unreachable!()
    };
    assert_eq!(child.parent_node_id.as_ref(), Some(&edge.from));
}

#[test]
fn parent_bound_process_path_connects_to_network_correlation_identity() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(197), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(198),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(199)).unwrap();

    let process = production_replay_bundle("hunt:phase286:process-network-path", 1_700_000_090_050);
    let mut network = production_replay_bundle(
        "hunt:phase286:process-network-path:network",
        1_700_000_090_051,
    );
    network.event = network_event("process-network-path:network", "203.0.113.78");
    network.event.source = process.event.source.clone();
    network.event.host_id = process.event.host_id.clone();
    network.findings[0].event_id = network.event.event_id.clone();
    network.audit.detection = network.findings[0].clone();

    service.submit_replay(&process).unwrap();
    service.submit_replay(&network).unwrap();
    let projection = service.operator_projection().unwrap();
    let spawned = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::Spawns)
        .unwrap();
    let correlation = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::DependsOn)
        .unwrap();
    let contact = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::Contacts)
        .unwrap();
    assert_eq!(spawned.to, correlation.from);
    assert_eq!(correlation.to, contact.from);
}

#[test]
fn accepted_future_ingest_skew_remains_valid_graph_evidence() {
    let config = HypothesisGraphConfig {
        enabled: true,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(200), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(201),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(202)).unwrap();
    let created_at_ms = 1_700_000_090_075;
    let mut replay = production_replay_bundle("hunt:phase286:accepted-future-skew", created_at_ms);
    replay.event.timestamp = created_at_ms + swarm_core::MAX_TELEMETRY_FUTURE_SKEW_MS;

    let submission = service.submit_replay(&replay).unwrap();
    let projection = service.operator_projection().unwrap();
    let evidence = &projection.graph.evidence[&submission.evidence_id];
    assert_eq!(
        evidence.clock.ingested_at,
        Some(GraphLogicalTime::new(created_at_ms))
    );
    assert_eq!(
        evidence.clock.uncertainty_ms,
        u64::try_from(swarm_core::MAX_TELEMETRY_FUTURE_SKEW_MS).unwrap()
    );

    let invalid_service =
        Arc::new(CollectiveHypothesisService::new(&config, key(212), None).unwrap());
    invalid_service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(213),
        )
        .unwrap();
    invalid_service
        .worker([TaskKind::ChallengeEdge], key(214))
        .unwrap();
    let mut beyond_allowance =
        production_replay_bundle("hunt:phase286:rejected-future-skew", created_at_ms);
    beyond_allowance.event.timestamp = created_at_ms + swarm_core::MAX_TELEMETRY_FUTURE_SKEW_MS + 1;
    assert!(invalid_service.submit_replay(&beyond_allowance).is_err());
    assert_eq!(invalid_service.summary().unwrap().evidence_count, 0);
}

#[test]
fn enabled_minimum_evidence_budget_admits_one_signed_production_envelope() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_evidence_bytes: MIN_HYPOTHESIS_GRAPH_EVIDENCE_BYTES,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(185), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(188),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(189)).unwrap();
    let replay =
        production_replay_bundle("hunt:phase286:minimum-evidence-budget", 1_700_000_090_100);

    let submitted = service.submit_replay(&replay).unwrap();
    let projection = service.operator_projection().unwrap();
    assert!(
        projection
            .graph
            .evidence
            .contains_key(&submitted.evidence_id)
    );
    assert!(
        projection.graph.evidence[&submitted.evidence_id]
            .canonical_bytes()
            .unwrap()
            .len()
            <= MIN_HYPOTHESIS_GRAPH_EVIDENCE_BYTES
    );
}

#[test]
fn persisted_threat_intel_match_is_admitted_atomically_with_network_evidence() {
    let config = HypothesisGraphConfig {
        enabled: true,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(191), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(192),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(193)).unwrap();
    let mut replay =
        production_replay_bundle("hunt:phase286:network-threat-intel", 1_700_000_090_200);
    replay.event = network_event("network-threat-intel", "203.0.113.77");
    let matched = ThreatIntelEntry {
        indicator_type: ThreatIntelIndicatorType::IpAddress,
        value: "203.0.113.77".to_string(),
        source: "taxii-production".to_string(),
        indicator_id: Some("indicator:203.0.113.77".to_string()),
        confidence: 0.98,
        expires_at: 1_800_000_000_000,
    };
    replay.findings[0].event_id = replay.event.event_id.clone();
    replay.findings[0].evidence = serde_json::json!({
        "threat_intel_matches": [matched],
    });
    replay.audit.detection = replay.findings[0].clone();

    service.submit_replay(&replay).unwrap();
    let projection = service.operator_projection().unwrap();
    assert_eq!(projection.graph.evidence.len(), 2);
    assert!(
        projection
            .graph
            .evidence
            .values()
            .any(|evidence| { evidence.source_family == EvidenceSourceFamily::ThreatIntelligence })
    );
    let contacts = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::Contacts)
        .unwrap();
    let indicator_match = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::MatchesIndicator)
        .unwrap();
    assert_eq!(contacts.to, indicator_match.to);
    assert_eq!(projection.tasks.len(), 5);
    assert!(
        projection
            .tasks
            .iter()
            .all(|task| { task.request.evidence_scope.evidence_ids.len() == 2 })
    );

    let invalid_service =
        Arc::new(CollectiveHypothesisService::new(&config, key(194), None).unwrap());
    invalid_service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(195),
        )
        .unwrap();
    invalid_service
        .worker([TaskKind::ChallengeEdge], key(196))
        .unwrap();
    let mut invalid = replay;
    invalid.bundle_id.push_str(":expired");
    invalid.audit.hunt_id.push_str(":expired");
    invalid.findings[0].evidence["threat_intel_matches"][0]["expires_at"] = serde_json::json!(1);
    assert!(invalid_service.submit_replay(&invalid).is_err());
    assert_eq!(
        invalid_service.summary().unwrap().evidence_count,
        0,
        "telemetry must not commit when its matched enrichment is invalid"
    );
}

#[test]
fn shipped_defaults_admit_the_maximum_bounded_replay_task_seed() {
    let config = HypothesisGraphConfig {
        enabled: true,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(215), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(216),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(217)).unwrap();
    let mut replay = production_replay_bundle("hunt:phase286:maximum-task-seed", 1_700_000_090_225);
    let matches = (0..64)
        .map(|index| ThreatIntelEntry {
            indicator_type: ThreatIntelIndicatorType::Domain,
            value: format!("indicator-{index}.example"),
            source: "taxii-production".to_string(),
            indicator_id: Some(format!("indicator:maximum:{index}")),
            confidence: 0.98,
            expires_at: 1_800_000_000_000,
        })
        .collect::<Vec<_>>();
    replay.findings[0].evidence = serde_json::json!({
        "threat_intel_matches": matches,
    });
    replay.audit.detection = replay.findings[0].clone();

    let submission = service.submit_replay(&replay).unwrap();
    assert_eq!(submission.task_ids.len(), 133);
    assert!(submission.task_ids.len() <= config.max_tasks);
}

#[test]
fn persisted_domain_match_converges_with_normalized_dns_destination() {
    let config = HypothesisGraphConfig {
        enabled: true,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(203), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(204),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(205)).unwrap();
    let mut replay = production_replay_bundle("hunt:phase286:dns-threat-intel", 1_700_000_090_250);
    replay.event = dns_event("dns-threat-intel", "Evil.Example.");
    replay.findings[0].event_id = replay.event.event_id.clone();
    replay.findings[0].evidence = serde_json::json!({
        "threat_intel_matches": [threat_entry("EVIL.EXAMPLE.")],
    });
    replay.audit.detection = replay.findings[0].clone();

    service.submit_replay(&replay).unwrap();
    let projection = service.operator_projection().unwrap();
    let contacts = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::Contacts)
        .unwrap();
    let indicator_match = projection
        .graph
        .edges
        .values()
        .find(|edge| edge.relation == CausalRelation::MatchesIndicator)
        .unwrap();
    assert_eq!(contacts.to, indicator_match.to);
}

#[test]
fn replay_rotation_uses_generated_task_target_count() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_tasks: 7,
        max_work_units_per_tick: 5,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(206), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(207),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(208)).unwrap();

    let mut first =
        production_replay_bundle("hunt:phase286:task-preflight:first", 1_700_000_090_300);
    first.event = network_event("task-preflight:first", "203.0.113.80");
    first.findings[0].event_id = first.event.event_id.clone();
    first.audit.detection = first.findings[0].clone();
    service.submit_replay(&first).unwrap();

    let mut second =
        production_replay_bundle("hunt:phase286:task-preflight:second", 1_700_000_090_301);
    second.event = network_event("task-preflight:second", "203.0.113.81");
    second.findings[0].event_id = second.event.event_id.clone();
    second.findings[0].evidence = serde_json::json!({
        "threat_intel_matches": [{
            "indicator_type": "ip_address",
            "value": "203.0.113.81",
            "source": "taxii-production",
            "indicator_id": "indicator:203.0.113.81",
            "confidence": 0.98,
            "expires_at": 1_800_000_000_000i64
        }],
    });
    second.audit.detection = second.findings[0].clone();

    assert!(matches!(
        service.submit_replay(&second),
        Err(
            swarm_runtime::hypothesis_graph::GraphServiceError::CampaignRotationBlocked {
                outstanding_tasks: 3,
                ..
            }
        )
    ));
    assert_eq!(service.operator_projection().unwrap().tasks.len(), 3);
}

#[test]
fn oversized_replay_task_seed_is_rejected_without_retry_or_partial_graph() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 5,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(209), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(210),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(211)).unwrap();
    let mut replay =
        production_replay_bundle("hunt:phase286:oversized-task-seed", 1_700_000_090_350);
    replay.event = network_event("oversized-task-seed", "203.0.113.82");
    replay.findings[0].event_id = replay.event.event_id.clone();
    replay.findings[0].evidence = serde_json::json!({
        "threat_intel_matches": [
            {
                "indicator_type": "ip_address",
                "value": "203.0.113.82",
                "source": "taxii-production",
                "indicator_id": "indicator:203.0.113.82",
                "confidence": 0.98,
                "expires_at": 1_800_000_000_000i64
            },
            {
                "indicator_type": "ip_address",
                "value": "203.0.113.83",
                "source": "taxii-production",
                "indicator_id": "indicator:203.0.113.83",
                "confidence": 0.97,
                "expires_at": 1_800_000_000_000i64
            }
        ],
    });
    replay.audit.detection = replay.findings[0].clone();

    assert!(matches!(
        service.submit_replay(&replay),
        Err(swarm_runtime::hypothesis_graph::GraphServiceError::Admission(
            GraphAdmissionError::ResourceLimitExceeded { resource, limit: 5 }
        )) if resource == "replay.task_targets"
    ));
    assert_eq!(service.summary().unwrap().evidence_count, 0);
}

#[test]
fn benign_or_ambiguous_investigation_closes_falsification_without_false_memory() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(132), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(133),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(134)).unwrap();
    let replay = production_replay_bundle("hunt:phase286:no-finding", 1_700_000_070_000);
    service.submit_replay(&replay).unwrap();

    let completion = stalker
        .complete_stalker_hunt(
            &replay.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_070_001),
            9_900,
            false,
            false,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 0);
    assert_eq!(completion.falsification_no_findings, 1);
    assert_eq!(completion.memory_records_projected, 0);

    let projection = service.operator_projection().unwrap();
    assert!(projection.memory.is_empty());
    let falsification_task = projection
        .tasks
        .iter()
        .find(|task| task.request.kind == TaskKind::FalsifyHypothesis)
        .unwrap();
    let TaskTarget::Hypothesis {
        hypothesis_id: benign_hypothesis_id,
    } = &falsification_task.request.target
    else {
        panic!("falsification task must target its evidence-scoped benign hypothesis");
    };
    assert_ne!(
        projection.hypotheses[benign_hypothesis_id].status,
        swarm_core::hypothesis_graph::HypothesisStatus::Falsified
    );
    assert_eq!(
        falsification_task.completion.as_ref().unwrap().kind,
        TaskCompletionKind::NoFinding
    );
    assert_eq!(projection.metrics.completed_falsifications, 1);
    assert_eq!(projection.metrics.falsification_no_findings, 1);
    assert_eq!(
        stalker.outstanding_stalker_hunts().unwrap(),
        vec![replay.audit.hunt_id.clone()]
    );
    let committed = stalker
        .committed_stalker_publication(&replay.audit.hunt_id)
        .unwrap()
        .unwrap();
    assert_eq!(committed.completion.acquisitions, 1);
    assert_eq!(committed.completion.falsification_no_findings, 1);
}

#[test]
fn stalker_recovery_is_bounded_and_acknowledgement_advances_the_durable_page() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 5,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(162), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(163),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(164)).unwrap();

    let mut hunt_ids = Vec::new();
    for index in 0..7_i64 {
        let hunt_id = format!("hunt:phase286:bounded-recovery:{index}");
        let created_at = 1_700_000_110_000 + index * 100;
        let replay = production_replay_bundle(&hunt_id, created_at);
        service.submit_replay(&replay).unwrap();
        stalker
            .complete_stalker_hunt(
                &hunt_id,
                GraphLogicalTime::new(created_at + 1),
                9_000,
                false,
                false,
            )
            .unwrap();
        hunt_ids.push(hunt_id);
    }

    let first_page = stalker
        .outstanding_stalker_hunts_at(GraphLogicalTime::new(1_700_000_111_000))
        .unwrap();
    assert_eq!(first_page, hunt_ids[..5]);
    for hunt_id in &first_page {
        stalker.acknowledge_stalker_publication(hunt_id).unwrap();
    }
    let second_page = stalker
        .outstanding_stalker_hunts_at(GraphLogicalTime::new(1_700_000_111_000))
        .unwrap();
    assert_eq!(second_page, hunt_ids[5..]);
}

#[test]
fn stalker_recovery_respects_capability_scope_without_republishing_acknowledged_work() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 5,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(168), None).unwrap());
    let stalker_key = key(169);
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    let acquisition_only = service
        .worker([TaskKind::AcquireEvidence], stalker_key)
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(170)).unwrap();
    let hunt_id = "hunt:phase286:scoped-recovery";
    let created_at = 1_700_000_112_000;
    service
        .submit_replay(&production_replay_bundle(hunt_id, created_at))
        .unwrap();
    stalker
        .complete_stalker_hunt(
            hunt_id,
            GraphLogicalTime::new(created_at + 1),
            9_000,
            false,
            false,
        )
        .unwrap();

    let acquisition = acquisition_only
        .committed_stalker_publication(hunt_id)
        .unwrap()
        .unwrap();
    assert_eq!(acquisition.completion.acquisitions, 1);
    assert_eq!(acquisition.completion.falsification_no_findings, 0);
    acquisition_only
        .acknowledge_stalker_publication(hunt_id)
        .unwrap();
    assert!(
        acquisition_only
            .outstanding_stalker_hunts()
            .unwrap()
            .is_empty()
    );

    let falsification = stalker
        .committed_stalker_publication(hunt_id)
        .unwrap()
        .unwrap();
    assert_eq!(falsification.completion.acquisitions, 0);
    assert_eq!(falsification.completion.falsification_no_findings, 1);
    stalker.acknowledge_stalker_publication(hunt_id).unwrap();
    assert!(stalker.outstanding_stalker_hunts().unwrap().is_empty());
}

#[test]
fn older_hunt_completion_is_ordered_after_newer_replay_high_water() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(129), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(130),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(131)).unwrap();
    let older = production_replay_bundle("hunt:phase286:older", 1_700_000_050_000);
    let newer = production_replay_bundle("hunt:phase286:newer", 1_700_000_060_000);
    service.submit_replay(&older).unwrap();
    service.submit_replay(&newer).unwrap();

    let completion = stalker
        .complete_stalker_hunt(
            &older.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_050_001),
            9_700,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 1);
    let projection = service.operator_projection().unwrap();
    assert_eq!(projection.hypotheses.len(), 4);
    assert_eq!(
        projection
            .hypotheses
            .values()
            .filter(|hypothesis| {
                hypothesis.status == swarm_core::hypothesis_graph::HypothesisStatus::Falsified
            })
            .count(),
        1,
        "the older hunt must not falsify the newer hunt's benign alternative"
    );
    let older_terminal_times = projection
        .tasks
        .iter()
        .filter(|task| {
            task.request
                .evidence_scope
                .evidence_ids
                .iter()
                .filter_map(|evidence_id| projection.graph.evidence.get(evidence_id))
                .any(|evidence| evidence.lineage.source_record_id == older.audit.hunt_id)
        })
        .filter_map(|task| {
            task.completion
                .as_ref()
                .map(|completion| completion.completed_at)
        })
        .collect::<Vec<_>>();
    assert_eq!(older_terminal_times.len(), 2);
    assert!(
        older_terminal_times
            .iter()
            .all(|completed_at| *completed_at >= GraphLogicalTime::new(1_700_000_060_000))
    );
}

#[test]
fn enabled_service_restores_graph_tasks_and_memory_after_restart() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "swarm-phase286-service-restart-{}-{unique}",
        std::process::id()
    ));
    let config = HypothesisGraphConfig {
        enabled: true,
        state_store: BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        },
        max_lease_ms: 10,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service_key = key(123);
    let stalker_key = key(124);
    let weaver_key = key(125);
    let replay = production_replay_bundle("hunt:phase286:restart", 1_700_000_030_000);

    let service =
        Arc::new(CollectiveHypothesisService::new(&config, service_key.clone(), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    let weaver = service
        .worker([TaskKind::ChallengeEdge], weaver_key.clone())
        .unwrap();
    service.ensure_workers_registered().unwrap();
    let first = service.submit_replay(&replay).unwrap();
    let challenge = weaver
        .next_challenge_context(GraphLogicalTime::new(1_700_000_030_001))
        .unwrap()
        .unwrap();
    assert!(
        weaver
            .complete_challenge(&challenge.task_id, GraphLogicalTime::new(1_700_000_030_001),)
            .unwrap()
    );
    let completion = stalker
        .complete_stalker_hunt(
            &replay.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_030_002),
            9_800,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.memory_records_projected, 1);
    let before = service.operator_projection().unwrap();
    assert_eq!(before.tasks.len(), 5);
    assert_eq!(before.memory.len(), 1);
    drop(stalker);
    drop(weaver);
    drop(service);

    let restarted = Arc::new(CollectiveHypothesisService::new(&config, service_key, None).unwrap());
    let restarted_stalker = restarted
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    restarted
        .worker([TaskKind::ChallengeEdge], weaver_key.clone())
        .unwrap();
    restarted.ensure_workers_registered().unwrap();
    let after = restarted.operator_projection().unwrap();
    assert_eq!(after.digest, before.digest);
    assert_eq!(after.tasks, before.tasks);
    assert_eq!(after.memory, before.memory);
    let retry = restarted.submit_replay(&replay).unwrap();
    assert!(retry.idempotent);
    assert_eq!(retry.evidence_id, first.evidence_id);
    assert_eq!(retry.task_ids, first.task_ids);
    let abandoned_replay =
        production_replay_bundle("hunt:phase286:restart-lease", 1_700_000_031_000);
    restarted.submit_replay(&abandoned_replay).unwrap();
    let abandoned = restarted_stalker
        .claim_next(GraphLogicalTime::new(1_700_000_031_001))
        .unwrap()
        .unwrap();
    drop(restarted_stalker);
    drop(restarted);

    let recovered = Arc::new(CollectiveHypothesisService::new(&config, key(123), None).unwrap());
    let recovered_stalker = recovered
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key,
        )
        .unwrap();
    recovered
        .worker([TaskKind::ChallengeEdge], weaver_key)
        .unwrap();
    let reclaimed = recovered_stalker
        .claim_next(GraphLogicalTime::new(1_700_000_031_011))
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.claim.task_id, abandoned.claim.task_id);
    assert!(reclaimed.claim.fencing_token > abandoned.claim.fencing_token);
    drop(recovered_stalker);
    drop(recovered);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restart_rebinds_an_elapsed_claim_to_a_replacement_worker() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "swarm-phase286-elapsed-worker-rebind-{}-{unique}",
        std::process::id()
    ));
    let config = HypothesisGraphConfig {
        enabled: true,
        state_store: BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        },
        max_lease_ms: 10,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let registered_at = GraphLogicalTime::new(1_700_000_032_000);
    let expired_at = GraphLogicalTime::new(1_700_000_032_011);
    let service_key = key(151);
    let prior_key = key(152);
    let replacement_key = key(153);
    let replay = production_replay_bundle("hunt:phase286:elapsed-rebind", 1_700_000_032_000);

    let initial =
        Arc::new(CollectiveHypothesisService::new(&config, service_key.clone(), None).unwrap());
    let prior = initial
        .worker_at([TaskKind::ChallengeEdge], prior_key, registered_at)
        .unwrap();
    initial
        .worker_at(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(154),
            registered_at,
        )
        .unwrap();
    initial.submit_replay(&replay).unwrap();
    let mut abandoned = Vec::new();
    for _ in 0..3 {
        let claim = prior
            .claim_next(GraphLogicalTime::new(1_700_000_032_001))
            .unwrap()
            .unwrap();
        assert_eq!(claim.request.kind, TaskKind::ChallengeEdge);
        abandoned.push(claim);
    }
    drop(prior);
    drop(initial);

    let restarted = Arc::new(CollectiveHypothesisService::new(&config, service_key, None).unwrap());
    let replacement = restarted
        .worker_at([TaskKind::ChallengeEdge], replacement_key, expired_at)
        .unwrap();
    let reclaimed = replacement.claim_next(expired_at).unwrap().unwrap();
    assert!(
        abandoned
            .iter()
            .any(|claim| claim.claim.task_id == reclaimed.claim.task_id)
    );
    assert_ne!(reclaimed.request.claimant, abandoned[0].request.claimant);
    assert_eq!(&reclaimed.request.claimant, replacement.claimant());
    let prior_fence = abandoned
        .iter()
        .find(|claim| claim.claim.task_id == reclaimed.claim.task_id)
        .map(|claim| claim.claim.fencing_token)
        .unwrap();
    assert!(reclaimed.claim.fencing_token > prior_fence);

    drop(replacement);
    drop(restarted);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn expired_worker_lease_is_fenced_and_reclaimed() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_lease_ms: 10,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let metrics = CriticalPathMetrics::new();
    let service = Arc::new(
        CollectiveHypothesisService::new(&config, key(126), Some(metrics.clone())).unwrap(),
    );
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(127),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(128)).unwrap();
    let replay = production_replay_bundle("hunt:phase286:lease-recovery", 1_700_000_040_000);
    service.submit_replay(&replay).unwrap();
    assert!(encode_metrics(&metrics).contains("swarm_hypothesis_graph_pending_tasks 5"));

    let first = stalker
        .claim_next(GraphLogicalTime::new(1_700_000_040_001))
        .unwrap()
        .unwrap();
    assert!(encode_metrics(&metrics).contains("swarm_hypothesis_graph_pending_tasks 4"));
    let reclaimed = stalker
        .claim_next(GraphLogicalTime::new(1_700_000_040_011))
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.claim.task_id, first.claim.task_id);
    assert_ne!(reclaimed.claim.lease_id, first.claim.lease_id);
    assert!(reclaimed.claim.fencing_token > first.claim.fencing_token);
    assert!(reclaimed.task_generation > first.task_generation);
    let task = service
        .operator_tasks_for(&service.graph_id())
        .unwrap()
        .into_iter()
        .find(|task| task.request.task_id == reclaimed.claim.task_id)
        .unwrap();
    assert_eq!(task.state, swarm_core::hypothesis_graph::TaskState::Claimed);
    assert_eq!(task.attempts, 2);
}

#[test]
fn exhausted_worker_retry_becomes_failed_and_does_not_starve_next_work() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "swarm-phase286-retry-exhaustion-{}-{unique}",
        std::process::id()
    ));
    let config = HypothesisGraphConfig {
        enabled: true,
        state_store: BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        },
        max_lease_ms: 10,
        max_retries: 2,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service_key = key(159);
    let stalker_key = key(160);
    let weaver_key = key(161);
    let service =
        Arc::new(CollectiveHypothesisService::new(&config, service_key.clone(), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    service
        .worker([TaskKind::ChallengeEdge], weaver_key.clone())
        .unwrap();
    service
        .submit_replay(&production_replay_bundle(
            "hunt:phase286:retry-exhaustion",
            1_700_000_095_000,
        ))
        .unwrap();

    let first = stalker
        .claim_next(GraphLogicalTime::new(1_700_000_095_001))
        .unwrap()
        .unwrap();
    let second = stalker
        .claim_next(GraphLogicalTime::new(1_700_000_095_011))
        .unwrap()
        .unwrap();
    assert_eq!(second.claim.task_id, first.claim.task_id);

    let next = stalker
        .claim_next(GraphLogicalTime::new(1_700_000_095_021))
        .unwrap()
        .unwrap();
    assert_ne!(next.claim.task_id, first.claim.task_id);
    let exhausted = service
        .operator_tasks_for(&service.graph_id())
        .unwrap()
        .into_iter()
        .find(|task| task.request.task_id == first.claim.task_id)
        .unwrap();
    assert_eq!(
        exhausted.state,
        swarm_core::hypothesis_graph::TaskState::Failed
    );
    assert_eq!(exhausted.attempts, config.max_retries);
    assert_eq!(
        exhausted
            .terminal_history
            .last()
            .and_then(|proof| proof.failure_summary_digest.as_deref()),
        Some(swarm_core::hypothesis_graph::TASK_RETRY_EXHAUSTED_FAILURE_SUMMARY)
    );
    let exhausted_task_id = exhausted.request.task_id.clone();
    drop(next);
    drop(second);
    drop(first);
    drop(stalker);
    drop(service);

    let restarted = Arc::new(CollectiveHypothesisService::new(&config, service_key, None).unwrap());
    restarted
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key,
        )
        .unwrap();
    restarted
        .worker([TaskKind::ChallengeEdge], weaver_key)
        .unwrap();
    let persisted = restarted
        .operator_tasks_for(&restarted.graph_id())
        .unwrap()
        .into_iter()
        .find(|task| task.request.task_id == exhausted_task_id)
        .unwrap();
    assert_eq!(
        persisted.state,
        swarm_core::hypothesis_graph::TaskState::Failed
    );
    assert_eq!(persisted.attempts, config.max_retries);
    drop(restarted);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn retry_exhausted_weaver_terminal_replays_until_durably_acknowledged() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "swarm-phase286-retry-terminal-replay-{}-{unique}",
        std::process::id()
    ));
    let config = HypothesisGraphConfig {
        enabled: true,
        state_store: BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        },
        max_lease_ms: 10,
        max_retries: 2,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service_key = key(165);
    let stalker_key = key(166);
    let weaver_key = key(167);
    let hunt_id = "hunt:phase286:retry-terminal-replay";
    let service =
        Arc::new(CollectiveHypothesisService::new(&config, service_key.clone(), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    let weaver = service
        .worker([TaskKind::ChallengeEdge], weaver_key.clone())
        .unwrap();
    service
        .submit_replay(&production_replay_bundle(hunt_id, 1_700_000_120_000))
        .unwrap();
    let first = weaver
        .claim_next(GraphLogicalTime::new(1_700_000_120_001))
        .unwrap()
        .unwrap();
    let second = weaver
        .claim_next(GraphLogicalTime::new(1_700_000_120_011))
        .unwrap()
        .unwrap();
    assert_eq!(first.claim.task_id, second.claim.task_id);
    let next = weaver
        .claim_next(GraphLogicalTime::new(1_700_000_120_021))
        .unwrap()
        .unwrap();
    assert_ne!(next.claim.task_id, first.claim.task_id);
    let pending = weaver.outstanding_weaver_publications().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].task_id, first.claim.task_id);
    assert_eq!(pending[0].hunt_id, hunt_id);
    assert!(pending[0].no_finding);
    assert_eq!(
        pending[0].retry_exhaustion_failure_summary.as_deref(),
        Some(swarm_core::hypothesis_graph::TASK_RETRY_EXHAUSTED_FAILURE_SUMMARY)
    );
    assert_eq!(
        service.operator_projection().unwrap().terminal_publications,
        1
    );
    drop(next);
    drop(weaver);
    drop(service);

    let restarted =
        Arc::new(CollectiveHypothesisService::new(&config, service_key.clone(), None).unwrap());
    restarted
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    let weaver = restarted
        .worker([TaskKind::ChallengeEdge], weaver_key.clone())
        .unwrap();
    let replayed = weaver.outstanding_weaver_publications().unwrap();
    assert_eq!(replayed, pending);
    weaver
        .acknowledge_weaver_publication(&first.claim.task_id)
        .unwrap();
    drop(weaver);
    drop(restarted);

    let acknowledged =
        Arc::new(CollectiveHypothesisService::new(&config, service_key, None).unwrap());
    acknowledged
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key,
        )
        .unwrap();
    let weaver = acknowledged
        .worker([TaskKind::ChallengeEdge], weaver_key)
        .unwrap();
    assert!(weaver.outstanding_weaver_publications().unwrap().is_empty());
    drop(weaver);
    drop(acknowledged);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_can_renew_the_same_claim_repeatedly() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_lease_ms: 10,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(138), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(139),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(140)).unwrap();
    service
        .submit_replay(&production_replay_bundle(
            "hunt:phase286:repeated-renewal",
            1_700_000_090_000,
        ))
        .unwrap();

    let mut claimed = stalker
        .claim_next(GraphLogicalTime::new(1_700_000_090_001))
        .unwrap()
        .unwrap();
    let claimed_generation = claimed.task_generation;
    stalker
        .renew(&mut claimed, GraphLogicalTime::new(1_700_000_090_002))
        .unwrap();
    let first_renewal_generation = claimed.task_generation;
    assert!(first_renewal_generation > claimed_generation);
    stalker
        .renew(&mut claimed, GraphLogicalTime::new(1_700_000_090_003))
        .unwrap();
    assert!(claimed.task_generation > first_renewal_generation);
}

#[test]
fn terminal_campaign_rotates_before_inferred_edge_exceeds_fan_out() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_graph_fan_out: 1,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(171), None).unwrap());
    let replay_consumer_graph_id = service.replay_consumer_graph_id();
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(172),
        )
        .unwrap();
    let weaver = service.worker([TaskKind::ChallengeEdge], key(173)).unwrap();
    let mut first_replay =
        production_replay_bundle("hunt:phase286:fan-out:first", 1_700_000_095_000);
    first_replay.event = network_event(&first_replay.audit.hunt_id, "198.51.100.10");
    let mut second_replay =
        production_replay_bundle("hunt:phase286:fan-out:second", 1_700_000_095_100);
    second_replay.event = network_event(&second_replay.audit.hunt_id, "198.51.100.11");

    let first = service.submit_replay(&first_replay).unwrap();
    let challenge = weaver
        .next_challenge_context(GraphLogicalTime::new(1_700_000_095_001))
        .unwrap()
        .unwrap();
    assert!(
        weaver
            .complete_challenge(&challenge.task_id, GraphLogicalTime::new(1_700_000_095_001),)
            .unwrap()
    );
    let completion = stalker
        .complete_stalker_hunt(
            &first_replay.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_095_002),
            9_000,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 1);

    let second = service.submit_replay(&second_replay).unwrap();
    assert_ne!(second.graph_id, first.graph_id);
    assert_eq!(service.replay_consumer_graph_id(), replay_consumer_graph_id);
    assert_eq!(service.summary().unwrap().metrics.campaign_rotations, 1);
    assert_eq!(
        service
            .operator_projection_for(&first.graph_id)
            .unwrap()
            .graph
            .edges
            .len(),
        1
    );
    assert_eq!(service.operator_projection().unwrap().graph.edges.len(), 1);
}

#[test]
fn full_campaign_rotates_after_terminal_work_and_preserves_archived_queries() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "swarm-phase286-campaign-rotation-{}-{unique}",
        std::process::id()
    ));
    let config = HypothesisGraphConfig {
        enabled: true,
        state_store: BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        },
        max_hypotheses: 2,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service_key = key(141);
    let stalker_key = key(142);
    let weaver_key = key(143);
    let first_replay = production_replay_bundle("hunt:phase286:campaign:first", 1_700_000_100_000);
    let second_replay =
        production_replay_bundle("hunt:phase286:campaign:second", 1_700_000_100_100);
    let service =
        Arc::new(CollectiveHypothesisService::new(&config, service_key.clone(), None).unwrap());
    let replay_consumer_graph_id = service.replay_consumer_graph_id();
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key.clone(),
        )
        .unwrap();
    let weaver = service
        .worker([TaskKind::ChallengeEdge], weaver_key.clone())
        .unwrap();
    let first = service.submit_replay(&first_replay).unwrap();
    let blocked = service.submit_replay(&second_replay).unwrap_err();
    assert!(matches!(
        blocked,
        swarm_runtime::hypothesis_graph::GraphServiceError::CampaignRotationBlocked {
            outstanding_tasks: 5,
            ..
        }
    ));

    let mut challenge_graph_id = None;
    while let Some(challenge) = weaver
        .next_challenge_context(GraphLogicalTime::new(1_700_000_100_001))
        .unwrap()
    {
        assert_eq!(challenge.graph_id, first.graph_id);
        challenge_graph_id = Some(challenge.graph_id.clone());
        assert!(
            weaver
                .complete_challenge(&challenge.task_id, GraphLogicalTime::new(1_700_000_100_001),)
                .unwrap()
        );
    }
    let completion = stalker
        .complete_stalker_hunt(
            &first_replay.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_100_002),
            9_700,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 1);

    let second = service.submit_replay(&second_replay).unwrap();
    assert_ne!(second.graph_id, first.graph_id);
    assert_eq!(challenge_graph_id.as_ref(), Some(&first.graph_id));
    assert_eq!(service.graph_id(), second.graph_id);
    assert_eq!(service.replay_consumer_graph_id(), replay_consumer_graph_id);
    assert_eq!(service.summary().unwrap().metrics.campaign_rotations, 1);
    let summaries = service.summaries().unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].graph_id, second.graph_id);
    assert_eq!(summaries[1].graph_id, first.graph_id);
    assert_eq!(summaries[0].evidence_count, 1);
    assert_eq!(summaries[1].evidence_count, 1);
    let archived = service.operator_projection_for(&first.graph_id).unwrap();
    assert_eq!(archived.graph.evidence.len(), 1);
    assert_eq!(archived.tasks.len(), 5);
    assert!(archived.tasks.iter().all(|task| matches!(
        task.state,
        swarm_core::hypothesis_graph::TaskState::Completed
            | swarm_core::hypothesis_graph::TaskState::Failed
    )));
    let first_task_page = service
        .operator_task_page_for(&first.graph_id, None, 2)
        .unwrap();
    assert_eq!(first_task_page.len(), 2);
    let task_cursor = first_task_page.last().unwrap();
    let second_task_page = service
        .operator_task_page_for(
            &first.graph_id,
            Some((
                task_cursor.request.requested_at,
                task_cursor.request.task_id.as_str(),
            )),
            2,
        )
        .unwrap();
    assert_eq!(second_task_page.len(), 2);
    let task_cursor = second_task_page.last().unwrap();
    let third_task_page = service
        .operator_task_page_for(
            &first.graph_id,
            Some((
                task_cursor.request.requested_at,
                task_cursor.request.task_id.as_str(),
            )),
            2,
        )
        .unwrap();
    assert_eq!(third_task_page.len(), 1);
    assert!(
        first_task_page
            .iter()
            .chain(&second_task_page)
            .chain(&third_task_page)
            .map(|task| task.request.task_id.clone())
            .collect::<BTreeSet<_>>()
            .len()
            == 5
    );
    assert_eq!(
        service
            .operator_memory_page_for(&first.graph_id, None, 1)
            .unwrap()
            .len(),
        1
    );
    let first_retry = service.submit_replay(&first_replay).unwrap();
    assert!(first_retry.idempotent);
    assert_eq!(first_retry.graph_id, first.graph_id);
    assert_eq!(first_retry.task_ids, first.task_ids);

    drop(stalker);
    drop(weaver);
    drop(service);
    let restarted = Arc::new(CollectiveHypothesisService::new(&config, service_key, None).unwrap());
    restarted
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            stalker_key,
        )
        .unwrap();
    restarted
        .worker([TaskKind::ChallengeEdge], weaver_key)
        .unwrap();
    assert_eq!(restarted.graph_id(), second.graph_id);
    assert_eq!(
        restarted.replay_consumer_graph_id(),
        replay_consumer_graph_id
    );
    assert_eq!(restarted.summary().unwrap().metrics.campaign_rotations, 1);
    let restarted_summaries = restarted.summaries().unwrap();
    assert_eq!(restarted_summaries.len(), 2);
    assert_eq!(restarted_summaries[0].graph_id, second.graph_id);
    assert_eq!(restarted_summaries[1].graph_id, first.graph_id);
    let retry_after_restart = restarted.submit_replay(&first_replay).unwrap();
    assert!(retry_after_restart.idempotent);
    assert_eq!(retry_after_restart.graph_id, first.graph_id);
    assert_eq!(
        restarted
            .operator_projection_for(&first.graph_id)
            .unwrap()
            .digest,
        archived.digest
    );
    drop(restarted);

    let head_path = root.join("campaign-head.json");
    let authenticated_head = fs::read(&head_path).unwrap();
    let mut tampered_head: serde_json::Value = serde_json::from_slice(&authenticated_head).unwrap();
    tampered_head["latest_index"] = serde_json::json!(0);
    fs::write(&head_path, serde_json::to_vec(&tampered_head).unwrap()).unwrap();
    assert!(matches!(
        CollectiveHypothesisService::new(&config, key(141), None),
        Err(swarm_runtime::hypothesis_graph::GraphServiceError::InvalidCampaignHead { .. })
    ));

    fs::write(&head_path, &authenticated_head).unwrap();
    fs::remove_file(&head_path).unwrap();
    assert!(matches!(
        CollectiveHypothesisService::new(&config, key(141), None),
        Err(swarm_runtime::hypothesis_graph::GraphServiceError::MissingCampaignHead { .. })
    ));

    fs::write(&head_path, &authenticated_head).unwrap();
    fs::remove_dir_all(root.join("campaigns").join("1")).unwrap();
    assert!(matches!(
        CollectiveHypothesisService::new(&config, key(141), None),
        Err(
            swarm_runtime::hypothesis_graph::GraphServiceError::CampaignIndexMismatch {
                latest_index: 1,
                ..
            }
        )
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn campaign_admission_reserves_memory_for_each_outstanding_falsification() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_memory_records: 1,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(144), None).unwrap());
    service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(145),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(146)).unwrap();
    service
        .submit_replay(&production_replay_bundle(
            "hunt:phase286:memory-reservation:first",
            1_700_000_110_000,
        ))
        .unwrap();

    let blocked = service
        .submit_replay(&production_replay_bundle(
            "hunt:phase286:memory-reservation:second",
            1_700_000_110_100,
        ))
        .unwrap_err();
    assert!(matches!(
        blocked,
        swarm_runtime::hypothesis_graph::GraphServiceError::CampaignRotationBlocked {
            outstanding_tasks: 5,
            ..
        }
    ));
}

#[test]
fn no_finding_falsification_releases_its_memory_reservation() {
    let config = HypothesisGraphConfig {
        enabled: true,
        max_memory_records: 1,
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(186), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(187),
        )
        .unwrap();
    service.worker([TaskKind::ChallengeEdge], key(190)).unwrap();
    let first = production_replay_bundle(
        "hunt:phase286:no-finding-releases-memory",
        1_700_000_111_000,
    );
    service.submit_replay(&first).unwrap();
    let completion = stalker
        .complete_stalker_hunt(
            &first.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_111_001),
            5_000,
            false,
            false,
        )
        .unwrap();
    assert_eq!(completion.falsification_no_findings, 1);
    assert_eq!(completion.memory_records_projected, 0);
    let original_graph_id = service.graph_id();

    service
        .submit_replay(&production_replay_bundle(
            "hunt:phase286:memory-after-no-finding",
            1_700_000_111_100,
        ))
        .unwrap();
    assert_eq!(service.graph_id(), original_graph_id);
}

#[test]
fn committed_completion_survives_a_persistently_unavailable_memory_projection() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "swarm-phase286-memory-projection-failure-{}-{unique}",
        std::process::id()
    ));
    let config = HypothesisGraphConfig {
        enabled: true,
        state_store: BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        },
        max_work_units_per_tick: 32,
        max_claims_per_tick: 16,
        ..HypothesisGraphConfig::default()
    };
    let service = Arc::new(CollectiveHypothesisService::new(&config, key(147), None).unwrap());
    let stalker = service
        .worker(
            [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
            key(148),
        )
        .unwrap();
    let weaver = service.worker([TaskKind::ChallengeEdge], key(149)).unwrap();
    let replay = production_replay_bundle(
        "hunt:phase286:persistent-memory-projection-failure",
        1_700_000_120_000,
    );
    service.submit_replay(&replay).unwrap();

    let memory_root = root.join("strategy-memory");
    fs::rename(&memory_root, root.join("strategy-memory-unavailable")).unwrap();
    fs::write(&memory_root, b"projection backend unavailable").unwrap();

    let admitted_while_degraded = service
        .submit_replay(&production_replay_bundle(
            "hunt:phase286:admitted-during-memory-projection-failure",
            1_700_000_120_100,
        ))
        .unwrap();
    assert!(!admitted_while_degraded.idempotent);
    assert!(
        weaver
            .next_challenge_context(GraphLogicalTime::new(1_700_000_120_101))
            .unwrap()
            .is_some()
    );
    assert!(
        weaver
            .claim_next(GraphLogicalTime::new(1_700_000_120_101))
            .unwrap()
            .is_some()
    );

    let completion = stalker
        .complete_stalker_hunt(
            &replay.audit.hunt_id,
            GraphLogicalTime::new(1_700_000_120_001),
            9_700,
            false,
            true,
        )
        .unwrap();
    assert_eq!(completion.acquisitions, 1);
    assert_eq!(completion.falsifications, 1);
    assert_eq!(completion.memory_records_projected, 0);
    let snapshot = service.store().unwrap().snapshot().unwrap();
    assert_eq!(
        snapshot
            .tasks()
            .filter(|task| task.task.state == swarm_core::hypothesis_graph::TaskState::Completed)
            .count(),
        2
    );
    assert!(service.summary().is_err());

    drop(stalker);
    drop(service);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn disabled_hypothesis_graph_preserves_legacy_runtime() {
    let config = HypothesisGraphConfig::default();
    assert!(!config.enabled);
    assert!(
        CollectiveHypothesisService::from_config(&config, key(114), None)
            .unwrap()
            .is_none()
    );
    let serialized = serde_json::to_value(&config).unwrap();
    assert!(serialized.get("state_store").is_none());

    let signer = key(115);
    let mut legacy = HypothesisGraphRuntime::new(clock(), EvidenceRegistry::with_key(&signer));
    legacy
        .scheduler
        .schedule_task(
            GraphLogicalTime::new(1),
            TaskKind::AcquireEvidence,
            100,
            TaskId::new("task:legacy-disabled-phase286"),
        )
        .unwrap();
    assert!(legacy.budget.is_none());
    assert!(
        legacy
            .pop_ready_budgeted(GraphLogicalTime::new(1), u32::MAX, u16::MAX)
            .unwrap()
            .is_some()
    );
}

#[test]
fn collective_reasoning_beats_single_agent_baseline() {
    let repository_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let report = run_collective_benchmark(&repository_root).unwrap();
    assert!(report.verdict.passed, "{:?}", report.verdict.failed_gates);
    assert!(
        report.collective.median_hypothesis_time_ms < report.single_agent.median_hypothesis_time_ms
    );
    assert!(
        report.collective.attack_chain_recall_bps > report.single_agent.attack_chain_recall_bps
    );
    if let Ok(path) = std::env::var("COLLECTIVE_HYPOTHESIS_REPORT_PATH") {
        fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
}
