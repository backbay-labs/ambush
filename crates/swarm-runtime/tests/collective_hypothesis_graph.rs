//! Stable runtime behavior for the collective-hypothesis graph core slice.
//!
//! This target is intentionally separate from the sealed oracle target.  It
//! exercises normalization, witness admission, idempotency, and explicit
//! source conflicts without changing the oracle's truth fixtures.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use swarm_core::config::HypothesisGraphConfig;
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
use swarm_core::types::AgentId;
use swarm_core::{
    AuthenticationEventData, CloudTrailEvent, DnsQueryEvent, KubernetesAuditEvent,
    NetworkConnectEvent, ProcessStartEvent, TelemetryEvent, TelemetryPayload, ThreatIntelEntry,
    ThreatIntelIndicatorType,
};
use swarm_crypto::Keypair;
use swarm_runtime::hypothesis_graph::{
    DeterministicScheduler, DurableHypothesisCoordinator, EvidenceAdmissionError,
    EvidenceAdmissionOutcome, EvidenceRegistry, FixedGraphClock, GraphRecordSigner,
    HypothesisGraphRuntime, HypothesisTaskLedger, KeypairGraphRecordSigner,
    MAX_RAW_PROJECTION_BYTES, MAX_RAW_PROJECTION_DEPTH, MAX_RAW_PROJECTION_NODES,
    MAX_SOURCE_TEXT_BYTES, SourceTimestampUnit, WitnessAdmission, normalize_source_timestamp,
    normalize_telemetry_event, normalize_telemetry_event_with_unit, normalize_threat_intel_entry,
};
use swarm_spine::{
    FileHypothesisGraphStore, GraphStoreRevision, GraphStoreSnapshot, GraphStoreState,
    HypothesisGraphStore, MemoryHypothesisGraphStore, ReasoningStateUpdate,
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
fn conflict_detection_is_insertion_order_invariant() {
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
        first.conflicts().keys().collect::<Vec<_>>(),
        second.conflicts().keys().collect::<Vec<_>>()
    );
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
        max_work_units_per_tick: 2,
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
            .pop_ready_budgeted(GraphLogicalTime::new(100), 2, 1)
            .unwrap()
            .is_some()
    );
    let used_budget = runtime.budget.as_ref().unwrap();
    assert_eq!(used_budget.work_units_used(), 2);
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
        max_work_units_per_tick: 2,
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
    tampered_wire["max_work_units"] = serde_json::json!(3);
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
        enabled: true,
        max_work_units_per_tick: 4,
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
    assert_eq!(coordinator.ledger().scheduler_budget().max_work_units, 4);
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
    assert_eq!(first.task_ids.len(), 4);
    assert_eq!(first.snapshot.state().tasks.len(), 4);
    let persisted_budget = first.snapshot.scheduler_budget().unwrap().clone();
    assert_eq!(persisted_budget.current_tick(), tick);
    assert_eq!(persisted_budget.work_units_used(), 4);
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
    assert_eq!(claimed_budget.work_units_used(), 4);
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
    let before_exhausted = store.snapshot().unwrap();
    let before_exhausted_bytes = before_exhausted.canonical_bytes().unwrap();
    let budget_before_exhausted = restarted.ledger().scheduler_budget().clone();
    assert!(
        restarted
            .coordinate_seed(
                &store,
                before_exhausted.revision(),
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
    assert_eq!(reset_budget.work_units_used(), 4);
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
    let initial = store.snapshot().unwrap();
    let reasoning_state = GraphStoreState::with_reasoning_state(
        initial.state().clone(),
        ReasoningStateUpdate::migration_to_hypotheses(
            config.resource_limits(),
            GraphLogicalTime::new(100),
        )
        .with_hypotheses(BTreeMap::from([(hypothesis_id.clone(), hypothesis)]))
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
