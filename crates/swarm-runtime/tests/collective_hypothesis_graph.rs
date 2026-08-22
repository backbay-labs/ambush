//! Stable runtime behavior for the collective-hypothesis graph core slice.
//!
//! This target is intentionally separate from the sealed oracle target.  It
//! exercises normalization, witness admission, idempotency, and explicit
//! source conflicts without changing the oracle's truth fixtures.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use swarm_core::hypothesis_graph::{
    CausalEdge, CausalRelation, DecisionKind, DecisionRecord, EdgeState, EvidenceEnvelope,
    EvidenceSourceFamily, GraphAdmissionError, GraphId, GraphLogicalTime, GraphNodeId,
    GraphProducerRole, GraphResourceLimits, HypothesisId, TypedEvidencePayload,
};
use swarm_core::types::AgentId;
use swarm_core::{
    AuthenticationEventData, CloudTrailEvent, DnsQueryEvent, KubernetesAuditEvent,
    NetworkConnectEvent, ProcessStartEvent, TelemetryEvent, TelemetryPayload, ThreatIntelEntry,
    ThreatIntelIndicatorType,
};
use swarm_crypto::Keypair;
use swarm_runtime::hypothesis_graph::{
    EvidenceAdmissionError, EvidenceAdmissionOutcome, EvidenceRegistry, FixedGraphClock,
    GraphRecordSigner, HypothesisGraphRuntime, KeypairGraphRecordSigner, MAX_RAW_PROJECTION_BYTES,
    MAX_RAW_PROJECTION_DEPTH, MAX_RAW_PROJECTION_NODES, MAX_SOURCE_TEXT_BYTES, SourceTimestampUnit,
    WitnessAdmission, normalize_source_timestamp, normalize_telemetry_event,
    normalize_telemetry_event_with_unit, normalize_threat_intel_entry,
};

fn key(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn clock() -> FixedGraphClock {
    FixedGraphClock::new(GraphLogicalTime::new(1_700_000_010_000))
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
