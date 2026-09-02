//! Strict adapters from already-normalized telemetry into graph evidence.
//!
//! The ingest crates and `swarm-whisker` own vendor parsing.  This module only
//! consumes their typed records, bounds any legacy `serde_json::Value` fields
//! before hashing them, and emits typed evidence families. Raw
//! request/response objects, command lines, credentials, and host labels never
//! cross the evidence-envelope boundary.

use serde::Serialize;
use serde_json::Value;
use swarm_core::hypothesis_graph::{
    ActorNode, AssetNode, ClockPrecision, CredentialNode, EventNode, EvidenceClock,
    EvidenceEnvelope, EvidenceSourceFamily, GraphAdmissionError, GraphLogicalTime, GraphNode,
    GraphProducerRole, OrderingClaim, ProcessNode, SourceLineage, TypedEvidencePayload,
};
use swarm_core::{
    AuthenticationEventData, CloudTrailEvent, DnsQueryEvent, KubernetesAuditEvent,
    NetworkConnectEvent, ProcessMemoryAccessEvent, ProcessStartEvent, TelemetryEvent,
    TelemetryPayload, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_crypto::{Keypair, canonical_json_bytes, sha256_hex};

use super::clock::GraphClock;

/// One normalized evidence envelope plus the exact typed graph nodes used to
/// derive its entity identifiers. Runtime admission can therefore materialize
/// inferred causal endpoints without reconstructing or aliasing identities.
#[derive(Debug, Clone)]
pub(crate) struct NormalizedGraphEvidence {
    pub(crate) evidence: EvidenceEnvelope,
    pub(crate) nodes: Vec<GraphNode>,
}

#[derive(Debug)]
struct NormalizedPayload {
    payload: TypedEvidencePayload,
    nodes: Vec<GraphNode>,
}

/// Maximum size of a single source text field accepted by an adapter.
pub const MAX_SOURCE_TEXT_BYTES: usize = 16 * 1024;
/// Maximum canonical size of a legacy structured request/response projection.
pub const MAX_RAW_PROJECTION_BYTES: usize = 16 * 1024;
/// Maximum nesting depth of a legacy structured request/response projection.
pub const MAX_RAW_PROJECTION_DEPTH: usize = 16;
/// Maximum number of values in a legacy structured request/response projection.
pub const MAX_RAW_PROJECTION_NODES: usize = 512;
const MAX_SOURCE_LIST_ITEMS: usize = 64;

/// Prefix emitted by the Tetragon adapter when process-start time was absent
/// and the mapper had to use its host clock.  Host fallback time is useful for
/// operational detection telemetry, but is not a causal observation and must
/// never enter a graph evidence identity.
pub const TETRAGON_FALLBACK_TIME_EVENT_ID_PREFIX: &str = "tetragon:fallback_time:";
/// Optional source marker accepted by the graph boundary for adapters that
/// carry fallback origin in `TelemetryEvent::source` instead of the event ID.
pub const TETRAGON_FALLBACK_TIME_SOURCE_MARKER: &str = "tetragon:fallback_time";

/// Unit declared by an upstream telemetry adapter for its source timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceTimestampUnit {
    Seconds,
    Milliseconds,
}

/// Normalize one existing telemetry event into a signed evidence envelope.
pub fn normalize_telemetry<C: GraphClock + ?Sized>(
    event: &TelemetryEvent,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    normalize_telemetry_with_unit(
        event,
        legacy_timestamp_unit(event.timestamp),
        clock,
        signer,
        role,
        scoped_agent_id,
    )
}

/// Normalize telemetry when the upstream adapter has explicitly declared its
/// timestamp unit.  New source adapters should use this entry point; the
/// compatibility wrapper above retains the legacy epoch-size heuristic.
pub fn normalize_telemetry_with_unit<C: GraphClock + ?Sized>(
    event: &TelemetryEvent,
    timestamp_unit: SourceTimestampUnit,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    normalize_telemetry_graph_with_unit(event, timestamp_unit, clock, signer, role, scoped_agent_id)
        .map(|normalized| normalized.evidence)
}

fn normalize_telemetry_graph_with_unit<C: GraphClock + ?Sized>(
    event: &TelemetryEvent,
    timestamp_unit: SourceTimestampUnit,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<NormalizedGraphEvidence, GraphAdmissionError> {
    if event.source == TETRAGON_FALLBACK_TIME_SOURCE_MARKER
        || event
            .event_id
            .starts_with(TETRAGON_FALLBACK_TIME_EVENT_ID_PREFIX)
    {
        return Err(GraphAdmissionError::InvalidField {
            field: "telemetry.timestamp".to_string(),
            reason: "Tetragon host-clock fallback is operational-only and cannot become graph causal time"
                .to_string(),
        });
    }
    let source_id = bounded_text("telemetry.source", &event.source, 256)?;
    let source_record_id = bounded_text("telemetry.event_id", &event.event_id, 256)?;
    let (observed_at, precision, uncertainty_ms) =
        normalize_source_timestamp(event.timestamp, timestamp_unit)?;
    let evidence_clock = clock_for(observed_at, precision, uncertainty_ms, clock)?;
    let (source_family, signal_kind, normalized) = match &event.payload {
        TelemetryPayload::ProcessStart(process) => (
            EvidenceSourceFamily::Process,
            "process_start",
            process_payload(process, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::ProcessMemoryAccess(access) => (
            EvidenceSourceFamily::Process,
            "process_memory_access",
            process_memory_payload(access, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::RegistryAccess(access) => (
            EvidenceSourceFamily::Process,
            "registry_access",
            registry_access_payload(access, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::RegistryPersistence(persistence) => (
            EvidenceSourceFamily::Process,
            "registry_persistence",
            registry_persistence_payload(persistence, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::FilePersistence(persistence) => (
            EvidenceSourceFamily::Process,
            "file_persistence",
            file_persistence_payload(persistence, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::AuthenticationEvent(authentication) => (
            EvidenceSourceFamily::Identity,
            "authentication_event",
            identity_payload(authentication, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::KubernetesAudit(audit) => (
            EvidenceSourceFamily::Kubernetes,
            "kubernetes_audit",
            kubernetes_payload(audit, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::CloudTrail(cloudtrail) => (
            EvidenceSourceFamily::Cloudtrail,
            "cloudtrail",
            cloudtrail_payload(cloudtrail, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::NetworkConnect(network) => (
            EvidenceSourceFamily::Network,
            "network_connect",
            network_payload(
                network,
                event.host_id.as_deref(),
                &source_id,
                &source_record_id,
                observed_at,
            )?,
        ),
        TelemetryPayload::DnsQuery(dns) => (
            EvidenceSourceFamily::Network,
            "dns_query",
            dns_payload(dns, &source_id, &source_record_id, observed_at)?,
        ),
        TelemetryPayload::InfrastructureHealth(health) => (
            EvidenceSourceFamily::Infrastructure,
            "infrastructure_health",
            infrastructure_payload(
                "infrastructure_health",
                &health.node_name,
                health,
                &source_id,
                &source_record_id,
                observed_at,
            )?,
        ),
        TelemetryPayload::ThermalAnomaly(thermal) => (
            EvidenceSourceFamily::Infrastructure,
            "thermal_anomaly",
            infrastructure_payload(
                "thermal_anomaly",
                &thermal.node_name,
                thermal,
                &source_id,
                &source_record_id,
                observed_at,
            )?,
        ),
        TelemetryPayload::ResourceExhaustion(exhaustion) => (
            EvidenceSourceFamily::Infrastructure,
            "resource_exhaustion",
            infrastructure_payload(
                "resource_exhaustion",
                &exhaustion.node_name,
                exhaustion,
                &source_id,
                &source_record_id,
                observed_at,
            )?,
        ),
    };

    let lineage = SourceLineage::new(format!("telemetry:{signal_kind}"), source_record_id)?;
    let envelope = EvidenceEnvelope::new(
        source_family,
        source_id,
        lineage,
        evidence_clock,
        OrderingClaim::Unknown,
        normalized.payload,
    )?;
    let evidence = envelope.sign_with(signer, role, scoped_agent_id)?;
    Ok(NormalizedGraphEvidence {
        evidence,
        nodes: normalized.nodes,
    })
}

/// Compatibility alias with the name used by the plan and integration tests.
pub fn normalize_telemetry_event<C: GraphClock + ?Sized>(
    event: &TelemetryEvent,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    normalize_telemetry(event, clock, signer, role, scoped_agent_id)
}

/// Normalize telemetry for durable graph admission, retaining the exact typed
/// nodes whose IDs appear in the evidence payload.
pub(crate) fn normalize_telemetry_event_for_graph<C: GraphClock + ?Sized>(
    event: &TelemetryEvent,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<NormalizedGraphEvidence, GraphAdmissionError> {
    normalize_telemetry_graph_with_unit(
        event,
        legacy_timestamp_unit(event.timestamp),
        clock,
        signer,
        role,
        scoped_agent_id,
    )
}

/// Explicit-unit alias matching the event-oriented adapter name.
pub fn normalize_telemetry_event_with_unit<C: GraphClock + ?Sized>(
    event: &TelemetryEvent,
    timestamp_unit: SourceTimestampUnit,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    normalize_telemetry_with_unit(event, timestamp_unit, clock, signer, role, scoped_agent_id)
}

/// Normalize a threat-intelligence entry already admitted by the existing
/// threat-intel substrate.  The caller supplies its observed time because the
/// legacy entry has an expiry but no observation timestamp.
pub fn normalize_threat_intel<C: GraphClock + ?Sized>(
    entry: &ThreatIntelEntry,
    source_record_id: impl Into<String>,
    observed_at: GraphLogicalTime,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    normalize_threat_intel_at(
        entry,
        source_record_id,
        observed_at,
        clock,
        signer,
        role,
        scoped_agent_id,
    )
}

/// Normalize threat intelligence with the core logical-time type directly.
pub fn normalize_threat_intel_at<C: GraphClock + ?Sized>(
    entry: &ThreatIntelEntry,
    source_record_id: impl Into<String>,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    let source_record_id = source_record_id.into();
    let source_record_id = bounded_text("threat_intel.source_record_id", &source_record_id, 256)?;
    observed_at.validate()?;
    if entry.expires_at < 0 {
        return Err(GraphAdmissionError::InvalidField {
            field: "threat_intel.expires_at".to_string(),
            reason: "must be non-negative milliseconds".to_string(),
        });
    }
    if entry.expires_at <= observed_at.as_millis() {
        return Err(GraphAdmissionError::InvalidField {
            field: "threat_intel.expires_at".to_string(),
            reason: "must be strictly later than the observation time".to_string(),
        });
    }
    let source_id = bounded_text("threat_intel.source", &entry.source, 256)?;
    let indicator_value = bounded_text("threat_intel.value", &entry.value, 4 * 1024)?;
    if !entry.confidence.is_finite() || !(0.0..=1.0).contains(&entry.confidence) {
        return Err(GraphAdmissionError::InvalidField {
            field: "threat_intel.confidence".to_string(),
            reason: "must be a finite value between 0.0 and 1.0".to_string(),
        });
    }
    let indicator_id = optional_text(
        "threat_intel.indicator_id",
        entry.indicator_id.as_deref(),
        256,
    )?;
    let indicator_kind = indicator_kind(&entry.indicator_type);
    let indicator_digest = digest_projection(&("indicator", indicator_kind, &indicator_value))?;
    let event_node_source_record_id = event_node_source_record_id(&source_id, &source_record_id)?;
    let event_node = EventNode::new(
        "threat_intelligence",
        event_node_source_record_id,
        observed_at,
    )?;
    let indicator_node = AssetNode::new(indicator_digest.clone(), indicator_kind)?;
    let expires_at = GraphLogicalTime::new(entry.expires_at);
    expires_at.validate()?;
    let content_digest = digest_projection(&(
        "threat_intelligence",
        indicator_kind,
        &indicator_value,
        &source_id,
        &indicator_id,
        entry.confidence.to_bits(),
        entry.expires_at,
    ))?;
    let payload = TypedEvidencePayload::ThreatIntelligence {
        signal_kind: "threat_intelligence".to_string(),
        feed_id: source_id.clone(),
        indicator_digest,
        indicator_kind: indicator_kind.to_string(),
        confidence_basis_points: confidence_basis_points(entry.confidence),
        expires_at,
        entity_ids: vec![event_node.node_id, indicator_node.node_id],
        content_digest,
    };
    let evidence_clock = clock_for(observed_at, ClockPrecision::Millisecond, 0, clock)?;
    let lineage = SourceLineage::new("threat_intelligence", source_record_id)?;
    let lineage = if let Some(indicator_id) = indicator_id {
        lineage.with_upstream([indicator_id])?
    } else {
        lineage
    };
    EvidenceEnvelope::new(
        EvidenceSourceFamily::ThreatIntelligence,
        source_id,
        lineage,
        evidence_clock,
        OrderingClaim::Unknown,
        payload,
    )?
    .sign_with(signer, role, scoped_agent_id)
}

/// Compatibility alias for callers that use the source record's type name.
pub fn normalize_threat_intel_entry<C: GraphClock + ?Sized>(
    entry: &ThreatIntelEntry,
    source_record_id: impl Into<String>,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
    clock: &C,
    signer: &Keypair,
    role: GraphProducerRole,
    scoped_agent_id: impl Into<String>,
) -> Result<EvidenceEnvelope, GraphAdmissionError> {
    normalize_threat_intel_at(
        entry,
        source_record_id,
        observed_at,
        clock,
        signer,
        role,
        scoped_agent_id,
    )
}

fn clock_for<C: GraphClock + ?Sized>(
    observed_at: GraphLogicalTime,
    precision: ClockPrecision,
    uncertainty_ms: u64,
    clock: &C,
) -> Result<EvidenceClock, GraphAdmissionError> {
    let ingested_at = GraphLogicalTime::new(clock.now_ms());
    ingested_at.validate()?;
    let evidence_clock = EvidenceClock {
        observed_at,
        ingested_at: Some(ingested_at),
        precision,
        uncertainty_ms,
    };
    evidence_clock.validate()?;
    Ok(evidence_clock)
}

pub fn normalize_source_timestamp(
    timestamp: i64,
    unit: SourceTimestampUnit,
) -> Result<(GraphLogicalTime, ClockPrecision, u64), GraphAdmissionError> {
    if timestamp < 0 {
        return Err(GraphAdmissionError::InvalidField {
            field: "telemetry.timestamp".to_string(),
            reason: "must be non-negative".to_string(),
        });
    }
    match unit {
        SourceTimestampUnit::Seconds => {
            let millis =
                timestamp
                    .checked_mul(1_000)
                    .ok_or_else(|| GraphAdmissionError::InvalidField {
                        field: "telemetry.timestamp".to_string(),
                        reason: "seconds value overflows milliseconds".to_string(),
                    })?;
            Ok((GraphLogicalTime::new(millis), ClockPrecision::Second, 999))
        }
        SourceTimestampUnit::Milliseconds => Ok((
            GraphLogicalTime::new(timestamp),
            ClockPrecision::Millisecond,
            0,
        )),
    }
}

fn legacy_timestamp_unit(timestamp: i64) -> SourceTimestampUnit {
    if timestamp.unsigned_abs() < 100_000_000_000 {
        SourceTimestampUnit::Seconds
    } else {
        SourceTimestampUnit::Milliseconds
    }
}

fn process_payload(
    process: &ProcessStartEvent,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let parent_process = match process.parent_process.trim() {
        "" | "<none>" | "none" | "unknown" => None,
        value => Some(bounded_text("process.parent_process", value, 4 * 1024)?),
    };
    let process_name = bounded_text("process.process_name", &process.process_name, 4 * 1024)?;
    let command_line = bounded_text(
        "process.command_line",
        &process.command_line,
        MAX_SOURCE_TEXT_BYTES,
    )?;
    let user = optional_text("process.user", process.user.as_deref(), 4 * 1024)?;
    let executable_path = optional_text(
        "process.executable_path",
        process.executable_path.as_deref(),
        4 * 1024,
    )?;
    let signer = optional_text("process.signer", process.signer.as_deref(), 4 * 1024)?;
    let process_digest = digest_projection(&(
        "process",
        &process_name,
        &command_line,
        &user,
        &signer,
        process.signature_valid,
    ))?;
    let executable_digest = digest_projection(&("executable", &executable_path))?;
    let parent_digest = parent_process
        .as_deref()
        .map(|parent_process| digest_projection(&("parent_process", parent_process)))
        .transpose()?;
    let parent_node = parent_digest
        .as_deref()
        .map(|digest| {
            let parent_executable_digest = digest_projection(&("parent_executable", digest))?;
            ProcessNode::new(digest, parent_executable_digest)
        })
        .transpose()?;
    let process_node = match parent_node.as_ref() {
        Some(parent) => ProcessNode::new_with_parent(
            process_digest.clone(),
            executable_digest,
            parent.node_id.clone(),
        )?,
        None => ProcessNode::new(process_digest.clone(), executable_digest)?,
    };
    let event_node_source_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event_node = EventNode::new("process_start", event_node_source_record_id, observed_at)?;
    let mut entity_ids = vec![process_node.node_id.clone(), event_node.node_id.clone()];
    if let Some(parent) = parent_node.as_ref() {
        entity_ids.push(parent.node_id.clone());
    }
    let mut nodes = parent_node
        .into_iter()
        .map(GraphNode::Process)
        .collect::<Vec<_>>();
    nodes.push(GraphNode::Process(process_node));
    nodes.push(GraphNode::Event(event_node));
    if let Some(user) = user.as_deref() {
        let actor = ActorNode::new(digest_projection(&("user", user))?, "process_user")?;
        entity_ids.push(actor.node_id.clone());
        nodes.push(GraphNode::Actor(actor));
    }
    let content_digest = digest_projection(&(
        "process_start",
        &parent_process,
        &process_name,
        &command_line,
        &user,
        &executable_path,
        &signer,
        process.signature_valid,
    ))?;
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Process {
            signal_kind: "process_start".to_string(),
            process_digest,
            parent_process_digest: parent_digest,
            entity_ids,
            content_digest,
        },
        nodes,
    })
}

fn process_memory_payload(
    access: &ProcessMemoryAccessEvent,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let source = bounded_text(
        "process_memory.source_process",
        &access.source_process,
        4 * 1024,
    )?;
    let target = bounded_text(
        "process_memory.target_process",
        &access.target_process,
        4 * 1024,
    )?;
    let allocation = bounded_text(
        "process_memory.allocation_type",
        &access.allocation_type,
        512,
    )?;
    let call_stack = optional_text(
        "process_memory.call_stack_hint",
        access.call_stack_hint.as_deref(),
        8 * 1024,
    )?;
    ensure_list_bound(
        "process_memory.protection_flags",
        access.protection_flags.len(),
    )?;
    let protection = access
        .protection_flags
        .iter()
        .map(|flag| bounded_text("process_memory.protection_flag", flag, 128))
        .collect::<Result<Vec<_>, _>>()?;
    let source_digest = digest_projection(&("source_process", &source))?;
    let target_digest = digest_projection(&("target_process", &target))?;
    let source_node = ProcessNode::new(source_digest.clone(), source_digest.clone())?;
    let target_node = ProcessNode::new(target_digest.clone(), target_digest.clone())?;
    let event_node_source_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event_node = EventNode::new(
        "process_memory_access",
        event_node_source_record_id,
        observed_at,
    )?;
    let content_digest = digest_projection(&(
        "process_memory_access",
        &source,
        &target,
        &allocation,
        &protection,
        access.region_size,
        &call_stack,
    ))?;
    let entity_ids = vec![
        source_node.node_id.clone(),
        target_node.node_id.clone(),
        event_node.node_id.clone(),
    ];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Process {
            signal_kind: "process_memory_access".to_string(),
            process_digest: target_digest,
            parent_process_digest: Some(source_digest),
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Process(source_node),
            GraphNode::Process(target_node),
            GraphNode::Event(event_node),
        ],
    })
}

fn registry_access_payload(
    access: &swarm_core::RegistryAccessEvent,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let process = bounded_text("registry.process_name", &access.process_name, 4 * 1024)?;
    let path = bounded_text("registry.registry_path", &access.registry_path, 4 * 1024)?;
    let access_type = bounded_text("registry.access_type", &access.access_type, 512)?;
    let target = optional_text(
        "registry.target_process",
        access.target_process.as_deref(),
        4 * 1024,
    )?;
    process_like_payload(
        "registry_access",
        &process,
        &path,
        &access_type,
        &target,
        EventNodeContext {
            source_id,
            source_record_id,
            observed_at,
        },
    )
}

fn registry_persistence_payload(
    persistence: &swarm_core::RegistryPersistenceEvent,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let process = bounded_text(
        "registry_persistence.process_name",
        &persistence.process_name,
        4 * 1024,
    )?;
    let path = bounded_text(
        "registry_persistence.registry_path",
        &persistence.registry_path,
        4 * 1024,
    )?;
    let value_name = optional_text(
        "registry_persistence.value_name",
        persistence.value_name.as_deref(),
        4 * 1024,
    )?;
    let value_data = optional_text(
        "registry_persistence.value_data",
        persistence.value_data.as_deref(),
        MAX_SOURCE_TEXT_BYTES,
    )?;
    let access_type = bounded_text(
        "registry_persistence.access_type",
        &persistence.access_type,
        512,
    )?;
    let value_name_digest = value_name
        .as_deref()
        .map(|value_name| digest_projection(&("registry_value_name", value_name)))
        .transpose()?;
    let value_data_digest = value_data
        .as_deref()
        .map(|value_data| digest_projection(&("registry_value_data", value_data)))
        .transpose()?;
    let process_digest = digest_projection(&(
        "registry_persistence",
        &process,
        &path,
        &access_type,
        &value_name_digest,
        &value_data_digest,
    ))?;
    let process_node = ProcessNode::new(process_digest.clone(), process_digest.clone())?;
    let event_node_source_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event_node = EventNode::new(
        "registry_persistence",
        event_node_source_record_id,
        observed_at,
    )?;
    let content_digest = digest_projection(&(
        "registry_persistence",
        &process,
        &path,
        &access_type,
        &value_name_digest,
        &value_data_digest,
    ))?;
    let entity_ids = vec![process_node.node_id.clone(), event_node.node_id.clone()];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Process {
            signal_kind: "registry_persistence".to_string(),
            process_digest,
            parent_process_digest: None,
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Process(process_node),
            GraphNode::Event(event_node),
        ],
    })
}

fn file_persistence_payload(
    persistence: &swarm_core::FilePersistenceEvent,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let process = bounded_text(
        "file_persistence.process_name",
        &persistence.process_name,
        4 * 1024,
    )?;
    let path = bounded_text(
        "file_persistence.file_path",
        &persistence.file_path,
        4 * 1024,
    )?;
    let operation = bounded_text("file_persistence.operation", &persistence.operation, 512)?;
    let preview = optional_text(
        "file_persistence.content_preview",
        persistence.content_preview.as_deref(),
        4 * 1024,
    )?;
    process_like_payload(
        "file_persistence",
        &process,
        &path,
        &operation,
        &preview,
        EventNodeContext {
            source_id,
            source_record_id,
            observed_at,
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct EventNodeContext<'a> {
    source_id: &'a str,
    source_record_id: &'a str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
}

fn process_like_payload(
    signal_kind: &str,
    process: &str,
    first_projection: &str,
    second_projection: &str,
    optional_projection: &Option<String>,
    context: EventNodeContext<'_>,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let process_digest =
        digest_projection(&(signal_kind, process, first_projection, second_projection))?;
    let process_node = ProcessNode::new(process_digest.clone(), process_digest.clone())?;
    let event_node_source_record_id =
        event_node_source_record_id(context.source_id, context.source_record_id)?;
    let event_node = EventNode::new(
        signal_kind,
        event_node_source_record_id,
        context.observed_at,
    )?;
    let content_digest = digest_projection(&(
        signal_kind,
        process,
        first_projection,
        second_projection,
        optional_projection,
    ))?;
    let entity_ids = vec![process_node.node_id.clone(), event_node.node_id.clone()];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Process {
            signal_kind: signal_kind.to_string(),
            process_digest,
            parent_process_digest: None,
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Process(process_node),
            GraphNode::Event(event_node),
        ],
    })
}

fn identity_payload(
    authentication: &AuthenticationEventData,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let auth_type = bounded_text("identity.auth_type", &authentication.auth_type, 512)?;
    let source_host = optional_text(
        "identity.source_host",
        authentication.source_host.as_deref(),
        4 * 1024,
    )?;
    let target_host = optional_text(
        "identity.target_host",
        authentication.target_host.as_deref(),
        4 * 1024,
    )?;
    let target_service = optional_text(
        "identity.target_service",
        authentication.target_service.as_deref(),
        4 * 1024,
    )?;
    let process_name = optional_text(
        "identity.process_name",
        authentication.process_name.as_deref(),
        4 * 1024,
    )?;
    let user = optional_text("identity.user", authentication.user.as_deref(), 4 * 1024)?;
    let principal = user
        .clone()
        .or(source_host.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let principal_digest = digest_projection(&("principal", &principal))?;
    let credential_digest =
        digest_projection(&("credential", &auth_type, &target_service, &process_name))?;
    let actor = ActorNode::new(principal_digest.clone(), "identity_principal")?;
    let credential = CredentialNode::new(credential_digest.clone(), "authentication")?;
    let event_node_source_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event_node = EventNode::new(
        "authentication_event",
        event_node_source_record_id,
        observed_at,
    )?;
    let content_digest = digest_projection(&(
        "authentication_event",
        &auth_type,
        &source_host,
        &target_host,
        &target_service,
        &process_name,
        authentication.success,
        &user,
    ))?;
    let entity_ids = vec![
        actor.node_id.clone(),
        credential.node_id.clone(),
        event_node.node_id.clone(),
    ];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Identity {
            signal_kind: "authentication_event".to_string(),
            principal_digest,
            credential_digest: Some(credential_digest),
            success: Some(authentication.success),
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Actor(actor),
            GraphNode::Credential(credential),
            GraphNode::Event(event_node),
        ],
    })
}

fn kubernetes_payload(
    audit: &KubernetesAuditEvent,
    source_id: &str,
    audit_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let verb = bounded_text("kubernetes.verb", &audit.verb, 512)?;
    let resource = bounded_text("kubernetes.resource", &audit.resource, 4 * 1024)?;
    let stage = optional_text("kubernetes.stage", audit.stage.as_deref(), 512)?;
    let username = optional_text("kubernetes.username", audit.username.as_deref(), 4 * 1024)?;
    let namespace = optional_text("kubernetes.namespace", audit.namespace.as_deref(), 4 * 1024)?;
    let subresource = optional_text(
        "kubernetes.subresource",
        audit.subresource.as_deref(),
        4 * 1024,
    )?;
    let resource_name = optional_text(
        "kubernetes.resource_name",
        audit.resource_name.as_deref(),
        4 * 1024,
    )?;
    let api_group = optional_text("kubernetes.api_group", audit.api_group.as_deref(), 4 * 1024)?;
    let user_agent = optional_text(
        "kubernetes.user_agent",
        audit.user_agent.as_deref(),
        4 * 1024,
    )?;
    ensure_list_bound("kubernetes.source_ips", audit.source_ips.len())?;
    let source_ips = audit
        .source_ips
        .iter()
        .map(|ip| bounded_text("kubernetes.source_ip", ip, 256))
        .collect::<Result<Vec<_>, _>>()?;
    ensure_list_bound("kubernetes.user_groups", audit.user_groups.len())?;
    let groups = audit
        .user_groups
        .iter()
        .map(|group| bounded_text("kubernetes.user_group", group, 512))
        .collect::<Result<Vec<_>, _>>()?;
    let impersonated_username = optional_text(
        "kubernetes.impersonated_username",
        audit.impersonated_username.as_deref(),
        4 * 1024,
    )?;
    let annotations_digest = bounded_json_digest("kubernetes.annotations", &audit.annotations)?;
    let request_digest = bounded_json_digest("kubernetes.request_object", &audit.request_object)?;
    let resource_digest = digest_projection(&(
        &resource,
        &namespace,
        &subresource,
        &resource_name,
        &api_group,
    ))?;
    let actor = ActorNode::new(
        digest_projection(&("kubernetes_user", &username, &groups))?,
        "kubernetes_principal",
    )?;
    let asset = AssetNode::new(resource_digest.clone(), "kubernetes_resource")?;
    let event_node_source_record_id = event_node_source_record_id(source_id, audit_id)?;
    let event_node = EventNode::new("kubernetes_audit", event_node_source_record_id, observed_at)?;
    let content_digest = digest_projection(&(
        audit_id,
        &verb,
        &stage,
        &username,
        &groups,
        &source_ips,
        &user_agent,
        &namespace,
        &resource,
        &subresource,
        &resource_name,
        &api_group,
        audit.response_code,
        &annotations_digest,
        &request_digest,
        &impersonated_username,
    ))?;
    let entity_ids = vec![
        actor.node_id.clone(),
        asset.node_id.clone(),
        event_node.node_id.clone(),
    ];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::KubernetesAudit {
            signal_kind: "kubernetes_audit".to_string(),
            audit_id: audit_id.to_string(),
            verb,
            resource_digest,
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Actor(actor),
            GraphNode::Asset(asset),
            GraphNode::Event(event_node),
        ],
    })
}

fn cloudtrail_payload(
    cloudtrail: &CloudTrailEvent,
    source_id: &str,
    event_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let event_name = bounded_text("cloudtrail.event_name", &cloudtrail.event_name, 4 * 1024)?;
    let event_source = bounded_text(
        "cloudtrail.event_source",
        &cloudtrail.event_source,
        4 * 1024,
    )?;
    let account = optional_text(
        "cloudtrail.aws_account_id",
        cloudtrail.aws_account_id.as_deref(),
        256,
    )?;
    let principal_arn = optional_text(
        "cloudtrail.principal_arn",
        cloudtrail.principal_arn.as_deref(),
        4 * 1024,
    )?;
    let principal_id = optional_text(
        "cloudtrail.principal_id",
        cloudtrail.principal_id.as_deref(),
        4 * 1024,
    )?;
    let principal_name = optional_text(
        "cloudtrail.principal_name",
        cloudtrail.principal_name.as_deref(),
        4 * 1024,
    )?;
    let principal_type = optional_text(
        "cloudtrail.principal_type",
        cloudtrail.principal_type.as_deref(),
        512,
    )?;
    let source_ip = optional_text(
        "cloudtrail.source_ip_address",
        cloudtrail.source_ip_address.as_deref(),
        256,
    )?;
    let region = optional_text(
        "cloudtrail.aws_region",
        cloudtrail.aws_region.as_deref(),
        256,
    )?;
    let user_agent = optional_text(
        "cloudtrail.user_agent",
        cloudtrail.user_agent.as_deref(),
        4 * 1024,
    )?;
    let error_code = optional_text(
        "cloudtrail.error_code",
        cloudtrail.error_code.as_deref(),
        512,
    )?;
    let error_message = optional_text(
        "cloudtrail.error_message",
        cloudtrail.error_message.as_deref(),
        4 * 1024,
    )?;
    let request_digest = bounded_json_digest(
        "cloudtrail.request_parameters",
        &cloudtrail.request_parameters,
    )?;
    let response_digest = bounded_json_digest(
        "cloudtrail.response_elements",
        &cloudtrail.response_elements,
    )?;
    // Keep absent identities event-scoped instead of collapsing every
    // identity-less CloudTrail event onto one global `unknown` node.  Once a
    // principal/account field is supplied, its digest must remain stable
    // across events so the same actor/account correlates in the graph.  Every
    // supplied principal field remains in the known-identity material so a
    // lower-priority mutation is visible even when an ARN is present.
    let principal_digest = if principal_arn.is_none()
        && principal_id.is_none()
        && principal_name.is_none()
        && principal_type.is_none()
    {
        digest_projection(&(
            "principal",
            event_id,
            &principal_arn,
            &principal_id,
            &principal_name,
            &principal_type,
        ))?
    } else {
        digest_projection(&(
            "principal",
            &principal_arn,
            &principal_id,
            &principal_name,
            &principal_type,
        ))?
    };
    let account_digest = if account.is_none() {
        digest_projection(&("account", event_id, &account))?
    } else {
        digest_projection(&("account", &account))?
    };
    let source_ip_digest = source_ip
        .as_deref()
        .map(|ip| digest_projection(&("source_ip", ip)))
        .transpose()?;
    let actor = ActorNode::new(principal_digest.clone(), "cloudtrail_principal")?;
    let account_node = AssetNode::new(account_digest.clone(), "aws_account")?;
    let event_node_source_record_id = event_node_source_record_id(source_id, event_id)?;
    let event_node = EventNode::new("cloudtrail", event_node_source_record_id, observed_at)?;
    let entity_ids = vec![
        actor.node_id.clone(),
        account_node.node_id.clone(),
        event_node.node_id.clone(),
    ];
    let content_digest = digest_projection(&(
        event_id,
        &event_name,
        &event_source,
        &account,
        &principal_arn,
        &principal_id,
        &principal_name,
        &principal_type,
        &source_ip,
        &region,
        &user_agent,
        cloudtrail.mfa_authenticated,
        &request_digest,
        &response_digest,
        &error_code,
        &error_message,
    ))?;
    // CloudTrail's account and principal semantics remain in their dedicated
    // digest fields; `host_id` is deliberately not consulted.
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Cloudtrail {
            signal_kind: "cloudtrail".to_string(),
            event_id: event_id.to_string(),
            event_name,
            event_source,
            principal_digest,
            account_digest,
            source_ip_digest,
            request_digest,
            response_digest,
            mfa_authenticated: cloudtrail.mfa_authenticated,
            region,
            error_code,
            error_message,
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Actor(actor),
            GraphNode::Asset(account_node),
            GraphNode::Event(event_node),
        ],
    })
}

fn network_payload(
    network: &NetworkConnectEvent,
    host_id: Option<&str>,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let process = bounded_text("network.process_name", &network.process_name, 4 * 1024)?;
    let host_id = optional_text("network.host_id", host_id, 4 * 1024)?;
    let destination_ip = bounded_text("network.destination_ip", &network.destination_ip, 256)?;
    let protocol = bounded_text("network.protocol", &network.protocol, 256)?;
    let origin_scope_digest =
        digest_projection(&("network_origin", source_id, host_id.as_deref()))?;
    let source_digest = digest_projection(&("process", &origin_scope_digest, &process))?;
    let destination_digest =
        digest_projection(&("destination", &destination_ip, network.destination_port))?;
    let process_node = ProcessNode::new(source_digest.clone(), source_digest.clone())?;
    let asset_node = AssetNode::new(destination_digest.clone(), "network_destination")?;
    let event_node_source_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event_node = EventNode::new("network_connect", event_node_source_record_id, observed_at)?;
    let content_digest = digest_projection(&(
        "network_connect",
        &process,
        &destination_ip,
        network.destination_port,
        &protocol,
    ))?;
    let entity_ids = vec![
        process_node.node_id.clone(),
        asset_node.node_id.clone(),
        event_node.node_id.clone(),
    ];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Network {
            signal_kind: "network_connect".to_string(),
            source_digest,
            destination_digest,
            protocol,
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Process(process_node),
            GraphNode::Asset(asset_node),
            GraphNode::Event(event_node),
        ],
    })
}

fn dns_payload(
    dns: &DnsQueryEvent,
    source_id: &str,
    source_record_id: &str,
    observed_at: swarm_core::hypothesis_graph::GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let query_name = bounded_text("dns.query_name", &dns.query_name, 4 * 1024)?;
    let query_type = bounded_text("dns.query_type", &dns.query_type, 256)?;
    let source_ip = optional_text("dns.source_ip", dns.source_ip.as_deref(), 256)?;
    let process_name = optional_text("dns.process_name", dns.process_name.as_deref(), 4 * 1024)?;
    let response_code = optional_text("dns.response_code", dns.response_code.as_deref(), 256)?;
    let source_digest = digest_projection(&("dns_source", &source_ip, &process_name))?;
    let destination_digest = digest_projection(&("dns_query", &query_name))?;
    let source_node = AssetNode::new(source_digest.clone(), "dns_source")?;
    let destination_node = AssetNode::new(destination_digest.clone(), "dns_name")?;
    let event_node_source_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event_node = EventNode::new("dns_query", event_node_source_record_id, observed_at)?;
    let content_digest = digest_projection(&(
        "dns_query",
        &query_name,
        &query_type,
        &source_ip,
        &process_name,
        &response_code,
    ))?;
    let entity_ids = vec![
        source_node.node_id.clone(),
        destination_node.node_id.clone(),
        event_node.node_id.clone(),
    ];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Network {
            signal_kind: "dns_query".to_string(),
            source_digest,
            destination_digest,
            protocol: query_type,
            entity_ids,
            content_digest,
        },
        nodes: vec![
            GraphNode::Asset(source_node),
            GraphNode::Asset(destination_node),
            GraphNode::Event(event_node),
        ],
    })
}

fn infrastructure_payload<T: Serialize>(
    signal_kind: &'static str,
    node_name: &str,
    payload: &T,
    source_id: &str,
    source_record_id: &str,
    observed_at: GraphLogicalTime,
) -> Result<NormalizedPayload, GraphAdmissionError> {
    let node_name = bounded_text("infrastructure.node_name", node_name, 4 * 1024)?;
    let node_digest = digest_projection(&("infrastructure_node", &node_name))?;
    let node = AssetNode::new(node_digest, "infrastructure_node")?;
    let event_record_id = event_node_source_record_id(source_id, source_record_id)?;
    let event = EventNode::new(signal_kind, event_record_id, observed_at)?;
    let content_digest = digest_projection(&(signal_kind, payload))?;
    let entity_ids = vec![event.node_id.clone(), node.node_id.clone()];
    Ok(NormalizedPayload {
        payload: TypedEvidencePayload::Signal {
            signal_kind: signal_kind.to_string(),
            entity_ids,
            relation_ids: Vec::new(),
            supports: Vec::new(),
            refutes: Vec::new(),
            content_digest,
        },
        nodes: vec![GraphNode::Event(event), GraphNode::Asset(node)],
    })
}

fn digest_projection<T: Serialize>(projection: &T) -> Result<String, GraphAdmissionError> {
    let bytes = canonical_json_bytes(projection).map_err(|error| {
        GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        }
    })?;
    Ok(sha256_hex(&bytes))
}

/// Construct the bounded, source-scoped identity used by event nodes.
///
/// Registry conflict keys already bind `(family, source_id, source_record_id)`.
/// Event nodes must carry the same source boundary or equal record IDs from two
/// vendors can alias one graph entity even though their evidence remains
/// separate.  Keep the raw record ID in the envelope lineage; only the event
/// node projection uses this digest.
fn event_node_source_record_id(
    source_id: &str,
    source_record_id: &str,
) -> Result<String, GraphAdmissionError> {
    // Keep the source-record identity bounded at the one event-node boundary
    // as well as at each adapter entry point.  This prevents a future adapter
    // from bypassing the canonical EventNode identity contract by calling the
    // shared projection with an empty or oversized lineage value.
    let source_id = bounded_text("event.source_id", source_id, 256)?;
    let source_record_id = bounded_text("event.source_record_id", source_record_id, 256)?;
    let digest = digest_projection(&("event_source_record", &source_id, &source_record_id))?;
    Ok(format!("event-source-record:{digest}"))
}

fn bounded_json_digest(field: &str, value: &Value) -> Result<String, GraphAdmissionError> {
    let mut nodes = 0_usize;
    validate_json_shape(field, value, 0, &mut nodes)?;
    let bytes =
        canonical_json_bytes(value).map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })?;
    if bytes.len() > MAX_RAW_PROJECTION_BYTES {
        return Err(GraphAdmissionError::ResourceLimitExceeded {
            resource: field.to_string(),
            limit: MAX_RAW_PROJECTION_BYTES,
        });
    }
    Ok(sha256_hex(&bytes))
}

fn ensure_list_bound(field: &str, length: usize) -> Result<(), GraphAdmissionError> {
    if length > MAX_SOURCE_LIST_ITEMS {
        return Err(GraphAdmissionError::ResourceLimitExceeded {
            resource: field.to_string(),
            limit: MAX_SOURCE_LIST_ITEMS,
        });
    }
    Ok(())
}

fn validate_json_shape(
    field: &str,
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), GraphAdmissionError> {
    if depth > MAX_RAW_PROJECTION_DEPTH {
        return Err(GraphAdmissionError::ResourceLimitExceeded {
            resource: format!("{field}.depth"),
            limit: MAX_RAW_PROJECTION_DEPTH,
        });
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_RAW_PROJECTION_NODES {
        return Err(GraphAdmissionError::ResourceLimitExceeded {
            resource: format!("{field}.nodes"),
            limit: MAX_RAW_PROJECTION_NODES,
        });
    }
    match value {
        Value::Array(items) => {
            for item in items {
                validate_json_shape(field, item, depth.saturating_add(1), nodes)?;
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                if key.len() > 512 {
                    return Err(GraphAdmissionError::InvalidField {
                        field: format!("{field}.key"),
                        reason: "object key exceeds 512 bytes".to_string(),
                    });
                }
                validate_json_shape(field, item, depth.saturating_add(1), nodes)?;
            }
        }
        Value::String(text) if text.len() > MAX_RAW_PROJECTION_BYTES => {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: format!("{field}.string"),
                limit: MAX_RAW_PROJECTION_BYTES,
            });
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn bounded_text(field: &str, value: &str, max_bytes: usize) -> Result<String, GraphAdmissionError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(GraphAdmissionError::InvalidField {
            field: field.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if value.len() > max_bytes.min(MAX_SOURCE_TEXT_BYTES) {
        return Err(GraphAdmissionError::ResourceLimitExceeded {
            resource: field.to_string(),
            limit: max_bytes.min(MAX_SOURCE_TEXT_BYTES),
        });
    }
    Ok(value.to_string())
}

fn optional_text(
    field: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<Option<String>, GraphAdmissionError> {
    value
        .map(|value| bounded_text(field, value, max_bytes))
        .transpose()
}

fn confidence_basis_points(confidence: f64) -> u16 {
    (confidence * 10_000.0).round() as u16
}

fn indicator_kind(indicator_type: &ThreatIntelIndicatorType) -> &'static str {
    match indicator_type {
        ThreatIntelIndicatorType::IpAddress => "ip_address",
        ThreatIntelIndicatorType::Domain => "domain",
        ThreatIntelIndicatorType::FileHash => "file_hash",
        ThreatIntelIndicatorType::Url => "url",
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        TETRAGON_FALLBACK_TIME_EVENT_ID_PREFIX, TETRAGON_FALLBACK_TIME_SOURCE_MARKER,
        normalize_telemetry_event, normalize_telemetry_event_for_graph,
        normalize_threat_intel_entry,
    };
    use crate::hypothesis_graph::clock::FixedGraphClock;
    use swarm_core::hypothesis_graph::{
        EvidenceSourceFamily, GraphAdmissionError, GraphLogicalTime, GraphNode, GraphProducerRole,
        TypedEvidencePayload,
    };
    use swarm_core::{
        CloudTrailEvent, ExhaustedResource, InfrastructureHealthEvent, NetworkConnectEvent,
        ProcessStartEvent, ResourceExhaustionEvent, TelemetryEvent, TelemetryPayload,
        ThermalAnomalyEvent, ThermalSeverity, ThreatIntelEntry, ThreatIntelIndicatorType,
    };
    use swarm_crypto::Keypair;

    fn key() -> Keypair {
        Keypair::from_seed(&[7_u8; 32])
    }

    fn process_event() -> TelemetryEvent {
        TelemetryEvent {
            source: "tetragon".to_string(),
            event_id: "record:process:1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-secret-that-must-not-be-causal".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "systemd".to_string(),
                process_name: "curl".to_string(),
                command_line: "curl https://example.test/?token=secret".to_string(),
                user: Some("alice".to_string()),
                executable_path: Some("/usr/bin/curl".to_string()),
                signer: Some("vendor".to_string()),
                signature_valid: Some(true),
            }),
        }
    }

    #[test]
    fn process_normalization_preserves_clock_lineage_and_redacts_raw_fields() {
        let event = process_event();
        let envelope = normalize_telemetry_event(
            &event,
            &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
            &key(),
            GraphProducerRole::Normalizer,
            "normalizer-process",
        )
        .unwrap();
        assert_eq!(envelope.source_family, EvidenceSourceFamily::Process);
        assert_eq!(envelope.lineage.source_record_id, "record:process:1");
        assert_eq!(
            envelope.clock.observed_at,
            GraphLogicalTime::new(1_700_000_000_000)
        );
        assert_eq!(
            envelope.clock.ingested_at,
            Some(GraphLogicalTime::new(1_700_000_001_000))
        );
        assert!(matches!(
            envelope.payload,
            TypedEvidencePayload::Process { .. }
        ));
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(!encoded.contains("token=secret"));
        assert!(!encoded.contains("host-secret-that-must-not-be-causal"));
        envelope.validate().unwrap();
    }

    #[test]
    fn network_process_identity_is_host_scoped_stable_and_redacted() {
        let event = |event_id: &str, host_id: Option<&str>, source: &str| TelemetryEvent {
            source: source.to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_700_000_000,
            host_id: host_id.map(str::to_string),
            payload: TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                process_name: "curl".to_string(),
                destination_ip: "203.0.113.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
            }),
        };
        let normalize = |event: &TelemetryEvent| {
            normalize_telemetry_event(
                event,
                &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
                &key(),
                GraphProducerRole::Normalizer,
                "normalizer-network",
            )
            .unwrap()
        };
        let first = normalize(&event("network:1", Some("host-secret-a"), "sensor-a"));
        let same_host = normalize(&event("network:2", Some("host-secret-a"), "sensor-a"));
        let other_host = normalize(&event("network:3", Some("host-secret-b"), "sensor-a"));
        let source_fallback_a = normalize(&event("network:4", None, "sensor-a"));
        let source_fallback_b = normalize(&event("network:5", None, "sensor-b"));
        let other_source = normalize(&event("network:6", Some("host-secret-a"), "sensor-b"));
        let source_digest = |evidence: &swarm_core::hypothesis_graph::EvidenceEnvelope| {
            let TypedEvidencePayload::Network { source_digest, .. } = &evidence.payload else {
                panic!("network telemetry must produce network evidence");
            };
            source_digest.clone()
        };

        assert_eq!(source_digest(&first), source_digest(&same_host));
        assert_ne!(source_digest(&first), source_digest(&other_host));
        assert_ne!(source_digest(&first), source_digest(&other_source));
        assert_ne!(
            source_digest(&source_fallback_a),
            source_digest(&source_fallback_b)
        );
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("host-secret-a"));
    }

    #[test]
    fn graph_normalization_retains_every_payload_and_parent_node_identity() {
        let normalized = normalize_telemetry_event_for_graph(
            &process_event(),
            &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
            &key(),
            GraphProducerRole::Normalizer,
            "normalizer-process-graph",
        )
        .unwrap();
        let TypedEvidencePayload::Process { entity_ids, .. } = &normalized.evidence.payload else {
            panic!("process telemetry must produce process evidence");
        };
        for entity_id in entity_ids {
            assert!(
                normalized.nodes.iter().any(|node| node.id() == entity_id),
                "payload entity {entity_id:?} was not retained"
            );
        }
        for parent_id in normalized.nodes.iter().filter_map(|node| match node {
            GraphNode::Process(process) => process.parent_node_id.as_ref(),
            _ => None,
        }) {
            assert!(
                normalized.nodes.iter().any(|node| node.id() == parent_id),
                "process parent {parent_id:?} was not retained"
            );
        }
    }

    #[test]
    fn infrastructure_detector_payloads_admit_as_redacted_graph_evidence() {
        let payloads = [
            (
                "infrastructure_health",
                TelemetryPayload::InfrastructureHealth(InfrastructureHealthEvent {
                    node_name: "node-secret-health".to_string(),
                    cpu_usage_percent: 91.0,
                    cpu_frequency_mhz: 3_200.0,
                    load_average_1m: 8.0,
                    load_average_5m: 7.0,
                    load_average_15m: 6.0,
                    memory_usage_percent: 88.0,
                    memory_available_bytes: 1_024,
                    disk_usage_percent: 72.0,
                    disk_io_latency_ms: 45.0,
                    network_rx_bytes: 11,
                    network_tx_bytes: 12,
                    network_rx_errors: 2,
                    network_tx_errors: 3,
                    failure_probability: 0.9,
                    prediction_confidence: 0.95,
                    time_to_failure_secs: 120.0,
                    collection_duration_ms: 25.0,
                }),
            ),
            (
                "thermal_anomaly",
                TelemetryPayload::ThermalAnomaly(ThermalAnomalyEvent {
                    node_name: "node-secret-thermal".to_string(),
                    temperature_celsius: 96.0,
                    cpu_throttled: true,
                    trend_slope: 1.5,
                    severity: ThermalSeverity::Critical,
                    estimated_time_to_critical_secs: 30.0,
                }),
            ),
            (
                "resource_exhaustion",
                TelemetryPayload::ResourceExhaustion(ResourceExhaustionEvent {
                    node_name: "node-secret-resource".to_string(),
                    resource_kind: ExhaustedResource::Memory,
                    utilization_percent: 99.0,
                    current_value: 990,
                    capacity_value: 1_000,
                    oom_kill_count: Some(4),
                    swap_used_bytes: Some(512),
                    is_new: true,
                }),
            ),
        ];

        for (index, (expected_kind, payload)) in payloads.into_iter().enumerate() {
            let event = TelemetryEvent {
                source: "sentinel".to_string(),
                event_id: format!("record:infrastructure:{index}"),
                timestamp: 1_700_000_000,
                host_id: Some("host-secret-that-must-not-be-causal".to_string()),
                payload,
            };
            let envelope = normalize_telemetry_event(
                &event,
                &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
                &key(),
                GraphProducerRole::Normalizer,
                "normalizer-infrastructure",
            )
            .unwrap();

            assert_eq!(envelope.source_family, EvidenceSourceFamily::Infrastructure);
            assert!(matches!(
                &envelope.payload,
                TypedEvidencePayload::Signal { signal_kind, entity_ids, .. }
                    if signal_kind == expected_kind && entity_ids.len() == 2
            ));
            let encoded = serde_json::to_string(&envelope).unwrap();
            assert!(!encoded.contains("node-secret"));
            assert!(!encoded.contains("host-secret"));
            envelope.validate().unwrap();
        }
    }

    #[test]
    fn tetragon_host_clock_fallback_is_rejected_at_graph_boundary() {
        for fallback_seconds in [1_700_000_001, 1_800_000_001] {
            let mut event = process_event();
            event.timestamp = fallback_seconds;
            event.event_id = format!("{TETRAGON_FALLBACK_TIME_EVENT_ID_PREFIX}{}", event.event_id);
            let result = normalize_telemetry_event(
                &event,
                &FixedGraphClock::new(GraphLogicalTime::new(1_900_000_001_000)),
                &key(),
                GraphProducerRole::Normalizer,
                "normalizer-tetragon-fallback",
            );
            assert!(matches!(
                result,
                Err(GraphAdmissionError::InvalidField { field, .. })
                    if field == "telemetry.timestamp"
            ));
        }

        let mut source_marked = process_event();
        source_marked.source = TETRAGON_FALLBACK_TIME_SOURCE_MARKER.to_string();
        assert!(matches!(
            normalize_telemetry_event(
                &source_marked,
                &FixedGraphClock::new(GraphLogicalTime::new(1_900_000_001_000)),
                &key(),
                GraphProducerRole::Normalizer,
                "normalizer-tetragon-fallback",
            ),
            Err(GraphAdmissionError::InvalidField { field, .. })
                if field == "telemetry.timestamp"
        ));
    }

    #[test]
    fn cloudtrail_hashes_nested_request_objects_without_exporting_them() {
        let event = TelemetryEvent {
            source: "cloudtrail".to_string(),
            event_id: "record:cloud:1".to_string(),
            timestamp: 1_700_000_000,
            host_id: None,
            payload: TelemetryPayload::CloudTrail(CloudTrailEvent {
                event_name: "PutRolePolicy".to_string(),
                event_source: "iam.amazonaws.com".to_string(),
                aws_account_id: Some("123456789012".to_string()),
                principal_arn: Some("arn:aws:iam::123456789012:user/a".to_string()),
                principal_id: None,
                principal_name: None,
                principal_type: Some("User".to_string()),
                source_ip_address: Some("198.51.100.10".to_string()),
                aws_region: Some("us-east-1".to_string()),
                user_agent: Some("fixture".to_string()),
                mfa_authenticated: Some(false),
                request_parameters: serde_json::json!({"secretAccessKey":"do-not-export", "policy":{"Statement":[]}}),
                response_elements: serde_json::json!({"ok":true}),
                error_code: None,
                error_message: None,
            }),
        };
        let envelope = normalize_telemetry_event(
            &event,
            &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
            &key(),
            GraphProducerRole::Normalizer,
            "normalizer-cloud",
        )
        .unwrap();
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(!encoded.contains("do-not-export"));
        assert!(matches!(
            envelope.payload,
            TypedEvidencePayload::Cloudtrail { .. }
        ));
    }

    #[test]
    fn threat_intel_normalization_uses_integer_confidence_and_signed_identity() {
        let entry = ThreatIntelEntry {
            indicator_type: ThreatIntelIndicatorType::Domain,
            value: "evil.example".to_string(),
            source: "taxii-feed".to_string(),
            indicator_id: Some("indicator--1".to_string()),
            confidence: 0.875,
            expires_at: 1_800_000_000_000,
        };
        let envelope = normalize_threat_intel_entry(
            &entry,
            "indicator--1",
            GraphLogicalTime::new(1_700_000_000_000),
            &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
            &key(),
            GraphProducerRole::Normalizer,
            "normalizer-threat",
        )
        .unwrap();
        assert_eq!(
            envelope.source_family,
            EvidenceSourceFamily::ThreatIntelligence
        );
        assert!(matches!(
            envelope.payload,
            TypedEvidencePayload::ThreatIntelligence {
                confidence_basis_points: 8750,
                ..
            }
        ));
        envelope.validate().unwrap();
    }

    #[test]
    fn threat_intel_normalization_rejects_expired_and_boundary_entries() {
        let observed_at = GraphLogicalTime::new(1_700_000_000_000);
        for expires_at in [observed_at.as_millis() - 1, observed_at.as_millis()] {
            let entry = ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::Domain,
                value: "expired.example".to_string(),
                source: "taxii-feed".to_string(),
                indicator_id: Some("indicator--expired".to_string()),
                confidence: 0.875,
                expires_at,
            };
            let error = normalize_threat_intel_entry(
                &entry,
                "indicator--expired",
                observed_at,
                &FixedGraphClock::new(GraphLogicalTime::new(1_700_000_001_000)),
                &key(),
                GraphProducerRole::Normalizer,
                "normalizer-threat",
            )
            .expect_err("expired threat intelligence must fail closed");
            assert!(matches!(
                error,
                GraphAdmissionError::InvalidField { ref field, .. }
                    if field == "threat_intel.expires_at"
            ));
        }
    }
}
