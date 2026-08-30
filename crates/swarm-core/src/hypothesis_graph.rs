//! Strict, bounded contracts for collective cyber reasoning.
//!
//! This module owns typed epistemic records only.  Persistence and runtime
//! orchestration are deliberately kept in higher-level crates.

use crate::types::AgentId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use swarm_crypto::{
    DetachedSignature, Keypair, canonical_json_bytes, sha256_hex, verify_detached_signature,
};

/// Current schema version for the collective-reasoning contracts.
pub const HYPOTHESIS_GRAPH_SCHEMA_VERSION: u32 = 1;
pub const CONFIDENCE_BASIS_POINTS: u16 = 10_000;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

id_type!(GraphId);
id_type!(GraphNodeId);
id_type!(EvidenceId);
id_type!(EdgeId);
id_type!(HypothesisId);
id_type!(ContradictionId);
id_type!(DecisionId);
id_type!(TaskId);
id_type!(LeaseId);
id_type!(IdempotencyKey);
id_type!(MemoryId);
id_type!(KillChainClaimId);

/// Integer logical time used by graph decisions and deterministic replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GraphLogicalTime(pub i64);

impl GraphLogicalTime {
    pub const fn new(millis: i64) -> Self {
        Self(millis)
    }

    pub const fn as_millis(self) -> i64 {
        self.0
    }

    pub fn validate(self) -> Result<(), GraphAdmissionError> {
        if self.0 < 0 {
            return Err(GraphAdmissionError::InvalidField {
                field: "logical_time".to_string(),
                reason: "must be non-negative".to_string(),
            });
        }
        Ok(())
    }

    pub fn checked_add(self, millis: i64) -> Option<Self> {
        self.0
            .checked_add(millis)
            .filter(|value| *value >= 0)
            .map(Self)
    }
}

impl fmt::Display for GraphLogicalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Explicit resource ceilings shared by admission, persistence, and replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphResourceLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_evidence_bytes: usize,
    pub max_evidence_references_per_edge: usize,
    pub max_hypotheses: usize,
    pub max_contradictions: usize,
    pub max_decisions_per_hypothesis: usize,
    pub max_tasks: usize,
    pub max_task_lease_ms: u64,
    pub max_task_retries: u16,
    pub max_memory_records: usize,
    pub max_graph_depth: usize,
    pub max_graph_fan_out: usize,
    pub max_benchmark_work_units: usize,
}

impl Default for GraphResourceLimits {
    fn default() -> Self {
        Self {
            max_nodes: 256,
            max_edges: 512,
            max_evidence_bytes: 1_048_576,
            max_evidence_references_per_edge: 8,
            max_hypotheses: 16,
            max_contradictions: 64,
            max_decisions_per_hypothesis: 64,
            max_tasks: 128,
            max_task_lease_ms: 300_000,
            max_task_retries: 3,
            max_memory_records: 128,
            max_graph_depth: 32,
            max_graph_fan_out: 32,
            max_benchmark_work_units: 10_000,
        }
    }
}

impl GraphResourceLimits {
    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        let checks = [
            ("max_nodes", self.max_nodes, 1, 4_096),
            ("max_edges", self.max_edges, 1, 8_192),
            (
                "max_evidence_bytes",
                self.max_evidence_bytes,
                1,
                16 * 1024 * 1024,
            ),
            (
                "max_evidence_references_per_edge",
                self.max_evidence_references_per_edge,
                1,
                256,
            ),
            ("max_hypotheses", self.max_hypotheses, 1, 256),
            ("max_contradictions", self.max_contradictions, 1, 4_096),
            (
                "max_decisions_per_hypothesis",
                self.max_decisions_per_hypothesis,
                1,
                4_096,
            ),
            ("max_tasks", self.max_tasks, 1, 4_096),
            ("max_memory_records", self.max_memory_records, 1, 4_096),
            ("max_graph_depth", self.max_graph_depth, 1, 1_024),
            ("max_graph_fan_out", self.max_graph_fan_out, 1, 1_024),
            (
                "max_benchmark_work_units",
                self.max_benchmark_work_units,
                1,
                1_000_000,
            ),
        ];
        for (field, value, minimum, maximum) in checks {
            if value < minimum || value > maximum {
                return Err(GraphAdmissionError::InvalidLimit {
                    field: field.to_string(),
                    reason: format!("must be between {minimum} and {maximum}"),
                });
            }
        }
        if self.max_task_lease_ms == 0 || self.max_task_lease_ms > 86_400_000 {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "max_task_lease_ms".to_string(),
                reason: "must be between 1 and 86400000".to_string(),
            });
        }
        if self.max_task_retries == 0 || self.max_task_retries > 128 {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "max_task_retries".to_string(),
                reason: "must be between 1 and 128".to_string(),
            });
        }
        if self.max_edges < self.max_nodes.saturating_sub(1) {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "max_edges".to_string(),
                reason: "must accommodate a spanning graph".to_string(),
            });
        }
        Ok(())
    }
}

/// Upper wire-safety bounds used by standalone Deserialize implementations.
/// Runtime graph admission still applies the caller's configured limits after
/// the nested records have been decoded.
fn persistence_limits() -> GraphResourceLimits {
    GraphResourceLimits {
        max_nodes: 4_096,
        max_edges: 8_192,
        max_evidence_bytes: 16 * 1024 * 1024,
        max_evidence_references_per_edge: 256,
        max_hypotheses: 256,
        max_contradictions: 4_096,
        max_decisions_per_hypothesis: 4_096,
        max_tasks: 4_096,
        max_task_lease_ms: 86_400_000,
        max_task_retries: 128,
        max_memory_records: 4_096,
        max_graph_depth: 1_024,
        max_graph_fan_out: 1_024,
        max_benchmark_work_units: 1_000_000,
    }
}

/// Stable SHA-256 digest over the repository's canonical JSON representation.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, GraphAdmissionError> {
    let bytes =
        canonical_json_bytes(value).map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })?;
    Ok(sha256_hex(&bytes))
}

/// Derive an ID with a human-readable typed prefix and canonical digest.
pub fn stable_id<T: Serialize>(prefix: &str, value: &T) -> Result<String, GraphAdmissionError> {
    if prefix.trim().is_empty() {
        return Err(GraphAdmissionError::InvalidIdentifier {
            field: "prefix".to_string(),
        });
    }
    Ok(format!("{}:{}", prefix, canonical_digest(value)?))
}

/// Graph node taxonomy required by the collective reasoning contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    Actor,
    Asset,
    Credential,
    Process,
    Event,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorNode {
    pub schema_version: u32,
    pub node_id: GraphNodeId,
    pub identity_digest: String,
    pub label: String,
}

impl ActorNode {
    pub fn new(
        identity_digest: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let identity_digest = identity_digest.into();
        let label = label.into();
        validate_text("identity_digest", &identity_digest, 256)?;
        validate_text("label", &label, 256)?;
        let material = (&identity_digest, &label);
        let node_id = GraphNodeId::new(stable_id("node:actor", &material)?);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            node_id,
            identity_digest,
            label,
        })
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("actor.identity_digest", &self.identity_digest, 256)?;
        validate_text("actor.label", &self.label, 256)?;
        let expected = GraphNodeId::new(stable_id(
            "node:actor",
            &(&self.identity_digest, &self.label),
        )?);
        if expected != self.node_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.node_id.0.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetNode {
    pub schema_version: u32,
    pub node_id: GraphNodeId,
    pub asset_digest: String,
    pub asset_kind: String,
}

impl AssetNode {
    pub fn new(
        asset_digest: impl Into<String>,
        asset_kind: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let asset_digest = asset_digest.into();
        let asset_kind = asset_kind.into();
        validate_text("asset_digest", &asset_digest, 256)?;
        validate_text("asset_kind", &asset_kind, 128)?;
        let material = (&asset_digest, &asset_kind);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            node_id: GraphNodeId::new(stable_id("node:asset", &material)?),
            asset_digest,
            asset_kind,
        })
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("asset.asset_digest", &self.asset_digest, 256)?;
        validate_text("asset.asset_kind", &self.asset_kind, 128)?;
        let expected = GraphNodeId::new(stable_id(
            "node:asset",
            &(&self.asset_digest, &self.asset_kind),
        )?);
        if expected != self.node_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.node_id.0.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialNode {
    pub schema_version: u32,
    pub node_id: GraphNodeId,
    pub credential_digest: String,
    pub credential_kind: String,
}

impl CredentialNode {
    pub fn new(
        credential_digest: impl Into<String>,
        credential_kind: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let credential_digest = credential_digest.into();
        let credential_kind = credential_kind.into();
        validate_text("credential_digest", &credential_digest, 256)?;
        validate_text("credential_kind", &credential_kind, 128)?;
        let material = (&credential_digest, &credential_kind);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            node_id: GraphNodeId::new(stable_id("node:credential", &material)?),
            credential_digest,
            credential_kind,
        })
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("credential.credential_digest", &self.credential_digest, 256)?;
        validate_text("credential.credential_kind", &self.credential_kind, 128)?;
        let expected = GraphNodeId::new(stable_id(
            "node:credential",
            &(&self.credential_digest, &self.credential_kind),
        )?);
        if expected != self.node_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.node_id.0.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessNode {
    pub schema_version: u32,
    pub node_id: GraphNodeId,
    pub process_digest: String,
    pub executable_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_node_id: Option<GraphNodeId>,
}

impl ProcessNode {
    pub fn new(
        process_digest: impl Into<String>,
        executable_digest: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let process_digest = process_digest.into();
        let executable_digest = executable_digest.into();
        validate_text("process_digest", &process_digest, 256)?;
        validate_text("executable_digest", &executable_digest, 256)?;
        let parent_node_id: Option<GraphNodeId> = None;
        let material = (&process_digest, &executable_digest, &parent_node_id);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            node_id: GraphNodeId::new(stable_id("node:process", &material)?),
            process_digest,
            executable_digest,
            parent_node_id: None,
        })
    }

    pub fn new_with_parent(
        process_digest: impl Into<String>,
        executable_digest: impl Into<String>,
        parent_node_id: GraphNodeId,
    ) -> Result<Self, GraphAdmissionError> {
        let process_digest = process_digest.into();
        let executable_digest = executable_digest.into();
        validate_text("process_digest", &process_digest, 256)?;
        validate_text("executable_digest", &executable_digest, 256)?;
        validate_id("process.parent_node_id", &parent_node_id, 256)?;
        let parent_node_id = Some(parent_node_id);
        let material = (&process_digest, &executable_digest, &parent_node_id);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            node_id: GraphNodeId::new(stable_id("node:process", &material)?),
            process_digest,
            executable_digest,
            parent_node_id,
        })
    }

    pub fn with_parent_node_id(
        mut self,
        parent_node_id: Option<GraphNodeId>,
    ) -> Result<Self, GraphAdmissionError> {
        if let Some(parent) = &parent_node_id {
            validate_id("process.parent_node_id", parent, 256)?;
        }
        self.parent_node_id = parent_node_id;
        self.node_id = self.derived_id()?;
        Ok(self)
    }

    pub fn derived_id(&self) -> Result<GraphNodeId, GraphAdmissionError> {
        Ok(GraphNodeId::new(stable_id(
            "node:process",
            &(
                &self.process_digest,
                &self.executable_digest,
                &self.parent_node_id,
            ),
        )?))
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("process.process_digest", &self.process_digest, 256)?;
        validate_text("process.executable_digest", &self.executable_digest, 256)?;
        if let Some(parent_node_id) = &self.parent_node_id {
            validate_id("process.parent_node_id", parent_node_id, 256)?;
        }
        let expected = self.derived_id()?;
        if expected != self.node_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.node_id.0.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventNode {
    pub schema_version: u32,
    pub node_id: GraphNodeId,
    pub event_kind: String,
    pub source_record_id: String,
    pub observed_at: GraphLogicalTime,
}

impl EventNode {
    pub fn new(
        event_kind: impl Into<String>,
        source_record_id: impl Into<String>,
        observed_at: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        let event_kind = event_kind.into();
        let source_record_id = source_record_id.into();
        validate_text("event_kind", &event_kind, 128)?;
        validate_text("event.source_record_id", &source_record_id, 256)?;
        observed_at.validate()?;
        let material = (&event_kind, &source_record_id, observed_at);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            node_id: GraphNodeId::new(stable_id("node:event", &material)?),
            event_kind,
            source_record_id,
            observed_at,
        })
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("event.event_kind", &self.event_kind, 128)?;
        validate_text("event.source_record_id", &self.source_record_id, 256)?;
        self.observed_at.validate()?;
        let expected = GraphNodeId::new(stable_id(
            "node:event",
            &(&self.event_kind, &self.source_record_id, self.observed_at),
        )?);
        if expected != self.node_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.node_id.0.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphNode {
    Actor(ActorNode),
    Asset(AssetNode),
    Credential(CredentialNode),
    Process(ProcessNode),
    Event(EventNode),
}

impl GraphNode {
    pub fn id(&self) -> &GraphNodeId {
        match self {
            Self::Actor(node) => &node.node_id,
            Self::Asset(node) => &node.node_id,
            Self::Credential(node) => &node.node_id,
            Self::Process(node) => &node.node_id,
            Self::Event(node) => &node.node_id,
        }
    }

    pub fn kind(&self) -> GraphNodeKind {
        match self {
            Self::Actor(_) => GraphNodeKind::Actor,
            Self::Asset(_) => GraphNodeKind::Asset,
            Self::Credential(_) => GraphNodeKind::Credential,
            Self::Process(_) => GraphNodeKind::Process,
            Self::Event(_) => GraphNodeKind::Event,
        }
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        match self {
            Self::Actor(node) => node.validate(),
            Self::Asset(node) => node.validate(),
            Self::Credential(node) => node.validate(),
            Self::Process(node) => node.validate(),
            Self::Event(node) => node.validate(),
        }
    }
}

/// Source families are deliberately explicit; no generic vendor JSON enters
/// the shared evidence contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceFamily {
    Process,
    Identity,
    Kubernetes,
    Cloudtrail,
    Network,
    ThreatIntelligence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLineage {
    pub adapter: String,
    pub source_record_id: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub upstream_record_ids: BTreeSet<String>,
}

impl SourceLineage {
    pub fn new(
        adapter: impl Into<String>,
        source_record_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let adapter = adapter.into();
        let source_record_id = source_record_id.into();
        validate_text("lineage.adapter", &adapter, 128)?;
        validate_text("lineage.source_record_id", &source_record_id, 256)?;
        Ok(Self {
            adapter,
            source_record_id,
            upstream_record_ids: BTreeSet::new(),
        })
    }

    pub fn with_upstream<I, S>(mut self, ids: I) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for id in ids {
            let id = id.into();
            validate_text("lineage.upstream_record_id", &id, 256)?;
            self.upstream_record_ids.insert(id);
        }
        Ok(self)
    }

    fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_text("lineage.adapter", &self.adapter, 128)?;
        validate_text("lineage.source_record_id", &self.source_record_id, 256)?;
        if self.upstream_record_ids.len() > 32 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "lineage.upstream_record_ids".to_string(),
                limit: 32,
            });
        }
        for id in &self.upstream_record_ids {
            validate_text("lineage.upstream_record_id", id, 256)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockPrecision {
    Millisecond,
    Second,
    Minute,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClock {
    pub observed_at: GraphLogicalTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingested_at: Option<GraphLogicalTime>,
    pub precision: ClockPrecision,
    pub uncertainty_ms: u64,
}

impl EvidenceClock {
    pub fn observed(observed_at: GraphLogicalTime) -> Self {
        Self {
            observed_at,
            ingested_at: None,
            precision: ClockPrecision::Millisecond,
            uncertainty_ms: 0,
        }
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        self.observed_at.validate()?;
        if let Some(ingested_at) = self.ingested_at {
            ingested_at.validate()?;
            let uncertainty = i64::try_from(self.uncertainty_ms).map_err(|_| {
                GraphAdmissionError::InvalidField {
                    field: "clock.uncertainty_ms".to_string(),
                    reason: "does not fit in logical time".to_string(),
                }
            })?;
            let lower_bound = self
                .observed_at
                .as_millis()
                .checked_sub(uncertainty)
                .unwrap_or(0);
            if ingested_at.as_millis() < lower_bound {
                return Err(GraphAdmissionError::InvalidField {
                    field: "clock.ingested_at".to_string(),
                    reason: "falls outside the observed-time uncertainty window".to_string(),
                });
            }
        }
        if self.uncertainty_ms > 86_400_000 {
            return Err(GraphAdmissionError::InvalidField {
                field: "clock.uncertainty_ms".to_string(),
                reason: "must be at most one day".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OrderingClaim {
    SourceSequence {
        sequence: u64,
    },
    DeclaredBefore {
        predecessor_evidence_ids: BTreeSet<EvidenceId>,
    },
    Partial {
        predecessor_evidence_ids: BTreeSet<EvidenceId>,
    },
    SameTime,
    Unknown,
}

impl OrderingClaim {
    fn validate(&self) -> Result<(), GraphAdmissionError> {
        match self {
            Self::SourceSequence { .. } | Self::SameTime | Self::Unknown => Ok(()),
            Self::DeclaredBefore {
                predecessor_evidence_ids,
            }
            | Self::Partial {
                predecessor_evidence_ids,
            } => {
                if predecessor_evidence_ids.is_empty() || predecessor_evidence_ids.len() > 32 {
                    return Err(GraphAdmissionError::InvalidField {
                        field: "ordering.predecessor_evidence_ids".to_string(),
                        reason: "must contain between one and 32 IDs".to_string(),
                    });
                }
                for evidence_id in predecessor_evidence_ids {
                    validate_id("ordering.predecessor_evidence_id", evidence_id, 256)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypedEvidencePayload {
    Signal {
        signal_kind: String,
        entity_ids: Vec<GraphNodeId>,
        relation_ids: Vec<EdgeId>,
        supports: Vec<HypothesisId>,
        refutes: Vec<HypothesisId>,
        content_digest: String,
    },
    Process {
        signal_kind: String,
        process_digest: String,
        parent_process_digest: Option<String>,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    Identity {
        signal_kind: String,
        principal_digest: String,
        credential_digest: Option<String>,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    KubernetesAudit {
        signal_kind: String,
        audit_id: String,
        verb: String,
        resource_digest: String,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    Cloudtrail {
        signal_kind: String,
        event_id: String,
        event_name: String,
        event_source: String,
        principal_digest: String,
        account_digest: String,
        source_ip_digest: Option<String>,
        request_digest: String,
        response_digest: String,
        mfa_authenticated: Option<bool>,
        region: Option<String>,
        error_code: Option<String>,
        error_message: Option<String>,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    Network {
        signal_kind: String,
        source_digest: String,
        destination_digest: String,
        protocol: String,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    ThreatIntelligence {
        signal_kind: String,
        feed_id: String,
        indicator_digest: String,
        indicator_kind: String,
        confidence_basis_points: u16,
        expires_at: GraphLogicalTime,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TypedEvidencePayloadWire {
    Signal {
        signal_kind: String,
        entity_ids: Vec<GraphNodeId>,
        relation_ids: Vec<EdgeId>,
        supports: Vec<HypothesisId>,
        refutes: Vec<HypothesisId>,
        content_digest: String,
    },
    Process {
        signal_kind: String,
        process_digest: String,
        parent_process_digest: Option<String>,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    Identity {
        signal_kind: String,
        principal_digest: String,
        credential_digest: Option<String>,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    KubernetesAudit {
        signal_kind: String,
        audit_id: String,
        verb: String,
        resource_digest: String,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    Cloudtrail {
        signal_kind: String,
        event_id: String,
        event_name: String,
        event_source: String,
        principal_digest: String,
        account_digest: String,
        source_ip_digest: Option<String>,
        request_digest: String,
        response_digest: String,
        mfa_authenticated: Option<bool>,
        region: Option<String>,
        error_code: Option<String>,
        error_message: Option<String>,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    Network {
        signal_kind: String,
        source_digest: String,
        destination_digest: String,
        protocol: String,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
    ThreatIntelligence {
        signal_kind: String,
        feed_id: String,
        indicator_digest: String,
        indicator_kind: String,
        confidence_basis_points: u16,
        expires_at: GraphLogicalTime,
        entity_ids: Vec<GraphNodeId>,
        content_digest: String,
    },
}

impl From<TypedEvidencePayloadWire> for TypedEvidencePayload {
    fn from(payload: TypedEvidencePayloadWire) -> Self {
        match payload {
            TypedEvidencePayloadWire::Signal {
                signal_kind,
                entity_ids,
                relation_ids,
                supports,
                refutes,
                content_digest,
            } => Self::Signal {
                signal_kind,
                entity_ids,
                relation_ids,
                supports,
                refutes,
                content_digest,
            },
            TypedEvidencePayloadWire::Process {
                signal_kind,
                process_digest,
                parent_process_digest,
                entity_ids,
                content_digest,
            } => Self::Process {
                signal_kind,
                process_digest,
                parent_process_digest,
                entity_ids,
                content_digest,
            },
            TypedEvidencePayloadWire::Identity {
                signal_kind,
                principal_digest,
                credential_digest,
                entity_ids,
                content_digest,
            } => Self::Identity {
                signal_kind,
                principal_digest,
                credential_digest,
                entity_ids,
                content_digest,
            },
            TypedEvidencePayloadWire::KubernetesAudit {
                signal_kind,
                audit_id,
                verb,
                resource_digest,
                entity_ids,
                content_digest,
            } => Self::KubernetesAudit {
                signal_kind,
                audit_id,
                verb,
                resource_digest,
                entity_ids,
                content_digest,
            },
            TypedEvidencePayloadWire::Cloudtrail {
                signal_kind,
                event_id,
                event_name,
                event_source,
                principal_digest,
                account_digest,
                source_ip_digest,
                request_digest,
                response_digest,
                mfa_authenticated,
                region,
                error_code,
                error_message,
                entity_ids,
                content_digest,
            } => Self::Cloudtrail {
                signal_kind,
                event_id,
                event_name,
                event_source,
                principal_digest,
                account_digest,
                source_ip_digest,
                request_digest,
                response_digest,
                mfa_authenticated,
                region,
                error_code,
                error_message,
                entity_ids,
                content_digest,
            },
            TypedEvidencePayloadWire::Network {
                signal_kind,
                source_digest,
                destination_digest,
                protocol,
                entity_ids,
                content_digest,
            } => Self::Network {
                signal_kind,
                source_digest,
                destination_digest,
                protocol,
                entity_ids,
                content_digest,
            },
            TypedEvidencePayloadWire::ThreatIntelligence {
                signal_kind,
                feed_id,
                indicator_digest,
                indicator_kind,
                confidence_basis_points,
                expires_at,
                entity_ids,
                content_digest,
            } => Self::ThreatIntelligence {
                signal_kind,
                feed_id,
                indicator_digest,
                indicator_kind,
                confidence_basis_points,
                expires_at,
                entity_ids,
                content_digest,
            },
        }
    }
}

impl<'de> Deserialize<'de> for TypedEvidencePayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload =
            TypedEvidencePayload::from(TypedEvidencePayloadWire::deserialize(deserializer)?);
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl TypedEvidencePayload {
    fn validate(&self) -> Result<(), GraphAdmissionError> {
        let validate_entities = |ids: &[GraphNodeId]| -> Result<(), GraphAdmissionError> {
            if ids.len() > 64 {
                return Err(GraphAdmissionError::ResourceLimitExceeded {
                    resource: "payload.entity_ids".to_string(),
                    limit: 64,
                });
            }
            for id in ids {
                validate_id("payload.entity_id", id, 256)?;
            }
            Ok(())
        };
        match self {
            Self::Signal {
                signal_kind,
                entity_ids,
                relation_ids,
                supports,
                refutes,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.content_digest", content_digest, 128)?;
                validate_entities(entity_ids)?;
                validate_id_set("payload.relation_ids", relation_ids, 64, 256)?;
                validate_id_set("payload.supports", supports, 64, 256)?;
                validate_id_set("payload.refutes", refutes, 64, 256)?;
            }
            Self::Process {
                signal_kind,
                process_digest,
                parent_process_digest,
                entity_ids,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.process_digest", process_digest, 256)?;
                if let Some(parent) = parent_process_digest {
                    validate_text("payload.parent_process_digest", parent, 256)?;
                }
                validate_text("payload.content_digest", content_digest, 128)?;
                validate_entities(entity_ids)?;
            }
            Self::Identity {
                signal_kind,
                principal_digest,
                credential_digest,
                entity_ids,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.principal_digest", principal_digest, 256)?;
                if let Some(credential) = credential_digest {
                    validate_text("payload.credential_digest", credential, 256)?;
                }
                validate_text("payload.content_digest", content_digest, 128)?;
                validate_entities(entity_ids)?;
            }
            Self::KubernetesAudit {
                signal_kind,
                audit_id,
                verb,
                resource_digest,
                entity_ids,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.audit_id", audit_id, 256)?;
                validate_text("payload.verb", verb, 128)?;
                validate_text("payload.resource_digest", resource_digest, 256)?;
                validate_text("payload.content_digest", content_digest, 128)?;
                validate_entities(entity_ids)?;
            }
            Self::Cloudtrail {
                signal_kind,
                event_id,
                event_name,
                event_source,
                principal_digest,
                account_digest,
                source_ip_digest,
                request_digest,
                response_digest,
                mfa_authenticated: _,
                region,
                error_code,
                error_message,
                entity_ids,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.event_id", event_id, 256)?;
                validate_text("payload.event_name", event_name, 256)?;
                validate_text("payload.event_source", event_source, 256)?;
                validate_text("payload.principal_digest", principal_digest, 256)?;
                validate_text("payload.account_digest", account_digest, 256)?;
                if let Some(source_ip) = source_ip_digest {
                    validate_text("payload.source_ip_digest", source_ip, 256)?;
                }
                validate_text("payload.request_digest", request_digest, 128)?;
                validate_text("payload.response_digest", response_digest, 128)?;
                if let Some(region) = region {
                    validate_text("payload.region", region, 256)?;
                }
                if let Some(error_code) = error_code {
                    validate_text("payload.error_code", error_code, 512)?;
                }
                if let Some(error_message) = error_message {
                    validate_text("payload.error_message", error_message, 4 * 1024)?;
                }
                validate_entities(entity_ids)?;
                validate_text("payload.content_digest", content_digest, 128)?;
            }
            Self::Network {
                signal_kind,
                source_digest,
                destination_digest,
                protocol,
                entity_ids,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.source_digest", source_digest, 256)?;
                validate_text("payload.destination_digest", destination_digest, 256)?;
                validate_text("payload.protocol", protocol, 128)?;
                validate_text("payload.content_digest", content_digest, 128)?;
                validate_entities(entity_ids)?;
            }
            Self::ThreatIntelligence {
                signal_kind,
                feed_id,
                indicator_digest,
                indicator_kind,
                confidence_basis_points,
                expires_at,
                entity_ids,
                content_digest,
            } => {
                validate_text("payload.signal_kind", signal_kind, 128)?;
                validate_text("payload.feed_id", feed_id, 256)?;
                validate_text("payload.indicator_digest", indicator_digest, 256)?;
                validate_text("payload.indicator_kind", indicator_kind, 128)?;
                validate_text("payload.content_digest", content_digest, 128)?;
                expires_at.validate()?;
                validate_entities(entity_ids)?;
                if *confidence_basis_points > CONFIDENCE_BASIS_POINTS {
                    return Err(GraphAdmissionError::InvalidConfidence {
                        value: *confidence_basis_points,
                    });
                }
            }
        }
        Ok(())
    }

    fn entity_ids(&self) -> Vec<GraphNodeId> {
        match self {
            Self::Signal { entity_ids, .. }
            | Self::Process { entity_ids, .. }
            | Self::Identity { entity_ids, .. }
            | Self::KubernetesAudit { entity_ids, .. }
            | Self::Cloudtrail { entity_ids, .. }
            | Self::Network { entity_ids, .. }
            | Self::ThreatIntelligence { entity_ids, .. } => entity_ids.clone(),
        }
    }

    /// Return the threat-intelligence expiry when this payload carries one.
    pub fn expires_at(&self) -> Option<GraphLogicalTime> {
        match self {
            Self::ThreatIntelligence { expires_at, .. } => Some(*expires_at),
            _ => None,
        }
    }

    /// Threat intelligence is active strictly before its expiry boundary.
    pub fn is_active_at(&self, now: GraphLogicalTime) -> Result<Option<bool>, GraphAdmissionError> {
        now.validate()?;
        Ok(self.expires_at().map(|expires_at| now < expires_at))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceWitness {
    pub schema_version: u32,
    pub producer_role: GraphProducerRole,
    pub scoped_agent_id: String,
    pub producer_identity: AgentId,
    pub public_key_hex: String,
    pub signature_hex: String,
}

impl EvidenceWitness {
    /// Sign exact canonical material for a typed graph publication.
    pub fn new(
        key: &Keypair,
        role: GraphProducerRole,
        scoped_agent_id: impl Into<String>,
        bytes: &[u8],
    ) -> Result<Self, GraphAdmissionError> {
        let public_key_hex = key.public_key().to_hex();
        let producer_identity = AgentId::from_public_key_hex(&public_key_hex);
        let scoped_agent_id = scoped_agent_id.into();
        validate_text("witness.scoped_agent_id", &scoped_agent_id, 128)?;
        let signature_hex = hex::encode(key.sign(bytes).to_bytes());
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            producer_role: role,
            scoped_agent_id,
            producer_identity,
            public_key_hex,
            signature_hex,
        })
    }

    /// Verify this witness against the exact canonical material it attests.
    pub fn validate(&self, bytes: &[u8]) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("witness.scoped_agent_id", &self.scoped_agent_id, 128)?;
        validate_text("witness.producer_identity", &self.producer_identity.0, 256)?;
        validate_text("witness.public_key_hex", &self.public_key_hex, 128)?;
        validate_text("witness.signature_hex", &self.signature_hex, 256)?;
        if hex::decode(&self.public_key_hex).map_or(true, |bytes| bytes.len() != 32) {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "public key must be 32 bytes".to_string(),
            });
        }
        if self.producer_identity != AgentId::from_public_key_hex(&self.public_key_hex) {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "producer identity is not key-derived".to_string(),
            });
        }
        let signature = DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: sha256_hex(&hex::decode(&self.public_key_hex).map_err(|_| {
                GraphAdmissionError::InvalidWitness {
                    reason: "public key is not hexadecimal".to_string(),
                }
            })?),
            public_key_hex: self.public_key_hex.clone(),
            signature_hex: self.signature_hex.clone(),
        };
        verify_detached_signature(bytes, &signature).map_err(|error| {
            GraphAdmissionError::InvalidWitness {
                reason: error.to_string(),
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEnvelopeCore {
    schema_version: u32,
    source_family: EvidenceSourceFamily,
    source_id: String,
    lineage: SourceLineage,
    clock: EvidenceClock,
    ordering: OrderingClaim,
    payload: TypedEvidencePayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSigningMaterial {
    schema_version: u32,
    evidence_id: EvidenceId,
    core: EvidenceEnvelopeCore,
    producer_role: GraphProducerRole,
    scoped_agent_id: String,
    producer_identity: AgentId,
    public_key_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDeterministicWitness<'a> {
    schema_version: u32,
    producer_role: GraphProducerRole,
    scoped_agent_id: &'a str,
    producer_identity: &'a AgentId,
    public_key_hex: &'a str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDeterministicMaterial<'a> {
    schema_version: u32,
    evidence_id: &'a EvidenceId,
    core: EvidenceEnvelopeCore,
    witness: EvidenceDeterministicWitness<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub schema_version: u32,
    pub evidence_id: EvidenceId,
    pub source_family: EvidenceSourceFamily,
    pub source_id: String,
    pub lineage: SourceLineage,
    pub clock: EvidenceClock,
    pub ordering: OrderingClaim,
    pub payload: TypedEvidencePayload,
    pub witness: EvidenceWitness,
}

impl EvidenceEnvelope {
    pub fn new(
        source_family: EvidenceSourceFamily,
        source_id: impl Into<String>,
        lineage: SourceLineage,
        clock: EvidenceClock,
        ordering: OrderingClaim,
        payload: TypedEvidencePayload,
    ) -> Result<Self, GraphAdmissionError> {
        let source_id = source_id.into();
        validate_text("evidence.source_id", &source_id, 256)?;
        lineage.validate()?;
        clock.validate()?;
        ordering.validate()?;
        payload.validate()?;
        let core = EvidenceEnvelopeCore {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            source_family,
            source_id: source_id.clone(),
            lineage: lineage.clone(),
            clock: clock_without_ingest(&clock),
            ordering: ordering.clone(),
            payload: payload.clone(),
        };
        let core_bytes =
            canonical_json_bytes(&core).map_err(|error| GraphAdmissionError::Canonicalization {
                reason: error.to_string(),
            })?;
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            evidence_id: EvidenceId::new(format!("evidence:{}", sha256_hex(&core_bytes))),
            source_family,
            source_id,
            lineage,
            clock,
            ordering,
            payload,
            witness: EvidenceWitness {
                schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
                producer_role: GraphProducerRole::Normalizer,
                scoped_agent_id: "unsigned".to_string(),
                producer_identity: AgentId::new("unsigned", "evidence"),
                public_key_hex: String::new(),
                signature_hex: String::new(),
            },
        })
    }

    pub fn sign_with(
        mut self,
        signer: &Keypair,
        role: GraphProducerRole,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let scoped_agent_id = scoped_agent_id.into();
        let public_key_hex = signer.public_key().to_hex();
        let producer_identity = AgentId::from_public_key_hex(&public_key_hex);
        let material = self.signing_material_for(
            role,
            scoped_agent_id.clone(),
            producer_identity,
            public_key_hex,
        )?;
        let bytes = canonical_json_bytes(&material).map_err(|error| {
            GraphAdmissionError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        self.witness = EvidenceWitness::new(signer, role, scoped_agent_id, &bytes)?;
        self.validate().map(|()| self)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        let material = self.signing_material()?;
        canonical_json_bytes(&material).map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    fn core(&self) -> EvidenceEnvelopeCore {
        EvidenceEnvelopeCore {
            schema_version: self.schema_version,
            source_family: self.source_family,
            source_id: self.source_id.clone(),
            lineage: self.lineage.clone(),
            clock: self.clock.clone(),
            ordering: self.ordering.clone(),
            payload: self.payload.clone(),
        }
    }

    fn identity_core(&self) -> EvidenceEnvelopeCore {
        EvidenceEnvelopeCore {
            schema_version: self.schema_version,
            source_family: self.source_family,
            source_id: self.source_id.clone(),
            lineage: self.lineage.clone(),
            clock: clock_without_ingest(&self.clock),
            ordering: self.ordering.clone(),
            payload: self.payload.clone(),
        }
    }

    fn signing_material(&self) -> Result<EvidenceSigningMaterial, GraphAdmissionError> {
        self.signing_material_for(
            self.witness.producer_role,
            self.witness.scoped_agent_id.clone(),
            self.witness.producer_identity.clone(),
            self.witness.public_key_hex.clone(),
        )
    }

    fn signing_material_for(
        &self,
        producer_role: GraphProducerRole,
        scoped_agent_id: String,
        producer_identity: AgentId,
        public_key_hex: String,
    ) -> Result<EvidenceSigningMaterial, GraphAdmissionError> {
        validate_text("witness.scoped_agent_id", &scoped_agent_id, 128)?;
        Ok(EvidenceSigningMaterial {
            schema_version: self.schema_version,
            evidence_id: self.evidence_id.clone(),
            core: self.core(),
            producer_role,
            scoped_agent_id,
            producer_identity,
            public_key_hex,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("evidence.source_id", &self.source_id, 256)?;
        self.lineage.validate()?;
        self.clock.validate()?;
        self.ordering.validate()?;
        self.payload.validate()?;
        let payload_family_matches = matches!(
            (self.source_family, &self.payload),
            (
                EvidenceSourceFamily::Process,
                TypedEvidencePayload::Process { .. }
            ) | (
                EvidenceSourceFamily::Identity,
                TypedEvidencePayload::Identity { .. }
            ) | (
                EvidenceSourceFamily::Kubernetes,
                TypedEvidencePayload::KubernetesAudit { .. }
            ) | (
                EvidenceSourceFamily::Cloudtrail,
                TypedEvidencePayload::Cloudtrail { .. }
            ) | (
                EvidenceSourceFamily::Network,
                TypedEvidencePayload::Network { .. }
            ) | (
                EvidenceSourceFamily::ThreatIntelligence,
                TypedEvidencePayload::ThreatIntelligence { .. }
            ) | (_, TypedEvidencePayload::Signal { .. })
        );
        if !payload_family_matches {
            return Err(GraphAdmissionError::InvalidField {
                field: "evidence.source_family".to_string(),
                reason: "does not match the typed payload family".to_string(),
            });
        }
        if let OrderingClaim::DeclaredBefore {
            predecessor_evidence_ids,
        }
        | OrderingClaim::Partial {
            predecessor_evidence_ids,
        } = &self.ordering
            && predecessor_evidence_ids.contains(&self.evidence_id)
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "ordering.predecessor_evidence_ids".to_string(),
                reason: "an evidence record cannot precede itself".to_string(),
            });
        }
        let core = self.identity_core();
        let core_bytes =
            canonical_json_bytes(&core).map_err(|error| GraphAdmissionError::Canonicalization {
                reason: error.to_string(),
            })?;
        let expected_id = EvidenceId::new(format!("evidence:{}", sha256_hex(&core_bytes)));
        if expected_id != self.evidence_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.evidence_id.0.clone(),
            });
        }
        let bytes = self.canonical_bytes()?;
        self.witness.validate(&bytes)
    }

    /// Canonical facts used for duplicate/conflict identity.
    ///
    /// Ingestion time is intentionally omitted: it is operational metadata,
    /// not source fact content.  Witness role, scoped label, base identity,
    /// and public key remain bound so a role alias or signer cannot turn a
    /// different witness into an idempotent retry.
    pub fn deterministic_content_bytes(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        let material = EvidenceDeterministicMaterial {
            schema_version: self.schema_version,
            evidence_id: &self.evidence_id,
            core: self.identity_core(),
            witness: EvidenceDeterministicWitness {
                schema_version: self.witness.schema_version,
                producer_role: self.witness.producer_role,
                scoped_agent_id: &self.witness.scoped_agent_id,
                producer_identity: &self.witness.producer_identity,
                public_key_hex: &self.witness.public_key_hex,
            },
        };
        canonical_json_bytes(&material).map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub fn entity_ids(&self) -> Vec<GraphNodeId> {
        self.payload.entity_ids()
    }
}

fn clock_without_ingest(clock: &EvidenceClock) -> EvidenceClock {
    EvidenceClock {
        observed_at: clock.observed_at,
        ingested_at: None,
        precision: clock.precision,
        uncertainty_ms: clock.uncertainty_ms,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphProducerRole {
    Hunter,
    Challenger,
    Falsifier,
    Adjudicator,
    Normalizer,
    Planner,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct WitnessBindingMaterial<'a> {
    record_bytes: &'a [u8],
    producer_role: GraphProducerRole,
    scoped_agent_id: &'a str,
}

fn witness_binding_bytes(
    record_bytes: &[u8],
    producer_role: GraphProducerRole,
    scoped_agent_id: &str,
) -> Result<Vec<u8>, GraphAdmissionError> {
    validate_text("witness.scoped_agent_id", scoped_agent_id, 128)?;
    canonical_json_bytes(&WitnessBindingMaterial {
        record_bytes,
        producer_role,
        scoped_agent_id,
    })
    .map_err(|error| GraphAdmissionError::Canonicalization {
        reason: error.to_string(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRelation {
    Uses,
    Spawns,
    Assumes,
    Creates,
    Contacts,
    MatchesIndicator,
    ObservedIn,
    DependsOn,
    Supports,
    Refutes,
    Contradicts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeState {
    Unresolved,
    Proposed,
    Validated,
    Rejected,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalEdge {
    pub schema_version: u32,
    pub edge_id: EdgeId,
    pub from: GraphNodeId,
    pub to: GraphNodeId,
    pub relation: CausalRelation,
    pub confidence_basis_points: u16,
    pub source_evidence_ids: BTreeSet<EvidenceId>,
    pub producer_role: GraphProducerRole,
    pub producer_identity: AgentId,
    pub observed_at: GraphLogicalTime,
    pub state: EdgeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<EdgeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<EvidenceWitness>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct EdgeIdentityMaterial<'a> {
    from: &'a GraphNodeId,
    to: &'a GraphNodeId,
    relation: CausalRelation,
    confidence_basis_points: u16,
    source_evidence_ids: &'a BTreeSet<EvidenceId>,
    producer_role: GraphProducerRole,
    producer_identity: &'a AgentId,
    observed_at: GraphLogicalTime,
    state: EdgeState,
    supersedes: &'a Option<EdgeId>,
}

impl CausalEdge {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I>(
        from: &GraphNodeId,
        to: &GraphNodeId,
        relation: CausalRelation,
        confidence_basis_points: u16,
        source_evidence_ids: I,
        producer_role: GraphProducerRole,
        producer_identity: AgentId,
        observed_at: GraphLogicalTime,
        state: EdgeState,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceId>,
    {
        let source_evidence_ids = source_evidence_ids.into_iter().collect::<BTreeSet<_>>();
        validate_id_set("edge.source_evidence_ids", &source_evidence_ids, 256, 256)?;
        validate_agent_id("edge.producer_identity", &producer_identity)?;
        observed_at.validate()?;
        if confidence_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: confidence_basis_points,
            });
        }
        if matches!(state, EdgeState::Proposed | EdgeState::Validated)
            && source_evidence_ids.is_empty()
        {
            return Err(GraphAdmissionError::UnprovenEdge);
        }
        if from == to {
            return Err(GraphAdmissionError::InvalidField {
                field: "edge.from".to_string(),
                reason: "from and to must differ".to_string(),
            });
        }
        validate_text("edge.from", from.as_str(), 256)?;
        validate_text("edge.to", to.as_str(), 256)?;
        let supersedes = None;
        let material = EdgeIdentityMaterial {
            from,
            to,
            relation,
            confidence_basis_points,
            source_evidence_ids: &source_evidence_ids,
            producer_role,
            producer_identity: &producer_identity,
            observed_at,
            state,
            supersedes: &supersedes,
        };
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            edge_id: EdgeId::new(format!("edge:{}", canonical_digest(&material)?)),
            from: from.clone(),
            to: to.clone(),
            relation,
            confidence_basis_points,
            source_evidence_ids,
            producer_role,
            producer_identity,
            observed_at,
            state,
            supersedes,
            witness: None,
        })
    }

    pub fn signed_with(
        mut self,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        self.producer_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        self.edge_id = self.derived_id()?;
        let scoped_agent_id = scoped_agent_id.into();
        let record_bytes = self.canonical_bytes_without_witness()?;
        let bytes = witness_binding_bytes(&record_bytes, self.producer_role, &scoped_agent_id)?;
        self.witness = Some(EvidenceWitness::new(
            signer,
            self.producer_role,
            scoped_agent_id,
            &bytes,
        )?);
        self.validate(&persistence_limits()).map(|()| self)
    }

    pub fn validate(&self, limits: &GraphResourceLimits) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("edge.edge_id", &self.edge_id, 256)?;
        validate_id("edge.from", &self.from, 256)?;
        validate_id("edge.to", &self.to, 256)?;
        if let Some(supersedes) = &self.supersedes {
            validate_id("edge.supersedes", supersedes, 256)?;
            if supersedes == &self.edge_id {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "an edge cannot supersede itself".to_string(),
                });
            }
        }
        validate_agent_id("edge.producer_identity", &self.producer_identity)?;
        self.observed_at.validate()?;
        validate_text("edge.from", self.from.as_str(), 256)?;
        validate_text("edge.to", self.to.as_str(), 256)?;
        if self.from == self.to {
            return Err(GraphAdmissionError::InvalidField {
                field: "edge.from".to_string(),
                reason: "from and to must differ".to_string(),
            });
        }
        if self.confidence_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: self.confidence_basis_points,
            });
        }
        if self.source_evidence_ids.len() > limits.max_evidence_references_per_edge {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "edge.source_evidence_ids".to_string(),
                limit: limits.max_evidence_references_per_edge,
            });
        }
        validate_id_set(
            "edge.source_evidence_ids",
            &self.source_evidence_ids,
            limits.max_evidence_references_per_edge,
            256,
        )?;
        if matches!(self.state, EdgeState::Proposed | EdgeState::Validated)
            && self.source_evidence_ids.is_empty()
        {
            return Err(GraphAdmissionError::UnprovenEdge);
        }
        if self.derived_id()? != self.edge_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.edge_id.0.clone(),
            });
        }
        let witness = self
            .witness
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidWitness {
                reason: "causal edge requires a self-contained signed witness".to_string(),
            })?;
        if witness.producer_identity != self.producer_identity
            || witness.producer_role != self.producer_role
        {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "causal edge witness does not bind producer identity and role".to_string(),
            });
        }
        let record_bytes = self.canonical_bytes_without_witness()?;
        let bytes = witness_binding_bytes(
            &record_bytes,
            witness.producer_role,
            &witness.scoped_agent_id,
        )?;
        witness.validate(&bytes)?;
        Ok(())
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&self.identity_material()).map_err(|error| {
            GraphAdmissionError::Canonicalization {
                reason: error.to_string(),
            }
        })
    }

    fn identity_material(&self) -> EdgeIdentityMaterial<'_> {
        EdgeIdentityMaterial {
            from: &self.from,
            to: &self.to,
            relation: self.relation,
            confidence_basis_points: self.confidence_basis_points,
            source_evidence_ids: &self.source_evidence_ids,
            producer_role: self.producer_role,
            producer_identity: &self.producer_identity,
            observed_at: self.observed_at,
            state: self.state,
            supersedes: &self.supersedes,
        }
    }

    pub fn derived_id(&self) -> Result<EdgeId, GraphAdmissionError> {
        Ok(EdgeId::new(format!(
            "edge:{}",
            canonical_digest(&self.identity_material())?
        )))
    }

    pub fn validate_identity_admission(
        &self,
        admitted_evidence: &BTreeMap<EvidenceId, EvidenceEnvelope>,
    ) -> Result<(), GraphAdmissionError> {
        if self.source_evidence_ids.is_empty() {
            return Ok(());
        }
        let mut identities = BTreeSet::new();
        for evidence_id in &self.source_evidence_ids {
            let evidence = admitted_evidence
                .get(evidence_id)
                .ok_or(GraphAdmissionError::UnknownEvidence)?;
            identities.insert(evidence.witness.producer_identity.clone());
        }
        if !identities.contains(&self.producer_identity) {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "edge producer identity is not an admitted evidence witness".to_string(),
            });
        }
        Ok(())
    }

    pub fn validate_temporal_admission(
        &self,
        admitted_evidence: &BTreeMap<EvidenceId, EvidenceEnvelope>,
    ) -> Result<(), GraphAdmissionError> {
        for evidence_id in &self.source_evidence_ids {
            let evidence = admitted_evidence
                .get(evidence_id)
                .ok_or(GraphAdmissionError::UnknownEvidence)?;
            let uncertainty = i64::try_from(evidence.clock.uncertainty_ms).map_err(|_| {
                GraphAdmissionError::InvalidField {
                    field: "edge.observed_at".to_string(),
                    reason: "evidence uncertainty does not fit in logical time".to_string(),
                }
            })?;
            let lower = evidence
                .clock
                .observed_at
                .as_millis()
                .checked_sub(uncertainty)
                .unwrap_or(0);
            if self.observed_at.as_millis() < lower {
                return Err(GraphAdmissionError::InvalidField {
                    field: "edge.observed_at".to_string(),
                    reason: "precedes supporting evidence outside its uncertainty window"
                        .to_string(),
                });
            }
            if let Some(ingested_at) = evidence.clock.ingested_at {
                let upper = ingested_at.as_millis().checked_add(uncertainty).ok_or(
                    GraphAdmissionError::InvalidField {
                        field: "edge.observed_at".to_string(),
                        reason: "overflows logical time".to_string(),
                    },
                )?;
                if self.observed_at.as_millis() > upper {
                    return Err(GraphAdmissionError::InvalidField {
                        field: "edge.observed_at".to_string(),
                        reason:
                            "follows supporting evidence ingestion outside its uncertainty window"
                                .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContradictionKind {
    EvidenceConflict,
    SourceTimeConflict,
    RelationConflict,
    HypothesisConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContradictionRecord {
    pub schema_version: u32,
    pub contradiction_id: ContradictionId,
    pub kind: ContradictionKind,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub basis: String,
}

impl ContradictionRecord {
    pub fn new<I>(
        kind: ContradictionKind,
        evidence_ids: I,
        basis: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceId>,
    {
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        validate_id_set("contradiction.evidence_ids", &evidence_ids, 256, 256)?;
        let basis = basis.into();
        if evidence_ids.len() < 2 {
            return Err(GraphAdmissionError::InvalidField {
                field: "contradiction.evidence_ids".to_string(),
                reason: "at least two evidence IDs are required".to_string(),
            });
        }
        validate_text("contradiction.basis", &basis, 512)?;
        let material = (kind, &evidence_ids, &basis);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            contradiction_id: ContradictionId::new(format!(
                "contradiction:{}",
                canonical_digest(&material)?
            )),
            kind,
            evidence_ids,
            basis,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id(
            "contradiction.contradiction_id",
            &self.contradiction_id,
            256,
        )?;
        if self.evidence_ids.len() < 2 {
            return Err(GraphAdmissionError::InvalidField {
                field: "contradiction.evidence_ids".to_string(),
                reason: "at least two evidence IDs are required".to_string(),
            });
        }
        validate_id_set("contradiction.evidence_ids", &self.evidence_ids, 256, 256)?;
        validate_text("contradiction.basis", &self.basis, 512)?;
        if self.derived_id()? != self.contradiction_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.contradiction_id.0.clone(),
            });
        }
        Ok(())
    }

    pub fn derived_id(&self) -> Result<ContradictionId, GraphAdmissionError> {
        Ok(ContradictionId::new(format!(
            "contradiction:{}",
            canonical_digest(&(&self.kind, &self.evidence_ids, &self.basis))?
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictRecord {
    pub schema_version: u32,
    pub conflict_id: ContradictionId,
    pub left_evidence_id: EvidenceId,
    pub right_evidence_id: EvidenceId,
    pub comparison_basis: String,
    pub kind: ContradictionKind,
}

impl ConflictRecord {
    pub fn new(
        left_evidence_id: EvidenceId,
        right_evidence_id: EvidenceId,
        kind: ContradictionKind,
        comparison_basis: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        if left_evidence_id == right_evidence_id {
            return Err(GraphAdmissionError::InvalidField {
                field: "conflict.evidence_ids".to_string(),
                reason: "conflict endpoints must differ".to_string(),
            });
        }
        let comparison_basis = comparison_basis.into();
        validate_text("conflict.comparison_basis", &comparison_basis, 512)?;
        let (left_evidence_id, right_evidence_id) =
            canonical_conflict_endpoints(left_evidence_id, right_evidence_id);
        let material = (
            &left_evidence_id,
            &right_evidence_id,
            kind,
            &comparison_basis,
        );
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            conflict_id: ContradictionId::new(format!("conflict:{}", canonical_digest(&material)?)),
            left_evidence_id,
            right_evidence_id,
            comparison_basis,
            kind,
        })
    }

    pub fn derived_id(&self) -> Result<ContradictionId, GraphAdmissionError> {
        Ok(ContradictionId::new(format!(
            "conflict:{}",
            canonical_digest(&(
                &self.left_evidence_id,
                &self.right_evidence_id,
                self.kind,
                &self.comparison_basis,
            ))?
        )))
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("conflict.conflict_id", &self.conflict_id, 256)?;
        validate_id("conflict.left_evidence_id", &self.left_evidence_id, 256)?;
        validate_id("conflict.right_evidence_id", &self.right_evidence_id, 256)?;
        if self.left_evidence_id == self.right_evidence_id {
            return Err(GraphAdmissionError::InvalidField {
                field: "conflict.evidence_ids".to_string(),
                reason: "conflict endpoints must differ".to_string(),
            });
        }
        if self.left_evidence_id > self.right_evidence_id {
            return Err(GraphAdmissionError::InvalidField {
                field: "conflict.evidence_ids".to_string(),
                reason: "conflict endpoints must be in canonical order".to_string(),
            });
        }
        validate_text("conflict.comparison_basis", &self.comparison_basis, 512)?;
        if self.derived_id()? != self.conflict_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.conflict_id.0.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisGraph {
    pub schema_version: u32,
    pub graph_id: GraphId,
    pub version: u64,
    pub limits: GraphResourceLimits,
    pub nodes: BTreeMap<GraphNodeId, GraphNode>,
    pub evidence: BTreeMap<EvidenceId, EvidenceEnvelope>,
    pub edges: BTreeMap<EdgeId, CausalEdge>,
    pub contradictions: BTreeMap<ContradictionId, ContradictionRecord>,
    pub conflicts: BTreeMap<ContradictionId, ConflictRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct HypothesisGraphWire {
    schema_version: u32,
    graph_id: GraphId,
    version: u64,
    limits: GraphResourceLimits,
    nodes: BTreeMap<GraphNodeId, GraphNode>,
    evidence: BTreeMap<EvidenceId, EvidenceEnvelope>,
    edges: BTreeMap<EdgeId, CausalEdge>,
    contradictions: BTreeMap<ContradictionId, ContradictionRecord>,
    conflicts: BTreeMap<ContradictionId, ConflictRecord>,
}

impl<'de> Deserialize<'de> for HypothesisGraph {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = HypothesisGraphWire::deserialize(deserializer)?;
        let graph = Self {
            schema_version: wire.schema_version,
            graph_id: wire.graph_id,
            version: wire.version,
            limits: wire.limits,
            nodes: wire.nodes,
            evidence: wire.evidence,
            edges: wire.edges,
            contradictions: wire.contradictions,
            conflicts: wire.conflicts,
        };
        graph.validate().map_err(serde::de::Error::custom)?;
        Ok(graph)
    }
}

impl HypothesisGraph {
    pub fn new(
        graph_id: GraphId,
        limits: GraphResourceLimits,
    ) -> Result<Self, GraphAdmissionError> {
        limits.validate()?;
        validate_text("graph_id", graph_id.as_str(), 256)?;
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            graph_id,
            version: 0,
            limits,
            nodes: BTreeMap::new(),
            evidence: BTreeMap::new(),
            edges: BTreeMap::new(),
            contradictions: BTreeMap::new(),
            conflicts: BTreeMap::new(),
        })
    }

    pub fn admit_node(&mut self, node: GraphNode) -> Result<(), GraphAdmissionError> {
        node.validate()?;
        if let GraphNode::Process(process) = &node
            && let Some(parent_id) = &process.parent_node_id
        {
            match self.nodes.get(parent_id) {
                Some(GraphNode::Process(_)) => {}
                Some(_) => {
                    return Err(GraphAdmissionError::InvalidField {
                        field: "process.parent_node_id".to_string(),
                        reason: "process parent must reference a process node".to_string(),
                    });
                }
                None => {
                    return Err(GraphAdmissionError::UnknownNode {
                        id: parent_id.0.clone(),
                    });
                }
            }
        }
        if self.nodes.len() >= self.limits.max_nodes && !self.nodes.contains_key(node.id()) {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "nodes".to_string(),
                limit: self.limits.max_nodes,
            });
        }
        if let Some(existing) = self.nodes.get(node.id()) {
            if existing != &node {
                return Err(GraphAdmissionError::IdCollision {
                    id: node.id().0.clone(),
                });
            }
            return Ok(());
        }
        self.bump_version()?;
        self.nodes.insert(node.id().clone(), node);
        Ok(())
    }

    pub fn admit_evidence(
        &mut self,
        evidence: EvidenceEnvelope,
    ) -> Result<(), GraphAdmissionError> {
        evidence.validate()?;
        let size = evidence.canonical_bytes()?.len();
        if size > self.limits.max_evidence_bytes {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "evidence_bytes".to_string(),
                limit: self.limits.max_evidence_bytes,
            });
        }
        if let Some(existing) = self.evidence.get(&evidence.evidence_id) {
            if existing.deterministic_content_bytes()? != evidence.deterministic_content_bytes()? {
                return Err(GraphAdmissionError::IdCollision {
                    id: evidence.evidence_id.0.clone(),
                });
            }
            return Ok(());
        }
        let total_bytes = self
            .evidence
            .values()
            .map(|item| item.canonical_bytes().map(|bytes| bytes.len()))
            .try_fold(0_usize, |total, size| {
                size.map(|size| total.saturating_add(size))
            })?;
        if total_bytes.saturating_add(size) > self.limits.max_evidence_bytes {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "evidence_bytes".to_string(),
                limit: self.limits.max_evidence_bytes,
            });
        }
        self.bump_version()?;
        self.evidence.insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    pub fn admit_edge(&mut self, edge: CausalEdge) -> Result<(), GraphAdmissionError> {
        edge.validate(&self.limits)?;
        if !self.nodes.contains_key(&edge.from) || !self.nodes.contains_key(&edge.to) {
            return Err(GraphAdmissionError::UnknownNode {
                id: if !self.nodes.contains_key(&edge.from) {
                    edge.from.0.clone()
                } else {
                    edge.to.0.clone()
                },
            });
        }
        if edge
            .source_evidence_ids
            .iter()
            .any(|evidence_id| !self.evidence.contains_key(evidence_id))
        {
            return Err(GraphAdmissionError::UnknownEvidence);
        }
        edge.validate_identity_admission(&self.evidence)?;
        edge.validate_temporal_admission(&self.evidence)?;
        self.validate_edge_topology(&edge)?;
        if self.edges.len() >= self.limits.max_edges && !self.edges.contains_key(&edge.edge_id) {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "edges".to_string(),
                limit: self.limits.max_edges,
            });
        }
        if let Some(existing) = self.edges.get(&edge.edge_id) {
            if existing != &edge {
                return Err(GraphAdmissionError::IdCollision {
                    id: edge.edge_id.0.clone(),
                });
            }
            return Ok(());
        }
        self.bump_version()?;
        self.edges.insert(edge.edge_id.clone(), edge);
        Ok(())
    }

    pub fn admit_contradiction(
        &mut self,
        contradiction: ContradictionRecord,
    ) -> Result<(), GraphAdmissionError> {
        contradiction.validate()?;
        if self.contradictions.len() >= self.limits.max_contradictions
            && !self
                .contradictions
                .contains_key(&contradiction.contradiction_id)
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "contradictions".to_string(),
                limit: self.limits.max_contradictions,
            });
        }
        if let Some(existing) = self.contradictions.get(&contradiction.contradiction_id) {
            if existing != &contradiction {
                return Err(GraphAdmissionError::IdCollision {
                    id: contradiction.contradiction_id.0.clone(),
                });
            }
            return Ok(());
        }
        if contradiction
            .evidence_ids
            .iter()
            .any(|evidence_id| !self.evidence.contains_key(evidence_id))
        {
            return Err(GraphAdmissionError::UnknownEvidence);
        }
        self.bump_version()?;
        self.contradictions
            .insert(contradiction.contradiction_id.clone(), contradiction);
        Ok(())
    }

    pub fn admit_conflict(&mut self, conflict: ConflictRecord) -> Result<(), GraphAdmissionError> {
        conflict.validate()?;
        if !self.evidence.contains_key(&conflict.left_evidence_id)
            || !self.evidence.contains_key(&conflict.right_evidence_id)
        {
            return Err(GraphAdmissionError::UnknownEvidence);
        }
        if self.conflicts.len() >= self.limits.max_contradictions
            && !self.conflicts.contains_key(&conflict.conflict_id)
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "conflicts".to_string(),
                limit: self.limits.max_contradictions,
            });
        }
        if let Some(existing) = self.conflicts.get(&conflict.conflict_id) {
            if existing != &conflict {
                return Err(GraphAdmissionError::IdCollision {
                    id: conflict.conflict_id.0.clone(),
                });
            }
            return Ok(());
        }
        self.bump_version()?;
        self.conflicts
            .insert(conflict.conflict_id.clone(), conflict);
        Ok(())
    }

    /// Remove one runtime-indexed conflict while preserving the graph version
    /// invariant.  The version is checked before removal so an exhausted
    /// graph cannot mutate and then report an overflow failure.
    pub fn remove_conflict(
        &mut self,
        conflict_id: &ContradictionId,
    ) -> Result<bool, GraphAdmissionError> {
        if !self.conflicts.contains_key(conflict_id) {
            return Ok(false);
        }
        self.bump_version()?;
        debug_assert!(self.conflicts.remove(conflict_id).is_some());
        Ok(true)
    }

    fn bump_version(&mut self) -> Result<(), GraphAdmissionError> {
        self.version =
            self.version
                .checked_add(1)
                .ok_or_else(|| GraphAdmissionError::InvalidTransition {
                    reason: "graph version is exhausted".to_string(),
                })?;
        Ok(())
    }

    fn validate_edge_topology(&self, candidate: &CausalEdge) -> Result<(), GraphAdmissionError> {
        let outgoing = self
            .edges
            .values()
            .filter(|edge| edge.from == candidate.from)
            .count();
        if outgoing >= self.limits.max_graph_fan_out && !self.edges.contains_key(&candidate.edge_id)
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "graph.fan_out".to_string(),
                limit: self.limits.max_graph_fan_out,
            });
        }

        let mut adjacency: BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>> = BTreeMap::new();
        for edge in self.edges.values() {
            adjacency
                .entry(edge.from.clone())
                .or_default()
                .insert(edge.to.clone());
        }
        adjacency
            .entry(candidate.from.clone())
            .or_default()
            .insert(candidate.to.clone());

        if reaches(&adjacency, &candidate.to, &candidate.from) {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "causal edges must remain acyclic".to_string(),
            });
        }
        if let Some(depth) = graph_depth(&adjacency)
            && depth > self.limits.max_graph_depth
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "graph.depth".to_string(),
                limit: self.limits.max_graph_depth,
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        self.limits.validate()?;
        validate_id("graph.graph_id", &self.graph_id, 256)?;
        if self.nodes.len() > self.limits.max_nodes
            || self.edges.len() > self.limits.max_edges
            || self.contradictions.len() > self.limits.max_contradictions
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "graph".to_string(),
                limit: self.limits.max_nodes,
            });
        }
        if self.conflicts.len() > self.limits.max_contradictions {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "graph.conflicts".to_string(),
                limit: self.limits.max_contradictions,
            });
        }
        for (key, node) in &self.nodes {
            if key != node.id() {
                return Err(GraphAdmissionError::IdCollision { id: key.0.clone() });
            }
            node.validate()?;
            if let GraphNode::Process(process) = node
                && let Some(parent_id) = &process.parent_node_id
            {
                match self.nodes.get(parent_id) {
                    Some(GraphNode::Process(_)) => {}
                    Some(_) => {
                        return Err(GraphAdmissionError::InvalidField {
                            field: "process.parent_node_id".to_string(),
                            reason: "process parent must reference a process node".to_string(),
                        });
                    }
                    None => {
                        return Err(GraphAdmissionError::UnknownNode {
                            id: parent_id.0.clone(),
                        });
                    }
                }
            }
        }
        for (key, evidence) in &self.evidence {
            if key != &evidence.evidence_id {
                return Err(GraphAdmissionError::IdCollision { id: key.0.clone() });
            }
            evidence.validate()?;
        }
        let evidence_bytes = self
            .evidence
            .values()
            .map(|evidence| evidence.canonical_bytes().map(|bytes| bytes.len()))
            .try_fold(0_usize, |total, size| {
                size.map(|size| total.saturating_add(size))
            })?;
        if evidence_bytes > self.limits.max_evidence_bytes {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "evidence_bytes".to_string(),
                limit: self.limits.max_evidence_bytes,
            });
        }
        for (key, edge) in &self.edges {
            if key != &edge.edge_id {
                return Err(GraphAdmissionError::IdCollision { id: key.0.clone() });
            }
            edge.validate(&self.limits)?;
            if !self.nodes.contains_key(&edge.from) || !self.nodes.contains_key(&edge.to) {
                return Err(GraphAdmissionError::UnknownNode {
                    id: edge.from.0.clone(),
                });
            }
            if edge
                .source_evidence_ids
                .iter()
                .any(|evidence_id| !self.evidence.contains_key(evidence_id))
            {
                return Err(GraphAdmissionError::UnknownEvidence);
            }
            edge.validate_identity_admission(&self.evidence)?;
            edge.validate_temporal_admission(&self.evidence)?;
        }
        for (key, contradiction) in &self.contradictions {
            if key != &contradiction.contradiction_id {
                return Err(GraphAdmissionError::IdCollision { id: key.0.clone() });
            }
            contradiction.validate()?;
            if contradiction
                .evidence_ids
                .iter()
                .any(|evidence_id| !self.evidence.contains_key(evidence_id))
            {
                return Err(GraphAdmissionError::UnknownEvidence);
            }
        }
        for (key, conflict) in &self.conflicts {
            if key != &conflict.conflict_id {
                return Err(GraphAdmissionError::IdCollision { id: key.0.clone() });
            }
            conflict.validate()?;
            if !self.evidence.contains_key(&conflict.left_evidence_id)
                || !self.evidence.contains_key(&conflict.right_evidence_id)
            {
                return Err(GraphAdmissionError::UnknownEvidence);
            }
        }
        let mut adjacency = BTreeMap::new();
        for edge in self.edges.values() {
            adjacency
                .entry(edge.from.clone())
                .or_insert_with(BTreeSet::new)
                .insert(edge.to.clone());
        }
        for (from, destinations) in &adjacency {
            if destinations.len() > self.limits.max_graph_fan_out {
                return Err(GraphAdmissionError::ResourceLimitExceeded {
                    resource: format!("graph.fan_out:{from}"),
                    limit: self.limits.max_graph_fan_out,
                });
            }
        }
        if reaches_cycle(&adjacency) {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "causal graph contains a cycle".to_string(),
            });
        }
        if let Some(depth) = graph_depth(&adjacency)
            && depth > self.limits.max_graph_depth
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "graph.depth".to_string(),
                limit: self.limits.max_graph_depth,
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphAdmissionError {
    #[error("unsupported schema version {0}")]
    UnsupportedSchema(u32),
    #[error("invalid identifier field `{field}`")]
    InvalidIdentifier { field: String },
    #[error("invalid field `{field}`: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("invalid resource limit `{field}`: {reason}")]
    InvalidLimit { field: String, reason: String },
    #[error("resource `{resource}` exceeded limit {limit}")]
    ResourceLimitExceeded { resource: String, limit: usize },
    #[error("canonicalization failed: {reason}")]
    Canonicalization { reason: String },
    #[error("validated deserialization failed: {reason}")]
    Deserialization { reason: String },
    #[error("invalid confidence basis points {value}")]
    InvalidConfidence { value: u16 },
    #[error("edge has no evidence support")]
    UnprovenEdge,
    #[error("unknown graph node")]
    UnknownNode { id: String },
    #[error("unknown evidence reference")]
    UnknownEvidence,
    #[error("canonical ID collision for `{id}`")]
    IdCollision { id: String },
    #[error("invalid producer witness: {reason}")]
    InvalidWitness { reason: String },
    #[error("invalid state transition: {reason}")]
    InvalidTransition { reason: String },
}

/// Records loaded from durable storage must pass their semantic validator
/// before callers can use them.  `HypothesisGraph` additionally validates from
/// its serde `Deserialize` implementation, while this helper covers the
/// smaller durable records that carry context-specific limits.
pub trait ValidatedGraphRecord: Sized {
    fn validate_record(&self) -> Result<(), GraphAdmissionError>;
}

pub fn deserialize_validated<T>(json: &str) -> Result<T, GraphAdmissionError>
where
    T: DeserializeOwned + ValidatedGraphRecord,
{
    let record: T =
        serde_json::from_str(json).map_err(|error| GraphAdmissionError::Deserialization {
            reason: error.to_string(),
        })?;
    record.validate_record()?;
    Ok(record)
}

fn validate_schema(version: u32) -> Result<(), GraphAdmissionError> {
    if version != HYPOTHESIS_GRAPH_SCHEMA_VERSION {
        return Err(GraphAdmissionError::UnsupportedSchema(version));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max_bytes: usize) -> Result<(), GraphAdmissionError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(GraphAdmissionError::InvalidField {
            field: field.to_string(),
            reason: format!("must be non-empty and at most {max_bytes} bytes"),
        });
    }
    Ok(())
}

fn validate_sha256_digest(field: &str, value: &str) -> Result<(), GraphAdmissionError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GraphAdmissionError::InvalidField {
            field: field.to_string(),
            reason: "must be a canonical lowercase SHA-256 digest".to_string(),
        });
    }
    Ok(())
}

fn validate_id<T: AsRef<str>>(
    field: &str,
    value: &T,
    max_bytes: usize,
) -> Result<(), GraphAdmissionError> {
    validate_text(field, value.as_ref(), max_bytes)
}

fn validate_agent_id(field: &str, value: &AgentId) -> Result<(), GraphAdmissionError> {
    validate_text(field, &value.0, 256)
}

fn validate_id_set<T: AsRef<str>>(
    field: &str,
    values: impl IntoIterator<Item = T>,
    max_len: usize,
    max_bytes: usize,
) -> Result<(), GraphAdmissionError> {
    let mut count = 0_usize;
    for value in values {
        count = count.saturating_add(1);
        if count > max_len {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: field.to_string(),
                limit: max_len,
            });
        }
        validate_text(field, value.as_ref(), max_bytes)?;
    }
    Ok(())
}

fn canonical_conflict_endpoints(left: EvidenceId, right: EvidenceId) -> (EvidenceId, EvidenceId) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn reaches(
    adjacency: &BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>>,
    start: &GraphNodeId,
    target: &GraphNodeId,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start.clone()];
    while let Some(node) = stack.pop() {
        if &node == target {
            return true;
        }
        if !seen.insert(node.clone()) {
            continue;
        }
        if let Some(next) = adjacency.get(&node) {
            stack.extend(next.iter().cloned());
        }
    }
    false
}

fn reaches_cycle(adjacency: &BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>>) -> bool {
    adjacency.iter().any(|(node, children)| {
        children
            .iter()
            .any(|child| child == node || reaches(adjacency, child, node))
    })
}

fn graph_depth(adjacency: &BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>>) -> Option<usize> {
    fn visit(
        node: &GraphNodeId,
        adjacency: &BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>>,
        visiting: &mut BTreeSet<GraphNodeId>,
        memo: &mut BTreeMap<GraphNodeId, usize>,
    ) -> Option<usize> {
        if let Some(depth) = memo.get(node) {
            return Some(*depth);
        }
        if !visiting.insert(node.clone()) {
            return None;
        }
        let mut depth = 1_usize;
        if let Some(children) = adjacency.get(node) {
            for child in children {
                depth = depth.max(visit(child, adjacency, visiting, memo)?.saturating_add(1));
            }
        }
        visiting.remove(node);
        memo.insert(node.clone(), depth);
        Some(depth)
    }

    let mut memo = BTreeMap::new();
    let mut maximum = 0_usize;
    for node in adjacency.keys() {
        maximum = maximum.max(visit(node, adjacency, &mut BTreeSet::new(), &mut memo)?);
    }
    Some(maximum)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBucket {
    High,
    Medium,
    Low,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceDistribution {
    pub schema_version: u32,
    pub buckets: BTreeMap<ConfidenceBucket, u16>,
}

impl ConfidenceDistribution {
    pub fn new<I>(entries: I) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = (ConfidenceBucket, u16)>,
    {
        let buckets = entries.into_iter().collect::<BTreeMap<_, _>>();
        let total = buckets
            .values()
            .try_fold(0_u64, |total, value| total.checked_add(u64::from(*value)))
            .ok_or(GraphAdmissionError::InvalidField {
                field: "confidence.buckets".to_string(),
                reason: "basis-point sum overflowed".to_string(),
            })?;
        if total != u64::from(CONFIDENCE_BASIS_POINTS) {
            return Err(GraphAdmissionError::InvalidField {
                field: "confidence.buckets".to_string(),
                reason: "basis points must sum to 10000".to_string(),
            });
        }
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            buckets,
        })
    }

    pub fn uniform_two() -> Self {
        Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            buckets: BTreeMap::from([
                (ConfidenceBucket::High, 5_000),
                (ConfidenceBucket::Low, 5_000),
            ]),
        }
    }

    pub fn total_basis_points(&self) -> u64 {
        self.buckets
            .values()
            .try_fold(0_u64, |total, value| total.checked_add(u64::from(*value)))
            .unwrap_or(u64::MAX)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        if self.total_basis_points() != u64::from(CONFIDENCE_BASIS_POINTS) {
            return Err(GraphAdmissionError::InvalidField {
                field: "confidence.buckets".to_string(),
                reason: "basis points must sum to 10000".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyReason {
    ConflictingEvidence,
    InsufficientEvidence,
    PartialOrdering,
    SourceClockSkew,
    UnwitnessedClaim,
    MissingKillChainEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Live,
    Selected,
    Retired,
    Falsified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Support,
    Challenge,
    Falsify,
    Adjudicate,
    Reopen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub schema_version: u32,
    pub decision_id: DecisionId,
    pub sequence: u64,
    pub kind: DecisionKind,
    pub hypothesis_id: HypothesisId,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub producer_role: GraphProducerRole,
    pub producer_identity: AgentId,
    pub decided_at: GraphLogicalTime,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_status: Option<HypothesisStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<EvidenceWitness>,
}

impl DecisionRecord {
    pub fn new<I>(
        kind: DecisionKind,
        hypothesis_id: HypothesisId,
        evidence_ids: I,
        producer_role: GraphProducerRole,
        producer_identity: AgentId,
        decided_at: GraphLogicalTime,
        rationale: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceId>,
    {
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        validate_decision_kind_role(kind, producer_role)?;
        validate_id("decision.hypothesis_id", &hypothesis_id, 256)?;
        validate_id_set("decision.evidence_ids", &evidence_ids, 256, 256)?;
        validate_agent_id("decision.producer_identity", &producer_identity)?;
        decided_at.validate()?;
        let rationale = rationale.into();
        validate_text("decision.rationale", &rationale, 512)?;
        if matches!(kind, DecisionKind::Adjudicate | DecisionKind::Falsify)
            && evidence_ids.is_empty()
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "decision.evidence_ids".to_string(),
                reason: "adjudication and falsification require evidence".to_string(),
            });
        }
        let material = (
            &kind,
            &hypothesis_id,
            &evidence_ids,
            &producer_role,
            &producer_identity,
            decided_at,
            &rationale,
            &Option::<HypothesisStatus>::None,
        );
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            decision_id: DecisionId::new(format!("decision:{}", canonical_digest(&material)?)),
            sequence: 0,
            kind,
            hypothesis_id,
            evidence_ids,
            producer_role,
            producer_identity,
            decided_at,
            rationale,
            resulting_status: None,
            witness: None,
        })
    }

    pub fn signed_with(
        mut self,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        self.producer_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        self.decision_id = self.derived_id()?;
        let scoped_agent_id = scoped_agent_id.into();
        let record_bytes = self.canonical_bytes_without_witness()?;
        let bytes = witness_binding_bytes(&record_bytes, self.producer_role, &scoped_agent_id)?;
        self.witness = Some(EvidenceWitness::new(
            signer,
            self.producer_role,
            scoped_agent_id,
            &bytes,
        )?);
        self.validate().map(|()| self)
    }

    pub fn with_resulting_status(
        mut self,
        status: HypothesisStatus,
    ) -> Result<Self, GraphAdmissionError> {
        self.resulting_status = Some(status);
        self.witness = None;
        self.decision_id = self.derived_id()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_decision_kind_role(self.kind, self.producer_role)?;
        validate_id("decision.decision_id", &self.decision_id, 256)?;
        validate_id("decision.hypothesis_id", &self.hypothesis_id, 256)?;
        validate_id_set("decision.evidence_ids", &self.evidence_ids, 256, 256)?;
        validate_agent_id("decision.producer_identity", &self.producer_identity)?;
        self.decided_at.validate()?;
        validate_text("decision.rationale", &self.rationale, 512)?;
        if matches!(self.kind, DecisionKind::Adjudicate | DecisionKind::Falsify)
            && self.evidence_ids.is_empty()
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "decision.evidence_ids".to_string(),
                reason: "adjudication and falsification require evidence".to_string(),
            });
        }
        if self.kind == DecisionKind::Adjudicate && self.resulting_status.is_none() {
            return Err(GraphAdmissionError::InvalidField {
                field: "decision.resulting_status".to_string(),
                reason: "adjudication must state the resulting status".to_string(),
            });
        }
        match (self.kind, self.resulting_status) {
            (DecisionKind::Support | DecisionKind::Challenge, Some(_)) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "support and challenge decisions cannot change status".to_string(),
                });
            }
            (DecisionKind::Support | DecisionKind::Challenge, None) => {}
            (DecisionKind::Falsify, Some(HypothesisStatus::Falsified) | None) => {}
            (DecisionKind::Falsify, Some(_)) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "falsification must result in falsified status".to_string(),
                });
            }
            (DecisionKind::Adjudicate, Some(HypothesisStatus::Live) | None) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "adjudication must produce a non-live status".to_string(),
                });
            }
            (DecisionKind::Adjudicate, Some(_)) => {}
            (DecisionKind::Reopen, Some(HypothesisStatus::Live) | None) => {}
            (DecisionKind::Reopen, Some(_)) => {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "reopening must return a hypothesis to live status".to_string(),
                });
            }
        }
        if self.derived_id()? != self.decision_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.decision_id.0.clone(),
            });
        }
        let witness = self
            .witness
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidWitness {
                reason: "decision requires a self-contained signed witness".to_string(),
            })?;
        if witness.producer_identity != self.producer_identity
            || witness.producer_role != self.producer_role
        {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "decision witness does not bind producer identity and role".to_string(),
            });
        }
        let record_bytes = self.canonical_bytes_without_witness()?;
        let bytes = witness_binding_bytes(
            &record_bytes,
            witness.producer_role,
            &witness.scoped_agent_id,
        )?;
        witness.validate(&bytes)?;
        Ok(())
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&(
            &self.schema_version,
            &self.decision_id,
            &self.kind,
            &self.hypothesis_id,
            &self.evidence_ids,
            &self.producer_role,
            &self.producer_identity,
            self.decided_at,
            &self.rationale,
            &self.resulting_status,
        ))
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub fn derived_id(&self) -> Result<DecisionId, GraphAdmissionError> {
        Ok(DecisionId::new(format!(
            "decision:{}",
            canonical_digest(&(
                &self.kind,
                &self.hypothesis_id,
                &self.evidence_ids,
                &self.producer_role,
                &self.producer_identity,
                self.decided_at,
                &self.rationale,
                &self.resulting_status,
            ))?
        )))
    }

    pub fn validate_identity_admission(
        &self,
        admitted_evidence: &BTreeMap<EvidenceId, EvidenceEnvelope>,
    ) -> Result<(), GraphAdmissionError> {
        if self.evidence_ids.is_empty() {
            return Ok(());
        }
        let mut identities = BTreeSet::new();
        for evidence_id in &self.evidence_ids {
            let evidence = admitted_evidence
                .get(evidence_id)
                .ok_or(GraphAdmissionError::UnknownEvidence)?;
            identities.insert(evidence.witness.producer_identity.clone());
        }
        if !identities.contains(&self.producer_identity) {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "decision producer identity is not an admitted evidence witness"
                    .to_string(),
            });
        }
        Ok(())
    }
}

fn validate_decision_kind_role(
    kind: DecisionKind,
    role: GraphProducerRole,
) -> Result<(), GraphAdmissionError> {
    let allowed = matches!(
        (kind, role),
        (DecisionKind::Support, GraphProducerRole::Hunter)
            | (DecisionKind::Challenge, GraphProducerRole::Challenger)
            | (DecisionKind::Falsify, GraphProducerRole::Falsifier)
            | (
                DecisionKind::Adjudicate | DecisionKind::Reopen,
                GraphProducerRole::Adjudicator
            )
    );
    if !allowed {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "decision producer role is not authorized for its decision kind".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hypothesis {
    pub schema_version: u32,
    pub hypothesis_id: HypothesisId,
    pub graph_version: u64,
    pub claims: BTreeSet<EdgeId>,
    pub confidence: ConfidenceDistribution,
    pub uncertainty: BTreeSet<UncertaintyReason>,
    pub contradiction_ids: BTreeSet<ContradictionId>,
    pub decision_history: Vec<DecisionRecord>,
    pub status: HypothesisStatus,
}

impl Hypothesis {
    pub fn new<I, J>(
        hypothesis_id: HypothesisId,
        confidence: ConfidenceDistribution,
        uncertainty: I,
        contradiction_ids: J,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = UncertaintyReason>,
        J: IntoIterator<Item = ContradictionId>,
    {
        let uncertainty = uncertainty.into_iter().collect::<BTreeSet<_>>();
        let contradiction_ids = contradiction_ids.into_iter().collect::<BTreeSet<_>>();
        validate_text("hypothesis_id", hypothesis_id.as_str(), 256)?;
        validate_id_set("hypothesis.contradiction_ids", &contradiction_ids, 256, 256)?;
        confidence.validate()?;
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            hypothesis_id,
            graph_version: 0,
            claims: BTreeSet::new(),
            confidence,
            uncertainty,
            contradiction_ids,
            decision_history: Vec::new(),
            status: HypothesisStatus::Live,
        })
    }

    pub fn with_claims<I>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = EdgeId>,
    {
        self.claims = claims.into_iter().collect();
        self
    }

    pub fn append_decision(
        mut self,
        mut decision: DecisionRecord,
    ) -> Result<Self, GraphAdmissionError> {
        decision.validate()?;
        if decision.sequence != 0 {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "new decisions must not reuse a sequence".to_string(),
            });
        }
        if decision.hypothesis_id != self.hypothesis_id {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "decision targets a different hypothesis".to_string(),
            });
        }
        let next_status = next_hypothesis_status(self.status, &decision)?;
        decision.sequence = self.decision_history.len() as u64 + 1;
        self.status = next_status;
        self.decision_history.push(decision);
        Ok(self)
    }

    pub fn validate(&self, limits: &GraphResourceLimits) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("hypothesis.hypothesis_id", &self.hypothesis_id, 256)?;
        validate_id_set("hypothesis.claims", &self.claims, limits.max_edges, 256)?;
        validate_id_set(
            "hypothesis.contradiction_ids",
            &self.contradiction_ids,
            limits.max_contradictions,
            256,
        )?;
        self.confidence.validate()?;
        if self.decision_history.len() > limits.max_decisions_per_hypothesis {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "hypothesis.decision_history".to_string(),
                limit: limits.max_decisions_per_hypothesis,
            });
        }
        let mut expected = 1_u64;
        let mut replayed_status = HypothesisStatus::Live;
        for decision in &self.decision_history {
            decision.validate()?;
            if decision.sequence != expected || decision.hypothesis_id != self.hypothesis_id {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "decision history is not append-only".to_string(),
                });
            }
            replayed_status = next_hypothesis_status(replayed_status, decision)?;
            expected = expected.saturating_add(1);
        }
        if replayed_status != self.status {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "hypothesis status does not match decision history".to_string(),
            });
        }
        Ok(())
    }
}

fn next_hypothesis_status(
    current: HypothesisStatus,
    decision: &DecisionRecord,
) -> Result<HypothesisStatus, GraphAdmissionError> {
    let requested = decision.resulting_status;
    match decision.kind {
        DecisionKind::Support | DecisionKind::Challenge => {
            if requested.is_some() {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "support and challenge cannot change hypothesis status".to_string(),
                });
            }
            if matches!(
                current,
                HypothesisStatus::Retired | HypothesisStatus::Falsified
            ) {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "terminal hypotheses require reopen before support or challenge"
                        .to_string(),
                });
            }
            Ok(current)
        }
        DecisionKind::Falsify => {
            if !matches!(current, HypothesisStatus::Live | HypothesisStatus::Selected) {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "only live or selected hypotheses can be falsified".to_string(),
                });
            }
            if let Some(status) = requested
                && status != HypothesisStatus::Falsified
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "falsification must result in falsified status".to_string(),
                });
            }
            Ok(HypothesisStatus::Falsified)
        }
        DecisionKind::Adjudicate => {
            if !matches!(current, HypothesisStatus::Live | HypothesisStatus::Selected) {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "only live or selected hypotheses can be adjudicated".to_string(),
                });
            }
            let status = requested.ok_or(GraphAdmissionError::InvalidTransition {
                reason: "adjudication must include resulting status".to_string(),
            })?;
            if status == HypothesisStatus::Live {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "adjudication cannot return a live status".to_string(),
                });
            }
            if matches!(
                status,
                HypothesisStatus::Retired | HypothesisStatus::Falsified
            ) && decision.evidence_ids.is_empty()
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "terminal adjudication requires evidence".to_string(),
                });
            }
            Ok(status)
        }
        DecisionKind::Reopen => {
            if current == HypothesisStatus::Live {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "live hypotheses cannot be reopened".to_string(),
                });
            }
            if let Some(status) = requested
                && status != HypothesisStatus::Live
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "reopen must return a hypothesis to live status".to_string(),
                });
            }
            Ok(HypothesisStatus::Live)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    AcquireEvidence,
    ChallengeEdge,
    FalsifyHypothesis,
}

impl TaskKind {
    /// Closed scheduler rank.  This is deliberately not derived from enum
    /// layout so adding a variant cannot silently change durable ordering.
    pub const fn dispatch_rank(self) -> u8 {
        match self {
            Self::AcquireEvidence => 0,
            Self::ChallengeEdge => 1,
            Self::FalsifyHypothesis => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskTarget {
    Evidence { evidence_id: EvidenceId },
    Edge { edge_id: EdgeId },
    Hypothesis { hypothesis_id: HypothesisId },
}

impl TaskTarget {
    fn validate(&self) -> Result<(), GraphAdmissionError> {
        match self {
            Self::Evidence { evidence_id } => {
                validate_id("task.target.evidence_id", evidence_id, 256)
            }
            Self::Edge { edge_id } => validate_id("task.target.edge_id", edge_id, 256),
            Self::Hypothesis { hypothesis_id } => {
                validate_id("task.target.hypothesis_id", hypothesis_id, 256)
            }
        }
    }
}

/// Derive the claimant-independent identity for one investigation operation.
///
/// The seed is intentionally part of the canonical material: a retry by a
/// different claimant must address the same logical task, while a new seed
/// must create a distinct task.  Claimant-scoped idempotency remains owned by
/// [`TaskClaimRequest`].
pub fn derive_logical_task_id(
    graph_id: &GraphId,
    target: &TaskTarget,
    kind: TaskKind,
    seed_digest: &str,
) -> Result<TaskId, GraphAdmissionError> {
    validate_id("task.logical.graph_id", graph_id, 256)?;
    target.validate()?;
    validate_task_kind_target(kind, target)?;
    validate_sha256_digest("task.logical.seed_digest", seed_digest)?;
    let material = (graph_id, target, kind, seed_digest);
    Ok(TaskId::new(format!(
        "task:logical:{}",
        canonical_digest(&material)?
    )))
}

/// Evidence and decision lineage retained by challenge/falsification tasks.
///
/// An optional decision is useful while a task is being assembled, but a
/// terminal challenge/falsification envelope requires it.  Evidence is
/// always required: a challenge without an evidentiary basis is not a
/// reviewable graph transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDecisionLink {
    pub task_id: TaskId,
    pub target: TaskTarget,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub decision_id: Option<DecisionId>,
}

impl TaskDecisionLink {
    pub fn new<I>(
        task_id: TaskId,
        target: TaskTarget,
        evidence_ids: I,
        decision_id: Option<DecisionId>,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceId>,
    {
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        let link = Self {
            task_id,
            target,
            evidence_ids,
            decision_id,
        };
        link.validate()?;
        Ok(link)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_id("task.decision_link.task_id", &self.task_id, 256)?;
        self.target.validate()?;
        if matches!(self.target, TaskTarget::Evidence { .. }) {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "decision lineage must target an edge or hypothesis".to_string(),
            });
        }
        validate_id_set(
            "task.decision_link.evidence_ids",
            &self.evidence_ids,
            256,
            256,
        )?;
        if self.evidence_ids.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "task.decision_link.evidence_ids".to_string(),
                reason: "challenge and falsification lineage requires evidence".to_string(),
            });
        }
        if let Some(decision_id) = &self.decision_id {
            validate_id("task.decision_link.decision_id", decision_id, 256)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceScope {
    pub schema_version: u32,
    pub source_families: BTreeSet<EvidenceSourceFamily>,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub node_ids: BTreeSet<GraphNodeId>,
}

impl EvidenceScope {
    pub fn new<I, J, K>(
        source_families: I,
        evidence_ids: J,
        node_ids: K,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceSourceFamily>,
        J: IntoIterator<Item = EvidenceId>,
        K: IntoIterator<Item = GraphNodeId>,
    {
        let source_families = source_families.into_iter().collect::<BTreeSet<_>>();
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        let node_ids = node_ids.into_iter().collect::<BTreeSet<_>>();
        if source_families.is_empty() && evidence_ids.is_empty() && node_ids.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "task.evidence_scope".to_string(),
                reason: "scope must identify a source, evidence, or node".to_string(),
            });
        }
        if source_families.len() > 6 || evidence_ids.len() > 256 || node_ids.len() > 256 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "task.evidence_scope".to_string(),
                limit: 256,
            });
        }
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            source_families,
            evidence_ids,
            node_ids,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        if self.source_families.is_empty()
            && self.evidence_ids.is_empty()
            && self.node_ids.is_empty()
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "task.evidence_scope".to_string(),
                reason: "scope must not be empty".to_string(),
            });
        }
        if self.source_families.len() > 6
            || self.evidence_ids.len() > 256
            || self.node_ids.len() > 256
        {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "task.evidence_scope".to_string(),
                limit: 256,
            });
        }
        validate_id_set(
            "task.evidence_scope.evidence_ids",
            &self.evidence_ids,
            256,
            256,
        )?;
        validate_id_set("task.evidence_scope.node_ids", &self.node_ids, 256, 256)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskClaimRequest {
    pub schema_version: u32,
    pub task_id: TaskId,
    pub kind: TaskKind,
    pub target: TaskTarget,
    pub role: GraphProducerRole,
    pub claimant: AgentId,
    pub evidence_scope: EvidenceScope,
    pub requested_at: GraphLogicalTime,
    pub idempotency_key: IdempotencyKey,
}

impl TaskClaimRequest {
    pub fn new(
        task_id: TaskId,
        kind: TaskKind,
        target: TaskTarget,
        role: GraphProducerRole,
        claimant: AgentId,
        evidence_scope: EvidenceScope,
        requested_at: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        evidence_scope.validate()?;
        target.validate()?;
        validate_text("task.task_id", task_id.as_str(), 256)?;
        validate_agent_id("task.claimant", &claimant)?;
        requested_at.validate()?;
        validate_task_kind_target(kind, &target)?;
        validate_task_kind_role(kind, role)?;
        let material = (&task_id, kind, &target, role, &claimant, &evidence_scope);
        let idempotency_key =
            IdempotencyKey::new(format!("idempotency:{}", canonical_digest(&material)?));
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            task_id,
            kind,
            target,
            role,
            claimant,
            evidence_scope,
            requested_at,
            idempotency_key,
        })
    }

    pub fn derive_idempotency_key(&self) -> Result<IdempotencyKey, GraphAdmissionError> {
        let material = (
            &self.task_id,
            self.kind,
            &self.target,
            self.role,
            &self.claimant,
            &self.evidence_scope,
        );
        Ok(IdempotencyKey::new(format!(
            "idempotency:{}",
            canonical_digest(&material)?
        )))
    }

    /// Digest the complete, validated claim envelope, including its
    /// claimant-scoped idempotency key and logical request time.  This is the
    /// capability binding used by durable terminal admission; it is distinct
    /// from `derive_idempotency_key`, which deliberately omits arrival time so
    /// a retry can reuse the same operation key.
    pub fn canonical_digest(&self) -> Result<String, GraphAdmissionError> {
        self.validate()?;
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("task.task_id", &self.task_id, 256)?;
        validate_agent_id("task.claimant", &self.claimant)?;
        validate_id("task.idempotency_key", &self.idempotency_key, 256)?;
        self.requested_at.validate()?;
        self.evidence_scope.validate()?;
        self.target.validate()?;
        validate_task_kind_target(self.kind, &self.target)?;
        validate_task_kind_role(self.kind, self.role)?;
        if self.idempotency_key != self.derive_idempotency_key()? {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "idempotency key does not match canonical task claim".to_string(),
            });
        }
        Ok(())
    }
}

fn validate_task_kind_target(
    kind: TaskKind,
    target: &TaskTarget,
) -> Result<(), GraphAdmissionError> {
    let matches = matches!(
        (kind, target),
        (TaskKind::AcquireEvidence, TaskTarget::Evidence { .. })
            | (TaskKind::ChallengeEdge, TaskTarget::Edge { .. })
            | (TaskKind::FalsifyHypothesis, TaskTarget::Hypothesis { .. })
    );
    if !matches {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "task kind does not match its typed target".to_string(),
        });
    }
    Ok(())
}

fn validate_task_kind_role(
    kind: TaskKind,
    role: GraphProducerRole,
) -> Result<(), GraphAdmissionError> {
    let allowed = matches!(
        (kind, role),
        (TaskKind::AcquireEvidence, GraphProducerRole::Hunter)
            | (TaskKind::ChallengeEdge, GraphProducerRole::Challenger)
            | (TaskKind::FalsifyHypothesis, GraphProducerRole::Falsifier)
    );
    if !allowed {
        return Err(GraphAdmissionError::InvalidTransition {
            reason: "task role is not authorized for its task kind".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FencingToken(pub u64);

impl FencingToken {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    fn validate(self) -> Result<(), GraphAdmissionError> {
        if self.0 == 0 {
            return Err(GraphAdmissionError::InvalidField {
                field: "task.lease.fencing_token".to_string(),
                reason: "must be non-zero".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLease {
    pub schema_version: u32,
    pub lease_id: LeaseId,
    pub holder: AgentId,
    pub issued_at: GraphLogicalTime,
    pub expires_at: GraphLogicalTime,
    pub fencing_token: FencingToken,
}

impl TaskLease {
    pub fn new(
        lease_id: LeaseId,
        holder: AgentId,
        issued_at: GraphLogicalTime,
        expires_at: GraphLogicalTime,
        fencing_token: FencingToken,
    ) -> Result<Self, GraphAdmissionError> {
        validate_id("task.lease_id", &lease_id, 256)?;
        validate_agent_id("task.lease.holder", &holder)?;
        issued_at.validate()?;
        expires_at.validate()?;
        fencing_token.validate()?;
        if expires_at <= issued_at {
            return Err(GraphAdmissionError::InvalidField {
                field: "task.lease.expires_at".to_string(),
                reason: "must be after issued_at".to_string(),
            });
        }
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            lease_id,
            holder,
            issued_at,
            expires_at,
            fencing_token,
        })
    }

    pub fn validate_with_limit(&self, max_lease_ms: u64) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("task.lease_id", &self.lease_id, 256)?;
        validate_agent_id("task.lease.holder", &self.holder)?;
        self.issued_at.validate()?;
        self.expires_at.validate()?;
        self.fencing_token.validate()?;
        if self.expires_at <= self.issued_at
            || u64::try_from(
                self.expires_at
                    .as_millis()
                    .checked_sub(self.issued_at.as_millis())
                    .ok_or(GraphAdmissionError::InvalidField {
                        field: "task.lease".to_string(),
                        reason: "lease time is not ordered".to_string(),
                    })?,
            )
            .map_err(|_| GraphAdmissionError::InvalidField {
                field: "task.lease".to_string(),
                reason: "lease duration is not representable".to_string(),
            })? > max_lease_ms
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "task.lease".to_string(),
                reason: "lease is outside the configured logical-time bound".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Claimed,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskCompletionKind {
    EvidenceAdded,
    EdgeChallenged,
    HypothesisFalsified,
    NoFinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCompletion {
    pub schema_version: u32,
    pub kind: TaskCompletionKind,
    pub completed_by: AgentId,
    pub completed_at: GraphLogicalTime,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub summary_digest: String,
}

impl TaskCompletion {
    pub fn new<I>(
        kind: TaskCompletionKind,
        completed_by: AgentId,
        completed_at: GraphLogicalTime,
        evidence_ids: I,
        summary_digest: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceId>,
    {
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        let summary_digest = summary_digest.into();
        validate_agent_id("task.completion.completed_by", &completed_by)?;
        completed_at.validate()?;
        validate_id_set("task.completion.evidence_ids", &evidence_ids, 256, 256)?;
        validate_text("task.completion.summary_digest", &summary_digest, 128)?;
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            kind,
            completed_by,
            completed_at,
            evidence_ids,
            summary_digest,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_agent_id("task.completion.completed_by", &self.completed_by)?;
        self.completed_at.validate()?;
        validate_id_set("task.completion.evidence_ids", &self.evidence_ids, 256, 256)?;
        validate_text("task.completion.summary_digest", &self.summary_digest, 128)
    }
}

/// Bind a worker's claim to the logical task, capability role, and signed
/// canonical claim it is authorized to complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCapabilityProof {
    pub task_id: TaskId,
    pub claimant: AgentId,
    pub role: GraphProducerRole,
    pub kind: TaskKind,
    pub canonical_claim_digest: String,
    pub witness: EvidenceWitness,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskCapabilityMaterial<'a> {
    task_id: &'a TaskId,
    claimant: &'a AgentId,
    role: GraphProducerRole,
    kind: TaskKind,
    canonical_claim_digest: &'a str,
    scoped_agent_id: &'a str,
}

impl TaskCapabilityProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        claimant: AgentId,
        role: GraphProducerRole,
        kind: TaskKind,
        canonical_claim_digest: impl Into<String>,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        Self::signed_with(
            task_id,
            claimant,
            role,
            kind,
            canonical_claim_digest,
            signer,
            scoped_agent_id,
        )
    }

    /// Sign a capability proof with the key belonging to `claimant`.
    #[allow(clippy::too_many_arguments)]
    pub fn signed_with(
        task_id: TaskId,
        claimant: AgentId,
        role: GraphProducerRole,
        kind: TaskKind,
        canonical_claim_digest: impl Into<String>,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let canonical_claim_digest = canonical_claim_digest.into();
        validate_id("task.capability.task_id", &task_id, 256)?;
        validate_agent_id("task.capability.claimant", &claimant)?;
        validate_task_kind_role(kind, role)?;
        validate_sha256_digest(
            "task.capability.canonical_claim_digest",
            &canonical_claim_digest,
        )?;
        let scoped_agent_id = scoped_agent_id.into();
        validate_text("task.capability.scoped_agent_id", &scoped_agent_id, 128)?;
        let signer_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        if signer_identity != claimant {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "capability signer does not match claimant identity".to_string(),
            });
        }
        let material = TaskCapabilityMaterial {
            task_id: &task_id,
            claimant: &claimant,
            role,
            kind,
            canonical_claim_digest: &canonical_claim_digest,
            scoped_agent_id: &scoped_agent_id,
        };
        let bytes = canonical_json_bytes(&material).map_err(|error| {
            GraphAdmissionError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        let witness = EvidenceWitness::new(signer, role, scoped_agent_id, &bytes)?;
        let proof = Self {
            task_id,
            claimant,
            role,
            kind,
            canonical_claim_digest,
            witness,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&TaskCapabilityMaterial {
            task_id: &self.task_id,
            claimant: &self.claimant,
            role: self.role,
            kind: self.kind,
            canonical_claim_digest: &self.canonical_claim_digest,
            scoped_agent_id: &self.witness.scoped_agent_id,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_id("task.capability.task_id", &self.task_id, 256)?;
        validate_agent_id("task.capability.claimant", &self.claimant)?;
        validate_task_kind_role(self.kind, self.role)?;
        validate_sha256_digest(
            "task.capability.canonical_claim_digest",
            &self.canonical_claim_digest,
        )?;
        if self.witness.producer_identity != self.claimant {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "capability witness identity does not match claimant".to_string(),
            });
        }
        if self.witness.producer_role != self.role {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "capability witness role does not match capability".to_string(),
            });
        }
        self.witness.validate(&self.canonical_bytes()?)
    }

    /// Bind this signed capability to one exact durable claim request.  A
    /// matching task ID or claimant alone is insufficient: changing the
    /// request's logical time, target, scope, role, or idempotency key must
    /// produce a different canonical claim digest and fail closed.
    pub fn validate_for_claim(&self, claim: &TaskClaimRequest) -> Result<(), GraphAdmissionError> {
        claim.validate()?;
        self.validate()?;
        if self.task_id != claim.task_id
            || self.claimant != claim.claimant
            || self.role != claim.role
            || self.kind != claim.kind
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "capability does not bind the exact task claim".to_string(),
            });
        }
        if self.canonical_claim_digest != claim.canonical_digest()? {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "capability canonical claim digest does not match task claim".to_string(),
            });
        }
        Ok(())
    }
}

/// Keep completion semantics closed at the task-kind boundary.
pub fn validate_completion_kind(
    task_kind: TaskKind,
    completion_kind: TaskCompletionKind,
) -> Result<(), GraphAdmissionError> {
    let valid = matches!(
        (task_kind, completion_kind),
        (TaskKind::AcquireEvidence, TaskCompletionKind::EvidenceAdded)
            | (TaskKind::AcquireEvidence, TaskCompletionKind::NoFinding)
            | (TaskKind::ChallengeEdge, TaskCompletionKind::EdgeChallenged)
            | (
                TaskKind::FalsifyHypothesis,
                TaskCompletionKind::HypothesisFalsified
            )
    );
    if valid {
        Ok(())
    } else {
        Err(GraphAdmissionError::InvalidTransition {
            reason: "task kind does not permit this completion kind".to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskTerminalMaterial<'a> {
    task_id: &'a TaskId,
    idempotency_key: &'a IdempotencyKey,
    lease_id: &'a LeaseId,
    fencing_token: FencingToken,
    completion: &'a TaskCompletion,
    decision_link: &'a Option<TaskDecisionLink>,
    producer: &'a AgentId,
    capability: &'a TaskCapabilityProof,
    terminal_scope: &'a str,
}

/// A terminal task publication that retains its lease/fence and complete
/// evidence lineage in one typed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskTerminalEnvelope {
    pub task_id: TaskId,
    pub idempotency_key: IdempotencyKey,
    pub lease_id: LeaseId,
    pub fencing_token: FencingToken,
    pub completion: TaskCompletion,
    pub decision_link: Option<TaskDecisionLink>,
    pub producer: AgentId,
    pub capability: TaskCapabilityProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_witness: Option<EvidenceWitness>,
}

impl TaskTerminalEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        idempotency_key: IdempotencyKey,
        lease_id: LeaseId,
        fencing_token: FencingToken,
        completion: TaskCompletion,
        decision_link: Option<TaskDecisionLink>,
        producer: AgentId,
        capability: TaskCapabilityProof,
    ) -> Result<Self, GraphAdmissionError> {
        let envelope = Self {
            task_id,
            idempotency_key,
            lease_id,
            fencing_token,
            completion,
            decision_link,
            producer,
            capability,
            terminal_witness: None,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Attach a claimant-key signature over the complete terminal material.
    /// The structural constructor intentionally leaves this witness absent so
    /// callers cannot mistake an assembled request for durable authority.
    pub fn signed_with(
        mut self,
        signer: &Keypair,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let signer_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        if signer_identity != self.producer || signer_identity != self.capability.claimant {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "terminal signer does not match the claimant producer".to_string(),
            });
        }
        let scoped_agent_id = scoped_agent_id.into();
        validate_text("task.terminal.scoped_agent_id", &scoped_agent_id, 128)?;
        let bytes = self.canonical_bytes_for_scope(&scoped_agent_id)?;
        self.terminal_witness = Some(EvidenceWitness::new(
            signer,
            self.capability.role,
            scoped_agent_id,
            &bytes,
        )?);
        self.validate()?;
        Ok(self)
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        let terminal_scope = self
            .terminal_witness
            .as_ref()
            .map_or("", |witness| witness.scoped_agent_id.as_str());
        self.canonical_bytes_for_scope(terminal_scope)
    }

    fn canonical_bytes_for_scope(
        &self,
        terminal_scope: &str,
    ) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&TaskTerminalMaterial {
            task_id: &self.task_id,
            idempotency_key: &self.idempotency_key,
            lease_id: &self.lease_id,
            fencing_token: self.fencing_token,
            completion: &self.completion,
            decision_link: &self.decision_link,
            producer: &self.producer,
            capability: &self.capability,
            terminal_scope,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_id("task.terminal.task_id", &self.task_id, 256)?;
        validate_id("task.terminal.idempotency_key", &self.idempotency_key, 256)?;
        validate_id("task.terminal.lease_id", &self.lease_id, 256)?;
        self.fencing_token.validate()?;
        self.completion.validate()?;
        validate_agent_id("task.terminal.producer", &self.producer)?;
        self.capability.validate()?;
        if self.capability.task_id != self.task_id {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal capability task does not match envelope task".to_string(),
            });
        }
        if self.capability.claimant != self.producer
            || self.completion.completed_by != self.producer
        {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "terminal producer, completion actor, and claimant must match".to_string(),
            });
        }
        validate_completion_kind(self.capability.kind, self.completion.kind.clone())?;
        match self.capability.kind {
            TaskKind::AcquireEvidence => {
                if self.decision_link.is_some() {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "evidence acquisition cannot carry decision lineage".to_string(),
                    });
                }
            }
            TaskKind::ChallengeEdge | TaskKind::FalsifyHypothesis => {
                let link = self.decision_link.as_ref().ok_or_else(|| {
                    GraphAdmissionError::InvalidField {
                        field: "task.terminal.decision_link".to_string(),
                        reason: "challenge and falsification require decision lineage".to_string(),
                    }
                })?;
                link.validate()?;
                if link.task_id != self.task_id || link.evidence_ids != self.completion.evidence_ids
                {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "terminal evidence does not match decision lineage".to_string(),
                    });
                }
                let target_matches = matches!(
                    (self.capability.kind, &link.target),
                    (TaskKind::ChallengeEdge, TaskTarget::Edge { .. })
                        | (TaskKind::FalsifyHypothesis, TaskTarget::Hypothesis { .. })
                );
                if !target_matches {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "terminal decision target does not match task kind".to_string(),
                    });
                }
                if link.decision_id.is_none() {
                    return Err(GraphAdmissionError::InvalidField {
                        field: "task.terminal.decision_link.decision_id".to_string(),
                        reason: "terminal challenge and falsification require a decision"
                            .to_string(),
                    });
                }
            }
        }
        if let Some(witness) = &self.terminal_witness {
            if witness.producer_identity != self.producer
                || witness.producer_role != self.capability.role
            {
                return Err(GraphAdmissionError::InvalidWitness {
                    reason: "terminal witness does not bind producer and capability role"
                        .to_string(),
                });
            }
            witness.validate(&self.canonical_bytes_without_witness()?)?;
        }
        Ok(())
    }

    /// Validate the terminal publication against the exact claimed task and
    /// its currently active lease.  This is the durable admission boundary;
    /// `validate()` remains structural so an unsigned assembled envelope can
    /// still be represented and inspected before a signer is available.
    pub fn validate_for_task(
        &self,
        task: &TaskRecord,
        max_task_lease_ms: u64,
        max_task_retries: u16,
    ) -> Result<(), GraphAdmissionError> {
        self.validate()?;
        task.validate_with_limits(max_task_lease_ms, max_task_retries)?;
        if task.state != TaskState::Claimed || task.completion.is_some() {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal envelope requires an active claimed task".to_string(),
            });
        }
        let lease = task
            .lease
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidTransition {
                reason: "terminal envelope requires the task's active lease".to_string(),
            })?;
        lease.validate_with_limit(max_task_lease_ms)?;
        self.capability.validate_for_claim(&task.request)?;
        if self.task_id != task.request.task_id
            || self.idempotency_key != task.request.idempotency_key
            || self.lease_id != lease.lease_id
            || self.fencing_token != lease.fencing_token
            || self.producer != lease.holder
            || self.completion.completed_by != lease.holder
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal envelope does not bind the active task lease".to_string(),
            });
        }
        if self.completion.completed_at < lease.issued_at
            || self.completion.completed_at > lease.expires_at
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal completion time is outside the active lease".to_string(),
            });
        }
        if let Some(link) = &self.decision_link
            && link.target != task.request.target
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal decision lineage target does not match the claimed task"
                    .to_string(),
            });
        }
        let Some(witness) = self.terminal_witness.as_ref() else {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "durable terminal admission requires a signed terminal witness".to_string(),
            });
        };
        // Re-run the signature check after all exact-task comparisons above;
        // this prevents a valid capability witness from being replayed with a
        // caller-selected completion, decision, lease, or fence.
        witness.validate(&self.canonical_bytes_without_witness()?)
    }
}

/// Durable proof for a terminal task transition.  A terminal state is not
/// admissible merely because its enum says `completed`, `failed`, or
/// `expired`: the record must retain the exact claimed generation, lease, and
/// fencing token that authorized the transition, together with the actor and
/// logical completion time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskTerminalProof {
    pub schema_version: u32,
    pub prior_state: TaskState,
    pub terminal_state: TaskState,
    pub prior_generation: u64,
    pub prior_lease: TaskLease,
    pub completer: AgentId,
    pub completed_at: GraphLogicalTime,
}

impl TaskTerminalProof {
    pub fn new(
        prior_generation: u64,
        prior_lease: TaskLease,
        terminal_state: TaskState,
        completer: AgentId,
        completed_at: GraphLogicalTime,
        max_task_lease_ms: u64,
    ) -> Result<Self, GraphAdmissionError> {
        let proof = Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            prior_state: TaskState::Claimed,
            terminal_state,
            prior_generation,
            prior_lease,
            completer,
            completed_at,
        };
        proof.validate(max_task_lease_ms)?;
        Ok(proof)
    }

    pub fn validate(&self, max_task_lease_ms: u64) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        if self.prior_state != TaskState::Claimed {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal proof must originate from a claimed task".to_string(),
            });
        }
        if !matches!(
            self.terminal_state,
            TaskState::Completed | TaskState::Failed | TaskState::Expired
        ) {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal proof must name a terminal destination state".to_string(),
            });
        }
        if self.prior_generation == 0 {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal proof prior generation must be positive".to_string(),
            });
        }
        self.prior_lease.validate_with_limit(max_task_lease_ms)?;
        validate_agent_id("task.terminal_proof.completer", &self.completer)?;
        self.completed_at.validate()?;
        if self.completer != self.prior_lease.holder {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal proof completer must equal prior lease holder".to_string(),
            });
        }
        if self.completed_at < self.prior_lease.issued_at {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "terminal proof completion precedes its prior lease".to_string(),
            });
        }
        if matches!(
            self.terminal_state,
            TaskState::Completed | TaskState::Failed
        ) && self.completed_at > self.prior_lease.expires_at
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "completed or failed proof must finish no later than lease expiry"
                    .to_string(),
            });
        }
        if self.terminal_state == TaskState::Expired
            && self.completed_at < self.prior_lease.expires_at
        {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "expired proof must finish at or after lease expiry".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRecord {
    pub schema_version: u32,
    pub request: TaskClaimRequest,
    pub state: TaskState,
    pub generation: u64,
    pub attempts: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<TaskLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<TaskCompletion>,
    pub terminal_history: Vec<TaskTerminalProof>,
}

impl TaskRecord {
    pub fn claimed(
        request: TaskClaimRequest,
        lease: TaskLease,
    ) -> Result<Self, GraphAdmissionError> {
        Self::claimed_with_limits(
            request,
            lease,
            GraphResourceLimits::default().max_task_lease_ms,
            GraphResourceLimits::default().max_task_retries,
        )
    }

    pub fn claimed_with_limits(
        request: TaskClaimRequest,
        lease: TaskLease,
        max_task_lease_ms: u64,
        max_task_retries: u16,
    ) -> Result<Self, GraphAdmissionError> {
        request.validate()?;
        if max_task_retries == 0 {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "max_task_retries".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if lease.holder != request.claimant {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "task lease holder must equal claimant".to_string(),
            });
        }
        lease.validate_with_limit(max_task_lease_ms)?;
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            request,
            state: TaskState::Claimed,
            generation: 1,
            attempts: 1,
            lease: Some(lease),
            completion: None,
            terminal_history: Vec::new(),
        })
    }

    pub fn validate_with_limits(
        &self,
        max_task_lease_ms: u64,
        max_task_retries: u16,
    ) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        self.request.validate()?;
        if max_task_retries == 0 || self.attempts == 0 || self.attempts > max_task_retries {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "max_task_retries".to_string(),
                reason: "task attempts exceed the configured positive retry bound".to_string(),
            });
        }
        if self.generation == 0 {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "task generation must be positive".to_string(),
            });
        }
        if self.terminal_history.len() > usize::from(max_task_retries) {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "task.terminal_history".to_string(),
                limit: usize::from(max_task_retries),
            });
        }
        let mut expected_prior_generation = 1_u64;
        for proof in &self.terminal_history {
            proof.validate(max_task_lease_ms)?;
            if proof.prior_generation != expected_prior_generation {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "terminal proof generations are not append-only".to_string(),
                });
            }
            if proof.prior_lease.holder != self.request.claimant {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "terminal proof lease holder must equal claimant".to_string(),
                });
            }
            expected_prior_generation = expected_prior_generation.saturating_add(1);
        }
        if self.terminal_history.is_empty() && self.generation != 1 {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "a task generation greater than one requires terminal proof history"
                    .to_string(),
            });
        }
        if !self.terminal_history.is_empty() && self.generation != expected_prior_generation {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "task generation does not match terminal proof history".to_string(),
            });
        }
        if let Some(lease) = &self.lease {
            lease.validate_with_limit(max_task_lease_ms)?;
            if lease.holder != self.request.claimant {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "task lease holder must equal claimant".to_string(),
                });
            }
        }
        if let Some(completion) = &self.completion {
            completion.validate()?;
        }
        match self.state {
            TaskState::Pending => {
                if self.lease.is_some()
                    || self.completion.is_some()
                    || !self.terminal_history.is_empty()
                {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "pending tasks cannot carry lease or completion".to_string(),
                    });
                }
            }
            TaskState::Claimed => {
                let lease = self
                    .lease
                    .as_ref()
                    .ok_or(GraphAdmissionError::InvalidTransition {
                        reason: "claimed tasks require a lease".to_string(),
                    })?;
                if self.completion.is_some()
                    || !self.terminal_history.is_empty()
                    || lease.holder != self.request.claimant
                {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "claimed task state is not bound to its lease".to_string(),
                    });
                }
            }
            TaskState::Completed => {
                if self.lease.is_some()
                    || self.completion.is_none()
                    || self.terminal_history.is_empty()
                {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "completed tasks require completion, proof, and no active lease"
                            .to_string(),
                    });
                }
            }
            TaskState::Failed | TaskState::Expired => {
                if self.lease.is_some() || self.terminal_history.is_empty() {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "terminal tasks require proof and cannot retain an active lease"
                            .to_string(),
                    });
                }
            }
        }
        let proof = self.terminal_history.last().filter(|_| {
            matches!(
                self.state,
                TaskState::Completed | TaskState::Failed | TaskState::Expired
            )
        });
        if let Some(proof) = proof {
            if proof.terminal_state != self.state {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "terminal proof destination does not match task state".to_string(),
                });
            }
            if let Some(completion) = &self.completion
                && (proof.completer != completion.completed_by
                    || proof.completed_at != completion.completed_at)
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "terminal proof does not match task completion".to_string(),
                });
            }
            if self.state == TaskState::Completed && self.completion.is_none() {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "completed tasks require a completion matching terminal proof"
                        .to_string(),
                });
            }
            if self.state == TaskState::Expired
                && (self.completion.is_some()
                    || proof.completer != self.request.claimant
                    || proof.completed_at < proof.prior_lease.expires_at)
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "expired task proof must be claimant-owned and at/after lease expiry"
                        .to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn complete(
        mut self,
        completion: TaskCompletion,
        fence: FencingToken,
        max_task_lease_ms: u64,
    ) -> Result<Self, GraphAdmissionError> {
        completion.validate()?;
        let lease = self
            .lease
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidTransition {
                reason: "completion requires the current lease".to_string(),
            })?;
        if self.state != TaskState::Claimed || lease.fencing_token != fence {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "completion requires the current claimed fencing token".to_string(),
            });
        }
        if completion.completed_by != lease.holder {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "completion actor must equal the lease holder".to_string(),
            });
        }
        if completion.completed_at < lease.issued_at || completion.completed_at > lease.expires_at {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "completion time must fall within the active lease".to_string(),
            });
        }
        let proof = TaskTerminalProof::new(
            self.generation,
            lease.clone(),
            TaskState::Completed,
            completion.completed_by.clone(),
            completion.completed_at,
            max_task_lease_ms,
        )?;
        self.terminal_history.push(proof);
        self.state = TaskState::Completed;
        self.generation = self.generation.saturating_add(1);
        self.completion = Some(completion);
        self.lease = None;
        Ok(self)
    }

    pub fn expire(
        mut self,
        now: GraphLogicalTime,
        max_task_lease_ms: u64,
    ) -> Result<Self, GraphAdmissionError> {
        now.validate()?;
        let lease = self
            .lease
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidTransition {
                reason: "only leased tasks can expire".to_string(),
            })?;
        if self.state != TaskState::Claimed || lease.expires_at > now {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "task lease has not expired".to_string(),
            });
        }
        let proof = TaskTerminalProof::new(
            self.generation,
            lease.clone(),
            TaskState::Expired,
            lease.holder.clone(),
            now,
            max_task_lease_ms,
        )?;
        self.terminal_history.push(proof);
        self.state = TaskState::Expired;
        self.generation = self.generation.saturating_add(1);
        self.lease = None;
        Ok(self)
    }
}

/// Closed graph behavior modes.  These values are consumed by orchestration,
/// not merely included in a digest: each mode changes what the coordinator is
/// allowed to converge on or simulate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphPolicyMode {
    EvidenceFirst,
    ChallengeContradictions,
    ConservativeContainment,
}

impl GraphPolicyMode {
    pub const fn requires_evidence_coverage(self) -> bool {
        matches!(self, Self::EvidenceFirst)
    }

    pub const fn emits_falsification_work(self) -> bool {
        matches!(self, Self::ChallengeContradictions)
    }

    pub const fn retains_alternatives(self) -> bool {
        matches!(self, Self::ChallengeContradictions)
    }

    pub const fn requires_reversible_containment(self) -> bool {
        matches!(self, Self::ConservativeContainment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphPolicyMaterial {
    schema_version: u32,
    mode: GraphPolicyMode,
}

/// Canonical policy contract.  The mode is both behavior-bearing and part of
/// the digest, so a caller cannot swap policy behavior while retaining an old
/// contract identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphPolicyContract {
    pub schema_version: u32,
    pub mode: GraphPolicyMode,
    pub policy_digest: String,
}

impl GraphPolicyContract {
    pub fn new(mode: GraphPolicyMode) -> Result<Self, GraphAdmissionError> {
        let material = GraphPolicyMaterial {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            mode,
        };
        let policy_digest = canonical_digest(&material)?;
        let contract = Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            mode,
            policy_digest,
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_sha256_digest("graph_policy.policy_digest", &self.policy_digest)?;
        let expected = canonical_digest(&GraphPolicyMaterial {
            schema_version: self.schema_version,
            mode: self.mode,
        })?;
        if self.policy_digest != expected {
            return Err(GraphAdmissionError::IdCollision {
                id: self.policy_digest.clone(),
            });
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        self.validate()?;
        canonical_json_bytes(&GraphPolicyMaterial {
            schema_version: self.schema_version,
            mode: self.mode,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub const fn requires_evidence_coverage(&self) -> bool {
        self.mode.requires_evidence_coverage()
    }

    pub const fn emits_falsification_work(&self) -> bool {
        self.mode.emits_falsification_work()
    }

    pub const fn retains_alternatives(&self) -> bool {
        self.mode.retains_alternatives()
    }

    pub const fn requires_reversible_containment(&self) -> bool {
        self.mode.requires_reversible_containment()
    }
}

/// Per-logical-tick scheduler ceilings and durable usage counters.
///
/// Counters and the current logical tick are part of the wire so a restart or
/// serialize/deserialize cycle cannot reset admission state within a tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerBudget {
    pub max_work_units: u32,
    pub max_claims: u16,
    current_tick: GraphLogicalTime,
    work_units_used: u32,
    claims_used: u16,
}

impl SchedulerBudget {
    pub const MAX_WORK_UNITS: u32 = 1_000_000;
    pub const MAX_CLAIMS: u16 = 4_096;

    /// Construct a budget bound to the active deployment configuration.
    ///
    /// The configuration is deliberately required here rather than accepting
    /// caller-selected ceilings: a budget must never become an authority for
    /// widening the deployment's reasoning limits.
    pub fn new(
        config: &crate::config::HypothesisGraphConfig,
        current_tick: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        Self::new_with_config(config, current_tick)
    }

    fn from_limits(
        max_work_units: u32,
        max_claims: u16,
        current_tick: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        let budget = Self {
            max_work_units,
            max_claims,
            current_tick,
            work_units_used: 0,
            claims_used: 0,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// Construct a budget from the deployment-scoped reasoning limits.  The
    /// config validator is part of this boundary so a caller cannot silently
    /// widen a deployment budget back to the global persistence ceiling.
    pub fn new_with_config(
        config: &crate::config::HypothesisGraphConfig,
        current_tick: GraphLogicalTime,
    ) -> Result<Self, GraphAdmissionError> {
        config.validate_reasoning_limits()?;
        let budget = Self::from_limits(
            config.max_work_units_per_tick,
            config.max_claims_per_tick,
            current_tick,
        )?;
        budget.validate_for_config(config)?;
        Ok(budget)
    }

    /// Validate a restored budget against the active deployment limits.
    /// `validate()` only checks the self-contained wire invariants; durable
    /// restart and admission must use this configuration-bound validator.
    pub fn validate_for_config(
        &self,
        config: &crate::config::HypothesisGraphConfig,
    ) -> Result<(), GraphAdmissionError> {
        config.validate_reasoning_limits()?;
        self.validate_with_limits(config.max_work_units_per_tick, config.max_claims_per_tick)
    }

    /// Deserialize a persisted budget and bind it to the active deployment
    /// limits before returning it to an application path.
    pub fn deserialize_with_config(
        json: &str,
        config: &crate::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphAdmissionError> {
        let budget: Self =
            serde_json::from_str(json).map_err(|error| GraphAdmissionError::Deserialization {
                reason: error.to_string(),
            })?;
        budget.validate_for_config(config)?;
        Ok(budget)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        self.validate_with_limits(Self::MAX_WORK_UNITS, Self::MAX_CLAIMS)
    }

    /// Validate one budget against deployment-scoped ceilings.  The supplied
    /// ceilings themselves are bounded by the global contract and the budget
    /// may not exceed either one.
    pub fn validate_with_limits(
        &self,
        max_work_units: u32,
        max_claims: u16,
    ) -> Result<(), GraphAdmissionError> {
        self.current_tick.validate()?;
        if max_work_units == 0 || max_work_units > Self::MAX_WORK_UNITS {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "scheduler.max_work_units_limit".to_string(),
                reason: format!("must be between 1 and {}", Self::MAX_WORK_UNITS),
            });
        }
        if max_claims == 0 || max_claims > Self::MAX_CLAIMS {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "scheduler.max_claims_limit".to_string(),
                reason: format!("must be between 1 and {}", Self::MAX_CLAIMS),
            });
        }
        if self.max_work_units == 0
            || self.max_work_units > Self::MAX_WORK_UNITS
            || self.max_work_units > max_work_units
        {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "scheduler.max_work_units".to_string(),
                reason: format!("must be between 1 and {max_work_units}"),
            });
        }
        if self.max_claims == 0
            || self.max_claims > Self::MAX_CLAIMS
            || self.max_claims > max_claims
        {
            return Err(GraphAdmissionError::InvalidLimit {
                field: "scheduler.max_claims".to_string(),
                reason: format!("must be between 1 and {max_claims}"),
            });
        }
        if self.work_units_used > self.max_work_units || self.claims_used > self.max_claims {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "scheduler budget usage exceeds its configured ceiling".to_string(),
            });
        }
        Ok(())
    }

    /// Atomically admit one unit of work and its associated claims under the
    /// active deployment configuration. Failed admissions leave both
    /// counters unchanged.
    pub fn admit(
        &mut self,
        config: &crate::config::HypothesisGraphConfig,
        work_units: u32,
        claims: u16,
    ) -> Result<(), GraphAdmissionError> {
        let current_tick = self.current_tick;
        self.admit_at(config, current_tick, work_units, claims)
    }

    /// Admit work at an injected logical tick. Advancing to a newer tick
    /// resets usage atomically with the successful admission; a stale tick or
    /// over-limit request leaves the complete budget byte-identical. The
    /// active configuration is checked on every call so a restored or mutated
    /// budget cannot widen itself through this path.
    pub fn admit_at(
        &mut self,
        config: &crate::config::HypothesisGraphConfig,
        logical_tick: GraphLogicalTime,
        work_units: u32,
        claims: u16,
    ) -> Result<(), GraphAdmissionError> {
        self.validate_for_config(config)?;
        logical_tick.validate()?;
        if logical_tick < self.current_tick {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "scheduler budget cannot move logical time backwards".to_string(),
            });
        }
        let (current_work, current_claims) = if logical_tick == self.current_tick {
            (self.work_units_used, self.claims_used)
        } else {
            (0, 0)
        };
        let next_work = current_work.checked_add(work_units).ok_or(
            GraphAdmissionError::ResourceLimitExceeded {
                resource: "scheduler.work_units_per_tick".to_string(),
                limit: self.max_work_units as usize,
            },
        )?;
        let next_claims = current_claims.checked_add(claims).ok_or(
            GraphAdmissionError::ResourceLimitExceeded {
                resource: "scheduler.claims_per_tick".to_string(),
                limit: self.max_claims as usize,
            },
        )?;
        if next_work > self.max_work_units {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "scheduler.work_units_per_tick".to_string(),
                limit: self.max_work_units as usize,
            });
        }
        if next_claims > self.max_claims {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "scheduler.claims_per_tick".to_string(),
                limit: self.max_claims as usize,
            });
        }
        self.current_tick = logical_tick;
        self.work_units_used = next_work;
        self.claims_used = next_claims;
        Ok(())
    }

    pub const fn current_tick(&self) -> GraphLogicalTime {
        self.current_tick
    }

    pub const fn work_units_used(&self) -> u32 {
        self.work_units_used
    }

    pub const fn claims_used(&self) -> u16 {
        self.claims_used
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSchedulerKey {
    pub ready_at: GraphLogicalTime,
    pub task_kind: TaskKind,
    pub priority_basis_points: u16,
    pub task_id: TaskId,
}

impl Ord for GraphSchedulerKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ready_at
            .cmp(&other.ready_at)
            .then_with(|| other.priority_basis_points.cmp(&self.priority_basis_points))
            .then_with(|| {
                self.task_kind
                    .dispatch_rank()
                    .cmp(&other.task_kind.dispatch_rank())
            })
            .then_with(|| self.task_id.cmp(&other.task_id))
    }
}

impl PartialOrd for GraphSchedulerKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl GraphSchedulerKey {
    pub fn new(
        ready_at: GraphLogicalTime,
        task_kind: TaskKind,
        priority_basis_points: u16,
        task_id: TaskId,
    ) -> Result<Self, GraphAdmissionError> {
        ready_at.validate()?;
        validate_id("scheduler.task_id", &task_id, 256)?;
        if priority_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: priority_basis_points,
            });
        }
        let key = Self {
            ready_at,
            task_kind,
            priority_basis_points,
            task_id,
        };
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        self.ready_at.validate()?;
        validate_id("scheduler.task_id", &self.task_id, 256)?;
        if self.priority_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: self.priority_basis_points,
            });
        }
        Ok(())
    }

    /// Return the exact dispatch tuple, including the descending-priority
    /// component.  The tuple is useful to independent consumers that must
    /// reproduce the core queue order without observing insertion order.
    pub fn dispatch_order_key(&self) -> (i64, Reverse<u16>, u8, String) {
        (
            self.ready_at.as_millis(),
            Reverse(self.priority_basis_points),
            self.task_kind.dispatch_rank(),
            self.task_id.0.clone(),
        )
    }

    pub fn dispatches_before(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Less
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillChainStage {
    InitialAccess,
    Execution,
    CredentialAccess,
    LateralMovement,
    CommandAndControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillChainOrder {
    Declared,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KillChainClaim {
    pub schema_version: u32,
    pub claim_id: KillChainClaimId,
    pub stage: KillChainStage,
    pub node_ids: BTreeSet<GraphNodeId>,
    pub edge_ids: BTreeSet<EdgeId>,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub predecessor_claim_ids: BTreeSet<KillChainClaimId>,
    pub order: KillChainOrder,
    pub narration: String,
    pub narration_evidence_ids: BTreeSet<EvidenceId>,
}

impl KillChainClaim {
    pub fn new<I, J, K, L, M>(
        stage: KillChainStage,
        node_ids: I,
        edge_ids: J,
        evidence_ids: K,
        predecessor_claim_ids: L,
        narration: impl Into<String>,
        narration_evidence_ids: M,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = GraphNodeId>,
        J: IntoIterator<Item = EdgeId>,
        K: IntoIterator<Item = EvidenceId>,
        L: IntoIterator<Item = KillChainClaimId>,
        M: IntoIterator<Item = EvidenceId>,
    {
        let node_ids = node_ids.into_iter().collect::<BTreeSet<_>>();
        let edge_ids = edge_ids.into_iter().collect::<BTreeSet<_>>();
        let evidence_ids = evidence_ids.into_iter().collect::<BTreeSet<_>>();
        let predecessor_claim_ids = predecessor_claim_ids.into_iter().collect::<BTreeSet<_>>();
        let narration_evidence_ids = narration_evidence_ids.into_iter().collect::<BTreeSet<_>>();
        validate_id_set("kill_chain.node_ids", &node_ids, 256, 256)?;
        validate_id_set("kill_chain.edge_ids", &edge_ids, 256, 256)?;
        validate_id_set("kill_chain.evidence_ids", &evidence_ids, 256, 256)?;
        validate_id_set(
            "kill_chain.predecessor_claim_ids",
            &predecessor_claim_ids,
            256,
            256,
        )?;
        validate_id_set(
            "kill_chain.narration_evidence_ids",
            &narration_evidence_ids,
            256,
            256,
        )?;
        let narration = narration.into();
        validate_text("kill_chain.narration", &narration, 1_024)?;
        if node_ids.is_empty() || evidence_ids.is_empty() || narration_evidence_ids.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain.claim".to_string(),
                reason: "nodes, evidence, and narration evidence are required".to_string(),
            });
        }
        if !narration_evidence_ids.is_subset(&evidence_ids) {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain.narration_evidence_ids".to_string(),
                reason: "narration evidence must be a subset of claim evidence".to_string(),
            });
        }
        let order = if predecessor_claim_ids.is_empty() {
            KillChainOrder::Declared
        } else {
            KillChainOrder::Partial
        };
        let material = (
            &stage,
            &node_ids,
            &edge_ids,
            &evidence_ids,
            &predecessor_claim_ids,
            &order,
            &narration,
            &narration_evidence_ids,
        );
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            claim_id: KillChainClaimId::new(format!("kill-chain:{}", canonical_digest(&material)?)),
            stage,
            node_ids,
            edge_ids,
            evidence_ids,
            predecessor_claim_ids,
            order,
            narration,
            narration_evidence_ids,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("kill_chain.claim_id", &self.claim_id, 256)?;
        validate_id_set("kill_chain.node_ids", &self.node_ids, 256, 256)?;
        validate_id_set("kill_chain.edge_ids", &self.edge_ids, 256, 256)?;
        validate_id_set("kill_chain.evidence_ids", &self.evidence_ids, 256, 256)?;
        validate_id_set(
            "kill_chain.predecessor_claim_ids",
            &self.predecessor_claim_ids,
            256,
            256,
        )?;
        validate_id_set(
            "kill_chain.narration_evidence_ids",
            &self.narration_evidence_ids,
            256,
            256,
        )?;
        validate_text("kill_chain.narration", &self.narration, 1_024)?;
        if self.node_ids.is_empty()
            || self.evidence_ids.is_empty()
            || self.narration_evidence_ids.is_empty()
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain.claim".to_string(),
                reason: "nodes, evidence, and narration evidence are required".to_string(),
            });
        }
        if !self.narration_evidence_ids.is_subset(&self.evidence_ids) {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain.narration_evidence_ids".to_string(),
                reason: "narration evidence must be a subset of claim evidence".to_string(),
            });
        }
        if self.predecessor_claim_ids.contains(&self.claim_id) {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "a kill-chain claim cannot precede itself".to_string(),
            });
        }
        let order_is_coherent = match self.order {
            KillChainOrder::Declared => self.predecessor_claim_ids.is_empty(),
            KillChainOrder::Partial => !self.predecessor_claim_ids.is_empty(),
            // Unknown preserves an explicitly uncertain order while still
            // retaining any predecessor edges that the reconstruction can
            // validate independently.
            KillChainOrder::Unknown => true,
        };
        if !order_is_coherent {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "kill-chain order does not match predecessor claims".to_string(),
            });
        }
        if self.derived_id()? != self.claim_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.claim_id.0.clone(),
            });
        }
        Ok(())
    }

    pub fn with_order(mut self, order: KillChainOrder) -> Result<Self, GraphAdmissionError> {
        self.order = order;
        self.claim_id = self.derived_id()?;
        self.validate()?;
        Ok(self)
    }

    pub fn derived_id(&self) -> Result<KillChainClaimId, GraphAdmissionError> {
        Ok(KillChainClaimId::new(format!(
            "kill-chain:{}",
            canonical_digest(&(
                &self.stage,
                &self.node_ids,
                &self.edge_ids,
                &self.evidence_ids,
                &self.predecessor_claim_ids,
                &self.order,
                &self.narration,
                &self.narration_evidence_ids,
            ))?
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MissingEvidence {
    pub schema_version: u32,
    pub claim_id: KillChainClaimId,
    pub expected_scope: String,
    pub reason: String,
}

impl MissingEvidence {
    pub fn new(
        claim_id: KillChainClaimId,
        expected_scope: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let expected_scope = expected_scope.into();
        let reason = reason.into();
        validate_text("missing_evidence.expected_scope", &expected_scope, 512)?;
        validate_text("missing_evidence.reason", &reason, 512)?;
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            claim_id,
            expected_scope,
            reason,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("missing_evidence.claim_id", &self.claim_id, 256)?;
        validate_text("missing_evidence.expected_scope", &self.expected_scope, 512)?;
        validate_text("missing_evidence.reason", &self.reason, 512)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KillChainReconstruction {
    pub schema_version: u32,
    pub claims: Vec<KillChainClaim>,
    pub missing_evidence: Vec<MissingEvidence>,
}

impl KillChainReconstruction {
    pub fn new<I, J>(claims: I, missing_evidence: J) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = KillChainClaim>,
        J: IntoIterator<Item = MissingEvidence>,
    {
        let claims = claims.into_iter().collect::<Vec<_>>();
        let missing_evidence = missing_evidence.into_iter().collect::<Vec<_>>();
        if claims.len() > 256 || missing_evidence.len() > 256 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "kill_chain.reconstruction".to_string(),
                limit: 256,
            });
        }
        if claims.is_empty() && missing_evidence.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain".to_string(),
                reason: "a reconstruction must contain a claim or explicit missing evidence"
                    .to_string(),
            });
        }
        for claim in &claims {
            claim.validate()?;
        }
        for missing in &missing_evidence {
            missing.validate()?;
        }
        let reconstruction = Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            claims,
            missing_evidence,
        };
        reconstruction.validate()?;
        Ok(reconstruction)
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        if self.claims.len() > 256 || self.missing_evidence.len() > 256 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "kill_chain.reconstruction".to_string(),
                limit: 256,
            });
        }
        if self.claims.is_empty() && self.missing_evidence.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "kill_chain".to_string(),
                reason: "a reconstruction must contain a claim or explicit missing evidence"
                    .to_string(),
            });
        }
        let mut claims_by_id = BTreeMap::new();
        let mut claim_indexes = BTreeMap::new();
        for (index, claim) in self.claims.iter().enumerate() {
            claim.validate()?;
            if claims_by_id.insert(claim.claim_id.clone(), claim).is_some() {
                return Err(GraphAdmissionError::IdCollision {
                    id: claim.claim_id.0.clone(),
                });
            }
            claim_indexes.insert(claim.claim_id.clone(), index);
            if let Some(previous) = self.claims.get(index.saturating_sub(1))
                && previous.stage > claim.stage
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "kill-chain claim vector must be ordered by stage".to_string(),
                });
            }
        }
        for missing in &self.missing_evidence {
            missing.validate()?;
            if !claims_by_id.contains_key(&missing.claim_id) {
                return Err(GraphAdmissionError::InvalidField {
                    field: "missing_evidence.claim_id".to_string(),
                    reason: "missing evidence must reference a claim in the reconstruction"
                        .to_string(),
                });
            }
        }
        let mut successors: BTreeMap<KillChainClaimId, BTreeSet<KillChainClaimId>> =
            BTreeMap::new();
        let mut indegree: BTreeMap<KillChainClaimId, usize> =
            claims_by_id.keys().cloned().map(|id| (id, 0)).collect();
        for claim in &self.claims {
            for predecessor_id in &claim.predecessor_claim_ids {
                let predecessor = claims_by_id.get(predecessor_id).ok_or_else(|| {
                    GraphAdmissionError::InvalidField {
                        field: "kill_chain.predecessor_claim_ids".to_string(),
                        reason: format!("unknown predecessor claim {predecessor_id}"),
                    }
                })?;
                if claim_indexes
                    .get(predecessor_id)
                    .is_none_or(|predecessor_index| {
                        *predecessor_index >= claim_indexes[&claim.claim_id]
                    })
                {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "kill-chain claims must be topologically ordered in the vector"
                            .to_string(),
                    });
                }
                successors
                    .entry(predecessor_id.clone())
                    .or_default()
                    .insert(claim.claim_id.clone());
                let degree = indegree.get_mut(&claim.claim_id).ok_or_else(|| {
                    GraphAdmissionError::InvalidTransition {
                        reason: "kill-chain claim was missing from predecessor index".to_string(),
                    }
                })?;
                *degree += 1;
                if predecessor.stage > claim.stage {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "declared kill-chain stages must be monotonic".to_string(),
                    });
                }
            }
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(id, degree)| (*degree == 0).then_some(id.clone()))
            .collect::<BTreeSet<_>>();
        let mut visited = 0_usize;
        while let Some(id) = ready.pop_first() {
            visited = visited.saturating_add(1);
            if let Some(children) = successors.get(&id) {
                for child in children {
                    let degree = indegree.get_mut(child).ok_or_else(|| {
                        GraphAdmissionError::InvalidTransition {
                            reason: "kill-chain successor was missing from predecessor index"
                                .to_string(),
                        }
                    })?;
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }
        if visited != claims_by_id.len() {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "kill-chain predecessor graph must be acyclic".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentOptionKind {
    IsolateAsset,
    RestrictNetwork,
    RotateCredential,
    SuspendProcess,
    EscalateReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalClass {
    None,
    Analyst,
    Operator,
    HumanGate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentOption {
    pub schema_version: u32,
    pub option_id: String,
    pub kind: ContainmentOptionKind,
    pub target_node_ids: BTreeSet<GraphNodeId>,
    pub predicted_blast_radius_basis_points: u16,
    pub reversibility_basis_points: u16,
    pub evidence_support_basis_points: u16,
    pub required_approval: ApprovalClass,
    pub rollback_expected: bool,
    pub rank: u32,
}

impl ContainmentOption {
    #[allow(clippy::too_many_arguments)]
    pub fn new<I>(
        kind: ContainmentOptionKind,
        target_node_ids: I,
        predicted_blast_radius_basis_points: u16,
        reversibility_basis_points: u16,
        evidence_support_basis_points: u16,
        required_approval: ApprovalClass,
        rollback_expected: bool,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = GraphNodeId>,
    {
        let target_node_ids = target_node_ids.into_iter().collect::<BTreeSet<_>>();
        validate_id_set("containment.target_node_ids", &target_node_ids, 256, 256)?;
        if target_node_ids.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "containment.target_node_ids".to_string(),
                reason: "at least one target is required".to_string(),
            });
        }
        for (field, value) in [
            (
                "predicted_blast_radius_basis_points",
                predicted_blast_radius_basis_points,
            ),
            ("reversibility_basis_points", reversibility_basis_points),
            (
                "evidence_support_basis_points",
                evidence_support_basis_points,
            ),
        ] {
            if value > CONFIDENCE_BASIS_POINTS {
                return Err(GraphAdmissionError::InvalidField {
                    field: field.to_string(),
                    reason: "must be between 0 and 10000".to_string(),
                });
            }
        }
        let material = (
            &kind,
            &target_node_ids,
            predicted_blast_radius_basis_points,
            reversibility_basis_points,
            evidence_support_basis_points,
            &required_approval,
            rollback_expected,
        );
        let option_id = format!("simulation:{}", canonical_digest(&material)?);
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            option_id,
            kind,
            target_node_ids,
            predicted_blast_radius_basis_points,
            reversibility_basis_points,
            evidence_support_basis_points,
            required_approval,
            rollback_expected,
            rank: 0,
        })
    }

    pub fn derived_id(&self) -> Result<String, GraphAdmissionError> {
        Ok(format!(
            "simulation:{}",
            canonical_digest(&(
                &self.kind,
                &self.target_node_ids,
                self.predicted_blast_radius_basis_points,
                self.reversibility_basis_points,
                self.evidence_support_basis_points,
                &self.required_approval,
                self.rollback_expected,
            ))?
        ))
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_text("containment.option_id", &self.option_id, 256)?;
        validate_id_set(
            "containment.target_node_ids",
            &self.target_node_ids,
            256,
            256,
        )?;
        if self.target_node_ids.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "containment.target_node_ids".to_string(),
                reason: "at least one target is required".to_string(),
            });
        }
        for (field, value) in [
            (
                "predicted_blast_radius_basis_points",
                self.predicted_blast_radius_basis_points,
            ),
            (
                "reversibility_basis_points",
                self.reversibility_basis_points,
            ),
            (
                "evidence_support_basis_points",
                self.evidence_support_basis_points,
            ),
        ] {
            if value > CONFIDENCE_BASIS_POINTS {
                return Err(GraphAdmissionError::InvalidConfidence { value });
            }
            let _ = field;
        }
        if self.derived_id()? != self.option_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.option_id.clone(),
            });
        }
        Ok(())
    }

    pub fn score_key(&self) -> (u16, u16, u16, ApprovalClass, String) {
        (
            self.predicted_blast_radius_basis_points,
            u16::MAX - self.reversibility_basis_points,
            u16::MAX - self.evidence_support_basis_points,
            self.required_approval,
            self.option_id.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentSimulation {
    pub schema_version: u32,
    pub graph_id: GraphId,
    pub options: Vec<ContainmentOption>,
    pub simulation_only: bool,
}

impl ContainmentSimulation {
    pub fn new<I>(graph_id: GraphId, options: I) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = ContainmentOption>,
    {
        let mut options = options.into_iter().collect::<Vec<_>>();
        if options.is_empty() {
            return Err(GraphAdmissionError::InvalidField {
                field: "containment.options".to_string(),
                reason: "at least one simulation option is required".to_string(),
            });
        }
        options.sort_by_key(ContainmentOption::score_key);
        for (index, option) in options.iter_mut().enumerate() {
            option.rank = index as u32 + 1;
        }
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            graph_id,
            options,
            simulation_only: true,
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("containment.graph_id", &self.graph_id, 256)?;
        if !self.simulation_only || self.options.is_empty() {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "containment plans must remain simulation-only".to_string(),
            });
        }
        if self.options.len() > 256 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "containment.options".to_string(),
                limit: 256,
            });
        }
        let mut expected_rank = 1_u32;
        let mut previous_score: Option<(u16, u16, u16, ApprovalClass, String)> = None;
        for option in &self.options {
            option.validate()?;
            if option.rank != expected_rank {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "containment options must have contiguous deterministic ranks"
                        .to_string(),
                });
            }
            if let Some(previous) = &previous_score
                && previous > &option.score_key()
            {
                return Err(GraphAdmissionError::InvalidTransition {
                    reason: "containment options are not ordered by their deterministic score"
                        .to_string(),
                });
            }
            previous_score = Some(option.score_key());
            expected_rank = expected_rank.saturating_add(1);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisDelta {
    pub schema_version: u32,
    pub added_edge_ids: BTreeSet<EdgeId>,
    pub retracted_edge_ids: BTreeSet<EdgeId>,
    pub superseded_edge_ids: BTreeSet<EdgeId>,
}

impl HypothesisDelta {
    pub fn new<I, J, K>(added: I, retracted: J, superseded: K) -> Self
    where
        I: IntoIterator<Item = EdgeId>,
        J: IntoIterator<Item = EdgeId>,
        K: IntoIterator<Item = EdgeId>,
    {
        Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            added_edge_ids: added.into_iter().collect(),
            retracted_edge_ids: retracted.into_iter().collect(),
            superseded_edge_ids: superseded.into_iter().collect(),
        }
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id_set(
            "hypothesis_delta.added_edge_ids",
            &self.added_edge_ids,
            512,
            256,
        )?;
        validate_id_set(
            "hypothesis_delta.retracted_edge_ids",
            &self.retracted_edge_ids,
            512,
            256,
        )?;
        validate_id_set(
            "hypothesis_delta.superseded_edge_ids",
            &self.superseded_edge_ids,
            512,
            256,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceUtility {
    pub schema_version: u32,
    pub evidence_id: EvidenceId,
    pub utility_basis_points: u16,
}

impl EvidenceUtility {
    pub fn new(evidence_id: EvidenceId, utility_basis_points: u16) -> Self {
        Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            evidence_id,
            utility_basis_points,
        }
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("evidence_utility.evidence_id", &self.evidence_id, 256)?;
        if self.utility_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: self.utility_basis_points,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOutcome {
    Confirmed,
    Falsified,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryProvenance {
    pub schema_version: u32,
    pub producer_identity: AgentId,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub witness: Option<EvidenceWitness>,
}

impl MemoryProvenance {
    pub fn new<I>(producer_identity: AgentId, evidence_ids: I) -> Self
    where
        I: IntoIterator<Item = EvidenceId>,
    {
        Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            producer_identity,
            evidence_ids: evidence_ids.into_iter().collect(),
            witness: None,
        }
    }

    pub fn signed_with(
        mut self,
        signer: &Keypair,
        role: GraphProducerRole,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        let bytes = canonical_json_bytes(&MemoryProvenanceCore {
            schema_version: self.schema_version,
            producer_identity: &self.producer_identity,
            evidence_ids: &self.evidence_ids,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })?;
        self.witness = Some(EvidenceWitness::new(signer, role, scoped_agent_id, &bytes)?);
        self.validate().map(|()| self)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&MemoryProvenanceCore {
            schema_version: self.schema_version,
            producer_identity: &self.producer_identity,
            evidence_ids: &self.evidence_ids,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_agent_id(
            "memory.provenance.producer_identity",
            &self.producer_identity,
        )?;
        validate_id_set(
            "memory.provenance.evidence_ids",
            &self.evidence_ids,
            256,
            256,
        )?;
        let witness = self
            .witness
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidWitness {
                reason: "strategy memory provenance requires a signed witness".to_string(),
            })?;
        if witness.producer_identity != self.producer_identity {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "memory provenance identity is not key-derived from its witness"
                    .to_string(),
            });
        }
        witness.validate(&self.canonical_bytes()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct MemoryProvenanceCore<'a> {
    schema_version: u32,
    producer_identity: &'a AgentId,
    evidence_ids: &'a BTreeSet<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyMemory {
    pub schema_version: u32,
    pub memory_id: MemoryId,
    pub graph_id: GraphId,
    pub selected_hypothesis_id: HypothesisId,
    pub hypothesis_delta: HypothesisDelta,
    pub evidence_utility: BTreeMap<EvidenceId, EvidenceUtility>,
    pub falsified_alternative_ids: BTreeSet<HypothesisId>,
    pub outcome: MemoryOutcome,
    pub provenance: MemoryProvenance,
    pub witness: Option<EvidenceWitness>,
}

impl StrategyMemory {
    pub fn new<I, J>(
        graph_id: GraphId,
        selected_hypothesis_id: HypothesisId,
        hypothesis_delta: HypothesisDelta,
        evidence_utility: I,
        falsified_alternative_ids: J,
        outcome: MemoryOutcome,
        provenance: MemoryProvenance,
    ) -> Result<Self, GraphAdmissionError>
    where
        I: IntoIterator<Item = EvidenceUtility>,
        J: IntoIterator<Item = HypothesisId>,
    {
        let evidence_utility = evidence_utility
            .into_iter()
            .map(|utility| (utility.evidence_id.clone(), utility))
            .collect::<BTreeMap<_, _>>();
        for utility in evidence_utility.values() {
            utility.validate()?;
        }
        provenance.validate()?;
        validate_id("memory.graph_id", &graph_id, 256)?;
        validate_id(
            "memory.selected_hypothesis_id",
            &selected_hypothesis_id,
            256,
        )?;
        hypothesis_delta.validate()?;
        if evidence_utility.len() > 512 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "memory.evidence_utility".to_string(),
                limit: 512,
            });
        }
        let falsified_alternative_ids = falsified_alternative_ids
            .into_iter()
            .collect::<BTreeSet<_>>();
        validate_id_set(
            "memory.falsified_alternative_ids",
            &falsified_alternative_ids,
            256,
            256,
        )?;
        if falsified_alternative_ids.contains(&selected_hypothesis_id) {
            return Err(GraphAdmissionError::InvalidField {
                field: "memory.falsified_alternative_ids".to_string(),
                reason: "selected hypothesis cannot also be falsified".to_string(),
            });
        }
        let material = (
            &graph_id,
            &selected_hypothesis_id,
            &hypothesis_delta,
            &evidence_utility,
            &falsified_alternative_ids,
            outcome,
            &provenance,
        );
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            memory_id: MemoryId::new(format!("memory:{}", canonical_digest(&material)?)),
            graph_id,
            selected_hypothesis_id,
            hypothesis_delta,
            evidence_utility,
            falsified_alternative_ids,
            outcome,
            provenance,
            witness: None,
        })
    }

    pub fn signed_with(
        mut self,
        signer: &Keypair,
        role: GraphProducerRole,
        scoped_agent_id: impl Into<String>,
    ) -> Result<Self, GraphAdmissionError> {
        self.provenance.validate()?;
        let bytes = self.canonical_bytes_without_witness()?;
        self.witness = Some(EvidenceWitness::new(signer, role, scoped_agent_id, &bytes)?);
        self.validate().map(|()| self)
    }

    fn canonical_bytes_without_witness(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&StrategyMemoryCore {
            schema_version: self.schema_version,
            memory_id: &self.memory_id,
            graph_id: &self.graph_id,
            selected_hypothesis_id: &self.selected_hypothesis_id,
            hypothesis_delta: &self.hypothesis_delta,
            evidence_utility: &self.evidence_utility,
            falsified_alternative_ids: &self.falsified_alternative_ids,
            outcome: self.outcome,
            provenance: &self.provenance,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("memory.memory_id", &self.memory_id, 256)?;
        validate_id("memory.graph_id", &self.graph_id, 256)?;
        validate_id(
            "memory.selected_hypothesis_id",
            &self.selected_hypothesis_id,
            256,
        )?;
        self.hypothesis_delta.validate()?;
        if self.evidence_utility.len() > 512 {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "memory.evidence_utility".to_string(),
                limit: 512,
            });
        }
        validate_id_set(
            "memory.falsified_alternative_ids",
            &self.falsified_alternative_ids,
            256,
            256,
        )?;
        if self
            .falsified_alternative_ids
            .contains(&self.selected_hypothesis_id)
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "memory.falsified_alternative_ids".to_string(),
                reason: "selected hypothesis cannot also be falsified".to_string(),
            });
        }
        for utility in self.evidence_utility.values() {
            utility.validate()?;
        }
        for (key, utility) in &self.evidence_utility {
            if key != &utility.evidence_id {
                return Err(GraphAdmissionError::IdCollision { id: key.0.clone() });
            }
        }
        self.provenance.validate()?;
        let witness = self
            .witness
            .as_ref()
            .ok_or(GraphAdmissionError::InvalidWitness {
                reason: "strategy memory requires a signed witness".to_string(),
            })?;
        witness.validate(&self.canonical_bytes_without_witness()?)?;
        if self.derived_id()? != self.memory_id {
            return Err(GraphAdmissionError::IdCollision {
                id: self.memory_id.0.clone(),
            });
        }
        Ok(())
    }

    pub fn derived_id(&self) -> Result<MemoryId, GraphAdmissionError> {
        Ok(MemoryId::new(format!(
            "memory:{}",
            canonical_digest(&(
                &self.graph_id,
                &self.selected_hypothesis_id,
                &self.hypothesis_delta,
                &self.evidence_utility,
                &self.falsified_alternative_ids,
                self.outcome,
                &self.provenance,
            ))?
        )))
    }

    pub fn applicable_to(&self, graph_id: &GraphId, hypothesis_id: &HypothesisId) -> bool {
        &self.graph_id == graph_id && &self.selected_hypothesis_id == hypothesis_id
    }
}

/// Versioned envelope for newly persisted logical-time strategy memory.
/// Existing `StrategyMemory` records intentionally retain their historical
/// wire shape; stores treat records without this envelope as quarantined.
pub const STRATEGY_MEMORY_EXPIRY_SCHEMA_VERSION: u32 = 1;
pub const MAX_STRATEGY_MEMORY_TTL_TICKS: u64 = 86_400_000;
const STRATEGY_MEMORY_EXPIRY_SCOPED_AGENT_ID: &str = "strategy-memory-expiry";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyMemoryExpiryEnvelope {
    pub schema_version: u32,
    pub memory_id: MemoryId,
    pub memory_digest: String,
    pub created_at: GraphLogicalTime,
    pub expires_at: GraphLogicalTime,
    pub signature: EvidenceWitness,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryExpiryMaterial<'a> {
    schema_version: u32,
    memory_id: &'a MemoryId,
    memory_digest: &'a str,
    created_at: GraphLogicalTime,
    expires_at: GraphLogicalTime,
}

impl StrategyMemoryExpiryEnvelope {
    /// Construct an expiry envelope using the active deployment TTL bound.
    pub fn new(
        memory: &StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
        config: &crate::config::HypothesisGraphConfig,
        signer: &Keypair,
    ) -> Result<Self, GraphAdmissionError> {
        Self::new_with_config(memory, created_at, ttl_ticks, config, signer)
    }

    /// Construct an expiry envelope bound to the active deployment
    /// configuration. A caller cannot silently fall back to the global TTL
    /// ceiling when the deployment has configured a lower one.
    pub fn new_with_config(
        memory: &StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
        config: &crate::config::HypothesisGraphConfig,
        signer: &Keypair,
    ) -> Result<Self, GraphAdmissionError> {
        config.validate_reasoning_limits()?;
        Self::new_with_limit(
            memory,
            created_at,
            ttl_ticks,
            config.max_memory_ttl_ticks,
            signer,
        )
    }

    pub fn new_with_limit(
        memory: &StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
        max_ttl_ticks: u64,
        signer: &Keypair,
    ) -> Result<Self, GraphAdmissionError> {
        memory.validate()?;
        created_at.validate()?;
        validate_ttl_ticks(ttl_ticks, max_ttl_ticks)?;
        let ttl = i64::try_from(ttl_ticks).map_err(|_| GraphAdmissionError::InvalidField {
            field: "strategy_memory_expiry.ttl_ticks".to_string(),
            reason: "must fit in logical time".to_string(),
        })?;
        let expires_at =
            created_at
                .checked_add(ttl)
                .ok_or_else(|| GraphAdmissionError::InvalidField {
                    field: "strategy_memory_expiry.expires_at".to_string(),
                    reason: "logical time overflow".to_string(),
                })?;
        let memory_digest = canonical_digest(memory)?;
        let material = StrategyMemoryExpiryMaterial {
            schema_version: STRATEGY_MEMORY_EXPIRY_SCHEMA_VERSION,
            memory_id: &memory.memory_id,
            memory_digest: &memory_digest,
            created_at,
            expires_at,
        };
        let bytes = canonical_json_bytes(&material).map_err(|error| {
            GraphAdmissionError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        let signature = EvidenceWitness::new(
            signer,
            GraphProducerRole::Planner,
            STRATEGY_MEMORY_EXPIRY_SCOPED_AGENT_ID,
            &bytes,
        )?;
        let envelope = Self {
            schema_version: STRATEGY_MEMORY_EXPIRY_SCHEMA_VERSION,
            memory_id: memory.memory_id.clone(),
            memory_digest,
            created_at,
            expires_at,
            signature,
        };
        envelope.validate_with_limit(max_ttl_ticks)?;
        envelope.validate_for(memory)?;
        Ok(envelope)
    }

    /// Validate a restored expiry envelope against the active deployment
    /// configuration before it is used for applicability decisions.
    pub fn validate_for_config(
        &self,
        config: &crate::config::HypothesisGraphConfig,
    ) -> Result<(), GraphAdmissionError> {
        config.validate_reasoning_limits()?;
        self.validate_with_limit(config.max_memory_ttl_ticks)
    }

    /// Deserialize a persisted expiry envelope and bind it to the active
    /// deployment TTL before returning it to an application path.
    pub fn deserialize_with_config(
        json: &str,
        config: &crate::config::HypothesisGraphConfig,
    ) -> Result<Self, GraphAdmissionError> {
        let envelope: Self =
            serde_json::from_str(json).map_err(|error| GraphAdmissionError::Deserialization {
                reason: error.to_string(),
            })?;
        envelope.validate_for_config(config)?;
        Ok(envelope)
    }

    /// Apply an expiry envelope under the active deployment TTL bound.
    pub fn is_applicable_at(
        &self,
        now: GraphLogicalTime,
        config: &crate::config::HypothesisGraphConfig,
    ) -> bool {
        now.validate().is_ok()
            && self.validate_for_config(config).is_ok()
            && self.created_at <= now
            && now < self.expires_at
    }

    pub fn is_applicable_at_with_limit(&self, now: GraphLogicalTime, max_ttl_ticks: u64) -> bool {
        now.validate().is_ok()
            && self.validate_with_limit(max_ttl_ticks).is_ok()
            && self.created_at <= now
            && now < self.expires_at
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        self.validate_with_limit(MAX_STRATEGY_MEMORY_TTL_TICKS)
    }

    pub fn validate_with_limit(&self, max_ttl_ticks: u64) -> Result<(), GraphAdmissionError> {
        if self.schema_version != STRATEGY_MEMORY_EXPIRY_SCHEMA_VERSION {
            return Err(GraphAdmissionError::UnsupportedSchema(self.schema_version));
        }
        validate_id("strategy_memory_expiry.memory_id", &self.memory_id, 256)?;
        validate_sha256_digest("strategy_memory_expiry.memory_digest", &self.memory_digest)?;
        self.created_at.validate()?;
        self.expires_at.validate()?;
        if self.expires_at <= self.created_at {
            return Err(GraphAdmissionError::InvalidField {
                field: "strategy_memory_expiry.expires_at".to_string(),
                reason: "must be after created_at".to_string(),
            });
        }
        let ttl = u64::try_from(
            self.expires_at
                .as_millis()
                .checked_sub(self.created_at.as_millis())
                .ok_or_else(|| GraphAdmissionError::InvalidField {
                    field: "strategy_memory_expiry.expires_at".to_string(),
                    reason: "logical time is not ordered".to_string(),
                })?,
        )
        .map_err(|_| GraphAdmissionError::InvalidField {
            field: "strategy_memory_expiry.ttl_ticks".to_string(),
            reason: "must be non-negative".to_string(),
        })?;
        validate_ttl_ticks(ttl, max_ttl_ticks)?;
        if self.signature.producer_role != GraphProducerRole::Planner
            || self.signature.scoped_agent_id != STRATEGY_MEMORY_EXPIRY_SCOPED_AGENT_ID
        {
            return Err(GraphAdmissionError::InvalidWitness {
                reason: "strategy memory expiry witness role or scope is invalid".to_string(),
            });
        }
        let bytes = self.canonical_bytes()?;
        self.signature.validate(&bytes)
    }

    /// Validate that this envelope actually describes the supplied memory,
    /// rather than merely carrying a valid signature over unrelated IDs.
    pub fn validate_for(&self, memory: &StrategyMemory) -> Result<(), GraphAdmissionError> {
        memory.validate()?;
        self.validate()?;
        if self.memory_id != memory.memory_id || self.memory_digest != canonical_digest(memory)? {
            return Err(GraphAdmissionError::InvalidTransition {
                reason: "strategy memory expiry does not bind the supplied memory".to_string(),
            });
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, GraphAdmissionError> {
        canonical_json_bytes(&StrategyMemoryExpiryMaterial {
            schema_version: self.schema_version,
            memory_id: &self.memory_id,
            memory_digest: &self.memory_digest,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
        .map_err(|error| GraphAdmissionError::Canonicalization {
            reason: error.to_string(),
        })
    }
}

fn validate_ttl_ticks(ttl_ticks: u64, max_ttl_ticks: u64) -> Result<(), GraphAdmissionError> {
    if ttl_ticks == 0 || max_ttl_ticks == 0 || ttl_ticks > max_ttl_ticks {
        return Err(GraphAdmissionError::InvalidLimit {
            field: "strategy_memory_expiry.ttl_ticks".to_string(),
            reason: format!("must be between 1 and {max_ttl_ticks}"),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryCore<'a> {
    schema_version: u32,
    memory_id: &'a MemoryId,
    graph_id: &'a GraphId,
    selected_hypothesis_id: &'a HypothesisId,
    hypothesis_delta: &'a HypothesisDelta,
    evidence_utility: &'a BTreeMap<EvidenceId, EvidenceUtility>,
    falsified_alternative_ids: &'a BTreeSet<HypothesisId>,
    outcome: MemoryOutcome,
    provenance: &'a MemoryProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyMemoryMatch {
    pub schema_version: u32,
    pub memory_id: MemoryId,
    pub relevance_basis_points: u16,
    pub provenance_evidence_ids: BTreeSet<EvidenceId>,
}

impl StrategyMemoryMatch {
    pub fn new(
        memory: &StrategyMemory,
        relevance_basis_points: u16,
    ) -> Result<Self, GraphAdmissionError> {
        if relevance_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: relevance_basis_points,
            });
        }
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            memory_id: memory.memory_id.clone(),
            relevance_basis_points,
            provenance_evidence_ids: memory.provenance.evidence_ids.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), GraphAdmissionError> {
        validate_schema(self.schema_version)?;
        validate_id("memory_match.memory_id", &self.memory_id, 256)?;
        if self.relevance_basis_points > CONFIDENCE_BASIS_POINTS {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: self.relevance_basis_points,
            });
        }
        validate_id_set(
            "memory_match.provenance_evidence_ids",
            &self.provenance_evidence_ids,
            256,
            256,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricDenominators {
    pub adjudicated_cases: u64,
    pub attack_chain_stages: u64,
    pub causal_edges: u64,
    pub logical_tasks: u64,
    pub evidence_claims: u64,
}

impl MetricDenominators {
    pub fn new(
        adjudicated_cases: u64,
        attack_chain_stages: u64,
        causal_edges: u64,
        logical_tasks: u64,
        evidence_claims: u64,
    ) -> Result<Self, GraphAdmissionError> {
        if [
            adjudicated_cases,
            attack_chain_stages,
            causal_edges,
            logical_tasks,
            evidence_claims,
        ]
        .into_iter()
        .any(|value| value == 0)
        {
            return Err(GraphAdmissionError::InvalidField {
                field: "metrics.denominators".to_string(),
                reason: "all denominators must be greater than zero".to_string(),
            });
        }
        Ok(Self {
            adjudicated_cases,
            attack_chain_stages,
            causal_edges,
            logical_tasks,
            evidence_claims,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricResults {
    pub median_hypothesis_time_ms: u64,
    pub attack_chain_recall_basis_points: u16,
    pub false_causal_edge_rate_basis_points: u16,
    pub duplicate_work_rate_basis_points: u16,
    pub evidence_coverage_basis_points: u16,
    pub logical_work_units: u64,
}

impl MetricResults {
    pub fn new(
        median_hypothesis_time_ms: u64,
        attack_chain_recall_basis_points: u16,
        false_causal_edge_rate_basis_points: u16,
        duplicate_work_rate_basis_points: u16,
        evidence_coverage_basis_points: u16,
        logical_work_units: u64,
    ) -> Result<Self, GraphAdmissionError> {
        if median_hypothesis_time_ms == 0 || logical_work_units == 0 {
            return Err(GraphAdmissionError::InvalidField {
                field: "metrics.results".to_string(),
                reason: "time and logical work must be greater than zero".to_string(),
            });
        }
        for (field, value) in [
            (
                "attack_chain_recall_basis_points",
                attack_chain_recall_basis_points,
            ),
            (
                "false_causal_edge_rate_basis_points",
                false_causal_edge_rate_basis_points,
            ),
            (
                "duplicate_work_rate_basis_points",
                duplicate_work_rate_basis_points,
            ),
            (
                "evidence_coverage_basis_points",
                evidence_coverage_basis_points,
            ),
        ] {
            if value > CONFIDENCE_BASIS_POINTS {
                return Err(GraphAdmissionError::InvalidField {
                    field: field.to_string(),
                    reason: "must be between 0 and 10000".to_string(),
                });
            }
        }
        Ok(Self {
            median_hypothesis_time_ms,
            attack_chain_recall_basis_points,
            false_causal_edge_rate_basis_points,
            duplicate_work_rate_basis_points,
            evidence_coverage_basis_points,
            logical_work_units,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectiveMetricReport {
    pub schema_version: u32,
    pub denominators: MetricDenominators,
    pub results: MetricResults,
}

impl CollectiveMetricReport {
    pub fn new(
        denominators: MetricDenominators,
        results: MetricResults,
    ) -> Result<Self, GraphAdmissionError> {
        if results.attack_chain_recall_basis_points > CONFIDENCE_BASIS_POINTS
            || results.evidence_coverage_basis_points > CONFIDENCE_BASIS_POINTS
        {
            return Err(GraphAdmissionError::InvalidConfidence {
                value: CONFIDENCE_BASIS_POINTS + 1,
            });
        }
        Ok(Self {
            schema_version: HYPOTHESIS_GRAPH_SCHEMA_VERSION,
            denominators,
            results,
        })
    }

    pub fn canonical_digest(&self) -> Result<String, GraphAdmissionError> {
        canonical_digest(self)
    }
}

// Selected durable graph artifacts do not deserialize directly into their
// public structs. These private wire types deliberately carry no semantic
// logic; each custom Deserialize implementation below constructs the record
// and admits it through the same validator used by live/runtime paths. The
// remaining small value records still derive Deserialize and must use
// `deserialize_validated` until they receive the same wire boundary.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEnvelopeWire {
    schema_version: u32,
    evidence_id: EvidenceId,
    source_family: EvidenceSourceFamily,
    source_id: String,
    lineage: SourceLineage,
    clock: EvidenceClock,
    ordering: OrderingClaim,
    payload: TypedEvidencePayload,
    witness: EvidenceWitness,
}

impl<'de> Deserialize<'de> for EvidenceEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = EvidenceEnvelopeWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            evidence_id: wire.evidence_id,
            source_family: wire.source_family,
            source_id: wire.source_id,
            lineage: wire.lineage,
            clock: wire.clock,
            ordering: wire.ordering,
            payload: wire.payload,
            witness: wire.witness,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CausalEdgeWire {
    schema_version: u32,
    edge_id: EdgeId,
    from: GraphNodeId,
    to: GraphNodeId,
    relation: CausalRelation,
    confidence_basis_points: u16,
    source_evidence_ids: BTreeSet<EvidenceId>,
    producer_role: GraphProducerRole,
    producer_identity: AgentId,
    observed_at: GraphLogicalTime,
    state: EdgeState,
    #[serde(default)]
    supersedes: Option<EdgeId>,
    #[serde(default)]
    witness: Option<EvidenceWitness>,
}

impl<'de> Deserialize<'de> for CausalEdge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CausalEdgeWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            edge_id: wire.edge_id,
            from: wire.from,
            to: wire.to,
            relation: wire.relation,
            confidence_basis_points: wire.confidence_basis_points,
            source_evidence_ids: wire.source_evidence_ids,
            producer_role: wire.producer_role,
            producer_identity: wire.producer_identity,
            observed_at: wire.observed_at,
            state: wire.state,
            supersedes: wire.supersedes,
            witness: wire.witness,
        };
        record
            .validate(&persistence_limits())
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContradictionRecordWire {
    schema_version: u32,
    contradiction_id: ContradictionId,
    kind: ContradictionKind,
    evidence_ids: BTreeSet<EvidenceId>,
    basis: String,
}

impl<'de> Deserialize<'de> for ContradictionRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ContradictionRecordWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            contradiction_id: wire.contradiction_id,
            kind: wire.kind,
            evidence_ids: wire.evidence_ids,
            basis: wire.basis,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConflictRecordWire {
    schema_version: u32,
    conflict_id: ContradictionId,
    left_evidence_id: EvidenceId,
    right_evidence_id: EvidenceId,
    comparison_basis: String,
    kind: ContradictionKind,
}

impl<'de> Deserialize<'de> for ConflictRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ConflictRecordWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            conflict_id: wire.conflict_id,
            left_evidence_id: wire.left_evidence_id,
            right_evidence_id: wire.right_evidence_id,
            comparison_basis: wire.comparison_basis,
            kind: wire.kind,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRecordWire {
    schema_version: u32,
    decision_id: DecisionId,
    sequence: u64,
    kind: DecisionKind,
    hypothesis_id: HypothesisId,
    evidence_ids: BTreeSet<EvidenceId>,
    producer_role: GraphProducerRole,
    producer_identity: AgentId,
    decided_at: GraphLogicalTime,
    rationale: String,
    #[serde(default)]
    resulting_status: Option<HypothesisStatus>,
    #[serde(default)]
    witness: Option<EvidenceWitness>,
}

impl<'de> Deserialize<'de> for DecisionRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DecisionRecordWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            decision_id: wire.decision_id,
            sequence: wire.sequence,
            kind: wire.kind,
            hypothesis_id: wire.hypothesis_id,
            evidence_ids: wire.evidence_ids,
            producer_role: wire.producer_role,
            producer_identity: wire.producer_identity,
            decided_at: wire.decided_at,
            rationale: wire.rationale,
            resulting_status: wire.resulting_status,
            witness: wire.witness,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HypothesisWire {
    schema_version: u32,
    hypothesis_id: HypothesisId,
    graph_version: u64,
    claims: BTreeSet<EdgeId>,
    confidence: ConfidenceDistribution,
    uncertainty: BTreeSet<UncertaintyReason>,
    contradiction_ids: BTreeSet<ContradictionId>,
    decision_history: Vec<DecisionRecord>,
    status: HypothesisStatus,
}

impl<'de> Deserialize<'de> for Hypothesis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = HypothesisWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            hypothesis_id: wire.hypothesis_id,
            graph_version: wire.graph_version,
            claims: wire.claims,
            confidence: wire.confidence,
            uncertainty: wire.uncertainty,
            contradiction_ids: wire.contradiction_ids,
            decision_history: wire.decision_history,
            status: wire.status,
        };
        record
            .validate(&persistence_limits())
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskRecordWire {
    schema_version: u32,
    request: TaskClaimRequest,
    state: TaskState,
    generation: u64,
    attempts: u16,
    #[serde(default)]
    lease: Option<TaskLease>,
    #[serde(default)]
    completion: Option<TaskCompletion>,
    terminal_history: Vec<TaskTerminalProof>,
}

impl<'de> Deserialize<'de> for TaskRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskRecordWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            request: wire.request,
            state: wire.state,
            generation: wire.generation,
            attempts: wire.attempts,
            lease: wire.lease,
            completion: wire.completion,
            terminal_history: wire.terminal_history,
        };
        record
            .validate_with_limits(
                persistence_limits().max_task_lease_ms,
                persistence_limits().max_task_retries,
            )
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KillChainReconstructionWire {
    schema_version: u32,
    claims: Vec<KillChainClaim>,
    missing_evidence: Vec<MissingEvidence>,
}

impl<'de> Deserialize<'de> for KillChainReconstruction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KillChainReconstructionWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            claims: wire.claims,
            missing_evidence: wire.missing_evidence,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainmentSimulationWire {
    schema_version: u32,
    graph_id: GraphId,
    options: Vec<ContainmentOption>,
    simulation_only: bool,
}

impl<'de> Deserialize<'de> for ContainmentSimulation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ContainmentSimulationWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            graph_id: wire.graph_id,
            options: wire.options,
            simulation_only: wire.simulation_only,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryProvenanceWire {
    schema_version: u32,
    producer_identity: AgentId,
    evidence_ids: BTreeSet<EvidenceId>,
    witness: Option<EvidenceWitness>,
}

impl<'de> Deserialize<'de> for MemoryProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MemoryProvenanceWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            producer_identity: wire.producer_identity,
            evidence_ids: wire.evidence_ids,
            witness: wire.witness,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryWire {
    schema_version: u32,
    memory_id: MemoryId,
    graph_id: GraphId,
    selected_hypothesis_id: HypothesisId,
    hypothesis_delta: HypothesisDelta,
    evidence_utility: BTreeMap<EvidenceId, EvidenceUtility>,
    falsified_alternative_ids: BTreeSet<HypothesisId>,
    outcome: MemoryOutcome,
    provenance: MemoryProvenance,
    witness: Option<EvidenceWitness>,
}

impl<'de> Deserialize<'de> for StrategyMemory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StrategyMemoryWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            memory_id: wire.memory_id,
            graph_id: wire.graph_id,
            selected_hypothesis_id: wire.selected_hypothesis_id,
            hypothesis_delta: wire.hypothesis_delta,
            evidence_utility: wire.evidence_utility,
            falsified_alternative_ids: wire.falsified_alternative_ids,
            outcome: wire.outcome,
            provenance: wire.provenance,
            witness: wire.witness,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectiveMetricReportWire {
    schema_version: u32,
    denominators: MetricDenominators,
    results: MetricResults,
}

impl<'de> Deserialize<'de> for CollectiveMetricReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CollectiveMetricReportWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            denominators: wire.denominators,
            results: wire.results,
        };
        validate_collective_metric_report(&record).map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

fn validate_collective_metric_report(
    record: &CollectiveMetricReport,
) -> Result<(), GraphAdmissionError> {
    validate_schema(record.schema_version)?;
    MetricDenominators::new(
        record.denominators.adjudicated_cases,
        record.denominators.attack_chain_stages,
        record.denominators.causal_edges,
        record.denominators.logical_tasks,
        record.denominators.evidence_claims,
    )?;
    MetricResults::new(
        record.results.median_hypothesis_time_ms,
        record.results.attack_chain_recall_basis_points,
        record.results.false_causal_edge_rate_basis_points,
        record.results.duplicate_work_rate_basis_points,
        record.results.evidence_coverage_basis_points,
        record.results.logical_work_units,
    )?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphResourceLimitsWire {
    max_nodes: usize,
    max_edges: usize,
    max_evidence_bytes: usize,
    max_evidence_references_per_edge: usize,
    max_hypotheses: usize,
    max_contradictions: usize,
    max_decisions_per_hypothesis: usize,
    max_tasks: usize,
    max_task_lease_ms: u64,
    max_task_retries: u16,
    max_memory_records: usize,
    max_graph_depth: usize,
    max_graph_fan_out: usize,
    max_benchmark_work_units: usize,
}

impl<'de> Deserialize<'de> for GraphResourceLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = GraphResourceLimitsWire::deserialize(deserializer)?;
        let record = Self {
            max_nodes: wire.max_nodes,
            max_edges: wire.max_edges,
            max_evidence_bytes: wire.max_evidence_bytes,
            max_evidence_references_per_edge: wire.max_evidence_references_per_edge,
            max_hypotheses: wire.max_hypotheses,
            max_contradictions: wire.max_contradictions,
            max_decisions_per_hypothesis: wire.max_decisions_per_hypothesis,
            max_tasks: wire.max_tasks,
            max_task_lease_ms: wire.max_task_lease_ms,
            max_task_retries: wire.max_task_retries,
            max_memory_records: wire.max_memory_records,
            max_graph_depth: wire.max_graph_depth,
            max_graph_fan_out: wire.max_graph_fan_out,
            max_benchmark_work_units: wire.max_benchmark_work_units,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskClaimRequestWire {
    schema_version: u32,
    task_id: TaskId,
    kind: TaskKind,
    target: TaskTarget,
    role: GraphProducerRole,
    claimant: AgentId,
    evidence_scope: EvidenceScope,
    requested_at: GraphLogicalTime,
    idempotency_key: IdempotencyKey,
}

impl<'de> Deserialize<'de> for TaskClaimRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskClaimRequestWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            task_id: wire.task_id,
            kind: wire.kind,
            target: wire.target,
            role: wire.role,
            claimant: wire.claimant,
            evidence_scope: wire.evidence_scope,
            requested_at: wire.requested_at,
            idempotency_key: wire.idempotency_key,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskLeaseWire {
    schema_version: u32,
    lease_id: LeaseId,
    holder: AgentId,
    issued_at: GraphLogicalTime,
    expires_at: GraphLogicalTime,
    fencing_token: FencingToken,
}

impl<'de> Deserialize<'de> for TaskLease {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskLeaseWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            lease_id: wire.lease_id,
            holder: wire.holder,
            issued_at: wire.issued_at,
            expires_at: wire.expires_at,
            fencing_token: wire.fencing_token,
        };
        record
            .validate_with_limit(persistence_limits().max_task_lease_ms)
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskCompletionWire {
    schema_version: u32,
    kind: TaskCompletionKind,
    completed_by: AgentId,
    completed_at: GraphLogicalTime,
    evidence_ids: BTreeSet<EvidenceId>,
    summary_digest: String,
}

impl<'de> Deserialize<'de> for TaskCompletion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskCompletionWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            kind: wire.kind,
            completed_by: wire.completed_by,
            completed_at: wire.completed_at,
            evidence_ids: wire.evidence_ids,
            summary_digest: wire.summary_digest,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskDecisionLinkWire {
    task_id: TaskId,
    target: TaskTarget,
    evidence_ids: BTreeSet<EvidenceId>,
    #[serde(default)]
    decision_id: Option<DecisionId>,
}

impl<'de> Deserialize<'de> for TaskDecisionLink {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskDecisionLinkWire::deserialize(deserializer)?;
        let record = Self {
            task_id: wire.task_id,
            target: wire.target,
            evidence_ids: wire.evidence_ids,
            decision_id: wire.decision_id,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskCapabilityProofWire {
    task_id: TaskId,
    claimant: AgentId,
    role: GraphProducerRole,
    kind: TaskKind,
    canonical_claim_digest: String,
    witness: EvidenceWitness,
}

impl<'de> Deserialize<'de> for TaskCapabilityProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskCapabilityProofWire::deserialize(deserializer)?;
        let record = Self {
            task_id: wire.task_id,
            claimant: wire.claimant,
            role: wire.role,
            kind: wire.kind,
            canonical_claim_digest: wire.canonical_claim_digest,
            witness: wire.witness,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskTerminalEnvelopeWire {
    task_id: TaskId,
    idempotency_key: IdempotencyKey,
    lease_id: LeaseId,
    fencing_token: FencingToken,
    completion: TaskCompletion,
    #[serde(default)]
    decision_link: Option<TaskDecisionLink>,
    producer: AgentId,
    capability: TaskCapabilityProof,
    #[serde(default)]
    terminal_witness: Option<EvidenceWitness>,
}

impl<'de> Deserialize<'de> for TaskTerminalEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskTerminalEnvelopeWire::deserialize(deserializer)?;
        let record = Self {
            task_id: wire.task_id,
            idempotency_key: wire.idempotency_key,
            lease_id: wire.lease_id,
            fencing_token: wire.fencing_token,
            completion: wire.completion,
            decision_link: wire.decision_link,
            producer: wire.producer,
            capability: wire.capability,
            terminal_witness: wire.terminal_witness,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskTerminalProofWire {
    schema_version: u32,
    prior_state: TaskState,
    terminal_state: TaskState,
    prior_generation: u64,
    prior_lease: TaskLease,
    completer: AgentId,
    completed_at: GraphLogicalTime,
}

impl<'de> Deserialize<'de> for TaskTerminalProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TaskTerminalProofWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            prior_state: wire.prior_state,
            terminal_state: wire.terminal_state,
            prior_generation: wire.prior_generation,
            prior_lease: wire.prior_lease,
            completer: wire.completer,
            completed_at: wire.completed_at,
        };
        record
            .validate(persistence_limits().max_task_lease_ms)
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphSchedulerKeyWire {
    ready_at: GraphLogicalTime,
    task_kind: TaskKind,
    priority_basis_points: u16,
    task_id: TaskId,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphPolicyContractWire {
    schema_version: u32,
    mode: GraphPolicyMode,
    policy_digest: String,
}

impl<'de> Deserialize<'de> for GraphPolicyContract {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = GraphPolicyContractWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            mode: wire.mode,
            policy_digest: wire.policy_digest,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

impl<'de> Deserialize<'de> for GraphSchedulerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = GraphSchedulerKeyWire::deserialize(deserializer)?;
        let record = Self {
            ready_at: wire.ready_at,
            task_kind: wire.task_kind,
            priority_basis_points: wire.priority_basis_points,
            task_id: wire.task_id,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulerBudgetWire {
    max_work_units: u32,
    max_claims: u16,
    current_tick: GraphLogicalTime,
    work_units_used: u32,
    claims_used: u16,
}

impl<'de> Deserialize<'de> for SchedulerBudget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SchedulerBudgetWire::deserialize(deserializer)?;
        let record = Self {
            max_work_units: wire.max_work_units,
            max_claims: wire.max_claims,
            current_tick: wire.current_tick,
            work_units_used: wire.work_units_used,
            claims_used: wire.claims_used,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryExpiryEnvelopeWire {
    schema_version: u32,
    memory_id: MemoryId,
    memory_digest: String,
    created_at: GraphLogicalTime,
    expires_at: GraphLogicalTime,
    signature: EvidenceWitness,
}

impl<'de> Deserialize<'de> for StrategyMemoryExpiryEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StrategyMemoryExpiryEnvelopeWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            memory_id: wire.memory_id,
            memory_digest: wire.memory_digest,
            created_at: wire.created_at,
            expires_at: wire.expires_at,
            signature: wire.signature,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KillChainClaimWire {
    schema_version: u32,
    claim_id: KillChainClaimId,
    stage: KillChainStage,
    node_ids: BTreeSet<GraphNodeId>,
    edge_ids: BTreeSet<EdgeId>,
    evidence_ids: BTreeSet<EvidenceId>,
    predecessor_claim_ids: BTreeSet<KillChainClaimId>,
    order: KillChainOrder,
    narration: String,
    narration_evidence_ids: BTreeSet<EvidenceId>,
}

impl<'de> Deserialize<'de> for KillChainClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KillChainClaimWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            claim_id: wire.claim_id,
            stage: wire.stage,
            node_ids: wire.node_ids,
            edge_ids: wire.edge_ids,
            evidence_ids: wire.evidence_ids,
            predecessor_claim_ids: wire.predecessor_claim_ids,
            order: wire.order,
            narration: wire.narration,
            narration_evidence_ids: wire.narration_evidence_ids,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MissingEvidenceWire {
    schema_version: u32,
    claim_id: KillChainClaimId,
    expected_scope: String,
    reason: String,
}

impl<'de> Deserialize<'de> for MissingEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MissingEvidenceWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            claim_id: wire.claim_id,
            expected_scope: wire.expected_scope,
            reason: wire.reason,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainmentOptionWire {
    schema_version: u32,
    option_id: String,
    kind: ContainmentOptionKind,
    target_node_ids: BTreeSet<GraphNodeId>,
    predicted_blast_radius_basis_points: u16,
    reversibility_basis_points: u16,
    evidence_support_basis_points: u16,
    required_approval: ApprovalClass,
    rollback_expected: bool,
    rank: u32,
}

impl<'de> Deserialize<'de> for ContainmentOption {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ContainmentOptionWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            option_id: wire.option_id,
            kind: wire.kind,
            target_node_ids: wire.target_node_ids,
            predicted_blast_radius_basis_points: wire.predicted_blast_radius_basis_points,
            reversibility_basis_points: wire.reversibility_basis_points,
            evidence_support_basis_points: wire.evidence_support_basis_points,
            required_approval: wire.required_approval,
            rollback_expected: wire.rollback_expected,
            rank: wire.rank,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HypothesisDeltaWire {
    schema_version: u32,
    added_edge_ids: BTreeSet<EdgeId>,
    retracted_edge_ids: BTreeSet<EdgeId>,
    superseded_edge_ids: BTreeSet<EdgeId>,
}

impl<'de> Deserialize<'de> for HypothesisDelta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = HypothesisDeltaWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            added_edge_ids: wire.added_edge_ids,
            retracted_edge_ids: wire.retracted_edge_ids,
            superseded_edge_ids: wire.superseded_edge_ids,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceUtilityWire {
    schema_version: u32,
    evidence_id: EvidenceId,
    utility_basis_points: u16,
}

impl<'de> Deserialize<'de> for EvidenceUtility {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = EvidenceUtilityWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            evidence_id: wire.evidence_id,
            utility_basis_points: wire.utility_basis_points,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryMatchWire {
    schema_version: u32,
    memory_id: MemoryId,
    relevance_basis_points: u16,
    provenance_evidence_ids: BTreeSet<EvidenceId>,
}

impl<'de> Deserialize<'de> for StrategyMemoryMatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StrategyMemoryMatchWire::deserialize(deserializer)?;
        let record = Self {
            schema_version: wire.schema_version,
            memory_id: wire.memory_id,
            relevance_basis_points: wire.relevance_basis_points,
            provenance_evidence_ids: wire.provenance_evidence_ids,
        };
        record.validate().map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

macro_rules! impl_validated_record {
    ($record:ty, $validator:expr) => {
        impl ValidatedGraphRecord for $record {
            fn validate_record(&self) -> Result<(), GraphAdmissionError> {
                $validator(self)
            }
        }
    };
}

impl_validated_record!(HypothesisGraph, |record: &HypothesisGraph| record
    .validate());
impl_validated_record!(GraphResourceLimits, |record: &GraphResourceLimits| record
    .validate());
impl_validated_record!(EvidenceEnvelope, |record: &EvidenceEnvelope| record
    .validate());
impl_validated_record!(CausalEdge, |record: &CausalEdge| record
    .validate(&persistence_limits()));
impl_validated_record!(ContradictionRecord, |record: &ContradictionRecord| record
    .validate());
impl_validated_record!(ConflictRecord, |record: &ConflictRecord| record.validate());
impl_validated_record!(DecisionRecord, |record: &DecisionRecord| record.validate());
impl_validated_record!(Hypothesis, |record: &Hypothesis| record
    .validate(&persistence_limits()));
impl_validated_record!(TaskClaimRequest, |record: &TaskClaimRequest| record
    .validate());
impl_validated_record!(TaskLease, |record: &TaskLease| record
    .validate_with_limit(persistence_limits().max_task_lease_ms));
impl_validated_record!(TaskCompletion, |record: &TaskCompletion| record.validate());
impl_validated_record!(TaskDecisionLink, |record: &TaskDecisionLink| record
    .validate());
impl_validated_record!(TaskCapabilityProof, |record: &TaskCapabilityProof| record
    .validate());
impl_validated_record!(TaskTerminalEnvelope, |record: &TaskTerminalEnvelope| record
    .validate());
impl_validated_record!(SchedulerBudget, |record: &SchedulerBudget| record
    .validate());
impl_validated_record!(GraphPolicyContract, |record: &GraphPolicyContract| record
    .validate());
impl_validated_record!(TaskRecord, |record: &TaskRecord| record
    .validate_with_limits(
        persistence_limits().max_task_lease_ms,
        persistence_limits().max_task_retries,
    ));
impl_validated_record!(GraphSchedulerKey, |record: &GraphSchedulerKey| record
    .validate());
impl_validated_record!(TaskTerminalProof, |record: &TaskTerminalProof| record
    .validate(persistence_limits().max_task_lease_ms));
impl_validated_record!(KillChainClaim, |record: &KillChainClaim| record.validate());
impl_validated_record!(
    KillChainReconstruction,
    |record: &KillChainReconstruction| record.validate()
);
impl_validated_record!(ContainmentOption, |record: &ContainmentOption| record
    .validate());
impl_validated_record!(ContainmentSimulation, |record: &ContainmentSimulation| {
    record.validate()
});
impl_validated_record!(HypothesisDelta, |record: &HypothesisDelta| record
    .validate());
impl_validated_record!(EvidenceUtility, |record: &EvidenceUtility| record
    .validate());
impl_validated_record!(MemoryProvenance, |record: &MemoryProvenance| record
    .validate());
impl_validated_record!(StrategyMemory, |record: &StrategyMemory| record.validate());
impl_validated_record!(
    StrategyMemoryExpiryEnvelope,
    |record: &StrategyMemoryExpiryEnvelope| record.validate()
);
impl_validated_record!(StrategyMemoryMatch, |record: &StrategyMemoryMatch| record
    .validate());
impl_validated_record!(CollectiveMetricReport, |record: &CollectiveMetricReport| {
    if record.denominators.adjudicated_cases == 0
        || record.denominators.attack_chain_stages == 0
        || record.denominators.causal_edges == 0
        || record.denominators.logical_tasks == 0
        || record.denominators.evidence_claims == 0
    {
        return Err(GraphAdmissionError::InvalidField {
            field: "metrics.denominators".to_string(),
            reason: "all denominators must be greater than zero".to_string(),
        });
    }
    MetricResults::new(
        record.results.median_hypothesis_time_ms,
        record.results.attack_chain_recall_basis_points,
        record.results.false_causal_edge_rate_basis_points,
        record.results.duplicate_work_rate_basis_points,
        record.results.evidence_coverage_basis_points,
        record.results.logical_work_units,
    )?;
    validate_schema(record.schema_version)
});

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::AgentId;
    use swarm_crypto::Keypair;

    fn signer() -> Keypair {
        Keypair::from_seed(&[7_u8; 32])
    }

    fn signer_identity() -> AgentId {
        let key = signer();
        let public_key_hex = key.public_key().to_hex();
        AgentId::from_public_key_hex(&public_key_hex)
    }

    fn envelope(id: &str, role: GraphProducerRole) -> EvidenceEnvelope {
        EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            id,
            SourceLineage::new("fixture", id).expect("lineage"),
            EvidenceClock::observed(GraphLogicalTime::new(1_700_000_000_100)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Signal {
                signal_kind: "test_signal".to_string(),
                entity_ids: vec![GraphNodeId::new("node:event:test")],
                relation_ids: vec![],
                supports: vec![HypothesisId::new("hypothesis:compromise")],
                refutes: vec![HypothesisId::new("hypothesis:automation")],
                content_digest: "digest:test".to_string(),
            },
        )
        .expect("envelope")
        .sign_with(&signer(), role, "hunter-a")
        .expect("signed envelope")
    }

    #[test]
    fn evidence_identity_ignores_ingest_time_but_signature_keeps_operational_clock() {
        let payload = TypedEvidencePayload::Signal {
            signal_kind: "clocked".to_string(),
            entity_ids: vec![GraphNodeId::new("node:event:clocked")],
            relation_ids: vec![],
            supports: vec![],
            refutes: vec![],
            content_digest: "digest:clocked".to_string(),
        };
        let first = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "tetragon",
            SourceLineage::new("fixture", "record:clocked").unwrap(),
            EvidenceClock {
                observed_at: GraphLogicalTime::new(1_000),
                ingested_at: Some(GraphLogicalTime::new(2_000)),
                precision: ClockPrecision::Millisecond,
                uncertainty_ms: 0,
            },
            OrderingClaim::Unknown,
            payload.clone(),
        )
        .unwrap()
        .sign_with(&signer(), GraphProducerRole::Normalizer, "normalizer-clock")
        .unwrap();
        let second = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "tetragon",
            SourceLineage::new("fixture", "record:clocked").unwrap(),
            EvidenceClock {
                observed_at: GraphLogicalTime::new(1_000),
                ingested_at: Some(GraphLogicalTime::new(3_000)),
                precision: ClockPrecision::Millisecond,
                uncertainty_ms: 0,
            },
            OrderingClaim::Unknown,
            payload,
        )
        .unwrap()
        .sign_with(&signer(), GraphProducerRole::Normalizer, "normalizer-clock")
        .unwrap();
        assert_eq!(first.evidence_id, second.evidence_id);
        assert_ne!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        assert_eq!(
            first.deterministic_content_bytes().unwrap(),
            second.deterministic_content_bytes().unwrap()
        );
        let mut graph =
            HypothesisGraph::new(GraphId::new("graph:clock"), Default::default()).unwrap();
        graph.admit_evidence(first).unwrap();
        graph.admit_evidence(second).unwrap();
        assert_eq!(graph.evidence.len(), 1);
    }

    #[test]
    fn threat_intelligence_expiry_is_typed_and_boundary_is_expired() {
        let payload = TypedEvidencePayload::ThreatIntelligence {
            signal_kind: "threat_intelligence".to_string(),
            feed_id: "feed:test".to_string(),
            indicator_digest: "digest:indicator".to_string(),
            indicator_kind: "domain".to_string(),
            confidence_basis_points: 9_000,
            expires_at: GraphLogicalTime::new(2_000),
            entity_ids: vec![GraphNodeId::new("node:indicator:test")],
            content_digest: "digest:threat".to_string(),
        };
        assert_eq!(payload.expires_at(), Some(GraphLogicalTime::new(2_000)));
        assert_eq!(
            payload.is_active_at(GraphLogicalTime::new(1_999)).unwrap(),
            Some(true)
        );
        assert_eq!(
            payload.is_active_at(GraphLogicalTime::new(2_000)).unwrap(),
            Some(false)
        );
        assert_eq!(
            payload.is_active_at(GraphLogicalTime::new(2_001)).unwrap(),
            Some(false)
        );
        assert!(payload.is_active_at(GraphLogicalTime::new(-1)).is_err());
        let invalid = TypedEvidencePayload::ThreatIntelligence {
            signal_kind: "threat_intelligence".to_string(),
            feed_id: "feed:test".to_string(),
            indicator_digest: "digest:indicator".to_string(),
            indicator_kind: "domain".to_string(),
            confidence_basis_points: 9_000,
            expires_at: GraphLogicalTime::new(-1),
            entity_ids: vec![GraphNodeId::new("node:indicator:test")],
            content_digest: "digest:threat".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn hypothesis_graph_strictly_admits_typed_nodes_evidence_and_edges() {
        let limits = GraphResourceLimits::default();
        let mut graph = HypothesisGraph::new(GraphId::new("graph:test"), limits).expect("graph");
        let actor =
            GraphNode::Actor(ActorNode::new("principal:digest", "principal-a").expect("actor"));
        let event = GraphNode::Event(
            EventNode::new(
                "seed",
                "source:seed:1",
                GraphLogicalTime::new(1_700_000_000_100),
            )
            .expect("event"),
        );
        let actor_id = actor.id().clone();
        let event_id = event.id().clone();
        graph.admit_node(actor).expect("actor admission");
        graph.admit_node(event).expect("event admission");
        let evidence = envelope("record:test", GraphProducerRole::Hunter);
        let evidence_id = evidence.evidence_id.clone();
        let evidence_identity = evidence.witness.producer_identity.clone();
        graph.admit_evidence(evidence).expect("evidence admission");
        let edge = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            8_000,
            [evidence_id],
            GraphProducerRole::Hunter,
            evidence_identity,
            GraphLogicalTime::new(1_700_000_000_100),
            EdgeState::Proposed,
        )
        .expect("edge")
        .signed_with(&signer(), "hunter-a")
        .expect("signed edge");
        graph.admit_edge(edge).expect("edge admission");
        let encoded = serde_json::to_string(&graph).expect("strict graph serialization");
        let decoded: HypothesisGraph = serde_json::from_str(&encoded).expect("strict round trip");
        assert_eq!(decoded, graph);
        assert!(
            serde_json::from_str::<HypothesisGraph>(&encoded.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"extra\":true"
            ))
            .is_err()
        );
    }

    #[test]
    fn hypothesis_graph_rejects_unproven_edges_and_id_collisions() {
        let limits = GraphResourceLimits::default();
        let mut graph = HypothesisGraph::new(GraphId::new("graph:test"), limits).expect("graph");
        let actor = GraphNode::Actor(ActorNode::new("principal:digest", "principal-a").unwrap());
        let event = GraphNode::Event(
            EventNode::new("seed", "source:seed:2", GraphLogicalTime::new(100)).unwrap(),
        );
        let actor_id = actor.id().clone();
        let event_id = event.id().clone();
        graph.admit_node(actor).unwrap();
        graph.admit_node(event).unwrap();
        let no_evidence = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            5_000,
            [],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(1_700_000_000_100),
            EdgeState::Proposed,
        );
        assert!(no_evidence.is_err());
        let evidence = envelope("record:test", GraphProducerRole::Hunter);
        let evidence_id = evidence.evidence_id.clone();
        let evidence_identity = evidence.witness.producer_identity.clone();
        graph.admit_evidence(evidence).unwrap();
        let edge = CausalEdge::new(
            &actor_id,
            &event_id,
            CausalRelation::ObservedIn,
            5_000,
            [evidence_id],
            GraphProducerRole::Hunter,
            evidence_identity,
            GraphLogicalTime::new(1_700_000_000_100),
            EdgeState::Proposed,
        )
        .unwrap()
        .signed_with(&signer(), "hunter-a")
        .unwrap();
        let mut changed = edge.clone();
        changed.confidence_basis_points = 5_001;
        assert!(graph.admit_edge(edge).is_ok());
        assert!(matches!(
            graph.admit_edge(changed),
            Err(GraphAdmissionError::IdCollision { .. })
        ));
    }

    #[test]
    fn hypothesis_graph_preserves_competing_hypotheses_and_append_only_decisions() {
        let confidence = ConfidenceDistribution::new([
            (ConfidenceBucket::High, 5_000),
            (ConfidenceBucket::Medium, 3_000),
            (ConfidenceBucket::Low, 1_000),
            (ConfidenceBucket::Unknown, 1_000),
        ])
        .expect("basis points sum");
        let contradiction = ContradictionRecord::new(
            ContradictionKind::EvidenceConflict,
            [EvidenceId::new("evidence:a"), EvidenceId::new("evidence:b")],
            "source observations disagree",
        )
        .expect("contradiction");
        let first = Hypothesis::new(
            HypothesisId::new("hypothesis:compromise"),
            confidence.clone(),
            [UncertaintyReason::ConflictingEvidence],
            [contradiction.contradiction_id.clone()],
        )
        .expect("first hypothesis");
        let second = Hypothesis::new(
            HypothesisId::new("hypothesis:automation"),
            ConfidenceDistribution::uniform_two(),
            [UncertaintyReason::InsufficientEvidence],
            [],
        )
        .expect("second hypothesis");
        assert_eq!(confidence.total_basis_points(), 10_000);
        assert_eq!(first.status, HypothesisStatus::Live);
        assert_eq!(second.status, HypothesisStatus::Live);
        let decision = DecisionRecord::new(
            DecisionKind::Support,
            first.hypothesis_id.clone(),
            [EvidenceId::new("evidence:a")],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(101),
            "supporting signal",
        )
        .expect("decision")
        .signed_with(&signer(), "hunter-a")
        .expect("signed decision");
        let updated = first.clone().append_decision(decision).expect("append");
        assert_eq!(updated.decision_history.len(), 1);
        assert_eq!(updated.status, HypothesisStatus::Live);
        assert_eq!(updated.contradiction_ids, first.contradiction_ids);
        // Sequence is assigned by append, so it must not invalidate the
        // decision's self-contained signature or a persisted reload.
        assert!(updated.validate(&GraphResourceLimits::default()).is_ok());
        let reloaded: Hypothesis =
            serde_json::from_str(&serde_json::to_string(&updated).expect("serialize hypothesis"))
                .expect("reload appended hypothesis");
        assert_eq!(reloaded, updated);
    }

    #[test]
    fn hypothesis_graph_tasks_kill_chain_memory_and_metrics_are_bounded_and_typed() {
        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:a")],
            [GraphNodeId::new("node:event:a")],
        )
        .expect("scope");
        let request = TaskClaimRequest::new(
            TaskId::new("task:a"),
            TaskKind::AcquireEvidence,
            TaskTarget::Evidence {
                evidence_id: EvidenceId::new("evidence:a"),
            },
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            scope.clone(),
            GraphLogicalTime::new(100),
        )
        .expect("claim request");
        assert_eq!(
            request.idempotency_key,
            request.derive_idempotency_key().unwrap()
        );
        let lease = TaskLease::new(
            LeaseId::new("lease:a"),
            request.claimant.clone(),
            GraphLogicalTime::new(100),
            GraphLogicalTime::new(200),
            FencingToken::new(1),
        )
        .expect("lease");
        let task = TaskRecord::claimed(request, lease).expect("task");
        assert_eq!(task.state, TaskState::Claimed);

        let claim = KillChainClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:process:a")],
            [EdgeId::new("edge:process:a")],
            [EvidenceId::new("evidence:a")],
            [],
            "process execution observed",
            [EvidenceId::new("evidence:a")],
        )
        .expect("kill chain claim");
        let reconstruction = KillChainReconstruction::new([claim], []).expect("chain");
        assert_eq!(reconstruction.claims.len(), 1);

        let memory = StrategyMemory::new(
            GraphId::new("graph:test"),
            HypothesisId::new("hypothesis:compromise"),
            HypothesisDelta::new([EdgeId::new("edge:process:a")], [], []),
            [EvidenceUtility::new(EvidenceId::new("evidence:a"), 8_000)],
            [HypothesisId::new("hypothesis:automation")],
            MemoryOutcome::Confirmed,
            MemoryProvenance::new(signer_identity(), [EvidenceId::new("evidence:a")])
                .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-a")
                .expect("signed provenance"),
        )
        .expect("memory")
        .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-a")
        .expect("signed memory");
        assert!(!serde_json::to_string(&memory).unwrap().contains("raw"));

        let report = CollectiveMetricReport::new(
            MetricDenominators::new(2, 5, 6, 100, 16).unwrap(),
            MetricResults::new(4_000, 8_000, 500, 200, 9_500, 10_000).unwrap(),
        )
        .expect("metrics");
        assert_eq!(report.results.evidence_coverage_basis_points, 9_500);
        assert_eq!(task.state, TaskState::Claimed);
    }

    #[test]
    fn persisted_graph_rejects_tampered_map_keys_and_validated_api_rejects_records() {
        let graph = HypothesisGraph::new(GraphId::new("graph:validated"), Default::default())
            .expect("graph");
        let node = GraphNode::Actor(ActorNode::new("principal:digest", "principal-a").unwrap());
        let node_id = node.id().clone();
        let mut graph = graph;
        graph.admit_node(node).unwrap();
        let mut encoded = serde_json::to_value(&graph).unwrap();
        let nodes = encoded["nodes"].as_object_mut().unwrap();
        let node_json = nodes.remove(node_id.as_str()).unwrap();
        nodes.insert("node:tampered".to_string(), node_json);
        assert!(serde_json::from_value::<HypothesisGraph>(encoded).is_err());

        let decision = DecisionRecord::new(
            DecisionKind::Support,
            HypothesisId::new("hypothesis:test"),
            [EvidenceId::new("evidence:test")],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(10),
            "support",
        )
        .unwrap()
        .signed_with(&signer(), "hunter-a")
        .unwrap();
        let mut decision_json = serde_json::to_value(&decision).unwrap();
        decision_json["decision_id"] = serde_json::json!("decision:tampered");
        assert!(deserialize_validated::<DecisionRecord>(&decision_json.to_string()).is_err());
    }

    #[test]
    fn canonical_identity_and_process_parent_admission_is_fail_closed() {
        let mut contradiction = ContradictionRecord::new(
            ContradictionKind::EvidenceConflict,
            [EvidenceId::new("evidence:a"), EvidenceId::new("evidence:b")],
            "basis",
        )
        .unwrap();
        contradiction.basis = "changed".to_string();
        assert!(contradiction.validate().is_err());

        let mut conflict = ConflictRecord::new(
            EvidenceId::new("evidence:z"),
            EvidenceId::new("evidence:a"),
            ContradictionKind::EvidenceConflict,
            "basis",
        )
        .unwrap();
        assert!(conflict.left_evidence_id < conflict.right_evidence_id);
        conflict.comparison_basis = "changed".to_string();
        assert!(conflict.validate().is_err());

        let decision = DecisionRecord::new(
            DecisionKind::Adjudicate,
            HypothesisId::new("hypothesis:test"),
            [EvidenceId::new("evidence:a")],
            GraphProducerRole::Adjudicator,
            AgentId::new("adjudicator", "a"),
            GraphLogicalTime::new(10),
            "select",
        )
        .unwrap()
        .with_resulting_status(HypothesisStatus::Selected)
        .unwrap()
        .signed_with(&signer(), "adjudicator-a")
        .unwrap();
        assert!(decision.validate().is_ok());
        let mut changed_decision = decision.clone();
        changed_decision.resulting_status = Some(HypothesisStatus::Retired);
        assert!(changed_decision.validate().is_err());

        let mut claim = KillChainClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:process")],
            [EdgeId::new("edge:process")],
            [EvidenceId::new("evidence:a")],
            [],
            "execution",
            [EvidenceId::new("evidence:a")],
        )
        .unwrap();
        claim.narration = "tampered".to_string();
        assert!(claim.validate().is_err());

        let mut option = ContainmentOption::new(
            ContainmentOptionKind::IsolateAsset,
            [GraphNodeId::new("node:asset")],
            100,
            9_000,
            8_000,
            ApprovalClass::Operator,
            true,
        )
        .unwrap();
        option
            .target_node_ids
            .insert(GraphNodeId::new("node:other"));
        assert!(option.validate().is_err());

        let parent = GraphNodeId::new("node:parent");
        let child = ProcessNode::new_with_parent("process", "executable", parent).unwrap();
        assert!(child.validate().is_ok());
        let mut tampered_child = child.clone();
        tampered_child.parent_node_id = None;
        assert!(tampered_child.validate().is_err());

        let memory = StrategyMemory::new(
            GraphId::new("graph:test"),
            HypothesisId::new("hypothesis:test"),
            HypothesisDelta::new([EdgeId::new("edge:a")], [], []),
            [EvidenceUtility::new(EvidenceId::new("evidence:a"), 5000)],
            [],
            MemoryOutcome::Confirmed,
            MemoryProvenance::new(signer_identity(), [EvidenceId::new("evidence:a")])
                .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-a")
                .expect("signed provenance"),
        )
        .unwrap();
        let mut changed_memory = memory.clone();
        changed_memory.graph_id = GraphId::new("graph:other");
        assert!(changed_memory.validate().is_err());
    }

    #[test]
    fn identity_temporal_topology_and_nested_bounds_are_enforced() {
        let evidence = envelope("record:identity", GraphProducerRole::Hunter);
        let evidence_id = evidence.evidence_id.clone();
        let witness_identity = evidence.witness.producer_identity.clone();
        let mut admitted = BTreeMap::new();
        admitted.insert(evidence_id.clone(), evidence);
        let actor = GraphNode::Actor(ActorNode::new("principal:a", "a").unwrap());
        let event = GraphNode::Event(
            EventNode::new(
                "event",
                "source:event:1",
                GraphLogicalTime::new(1_700_000_000_100),
            )
            .unwrap(),
        );
        let mut edge = CausalEdge::new(
            actor.id(),
            event.id(),
            CausalRelation::ObservedIn,
            5_000,
            [evidence_id.clone()],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "forged"),
            GraphLogicalTime::new(1_700_000_000_100),
            EdgeState::Proposed,
        )
        .unwrap()
        .signed_with(&signer(), "hunter-a")
        .unwrap();
        edge.producer_identity = AgentId::new("hunter", "forged");
        assert!(edge.validate_identity_admission(&admitted).is_err());
        edge.producer_identity = witness_identity.clone();
        assert!(edge.validate_identity_admission(&admitted).is_ok());
        edge.observed_at = GraphLogicalTime::new(1);
        assert!(edge.validate_temporal_admission(&admitted).is_err());

        let limits = GraphResourceLimits {
            max_task_retries: 0,
            ..GraphResourceLimits::default()
        };
        assert!(limits.validate().is_err());
        assert!(GraphLogicalTime::new(-1).validate().is_err());
        assert!(serde_json::from_str::<TypedEvidencePayload>(
            r#"{"kind":"signal","signal_kind":"x","entity_ids":[],"relation_ids":[],"supports":[],"refutes":[],"content_digest":"x","extra":true}"#
        )
        .is_err());

        let oversized = TypedEvidencePayload::Process {
            signal_kind: "process".to_string(),
            process_digest: "x".repeat(257),
            parent_process_digest: None,
            entity_ids: Vec::new(),
            content_digest: "digest".to_string(),
        };
        assert!(
            EvidenceEnvelope::new(
                EvidenceSourceFamily::Process,
                "record:oversized",
                SourceLineage::new("fixture", "record:oversized").unwrap(),
                EvidenceClock::observed(GraphLogicalTime::new(10)),
                OrderingClaim::Unknown,
                oversized,
            )
            .is_err()
        );
    }

    #[test]
    fn topology_and_task_state_transitions_cannot_be_bypassed() {
        let evidence = envelope("record:topology", GraphProducerRole::Hunter);
        let evidence_id = evidence.evidence_id.clone();
        let witness_identity = evidence.witness.producer_identity.clone();
        let mut graph = HypothesisGraph::new(
            GraphId::new("graph:topology"),
            GraphResourceLimits {
                max_graph_fan_out: 1,
                max_graph_depth: 3,
                ..GraphResourceLimits::default()
            },
        )
        .unwrap();
        let actor = GraphNode::Actor(ActorNode::new("principal:t", "t").unwrap());
        let event_a = GraphNode::Event(
            EventNode::new("a", "source:a:1", GraphLogicalTime::new(1_700_000_000_100)).unwrap(),
        );
        let event_b = GraphNode::Event(
            EventNode::new("b", "source:b:1", GraphLogicalTime::new(1_700_000_000_100)).unwrap(),
        );
        let actor_id = actor.id().clone();
        let a_id = event_a.id().clone();
        let b_id = event_b.id().clone();
        graph.admit_node(actor).unwrap();
        graph.admit_node(event_a).unwrap();
        graph.admit_node(event_b).unwrap();
        graph.admit_evidence(evidence).unwrap();
        let edge = |from: &GraphNodeId, to: &GraphNodeId| {
            CausalEdge::new(
                from,
                to,
                CausalRelation::ObservedIn,
                5_000,
                [evidence_id.clone()],
                GraphProducerRole::Hunter,
                witness_identity.clone(),
                GraphLogicalTime::new(1_700_000_000_100),
                EdgeState::Proposed,
            )
            .unwrap()
            .signed_with(&signer(), "hunter-a")
            .unwrap()
        };
        graph.admit_edge(edge(&actor_id, &a_id)).unwrap();
        assert!(matches!(
            graph.admit_edge(edge(&actor_id, &b_id)),
            Err(GraphAdmissionError::ResourceLimitExceeded { .. })
        ));
        assert!(matches!(
            graph.admit_edge(edge(&a_id, &actor_id)),
            Err(GraphAdmissionError::InvalidTransition { .. })
        ));

        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:a")],
            [GraphNodeId::new("node:a")],
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            TaskId::new("task:state"),
            TaskKind::AcquireEvidence,
            TaskTarget::Evidence {
                evidence_id: EvidenceId::new("evidence:a"),
            },
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            scope,
            GraphLogicalTime::new(100),
        )
        .unwrap();
        let wrong_holder = TaskLease::new(
            LeaseId::new("lease:wrong"),
            AgentId::new("hunter", "other"),
            GraphLogicalTime::new(100),
            GraphLogicalTime::new(200),
            FencingToken::new(1),
        )
        .unwrap();
        assert!(TaskRecord::claimed(request.clone(), wrong_holder).is_err());
        let long_lease = TaskLease::new(
            LeaseId::new("lease:long"),
            request.claimant.clone(),
            GraphLogicalTime::new(100),
            GraphLogicalTime::new(10_000),
            FencingToken::new(1),
        )
        .unwrap();
        assert!(TaskRecord::claimed_with_limits(request.clone(), long_lease, 100, 3).is_err());
        let lease = TaskLease::new(
            LeaseId::new("lease:ok"),
            request.claimant.clone(),
            GraphLogicalTime::new(100),
            GraphLogicalTime::new(200),
            FencingToken::new(1),
        )
        .unwrap();
        let task = TaskRecord::claimed_with_limits(request, lease, 100, 3).unwrap();
        let completion = TaskCompletion::new(
            TaskCompletionKind::NoFinding,
            AgentId::new("hunter", "other"),
            GraphLogicalTime::new(150),
            [],
            "summary",
        )
        .unwrap();
        assert!(
            task.complete(completion, FencingToken::new(1), 100)
                .is_err()
        );

        let mut hypothesis = Hypothesis::new(
            HypothesisId::new("hypothesis:state"),
            ConfidenceDistribution::uniform_two(),
            [],
            [],
        )
        .unwrap();
        let adjudication = DecisionRecord::new(
            DecisionKind::Adjudicate,
            hypothesis.hypothesis_id.clone(),
            [EvidenceId::new("evidence:a")],
            GraphProducerRole::Adjudicator,
            AgentId::new("adjudicator", "a"),
            GraphLogicalTime::new(1),
            "select",
        )
        .unwrap()
        .with_resulting_status(HypothesisStatus::Selected)
        .unwrap()
        .signed_with(&signer(), "adjudicator-a")
        .unwrap();
        hypothesis = hypothesis.append_decision(adjudication).unwrap();
        let support = DecisionRecord::new(
            DecisionKind::Support,
            hypothesis.hypothesis_id.clone(),
            [EvidenceId::new("evidence:a")],
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "a"),
            GraphLogicalTime::new(2),
            "late support",
        )
        .unwrap()
        .signed_with(&signer(), "hunter-a")
        .unwrap();
        hypothesis = hypothesis.append_decision(support).unwrap();
        let mut tampered = hypothesis;
        tampered.status = HypothesisStatus::Live;
        assert!(tampered.validate(&GraphResourceLimits::default()).is_err());
    }

    #[test]
    fn event_node_same_time_different_source_records_are_distinct() {
        let observed_at = GraphLogicalTime::new(10);
        let first = EventNode::new("process_exec", "source-record:a", observed_at).unwrap();
        let retry = EventNode::new("process_exec", "source-record:a", observed_at).unwrap();
        let distinct = EventNode::new("process_exec", "source-record:b", observed_at).unwrap();

        assert_eq!(first.node_id, retry.node_id);
        assert_ne!(first.node_id, distinct.node_id);

        let mut graph =
            HypothesisGraph::new(GraphId::new("graph:event-identity"), Default::default()).unwrap();
        graph.admit_node(GraphNode::Event(first)).unwrap();
        let retry_bytes = serde_json::to_vec(&graph).unwrap();
        graph.admit_node(GraphNode::Event(retry)).unwrap();
        assert_eq!(serde_json::to_vec(&graph).unwrap(), retry_bytes);
        graph.admit_node(GraphNode::Event(distinct)).unwrap();
        assert_eq!(graph.nodes.len(), 2);
    }

    #[test]
    fn unsigned_witness_is_untrusted() {
        let unsigned = EvidenceEnvelope::new(
            EvidenceSourceFamily::Process,
            "unsigned-record",
            SourceLineage::new("fixture", "unsigned-record").unwrap(),
            EvidenceClock::observed(GraphLogicalTime::new(10)),
            OrderingClaim::Unknown,
            TypedEvidencePayload::Signal {
                signal_kind: "unsigned".to_string(),
                entity_ids: vec![GraphNodeId::new("node:event:unsigned")],
                relation_ids: vec![],
                supports: vec![],
                refutes: vec![],
                content_digest: "digest:unsigned".to_string(),
            },
        )
        .unwrap();
        assert_eq!(unsigned.witness.scoped_agent_id, "unsigned");
        assert!(unsigned.validate().is_err());

        let mut graph =
            HypothesisGraph::new(GraphId::new("graph:unsigned"), Default::default()).unwrap();
        let before = serde_json::to_vec(&graph).unwrap();
        assert!(graph.admit_evidence(unsigned).is_err());
        assert_eq!(serde_json::to_vec(&graph).unwrap(), before);
    }

    #[test]
    fn typed_evidence_payload_direct_deserialize_is_validated() {
        let valid_signal = serde_json::json!({
            "kind": "signal",
            "signal_kind": "seed",
            "entity_ids": ["node:event:seed"],
            "relation_ids": [],
            "supports": [],
            "refutes": [],
            "content_digest": "digest:seed"
        });
        assert!(serde_json::from_value::<TypedEvidencePayload>(valid_signal.clone()).is_ok());

        let mut malformed_entity = valid_signal.clone();
        malformed_entity["entity_ids"] = serde_json::json!([""]);
        assert!(serde_json::from_value::<TypedEvidencePayload>(malformed_entity).is_err());

        let mut empty_digest = valid_signal.clone();
        empty_digest["content_digest"] = serde_json::json!("");
        assert!(serde_json::from_value::<TypedEvidencePayload>(empty_digest).is_err());

        let mut oversized_digest = valid_signal.clone();
        oversized_digest["content_digest"] = serde_json::json!("x".repeat(129));
        assert!(serde_json::from_value::<TypedEvidencePayload>(oversized_digest).is_err());

        let family_mismatch = EvidenceEnvelope::new(
            EvidenceSourceFamily::Identity,
            "family-mismatch",
            SourceLineage::new("fixture", "family-mismatch").unwrap(),
            EvidenceClock::observed(GraphLogicalTime::new(10)),
            OrderingClaim::Unknown,
            serde_json::from_value::<TypedEvidencePayload>(valid_signal).unwrap(),
        )
        .unwrap();
        assert!(family_mismatch.validate().is_err());

        let threat = serde_json::json!({
            "kind": "threat_intelligence",
            "signal_kind": "intel",
            "feed_id": "feed:test",
            "indicator_digest": "digest:indicator",
            "indicator_kind": "domain",
            "confidence_basis_points": 10_001,
            "expires_at": 100,
            "entity_ids": [],
            "content_digest": "digest:intel"
        });
        assert!(serde_json::from_value::<TypedEvidencePayload>(threat).is_err());

        let expired = serde_json::json!({
            "kind": "threat_intelligence",
            "signal_kind": "intel",
            "feed_id": "feed:test",
            "indicator_digest": "digest:indicator",
            "indicator_kind": "domain",
            "confidence_basis_points": 9_000,
            "expires_at": -1,
            "entity_ids": [],
            "content_digest": "digest:intel"
        });
        assert!(serde_json::from_value::<TypedEvidencePayload>(expired).is_err());
    }

    #[test]
    fn graph_version_overflow_is_fail_closed() {
        let mut graph = HypothesisGraph::new(
            GraphId::new("graph:version-overflow"),
            GraphResourceLimits::default(),
        )
        .unwrap();
        graph.version = u64::MAX;
        let before = serde_json::to_vec(&graph).unwrap();
        let result = graph.admit_node(GraphNode::Actor(
            ActorNode::new("actor:version-overflow", "test").unwrap(),
        ));
        assert!(matches!(
            result,
            Err(GraphAdmissionError::InvalidTransition { .. })
        ));
        assert_eq!(serde_json::to_vec(&graph).unwrap(), before);
        assert!(graph.nodes.is_empty());
    }

    #[test]
    fn review_regressions_reject_invalid_time_claim_scheduler_and_parent() {
        assert!(EventNode::new("negative", "source:negative", GraphLogicalTime::new(-1)).is_err());
        let first =
            EventNode::new("same-time", "source-record:a", GraphLogicalTime::new(10)).unwrap();
        let second =
            EventNode::new("same-time", "source-record:b", GraphLogicalTime::new(10)).unwrap();
        assert_ne!(first.node_id, second.node_id);

        assert!(serde_json::from_str::<TypedEvidencePayload>(
            r#"{"kind":"process","signal_kind":"","process_digest":"digest","parent_process_digest":null,"entity_ids":[],"content_digest":"digest"}"#
        )
        .is_err());

        let mut exhausted = HypothesisGraph::new(
            GraphId::new("graph:version-exhausted"),
            GraphResourceLimits::default(),
        )
        .unwrap();
        exhausted.version = u64::MAX;
        assert!(matches!(
            exhausted.admit_node(GraphNode::Actor(
                ActorNode::new("actor:version-exhausted", "test",).unwrap()
            )),
            Err(GraphAdmissionError::InvalidTransition { .. })
        ));
        assert!(exhausted.nodes.is_empty());

        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:review")],
            [GraphNodeId::new("node:event:review")],
        )
        .unwrap();
        assert!(
            TaskClaimRequest::new(
                TaskId::new("task:review"),
                TaskKind::AcquireEvidence,
                TaskTarget::Evidence {
                    evidence_id: EvidenceId::new("evidence:review"),
                },
                GraphProducerRole::Hunter,
                AgentId::new("", ""),
                scope.clone(),
                GraphLogicalTime::new(-1),
            )
            .is_err()
        );
        assert!(
            TaskClaimRequest::new(
                TaskId::new("task:review"),
                TaskKind::AcquireEvidence,
                TaskTarget::Evidence {
                    evidence_id: EvidenceId::new("evidence:review"),
                },
                GraphProducerRole::Challenger,
                AgentId::new("hunter", "review"),
                scope,
                GraphLogicalTime::new(1),
            )
            .is_err()
        );
        assert!(
            GraphSchedulerKey::new(
                GraphLogicalTime::new(-1),
                TaskKind::AcquireEvidence,
                1,
                TaskId::new("task:review"),
            )
            .is_err()
        );
        assert!(
            GraphSchedulerKey::new(
                GraphLogicalTime::new(1),
                TaskKind::AcquireEvidence,
                1,
                TaskId::new(""),
            )
            .is_err()
        );

        let process_parent =
            GraphNode::Process(ProcessNode::new("parent", "parent-executable").unwrap());
        let child = GraphNode::Process(
            ProcessNode::new_with_parent("child", "child-executable", process_parent.id().clone())
                .unwrap(),
        );
        let mut graph =
            HypothesisGraph::new(GraphId::new("graph:review"), Default::default()).unwrap();
        assert!(matches!(
            graph.admit_node(child),
            Err(GraphAdmissionError::UnknownNode { .. })
        ));
        graph.admit_node(process_parent).unwrap();
    }

    #[test]
    fn review_regressions_require_terminal_fence_proof_on_persisted_tasks() {
        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:task-proof")],
            [GraphNodeId::new("node:event:task-proof")],
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            TaskId::new("task:proof"),
            TaskKind::AcquireEvidence,
            TaskTarget::Evidence {
                evidence_id: EvidenceId::new("evidence:task-proof"),
            },
            GraphProducerRole::Hunter,
            AgentId::new("hunter", "proof"),
            scope,
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let lease = TaskLease::new(
            LeaseId::new("lease:proof"),
            request.claimant.clone(),
            GraphLogicalTime::new(10),
            GraphLogicalTime::new(20),
            FencingToken::new(7),
        )
        .unwrap();
        let task = TaskRecord::claimed(request, lease).unwrap();
        let completion = TaskCompletion::new(
            TaskCompletionKind::NoFinding,
            AgentId::new("hunter", "proof"),
            GraphLogicalTime::new(15),
            [],
            "digest",
        )
        .unwrap();
        let completed = task
            .complete(completion, FencingToken::new(7), 100)
            .unwrap();
        assert!(completed.validate_with_limits(100, 3).is_ok());

        let mut forged = serde_json::to_value(&completed).unwrap();
        forged["terminal_history"] = serde_json::json!([]);
        assert!(serde_json::from_value::<TaskRecord>(forged).is_err());

        let mut forged_proof = serde_json::to_value(&completed).unwrap();
        forged_proof["terminal_history"][0]["fencing_token"] = serde_json::json!(999);
        assert!(serde_json::from_value::<TaskRecord>(forged_proof).is_err());
    }

    #[test]
    fn review_regressions_validate_kill_chain_predecessors_order_and_containment_rank() {
        let claim = KillChainClaim::new(
            KillChainStage::Execution,
            [GraphNodeId::new("node:process:review")],
            [EdgeId::new("edge:review")],
            [EvidenceId::new("evidence:review")],
            [],
            "execution",
            [EvidenceId::new("evidence:review")],
        )
        .unwrap();
        let unknown_predecessor = KillChainClaim::new(
            KillChainStage::CredentialAccess,
            [GraphNodeId::new("node:credential:review")],
            [EdgeId::new("edge:credential-review")],
            [EvidenceId::new("evidence:review")],
            [KillChainClaimId::new("kill-chain:missing")],
            "credential access",
            [EvidenceId::new("evidence:review")],
        )
        .unwrap();
        assert!(KillChainReconstruction::new([claim.clone(), unknown_predecessor], []).is_err());
        assert!(claim.clone().with_order(KillChainOrder::Unknown).is_ok());
        assert!(claim.with_order(KillChainOrder::Partial).is_err());

        let first = ContainmentOption::new(
            ContainmentOptionKind::IsolateAsset,
            [GraphNodeId::new("node:asset:first")],
            100,
            9_000,
            8_000,
            ApprovalClass::Operator,
            true,
        )
        .unwrap();
        let second = ContainmentOption::new(
            ContainmentOptionKind::RestrictNetwork,
            [GraphNodeId::new("node:asset:second")],
            200,
            8_000,
            7_000,
            ApprovalClass::Operator,
            true,
        )
        .unwrap();
        let mut simulation =
            ContainmentSimulation::new(GraphId::new("graph:review"), [first, second]).unwrap();
        simulation.options.swap(0, 1);
        assert!(simulation.validate().is_err());
    }

    #[test]
    fn review_regressions_require_signed_memory_and_reject_direct_tampered_deserialization() {
        let unsigned_provenance = MemoryProvenance::new(
            AgentId::new("hunter", "forgeable"),
            [EvidenceId::new("evidence:review")],
        );
        assert!(
            StrategyMemory::new(
                GraphId::new("graph:review"),
                HypothesisId::new("hypothesis:review"),
                HypothesisDelta::new([EdgeId::new("edge:review")], [], []),
                [EvidenceUtility::new(
                    EvidenceId::new("evidence:review"),
                    5_000,
                )],
                [],
                MemoryOutcome::Confirmed,
                unsigned_provenance,
            )
            .is_err()
        );
        let provenance =
            MemoryProvenance::new(signer_identity(), [EvidenceId::new("evidence:review")])
                .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-review")
                .unwrap();
        let memory = StrategyMemory::new(
            GraphId::new("graph:review"),
            HypothesisId::new("hypothesis:review"),
            HypothesisDelta::new([EdgeId::new("edge:review")], [], []),
            [EvidenceUtility::new(
                EvidenceId::new("evidence:review"),
                5_000,
            )],
            [],
            MemoryOutcome::Confirmed,
            provenance,
        )
        .unwrap()
        .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-review")
        .unwrap();
        let mut tampered = serde_json::to_value(&memory).unwrap();
        tampered["graph_id"] = serde_json::json!("graph:tampered");
        assert!(serde_json::from_value::<StrategyMemory>(tampered).is_err());
    }

    #[test]
    fn review_regressions_preserve_non_default_nested_limits_and_reject_unauthorized_decisions() {
        let from = GraphNodeId::new("node:process:custom-limits");
        let to = GraphNodeId::new("node:event:custom-limits");
        let evidence_ids = (0..9)
            .map(|index| EvidenceId::new(format!("evidence:custom:{index}")))
            .collect::<Vec<_>>();
        let edge = CausalEdge::new(
            &from,
            &to,
            CausalRelation::ObservedIn,
            5_000,
            evidence_ids,
            GraphProducerRole::Hunter,
            signer_identity(),
            GraphLogicalTime::new(10),
            EdgeState::Proposed,
        )
        .expect("edge with nine evidence references")
        .signed_with(&signer(), "hunter-custom-limits")
        .expect("signed edge");
        let edge_json = serde_json::to_string(&edge).expect("serialize edge");
        let reloaded_edge: CausalEdge =
            serde_json::from_str(&edge_json).expect("standalone edge reload uses wire ceiling");
        assert_eq!(reloaded_edge, edge);
        assert!(edge.validate(&GraphResourceLimits::default()).is_err());
        let edge_limits = GraphResourceLimits {
            max_evidence_references_per_edge: 9,
            ..GraphResourceLimits::default()
        };
        assert!(edge.validate(&edge_limits).is_ok());

        let lease = TaskLease::new(
            LeaseId::new("lease:custom-limits"),
            AgentId::new("hunter", "custom-limits"),
            GraphLogicalTime::new(0),
            GraphLogicalTime::new(400_000),
            FencingToken::new(1),
        )
        .expect("lease beyond the default runtime bound");
        let lease_json = serde_json::to_string(&lease).expect("serialize lease");
        let reloaded_lease: TaskLease =
            serde_json::from_str(&lease_json).expect("standalone lease reload uses wire ceiling");
        assert_eq!(reloaded_lease, lease);
        assert!(
            lease
                .validate_with_limit(GraphResourceLimits::default().max_task_lease_ms)
                .is_err()
        );
        let lease_limits = GraphResourceLimits {
            max_task_lease_ms: 400_000,
            ..GraphResourceLimits::default()
        };
        assert!(
            lease
                .validate_with_limit(lease_limits.max_task_lease_ms)
                .is_ok()
        );

        let hypothesis = Hypothesis::new(
            HypothesisId::new("hypothesis:custom-limits"),
            ConfidenceDistribution::uniform_two(),
            [],
            [],
        )
        .expect("hypothesis")
        .with_claims((0..513).map(|index| EdgeId::new(format!("edge:custom-limit:{index}"))));
        let hypothesis_json = serde_json::to_string(&hypothesis).expect("serialize hypothesis");
        let reloaded_hypothesis: Hypothesis = serde_json::from_str(&hypothesis_json)
            .expect("standalone hypothesis reload uses wire ceiling");
        assert_eq!(reloaded_hypothesis, hypothesis);
        assert!(
            hypothesis
                .validate(&GraphResourceLimits::default())
                .is_err()
        );
        let hypothesis_limits = GraphResourceLimits {
            max_edges: 513,
            ..GraphResourceLimits::default()
        };
        assert!(hypothesis.validate(&hypothesis_limits).is_ok());

        for kind in [
            DecisionKind::Challenge,
            DecisionKind::Falsify,
            DecisionKind::Adjudicate,
            DecisionKind::Reopen,
        ] {
            assert!(
                DecisionRecord::new(
                    kind,
                    HypothesisId::new("hypothesis:role-matrix"),
                    [EvidenceId::new("evidence:role-matrix")],
                    GraphProducerRole::Hunter,
                    AgentId::new("hunter", "role-matrix"),
                    GraphLogicalTime::new(1),
                    "unauthorized hunter decision",
                )
                .is_err()
            );
        }

        let valid_roles = [
            (DecisionKind::Support, GraphProducerRole::Hunter),
            (DecisionKind::Challenge, GraphProducerRole::Challenger),
            (DecisionKind::Falsify, GraphProducerRole::Falsifier),
            (DecisionKind::Adjudicate, GraphProducerRole::Adjudicator),
            (DecisionKind::Reopen, GraphProducerRole::Adjudicator),
        ];
        for (kind, role) in valid_roles {
            let mut decision = DecisionRecord::new(
                kind,
                HypothesisId::new("hypothesis:role-matrix-valid"),
                [EvidenceId::new("evidence:role-matrix")],
                role,
                AgentId::new("role", "matrix"),
                GraphLogicalTime::new(1),
                "authorized decision",
            )
            .expect("authorized decision role");
            if kind == DecisionKind::Adjudicate {
                decision = decision
                    .with_resulting_status(HypothesisStatus::Selected)
                    .expect("adjudication status");
            }
            let decision = decision
                .signed_with(&signer(), "role-matrix")
                .expect("signed authorized decision");
            assert!(decision.validate().is_ok());
        }
    }

    #[test]
    fn post_plan03_task_identity_lineage_and_capability_are_strict() {
        let graph_id = GraphId::new("graph:post-plan03");
        let seed_digest = canonical_digest(&"seed").unwrap();
        let other_seed_digest = canonical_digest(&"other-seed").unwrap();
        let claim_digest = canonical_digest(&"claim").unwrap();
        let target = TaskTarget::Edge {
            edge_id: EdgeId::new("edge:challenge"),
        };
        let logical =
            derive_logical_task_id(&graph_id, &target, TaskKind::ChallengeEdge, &seed_digest)
                .expect("logical task id");
        assert_eq!(
            logical,
            derive_logical_task_id(&graph_id, &target, TaskKind::ChallengeEdge, &seed_digest)
                .unwrap()
        );
        assert_ne!(
            logical,
            derive_logical_task_id(
                &graph_id,
                &target,
                TaskKind::ChallengeEdge,
                &other_seed_digest
            )
            .unwrap()
        );
        assert!(
            derive_logical_task_id(&graph_id, &target, TaskKind::ChallengeEdge, "seed:digest")
                .is_err()
        );

        let signer = signer();
        let claimant = signer_identity();
        let capability = TaskCapabilityProof::signed_with(
            logical.clone(),
            claimant.clone(),
            GraphProducerRole::Challenger,
            TaskKind::ChallengeEdge,
            claim_digest,
            &signer,
            "challenger-a",
        )
        .expect("capability proof");
        assert!(capability.validate().is_ok());

        let link = TaskDecisionLink::new(
            logical.clone(),
            target.clone(),
            [EvidenceId::new("evidence:challenge")],
            Some(DecisionId::new("decision:challenge")),
        )
        .expect("decision lineage");
        let completion = TaskCompletion::new(
            TaskCompletionKind::EdgeChallenged,
            claimant.clone(),
            GraphLogicalTime::new(10),
            [EvidenceId::new("evidence:challenge")],
            "summary:challenge",
        )
        .unwrap();
        let envelope = TaskTerminalEnvelope::new(
            logical,
            IdempotencyKey::new("idempotency:claim"),
            LeaseId::new("lease:challenge"),
            FencingToken::new(1),
            completion,
            Some(link),
            claimant,
            capability,
        )
        .expect("terminal envelope");
        assert!(envelope.validate().is_ok());

        let mut forged = envelope.clone();
        forged.completion.kind = TaskCompletionKind::EvidenceAdded;
        assert!(forged.validate().is_err());
        forged = envelope;
        forged.producer = AgentId::new("other", "producer");
        assert!(forged.validate().is_err());

        let mut forged_scope = TaskCapabilityProof::signed_with(
            TaskId::new("task:scope"),
            signer_identity(),
            GraphProducerRole::Challenger,
            TaskKind::ChallengeEdge,
            canonical_digest(&"scope-claim").unwrap(),
            &signer,
            "scope-a",
        )
        .unwrap();
        forged_scope.witness.scoped_agent_id = "scope-b".to_string();
        assert!(forged_scope.validate().is_err());
    }

    #[test]
    fn terminal_signature_binds_exact_claim_lease_and_lineage() {
        let signer = signer();
        let claimant = signer_identity();
        let scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:terminal")],
            [GraphNodeId::new("node:event:terminal")],
        )
        .unwrap();
        let request = TaskClaimRequest::new(
            TaskId::new("task:terminal"),
            TaskKind::AcquireEvidence,
            TaskTarget::Evidence {
                evidence_id: EvidenceId::new("evidence:terminal"),
            },
            GraphProducerRole::Hunter,
            claimant.clone(),
            scope,
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let lease = TaskLease::new(
            LeaseId::new("lease:terminal"),
            claimant.clone(),
            GraphLogicalTime::new(10),
            GraphLogicalTime::new(20),
            FencingToken::new(1),
        )
        .unwrap();
        let task = TaskRecord::claimed(request.clone(), lease.clone()).unwrap();
        let capability = TaskCapabilityProof::new(
            request.task_id.clone(),
            claimant.clone(),
            request.role,
            request.kind,
            request.canonical_digest().unwrap(),
            &signer,
            "hunter-terminal",
        )
        .unwrap();
        let completion = TaskCompletion::new(
            TaskCompletionKind::NoFinding,
            claimant.clone(),
            GraphLogicalTime::new(15),
            [],
            "digest:terminal",
        )
        .unwrap();
        let unsigned = TaskTerminalEnvelope::new(
            request.task_id.clone(),
            request.idempotency_key.clone(),
            lease.lease_id.clone(),
            lease.fencing_token,
            completion,
            None,
            claimant.clone(),
            capability,
        )
        .unwrap();
        assert!(unsigned.validate().is_ok());
        assert!(unsigned.validate_for_task(&task, 100, 3).is_err());

        let signed = unsigned
            .clone()
            .signed_with(&signer, "terminal-worker")
            .unwrap();
        assert!(signed.validate_for_task(&task, 100, 3).is_ok());
        let other_signer = Keypair::from_seed(&[8_u8; 32]);
        assert!(
            signed
                .clone()
                .signed_with(&other_signer, "attacker")
                .is_err()
        );

        let mut changed = signed.clone();
        changed.completion.summary_digest = "digest:changed".to_string();
        assert!(changed.validate_for_task(&task, 100, 3).is_err());

        let mut changed = signed.clone();
        changed.terminal_witness.as_mut().unwrap().scoped_agent_id =
            "terminal-attacker".to_string();
        assert!(changed.validate_for_task(&task, 100, 3).is_err());

        let mut changed = signed.clone();
        changed.lease_id = LeaseId::new("lease:attacker");
        assert!(changed.validate_for_task(&task, 100, 3).is_err());

        let mut changed = signed.clone();
        changed.fencing_token = FencingToken::new(2);
        assert!(changed.validate_for_task(&task, 100, 3).is_err());

        let mut changed = signed.clone();
        changed.idempotency_key = IdempotencyKey::new("idempotency:attacker");
        assert!(changed.validate_for_task(&task, 100, 3).is_err());

        let mut invalid_task = task.clone();
        invalid_task.attempts = 4;
        assert!(signed.validate_for_task(&invalid_task, 100, 3).is_err());
        let mut invalid_task = task.clone();
        invalid_task.generation = 2;
        assert!(signed.validate_for_task(&invalid_task, 100, 3).is_err());

        let challenge_scope = EvidenceScope::new(
            [EvidenceSourceFamily::Process],
            [EvidenceId::new("evidence:challenge-terminal")],
            [],
        )
        .unwrap();
        let challenge_request = TaskClaimRequest::new(
            TaskId::new("task:challenge-terminal"),
            TaskKind::ChallengeEdge,
            TaskTarget::Edge {
                edge_id: EdgeId::new("edge:claimed"),
            },
            GraphProducerRole::Challenger,
            claimant.clone(),
            challenge_scope,
            GraphLogicalTime::new(10),
        )
        .unwrap();
        let challenge_lease = TaskLease::new(
            LeaseId::new("lease:challenge-terminal"),
            claimant.clone(),
            GraphLogicalTime::new(10),
            GraphLogicalTime::new(20),
            FencingToken::new(2),
        )
        .unwrap();
        let challenge_task =
            TaskRecord::claimed(challenge_request.clone(), challenge_lease.clone()).unwrap();
        let challenge_capability = TaskCapabilityProof::new(
            challenge_request.task_id.clone(),
            claimant.clone(),
            challenge_request.role,
            challenge_request.kind,
            challenge_request.canonical_digest().unwrap(),
            &signer,
            "challenger-terminal",
        )
        .unwrap();
        let challenge_completion = TaskCompletion::new(
            TaskCompletionKind::EdgeChallenged,
            claimant.clone(),
            GraphLogicalTime::new(15),
            [EvidenceId::new("evidence:challenge-terminal")],
            "digest:challenge-terminal",
        )
        .unwrap();
        let wrong_lineage = TaskDecisionLink::new(
            challenge_request.task_id.clone(),
            TaskTarget::Edge {
                edge_id: EdgeId::new("edge:attacker-selected"),
            },
            [EvidenceId::new("evidence:challenge-terminal")],
            Some(DecisionId::new("decision:challenge-terminal")),
        )
        .unwrap();
        let wrong_lineage = TaskTerminalEnvelope::new(
            challenge_request.task_id,
            challenge_request.idempotency_key,
            challenge_lease.lease_id,
            challenge_lease.fencing_token,
            challenge_completion,
            Some(wrong_lineage),
            claimant,
            challenge_capability,
        )
        .unwrap()
        .signed_with(&signer, "challenger-terminal")
        .unwrap();
        assert!(
            wrong_lineage
                .validate_for_task(&challenge_task, 100, 3)
                .is_err()
        );
    }

    #[test]
    fn policy_contract_digest_and_behavior_are_mode_bound() {
        let evidence_first = GraphPolicyContract::new(GraphPolicyMode::EvidenceFirst).unwrap();
        let challenge = GraphPolicyContract::new(GraphPolicyMode::ChallengeContradictions).unwrap();
        let containment =
            GraphPolicyContract::new(GraphPolicyMode::ConservativeContainment).unwrap();

        assert_ne!(evidence_first.policy_digest, challenge.policy_digest);
        assert_ne!(challenge.policy_digest, containment.policy_digest);
        assert!(evidence_first.requires_evidence_coverage());
        assert!(!evidence_first.emits_falsification_work());
        assert!(challenge.emits_falsification_work());
        assert!(challenge.retains_alternatives());
        assert!(containment.requires_reversible_containment());

        let encoded = serde_json::to_value(&evidence_first).unwrap();
        assert_eq!(
            serde_json::from_value::<GraphPolicyContract>(encoded.clone()).unwrap(),
            evidence_first
        );
        let mut tampered = encoded;
        tampered["mode"] = serde_json::json!("challenge_contradictions");
        assert!(serde_json::from_value::<GraphPolicyContract>(tampered).is_err());
        assert!(serde_json::from_str::<GraphPolicyContract>(
            r#"{"schema_version":1,"mode":"future_mode","policy_digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#
        )
        .is_err());
    }

    #[test]
    fn scheduler_dispatch_is_ready_priority_kind_and_id_deterministic() {
        let low = GraphSchedulerKey::new(
            GraphLogicalTime::new(5),
            TaskKind::ChallengeEdge,
            1_000,
            TaskId::new("task:b"),
        )
        .unwrap();
        let high = GraphSchedulerKey::new(
            GraphLogicalTime::new(5),
            TaskKind::AcquireEvidence,
            9_000,
            TaskId::new("task:z"),
        )
        .unwrap();
        assert!(high.dispatches_before(&low));
        assert_eq!(
            high.dispatch_order_key(),
            (5, std::cmp::Reverse(9_000), 0, "task:z".to_string())
        );

        let config = crate::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..Default::default()
        };
        let mut budget = SchedulerBudget::new(&config, GraphLogicalTime::new(0)).unwrap();
        budget.admit(&config, 6, 1).unwrap();
        assert!(budget.admit(&config, 5, 1).is_err());
        assert!(budget.admit(&config, 1, 2).is_err());
        let encoded = serde_json::to_vec(&budget).unwrap();
        let mut decoded = SchedulerBudget::deserialize_with_config(
            std::str::from_utf8(&encoded).unwrap(),
            &config,
        )
        .unwrap();
        assert_eq!(decoded, budget);
        assert!(
            decoded
                .admit_at(&config, GraphLogicalTime::new(0), 5, 1)
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
        assert!(
            decoded
                .admit_at(&config, GraphLogicalTime::new(1), 10, 2)
                .is_ok()
        );
        assert_eq!(decoded.current_tick(), GraphLogicalTime::new(1));
        assert!(
            decoded
                .admit_at(&config, GraphLogicalTime::new(0), 0, 0)
                .is_err()
        );
    }

    #[test]
    fn deployment_limits_bind_scheduler_and_memory_expiry() {
        let config = crate::config::HypothesisGraphConfig {
            max_work_units_per_tick: 10,
            max_claims_per_tick: 2,
            ..Default::default()
        };
        let budget = SchedulerBudget::new_with_config(&config, GraphLogicalTime::new(1)).unwrap();
        assert!(budget.validate_with_limits(10, 2).is_ok());
        assert!(budget.validate_with_limits(9, 2).is_err());
        assert!(budget.validate_with_limits(10, 1).is_err());
        let widened_config = crate::config::HypothesisGraphConfig {
            max_work_units_per_tick: 11,
            max_claims_per_tick: 2,
            ..Default::default()
        };
        let widened =
            SchedulerBudget::new_with_config(&widened_config, GraphLogicalTime::new(1)).unwrap();
        assert!(widened.validate_with_limits(10, 2).is_err());

        let provenance =
            MemoryProvenance::new(signer_identity(), [EvidenceId::new("evidence:limit")])
                .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-limit")
                .unwrap();
        let memory = StrategyMemory::new(
            GraphId::new("graph:limit"),
            HypothesisId::new("hypothesis:limit"),
            HypothesisDelta::new([], [], []),
            [EvidenceUtility::new(
                EvidenceId::new("evidence:limit"),
                5_000,
            )],
            [],
            MemoryOutcome::Confirmed,
            provenance,
        )
        .unwrap()
        .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-limit")
        .unwrap();
        let expiry = StrategyMemoryExpiryEnvelope::new_with_limit(
            &memory,
            GraphLogicalTime::new(100),
            5,
            5,
            &signer(),
        )
        .unwrap();
        assert!(expiry.is_applicable_at_with_limit(GraphLogicalTime::new(104), 5));
        assert!(!expiry.is_applicable_at_with_limit(GraphLogicalTime::new(105), 5));
        assert!(!expiry.is_applicable_at_with_limit(GraphLogicalTime::new(104), 4));
        let config = crate::config::HypothesisGraphConfig {
            max_memory_ttl_ticks: 5,
            ..Default::default()
        };
        assert!(expiry.is_applicable_at(GraphLogicalTime::new(104), &config));
        let mut narrower = config.clone();
        narrower.max_memory_ttl_ticks = 4;
        assert!(!expiry.is_applicable_at(GraphLogicalTime::new(104), &narrower));
        let encoded = serde_json::to_string(&expiry).unwrap();
        assert!(StrategyMemoryExpiryEnvelope::deserialize_with_config(&encoded, &config).is_ok());
        assert!(
            StrategyMemoryExpiryEnvelope::deserialize_with_config(&encoded, &narrower).is_err()
        );
        assert!(expiry.validate_with_limit(4).is_err());
    }

    #[test]
    fn strategy_memory_expiry_is_signed_and_logical() {
        let provenance =
            MemoryProvenance::new(signer_identity(), [EvidenceId::new("evidence:ttl")])
                .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-ttl")
                .unwrap();
        let memory = StrategyMemory::new(
            GraphId::new("graph:ttl"),
            HypothesisId::new("hypothesis:ttl"),
            HypothesisDelta::new([], [], []),
            [EvidenceUtility::new(EvidenceId::new("evidence:ttl"), 5_000)],
            [],
            MemoryOutcome::Confirmed,
            provenance,
        )
        .unwrap()
        .signed_with(&signer(), GraphProducerRole::Hunter, "hunter-ttl")
        .unwrap();
        let config = crate::config::HypothesisGraphConfig {
            max_memory_ttl_ticks: 10,
            ..Default::default()
        };
        let expiry = StrategyMemoryExpiryEnvelope::new(
            &memory,
            GraphLogicalTime::new(100),
            10,
            &config,
            &signer(),
        )
        .unwrap();
        assert!(expiry.is_applicable_at(GraphLogicalTime::new(100), &config));
        assert!(expiry.is_applicable_at(GraphLogicalTime::new(109), &config));
        assert!(!expiry.is_applicable_at(GraphLogicalTime::new(110), &config));
        assert!(expiry.validate().is_ok());

        let mut forged = expiry.clone();
        forged.memory_digest = "digest:forged".to_string();
        assert!(!forged.is_applicable_at(GraphLogicalTime::new(101), &config));
        assert!(forged.validate().is_err());
        let mut unknown = expiry;
        unknown.schema_version = STRATEGY_MEMORY_EXPIRY_SCHEMA_VERSION + 1;
        assert!(unknown.validate().is_err());
    }
}
