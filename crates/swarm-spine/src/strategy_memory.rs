//! Signed, append-only, privacy-minimized strategy memory.
//!
//! `StrategyMemory` is a core contract made only from graph IDs, bounded
//! evidence utility, hypothesis deltas, outcomes, and signed provenance.  The
//! store never accepts a telemetry event, command line, request object, or
//! arbitrary JSON value.  It adds a second store-owned generation signature so
//! a restart validates both the producer witness and the persistence chain.

#[cfg(test)]
use crate::hypothesis_graph_store::{
    CommitFailureBoundary, install_test_commit_failure, install_test_persisted_json_limit,
    install_test_rotation_failure, maybe_fail_commit,
};
use crate::hypothesis_graph_store::{
    DurableFileLock, DurableMonotonicAnchor, DurableStateHead, ExternalCommitPhase,
    GRAPH_STORE_HIGH_WATER_FILE, GRAPH_STORE_HIGH_WATER_TAIL_FILE, GraphStoreError,
    GraphStoreRevision, append_high_water, clear_transaction_stage, persisted_json_limit,
    prepare_private_store_root, read_high_water, reconcile_state_head, recover_external_journal,
    sign_external_commit_record, sign_state_head, stage_transaction,
    validate_external_journal_against_state, validate_high_water_against_revisions,
    verify_external_journal, verify_state_head,
};
#[cfg(test)]
use crate::hypothesis_graph_store::{atomic_write_json, read_json_file};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use swarm_core::config::HypothesisGraphConfig;
use swarm_core::hypothesis_graph::{
    EvidenceId, GraphAdmissionError, GraphId, GraphLogicalTime, GraphResourceLimits, HypothesisId,
    MAX_STRATEGY_MEMORY_TTL_TICKS, StrategyMemory, StrategyMemoryExpiryEnvelope,
    StrategyMemoryMatch,
};
use swarm_crypto::{
    DetachedSignature, Keypair, canonical_json_bytes, sha256_hex, verify_detached_signature,
};

const MAX_STRATEGY_MEMORY_LIST_LIMIT: usize = 4_096;

pub const STRATEGY_MEMORY_STORE_SCHEMA_VERSION: u32 = 1;
pub const STRATEGY_MEMORY_STATE_KIND: &str = "collective_strategy_memory";
pub const STRATEGY_MEMORY_STATE_FILE: &str = "state.json";
pub const STRATEGY_MEMORY_LOCK_FILE: &str = "state.lock";
pub const STRATEGY_MEMORY_ANCHOR_FILE: &str = "state.head";
pub const STRATEGY_MEMORY_HIGH_WATER_FILE: &str = GRAPH_STORE_HIGH_WATER_FILE;
pub const STRATEGY_MEMORY_HIGH_WATER_TAIL_FILE: &str = GRAPH_STORE_HIGH_WATER_TAIL_FILE;

fn validate_max_memory_ttl_ticks(
    max_memory_ttl_ticks: u64,
) -> Result<(), StrategyMemoryStoreError> {
    if max_memory_ttl_ticks == 0 || max_memory_ttl_ticks > MAX_STRATEGY_MEMORY_TTL_TICKS {
        return Err(StrategyMemoryStoreError::Admission(
            GraphAdmissionError::InvalidLimit {
                field: "max_memory_ttl_ticks".to_string(),
                reason: format!("must be between 1 and {MAX_STRATEGY_MEMORY_TTL_TICKS}"),
            },
        ));
    }
    Ok(())
}

fn validate_expiry_for(
    memory: &StrategyMemory,
    envelope: &StrategyMemoryExpiryEnvelope,
    max_memory_ttl_ticks: u64,
) -> Result<(), StrategyMemoryStoreError> {
    memory
        .validate()
        .map_err(StrategyMemoryStoreError::Admission)?;
    envelope
        .validate_with_limit(max_memory_ttl_ticks)
        .map_err(StrategyMemoryStoreError::Admission)?;
    let memory_digest = canonical_json_bytes(memory)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| StrategyMemoryStoreError::Canonicalization {
            reason: error.to_string(),
        })?;
    if envelope.memory_id != memory.memory_id || envelope.memory_digest != memory_digest {
        return Err(StrategyMemoryStoreError::InvalidState {
            reason: "memory expiry sidecar does not bind its memory record".to_string(),
        });
    }
    Ok(())
}

/// The expiry envelope is deliberately kept out of `StrategyMemoryRecord` so
/// the historical memory wire bytes remain unchanged.  It is persisted in a
/// state-owned sidecar map instead.
pub type StrategyMemoryExpiryRecord = StrategyMemoryExpiryEnvelope;

fn strategy_memory_stream_id(path: &Path) -> String {
    let normalized = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    format!(
        "strategy-memory:{}",
        sha256_hex(normalized.to_string_lossy().as_bytes())
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyMemoryRecord {
    pub schema_version: u32,
    pub memory: StrategyMemory,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<String>,
    pub digest: String,
    pub store_signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyMemoryAppendResult {
    pub record: StrategyMemoryRecord,
    pub idempotent: bool,
    pub generation: u64,
}

pub type MemoryAppendResult = StrategyMemoryAppendResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrievedStrategyMemory {
    pub record: StrategyMemoryRecord,
    pub matched: StrategyMemoryMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryState {
    schema_version: u32,
    limits: GraphResourceLimits,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_digest: Option<String>,
    /// Digest of the last record removed by expiry-prefix compaction.  This
    /// preserves the signed append chain without retaining expired payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_chain_prefix_digest: Option<String>,
    memories: BTreeMap<String, StrategyMemoryRecord>,
    order: Vec<String>,
    /// Versioned logical-time sidecars keyed by the unchanged memory ID.
    /// Missing entries are legacy/quarantined and are never returned by the
    /// logical-time retrieval path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    expiry_envelopes: BTreeMap<String, StrategyMemoryExpiryEnvelope>,
    /// The deployment TTL ceiling is absent from historical Plan 03 state.
    /// Keeping it optional lets the exact legacy canonical bytes verify before
    /// an explicit append migrates the state to the configured ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_memory_ttl_ticks: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedStrategyMemoryState {
    state: StrategyMemoryState,
    digest: String,
    signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryRecordMaterial<'a> {
    schema_version: u32,
    memory: &'a StrategyMemory,
    generation: u64,
    predecessor_digest: &'a Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct StrategyMemoryStateMaterial<'a> {
    schema_version: u32,
    state_kind: &'static str,
    generation: u64,
    digest: &'a str,
    state: &'a StrategyMemoryState,
}

impl StrategyMemoryState {
    fn empty(limits: GraphResourceLimits, max_memory_ttl_ticks: u64) -> Self {
        Self {
            schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
            limits,
            generation: 0,
            predecessor_digest: None,
            record_chain_prefix_digest: None,
            memories: BTreeMap::new(),
            order: Vec::new(),
            expiry_envelopes: BTreeMap::new(),
            max_memory_ttl_ticks: Some(max_memory_ttl_ticks),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, StrategyMemoryStoreError> {
        let bytes = canonical_json_bytes(self).map_err(|error| {
            StrategyMemoryStoreError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        if bytes.len() > persisted_json_limit() {
            return Err(StrategyMemoryStoreError::ResourceLimit {
                resource: "persisted_file_bytes".to_string(),
                limit: persisted_json_limit(),
            });
        }
        Ok(bytes)
    }

    fn digest(&self) -> Result<String, StrategyMemoryStoreError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    fn revision(&self) -> Result<GraphStoreRevision, StrategyMemoryStoreError> {
        Ok(GraphStoreRevision::new(self.generation, self.digest()?))
    }

    fn prune_expired_prefix(&mut self, now: GraphLogicalTime, max_memory_ttl_ticks: u64) {
        let expired_prefix_len = self
            .order
            .iter()
            .take_while(|memory_id| {
                self.expiry_envelopes
                    .get(memory_id.as_str())
                    .is_some_and(|envelope| {
                        !envelope.is_applicable_at_with_limit(now, max_memory_ttl_ticks)
                    })
            })
            .count();
        if expired_prefix_len == 0 {
            return;
        }

        let expired_ids = self.order.drain(..expired_prefix_len).collect::<Vec<_>>();
        for memory_id in expired_ids {
            if let Some(record) = self.memories.remove(&memory_id) {
                self.record_chain_prefix_digest = Some(record.digest);
            }
            self.expiry_envelopes.remove(&memory_id);
        }
    }

    fn record_tail_digest(&self) -> Option<String> {
        self.order
            .last()
            .and_then(|id| self.memories.get(id).map(|record| record.digest.clone()))
            .or_else(|| self.record_chain_prefix_digest.clone())
    }

    fn validate(
        &self,
        limits: &GraphResourceLimits,
        expected_signer: &swarm_core::types::AgentId,
        max_memory_ttl_ticks: u64,
    ) -> Result<(), StrategyMemoryStoreError> {
        if self.schema_version != STRATEGY_MEMORY_STORE_SCHEMA_VERSION {
            return Err(StrategyMemoryStoreError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        self.limits
            .validate()
            .map_err(StrategyMemoryStoreError::Admission)?;
        limits
            .validate()
            .map_err(StrategyMemoryStoreError::Admission)?;
        if self.limits != *limits {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "memory resource limits do not match the configured store limits"
                    .to_string(),
            });
        }
        validate_max_memory_ttl_ticks(max_memory_ttl_ticks)?;
        if let Some(persisted) = self.max_memory_ttl_ticks {
            validate_max_memory_ttl_ticks(persisted)?;
            if persisted != max_memory_ttl_ticks {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "configured memory TTL does not match persisted TTL".to_string(),
                });
            }
        }
        if self.generation == 0 {
            if self.predecessor_digest.is_some()
                || self.record_chain_prefix_digest.is_some()
                || !self.order.is_empty()
            {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "empty memory state has predecessor or order entries".to_string(),
                });
            }
        } else if self.predecessor_digest.as_deref().is_none_or(str::is_empty) {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "advanced memory state requires a predecessor digest".to_string(),
            });
        }
        if self.memories.len() > limits.max_memory_records
            || self.order.len() > limits.max_memory_records
        {
            return Err(StrategyMemoryStoreError::ResourceLimit {
                resource: "strategy_memory.records".to_string(),
                limit: limits.max_memory_records,
            });
        }
        if self.memories.len() != self.order.len() {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "memory index and append order have different lengths".to_string(),
            });
        }
        if self.expiry_envelopes.len() > self.memories.len() {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "memory expiry sidecar has more entries than memory records".to_string(),
            });
        }
        if self
            .record_chain_prefix_digest
            .as_deref()
            .is_some_and(str::is_empty)
        {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "compacted record-chain prefix digest is empty".to_string(),
            });
        }
        if self.generation > 0 && self.order.is_empty() && self.record_chain_prefix_digest.is_none()
        {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "compacted memory state is missing its record-chain prefix".to_string(),
            });
        }
        let mut previous_digest = self.record_chain_prefix_digest.clone();
        let mut previous_generation: Option<u64> = None;
        let mut seen_ids = BTreeSet::new();
        for memory_id in &self.order {
            if !seen_ids.insert(memory_id) {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "append order contains a duplicate memory ID".to_string(),
                });
            }
            let record = self.memories.get(memory_id).ok_or_else(|| {
                StrategyMemoryStoreError::InvalidState {
                    reason: "append order references a missing memory".to_string(),
                }
            })?;
            if record.memory.memory_id.as_str() != memory_id {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "memory index key does not match memory ID".to_string(),
                });
            }
            record.validate(expected_signer, previous_digest.as_deref())?;
            let generation_is_contiguous = match previous_generation {
                Some(previous) => previous.checked_add(1) == Some(record.generation),
                None if self.record_chain_prefix_digest.is_some() => record.generation > 1,
                None => record.generation == 1,
            };
            if !generation_is_contiguous {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "memory generations are not contiguous append order".to_string(),
                });
            }
            previous_generation = Some(record.generation);
            previous_digest = Some(record.digest.clone());
        }
        for (memory_id, envelope) in &self.expiry_envelopes {
            let memory = self.memories.get(memory_id).ok_or_else(|| {
                StrategyMemoryStoreError::InvalidState {
                    reason: "memory expiry sidecar references a missing memory".to_string(),
                }
            })?;
            if envelope.memory_id.as_str() != memory_id {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "memory expiry sidecar key does not match memory ID".to_string(),
                });
            }
            validate_expiry_for(&memory.memory, envelope, max_memory_ttl_ticks)?;
        }
        if previous_generation.is_some_and(|generation| generation != self.generation) {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "state generation does not match the retained record tail".to_string(),
            });
        }
        Ok(())
    }
}

fn strategy_memory_page(
    state: &StrategyMemoryState,
    after: Option<(u64, &str)>,
    limit: usize,
) -> Vec<StrategyMemoryRecord> {
    state
        .order
        .iter()
        .rev()
        .filter_map(|id| state.memories.get(id))
        .filter(|record| {
            after.is_none_or(|(generation, stable_id)| {
                record.generation < generation
                    || (record.generation == generation
                        && record.memory.memory_id.as_str() < stable_id)
            })
        })
        .take(limit)
        .cloned()
        .collect()
}

impl StrategyMemoryRecord {
    fn new(
        memory: StrategyMemory,
        generation: u64,
        predecessor_digest: Option<String>,
        signer: &Keypair,
    ) -> Result<Self, StrategyMemoryStoreError> {
        memory
            .validate()
            .map_err(StrategyMemoryStoreError::Admission)?;
        let material = StrategyMemoryRecordMaterial {
            schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
            memory: &memory,
            generation,
            predecessor_digest: &predecessor_digest,
        };
        let bytes = canonical_json_bytes(&material).map_err(|error| {
            StrategyMemoryStoreError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        let digest = sha256_hex(&bytes);
        let public_key_hex = signer.public_key().to_hex();
        let signature = signer.sign(&bytes);
        Ok(Self {
            schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
            memory,
            generation,
            predecessor_digest,
            digest,
            store_signature: DetachedSignature {
                algorithm: "ed25519".to_string(),
                key_id: sha256_hex(signer.public_key().as_bytes()),
                public_key_hex,
                signature_hex: signature.to_hex(),
            },
        })
    }

    fn validate(
        &self,
        expected_signer: &swarm_core::types::AgentId,
        expected_predecessor: Option<&str>,
    ) -> Result<(), StrategyMemoryStoreError> {
        if self.schema_version != STRATEGY_MEMORY_STORE_SCHEMA_VERSION {
            return Err(StrategyMemoryStoreError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        self.memory
            .validate()
            .map_err(StrategyMemoryStoreError::Admission)?;
        if self.generation == 0 {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "memory record generation must be positive".to_string(),
            });
        }
        match (expected_predecessor, self.predecessor_digest.as_deref()) {
            (None, None) => {}
            (Some(expected), Some(observed)) if expected == observed => {}
            (expected, observed) => {
                return Err(StrategyMemoryStoreError::ReplayOrGap {
                    expected: expected.map(str::to_string),
                    observed: observed.map(str::to_string),
                });
            }
        }
        let material = StrategyMemoryRecordMaterial {
            schema_version: self.schema_version,
            memory: &self.memory,
            generation: self.generation,
            predecessor_digest: &self.predecessor_digest,
        };
        let bytes = canonical_json_bytes(&material).map_err(|error| {
            StrategyMemoryStoreError::Canonicalization {
                reason: error.to_string(),
            }
        })?;
        let digest = sha256_hex(&bytes);
        if digest != self.digest {
            return Err(StrategyMemoryStoreError::DigestMismatch {
                expected: self.digest.clone(),
                observed: digest,
            });
        }
        verify_detached_signature(&bytes, &self.store_signature).map_err(|error| {
            StrategyMemoryStoreError::InvalidSignature {
                reason: error.to_string(),
            }
        })?;
        let derived =
            swarm_core::types::AgentId::from_public_key_hex(&self.store_signature.public_key_hex);
        if &derived != expected_signer {
            return Err(StrategyMemoryStoreError::SignerMismatch {
                expected: expected_signer.clone(),
                observed: derived,
            });
        }
        Ok(())
    }
}

fn sign_state_with_limit(
    state: StrategyMemoryState,
    signer: &Keypair,
    limits: &GraphResourceLimits,
    max_memory_ttl_ticks: u64,
) -> Result<SignedStrategyMemoryState, StrategyMemoryStoreError> {
    let signer_id = swarm_core::types::AgentId::from_public_key_hex(&signer.public_key().to_hex());
    state.validate(limits, &signer_id, max_memory_ttl_ticks)?;
    let digest = state.digest()?;
    let material = StrategyMemoryStateMaterial {
        schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
        state_kind: STRATEGY_MEMORY_STATE_KIND,
        generation: state.generation,
        digest: &digest,
        state: &state,
    };
    let bytes = canonical_json_bytes(&material).map_err(|error| {
        StrategyMemoryStoreError::Canonicalization {
            reason: error.to_string(),
        }
    })?;
    if bytes.len() > persisted_json_limit() {
        return Err(StrategyMemoryStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: persisted_json_limit(),
        });
    }
    let public_key_hex = signer.public_key().to_hex();
    let signature = signer.sign(&bytes);
    let envelope = SignedStrategyMemoryState {
        state,
        digest,
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: sha256_hex(signer.public_key().as_bytes()),
            public_key_hex,
            signature_hex: signature.to_hex(),
        },
    };
    let persisted = serde_json::to_vec(&envelope).map_err(|error| {
        StrategyMemoryStoreError::GraphPersistence(GraphStoreError::Serialize {
            path: PathBuf::from(STRATEGY_MEMORY_STATE_FILE),
            source: error,
        })
    })?;
    if persisted.len() > persisted_json_limit() {
        return Err(StrategyMemoryStoreError::ResourceLimit {
            resource: "persisted_file_bytes".to_string(),
            limit: persisted_json_limit(),
        });
    }
    Ok(envelope)
}

fn verify_state_with_limit(
    envelope: &SignedStrategyMemoryState,
    expected_signer: &swarm_core::types::AgentId,
    limits: &GraphResourceLimits,
    max_memory_ttl_ticks: u64,
) -> Result<(), StrategyMemoryStoreError> {
    envelope
        .state
        .validate(limits, expected_signer, max_memory_ttl_ticks)?;
    let digest = envelope.state.digest()?;
    if digest != envelope.digest {
        return Err(StrategyMemoryStoreError::DigestMismatch {
            expected: envelope.digest.clone(),
            observed: digest,
        });
    }
    let material = StrategyMemoryStateMaterial {
        schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
        state_kind: STRATEGY_MEMORY_STATE_KIND,
        generation: envelope.state.generation,
        digest: &envelope.digest,
        state: &envelope.state,
    };
    let bytes = canonical_json_bytes(&material).map_err(|error| {
        StrategyMemoryStoreError::Canonicalization {
            reason: error.to_string(),
        }
    })?;
    verify_detached_signature(&bytes, &envelope.signature).map_err(|error| {
        StrategyMemoryStoreError::InvalidSignature {
            reason: error.to_string(),
        }
    })?;
    let derived =
        swarm_core::types::AgentId::from_public_key_hex(&envelope.signature.public_key_hex);
    if &derived != expected_signer {
        return Err(StrategyMemoryStoreError::SignerMismatch {
            expected: expected_signer.clone(),
            observed: derived,
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum StrategyMemoryStoreError {
    #[error("memory store lock poisoned")]
    PoisonedLock,
    #[error("unsupported memory store schema version {0}")]
    UnsupportedSchema(u32),
    #[error("memory admission failed: {0}")]
    Admission(#[source] GraphAdmissionError),
    #[error("canonicalization failed: {reason}")]
    Canonicalization { reason: String },
    #[error("invalid memory state: {reason}")]
    InvalidState { reason: String },
    #[error("memory resource `{resource}` exceeded limit {limit}")]
    ResourceLimit { resource: String, limit: usize },
    #[error("memory digest mismatch: expected `{expected}`, observed `{observed}`")]
    DigestMismatch { expected: String, observed: String },
    #[error("memory signature invalid: {reason}")]
    InvalidSignature { reason: String },
    #[error("memory store signer mismatch: expected `{expected}`, observed `{observed}`")]
    SignerMismatch {
        expected: swarm_core::types::AgentId,
        observed: swarm_core::types::AgentId,
    },
    #[error("memory append chain gap or replay: expected {expected:?}, observed {observed:?}")]
    ReplayOrGap {
        expected: Option<String>,
        observed: Option<String>,
    },
    #[error("strategy memory `{memory_id}` already exists with different content")]
    DuplicateConflict {
        memory_id: swarm_core::hypothesis_graph::MemoryId,
    },
    #[error("strategy memory `{memory_id}` was not found")]
    NotFound {
        memory_id: swarm_core::hypothesis_graph::MemoryId,
    },
    #[error("retrieval limit must be positive and at most {0}")]
    InvalidLimit(usize),
    #[error("graph persistence failed: {0}")]
    GraphPersistence(#[from] GraphStoreError),
}

/// Advisory memory persistence/retrieval contract.  Retrieval only returns
/// typed matches; it does not grant task or response authority.
pub trait StrategyMemoryStore: Send + Sync {
    fn append(
        &self,
        memory: StrategyMemory,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError>;
    fn persist(
        &self,
        memory: StrategyMemory,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        self.append(memory)
    }
    /// Append a memory together with its signed logical-time expiry sidecar.
    /// The historical `append` method remains available for legacy records;
    /// those records are quarantined from priority retrieval until an expiry
    /// envelope is explicitly supplied.
    fn append_at(
        &self,
        memory: StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError>;
    fn append_with_expiry(
        &self,
        memory: StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        self.append_at(memory, created_at, ttl_ticks)
    }
    fn load(
        &self,
        memory_id: &swarm_core::hypothesis_graph::MemoryId,
    ) -> Result<Option<StrategyMemoryRecord>, StrategyMemoryStoreError>;
    fn list(&self, limit: usize) -> Result<Vec<StrategyMemoryRecord>, StrategyMemoryStoreError>;
    fn list_page(
        &self,
        after: Option<(u64, &str)>,
        limit: usize,
    ) -> Result<Vec<StrategyMemoryRecord>, StrategyMemoryStoreError>;
    fn retrieve(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        limit: usize,
    ) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError>;
    fn retrieve_at(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        now: GraphLogicalTime,
        limit: usize,
    ) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError>;
}

fn relevance(memory: &StrategyMemory, evidence_ids: &BTreeSet<EvidenceId>) -> u16 {
    let overlap = evidence_ids
        .iter()
        .filter_map(|id| memory.evidence_utility.get(id))
        .map(|utility| u32::from(utility.utility_basis_points))
        .sum::<u32>();
    let base = if evidence_ids.is_empty() { 1 } else { 1_000 };
    u16::try_from((overlap.saturating_add(base)).min(10_000)).unwrap_or(10_000)
}

/// Return only valid, logically applicable expiry sidecars in canonical ID
/// order.  Invalid envelopes are omitted so a malformed or forged sidecar
/// cannot influence priority; callers still bind each returned envelope to its
/// memory record before using it.
pub fn applicable_strategy_memory(
    memories: &[StrategyMemoryExpiryEnvelope],
    now: GraphLogicalTime,
) -> Vec<&StrategyMemoryExpiryEnvelope> {
    if now.validate().is_err() {
        return Vec::new();
    }
    let mut applicable = memories
        .iter()
        .filter(|envelope| envelope.is_applicable_at_with_limit(now, MAX_STRATEGY_MEMORY_TTL_TICKS))
        .collect::<Vec<_>>();
    applicable.sort_by(|left, right| left.memory_id.cmp(&right.memory_id));
    applicable
}

fn retrieve_from_state(
    state: &StrategyMemoryState,
    graph_id: &GraphId,
    hypothesis_id: &HypothesisId,
    evidence_ids: &BTreeSet<EvidenceId>,
    now: GraphLogicalTime,
    limit: usize,
    max_memory_ttl_ticks: u64,
) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError> {
    if limit == 0 || limit > 256 {
        return Err(StrategyMemoryStoreError::InvalidLimit(256));
    }
    now.validate()
        .map_err(StrategyMemoryStoreError::Admission)?;
    let active_ids = state
        .expiry_envelopes
        .values()
        .filter(|envelope| envelope.is_applicable_at_with_limit(now, max_memory_ttl_ticks))
        .map(|envelope| envelope.memory_id.as_str())
        .collect::<BTreeSet<_>>();
    let ordering = |left: &(&StrategyMemoryRecord, StrategyMemoryMatch),
                    right: &(&StrategyMemoryRecord, StrategyMemoryMatch)| {
        right
            .1
            .relevance_basis_points
            .cmp(&left.1.relevance_basis_points)
            .then_with(|| left.0.memory.memory_id.cmp(&right.0.memory.memory_id))
    };
    // Keep only the requested top-k candidates while scanning.  In
    // particular, do not first collect every applicable memory: a valid
    // state may contain the full configured set and retrieval is an
    // untrusted caller-controlled allocation boundary.
    let mut matches = Vec::with_capacity(limit);
    for record in state
        .memories
        .values()
        .filter(|record| active_ids.contains(record.memory.memory_id.as_str()))
        .filter(|record| record.memory.applicable_to(graph_id, hypothesis_id))
    {
        let score = relevance(&record.memory, evidence_ids);
        let matched = StrategyMemoryMatch::new(&record.memory, score)
            .map_err(StrategyMemoryStoreError::Admission)?;
        if matches.len() < limit {
            matches.push((record, matched));
            continue;
        }
        let mut worst = 0;
        for index in 1..matches.len() {
            if ordering(&matches[index], &matches[worst]).is_gt() {
                worst = index;
            }
        }
        let candidate = (record, matched);
        if ordering(&candidate, &matches[worst]).is_lt() {
            matches[worst] = candidate;
        }
    }
    matches.sort_by(ordering);
    Ok(matches
        .into_iter()
        .map(|(record, matched)| RetrievedStrategyMemory {
            record: record.clone(),
            matched,
        })
        .collect())
}

#[derive(Debug, Clone)]
pub struct MemoryStrategyMemoryStore {
    inner: Arc<RwLock<SignedStrategyMemoryState>>,
    signer: Keypair,
    limits: GraphResourceLimits,
    max_memory_ttl_ticks: u64,
    signer_id: swarm_core::types::AgentId,
}

impl MemoryStrategyMemoryStore {
    pub fn new(
        signer: Keypair,
        limits: GraphResourceLimits,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::new_with_max_memory_ttl(signer, limits, MAX_STRATEGY_MEMORY_TTL_TICKS)
    }

    pub fn new_with_max_memory_ttl(
        signer: Keypair,
        limits: GraphResourceLimits,
        max_memory_ttl_ticks: u64,
    ) -> Result<Self, StrategyMemoryStoreError> {
        validate_max_memory_ttl_ticks(max_memory_ttl_ticks)?;
        let signer_id =
            swarm_core::types::AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let state = sign_state_with_limit(
            StrategyMemoryState::empty(limits.clone(), max_memory_ttl_ticks),
            &signer,
            &limits,
            max_memory_ttl_ticks,
        )?;
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
            signer,
            limits,
            max_memory_ttl_ticks,
            signer_id,
        })
    }

    pub fn new_with_config(
        signer: Keypair,
        config: &HypothesisGraphConfig,
    ) -> Result<Self, StrategyMemoryStoreError> {
        config
            .validate_reasoning_limits()
            .map_err(StrategyMemoryStoreError::Admission)?;
        Self::new_with_max_memory_ttl(
            signer,
            config.resource_limits(),
            config.max_memory_ttl_ticks,
        )
    }

    pub fn with_config(
        signer: Keypair,
        config: &HypothesisGraphConfig,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::new_with_config(signer, config)
    }

    pub fn with_defaults(signer: Keypair) -> Result<Self, StrategyMemoryStoreError> {
        Self::new(signer, GraphResourceLimits::default())
    }

    fn read_state(&self) -> Result<SignedStrategyMemoryState, StrategyMemoryStoreError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| StrategyMemoryStoreError::PoisonedLock)?;
        verify_state_with_limit(
            &guard,
            &self.signer_id,
            &self.limits,
            self.max_memory_ttl_ticks,
        )?;
        Ok(guard.clone())
    }

    fn append_inner(
        &self,
        memory: StrategyMemory,
        expiry: Option<(GraphLogicalTime, u64)>,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StrategyMemoryStoreError::PoisonedLock)?;
        verify_state_with_limit(
            &guard,
            &self.signer_id,
            &self.limits,
            self.max_memory_ttl_ticks,
        )?;
        let compact_at = expiry.map(|(created_at, _)| created_at);
        let expiry_envelope = expiry
            .map(|(created_at, ttl_ticks)| {
                StrategyMemoryExpiryEnvelope::new_with_limit(
                    &memory,
                    created_at,
                    ttl_ticks,
                    self.max_memory_ttl_ticks,
                    &self.signer,
                )
                .map_err(StrategyMemoryStoreError::Admission)
            })
            .transpose()?;
        if let Some(existing) = guard.state.memories.get(memory.memory_id.as_str()) {
            if existing.memory == memory {
                let persisted = guard.state.expiry_envelopes.get(memory.memory_id.as_str());
                match (expiry_envelope.as_ref(), persisted) {
                    (Some(requested), Some(persisted)) if requested == persisted => {}
                    (None, None) => {}
                    (Some(_), None) => {
                        return Err(StrategyMemoryStoreError::InvalidState {
                            reason: "legacy memory has no expiry sidecar; explicit append_at is quarantined"
                                .to_string(),
                        });
                    }
                    _ => {
                        return Err(StrategyMemoryStoreError::DuplicateConflict {
                            memory_id: memory.memory_id.clone(),
                        });
                    }
                }
                return Ok(StrategyMemoryAppendResult {
                    generation: existing.generation,
                    record: existing.clone(),
                    idempotent: true,
                });
            }
            return Err(StrategyMemoryStoreError::DuplicateConflict {
                memory_id: memory.memory_id.clone(),
            });
        }
        let state_predecessor_digest = guard.state.digest()?;
        let mut next_state = guard.state.clone();
        if next_state.memories.len() >= self.limits.max_memory_records
            && let Some(now) = compact_at
        {
            next_state.prune_expired_prefix(now, self.max_memory_ttl_ticks);
        }
        if next_state.memories.len() >= self.limits.max_memory_records {
            return Err(StrategyMemoryStoreError::ResourceLimit {
                resource: "strategy_memory.records".to_string(),
                limit: self.limits.max_memory_records,
            });
        }
        let generation = guard.state.generation.checked_add(1).ok_or_else(|| {
            StrategyMemoryStoreError::InvalidState {
                reason: "memory generation overflow".to_string(),
            }
        })?;
        let predecessor_digest = next_state.record_tail_digest();
        let record =
            StrategyMemoryRecord::new(memory, generation, predecessor_digest, &self.signer)?;
        // Build and sign an independent candidate before publishing it.  A
        // size/signing failure must leave the locked state byte-for-byte
        // unchanged, matching the file backend's fail-closed admission.
        next_state.max_memory_ttl_ticks = Some(self.max_memory_ttl_ticks);
        next_state.generation = generation;
        next_state.predecessor_digest = Some(state_predecessor_digest);
        next_state
            .order
            .push(record.memory.memory_id.as_str().to_string());
        next_state
            .memories
            .insert(record.memory.memory_id.as_str().to_string(), record.clone());
        if let Some(envelope) = expiry_envelope {
            next_state
                .expiry_envelopes
                .insert(record.memory.memory_id.as_str().to_string(), envelope);
        }
        let next = sign_state_with_limit(
            next_state,
            &self.signer,
            &self.limits,
            self.max_memory_ttl_ticks,
        )?;
        *guard = next;
        Ok(StrategyMemoryAppendResult {
            generation,
            record,
            idempotent: false,
        })
    }

    pub fn state_digest(&self) -> Result<String, StrategyMemoryStoreError> {
        Ok(self.read_state()?.digest)
    }

    pub fn signer_id(&self) -> &swarm_core::types::AgentId {
        &self.signer_id
    }
}

impl StrategyMemoryStore for MemoryStrategyMemoryStore {
    fn append(
        &self,
        memory: StrategyMemory,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        self.append_inner(memory, None)
    }

    fn append_at(
        &self,
        memory: StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        self.append_inner(memory, Some((created_at, ttl_ticks)))
    }

    fn load(
        &self,
        memory_id: &swarm_core::hypothesis_graph::MemoryId,
    ) -> Result<Option<StrategyMemoryRecord>, StrategyMemoryStoreError> {
        let state = self.read_state()?;
        Ok(state.state.memories.get(memory_id.as_str()).cloned())
    }

    fn list(&self, limit: usize) -> Result<Vec<StrategyMemoryRecord>, StrategyMemoryStoreError> {
        if limit == 0 || limit > MAX_STRATEGY_MEMORY_LIST_LIMIT {
            return Err(StrategyMemoryStoreError::InvalidLimit(
                MAX_STRATEGY_MEMORY_LIST_LIMIT,
            ));
        }
        let state = self.read_state()?;
        let records = state
            .state
            .order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|id| state.state.memories.get(id).cloned())
            .collect::<Vec<_>>();
        Ok(records)
    }

    fn list_page(
        &self,
        after: Option<(u64, &str)>,
        limit: usize,
    ) -> Result<Vec<StrategyMemoryRecord>, StrategyMemoryStoreError> {
        if limit == 0 || limit > MAX_STRATEGY_MEMORY_LIST_LIMIT {
            return Err(StrategyMemoryStoreError::InvalidLimit(
                MAX_STRATEGY_MEMORY_LIST_LIMIT,
            ));
        }
        let state = self.read_state()?;
        Ok(strategy_memory_page(&state.state, after, limit))
    }

    fn retrieve(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        limit: usize,
    ) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError> {
        self.retrieve_at(
            graph_id,
            hypothesis_id,
            evidence_ids,
            GraphLogicalTime::new(0),
            limit,
        )
    }

    fn retrieve_at(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        now: GraphLogicalTime,
        limit: usize,
    ) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError> {
        retrieve_from_state(
            &self.read_state()?.state,
            graph_id,
            hypothesis_id,
            evidence_ids,
            now,
            limit,
            self.max_memory_ttl_ticks,
        )
    }
}

#[derive(Debug)]
pub struct FileStrategyMemoryStore {
    root: PathBuf,
    state_path: PathBuf,
    anchor_path: PathBuf,
    high_water_path: PathBuf,
    high_water_tail_path: PathBuf,
    monotonic_anchor: DurableMonotonicAnchor,
    #[allow(dead_code)]
    lock: DurableFileLock,
    mutation_lock: Mutex<()>,
    signer: Keypair,
    limits: GraphResourceLimits,
    max_memory_ttl_ticks: u64,
    signer_id: swarm_core::types::AgentId,
}

impl FileStrategyMemoryStore {
    pub fn new(
        path: impl AsRef<Path>,
        signer: Keypair,
        limits: GraphResourceLimits,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::open_internal(path.as_ref(), signer, limits, MAX_STRATEGY_MEMORY_TTL_TICKS)
    }

    pub fn new_with_max_memory_ttl(
        path: impl AsRef<Path>,
        signer: Keypair,
        limits: GraphResourceLimits,
        max_memory_ttl_ticks: u64,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::open_internal(path.as_ref(), signer, limits, max_memory_ttl_ticks)
    }

    pub fn open_with_signer(
        path: impl AsRef<Path>,
        signer: Keypair,
        limits: GraphResourceLimits,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::open_internal(path.as_ref(), signer, limits, MAX_STRATEGY_MEMORY_TTL_TICKS)
    }

    pub fn open_with_signer_and_max_memory_ttl(
        path: impl AsRef<Path>,
        signer: Keypair,
        limits: GraphResourceLimits,
        max_memory_ttl_ticks: u64,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::open_internal(path.as_ref(), signer, limits, max_memory_ttl_ticks)
    }

    pub fn new_with_config(
        path: impl AsRef<Path>,
        signer: Keypair,
        config: &HypothesisGraphConfig,
    ) -> Result<Self, StrategyMemoryStoreError> {
        config
            .validate_reasoning_limits()
            .map_err(StrategyMemoryStoreError::Admission)?;
        Self::open_internal(
            path.as_ref(),
            signer,
            config.resource_limits(),
            config.max_memory_ttl_ticks,
        )
    }

    pub fn open_with_config(
        path: impl AsRef<Path>,
        signer: Keypair,
        config: &HypothesisGraphConfig,
    ) -> Result<Self, StrategyMemoryStoreError> {
        Self::new_with_config(path, signer, config)
    }

    fn open_internal(
        path: &Path,
        signer: Keypair,
        limits: GraphResourceLimits,
        max_memory_ttl_ticks: u64,
    ) -> Result<Self, StrategyMemoryStoreError> {
        validate_max_memory_ttl_ticks(max_memory_ttl_ticks)?;
        prepare_private_store_root(path).map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let root = std::fs::canonicalize(path).map_err(|source| {
            StrategyMemoryStoreError::GraphPersistence(GraphStoreError::Read {
                path: path.to_path_buf(),
                source,
            })
        })?;
        // Every signed stream identifier and every persistence path must be
        // derived from one normalized root.  Equivalent relative and absolute
        // spellings must reopen the same external monotonic journal.
        let path = root.as_path();
        let lock_path = path.join(STRATEGY_MEMORY_LOCK_FILE);
        let lock_existed = std::fs::symlink_metadata(&lock_path).is_ok();
        let lock = DurableFileLock::acquire(&lock_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let state_path = path.join(STRATEGY_MEMORY_STATE_FILE);
        let anchor_path = path.join(STRATEGY_MEMORY_ANCHOR_FILE);
        let high_water_path = path.join(STRATEGY_MEMORY_HIGH_WATER_FILE);
        let high_water_tail_path = path.join(STRATEGY_MEMORY_HIGH_WATER_TAIL_FILE);
        let monotonic_anchor = DurableMonotonicAnchor::new(path, STRATEGY_MEMORY_STATE_KIND)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        crate::hypothesis_graph_store::ensure_path_not_symlink(&state_path)?;
        crate::hypothesis_graph_store::ensure_path_not_symlink(&anchor_path)?;
        crate::hypothesis_graph_store::ensure_path_not_symlink(&high_water_path)?;
        crate::hypothesis_graph_store::ensure_path_not_symlink(&high_water_tail_path)?;
        let signer_id =
            swarm_core::types::AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let stream_id = strategy_memory_stream_id(path);
        if state_path.exists() {
            if !anchor_path.exists() {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingAnchor { path: anchor_path },
                ));
            }
            if !high_water_path.exists() {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingHighWater {
                        path: high_water_path,
                    },
                ));
            }
            if !high_water_tail_path.exists() {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingHighWater {
                        path: high_water_tail_path,
                    },
                ));
            }
            if !monotonic_anchor.exists() {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingHighWater {
                        path: monotonic_anchor.path().to_path_buf(),
                    },
                ));
            }
            lock.revalidate()
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let mut state: SignedStrategyMemoryState = lock
                .read_json(&state_path)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let persisted_limits = state.state.limits.clone();
            if persisted_limits != limits {
                return Err(StrategyMemoryStoreError::InvalidState {
                    reason: "configured memory limits do not match persisted limits".to_string(),
                });
            }
            verify_state_with_limit(&state, &signer_id, &limits, max_memory_ttl_ticks)?;
            let mut state_revision = state.state.revision()?;
            // Resolve pending rollback before ordinary tuple validation.  The
            // rollback pointer makes each replacement restart-safe.
            let (external_journal, recovered) = recover_external_journal(
                &monotonic_anchor,
                &lock,
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &signer,
                &signer_id,
                lock.generation(),
                &lock.identity_token(),
                &state_revision,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let mut head: DurableStateHead = lock
                .read_json(&anchor_path)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let mut high_water = read_high_water(&lock, &high_water_path, &high_water_tail_path)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let mut head_revision = verify_state_head(
                &head,
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &signer_id,
                lock.generation(),
                &lock.identity_token(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let mut high_water_revision = verify_state_head(
                &high_water,
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &signer_id,
                lock.generation(),
                &lock.identity_token(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            if recovered {
                state = lock
                    .read_json(&state_path)
                    .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                verify_state_with_limit(&state, &signer_id, &limits, max_memory_ttl_ticks)?;
                state_revision = state.state.revision()?;
                head = lock
                    .read_json(&anchor_path)
                    .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                head_revision = verify_state_head(
                    &head,
                    STRATEGY_MEMORY_STATE_KIND,
                    &stream_id,
                    &signer_id,
                    lock.generation(),
                    &lock.identity_token(),
                )
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                high_water = read_high_water(&lock, &high_water_path, &high_water_tail_path)
                    .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                high_water_revision = verify_state_head(
                    &high_water,
                    STRATEGY_MEMORY_STATE_KIND,
                    &stream_id,
                    &signer_id,
                    lock.generation(),
                    &lock.identity_token(),
                )
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                validate_high_water_against_revisions(
                    &high_water_revision,
                    &head_revision,
                    &state_revision,
                    state.state.predecessor_digest.as_deref(),
                )
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            }
            validate_high_water_against_revisions(
                &high_water_revision,
                &head_revision,
                &state_revision,
                state.state.predecessor_digest.as_deref(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            validate_external_journal_against_state(&external_journal, &state_revision)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            lock.revalidate()
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            reconcile_state_head(
                &anchor_path,
                &lock,
                &head_revision,
                &state_revision,
                state.state.predecessor_digest.as_deref(),
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                lock.generation(),
                &lock.identity_token(),
                &signer,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            if high_water_revision != state_revision {
                let promoted = sign_state_head(
                    STRATEGY_MEMORY_STATE_KIND,
                    &stream_id,
                    &state_revision,
                    lock.generation(),
                    &lock.identity_token(),
                    &signer,
                )
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                lock.revalidate()
                    .map_err(StrategyMemoryStoreError::GraphPersistence)?;
                append_high_water(&lock, &high_water_path, &high_water_tail_path, &promoted)
                    .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            }
        } else {
            if lock_existed {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingState { path: state_path },
                ));
            }
            if anchor_path.exists() {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingState { path: state_path },
                ));
            }
            if high_water_path.exists()
                || high_water_tail_path.exists()
                || monotonic_anchor.exists()
            {
                return Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::MissingState { path: state_path },
                ));
            }
            let state = sign_state_with_limit(
                StrategyMemoryState::empty(limits.clone(), max_memory_ttl_ticks),
                &signer,
                &limits,
                max_memory_ttl_ticks,
            )?;
            let head = sign_state_head(
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &state.state.revision()?,
                lock.generation(),
                &lock.identity_token(),
                &signer,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let external_commit = sign_external_commit_record(
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                state.state.generation,
                &state.digest,
                0,
                ExternalCommitPhase::Commit,
                None,
                lock.generation(),
                &lock.identity_token(),
                &signer,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            let external_lock = monotonic_anchor
                .acquire_lock()
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            monotonic_anchor
                .append_external_locked(&external_lock, &external_commit)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            lock.revalidate()
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            lock.atomic_write_json(&state_path, &state)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            lock.revalidate()
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            lock.atomic_write_json(&anchor_path, &head)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            append_high_water(&lock, &high_water_path, &high_water_tail_path, &head)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        }
        Ok(Self {
            root: path.to_path_buf(),
            state_path,
            anchor_path,
            high_water_path,
            high_water_tail_path,
            monotonic_anchor,
            lock,
            mutation_lock: Mutex::new(()),
            signer,
            limits,
            max_memory_ttl_ticks,
            signer_id,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn anchor_path(&self) -> &Path {
        &self.anchor_path
    }

    pub fn signer_id(&self) -> &swarm_core::types::AgentId {
        &self.signer_id
    }

    fn read_state(&self) -> Result<SignedStrategyMemoryState, StrategyMemoryStoreError> {
        self.lock
            .revalidate()
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        if !self.state_path.exists() {
            return Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::MissingState {
                    path: self.state_path.clone(),
                },
            ));
        }
        if !self.anchor_path.exists() {
            return Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::MissingAnchor {
                    path: self.anchor_path.clone(),
                },
            ));
        }
        if !self.high_water_path.exists() {
            return Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::MissingHighWater {
                    path: self.high_water_path.clone(),
                },
            ));
        }
        if !self.high_water_tail_path.exists() {
            return Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::MissingHighWater {
                    path: self.high_water_tail_path.clone(),
                },
            ));
        }
        if !self.monotonic_anchor.exists() {
            return Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::MissingHighWater {
                    path: self.monotonic_anchor.path().to_path_buf(),
                },
            ));
        }
        let mut state: SignedStrategyMemoryState = self
            .lock
            .read_json(&self.state_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        verify_state_with_limit(
            &state,
            &self.signer_id,
            &self.limits,
            self.max_memory_ttl_ticks,
        )?;
        let mut state_revision = state.state.revision()?;
        let stream_id = strategy_memory_stream_id(&self.root);
        // Process a pending rollback before loading/validating the ordinary
        // tuple; a crash may have left only some replacements visible.
        let (external_journal, recovered) = recover_external_journal(
            &self.monotonic_anchor,
            &self.lock,
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            &self.signer,
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
            &state_revision,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let mut head: DurableStateHead = self
            .lock
            .read_json(&self.anchor_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let mut high_water = read_high_water(
            &self.lock,
            &self.high_water_path,
            &self.high_water_tail_path,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let mut head_revision = verify_state_head(
            &head,
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let mut high_water_revision = verify_state_head(
            &high_water,
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        if recovered {
            state = self
                .lock
                .read_json(&self.state_path)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            verify_state_with_limit(
                &state,
                &self.signer_id,
                &self.limits,
                self.max_memory_ttl_ticks,
            )?;
            state_revision = state.state.revision()?;
            head = self
                .lock
                .read_json(&self.anchor_path)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            head_revision = verify_state_head(
                &head,
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &self.signer_id,
                self.lock.generation(),
                &self.lock.identity_token(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            high_water = read_high_water(
                &self.lock,
                &self.high_water_path,
                &self.high_water_tail_path,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            high_water_revision = verify_state_head(
                &high_water,
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &self.signer_id,
                self.lock.generation(),
                &self.lock.identity_token(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            validate_high_water_against_revisions(
                &high_water_revision,
                &head_revision,
                &state_revision,
                state.state.predecessor_digest.as_deref(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        }
        validate_high_water_against_revisions(
            &high_water_revision,
            &head_revision,
            &state_revision,
            state.state.predecessor_digest.as_deref(),
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        validate_external_journal_against_state(&external_journal, &state_revision)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.lock
            .revalidate()
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        reconcile_state_head(
            &self.anchor_path,
            &self.lock,
            &head_revision,
            &state_revision,
            state.state.predecessor_digest.as_deref(),
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            self.lock.generation(),
            &self.lock.identity_token(),
            &self.signer,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        if high_water_revision != state_revision {
            let promoted = sign_state_head(
                STRATEGY_MEMORY_STATE_KIND,
                &stream_id,
                &state_revision,
                self.lock.generation(),
                &self.lock.identity_token(),
                &self.signer,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            self.lock
                .revalidate()
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            append_high_water(
                &self.lock,
                &self.high_water_path,
                &self.high_water_tail_path,
                &promoted,
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        }
        Ok(state)
    }

    pub fn state_digest(&self) -> Result<String, StrategyMemoryStoreError> {
        Ok(self.read_state()?.digest)
    }
}

impl FileStrategyMemoryStore {
    fn append_inner(
        &self,
        memory: StrategyMemory,
        expiry: Option<(GraphLogicalTime, u64)>,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| StrategyMemoryStoreError::PoisonedLock)?;
        let current = self.read_state()?;
        let compact_at = expiry.map(|(created_at, _)| created_at);
        let expiry_envelope = expiry
            .map(|(created_at, ttl_ticks)| {
                StrategyMemoryExpiryEnvelope::new_with_limit(
                    &memory,
                    created_at,
                    ttl_ticks,
                    self.max_memory_ttl_ticks,
                    &self.signer,
                )
                .map_err(StrategyMemoryStoreError::Admission)
            })
            .transpose()?;
        if let Some(existing) = current.state.memories.get(memory.memory_id.as_str()) {
            if existing.memory == memory {
                let persisted = current
                    .state
                    .expiry_envelopes
                    .get(memory.memory_id.as_str());
                match (expiry_envelope.as_ref(), persisted) {
                    (Some(requested), Some(persisted)) if requested == persisted => {}
                    (None, None) => {}
                    (Some(_), None) => {
                        return Err(StrategyMemoryStoreError::InvalidState {
                            reason: "legacy memory has no expiry sidecar; explicit append_at is quarantined"
                                .to_string(),
                        });
                    }
                    _ => {
                        return Err(StrategyMemoryStoreError::DuplicateConflict {
                            memory_id: memory.memory_id.clone(),
                        });
                    }
                }
                return Ok(StrategyMemoryAppendResult {
                    generation: existing.generation,
                    record: existing.clone(),
                    idempotent: true,
                });
            }
            return Err(StrategyMemoryStoreError::DuplicateConflict {
                memory_id: memory.memory_id.clone(),
            });
        }
        let state_predecessor_digest = current.state.digest()?;
        let base_state = current.clone();
        let mut next_state = current.state;
        if next_state.memories.len() >= self.limits.max_memory_records
            && let Some(now) = compact_at
        {
            next_state.prune_expired_prefix(now, self.max_memory_ttl_ticks);
        }
        if next_state.memories.len() >= self.limits.max_memory_records {
            return Err(StrategyMemoryStoreError::ResourceLimit {
                resource: "strategy_memory.records".to_string(),
                limit: self.limits.max_memory_records,
            });
        }
        let generation = next_state.generation.checked_add(1).ok_or_else(|| {
            StrategyMemoryStoreError::InvalidState {
                reason: "memory generation overflow".to_string(),
            }
        })?;
        let record_predecessor_digest = next_state.record_tail_digest();
        let record =
            StrategyMemoryRecord::new(memory, generation, record_predecessor_digest, &self.signer)?;
        next_state.max_memory_ttl_ticks = Some(self.max_memory_ttl_ticks);
        next_state.generation = generation;
        next_state.predecessor_digest = Some(state_predecessor_digest);
        next_state
            .order
            .push(record.memory.memory_id.as_str().to_string());
        next_state
            .memories
            .insert(record.memory.memory_id.as_str().to_string(), record.clone());
        if let Some(envelope) = expiry_envelope {
            next_state
                .expiry_envelopes
                .insert(record.memory.memory_id.as_str().to_string(), envelope);
        }
        let next = sign_state_with_limit(
            next_state,
            &self.signer,
            &self.limits,
            self.max_memory_ttl_ticks,
        )?;
        let external_lock = self
            .monotonic_anchor
            .acquire_lock()
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let external_records = self
            .monotonic_anchor
            .read_records_locked(&external_lock)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.monotonic_anchor
            .validate_tail_locked(&external_lock, &external_records)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let mut journal = verify_external_journal(
            &external_records,
            STRATEGY_MEMORY_STATE_KIND,
            &strategy_memory_stream_id(&self.root),
            &self.signer_id,
            self.lock.generation(),
            &self.lock.identity_token(),
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        if journal.pending.is_some() {
            return Err(StrategyMemoryStoreError::InvalidState {
                reason: "cannot append while external commit intent is pending".to_string(),
            });
        }
        if self
            .monotonic_anchor
            .rotate_if_needed_locked(&external_lock, &journal.committed, &self.signer)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?
        {
            let rotated_records = self
                .monotonic_anchor
                .read_records_locked(&external_lock)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            self.monotonic_anchor
                .validate_tail_locked(&external_lock, &rotated_records)
                .map_err(StrategyMemoryStoreError::GraphPersistence)?;
            journal = verify_external_journal(
                &rotated_records,
                STRATEGY_MEMORY_STATE_KIND,
                &strategy_memory_stream_id(&self.root),
                &self.signer_id,
                self.lock.generation(),
                &self.lock.identity_token(),
            )
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        }
        let next_revision = next.state.revision()?;
        let intent = sign_external_commit_record(
            STRATEGY_MEMORY_STATE_KIND,
            &strategy_memory_stream_id(&self.root),
            next_revision.generation,
            &next_revision.digest,
            journal.last_sequence.checked_add(1).ok_or_else(|| {
                StrategyMemoryStoreError::InvalidState {
                    reason: "external journal sequence overflow".to_string(),
                }
            })?,
            ExternalCommitPhase::Intent,
            Some(journal.last_record_digest),
            self.lock.generation(),
            &self.lock.identity_token(),
            &self.signer,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let base_head: DurableStateHead = self
            .lock
            .read_json(&self.anchor_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let _base_high_water = read_high_water(
            &self.lock,
            &self.high_water_path,
            &self.high_water_tail_path,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let base_high_water_tail = self
            .lock
            .read_bytes(&self.high_water_tail_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let base_state_bytes = serde_json::to_vec(&base_state).map_err(|source| {
            StrategyMemoryStoreError::GraphPersistence(GraphStoreError::Serialize {
                path: self.state_path.clone(),
                source,
            })
        })?;
        let base_head_bytes = serde_json::to_vec(&base_head).map_err(|source| {
            StrategyMemoryStoreError::GraphPersistence(GraphStoreError::Serialize {
                path: self.anchor_path.clone(),
                source,
            })
        })?;
        let base_high_water_bytes = self
            .lock
            .read_bytes(&self.high_water_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let base_revision = base_state.state.revision()?;
        stage_transaction(
            &self.lock,
            &intent.transaction_id,
            &base_revision,
            &base_state_bytes,
            &base_head_bytes,
            &base_high_water_bytes,
            &base_high_water_tail,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.monotonic_anchor
            .append_external_locked(&external_lock, &intent)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        #[cfg(test)]
        maybe_fail_commit(&self.root, CommitFailureBoundary::ExternalIntent)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.lock
            .revalidate()
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.lock
            .atomic_write_json(&self.state_path, &next)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        #[cfg(test)]
        maybe_fail_commit(&self.root, CommitFailureBoundary::State)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let stream_id = strategy_memory_stream_id(&self.root);
        let head = sign_state_head(
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            &next.state.revision()?,
            self.lock.generation(),
            &self.lock.identity_token(),
            &self.signer,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.lock
            .revalidate()
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.lock
            .atomic_write_json(&self.anchor_path, &head)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        #[cfg(test)]
        maybe_fail_commit(&self.root, CommitFailureBoundary::Head)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        append_high_water(
            &self.lock,
            &self.high_water_path,
            &self.high_water_tail_path,
            &head,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        #[cfg(test)]
        maybe_fail_commit(&self.root, CommitFailureBoundary::HighWater)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let commit = sign_external_commit_record(
            STRATEGY_MEMORY_STATE_KIND,
            &strategy_memory_stream_id(&self.root),
            next_revision.generation,
            &next_revision.digest,
            intent.sequence.checked_add(1).ok_or_else(|| {
                StrategyMemoryStoreError::InvalidState {
                    reason: "external journal sequence overflow".to_string(),
                }
            })?,
            ExternalCommitPhase::Commit,
            Some(intent.record_digest),
            self.lock.generation(),
            &self.lock.identity_token(),
            &self.signer,
        )
        .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        self.monotonic_anchor
            .append_external_locked(&external_lock, &commit)
            .map_err(StrategyMemoryStoreError::GraphPersistence)?;
        let _ = clear_transaction_stage(&self.lock);
        Ok(StrategyMemoryAppendResult {
            generation,
            record,
            idempotent: false,
        })
    }
}

impl StrategyMemoryStore for FileStrategyMemoryStore {
    fn append(
        &self,
        memory: StrategyMemory,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        self.append_inner(memory, None)
    }

    fn append_at(
        &self,
        memory: StrategyMemory,
        created_at: GraphLogicalTime,
        ttl_ticks: u64,
    ) -> Result<StrategyMemoryAppendResult, StrategyMemoryStoreError> {
        self.append_inner(memory, Some((created_at, ttl_ticks)))
    }

    fn load(
        &self,
        memory_id: &swarm_core::hypothesis_graph::MemoryId,
    ) -> Result<Option<StrategyMemoryRecord>, StrategyMemoryStoreError> {
        Ok(self
            .read_state()?
            .state
            .memories
            .get(memory_id.as_str())
            .cloned())
    }

    fn list(&self, limit: usize) -> Result<Vec<StrategyMemoryRecord>, StrategyMemoryStoreError> {
        if limit == 0 || limit > MAX_STRATEGY_MEMORY_LIST_LIMIT {
            return Err(StrategyMemoryStoreError::InvalidLimit(
                MAX_STRATEGY_MEMORY_LIST_LIMIT,
            ));
        }
        let state = self.read_state()?;
        let records = state
            .state
            .order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|id| state.state.memories.get(id).cloned())
            .collect::<Vec<_>>();
        Ok(records)
    }

    fn list_page(
        &self,
        after: Option<(u64, &str)>,
        limit: usize,
    ) -> Result<Vec<StrategyMemoryRecord>, StrategyMemoryStoreError> {
        if limit == 0 || limit > MAX_STRATEGY_MEMORY_LIST_LIMIT {
            return Err(StrategyMemoryStoreError::InvalidLimit(
                MAX_STRATEGY_MEMORY_LIST_LIMIT,
            ));
        }
        let state = self.read_state()?;
        Ok(strategy_memory_page(&state.state, after, limit))
    }

    fn retrieve(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        limit: usize,
    ) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError> {
        self.retrieve_at(
            graph_id,
            hypothesis_id,
            evidence_ids,
            GraphLogicalTime::new(0),
            limit,
        )
    }

    fn retrieve_at(
        &self,
        graph_id: &GraphId,
        hypothesis_id: &HypothesisId,
        evidence_ids: &BTreeSet<EvidenceId>,
        now: GraphLogicalTime,
        limit: usize,
    ) -> Result<Vec<RetrievedStrategyMemory>, StrategyMemoryStoreError> {
        retrieve_from_state(
            &self.read_state()?.state,
            graph_id,
            hypothesis_id,
            evidence_ids,
            now,
            limit,
            self.max_memory_ttl_ticks,
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::hypothesis_graph::{
        GraphProducerRole, HypothesisDelta, MemoryOutcome, MemoryProvenance,
    };

    fn signer(byte: u8) -> Keypair {
        Keypair::from_seed(&[byte; 32])
    }

    fn memory(byte: u8, suffix: &str) -> StrategyMemory {
        let key = signer(byte);
        let identity = swarm_core::types::AgentId::from_public_key_hex(&key.public_key().to_hex());
        let provenance =
            MemoryProvenance::new(identity, [EvidenceId::new(format!("evidence:{suffix}"))])
                .signed_with(&key, GraphProducerRole::Hunter, format!("hunter-{suffix}"))
                .unwrap();
        StrategyMemory::new(
            GraphId::new("graph:test"),
            HypothesisId::new("hypothesis:selected"),
            HypothesisDelta::new([], [], []),
            [swarm_core::hypothesis_graph::EvidenceUtility::new(
                EvidenceId::new(format!("evidence:{suffix}")),
                7_500,
            )],
            [HypothesisId::new("hypothesis:alternative")],
            MemoryOutcome::Confirmed,
            provenance,
        )
        .unwrap()
        .signed_with(&key, GraphProducerRole::Hunter, format!("hunter-{suffix}"))
        .unwrap()
    }

    #[derive(serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyStrategyMemoryStateFixture {
        schema_version: u32,
        limits: GraphResourceLimits,
        generation: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        predecessor_digest: Option<String>,
        memories: BTreeMap<String, StrategyMemoryRecord>,
        order: Vec<String>,
    }

    #[derive(serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyStrategyMemoryStateMaterial<'a> {
        schema_version: u32,
        state_kind: &'static str,
        generation: u64,
        digest: &'a str,
        state: &'a LegacyStrategyMemoryStateFixture,
    }

    #[derive(serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct LegacySignedStrategyMemoryStateFixture {
        state: LegacyStrategyMemoryStateFixture,
        digest: String,
        signature: DetachedSignature,
    }

    fn temp_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "swarm-memory-{name}-{}-{stamp}",
                std::process::id()
            ))
    }

    fn signed_strategy_candidate_bytes(
        store: &MemoryStrategyMemoryStore,
        memory: &StrategyMemory,
    ) -> Vec<u8> {
        let current = store.inner.read().unwrap().clone();
        let generation = current.state.generation.checked_add(1).unwrap();
        let predecessor_digest = current.state.order.last().and_then(|id| {
            current
                .state
                .memories
                .get(id)
                .map(|record| record.digest.clone())
        });
        let state_predecessor_digest = current.state.digest().unwrap();
        let record = StrategyMemoryRecord::new(
            memory.clone(),
            generation,
            predecessor_digest,
            &store.signer,
        )
        .unwrap();
        let mut next_state = current.state;
        next_state.generation = generation;
        next_state.predecessor_digest = Some(state_predecessor_digest);
        next_state
            .order
            .push(record.memory.memory_id.as_str().to_string());
        next_state
            .memories
            .insert(record.memory.memory_id.as_str().to_string(), record);
        let signed = sign_state_with_limit(
            next_state,
            &store.signer,
            &store.limits,
            store.max_memory_ttl_ticks,
        )
        .unwrap();
        serde_json::to_vec(&signed).unwrap()
    }

    fn root_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }

    fn strategy_size_class(error: StrategyMemoryStoreError) -> (String, usize) {
        match error {
            StrategyMemoryStoreError::ResourceLimit { resource, limit } => (resource, limit),
            other => panic!("expected persisted-size admission failure, got {other:?}"),
        }
    }

    #[test]
    fn memory_is_signed_deduplicated_and_retrieved_deterministically() {
        let store = MemoryStrategyMemoryStore::with_defaults(signer(1)).unwrap();
        let first = memory(2, "one");
        let inserted = store
            .append_at(first.clone(), GraphLogicalTime::new(100), 100)
            .unwrap();
        assert!(!inserted.idempotent);
        let duplicate = store
            .append_at(first, GraphLogicalTime::new(100), 100)
            .unwrap();
        assert!(duplicate.idempotent);
        assert_eq!(inserted.record, duplicate.record);
        let matches = store
            .retrieve_at(
                &GraphId::new("graph:test"),
                &HypothesisId::new("hypothesis:selected"),
                &BTreeSet::from([EvidenceId::new("evidence:one")]),
                GraphLogicalTime::new(150),
                8,
            )
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched.relevance_basis_points, 8_500);
        assert!(
            store
                .retrieve_at(
                    &GraphId::new("graph:other"),
                    &HypothesisId::new("hypothesis:selected"),
                    &BTreeSet::new(),
                    GraphLogicalTime::new(150),
                    8,
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn expired_prefix_is_compacted_before_memory_capacity_is_enforced() {
        let limits = GraphResourceLimits {
            max_memory_records: 1,
            ..GraphResourceLimits::default()
        };
        let first = memory(61, "expired-capacity-first");
        let second = memory(62, "expired-capacity-second");

        let memory_store =
            MemoryStrategyMemoryStore::new_with_max_memory_ttl(signer(60), limits.clone(), 100)
                .unwrap();
        memory_store
            .append_at(first.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        let appended = memory_store
            .append_at(second.clone(), GraphLogicalTime::new(111), 10)
            .unwrap();
        assert_eq!(appended.generation, 2);
        assert!(memory_store.load(&first.memory_id).unwrap().is_none());
        assert!(memory_store.load(&second.memory_id).unwrap().is_some());

        let path = temp_dir("expired-capacity-file");
        let key = signer(63);
        let file_store = FileStrategyMemoryStore::new_with_max_memory_ttl(
            &path,
            key.clone(),
            limits.clone(),
            100,
        )
        .unwrap();
        file_store
            .append_at(first.clone(), GraphLogicalTime::new(100), 10)
            .unwrap();
        let appended = file_store
            .append_at(second.clone(), GraphLogicalTime::new(111), 10)
            .unwrap();
        assert_eq!(appended.generation, 2);
        assert!(file_store.load(&first.memory_id).unwrap().is_none());
        drop(file_store);

        let reopened = FileStrategyMemoryStore::open_with_signer_and_max_memory_ttl(
            path.join("."),
            key,
            limits,
            100,
        )
        .unwrap();
        assert_eq!(reopened.root(), std::fs::canonicalize(&path).unwrap());
        assert!(reopened.load(&second.memory_id).unwrap().is_some());
        drop(reopened);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn legacy_signed_state_reopens_without_rewriting_its_authenticated_bytes() {
        let path = temp_dir("legacy-byte-exact");
        let key = signer(27);
        let limits = GraphResourceLimits::default();
        let store = FileStrategyMemoryStore::new(&path, key.clone(), limits.clone()).unwrap();
        let state_path = store.state_path().to_path_buf();
        drop(store);

        // Construct the exact Plan 03 wire shape: no expiry sidecar and no
        // deployment TTL field.  The fixture is signed independently instead
        // of being produced by the current serializer, so a new field cannot
        // accidentally hide a compatibility regression.
        let legacy_empty = LegacyStrategyMemoryStateFixture {
            schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
            limits: limits.clone(),
            generation: 0,
            predecessor_digest: None,
            memories: BTreeMap::new(),
            order: Vec::new(),
        };
        let legacy_empty_digest = sha256_hex(&canonical_json_bytes(&legacy_empty).unwrap());
        let legacy_memory = memory(28, "legacy-byte-exact");
        let legacy_record = StrategyMemoryRecord::new(legacy_memory, 1, None, &key).unwrap();
        let legacy_state = LegacyStrategyMemoryStateFixture {
            schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
            limits,
            generation: 1,
            predecessor_digest: Some(legacy_empty_digest),
            memories: BTreeMap::from([(
                legacy_record.memory.memory_id.as_str().to_string(),
                legacy_record.clone(),
            )]),
            order: vec![legacy_record.memory.memory_id.as_str().to_string()],
        };
        let legacy_digest = sha256_hex(&canonical_json_bytes(&legacy_state).unwrap());
        let material = LegacyStrategyMemoryStateMaterial {
            schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
            state_kind: STRATEGY_MEMORY_STATE_KIND,
            generation: legacy_state.generation,
            digest: &legacy_digest,
            state: &legacy_state,
        };
        let signature_bytes = canonical_json_bytes(&material).unwrap();
        let signed = LegacySignedStrategyMemoryStateFixture {
            state: legacy_state,
            digest: legacy_digest.clone(),
            signature: DetachedSignature {
                algorithm: "ed25519".to_string(),
                key_id: sha256_hex(key.public_key().as_bytes()),
                public_key_hex: key.public_key().to_hex(),
                signature_hex: key.sign(&signature_bytes).to_hex(),
            },
        };
        let legacy_bytes = serde_json::to_vec(&signed).unwrap();

        // Rebuild the sibling signed head/high-water/journal tuple against
        // the legacy digest so reopening exercises the real file protocol.
        let old_anchor = DurableMonotonicAnchor::new(&path, STRATEGY_MEMORY_STATE_KIND).unwrap();
        let anchor_namespace = old_anchor.path().parent().unwrap().to_path_buf();
        drop(old_anchor);
        fs::remove_dir_all(anchor_namespace).unwrap();
        let root_lock = DurableFileLock::acquire(&path.join(STRATEGY_MEMORY_LOCK_FILE)).unwrap();
        let stream_id = strategy_memory_stream_id(&path);
        let legacy_revision = GraphStoreRevision::new(1, legacy_digest.clone());
        let head = sign_state_head(
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            &legacy_revision,
            root_lock.generation(),
            &root_lock.identity_token(),
            &key,
        )
        .unwrap();
        root_lock
            .atomic_write_bytes(&state_path, &legacy_bytes)
            .unwrap();
        root_lock
            .atomic_write_json(&path.join(STRATEGY_MEMORY_ANCHOR_FILE), &head)
            .unwrap();
        let high_water = path.join(STRATEGY_MEMORY_HIGH_WATER_FILE);
        let high_water_tail = path.join(STRATEGY_MEMORY_HIGH_WATER_TAIL_FILE);
        let _ = fs::remove_file(&high_water);
        let _ = fs::remove_file(&high_water_tail);
        append_high_water(&root_lock, &high_water, &high_water_tail, &head).unwrap();

        let monotonic = DurableMonotonicAnchor::new(&path, STRATEGY_MEMORY_STATE_KIND).unwrap();
        let external_lock = monotonic.acquire_lock().unwrap();
        let initial = sign_external_commit_record(
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            0,
            &sha256_hex(
                &canonical_json_bytes(&LegacyStrategyMemoryStateFixture {
                    schema_version: STRATEGY_MEMORY_STORE_SCHEMA_VERSION,
                    limits: GraphResourceLimits::default(),
                    generation: 0,
                    predecessor_digest: None,
                    memories: BTreeMap::new(),
                    order: Vec::new(),
                })
                .unwrap(),
            ),
            0,
            ExternalCommitPhase::Commit,
            None,
            root_lock.generation(),
            &root_lock.identity_token(),
            &key,
        )
        .unwrap();
        monotonic
            .append_external_locked(&external_lock, &initial)
            .unwrap();
        let intent = sign_external_commit_record(
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            1,
            &legacy_digest,
            1,
            ExternalCommitPhase::Intent,
            Some(initial.record_digest.clone()),
            root_lock.generation(),
            &root_lock.identity_token(),
            &key,
        )
        .unwrap();
        monotonic
            .append_external_locked(&external_lock, &intent)
            .unwrap();
        let commit = sign_external_commit_record(
            STRATEGY_MEMORY_STATE_KIND,
            &stream_id,
            1,
            &legacy_digest,
            2,
            ExternalCommitPhase::Commit,
            Some(intent.record_digest.clone()),
            root_lock.generation(),
            &root_lock.identity_token(),
            &key,
        )
        .unwrap();
        monotonic
            .append_external_locked(&external_lock, &commit)
            .unwrap();
        drop(external_lock);
        drop(root_lock);

        let before = fs::read(&state_path).unwrap();
        let reopened =
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default())
                .unwrap();
        assert_eq!(
            reopened.load(&legacy_record.memory.memory_id).unwrap(),
            Some(legacy_record)
        );
        assert_eq!(fs::read(&state_path).unwrap(), before);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_memory_survives_restart_and_rejects_tamper_and_lock_contention() {
        let path = temp_dir("restart");
        let key = signer(3);
        let store =
            FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        let inserted = store.append(memory(4, "restart")).unwrap();
        let state_path = store.state_path().to_path_buf();
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(
                &path,
                key.clone(),
                GraphResourceLimits::default(),
            ),
            Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::LockContended { .. }
            ))
        ));
        drop(store);
        let reopened =
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default())
                .unwrap();
        assert_eq!(
            reopened
                .load(&inserted.record.memory.memory_id)
                .unwrap()
                .unwrap(),
            inserted.record
        );
        drop(reopened);
        let raw =
            fs::read_to_string(&state_path)
                .unwrap()
                .replacen("graph:test", "graph:tampered", 1);
        fs::write(&state_path, raw).unwrap();
        let error = FileStrategyMemoryStore::open_with_signer(
            &path,
            signer(3),
            GraphResourceLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StrategyMemoryStoreError::DigestMismatch { .. }
                | StrategyMemoryStoreError::InvalidSignature { .. }
                | StrategyMemoryStoreError::InvalidState { .. }
                | StrategyMemoryStoreError::GraphPersistence(GraphStoreError::Parse { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_memory_reopen_requires_exact_configured_limits() {
        let path = temp_dir("limits");
        let key = signer(20);
        let persisted_limits = GraphResourceLimits::default();
        let store = FileStrategyMemoryStore::new(&path, key.clone(), persisted_limits).unwrap();
        store.append(memory(21, "limits")).unwrap();
        drop(store);
        let tighter_limits = GraphResourceLimits {
            max_memory_records: 1,
            ..GraphResourceLimits::default()
        };
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(&path, key, tighter_limits),
            Err(StrategyMemoryStoreError::InvalidState { .. })
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn strategy_memory_wire_has_no_raw_telemetry_or_request_shape() {
        let encoded = serde_json::to_string(&memory(5, "privacy")).unwrap();
        assert!(!encoded.contains("TelemetryEvent"));
        assert!(!encoded.contains("command_line"));
        assert!(!encoded.contains("request_object"));
        assert!(!encoded.contains("serde_json::Value"));
    }

    #[test]
    fn file_memory_rejects_replayed_state_anchor() {
        let path = temp_dir("replay");
        let key = signer(6);
        let store =
            FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        let state_path = store.state_path().to_path_buf();
        let initial_state = fs::read(&state_path).unwrap();
        store.append(memory(7, "first")).unwrap();
        drop(store);
        fs::write(&state_path, initial_state).unwrap();
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default(),),
            Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::ReplayDetected { .. }
            )) | Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::AnchorMismatch { .. }
            ))
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn file_memory_refuses_full_root_snapshot_rollback_with_external_anchor() {
        let path = temp_dir("full-root-rollback");
        let key = signer(27);
        let store =
            FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let high_water_path = path.join(STRATEGY_MEMORY_HIGH_WATER_FILE);
        let old_state = std::fs::read(&state_path).unwrap();
        let old_anchor = std::fs::read(&anchor_path).unwrap();
        let old_high_water = std::fs::read(&high_water_path).unwrap();
        let external_anchor_path = store.monotonic_anchor.path().to_path_buf();
        let old_external_anchor = std::fs::read(&external_anchor_path).unwrap();

        store.append(memory(28, "full-root-rollback")).unwrap();
        let current_external_anchor = std::fs::read(&external_anchor_path).unwrap();
        assert_ne!(current_external_anchor, old_external_anchor);
        drop(store);

        // Restoring state, head, and the local high-water log cannot restore
        // the sibling monotonic anchor, so reopening must reject the replay.
        std::fs::write(&state_path, old_state).unwrap();
        std::fs::write(&anchor_path, old_anchor).unwrap();
        std::fs::write(&high_water_path, old_high_water).unwrap();
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default(),),
            Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::ReplayDetected { .. }
            )) | Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::AnchorMismatch { .. }
            ))
        ));
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn file_memory_requires_exact_anchor_successor_and_predecessor() {
        let promote_path = temp_dir("head-promote");
        let key = signer(22);
        let store = FileStrategyMemoryStore::new(
            &promote_path,
            key.clone(),
            GraphResourceLimits::default(),
        )
        .unwrap();
        let anchor_path = store.anchor_path().to_path_buf();
        let initial_anchor = fs::read(&anchor_path).unwrap();
        store.append(memory(23, "promote")).unwrap();
        drop(store);
        fs::write(&anchor_path, initial_anchor).unwrap();
        let reopened = FileStrategyMemoryStore::open_with_signer(
            &promote_path,
            key.clone(),
            GraphResourceLimits::default(),
        )
        .unwrap();
        assert_eq!(reopened.list(8).unwrap().len(), 1);
        drop(reopened);
        let _ = fs::remove_dir_all(promote_path);

        let gap_path = temp_dir("head-gap");
        let store =
            FileStrategyMemoryStore::new(&gap_path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        let anchor_path = store.anchor_path().to_path_buf();
        let initial_anchor = fs::read(&anchor_path).unwrap();
        store.append(memory(25, "gap-one")).unwrap();
        store.append(memory(26, "gap-two")).unwrap();
        drop(store);
        fs::write(&anchor_path, initial_anchor).unwrap();
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(
                &gap_path,
                key.clone(),
                GraphResourceLimits::default(),
            ),
            Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::ReplayDetected { .. }
            ))
        ));
        let _ = fs::remove_dir_all(gap_path);

        let mismatch_path = temp_dir("head-mismatch");
        let store = FileStrategyMemoryStore::new(
            &mismatch_path,
            key.clone(),
            GraphResourceLimits::default(),
        )
        .unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let initial_anchor = fs::read(&anchor_path).unwrap();
        store.append(memory(24, "mismatch")).unwrap();
        let mut state: SignedStrategyMemoryState = read_json_file(&state_path)
            .map_err(StrategyMemoryStoreError::GraphPersistence)
            .unwrap();
        state.state.predecessor_digest = Some("forged-state-predecessor".to_string());
        let signed = sign_state_with_limit(
            state.state,
            &key,
            &GraphResourceLimits::default(),
            MAX_STRATEGY_MEMORY_TTL_TICKS,
        )
        .unwrap();
        atomic_write_json(&state_path, &signed).unwrap();
        drop(store);
        fs::write(&anchor_path, initial_anchor).unwrap();
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(
                &mismatch_path,
                key,
                GraphResourceLimits::default(),
            ),
            Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::AnchorMismatch { .. }
            ))
        ));
        let _ = fs::remove_dir_all(mismatch_path);
    }

    #[test]
    fn file_memory_transaction_stage_recovers_orphaned_intent_at_each_boundary() {
        for (index, boundary) in [
            CommitFailureBoundary::ExternalIntent,
            CommitFailureBoundary::State,
            CommitFailureBoundary::Head,
            CommitFailureBoundary::HighWater,
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_dir(&format!("txn-recovery-{index}"));
            let key = signer(40);
            let store =
                FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                    .unwrap();
            install_test_commit_failure(path.clone(), boundary);
            assert!(matches!(
                store.append(memory(41, &format!("txn-{index}"))),
                Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::Write { .. }
                ))
            ));
            drop(store);
            let reopened = FileStrategyMemoryStore::open_with_signer(
                &path,
                key,
                GraphResourceLimits::default(),
            )
            .unwrap();
            assert!(reopened.list(8).unwrap().is_empty());
            drop(reopened);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn oversized_strategy_append_has_memory_file_admission_parity_and_no_mutation() {
        // Valid public memory records stay well below the production 16 MiB
        // envelope ceiling. Measure one valid candidate with the production
        // signer, then lower only this test thread's ceiling to exercise the
        // exact boundary without allocating an artificial oversized record.
        for (index, (offset, should_reject)) in [(0_usize, true), (1, false), (2, false)]
            .into_iter()
            .enumerate()
        {
            let path = temp_dir(&format!("oversized-strategy-{index}"));
            let key = signer(52);
            let memory_store = MemoryStrategyMemoryStore::with_defaults(key.clone()).unwrap();
            let file_store =
                FileStrategyMemoryStore::new(&path, key, GraphResourceLimits::default()).unwrap();
            let candidate = memory(53, &format!("oversized-{index}"));
            let candidate_bytes = signed_strategy_candidate_bytes(&memory_store, &candidate);
            let baseline_memory_bytes = {
                let state = memory_store.inner.read().unwrap().clone();
                serde_json::to_vec(&state).unwrap()
            };
            let baseline_file_bytes = fs::read(file_store.state_path()).unwrap();
            assert_eq!(baseline_memory_bytes, baseline_file_bytes);
            assert!(candidate_bytes.len() > baseline_memory_bytes.len());

            let before_files = root_files(&path);
            let limit = candidate_bytes.len().checked_sub(1).unwrap() + offset;
            let limit_guard = install_test_persisted_json_limit(limit);
            let memory_result = memory_store.append(candidate.clone());
            let file_result = file_store.append(candidate);
            if should_reject {
                let memory_class = strategy_size_class(memory_result.unwrap_err());
                let file_class = strategy_size_class(file_result.unwrap_err());
                assert_eq!(memory_class, file_class);
                assert_eq!(memory_class, ("persisted_file_bytes".to_string(), limit));
                let after_memory_bytes = {
                    let state = memory_store.inner.read().unwrap().clone();
                    serde_json::to_vec(&state).unwrap()
                };
                assert_eq!(after_memory_bytes, baseline_memory_bytes);
                assert_eq!(
                    fs::read(file_store.state_path()).unwrap(),
                    baseline_file_bytes
                );
                assert_eq!(root_files(&path), before_files);
                assert_eq!(
                    memory_store.state_digest().unwrap(),
                    file_store.state_digest().unwrap()
                );
            } else {
                let memory_result = memory_result.unwrap();
                let file_result = file_result.unwrap();
                assert!(!memory_result.idempotent);
                assert!(!file_result.idempotent);
                assert_eq!(memory_result.record, file_result.record);
                let after_memory_bytes = {
                    let state = memory_store.inner.read().unwrap().clone();
                    serde_json::to_vec(&state).unwrap()
                };
                let after_file_bytes = fs::read(file_store.state_path()).unwrap();
                assert_eq!(after_memory_bytes, after_file_bytes);
                assert_ne!(after_memory_bytes, baseline_memory_bytes);
                assert_eq!(
                    memory_store.state_digest().unwrap(),
                    file_store.state_digest().unwrap()
                );
            }
            drop(limit_guard);
            drop(file_store);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn external_memory_rotation_manifest_recovers_after_active_data_boundary() {
        let path = temp_dir("external-rotation-recovery");
        let key = signer(44);
        let store =
            FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        let external_lock = store.monotonic_anchor.acquire_lock().unwrap();
        let records = store
            .monotonic_anchor
            .read_records_locked::<crate::hypothesis_graph_store::DurableExternalCommitRecord>(
                &external_lock,
            )
            .unwrap();
        let journal = verify_external_journal(
            &records,
            STRATEGY_MEMORY_STATE_KIND,
            &strategy_memory_stream_id(&path),
            &store.signer_id,
            store.lock.generation(),
            &store.lock.identity_token(),
        )
        .unwrap();
        install_test_rotation_failure(
            store
                .monotonic_anchor
                .rotation_manifest_path_for_test()
                .to_path_buf(),
        );
        assert!(matches!(
            store
                .monotonic_anchor
                .rotate_for_test_locked(&external_lock, &journal.committed, &key,),
            Err(GraphStoreError::Write { .. })
        ));
        drop(external_lock);
        drop(store);
        let reopened =
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default())
                .unwrap();
        assert!(reopened.list(8).unwrap().is_empty());
        assert!(
            !reopened
                .monotonic_anchor
                .rotation_manifest_path_for_test()
                .exists()
        );
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn external_memory_journal_tail_rejects_valid_prefix_truncation_with_root_rollback() {
        let path = temp_dir("external-prefix-truncation");
        let key = signer(42);
        let store =
            FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        let state_path = store.state_path().to_path_buf();
        let anchor_path = store.anchor_path().to_path_buf();
        let high_water_path = path.join(STRATEGY_MEMORY_HIGH_WATER_FILE);
        let high_water_tail_path = path.join(STRATEGY_MEMORY_HIGH_WATER_TAIL_FILE);
        let old_state = fs::read(&state_path).unwrap();
        let old_anchor = fs::read(&anchor_path).unwrap();
        let old_high_water = fs::read(&high_water_path).unwrap();
        let old_high_water_tail = fs::read(&high_water_tail_path).unwrap();
        let external_path = store.monotonic_anchor.path().to_path_buf();
        let old_external = fs::read(&external_path).unwrap();
        store.append(memory(43, "external-prefix")).unwrap();
        drop(store);
        fs::write(&state_path, old_state).unwrap();
        fs::write(&anchor_path, old_anchor).unwrap();
        fs::write(&high_water_path, old_high_water).unwrap();
        fs::write(&high_water_tail_path, old_high_water_tail).unwrap();
        fs::write(&external_path, old_external).unwrap();
        assert!(matches!(
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default(),),
            Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::ReplayDetected { .. }
            )) | Err(StrategyMemoryStoreError::GraphPersistence(
                GraphStoreError::AnchorMismatch { .. }
            ))
        ));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn memory_rollback_manifest_recovers_after_each_replacement() {
        for (index, boundary) in [
            CommitFailureBoundary::RollbackState,
            CommitFailureBoundary::RollbackHead,
            CommitFailureBoundary::RollbackHighWater,
            CommitFailureBoundary::RollbackHighWaterTail,
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_dir(&format!("rollback-manifest-{index}"));
            let key = signer(45);
            let store =
                FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                    .unwrap();
            install_test_commit_failure(path.clone(), CommitFailureBoundary::State);
            assert!(matches!(
                store.append(memory(46, &format!("rollback-{index}"))),
                Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::Write { .. }
                ))
            ));
            drop(store);
            install_test_commit_failure(path.clone(), boundary);
            assert!(matches!(
                FileStrategyMemoryStore::open_with_signer(
                    &path,
                    key.clone(),
                    GraphResourceLimits::default(),
                ),
                Err(StrategyMemoryStoreError::GraphPersistence(
                    GraphStoreError::Write { .. }
                ))
            ));
            let reopened = FileStrategyMemoryStore::open_with_signer(
                &path,
                key,
                GraphResourceLimits::default(),
            )
            .unwrap();
            assert!(reopened.list(8).unwrap().is_empty());
            drop(reopened);
            let _ = fs::remove_dir_all(path);
        }
    }

    #[test]
    fn memory_external_rotation_keeps_active_record_count_for_followup_append() {
        let path = temp_dir("external-rotation-count");
        let key = signer(47);
        let store =
            FileStrategyMemoryStore::new(&path, key.clone(), GraphResourceLimits::default())
                .unwrap();
        store.append(memory(48, "before-rotation")).unwrap();
        let external_lock = store.monotonic_anchor.acquire_lock().unwrap();
        let records = store
            .monotonic_anchor
            .read_records_locked::<crate::hypothesis_graph_store::DurableExternalCommitRecord>(
                &external_lock,
            )
            .unwrap();
        let journal = verify_external_journal(
            &records,
            STRATEGY_MEMORY_STATE_KIND,
            &strategy_memory_stream_id(&path),
            &store.signer_id,
            store.lock.generation(),
            &store.lock.identity_token(),
        )
        .unwrap();
        assert!(
            store
                .monotonic_anchor
                .rotate_for_test_locked(&external_lock, &journal.committed, &key)
                .unwrap()
        );
        drop(external_lock);
        store.append(memory(49, "after-rotation")).unwrap();
        drop(store);
        let reopened =
            FileStrategyMemoryStore::open_with_signer(&path, key, GraphResourceLimits::default())
                .unwrap();
        assert_eq!(reopened.list(8).unwrap().len(), 2);
        drop(reopened);
        let _ = fs::remove_dir_all(path);
    }
}
