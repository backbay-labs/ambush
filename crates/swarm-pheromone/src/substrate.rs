//! Core substrate operations.

use crate::jetstream::JetStreamPheromoneSubstrate;
use async_trait::async_trait;
use ed25519_dalek::{Signature as DalekSignature, SigningKey, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::agent::AgentRole;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, EscalationRecord, PheromoneConcentration, PheromoneDeposit,
    ThreatClass, ThreatClassConfig, ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::signed_state::{SignedStateEnvelope, SignedStateError, SignedStateExpectation};
use swarm_core::types::{AgentId, SWARM_PROVIDENCE_FEEDBACK_SCHEMA, Severity};
use swarm_crypto::sha256_hex;

pub(crate) const BEHAVIORAL_BASELINE_STATE_KIND: &str = "behavioral_baseline_snapshot";
type BehavioralBaselineEnvelope = SignedStateEnvelope<BehavioralBaselineSnapshot>;

pub(crate) const MAX_ACTIVE_DEPOSITS: usize = 10_000;
pub(crate) const MAX_ACTIVE_DEPOSIT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_SINGLE_DEPOSIT_BYTES: usize = 256 * 1024;
const COMPACTED_DEPOSIT_COUNT: usize = 7_500;
const COMPACTED_DEPOSIT_BYTES: usize = 24 * 1024 * 1024;
const MAX_LOCAL_DEPOSIT_JOURNAL_BYTES: u64 =
    (MAX_ACTIVE_DEPOSIT_BYTES + MAX_ACTIVE_DEPOSITS) as u64;
const MAX_DEPOSIT_OPERATION_LEDGER_ENTRIES: usize = 131_072;
const MAX_LOCAL_DEPOSIT_OPERATION_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DEPOSIT_OPERATION_ID_BYTES: usize = 1_024;

// Zero-strength deposits are used for typed control records (for example,
// Sphinx memory queries/answers and Providence feedback), not concentration
// evidence. They must remain durable long enough for consumers to observe
// them, while still expiring under the configured decay policy so delayed
// control-record floods cannot consume the bounded retention window.
const CONTROL_RECORD_RETENTION_STRENGTH: f64 = 1.0;
const MAX_LIVE_DEPOSIT_FUTURE_SKEW_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, Default)]
enum DepositAdmissionClock {
    #[default]
    System,
    Replay,
}

impl DepositAdmissionClock {
    fn trusted_now(self) -> Result<Option<i64>, SubstrateError> {
        match self {
            Self::System => trusted_system_unix_seconds().map(Some),
            Self::Replay => Ok(None),
        }
    }
}

pub(crate) fn trusted_system_unix_seconds() -> Result<i64, SubstrateError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| SubstrateError::Clock {
            reason: format!("system clock is before the Unix epoch: {source}"),
        })?;
    i64::try_from(elapsed.as_secs()).map_err(|_| SubstrateError::Clock {
        reason: "system clock exceeds the supported signed Unix timestamp range".to_string(),
    })
}

#[cfg(all(test, unix))]
static REWRITE_PARENT_SYNC_FAILURE_PATH: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

#[cfg(all(test, unix))]
fn rewrite_parent_sync_failure_path() -> &'static Mutex<Option<PathBuf>> {
    REWRITE_PARENT_SYNC_FAILURE_PATH.get_or_init(|| Mutex::new(None))
}

/// Errors raised by the pheromone substrate.
#[derive(Debug, thiserror::Error)]
pub enum SubstrateError {
    #[error("substrate lock poisoned")]
    PoisonedLock,

    #[error("failed to read substrate journal `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write substrate journal `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "substrate journal replacement `{path}` is visible but its directory entry could not be made crash-durable: {source}"
    )]
    DurabilityOutcomeUnknown {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse substrate journal `{path}` line {line}: {source}")]
    Parse {
        path: PathBuf,
        line: usize,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to encode substrate payload for {context}: {source}")]
    Encode {
        context: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to decode substrate payload from `{location}`: {source}")]
    Decode {
        location: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("nats operation `{operation}` failed: {reason}")]
    Nats {
        operation: &'static str,
        reason: String,
    },

    #[error("unsupported substrate backend `{backend}`: {reason}")]
    UnsupportedBackend {
        backend: &'static str,
        reason: String,
    },

    #[error("deposit rejected: {reason}")]
    InvalidDeposit { reason: String },

    #[error("trusted substrate clock is unavailable: {reason}")]
    Clock { reason: String },

    #[error(
        "deposit timestamp {timestamp} exceeds trusted current time {trusted_now} plus the {max_future_skew_secs}-second future-skew allowance"
    )]
    FutureDeposit {
        timestamp: i64,
        trusted_now: i64,
        max_future_skew_secs: i64,
    },

    #[error(
        "deposit decay half-life {declared_half_life_secs} does not match the effective threat-class policy half-life {effective_half_life_secs}"
    )]
    DepositPolicyMismatch {
        declared_half_life_secs: f64,
        effective_half_life_secs: f64,
    },

    #[error(
        "deposit timestamp {timestamp} is already evaporated at logical timestamp high-water {timestamp_high_water}"
    )]
    ExpiredDeposit {
        timestamp: i64,
        timestamp_high_water: i64,
    },

    #[error(
        "substrate journal `{path}` is {observed_bytes} bytes; hard limit is {max_bytes} bytes"
    )]
    JournalLimitExceeded {
        path: PathBuf,
        observed_bytes: u64,
        max_bytes: u64,
    },

    #[error(
        "behavioral baseline snapshot verification failed for strategy `{strategy_id}`: {source}"
    )]
    InvalidBehavioralBaseline {
        strategy_id: String,
        #[source]
        source: SignedStateError,
    },
}

/// Canonical payload used for signing and verifying pheromone deposits.
///
/// The fields here must match the signing side exactly (same order, same types).
/// Both `pipeline.rs` and `stalker_agent.rs` serialize this struct to produce the
/// bytes that are signed; `validate_deposit_signature` deserializes and re-verifies.
#[derive(Serialize)]
pub struct DepositSigningPayload<'a> {
    pub schema_version: u32,
    pub indicator: &'a serde_json::Value,
    pub threat_class: &'a ThreatClass,
    pub severity: &'a Severity,
    pub confidence: f64,
    pub timestamp: i64,
    pub decay_half_life: f64,
    pub agent_id: &'a AgentId,
    pub agent_identity: &'a str,
    pub agent_role: Option<AgentRole>,
}

#[derive(Serialize)]
struct LegacyDepositSigningPayload<'a> {
    pub indicator: &'a serde_json::Value,
    pub threat_class: &'a ThreatClass,
    pub severity: &'a Severity,
    pub confidence: f64,
    pub timestamp: i64,
    pub decay_half_life: f64,
    pub agent_id: &'a AgentId,
    pub agent_identity: &'a str,
    pub agent_role: Option<AgentRole>,
}

pub(crate) fn signing_payload_bytes_for_deposit(
    deposit: &PheromoneDeposit,
) -> Result<Vec<u8>, serde_json::Error> {
    if deposit.schema_version == PheromoneDeposit::previous_schema_version() {
        let payload = LegacyDepositSigningPayload {
            indicator: &deposit.indicator,
            threat_class: &deposit.threat_class,
            severity: &deposit.severity,
            confidence: deposit.confidence,
            timestamp: deposit.timestamp,
            decay_half_life: deposit.decay_half_life,
            agent_id: &deposit.agent_id,
            agent_identity: &deposit.agent_identity,
            agent_role: deposit.agent_role,
        };
        serde_json::to_vec(&payload)
    } else {
        let payload = DepositSigningPayload {
            schema_version: deposit.schema_version,
            indicator: &deposit.indicator,
            threat_class: &deposit.threat_class,
            severity: &deposit.severity,
            confidence: deposit.confidence,
            timestamp: deposit.timestamp,
            decay_half_life: deposit.decay_half_life,
            agent_id: &deposit.agent_id,
            agent_identity: &deposit.agent_identity,
            agent_role: deposit.agent_role,
        };
        serde_json::to_vec(&payload)
    }
}

fn ensure_supported_deposit_schema_version(schema_version: u32) -> Result<(), SubstrateError> {
    if PheromoneDeposit::supports_schema_version(schema_version) {
        return Ok(());
    }

    Err(SubstrateError::InvalidDeposit {
        reason: format!("unsupported pheromone deposit schema version `{schema_version}`"),
    })
}

pub(crate) fn decode_deposit_payload(
    payload: &[u8],
    location: impl Into<String>,
) -> Result<VerifiedDeposit, SubstrateError> {
    let location = location.into();
    let raw =
        serde_json::from_slice::<JsonValue>(payload).map_err(|source| SubstrateError::Decode {
            location: location.clone(),
            source,
        })?;
    let schema_version = raw
        .get("schema_version")
        .and_then(JsonValue::as_u64)
        .map(|value| value as u32)
        .unwrap_or_else(PheromoneDeposit::previous_schema_version);
    ensure_supported_deposit_schema_version(schema_version)?;
    let deposit = serde_json::from_value::<PheromoneDeposit>(raw)
        .map_err(|source| SubstrateError::Decode { location, source })?;
    VerifiedDeposit::admit(deposit)
}

/// Validate that a [`PheromoneDeposit`] carries a valid Ed25519 signature
/// over its canonical content. Returns `Err(SubstrateError::InvalidDeposit)`
/// when the signature is missing, malformed, or does not verify.
pub fn validate_deposit_signature(deposit: &PheromoneDeposit) -> Result<(), SubstrateError> {
    ensure_supported_deposit_schema_version(deposit.schema_version)?;
    if deposit.signature.is_empty() {
        return Err(SubstrateError::InvalidDeposit {
            reason: "empty signature".into(),
        });
    }
    if deposit.agent_key.is_empty() {
        return Err(SubstrateError::InvalidDeposit {
            reason: "empty agent_key".into(),
        });
    }

    let key_bytes: [u8; 32] =
        deposit
            .agent_key
            .as_slice()
            .try_into()
            .map_err(|_| SubstrateError::InvalidDeposit {
                reason: format!(
                    "agent_key must be 32 bytes, got {}",
                    deposit.agent_key.len()
                ),
            })?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|err| SubstrateError::InvalidDeposit {
            reason: format!("invalid agent_key: {err}"),
        })?;

    let sig_bytes: [u8; 64] =
        deposit
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SubstrateError::InvalidDeposit {
                reason: format!(
                    "signature must be 64 bytes, got {}",
                    deposit.signature.len()
                ),
            })?;
    let signature = DalekSignature::from_bytes(&sig_bytes);

    let payload_bytes =
        signing_payload_bytes_for_deposit(deposit).map_err(|source| SubstrateError::Encode {
            context: "deposit signing payload".into(),
            source,
        })?;

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|err| SubstrateError::InvalidDeposit {
            reason: format!("signature verification failed: {err}"),
        })?;

    let derived_agent_id = AgentId::from_verifying_key(&verifying_key);
    let agent_id_matches = derived_agent_id == deposit.agent_id
        || deposit
            .agent_id
            .0
            .strip_prefix(&derived_agent_id.0)
            .is_some_and(|suffix| suffix.starts_with(':') && suffix.len() > 1);
    if !agent_id_matches {
        return Err(SubstrateError::InvalidDeposit {
            reason: format!(
                "agent_id `{}` does not match signing key identity `{}`",
                deposit.agent_id, derived_agent_id
            ),
        });
    }
    if deposit.agent_identity != derived_agent_id.to_string() {
        return Err(SubstrateError::InvalidDeposit {
            reason: format!(
                "agent_identity `{}` does not match signing key identity `{}`",
                deposit.agent_identity, derived_agent_id
            ),
        });
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct DepositRetentionLimits {
    max_count: usize,
    max_bytes: usize,
    compacted_count: usize,
    compacted_bytes: usize,
    max_journal_bytes: u64,
}

impl Default for DepositRetentionLimits {
    fn default() -> Self {
        Self {
            max_count: MAX_ACTIVE_DEPOSITS,
            max_bytes: MAX_ACTIVE_DEPOSIT_BYTES,
            compacted_count: COMPACTED_DEPOSIT_COUNT,
            compacted_bytes: COMPACTED_DEPOSIT_BYTES,
            max_journal_bytes: MAX_LOCAL_DEPOSIT_JOURNAL_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedDeposit {
    deposit: PheromoneDeposit,
    encoded_len: usize,
}

impl VerifiedDeposit {
    pub(crate) fn admit(deposit: PheromoneDeposit) -> Result<Self, SubstrateError> {
        validate_deposit_numeric_fields(&deposit)?;
        let encoded_len = serde_json::to_vec(&deposit)
            .map_err(|source| SubstrateError::Encode {
                context: "verified pheromone deposit".to_string(),
                source,
            })?
            .len();
        if encoded_len > MAX_SINGLE_DEPOSIT_BYTES {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "encoded deposit is {encoded_len} bytes; hard limit is {MAX_SINGLE_DEPOSIT_BYTES} bytes"
                ),
            });
        }
        validate_deposit_signature(&deposit)?;
        let _ = deposit_operation_id(&deposit)?;
        Ok(Self {
            deposit,
            encoded_len,
        })
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.encoded_len
    }
}

pub(crate) fn deposit_operation_id(
    deposit: &PheromoneDeposit,
) -> Result<Option<String>, SubstrateError> {
    let Some(indicator) = deposit.indicator.as_object() else {
        return Ok(None);
    };
    if indicator.get("schema").and_then(JsonValue::as_str) != Some(SWARM_PROVIDENCE_FEEDBACK_SCHEMA)
    {
        return Ok(None);
    }
    let Some(feedback_id) = indicator
        .get("feedback_id")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let operation_id = format!(
        "swarm-providence-feedback-deposit-v1\0{}\0{feedback_id}",
        deposit.agent_identity
    );
    if operation_id.len() > MAX_DEPOSIT_OPERATION_ID_BYTES {
        return Err(SubstrateError::InvalidDeposit {
            reason: format!(
                "Providence feedback operation id exceeds the {MAX_DEPOSIT_OPERATION_ID_BYTES}-byte hard limit"
            ),
        });
    }
    Ok(Some(operation_id))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DepositOperationRecord {
    operation_id: String,
    deposit_digest: String,
}

#[derive(Debug, Clone, Default)]
struct DepositOperationLedger {
    records: BTreeMap<String, String>,
    insertion_order: VecDeque<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepositOperationInsert {
    AlreadyRecorded,
    Inserted { evicted: usize },
}

impl DepositOperationLedger {
    fn already_recorded(&self, candidate: &DepositOperationRecord) -> Result<bool, SubstrateError> {
        let Some(existing_digest) = self.records.get(&candidate.operation_id) else {
            return Ok(false);
        };
        if existing_digest == &candidate.deposit_digest {
            Ok(true)
        } else {
            Err(SubstrateError::InvalidDeposit {
                reason:
                    "Providence feedback operation id was reused with a different signed deposit"
                        .to_string(),
            })
        }
    }

    fn insert_with_limit(
        &mut self,
        candidate: &DepositOperationRecord,
        maximum_entries: usize,
    ) -> Result<DepositOperationInsert, SubstrateError> {
        if self.already_recorded(candidate)? {
            return Ok(DepositOperationInsert::AlreadyRecorded);
        }
        if maximum_entries == 0 {
            return Err(SubstrateError::InvalidDeposit {
                reason: "Providence feedback operation ledger capacity must be nonzero".to_string(),
            });
        }

        let mut evicted = 0usize;
        while self.records.len() >= maximum_entries {
            let Some(oldest) = self.insertion_order.pop_front() else {
                return Err(SubstrateError::InvalidDeposit {
                    reason: "Providence feedback operation ledger order is inconsistent"
                        .to_string(),
                });
            };
            if self.records.remove(&oldest).is_some() {
                evicted = evicted.saturating_add(1);
            }
        }
        self.records.insert(
            candidate.operation_id.clone(),
            candidate.deposit_digest.clone(),
        );
        self.insertion_order
            .push_back(candidate.operation_id.clone());
        Ok(DepositOperationInsert::Inserted { evicted })
    }

    fn evict_oldest(&mut self) -> Result<bool, SubstrateError> {
        let Some(oldest) = self.insertion_order.pop_front() else {
            return Ok(false);
        };
        if self.records.remove(&oldest).is_none() {
            return Err(SubstrateError::InvalidDeposit {
                reason: "Providence feedback operation ledger order is inconsistent".to_string(),
            });
        }
        Ok(true)
    }

    fn ordered_records(&self) -> Result<Vec<DepositOperationRecord>, SubstrateError> {
        if self.records.len() != self.insertion_order.len() {
            return Err(SubstrateError::InvalidDeposit {
                reason: "Providence feedback operation ledger order is inconsistent".to_string(),
            });
        }
        self.insertion_order
            .iter()
            .map(|operation_id| {
                self.records
                    .get(operation_id)
                    .map(|deposit_digest| DepositOperationRecord {
                        operation_id: operation_id.clone(),
                        deposit_digest: deposit_digest.clone(),
                    })
                    .ok_or_else(|| SubstrateError::InvalidDeposit {
                        reason: "Providence feedback operation ledger order is inconsistent"
                            .to_string(),
                    })
            })
            .collect()
    }
}

fn deposit_operation_record(
    deposit: &VerifiedDeposit,
) -> Result<Option<DepositOperationRecord>, SubstrateError> {
    let Some(operation_id) = deposit_operation_id(deposit)? else {
        return Ok(None);
    };
    let canonical =
        serde_json::to_vec(&deposit.deposit).map_err(|source| SubstrateError::Encode {
            context: "idempotent pheromone deposit".to_string(),
            source,
        })?;
    Ok(Some(DepositOperationRecord {
        operation_id,
        deposit_digest: sha256_hex(&canonical),
    }))
}

fn insert_deposit_operation(
    operations: &mut DepositOperationLedger,
    operation: &DepositOperationRecord,
) -> Result<DepositOperationInsert, SubstrateError> {
    operations.insert_with_limit(operation, MAX_DEPOSIT_OPERATION_LEDGER_ENTRIES)
}

fn exact_deposit_operation_already_retained(
    entries: &[VerifiedDeposit],
    candidate: &VerifiedDeposit,
) -> Result<bool, SubstrateError> {
    let Some(operation_id) = deposit_operation_id(candidate)? else {
        return Ok(false);
    };
    let mut existing = None;
    for entry in entries {
        if deposit_operation_id(entry)?.as_deref() == Some(operation_id.as_str()) {
            existing = Some(entry);
            break;
        }
    }
    let Some(existing) = existing else {
        return Ok(false);
    };
    let existing_bytes =
        serde_json::to_vec(&existing.deposit).map_err(|source| SubstrateError::Encode {
            context: "retained idempotent pheromone deposit".to_string(),
            source,
        })?;
    let candidate_bytes =
        serde_json::to_vec(&candidate.deposit).map_err(|source| SubstrateError::Encode {
            context: "candidate idempotent pheromone deposit".to_string(),
            source,
        })?;
    if existing_bytes == candidate_bytes {
        Ok(true)
    } else {
        Err(SubstrateError::InvalidDeposit {
            reason: "Providence feedback operation id was reused with a different signed deposit"
                .to_string(),
        })
    }
}

fn validate_deposit_numeric_fields(deposit: &PheromoneDeposit) -> Result<(), SubstrateError> {
    if !deposit.confidence.is_finite() || !(0.0..=1.0).contains(&deposit.confidence) {
        return Err(SubstrateError::InvalidDeposit {
            reason: format!(
                "confidence must be finite and between 0.0 and 1.0, got {}",
                deposit.confidence
            ),
        });
    }
    if !deposit.decay_half_life.is_finite() || deposit.decay_half_life <= 0.0 {
        return Err(SubstrateError::InvalidDeposit {
            reason: format!(
                "decay_half_life must be finite and greater than 0.0, got {}",
                deposit.decay_half_life
            ),
        });
    }
    if deposit.timestamp < 0 {
        return Err(SubstrateError::InvalidDeposit {
            reason: format!(
                "timestamp must be a nonnegative Unix timestamp in seconds, got {}",
                deposit.timestamp
            ),
        });
    }
    Ok(())
}

impl Deref for VerifiedDeposit {
    type Target = PheromoneDeposit;

    fn deref(&self) -> &Self::Target {
        &self.deposit
    }
}

#[derive(Debug, Clone, Default)]
struct RetainedDeposits {
    entries: Vec<VerifiedDeposit>,
    encoded_bytes: usize,
    timestamp_high_water: BTreeMap<ThreatClass, i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DepositRetentionPartition {
    threat_class: ThreatClass,
    signer_identity: String,
    control_record: bool,
}

impl DepositRetentionPartition {
    fn for_deposit(deposit: &PheromoneDeposit) -> Self {
        Self {
            threat_class: deposit.threat_class.clone(),
            // `agent_identity` is bound exactly to the signing key by
            // `validate_deposit_signature`; unlike `agent_id`, it cannot carry
            // attacker-selected strategy suffixes that manufacture partitions.
            signer_identity: deposit.agent_identity.clone(),
            control_record: deposit.confidence == 0.0,
        }
    }
}

#[derive(Debug, Default)]
struct DepositRetentionPartitionState {
    indexes: VecDeque<usize>,
    encoded_bytes: usize,
}

impl RetainedDeposits {
    fn push(
        &mut self,
        deposit: VerifiedDeposit,
        limits: DepositRetentionLimits,
        policy_half_life_secs: f64,
        evaporation_threshold: f64,
        trusted_now: Option<i64>,
    ) -> Result<usize, SubstrateError> {
        let threat_class = deposit.threat_class.clone();
        let logical_high_water = self
            .timestamp_high_water
            .get(&threat_class)
            .map_or(deposit.timestamp, |current| {
                (*current).max(deposit.timestamp)
            });
        let timestamp_high_water =
            trusted_now.map_or(logical_high_water, |now| now.max(logical_high_water));
        validate_deposit_retention(
            &deposit,
            timestamp_high_water,
            policy_half_life_secs,
            evaporation_threshold,
            trusted_now,
        )?;
        self.timestamp_high_water
            .insert(threat_class, timestamp_high_water);
        self.encoded_bytes = self.encoded_bytes.saturating_add(deposit.encoded_len);
        self.entries.push(deposit);
        Ok(self.compact_if_needed(limits))
    }

    fn compact_if_needed(&mut self, limits: DepositRetentionLimits) -> usize {
        if self.entries.len() <= limits.max_count && self.encoded_bytes <= limits.max_bytes {
            return 0;
        }
        let mut partitions =
            BTreeMap::<DepositRetentionPartition, DepositRetentionPartitionState>::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let partition = partitions
                .entry(DepositRetentionPartition::for_deposit(entry))
                .or_default();
            partition.indexes.push_back(index);
            partition.encoded_bytes = partition.encoded_bytes.saturating_add(entry.encoded_len);
        }

        let mut removed = vec![false; self.entries.len()];
        let mut remaining_count = self.entries.len();
        while remaining_count > 1
            && (remaining_count > limits.compacted_count
                || self.encoded_bytes > limits.compacted_bytes)
        {
            let count_is_over_limit = remaining_count > limits.compacted_count;
            let selected = partitions
                .iter()
                .filter(|(_, state)| !state.indexes.is_empty())
                .max_by(|(left_key, left), (right_key, right)| {
                    let primary = if count_is_over_limit {
                        left.indexes.len().cmp(&right.indexes.len())
                    } else {
                        left.encoded_bytes.cmp(&right.encoded_bytes)
                    };
                    primary
                        // Equal-size partitions retain the historical FIFO
                        // behavior, which is deterministic and preserves the
                        // feedback tombstone cleanup contract below.
                        .then_with(|| right.indexes.front().cmp(&left.indexes.front()))
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(key, _)| key.clone());
            let Some(selected) = selected else {
                break;
            };
            let Some(partition) = partitions.get_mut(&selected) else {
                break;
            };
            let Some(index) = partition.indexes.pop_front() else {
                break;
            };
            let encoded_len = self.entries[index].encoded_len;
            partition.encoded_bytes = partition.encoded_bytes.saturating_sub(encoded_len);
            self.encoded_bytes = self.encoded_bytes.saturating_sub(encoded_len);
            removed[index] = true;
            remaining_count = remaining_count.saturating_sub(1);
        }

        let orphaned_feedback_scopes =
            feedback_keys_requiring_evidence_purge_after_compaction(&self.entries, &mut removed);

        let before = self.entries.len();
        self.entries = self
            .entries
            .drain(..)
            .enumerate()
            .filter_map(|(index, entry)| (!removed[index]).then_some(entry))
            .collect();
        if !orphaned_feedback_scopes.is_empty() {
            self.entries.retain(|entry| {
                !orphaned_feedback_scopes
                    .iter()
                    .any(|scope| scope.governs(entry))
            });
        }
        self.encoded_bytes = self.entries.iter().map(|entry| entry.encoded_len).sum();
        before.saturating_sub(self.entries.len())
    }

    fn retain(&mut self, mut keep: impl FnMut(&PheromoneDeposit) -> bool) -> usize {
        let before = self.entries.len();
        self.entries.retain(|entry| keep(entry));
        self.encoded_bytes = self.entries.iter().map(|entry| entry.encoded_len).sum();
        before.saturating_sub(self.entries.len())
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

pub(crate) fn retention_initial_strength(deposit: &PheromoneDeposit) -> f64 {
    if deposit.confidence == 0.0 {
        CONTROL_RECORD_RETENTION_STRENGTH
    } else {
        deposit.confidence
    }
}

pub(crate) fn is_retention_expired(
    deposit: &PheromoneDeposit,
    now: i64,
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
) -> bool {
    let retained_strength = decayed_strength(
        deposit,
        now,
        retention_initial_strength(deposit),
        policy_half_life_secs,
    );
    retained_strength < evaporation_threshold
}

fn decayed_strength(
    deposit: &PheromoneDeposit,
    now: i64,
    initial_strength: f64,
    policy_half_life_secs: f64,
) -> f64 {
    if now <= deposit.timestamp {
        return initial_strength;
    }
    let elapsed = (now - deposit.timestamp) as f64;
    initial_strength * (0.5_f64).powf(elapsed / deposit.decay_half_life.min(policy_half_life_secs))
}

pub(crate) fn validate_deposit_policy(
    deposit: &PheromoneDeposit,
    policy_half_life_secs: f64,
) -> Result<(), SubstrateError> {
    if deposit.decay_half_life == policy_half_life_secs {
        return Ok(());
    }
    Err(SubstrateError::DepositPolicyMismatch {
        declared_half_life_secs: deposit.decay_half_life,
        effective_half_life_secs: policy_half_life_secs,
    })
}

pub(crate) fn validate_deposit_retention(
    deposit: &PheromoneDeposit,
    timestamp_high_water: i64,
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
    trusted_now: Option<i64>,
) -> Result<(), SubstrateError> {
    if let Some(now) = trusted_now
        && deposit.timestamp > now.saturating_add(MAX_LIVE_DEPOSIT_FUTURE_SKEW_SECS)
    {
        return Err(SubstrateError::FutureDeposit {
            timestamp: deposit.timestamp,
            trusted_now: now,
            max_future_skew_secs: MAX_LIVE_DEPOSIT_FUTURE_SKEW_SECS,
        });
    }
    if is_retention_expired(
        deposit,
        timestamp_high_water,
        policy_half_life_secs,
        evaporation_threshold,
    ) {
        return Err(SubstrateError::ExpiredDeposit {
            timestamp: deposit.timestamp,
            timestamp_high_water,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AdmissionControl {
    admitted_identities: Arc<RwLock<Option<HashSet<AgentId>>>>,
}

impl AdmissionControl {
    pub(crate) fn set_admitted_identities(
        &self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> Result<(), SubstrateError> {
        let mut guard = self
            .admitted_identities
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        *guard = Some(identities.into_iter().collect());
        Ok(())
    }

    pub(crate) fn validate_deposit_admission(
        &self,
        deposit: &PheromoneDeposit,
    ) -> Result<(), SubstrateError> {
        let guard = self
            .admitted_identities
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        if let Some(admitted_identities) = guard.as_ref() {
            let base_identity = AgentId(deposit.agent_identity.clone());
            if !admitted_identities.contains(&deposit.agent_id)
                && !admitted_identities.contains(&base_identity)
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!("agent `{}` is not admitted", deposit.agent_id),
                });
            }
        }
        Ok(())
    }
}

/// Query filters for reading persisted deposits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DepositQuery {
    pub threat_class: Option<ThreatClass>,
    pub since_timestamp: Option<i64>,
    pub host_id: Option<String>,
    pub limit: usize,
}

impl DepositQuery {
    pub fn recent(limit: usize) -> Self {
        Self {
            threat_class: None,
            since_timestamp: None,
            host_id: None,
            limit,
        }
    }
}

/// Runtime-visible health for a substrate backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub details: String,
    pub deposit_count: usize,
}

type ThreatIntelKey = (ThreatIntelIndicatorType, String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FeedbackSuppressionKey {
    threat_class: ThreatClass,
    event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedbackSuppressionState {
    Confirm,
    Dismiss,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FeedbackSuppressionOrder {
    observed_at_ms: i64,
    feedback_id: String,
    governed_evidence_timestamp: Option<i64>,
}

impl FeedbackSuppressionOrder {
    fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    pub(crate) fn governs_evidence_timestamp(&self, timestamp: i64) -> bool {
        self.governed_evidence_timestamp.map_or_else(
            || self.observed_at_ms() >= timestamp.saturating_mul(1_000),
            |governed_timestamp| governed_timestamp == timestamp,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeedbackEvidencePurgeScope {
    key: FeedbackSuppressionKey,
    order: FeedbackSuppressionOrder,
}

impl FeedbackEvidencePurgeScope {
    fn governs(&self, deposit: &VerifiedDeposit) -> bool {
        deposit_suppression_key(deposit).as_ref() == Some(&self.key)
            && self.order.governs_evidence_timestamp(deposit.timestamp)
    }
}

/// Async contract for pheromone substrates.
#[async_trait]
pub trait PheromoneSubstrate: Send + Sync {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError>;

    async fn record_escalation(&self, record: EscalationRecord) -> Result<(), SubstrateError>;

    async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<(), SubstrateError>;

    async fn store_threat_intel_entry(&self, entry: ThreatIntelEntry)
    -> Result<(), SubstrateError>;

    async fn store_behavioral_baseline_snapshot(
        &self,
        snapshot: BehavioralBaselineSnapshot,
        signer_agent_id: &AgentId,
        signing_key: &SigningKey,
    ) -> Result<(), SubstrateError>;

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError>;

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError>;

    async fn query_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError>;

    async fn query_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError>;

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError>;

    async fn query_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError>;

    async fn query_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError>;

    async fn recent_deposits(&self, limit: usize) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        self.query_deposits(DepositQuery::recent(limit)).await
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError>;

    async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError>;

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError>;
}

/// Selectable substrate backend used by the runtime bootstrap path.
#[derive(Debug, Clone)]
pub enum ConfiguredPheromoneSubstrate {
    InMemory(InMemoryPheromoneSubstrate),
    LocalJournal(LocalJournalPheromoneSubstrate),
    JetStream(JetStreamPheromoneSubstrate),
}

impl ConfiguredPheromoneSubstrate {
    pub fn from_config(config: &PheromoneConfig) -> Result<Self, SubstrateError> {
        match &config.backend {
            PheromoneBackendConfig::InMemory => Ok(Self::InMemory(
                InMemoryPheromoneSubstrate::new(config.clone()),
            )),
            PheromoneBackendConfig::LocalJournal { path } => Ok(Self::LocalJournal(
                LocalJournalPheromoneSubstrate::open(config.clone(), path)?,
            )),
            PheromoneBackendConfig::JetStream { url, .. } => Ok(Self::JetStream(
                JetStreamPheromoneSubstrate::new(config.clone(), url.clone()),
            )),
        }
    }

    pub fn set_admitted_identities(
        &self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> Result<(), SubstrateError> {
        let identities = identities.into_iter().collect::<Vec<_>>();
        match self {
            Self::InMemory(substrate) => substrate.set_admitted_identities(identities),
            Self::LocalJournal(substrate) => substrate.set_admitted_identities(identities),
            Self::JetStream(substrate) => substrate.set_admitted_identities(identities),
        }
    }
}

#[async_trait]
impl PheromoneSubstrate for ConfiguredPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.deposit(deposit).await,
            Self::LocalJournal(substrate) => substrate.deposit(deposit).await,
            Self::JetStream(substrate) => substrate.deposit(deposit).await,
        }
    }

    async fn record_escalation(&self, record: EscalationRecord) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.record_escalation(record).await,
            Self::LocalJournal(substrate) => substrate.record_escalation(record).await,
            Self::JetStream(substrate) => substrate.record_escalation(record).await,
        }
    }

    async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.store_threat_class_config(config).await,
            Self::LocalJournal(substrate) => substrate.store_threat_class_config(config).await,
            Self::JetStream(substrate) => substrate.store_threat_class_config(config).await,
        }
    }

    async fn store_threat_intel_entry(
        &self,
        entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.store_threat_intel_entry(entry).await,
            Self::LocalJournal(substrate) => substrate.store_threat_intel_entry(entry).await,
            Self::JetStream(substrate) => substrate.store_threat_intel_entry(entry).await,
        }
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        snapshot: BehavioralBaselineSnapshot,
        signer_agent_id: &AgentId,
        signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => {
                substrate
                    .store_behavioral_baseline_snapshot(snapshot, signer_agent_id, signing_key)
                    .await
            }
            Self::LocalJournal(substrate) => {
                substrate
                    .store_behavioral_baseline_snapshot(snapshot, signer_agent_id, signing_key)
                    .await
            }
            Self::JetStream(substrate) => {
                substrate
                    .store_behavioral_baseline_snapshot(snapshot, signer_agent_id, signing_key)
                    .await
            }
        }
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.query_concentration(threat_class, now).await,
            Self::LocalJournal(substrate) => substrate.query_concentration(threat_class, now).await,
            Self::JetStream(substrate) => substrate.query_concentration(threat_class, now).await,
        }
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.query_deposits(query).await,
            Self::LocalJournal(substrate) => substrate.query_deposits(query).await,
            Self::JetStream(substrate) => substrate.query_deposits(query).await,
        }
    }

    async fn query_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.query_escalations(since_timestamp).await,
            Self::LocalJournal(substrate) => substrate.query_escalations(since_timestamp).await,
            Self::JetStream(substrate) => substrate.query_escalations(since_timestamp).await,
        }
    }

    async fn query_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.query_threat_class_config(threat_class).await,
            Self::LocalJournal(substrate) => {
                substrate.query_threat_class_config(threat_class).await
            }
            Self::JetStream(substrate) => substrate.query_threat_class_config(threat_class).await,
        }
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.query_threat_class_configs().await,
            Self::LocalJournal(substrate) => substrate.query_threat_class_configs().await,
            Self::JetStream(substrate) => substrate.query_threat_class_configs().await,
        }
    }

    async fn query_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => {
                substrate
                    .query_threat_intel_entry(indicator_type, value, now)
                    .await
            }
            Self::LocalJournal(substrate) => {
                substrate
                    .query_threat_intel_entry(indicator_type, value, now)
                    .await
            }
            Self::JetStream(substrate) => {
                substrate
                    .query_threat_intel_entry(indicator_type, value, now)
                    .await
            }
        }
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => {
                substrate
                    .query_behavioral_baseline_snapshot(strategy_id, expected_signer_agent_id)
                    .await
            }
            Self::LocalJournal(substrate) => {
                substrate
                    .query_behavioral_baseline_snapshot(strategy_id, expected_signer_agent_id)
                    .await
            }
            Self::JetStream(substrate) => {
                substrate
                    .query_behavioral_baseline_snapshot(strategy_id, expected_signer_agent_id)
                    .await
            }
        }
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.gc_evaporated(now).await,
            Self::LocalJournal(substrate) => substrate.gc_evaporated(now).await,
            Self::JetStream(substrate) => substrate.gc_evaporated(now).await,
        }
    }

    async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.gc_expired_threat_intel(now).await,
            Self::LocalJournal(substrate) => substrate.gc_expired_threat_intel(now).await,
            Self::JetStream(substrate) => substrate.gc_expired_threat_intel(now).await,
        }
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.health().await,
            Self::LocalJournal(substrate) => substrate.health().await,
            Self::JetStream(substrate) => substrate.health().await,
        }
    }
}

/// In-memory substrate used by the first vertical slice and replay tests.
#[derive(Debug, Clone)]
pub struct InMemoryPheromoneSubstrate {
    config: PheromoneConfig,
    admission_control: AdmissionControl,
    admission_clock: DepositAdmissionClock,
    retention_limits: DepositRetentionLimits,
    deposits: Arc<RwLock<RetainedDeposits>>,
    deposit_operations: Arc<RwLock<DepositOperationLedger>>,
    escalations: Arc<RwLock<Vec<EscalationRecord>>>,
    threat_class_configs: Arc<RwLock<BTreeMap<ThreatClass, ThreatClassConfig>>>,
    threat_intel_entries: Arc<RwLock<BTreeMap<ThreatIntelKey, ThreatIntelEntry>>>,
    behavioral_baseline_snapshots: Arc<RwLock<BTreeMap<String, BehavioralBaselineEnvelope>>>,
}

impl InMemoryPheromoneSubstrate {
    pub fn new(config: PheromoneConfig) -> Self {
        Self::with_admission_clock(config, DepositAdmissionClock::System)
    }

    /// Construct an explicitly logical-time substrate for bounded offline replay.
    ///
    /// Live and service construction must use [`Self::new`], whose trusted wall
    /// clock prevents stale or future deposits from consuming retention.
    pub fn new_for_replay(config: PheromoneConfig) -> Self {
        Self::with_admission_clock(config, DepositAdmissionClock::Replay)
    }

    fn with_admission_clock(
        config: PheromoneConfig,
        admission_clock: DepositAdmissionClock,
    ) -> Self {
        Self {
            config,
            admission_control: AdmissionControl::default(),
            admission_clock,
            retention_limits: DepositRetentionLimits::default(),
            deposits: Arc::new(RwLock::new(RetainedDeposits::default())),
            deposit_operations: Arc::new(RwLock::new(DepositOperationLedger::default())),
            escalations: Arc::new(RwLock::new(Vec::new())),
            threat_class_configs: Arc::new(RwLock::new(BTreeMap::new())),
            threat_intel_entries: Arc::new(RwLock::new(BTreeMap::new())),
            behavioral_baseline_snapshots: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn set_admitted_identities(
        &self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> Result<(), SubstrateError> {
        self.admission_control.set_admitted_identities(identities)
    }

    #[cfg(test)]
    fn with_retention_limits(
        config: PheromoneConfig,
        retention_limits: DepositRetentionLimits,
    ) -> Self {
        Self {
            retention_limits,
            ..Self::new_for_replay(config)
        }
    }

    #[cfg(test)]
    fn with_live_retention_limits(
        config: PheromoneConfig,
        retention_limits: DepositRetentionLimits,
    ) -> Self {
        Self {
            retention_limits,
            ..Self::new(config)
        }
    }
}

#[async_trait]
impl PheromoneSubstrate for InMemoryPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        let deposit = VerifiedDeposit::admit(deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        let threat_class_config = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .get(&deposit.threat_class)
            .cloned();
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        validate_deposit_policy(&deposit, policy.half_life_secs)?;
        let operation = deposit_operation_record(&deposit)?;
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let mut operations = self
            .deposit_operations
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        if let Some(operation) = operation.as_ref()
            && operations.already_recorded(operation)?
        {
            return Ok(());
        }
        if exact_deposit_operation_already_retained(&guard.entries, &deposit)? {
            if let Some(operation) = operation.as_ref() {
                let _ = insert_deposit_operation(&mut operations, operation)?;
            }
            return Ok(());
        }
        guard.push(
            deposit,
            self.retention_limits,
            policy.half_life_secs,
            policy.evaporation_threshold,
            self.admission_clock.trusted_now()?,
        )?;
        if let Some(operation) = operation.as_ref() {
            let _ = insert_deposit_operation(&mut operations, operation)?;
        }
        Ok(())
    }

    async fn record_escalation(&self, record: EscalationRecord) -> Result<(), SubstrateError> {
        let mut guard = self
            .escalations
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.push(record);
        Ok(())
    }

    async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        let mut guard = self
            .threat_class_configs
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.insert(config.threat_class.clone(), config);
        Ok(())
    }

    async fn store_threat_intel_entry(
        &self,
        entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        let entry = normalize_threat_intel_entry(entry);
        let key = threat_intel_key(&entry.indicator_type, &entry.value);
        let mut guard = self
            .threat_intel_entries
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.insert(key, entry);
        Ok(())
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        snapshot: BehavioralBaselineSnapshot,
        signer_agent_id: &AgentId,
        signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        let strategy_id = snapshot.strategy_id.clone();
        let mut guard = self
            .behavioral_baseline_snapshots
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let sequence = next_behavioral_baseline_sequence(
            guard
                .get(&strategy_id)
                .map(BehavioralBaselineEnvelope::sequence),
        );
        let envelope =
            sign_behavioral_baseline_snapshot(snapshot, signer_agent_id, sequence, signing_key)?;
        guard.insert(strategy_id, envelope);
        Ok(())
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let config_guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let policy = resolved_policy(&self.config, &config_guard, threat_class);
        Ok(concentration_for(
            &guard.entries,
            threat_class,
            now,
            &policy,
        ))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(filter_deposits(&guard.entries, query))
    }

    async fn query_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        let guard = self
            .escalations
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(filter_escalations(&guard, since_timestamp))
    }

    async fn query_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        let guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(guard.get(threat_class).cloned())
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        let guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(ordered_threat_class_configs(&guard))
    }

    async fn query_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        let guard = self
            .threat_intel_entries
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let key = threat_intel_key(indicator_type, value);
        Ok(guard
            .get(&key)
            .filter(|entry| entry.expires_at > now)
            .cloned())
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        let guard = self
            .behavioral_baseline_snapshots
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let Some(envelope) = guard.get(strategy_id) else {
            return Ok(None);
        };
        Ok(Some(
            verify_behavioral_baseline_snapshot(
                envelope,
                strategy_id,
                Some(expected_signer_agent_id),
                Some(envelope.sequence()),
            )?
            .payload,
        ))
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let config_guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let removed = guard.retain(|deposit| {
            let policy = resolved_policy(&self.config, &config_guard, &deposit.threat_class);
            !is_retention_expired(
                deposit,
                now,
                policy.half_life_secs,
                policy.evaporation_threshold,
            )
        });
        Ok(removed)
    }

    async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self
            .threat_intel_entries
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let before = guard.len();
        guard.retain(|_key, entry| entry.expires_at > now);
        let purged = before - guard.len();
        if purged > 0 {
            tracing::info!(purged, "gc_expired_threat_intel complete");
        } else {
            tracing::debug!(purged, "gc_expired_threat_intel complete");
        }
        Ok(purged)
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(SubstrateHealth {
            backend: "in_memory".to_string(),
            durable: false,
            ready: true,
            details: "ephemeral in-process substrate".to_string(),
            deposit_count: guard.len(),
        })
    }
}

/// Local JSONL journal substrate used for restart-safe single-node durability.
#[derive(Debug, Clone)]
pub struct LocalJournalPheromoneSubstrate {
    config: PheromoneConfig,
    admission_control: AdmissionControl,
    admission_clock: DepositAdmissionClock,
    retention_limits: DepositRetentionLimits,
    journal_path: PathBuf,
    deposit_operation_journal_path: PathBuf,
    escalation_journal_path: PathBuf,
    threat_class_config_journal_path: PathBuf,
    threat_intel_journal_path: PathBuf,
    behavioral_baseline_journal_path: PathBuf,
    behavioral_baseline_sequence_path: PathBuf,
    deposits: Arc<RwLock<RetainedDeposits>>,
    deposit_operations: Arc<RwLock<DepositOperationLedger>>,
    escalations: Arc<RwLock<Vec<EscalationRecord>>>,
    threat_class_configs: Arc<RwLock<BTreeMap<ThreatClass, ThreatClassConfig>>>,
    threat_intel_entries: Arc<RwLock<BTreeMap<ThreatIntelKey, ThreatIntelEntry>>>,
    behavioral_baseline_snapshots: Arc<RwLock<BTreeMap<String, BehavioralBaselineEnvelope>>>,
    behavioral_baseline_sequences: Arc<RwLock<BTreeMap<String, u64>>>,
}

impl LocalJournalPheromoneSubstrate {
    pub fn open(config: PheromoneConfig, path: impl AsRef<Path>) -> Result<Self, SubstrateError> {
        Self::open_with_admission_clock(
            config,
            path,
            DepositRetentionLimits::default(),
            DepositAdmissionClock::System,
        )
    }

    /// Open an explicitly logical-time journal for bounded offline replay.
    ///
    /// Live and service construction must use [`Self::open`].
    pub fn open_for_replay(
        config: PheromoneConfig,
        path: impl AsRef<Path>,
    ) -> Result<Self, SubstrateError> {
        Self::open_with_admission_clock(
            config,
            path,
            DepositRetentionLimits::default(),
            DepositAdmissionClock::Replay,
        )
    }

    #[cfg(test)]
    fn open_with_retention_limits(
        config: PheromoneConfig,
        path: impl AsRef<Path>,
        retention_limits: DepositRetentionLimits,
    ) -> Result<Self, SubstrateError> {
        Self::open_with_admission_clock(
            config,
            path,
            retention_limits,
            DepositAdmissionClock::Replay,
        )
    }

    #[cfg(test)]
    fn open_with_live_retention_limits(
        config: PheromoneConfig,
        path: impl AsRef<Path>,
        retention_limits: DepositRetentionLimits,
    ) -> Result<Self, SubstrateError> {
        Self::open_with_admission_clock(
            config,
            path,
            retention_limits,
            DepositAdmissionClock::System,
        )
    }

    fn open_with_admission_clock(
        config: PheromoneConfig,
        path: impl AsRef<Path>,
        retention_limits: DepositRetentionLimits,
        admission_clock: DepositAdmissionClock,
    ) -> Result<Self, SubstrateError> {
        let journal_path = path.as_ref().to_path_buf();
        let deposit_operation_journal_path = deposit_operation_journal_path(&journal_path);
        let escalation_journal_path = escalation_journal_path(&journal_path);
        let threat_class_config_journal_path = threat_class_config_journal_path(&journal_path);
        let threat_intel_journal_path = threat_intel_journal_path(&journal_path);
        let behavioral_baseline_journal_path = behavioral_baseline_journal_path(&journal_path);
        let behavioral_baseline_sequence_path = behavioral_baseline_sequence_path(&journal_path);
        ensure_parent_dir(&journal_path)?;
        let threat_class_configs = load_threat_class_configs(&threat_class_config_journal_path)?;
        let (deposits, rewrite_required) = load_retained_deposit_jsonl(
            &journal_path,
            retention_limits,
            &config,
            &threat_class_configs,
            admission_clock.trusted_now()?,
        )?;
        if rewrite_required {
            rewrite_verified_deposit_jsonl(&journal_path, &deposits.entries)?;
            enforce_journal_file_limit(&journal_path, retention_limits.max_journal_bytes)?;
        }
        let (deposit_operations, operation_rewrite_required) =
            load_deposit_operations(&deposit_operation_journal_path)?;
        if operation_rewrite_required {
            rewrite_deposit_operation_journal(
                &deposit_operation_journal_path,
                &deposit_operations,
            )?;
        }
        let escalations = load_jsonl(&escalation_journal_path)?;
        let threat_intel_entries = load_threat_intel_entries(&threat_intel_journal_path)?;
        let mut behavioral_baseline_sequences =
            load_behavioral_baseline_sequences(&behavioral_baseline_sequence_path)?;
        let behavioral_baseline_snapshots = load_behavioral_baseline_snapshots(
            &behavioral_baseline_journal_path,
            &mut behavioral_baseline_sequences,
        )?;
        write_behavioral_baseline_sequences(
            &behavioral_baseline_sequence_path,
            &behavioral_baseline_sequences,
        )?;

        Ok(Self {
            config,
            admission_control: AdmissionControl::default(),
            admission_clock,
            retention_limits,
            journal_path,
            deposit_operation_journal_path,
            escalation_journal_path,
            threat_class_config_journal_path,
            threat_intel_journal_path,
            behavioral_baseline_journal_path,
            behavioral_baseline_sequence_path,
            deposits: Arc::new(RwLock::new(deposits)),
            deposit_operations: Arc::new(RwLock::new(deposit_operations)),
            escalations: Arc::new(RwLock::new(escalations)),
            threat_class_configs: Arc::new(RwLock::new(threat_class_configs)),
            threat_intel_entries: Arc::new(RwLock::new(threat_intel_entries)),
            behavioral_baseline_snapshots: Arc::new(RwLock::new(behavioral_baseline_snapshots)),
            behavioral_baseline_sequences: Arc::new(RwLock::new(behavioral_baseline_sequences)),
        })
    }

    pub fn set_admitted_identities(
        &self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> Result<(), SubstrateError> {
        self.admission_control.set_admitted_identities(identities)
    }
}

#[async_trait]
impl PheromoneSubstrate for LocalJournalPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        let deposit = VerifiedDeposit::admit(deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        let threat_class_config = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .get(&deposit.threat_class)
            .cloned();
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        validate_deposit_policy(&deposit, policy.half_life_secs)?;
        let operation = deposit_operation_record(&deposit)?;
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let mut operations = self
            .deposit_operations
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        if let Some(operation) = operation.as_ref()
            && operations.already_recorded(operation)?
        {
            return Ok(());
        }
        if exact_deposit_operation_already_retained(&guard.entries, &deposit)? {
            if let Some(operation) = operation.as_ref() {
                // The deposit may have become process-visible immediately before
                // a crash or directory-sync failure. Rewrite the retained set to
                // establish its durability before committing the operation marker.
                rewrite_verified_deposit_jsonl(&self.journal_path, &guard.entries)?;
                persist_deposit_operation(
                    &self.deposit_operation_journal_path,
                    &mut operations,
                    operation,
                )?;
            }
            return Ok(());
        }
        let mut candidate = guard.clone();
        let pruned = candidate.push(
            deposit,
            self.retention_limits,
            policy.half_life_secs,
            policy.evaporation_threshold,
            self.admission_clock.trusted_now()?,
        )?;
        let persistence_result = if operation.is_some() || pruned > 0 {
            rewrite_verified_deposit_jsonl(&self.journal_path, &candidate.entries)
        } else {
            let persisted =
                candidate
                    .entries
                    .last()
                    .ok_or_else(|| SubstrateError::InvalidDeposit {
                        reason: "retention removed the newly admitted deposit".to_string(),
                    })?;
            append_jsonl_line(&self.journal_path, &persisted.deposit)
        };
        match persistence_result {
            Ok(()) => {}
            Err(error @ SubstrateError::DurabilityOutcomeUnknown { .. }) => {
                // rename(2) completed, so the candidate is the process-visible journal even
                // though crash durability is unknown. Reconcile memory before failing closed.
                *guard = candidate;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        *guard = candidate;
        if let Some(operation) = operation.as_ref() {
            persist_deposit_operation(
                &self.deposit_operation_journal_path,
                &mut operations,
                operation,
            )?;
        }
        Ok(())
    }

    async fn record_escalation(&self, record: EscalationRecord) -> Result<(), SubstrateError> {
        append_jsonl_line(&self.escalation_journal_path, &record)?;
        let mut guard = self
            .escalations
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.push(record);
        Ok(())
    }

    async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        append_jsonl_line(&self.threat_class_config_journal_path, &config)?;
        let mut guard = self
            .threat_class_configs
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.insert(config.threat_class.clone(), config);
        Ok(())
    }

    async fn store_threat_intel_entry(
        &self,
        entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        let entry = normalize_threat_intel_entry(entry);
        append_jsonl_line(&self.threat_intel_journal_path, &entry)?;
        let key = threat_intel_key(&entry.indicator_type, &entry.value);
        let mut guard = self
            .threat_intel_entries
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.insert(key, entry);
        Ok(())
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        snapshot: BehavioralBaselineSnapshot,
        signer_agent_id: &AgentId,
        signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        let strategy_id = snapshot.strategy_id.clone();
        let mut guard = self
            .behavioral_baseline_snapshots
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let mut sequence_guard = self
            .behavioral_baseline_sequences
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let sequence = next_behavioral_baseline_sequence(
            sequence_guard.get(&strategy_id).copied().or_else(|| {
                guard
                    .get(&strategy_id)
                    .map(BehavioralBaselineEnvelope::sequence)
            }),
        );
        let envelope =
            sign_behavioral_baseline_snapshot(snapshot, signer_agent_id, sequence, signing_key)?;
        guard.insert(strategy_id.clone(), envelope);
        sequence_guard.insert(strategy_id, sequence);
        rewrite_jsonl(
            &self.behavioral_baseline_journal_path,
            &guard.values().collect::<Vec<_>>(),
        )?;
        write_behavioral_baseline_sequences(
            &self.behavioral_baseline_sequence_path,
            &sequence_guard,
        )?;
        Ok(())
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let config_guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let policy = resolved_policy(&self.config, &config_guard, threat_class);
        Ok(concentration_for(
            &guard.entries,
            threat_class,
            now,
            &policy,
        ))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(filter_deposits(&guard.entries, query))
    }

    async fn query_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        let guard = self
            .escalations
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(filter_escalations(&guard, since_timestamp))
    }

    async fn query_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        let guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(guard.get(threat_class).cloned())
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        let guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(ordered_threat_class_configs(&guard))
    }

    async fn query_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        let guard = self
            .threat_intel_entries
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let key = threat_intel_key(indicator_type, value);
        Ok(guard
            .get(&key)
            .filter(|entry| entry.expires_at > now)
            .cloned())
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        let guard = self
            .behavioral_baseline_snapshots
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let Some(envelope) = guard.get(strategy_id) else {
            return Ok(None);
        };
        let accepted_sequence = self
            .behavioral_baseline_sequences
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .get(strategy_id)
            .copied();
        Ok(Some(
            verify_behavioral_baseline_snapshot(
                envelope,
                strategy_id,
                Some(expected_signer_agent_id),
                accepted_sequence,
            )?
            .payload,
        ))
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let config_guard = self
            .threat_class_configs
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let mut candidate = guard.clone();
        let removed = candidate.retain(|deposit| {
            let policy = resolved_policy(&self.config, &config_guard, &deposit.threat_class);
            !is_retention_expired(
                deposit,
                now,
                policy.half_life_secs,
                policy.evaporation_threshold,
            )
        });
        match rewrite_verified_deposit_jsonl(&self.journal_path, &candidate.entries) {
            Ok(()) => {}
            Err(error @ SubstrateError::DurabilityOutcomeUnknown { .. }) => {
                *guard = candidate;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        *guard = candidate;
        Ok(removed)
    }

    async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self
            .threat_intel_entries
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let before = guard.len();
        guard.retain(|_key, entry| entry.expires_at > now);
        rewrite_jsonl(
            &self.threat_intel_journal_path,
            &guard.values().collect::<Vec<_>>(),
        )?;
        let purged = before - guard.len();
        if purged > 0 {
            tracing::info!(purged, "gc_expired_threat_intel complete");
        } else {
            tracing::debug!(purged, "gc_expired_threat_intel complete");
        }
        Ok(purged)
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let deposits_ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .is_ok();
        let escalations_ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.escalation_journal_path)
            .is_ok();
        let configs_ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.threat_class_config_journal_path)
            .is_ok();
        let threat_intel_ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.threat_intel_journal_path)
            .is_ok();
        let behavioral_baseline_ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.behavioral_baseline_journal_path)
            .is_ok();
        let behavioral_baseline_sequence_ready = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.behavioral_baseline_sequence_path)
            .is_ok();
        let ready = deposits_ready
            && escalations_ready
            && configs_ready
            && threat_intel_ready
            && behavioral_baseline_ready
            && behavioral_baseline_sequence_ready;

        Ok(SubstrateHealth {
            backend: "local_journal".to_string(),
            durable: true,
            ready,
            details: format!(
                "journal files at {}, {}, {}, {}, {}, and {}",
                self.journal_path.display(),
                self.escalation_journal_path.display(),
                self.threat_class_config_journal_path.display(),
                self.threat_intel_journal_path.display(),
                self.behavioral_baseline_journal_path.display(),
                self.behavioral_baseline_sequence_path.display()
            ),
            deposit_count: guard.len(),
        })
    }
}

pub(crate) fn concentration_for(
    deposits: &[VerifiedDeposit],
    threat_class: &ThreatClass,
    now: i64,
    policy: &ThreatClassPolicy,
) -> PheromoneConcentration {
    let suppression = latest_feedback_suppression_states(deposits);
    let mut sources = HashSet::new();
    let mut total_strength = 0.0;
    let mut peak_confidence: f64 = 0.0;

    for deposit in deposits
        .iter()
        .filter(|deposit| &deposit.threat_class == threat_class)
    {
        let strength = decayed_strength(deposit, now, deposit.confidence, policy.half_life_secs);
        if strength < policy.evaporation_threshold {
            continue;
        }
        if is_suppressed_by_feedback(deposit, &suppression) {
            continue;
        }
        let agent_identity = independent_source_identity(deposit);
        if strength <= 0.0 {
            continue;
        }
        total_strength += strength;
        peak_confidence = peak_confidence.max(deposit.confidence);
        sources.insert(agent_identity.to_owned());
    }

    PheromoneConcentration {
        threat_class: threat_class.clone(),
        total_strength,
        distinct_sources: sources.len(),
        peak_confidence,
    }
}

/// Return the stable cryptographic witness identity for a deposit.
///
/// `agent_id` is intentionally not used here: it may carry a strategy scope
/// suffix (for example, `identity:strategy-a`) and therefore is not an
/// independent source. The [`VerifiedDeposit`] boundary guarantees that the
/// signature and key-derived identity were checked once at admission or load.
fn independent_source_identity(deposit: &VerifiedDeposit) -> &str {
    deposit.agent_identity.as_str()
}

pub(crate) fn filter_deposits(
    deposits: &[VerifiedDeposit],
    query: DepositQuery,
) -> Vec<PheromoneDeposit> {
    let suppression = latest_feedback_suppression_states(deposits);
    let mut filtered = deposits
        .iter()
        .filter(|deposit| {
            query
                .threat_class
                .as_ref()
                .is_none_or(|threat_class| &deposit.threat_class == threat_class)
                && query
                    .since_timestamp
                    .is_none_or(|since_timestamp| deposit.timestamp >= since_timestamp)
                && query
                    .host_id
                    .as_deref()
                    .is_none_or(|host_id| deposit_host_id(deposit) == Some(host_id))
                && !is_suppressed_by_feedback(deposit, &suppression)
        })
        .map(|deposit| deposit.deposit.clone())
        .collect::<Vec<_>>();
    filtered.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp));
    if query.limit > 0 {
        filtered.truncate(query.limit);
    }
    filtered
}

fn deposit_host_id(deposit: &PheromoneDeposit) -> Option<&str> {
    deposit
        .indicator
        .get("host_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            deposit
                .indicator
                .pointer("/evidence/host_metadata/host_id")
                .and_then(serde_json::Value::as_str)
        })
}

fn latest_feedback_suppression_states(
    deposits: &[VerifiedDeposit],
) -> BTreeMap<FeedbackSuppressionKey, (FeedbackSuppressionState, FeedbackSuppressionOrder)> {
    let mut states = BTreeMap::new();
    for deposit in deposits {
        let Some((key, state, order)) = feedback_suppression_marker(deposit) else {
            continue;
        };
        let replace = states
            .get(&key)
            .is_none_or(|(_, current_order)| current_order <= &order);
        if replace {
            states.insert(key, (state, order));
        }
    }
    states
}

fn feedback_keys_requiring_evidence_purge_after_compaction(
    deposits: &[VerifiedDeposit],
    removed: &mut [bool],
) -> BTreeSet<FeedbackEvidencePurgeScope> {
    debug_assert_eq!(deposits.len(), removed.len());
    let mut final_states = BTreeMap::<
        FeedbackSuppressionKey,
        (FeedbackSuppressionState, FeedbackSuppressionOrder, usize),
    >::new();
    for (index, deposit) in deposits.iter().enumerate() {
        let Some((key, state, order)) = feedback_suppression_marker(deposit) else {
            continue;
        };
        let replace = final_states
            .get(&key)
            .is_none_or(|(_, current_order, _)| current_order <= &order);
        if replace {
            final_states.insert(key, (state, order, index));
        }
    }

    let mut evidence_purge = BTreeSet::new();
    for (key, (state, final_order, final_index)) in final_states {
        if !removed.get(final_index).copied().unwrap_or(true) {
            continue;
        }
        // Once the terminal marker is evicted, no older marker may survive
        // and impersonate the final analyst decision. A lost dismissal also
        // purges the evidence it suppressed; a lost confirmation preserves
        // ordinary evidence after removing its superseded markers.
        for (index, deposit) in deposits.iter().enumerate() {
            if feedback_suppression_marker(deposit).is_some_and(
                |(candidate_key, _, candidate_order)| {
                    candidate_key == key && candidate_order <= final_order
                },
            ) && let Some(slot) = removed.get_mut(index)
            {
                *slot = true;
            }
        }
        if state == FeedbackSuppressionState::Dismiss {
            evidence_purge.insert(FeedbackEvidencePurgeScope {
                key,
                order: final_order,
            });
        }
    }
    evidence_purge
}

fn is_suppressed_by_feedback(
    deposit: &VerifiedDeposit,
    suppression: &BTreeMap<
        FeedbackSuppressionKey,
        (FeedbackSuppressionState, FeedbackSuppressionOrder),
    >,
) -> bool {
    if is_providence_feedback_deposit(deposit) {
        return false;
    }
    let Some(key) = deposit_suppression_key(deposit) else {
        return false;
    };
    suppression.get(&key).is_some_and(|(state, order)| {
        *state == FeedbackSuppressionState::Dismiss
            && order.governs_evidence_timestamp(deposit.timestamp)
    })
}

pub(crate) fn feedback_suppression_marker(
    deposit: &VerifiedDeposit,
) -> Option<(
    FeedbackSuppressionKey,
    FeedbackSuppressionState,
    FeedbackSuppressionOrder,
)> {
    let indicator = deposit.indicator.as_object()?;
    if indicator.get("schema").and_then(serde_json::Value::as_str)
        != Some(SWARM_PROVIDENCE_FEEDBACK_SCHEMA)
    {
        return None;
    }
    let event_id = indicator
        .get("event_id")
        .and_then(serde_json::Value::as_str)?;
    let state = match indicator
        .get("action")
        .and_then(serde_json::Value::as_str)?
        .trim()
    {
        "confirm" => FeedbackSuppressionState::Confirm,
        "dismiss" => FeedbackSuppressionState::Dismiss,
        _ => return None,
    };
    let timestamp_ms = deposit.timestamp.saturating_mul(1_000);
    let observed_at_ms = indicator
        .get("observed_at_ms")
        .and_then(serde_json::Value::as_i64)
        .filter(|observed_at_ms| observed_at_ms.div_euclid(1_000) == deposit.timestamp)
        .unwrap_or(timestamp_ms);
    let feedback_id = indicator
        .get("feedback_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let governed_evidence_timestamp = indicator
        .get("governed_evidence_timestamp")
        .and_then(serde_json::Value::as_i64);
    Some((
        FeedbackSuppressionKey {
            threat_class: deposit.threat_class.clone(),
            event_id: event_id.to_string(),
        },
        state,
        FeedbackSuppressionOrder {
            observed_at_ms,
            feedback_id,
            governed_evidence_timestamp,
        },
    ))
}

pub(crate) fn deposit_suppression_key(deposit: &VerifiedDeposit) -> Option<FeedbackSuppressionKey> {
    Some(FeedbackSuppressionKey {
        threat_class: deposit.threat_class.clone(),
        event_id: deposit
            .indicator
            .get("event_id")
            .and_then(serde_json::Value::as_str)?
            .to_string(),
    })
}

fn is_providence_feedback_deposit(deposit: &VerifiedDeposit) -> bool {
    deposit
        .indicator
        .get("schema")
        .and_then(serde_json::Value::as_str)
        == Some(SWARM_PROVIDENCE_FEEDBACK_SCHEMA)
}

pub(crate) fn filter_escalations(
    escalations: &[EscalationRecord],
    since_timestamp: i64,
) -> Vec<EscalationRecord> {
    let mut filtered = escalations
        .iter()
        .filter(|record| record.timestamp >= since_timestamp)
        .cloned()
        .collect::<Vec<_>>();
    filtered.sort_by_key(|entry| entry.timestamp);
    filtered
}

fn ensure_parent_dir(path: &Path) -> Result<(), SubstrateError> {
    if let Some(parent) = path.parent() {
        let mut missing = Vec::new();
        let mut cursor = parent;
        while !cursor.exists() {
            missing.push(cursor.to_path_buf());
            let Some(ancestor) = cursor.parent() else {
                break;
            };
            cursor = ancestor;
        }
        fs::create_dir_all(parent).map_err(|source| SubstrateError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
        #[cfg(unix)]
        for created in missing {
            let Some(ancestor) = created.parent() else {
                continue;
            };
            fs::File::open(ancestor)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| SubstrateError::DurabilityOutcomeUnknown {
                    path: created,
                    source,
                })?;
        }
    }
    Ok(())
}

fn load_jsonl<T>(path: &Path) -> Result<Vec<T>, SubstrateError>
where
    T: DeserializeOwned,
{
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(path).map_err(|source| SubstrateError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| SubstrateError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<T>(&line).map_err(|source| SubstrateError::Parse {
            path: path.to_path_buf(),
            line: index + 1,
            source,
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

fn enforce_journal_file_limit(path: &Path, max_bytes: u64) -> Result<(), SubstrateError> {
    let observed_bytes = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(SubstrateError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if observed_bytes > max_bytes {
        return Err(SubstrateError::JournalLimitExceeded {
            path: path.to_path_buf(),
            observed_bytes,
            max_bytes,
        });
    }
    Ok(())
}

fn load_deposit_operations(path: &Path) -> Result<(DepositOperationLedger, bool), SubstrateError> {
    repair_uncommitted_deposit_operation_tail(path)?;
    enforce_journal_file_limit(path, MAX_LOCAL_DEPOSIT_OPERATION_JOURNAL_BYTES)?;
    let records = load_jsonl::<DepositOperationRecord>(path)?;
    let mut operations = DepositOperationLedger::default();
    let mut rewrite_required = false;
    for record in records {
        if record.operation_id.is_empty()
            || record.operation_id.len() > MAX_DEPOSIT_OPERATION_ID_BYTES
            || record.deposit_digest.len() != 64
            || !record
                .deposit_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: "local Providence feedback operation ledger contains an invalid record"
                    .to_string(),
            });
        }
        match insert_deposit_operation(&mut operations, &record)? {
            DepositOperationInsert::AlreadyRecorded => rewrite_required = true,
            DepositOperationInsert::Inserted { evicted } => rewrite_required |= evicted > 0,
        }
    }
    Ok((operations, rewrite_required))
}

fn repair_uncommitted_deposit_operation_tail(path: &Path) -> Result<(), SubstrateError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(SubstrateError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if bytes.is_empty() || bytes.last() == Some(&b'\n') {
        return Ok(());
    }

    // A record is committed only once its terminating newline and sync_data
    // complete. A crash may leave an arbitrary final prefix; discard only
    // that uncommitted tail and preserve every newline-terminated record.
    let committed_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    file.set_len(u64::try_from(committed_len).unwrap_or(0))
        .and_then(|()| file.sync_all())
        .map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })
}

fn append_deposit_operation_record(
    path: &Path,
    operation: &DepositOperationRecord,
    maximum_bytes: u64,
) -> Result<(), SubstrateError> {
    let serialized = serde_json::to_string(operation).map_err(|source| SubstrateError::Parse {
        path: path.to_path_buf(),
        line: 0,
        source,
    })?;
    let observed_bytes = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(source) => {
            return Err(SubstrateError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let next_bytes = observed_bytes
        .checked_add(u64::try_from(serialized.len()).unwrap_or(u64::MAX))
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| SubstrateError::JournalLimitExceeded {
            path: path.to_path_buf(),
            observed_bytes: u64::MAX,
            max_bytes: maximum_bytes,
        })?;
    if next_bytes > maximum_bytes {
        return Err(SubstrateError::JournalLimitExceeded {
            path: path.to_path_buf(),
            observed_bytes: next_bytes,
            max_bytes: maximum_bytes,
        });
    }
    ensure_parent_dir(path)?;
    let existed = path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    writeln!(file, "{serialized}")
        .and_then(|()| file.sync_data())
        .map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    if !existed {
        #[cfg(unix)]
        sync_rewrite_parent(path, path.parent().unwrap_or_else(|| Path::new(".")))?;
    }
    Ok(())
}

fn compact_deposit_operation_ledger_to_bytes(
    path: &Path,
    operations: &mut DepositOperationLedger,
    maximum_bytes: u64,
) -> Result<(), SubstrateError> {
    let ordered = operations.ordered_records()?;
    let mut line_bytes = VecDeque::with_capacity(ordered.len());
    let mut total_bytes = 0u64;
    for record in ordered {
        let bytes = serde_json::to_vec(&record).map_err(|source| SubstrateError::Parse {
            path: path.to_path_buf(),
            line: 0,
            source,
        })?;
        let bytes = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        total_bytes = total_bytes.saturating_add(bytes);
        line_bytes.push_back(bytes);
    }
    while total_bytes > maximum_bytes {
        let Some(oldest_bytes) = line_bytes.pop_front() else {
            break;
        };
        if !operations.evict_oldest()? {
            break;
        }
        total_bytes = total_bytes.saturating_sub(oldest_bytes);
    }
    if total_bytes > maximum_bytes || operations.records.is_empty() {
        return Err(SubstrateError::JournalLimitExceeded {
            path: path.to_path_buf(),
            observed_bytes: total_bytes,
            max_bytes: maximum_bytes,
        });
    }
    Ok(())
}

fn rewrite_deposit_operation_journal(
    path: &Path,
    operations: &DepositOperationLedger,
) -> Result<(), SubstrateError> {
    let records = operations.ordered_records()?;
    rewrite_jsonl(path, &records)
}

fn persist_deposit_operation_with_limits(
    path: &Path,
    operations: &mut DepositOperationLedger,
    operation: &DepositOperationRecord,
    maximum_entries: usize,
    maximum_bytes: u64,
) -> Result<(), SubstrateError> {
    let mut candidate = operations.clone();
    let insertion = candidate.insert_with_limit(operation, maximum_entries)?;
    if insertion == DepositOperationInsert::AlreadyRecorded {
        return Ok(());
    }

    let count_rollover = matches!(
        insertion,
        DepositOperationInsert::Inserted { evicted } if evicted > 0
    );
    let persistence = if count_rollover {
        compact_deposit_operation_ledger_to_bytes(path, &mut candidate, maximum_bytes)?;
        rewrite_deposit_operation_journal(path, &candidate)
    } else {
        match append_deposit_operation_record(path, operation, maximum_bytes) {
            Ok(()) => Ok(()),
            Err(SubstrateError::JournalLimitExceeded { .. }) => {
                compact_deposit_operation_ledger_to_bytes(path, &mut candidate, maximum_bytes)?;
                rewrite_deposit_operation_journal(path, &candidate)
            }
            Err(error) => Err(error),
        }
    };

    match persistence {
        Ok(()) => {
            *operations = candidate;
            Ok(())
        }
        Err(error @ SubstrateError::DurabilityOutcomeUnknown { .. }) => {
            // rename(2) made the rolled ledger process-visible. Reconcile
            // memory before failing closed so an exact retry observes it.
            *operations = candidate;
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn persist_deposit_operation(
    path: &Path,
    operations: &mut DepositOperationLedger,
    operation: &DepositOperationRecord,
) -> Result<(), SubstrateError> {
    persist_deposit_operation_with_limits(
        path,
        operations,
        operation,
        MAX_DEPOSIT_OPERATION_LEDGER_ENTRIES,
        MAX_LOCAL_DEPOSIT_OPERATION_JOURNAL_BYTES,
    )
}

fn load_retained_deposit_jsonl(
    path: &Path,
    limits: DepositRetentionLimits,
    config: &PheromoneConfig,
    threat_class_configs: &BTreeMap<ThreatClass, ThreatClassConfig>,
    trusted_now: Option<i64>,
) -> Result<(RetainedDeposits, bool), SubstrateError> {
    let observed_bytes = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((RetainedDeposits::default(), false));
        }
        Err(source) => {
            return Err(SubstrateError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if observed_bytes == 0 {
        return Ok((RetainedDeposits::default(), false));
    }

    let file = fs::File::open(path).map_err(|source| SubstrateError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut retained = RetainedDeposits::default();
    let mut pruned = 0usize;
    let mut line_number = 0usize;
    let read_limit = u64::try_from(MAX_SINGLE_DEPOSIT_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(2);

    loop {
        let mut line = Vec::new();
        let bytes_read = Read::by_ref(&mut reader)
            .take(read_limit)
            .read_until(b'\n', &mut line)
            .map_err(|source| SubstrateError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        line_number = line_number.saturating_add(1);
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
        }
        if line.len() > MAX_SINGLE_DEPOSIT_BYTES {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!(
                    "journal line {line_number} is larger than the {MAX_SINGLE_DEPOSIT_BYTES}-byte deposit limit"
                ),
            });
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let location = format!("{} line {line_number}", path.display());
        let entry = decode_deposit_payload(&line, location)?;
        let policy = resolved_policy(config, threat_class_configs, &entry.threat_class);
        match retained.push(
            entry,
            limits,
            policy.half_life_secs,
            policy.evaporation_threshold,
            trusted_now,
        ) {
            Ok(removed) => pruned = pruned.saturating_add(removed),
            Err(SubstrateError::ExpiredDeposit { .. }) => {
                pruned = pruned.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }

    Ok((
        retained,
        pruned > 0 || observed_bytes > limits.max_journal_bytes,
    ))
}

fn rewrite_verified_deposit_jsonl(
    path: &Path,
    entries: &[VerifiedDeposit],
) -> Result<(), SubstrateError> {
    let deposits = entries
        .iter()
        .map(|entry| &entry.deposit)
        .collect::<Vec<_>>();
    rewrite_jsonl(path, &deposits)
}

fn append_jsonl_line<T>(path: &Path, entry: &T) -> Result<(), SubstrateError>
where
    T: Serialize,
{
    ensure_parent_dir(path)?;
    let serialized = serde_json::to_string(entry).map_err(|source| SubstrateError::Parse {
        path: path.to_path_buf(),
        line: 0,
        source,
    })?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    writeln!(file, "{serialized}").map_err(|source| SubstrateError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    file.sync_data().map_err(|source| SubstrateError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn rewrite_jsonl<T>(path: &Path, entries: &[T]) -> Result<(), SubstrateError>
where
    T: Serialize,
{
    ensure_parent_dir(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pheromone.jsonl");
    static NEXT_REWRITE: AtomicU64 = AtomicU64::new(0);
    let (temp_path, mut file) = loop {
        let nonce = NEXT_REWRITE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.rewrite-{}-{nonce}",
            std::process::id()
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(SubstrateError::Write {
                    path: candidate,
                    source,
                });
            }
        }
    };

    let rewrite_result = (|| {
        for entry in entries {
            let serialized =
                serde_json::to_string(entry).map_err(|source| SubstrateError::Parse {
                    path: path.to_path_buf(),
                    line: 0,
                    source,
                })?;
            writeln!(file, "{serialized}").map_err(|source| SubstrateError::Write {
                path: temp_path.clone(),
                source,
            })?;
        }
        file.sync_all().map_err(|source| SubstrateError::Write {
            path: temp_path.clone(),
            source,
        })?;
        fs::rename(&temp_path, path).map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Ok::<(), SubstrateError>(())
    })();
    if let Err(error) = rewrite_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    #[cfg(unix)]
    sync_rewrite_parent(path, parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_rewrite_parent(path: &Path, parent: &Path) -> Result<(), SubstrateError> {
    #[cfg(test)]
    {
        let mut guard = match rewrite_parent_sync_failure_path().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.as_deref() == Some(path) {
            *guard = None;
            return Err(SubstrateError::DurabilityOutcomeUnknown {
                path: path.to_path_buf(),
                source: std::io::Error::other("injected parent directory sync failure"),
            });
        }
    }
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| SubstrateError::DurabilityOutcomeUnknown {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(all(test, unix))]
fn inject_rewrite_parent_sync_failure(path: &Path) {
    let mut guard = match rewrite_parent_sync_failure_path().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.replace(path.to_path_buf());
}

fn load_threat_class_configs(
    path: &Path,
) -> Result<BTreeMap<ThreatClass, ThreatClassConfig>, SubstrateError> {
    let entries = load_jsonl::<ThreatClassConfig>(path)?;
    let mut configs = BTreeMap::new();
    for entry in entries {
        configs.insert(entry.threat_class.clone(), entry);
    }
    Ok(configs)
}

fn load_threat_intel_entries(
    path: &Path,
) -> Result<BTreeMap<ThreatIntelKey, ThreatIntelEntry>, SubstrateError> {
    let entries = load_jsonl::<ThreatIntelEntry>(path)?;
    let mut threat_intel_entries = BTreeMap::new();
    for entry in entries {
        let entry = normalize_threat_intel_entry(entry);
        let key = threat_intel_key(&entry.indicator_type, &entry.value);
        threat_intel_entries.insert(key, entry);
    }
    Ok(threat_intel_entries)
}

fn load_behavioral_baseline_snapshots(
    path: &Path,
    sequences: &mut BTreeMap<String, u64>,
) -> Result<BTreeMap<String, BehavioralBaselineEnvelope>, SubstrateError> {
    let entries = load_jsonl::<BehavioralBaselineEnvelope>(path)?;
    let mut snapshots = BTreeMap::new();
    for entry in entries {
        let strategy_id = entry.stream_id().to_string();
        let accepted_sequence = sequences.get(&strategy_id).copied();
        verify_behavioral_baseline_snapshot(&entry, &strategy_id, None, accepted_sequence)?;
        sequences.insert(
            strategy_id.clone(),
            accepted_sequence.map_or(entry.sequence(), |current| current.max(entry.sequence())),
        );
        snapshots.insert(strategy_id, entry);
    }
    Ok(snapshots)
}

fn escalation_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("escalations.jsonl")
}

fn deposit_operation_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("deposit-operations.jsonl")
}

fn threat_class_config_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("threat-class-configs.jsonl")
}

fn threat_intel_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("threat-intel.jsonl")
}

fn behavioral_baseline_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("behavioral-baselines.jsonl")
}

fn behavioral_baseline_sequence_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("behavioral-baselines.sequence.json")
}

fn load_behavioral_baseline_sequences(
    path: &Path,
) -> Result<BTreeMap<String, u64>, SubstrateError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path).map_err(|source| SubstrateError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| SubstrateError::Parse {
        path: path.to_path_buf(),
        line: 0,
        source,
    })
}

fn write_behavioral_baseline_sequences(
    path: &Path,
    sequences: &BTreeMap<String, u64>,
) -> Result<(), SubstrateError> {
    ensure_parent_dir(path)?;
    let raw = serde_json::to_string_pretty(sequences).map_err(|source| SubstrateError::Parse {
        path: path.to_path_buf(),
        line: 0,
        source,
    })?;
    fs::write(path, raw).map_err(|source| SubstrateError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn next_behavioral_baseline_sequence(current_sequence: Option<u64>) -> u64 {
    current_sequence.unwrap_or(0).saturating_add(1)
}

fn sign_behavioral_baseline_snapshot(
    snapshot: BehavioralBaselineSnapshot,
    signer_agent_id: &AgentId,
    sequence: u64,
    signing_key: &SigningKey,
) -> Result<BehavioralBaselineEnvelope, SubstrateError> {
    let strategy_id = snapshot.strategy_id.clone();
    SignedStateEnvelope::sign(
        BEHAVIORAL_BASELINE_STATE_KIND,
        strategy_id.clone(),
        signer_agent_id.clone(),
        sequence,
        snapshot,
        signing_key,
    )
    .map_err(|source| SubstrateError::InvalidBehavioralBaseline {
        strategy_id,
        source,
    })
}

fn verify_behavioral_baseline_snapshot(
    envelope: &BehavioralBaselineEnvelope,
    strategy_id: &str,
    expected_signer_agent_id: Option<&AgentId>,
    accepted_sequence: Option<u64>,
) -> Result<swarm_core::VerifiedSignedState<BehavioralBaselineSnapshot>, SubstrateError> {
    envelope
        .verify(SignedStateExpectation {
            state_kind: BEHAVIORAL_BASELINE_STATE_KIND,
            stream_id: strategy_id,
            expected_signer_agent_id,
            accepted_sequence,
        })
        .map_err(|source| SubstrateError::InvalidBehavioralBaseline {
            strategy_id: strategy_id.to_string(),
            source,
        })
}

fn resolved_policy(
    config: &PheromoneConfig,
    threat_class_configs: &BTreeMap<ThreatClass, ThreatClassConfig>,
    threat_class: &ThreatClass,
) -> ThreatClassPolicy {
    config.resolve_threat_class_policy(threat_class_configs.get(threat_class))
}

fn ordered_threat_class_configs(
    threat_class_configs: &BTreeMap<ThreatClass, ThreatClassConfig>,
) -> Vec<ThreatClassConfig> {
    threat_class_configs.values().cloned().collect()
}

pub(crate) fn normalize_threat_intel_value(
    indicator_type: &ThreatIntelIndicatorType,
    value: &str,
) -> String {
    let trimmed = value.trim();
    match indicator_type {
        ThreatIntelIndicatorType::Domain => trimmed.trim_end_matches('.').to_ascii_lowercase(),
        ThreatIntelIndicatorType::Url => normalize_url_value(trimmed),
        ThreatIntelIndicatorType::IpAddress | ThreatIntelIndicatorType::FileHash => {
            trimmed.to_ascii_lowercase()
        }
    }
}

fn normalize_url_value(value: &str) -> String {
    // URL paths and query strings are case-sensitive on most servers, so
    // lowercasing the whole URL collapses distinct resources to the same key.
    // Lowercase only the scheme and authority (host[:port]); preserve path,
    // query, and fragment case verbatim. Strip exactly one trailing `/` from
    // the path component (so `https://x/p/` and `https://x/p` collapse to the
    // same key) but never touch trailing slashes inside the query or fragment
    // — `?next=/admin/` and `?next=/admin` are distinct values.
    let after_scheme = value.find("://").map(|i| i + 3).unwrap_or(0);
    let authority_end = value[after_scheme..]
        .find(['/', '?', '#'])
        .map(|rel| after_scheme + rel)
        .unwrap_or(value.len());
    let scheme_authority = value[..authority_end].to_ascii_lowercase();
    let remainder = &value[authority_end..];
    let (path, query_frag) = match remainder.find(['?', '#']) {
        Some(i) => (&remainder[..i], &remainder[i..]),
        None => (remainder, ""),
    };
    let path_normalized = path.strip_suffix('/').unwrap_or(path);
    let mut out = scheme_authority;
    out.push_str(path_normalized);
    out.push_str(query_frag);
    out
}

fn normalize_threat_intel_entry(mut entry: ThreatIntelEntry) -> ThreatIntelEntry {
    entry.value = normalize_threat_intel_value(&entry.indicator_type, &entry.value);
    entry
}

fn threat_intel_key(indicator_type: &ThreatIntelIndicatorType, value: &str) -> ThreatIntelKey {
    (
        indicator_type.clone(),
        normalize_threat_intel_value(indicator_type, value),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ConfiguredPheromoneSubstrate, DepositQuery, InMemoryPheromoneSubstrate,
        LocalJournalPheromoneSubstrate, PheromoneSubstrate,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
    use swarm_core::pheromone::{
        BehavioralBaselineSnapshot, BehavioralFrequencyEntry, BehavioralHostBaseline,
        BehavioralIdentityBaseline, BehavioralPeerGroupBaseline, BehavioralRoleToolFrequencyEntry,
        BehavioralTelemetryFamilyBaseline, EscalationRecord, PheromoneConcentration,
        PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry,
        ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, SWARM_PROVIDENCE_FEEDBACK_SCHEMA, Severity};

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn normalize_url_value_lowercases_scheme_authority_only() {
        let out = super::normalize_url_value(
            "HTTPS://Evil.Example/Path/Mixed?Q=Keep&Slash=/Admin/#Frag/",
        );
        assert_eq!(
            out,
            "https://evil.example/Path/Mixed?Q=Keep&Slash=/Admin/#Frag/"
        );
    }

    #[test]
    fn normalize_url_value_strips_one_path_slash_only() {
        assert_eq!(super::normalize_url_value("https://x/p/"), "https://x/p");
        assert_eq!(super::normalize_url_value("https://x/p//"), "https://x/p/");
    }

    #[test]
    fn normalize_url_value_preserves_query_trailing_slash() {
        let out = super::normalize_url_value("https://evil.example/cb?next=/admin/");
        assert_eq!(out, "https://evil.example/cb?next=/admin/");
    }

    #[test]
    fn normalize_url_value_preserves_fragment_trailing_slash() {
        let out = super::normalize_url_value("https://x/p#section/");
        assert_eq!(out, "https://x/p#section/");
    }

    #[test]
    fn normalize_url_value_strips_path_slash_before_query() {
        let out = super::normalize_url_value("https://x/p/?a=b");
        assert_eq!(out, "https://x/p?a=b");
    }

    fn signing_key_for_label(label: &str) -> SigningKey {
        let digest = Sha256::digest(label.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        SigningKey::from_bytes(&seed)
    }

    fn sign_deposit(deposit: &mut PheromoneDeposit, key: &SigningKey) {
        let payload_bytes = super::signing_payload_bytes_for_deposit(deposit).unwrap();
        let sig = key.sign(&payload_bytes);
        deposit.signature = sig.to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
    }

    fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
        sample_deposit_with_host(agent_id, timestamp, confidence, "host-1")
    }

    fn sample_event_deposit(agent_id: &str, event_id: &str, timestamp: i64) -> PheromoneDeposit {
        let key = signing_key_for_label(agent_id);
        let mut deposit = sample_deposit(agent_id, timestamp, 0.9);
        deposit.indicator["event_id"] = serde_json::Value::String(event_id.to_string());
        sign_deposit(&mut deposit, &key);
        deposit
    }

    fn sample_feedback_deposit(
        agent_id: &str,
        event_id: &str,
        action: &str,
        timestamp: i64,
    ) -> PheromoneDeposit {
        let key = signing_key_for_label(agent_id);
        let mut deposit = sample_deposit(agent_id, timestamp, 0.9);
        deposit.indicator = serde_json::json!({
            "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
            "feedback_id": format!("feedback-{event_id}-{timestamp}"),
            "event_id": event_id,
            "action": action,
            "observed_at_ms": timestamp.saturating_mul(1_000),
        });
        sign_deposit(&mut deposit, &key);
        deposit
    }

    fn sample_deposit_with_host(
        agent_id: &str,
        timestamp: i64,
        confidence: f64,
        host_id: &str,
    ) -> PheromoneDeposit {
        let key = signing_key_for_label(agent_id);
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "signal": "process-tree",
                "host_id": host_id,
            }),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: derived_agent_id.clone(),
            agent_identity: derived_agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        sign_deposit(&mut deposit, &key);
        deposit
    }

    fn strategy_scoped_deposit(
        base_agent: &str,
        strategy: &str,
        timestamp: i64,
        confidence: f64,
    ) -> PheromoneDeposit {
        let key = signing_key_for_label(base_agent);
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = sample_deposit(base_agent, timestamp, confidence);
        deposit.agent_id = AgentId(format!("{}:{strategy}", derived_agent_id.0));
        deposit.agent_identity = derived_agent_id.0;
        sign_deposit(&mut deposit, &key);
        deposit
    }

    fn unsigned_deposit() -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({"signal": "process-tree"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.9,
            timestamp: 100,
            decay_half_life: 3600.0,
            agent_id: AgentId("test-agent".to_string()),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn sample_escalation(mode: SwarmMode, timestamp: i64) -> EscalationRecord {
        EscalationRecord {
            mode,
            threat_class: ThreatClass::Execution,
            total_strength: 2.4,
            distinct_sources: 2,
            peak_confidence: 0.9,
            timestamp,
        }
    }

    fn sample_threat_class_config(
        threat_class: ThreatClass,
        half_life_secs: f64,
        alert_threshold: f64,
        incident_threshold: f64,
    ) -> ThreatClassConfig {
        ThreatClassConfig {
            threat_class,
            half_life_secs,
            evaporation_threshold: 0.05,
            alert_threshold,
            incident_threshold,
        }
    }

    fn sample_threat_intel_entry(
        indicator_type: ThreatIntelIndicatorType,
        value: &str,
        confidence: f64,
        expires_at: i64,
    ) -> ThreatIntelEntry {
        ThreatIntelEntry {
            indicator_type,
            value: value.to_string(),
            source: "operator".to_string(),
            indicator_id: None,
            confidence,
            expires_at,
        }
    }

    fn sample_behavioral_baseline_snapshot(strategy_id: &str) -> BehavioralBaselineSnapshot {
        BehavioralBaselineSnapshot {
            strategy_id: strategy_id.to_string(),
            captured_at: 1_700_000_500,
            hosts: vec![BehavioralHostBaseline {
                host_id: "host-1".to_string(),
                observation_count: 3,
                novelty_distribution: swarm_core::pheromone::BehavioralOnlineDistributionSnapshot {
                    sample_count: 2,
                    mean: 0.0,
                    m2: 0.0,
                },
                telemetry_families: vec![BehavioralTelemetryFamilyBaseline {
                    family: "network_connect".to_string(),
                    observation_count: 2,
                    novelty_distribution:
                        swarm_core::pheromone::BehavioralOnlineDistributionSnapshot {
                            sample_count: 1,
                            mean: 0.0,
                            m2: 0.0,
                        },
                    features: vec![BehavioralFrequencyEntry {
                        key: "network:svchost.exe->10.0.0.5:443/tcp".to_string(),
                        weight: 2.0,
                        last_seen_at: 1_700_000_450,
                    }],
                }],
                parent_child_pairs: vec![BehavioralFrequencyEntry {
                    key: "explorer.exe->notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
                binaries: vec![BehavioralFrequencyEntry {
                    key: "c:\\windows\\system32\\notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
                role_tools: vec![BehavioralRoleToolFrequencyEntry {
                    user_role: "user".to_string(),
                    tool: "notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
            }],
            identities: vec![BehavioralIdentityBaseline {
                identity_id: "alice".to_string(),
                observation_count: 3,
                novelty_distribution: swarm_core::pheromone::BehavioralOnlineDistributionSnapshot {
                    sample_count: 2,
                    mean: 0.0,
                    m2: 0.0,
                },
                telemetry_families: vec![BehavioralTelemetryFamilyBaseline {
                    family: "dns_query".to_string(),
                    observation_count: 2,
                    novelty_distribution:
                        swarm_core::pheromone::BehavioralOnlineDistributionSnapshot {
                            sample_count: 1,
                            mean: 0.0,
                            m2: 0.0,
                        },
                    features: vec![BehavioralFrequencyEntry {
                        key: "dns:chrome.exe->example.com:a".to_string(),
                        weight: 2.0,
                        last_seen_at: 1_700_000_450,
                    }],
                }],
                parent_child_pairs: vec![BehavioralFrequencyEntry {
                    key: "explorer.exe->notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
                binaries: vec![BehavioralFrequencyEntry {
                    key: "c:\\windows\\system32\\notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
                role_tools: vec![BehavioralRoleToolFrequencyEntry {
                    user_role: "interactive".to_string(),
                    tool: "notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
            }],
            peer_groups: vec![BehavioralPeerGroupBaseline {
                peer_group_id: "role:interactive".to_string(),
                observation_count: 4,
                novelty_distribution: swarm_core::pheromone::BehavioralOnlineDistributionSnapshot {
                    sample_count: 3,
                    mean: 0.0,
                    m2: 0.0,
                },
                telemetry_families: vec![BehavioralTelemetryFamilyBaseline {
                    family: "process_memory_access".to_string(),
                    observation_count: 2,
                    novelty_distribution:
                        swarm_core::pheromone::BehavioralOnlineDistributionSnapshot {
                            sample_count: 1,
                            mean: 0.0,
                            m2: 0.0,
                        },
                    features: vec![BehavioralFrequencyEntry {
                        key: "memory:winword.exe->lsass.exe:virtual_alloc_ex".to_string(),
                        weight: 2.0,
                        last_seen_at: 1_700_000_450,
                    }],
                }],
                parent_child_pairs: vec![BehavioralFrequencyEntry {
                    key: "explorer.exe->notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
                binaries: vec![BehavioralFrequencyEntry {
                    key: "c:\\windows\\system32\\notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
                role_tools: vec![BehavioralRoleToolFrequencyEntry {
                    user_role: "interactive".to_string(),
                    tool: "notepad.exe".to_string(),
                    weight: 2.0,
                    last_seen_at: 1_700_000_400,
                }],
            }],
        }
    }

    fn substrate_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: ResponsePlaybookConfig::default(),
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn in_memory() -> InMemoryPheromoneSubstrate {
        InMemoryPheromoneSubstrate::new_for_replay(substrate_config())
    }

    #[tokio::test]
    async fn providence_feedback_deposit_operation_is_idempotent_and_conflict_safe() {
        let substrate = in_memory();
        let deposit =
            sample_feedback_deposit("reviewer-idempotent", "event-idempotent", "dismiss", 200);
        substrate.deposit(deposit.clone()).await.unwrap();
        substrate.deposit(deposit.clone()).await.unwrap();
        assert_eq!(substrate.recent_deposits(10).await.unwrap().len(), 1);

        assert_eq!(substrate.gc_evaporated(1_000_000).await.unwrap(), 1);
        substrate.deposit(deposit.clone()).await.unwrap();
        assert!(substrate.recent_deposits(10).await.unwrap().is_empty());

        let mut conflict = deposit;
        conflict.indicator["reason"] = serde_json::json!("different signed payload");
        sign_deposit(&mut conflict, &signing_key_for_label("reviewer-idempotent"));
        assert!(matches!(
            substrate.deposit(conflict).await,
            Err(super::SubstrateError::InvalidDeposit { reason })
                if reason.contains("operation id was reused")
        ));
    }

    #[tokio::test]
    async fn query_respects_source_diversity() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("whisker-a", 100, 1.0))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-a", 100, 0.8))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", 100, 0.9))
            .await
            .unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();

        assert_eq!(concentration.distinct_sources, 2);
        assert!(concentration.total_strength > 2.0);
    }

    #[tokio::test]
    async fn query_counts_strategy_scoped_agent_ids_by_derived_identity() {
        let substrate = in_memory();
        let admitted_identity =
            AgentId::from_verifying_key(&signing_key_for_label("whisker-primary").verifying_key());
        substrate
            .set_admitted_identities([admitted_identity])
            .unwrap();
        substrate
            .deposit(strategy_scoped_deposit(
                "whisker-primary",
                "suspicious_process_tree",
                100,
                0.9,
            ))
            .await
            .unwrap();
        substrate
            .deposit(strategy_scoped_deposit(
                "whisker-primary",
                "dns_exfiltration",
                100,
                0.9,
            ))
            .await
            .unwrap();
        substrate
            .deposit(strategy_scoped_deposit(
                "whisker-primary",
                "credential_access",
                100,
                0.9,
            ))
            .await
            .unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();

        assert_eq!(concentration.distinct_sources, 1);
    }

    #[tokio::test]
    async fn query_collapses_replayed_strategy_scoped_agent_ids_to_one_source() {
        let substrate = in_memory();
        substrate
            .deposit(strategy_scoped_deposit(
                "whisker-primary",
                "suspicious_process_tree",
                100,
                0.9,
            ))
            .await
            .unwrap();
        substrate
            .deposit(strategy_scoped_deposit(
                "whisker-primary",
                "dns_exfiltration",
                101,
                0.8,
            ))
            .await
            .unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();

        assert_eq!(concentration.distinct_sources, 1);
    }

    #[tokio::test]
    async fn query_counts_two_admitted_signing_keys_as_two_sources() {
        let substrate = in_memory();
        let admitted_a =
            AgentId::from_verifying_key(&signing_key_for_label("admitted-a").verifying_key());
        let admitted_b =
            AgentId::from_verifying_key(&signing_key_for_label("admitted-b").verifying_key());
        substrate
            .set_admitted_identities([admitted_a, admitted_b])
            .unwrap();

        substrate
            .deposit(strategy_scoped_deposit(
                "admitted-a",
                "suspicious_process_tree",
                100,
                0.9,
            ))
            .await
            .unwrap();
        substrate
            .deposit(strategy_scoped_deposit(
                "admitted-b",
                "dns_exfiltration",
                100,
                0.9,
            ))
            .await
            .unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();

        assert_eq!(concentration.distinct_sources, 2);
    }

    #[tokio::test]
    async fn changing_only_strategy_suffix_cannot_change_escalation_outcome() {
        async fn query_for_suffixes(suffixes: &[&str]) -> PheromoneConcentration {
            let substrate = in_memory();
            for (timestamp, suffix) in suffixes.iter().enumerate() {
                substrate
                    .deposit(strategy_scoped_deposit(
                        "threshold-agent",
                        suffix,
                        100 + timestamp as i64,
                        1.0,
                    ))
                    .await
                    .unwrap();
            }
            substrate
                .query_concentration(&ThreatClass::Execution, 100)
                .await
                .unwrap()
        }

        let unchanged_suffix = query_for_suffixes(&["strategy-a", "strategy-a"]).await;
        let changed_suffix = query_for_suffixes(&["strategy-a", "strategy-b"]).await;

        assert_eq!(unchanged_suffix.distinct_sources, 1);
        assert_eq!(changed_suffix.distinct_sources, 1);
        assert!((unchanged_suffix.total_strength - changed_suffix.total_strength).abs() < 0.01);
        assert_eq!(
            unchanged_suffix.exceeds_threshold(2.0, 2),
            changed_suffix.exceeds_threshold(2.0, 2)
        );
        assert!(!changed_suffix.exceeds_threshold(2.0, 2));
    }

    #[test]
    fn verified_deposit_rejects_malformed_cryptographic_identity_before_query() {
        let key = signing_key_for_label("malformed-identity");
        let mut deposit = strategy_scoped_deposit("malformed-identity", "strategy-a", 100, 1.0);
        deposit.agent_identity = "not-a-derived-identity".to_string();
        sign_deposit(&mut deposit, &key);

        assert!(matches!(
            super::VerifiedDeposit::admit(deposit),
            Err(super::SubstrateError::InvalidDeposit { .. })
        ));
    }

    #[test]
    fn verified_deposit_rejects_body_tamper_before_query() {
        let mut deposit = strategy_scoped_deposit("tampered-body", "strategy-a", 100, 1.0);
        deposit.confidence = 0.25;

        assert!(matches!(
            super::VerifiedDeposit::admit(deposit),
            Err(super::SubstrateError::InvalidDeposit { .. })
        ));
    }

    #[tokio::test]
    async fn recent_deposits_support_replay() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("whisker-a", 100, 1.0))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", 200, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-c", 300, 0.8))
            .await
            .unwrap();

        let deposits = substrate.recent_deposits(2).await.unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].timestamp, 300);
        assert_eq!(deposits[1].timestamp, 200);
    }

    #[tokio::test]
    async fn query_deposits_filters_by_threat_class_and_time() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("whisker-a", 100, 1.0))
            .await
            .unwrap();
        let mut second = sample_deposit("whisker-b", 200, 0.9);
        second.threat_class = ThreatClass::DefenseEvasion;
        sign_deposit(&mut second, &signing_key_for_label("whisker-b"));
        substrate.deposit(second).await.unwrap();

        let deposits = substrate
            .query_deposits(DepositQuery {
                threat_class: Some(ThreatClass::Execution),
                since_timestamp: Some(50),
                host_id: None,
                limit: 10,
            })
            .await
            .unwrap();

        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].timestamp, 100);
    }

    #[tokio::test]
    async fn gc_removes_evaporated_deposits() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("whisker-a", 0, 0.1))
            .await
            .unwrap();

        let removed = substrate.gc_evaporated(100_000).await.unwrap();
        assert_eq!(removed, 1);
    }

    #[tokio::test]
    async fn query_deposits_filters_by_host_id() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit_with_host("whisker-a", 100, 1.0, "host-a"))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit_with_host("whisker-b", 200, 0.9, "host-b"))
            .await
            .unwrap();

        let deposits = substrate
            .query_deposits(DepositQuery {
                threat_class: None,
                since_timestamp: None,
                host_id: Some("host-b".to_string()),
                limit: 10,
            })
            .await
            .unwrap();

        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].timestamp, 200);
        assert_eq!(deposits[0].indicator["host_id"], "host-b");
    }

    #[tokio::test]
    async fn query_escalations_returns_chronological_records() {
        let substrate = in_memory();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Alert, 100))
            .await
            .unwrap();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Incident, 250))
            .await
            .unwrap();

        let escalations = substrate.query_escalations(150).await.unwrap();
        assert_eq!(escalations.len(), 1);
        assert_eq!(escalations[0].mode, SwarmMode::Incident);
        assert_eq!(escalations[0].timestamp, 250);
    }

    #[tokio::test]
    async fn query_threat_class_configs_returns_stored_overrides() {
        let substrate = in_memory();
        substrate
            .store_threat_class_config(sample_threat_class_config(
                ThreatClass::Execution,
                120.0,
                1.2,
                3.0,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_class_config(sample_threat_class_config(
                ThreatClass::DefenseEvasion,
                240.0,
                1.4,
                3.5,
            ))
            .await
            .unwrap();

        let configs = substrate.query_threat_class_configs().await.unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].threat_class, ThreatClass::DefenseEvasion);
        assert_eq!(configs[1].threat_class, ThreatClass::Execution);
    }

    #[tokio::test]
    async fn threat_class_override_rejects_already_evaporated_deposit() {
        let substrate = in_memory();
        substrate
            .store_threat_class_config(sample_threat_class_config(
                ThreatClass::Execution,
                60.0,
                0.4,
                0.8,
            ))
            .await
            .unwrap();
        let mut already_evaporated = sample_deposit("whisker-a", 0, 0.03);
        already_evaporated.decay_half_life = 60.0;
        sign_deposit(&mut already_evaporated, &signing_key_for_label("whisker-a"));
        assert!(matches!(
            substrate.deposit(already_evaporated).await,
            Err(super::SubstrateError::ExpiredDeposit {
                timestamp: 0,
                timestamp_high_water: 0,
            })
        ));

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 0)
            .await
            .unwrap();
        assert_eq!(concentration.total_strength, 0.0);

        assert_eq!(substrate.gc_evaporated(0).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn zero_strength_control_records_have_a_bounded_retention_lifetime() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("memory-query", 100, 0.0))
            .await
            .unwrap();

        assert_eq!(substrate.recent_deposits(10).await.unwrap().len(), 1);
        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();
        assert_eq!(concentration.total_strength, 0.0);
        assert_eq!(substrate.gc_evaporated(100).await.unwrap(), 0);

        assert_eq!(substrate.gc_evaporated(100_000).await.unwrap(), 1);
        assert!(substrate.recent_deposits(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn timestamp_high_water_is_isolated_by_threat_class() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("future-execution", 100_000, 0.9))
            .await
            .unwrap();

        let mut defense_evasion = sample_deposit("older-defense-evasion", 0, 0.9);
        defense_evasion.threat_class = ThreatClass::DefenseEvasion;
        sign_deposit(
            &mut defense_evasion,
            &signing_key_for_label("older-defense-evasion"),
        );
        substrate.deposit(defense_evasion).await.unwrap();

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);
        assert!(
            deposits
                .iter()
                .any(|deposit| deposit.threat_class == ThreatClass::DefenseEvasion)
        );
    }

    #[tokio::test]
    async fn query_threat_intel_entry_respects_normalization_and_expiration() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                " Example.COM. ",
                0.92,
                1_700_000_000_100,
            ))
            .await
            .unwrap();

        let stored = substrate
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_000,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.value, "example.com");
        assert_eq!(stored.confidence, 0.92);

        let expired = substrate
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "EXAMPLE.COM.",
                1_700_000_000_100,
            )
            .await
            .unwrap();
        assert!(expired.is_none());
    }

    #[tokio::test]
    async fn local_journal_recovers_deposits_after_reopen() {
        let path = std::env::temp_dir().join("swarm-pheromone-journal.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };

        {
            let substrate =
                LocalJournalPheromoneSubstrate::open_for_replay(config.clone(), &path).unwrap();
            substrate
                .deposit(sample_deposit("whisker-a", 100, 0.9))
                .await
                .unwrap();
            substrate
                .deposit(sample_deposit("whisker-b", 200, 0.8))
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open_for_replay(config, &path).unwrap();
        let deposits = reopened.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].timestamp, 200);

        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert!(health.durable);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
    }

    fn sample_deposit_operation_record(label: &str) -> super::DepositOperationRecord {
        super::DepositOperationRecord {
            operation_id: format!("operation-{label}"),
            deposit_digest: swarm_crypto::sha256_hex(label.as_bytes()),
        }
    }

    #[test]
    fn feedback_operation_ledger_is_a_bounded_conflict_safe_retry_window() {
        let first = sample_deposit_operation_record("first");
        let second = sample_deposit_operation_record("second");
        let third = sample_deposit_operation_record("third");
        let mut ledger = super::DepositOperationLedger::default();

        assert_eq!(
            ledger.insert_with_limit(&first, 2).unwrap(),
            super::DepositOperationInsert::Inserted { evicted: 0 }
        );
        assert_eq!(
            ledger.insert_with_limit(&second, 2).unwrap(),
            super::DepositOperationInsert::Inserted { evicted: 0 }
        );
        assert_eq!(
            ledger.insert_with_limit(&first, 2).unwrap(),
            super::DepositOperationInsert::AlreadyRecorded
        );

        let mut conflict = first.clone();
        conflict.deposit_digest = swarm_crypto::sha256_hex(b"conflict");
        assert!(matches!(
            ledger.insert_with_limit(&conflict, 2),
            Err(super::SubstrateError::InvalidDeposit { reason })
                if reason.contains("operation id was reused")
        ));

        assert_eq!(
            ledger.insert_with_limit(&third, 2).unwrap(),
            super::DepositOperationInsert::Inserted { evicted: 1 }
        );
        assert!(!ledger.records.contains_key(&first.operation_id));
        assert!(ledger.records.contains_key(&second.operation_id));
        assert!(ledger.records.contains_key(&third.operation_id));
        assert_eq!(
            ledger.insertion_order,
            std::collections::VecDeque::from([second.operation_id, third.operation_id])
        );
    }

    #[test]
    fn local_feedback_operation_ledger_rolls_over_durably_by_count_and_bytes() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-feedback-operation-rollover-{unique}.jsonl"
        ));
        let first = sample_deposit_operation_record("first");
        let second = sample_deposit_operation_record("second");
        let third = sample_deposit_operation_record("third");
        let fourth = sample_deposit_operation_record("fourth");
        let mut ledger = super::DepositOperationLedger::default();

        super::persist_deposit_operation_with_limits(&path, &mut ledger, &first, 2, 1_000_000)
            .unwrap();
        super::persist_deposit_operation_with_limits(&path, &mut ledger, &second, 2, 1_000_000)
            .unwrap();
        super::persist_deposit_operation_with_limits(&path, &mut ledger, &third, 2, 1_000_000)
            .unwrap();

        let (reopened, rewrite_required) = super::load_deposit_operations(&path).unwrap();
        assert!(!rewrite_required);
        assert_eq!(
            reopened.insertion_order,
            std::collections::VecDeque::from([
                second.operation_id.clone(),
                third.operation_id.clone(),
            ])
        );
        assert!(!reopened.records.contains_key(&first.operation_id));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);

        let retained_bytes = [&third, &fourth]
            .into_iter()
            .map(|record| serde_json::to_vec(record).unwrap().len() + 1)
            .sum::<usize>() as u64;
        let mut reopened = reopened;
        super::persist_deposit_operation_with_limits(
            &path,
            &mut reopened,
            &fourth,
            10,
            retained_bytes,
        )
        .unwrap();

        let (rolled, rewrite_required) = super::load_deposit_operations(&path).unwrap();
        assert!(!rewrite_required);
        assert_eq!(
            rolled.insertion_order,
            std::collections::VecDeque::from([
                third.operation_id.clone(),
                fourth.operation_id.clone(),
            ])
        );
        assert!(!rolled.records.contains_key(&second.operation_id));
        assert!(std::fs::metadata(&path).unwrap().len() <= retained_bytes);

        super::append_deposit_operation_record(&path, &fourth, 1_000_000).unwrap();
        let (deduplicated, rewrite_required) = super::load_deposit_operations(&path).unwrap();
        assert!(rewrite_required);
        super::rewrite_deposit_operation_journal(&path, &deduplicated).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        assert_eq!(deduplicated.insertion_order, rolled.insertion_order);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn local_journal_remembers_feedback_operations_after_eviction_and_restart() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-feedback-operation-ledger-{unique}.jsonl"
        ));
        let operation_path = super::deposit_operation_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let deposit = sample_feedback_deposit("reviewer-durable", "event-durable", "dismiss", 200);
        {
            let substrate =
                LocalJournalPheromoneSubstrate::open_for_replay(config.clone(), &path).unwrap();
            substrate.deposit(deposit.clone()).await.unwrap();
            assert_eq!(substrate.gc_evaporated(1_000_000).await.unwrap(), 1);
            assert!(substrate.recent_deposits(10).await.unwrap().is_empty());
        }

        let reopened =
            LocalJournalPheromoneSubstrate::open_for_replay(config.clone(), &path).unwrap();
        reopened.deposit(deposit.clone()).await.unwrap();
        assert!(reopened.recent_deposits(10).await.unwrap().is_empty());

        let mut conflict = deposit;
        conflict.indicator["reason"] = serde_json::json!("conflicting retry");
        sign_deposit(&mut conflict, &signing_key_for_label("reviewer-durable"));
        assert!(matches!(
            reopened.deposit(conflict).await,
            Err(super::SubstrateError::InvalidDeposit { reason })
                if reason.contains("operation id was reused")
        ));

        drop(reopened);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(operation_path);
    }

    #[tokio::test]
    async fn local_journal_repairs_only_an_uncommitted_operation_ledger_tail() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-feedback-operation-torn-tail-{unique}.jsonl"
        ));
        let operation_path = super::deposit_operation_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let committed = sample_feedback_deposit("reviewer-tail", "event-committed", "dismiss", 200);
        {
            let substrate =
                LocalJournalPheromoneSubstrate::open_for_replay(config.clone(), &path).unwrap();
            substrate.deposit(committed.clone()).await.unwrap();
        }
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&operation_path)
                .unwrap();
            file.write_all(b"{\"operation_id\":\"torn").unwrap();
            file.sync_all().unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open_for_replay(config, &path).unwrap();
        reopened.deposit(committed).await.unwrap();
        let repaired = std::fs::read(&operation_path).unwrap();
        assert_eq!(repaired.last(), Some(&b'\n'));
        assert_eq!(repaired.iter().filter(|byte| **byte == b'\n').count(), 1);

        drop(reopened);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(operation_path);
    }

    #[tokio::test]
    async fn deposit_retention_bounds_memory_and_compacts_the_durable_journal() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("swarm-pheromone-retention-{unique}.jsonl"));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let limits = super::DepositRetentionLimits {
            max_count: 4,
            max_bytes: 1024 * 1024,
            compacted_count: 2,
            compacted_bytes: 768 * 1024,
            max_journal_bytes: 1024 * 1024,
        };

        let memory = InMemoryPheromoneSubstrate::with_retention_limits(config.clone(), limits);
        let local = LocalJournalPheromoneSubstrate::open_with_retention_limits(
            config.clone(),
            &path,
            limits,
        )
        .unwrap();
        for timestamp in 100..105 {
            let deposit = sample_deposit("retained-agent", timestamp, 0.9);
            memory.deposit(deposit.clone()).await.unwrap();
            local.deposit(deposit).await.unwrap();
        }

        let memory_entries = memory.recent_deposits(10).await.unwrap();
        let local_entries = local.recent_deposits(10).await.unwrap();
        assert_eq!(memory_entries.len(), 2);
        assert_eq!(local_entries.len(), 2);
        assert_eq!(
            local_entries
                .iter()
                .map(|deposit| deposit.timestamp)
                .collect::<Vec<_>>(),
            vec![104, 103]
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().lines().count(),
            2,
            "durable compaction must match the bounded in-memory view"
        );
        drop(local);

        let reopened =
            LocalJournalPheromoneSubstrate::open_with_retention_limits(config, &path, limits)
                .unwrap();
        assert_eq!(reopened.recent_deposits(10).await.unwrap().len(), 2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[tokio::test]
    async fn retention_compaction_preserves_independent_signed_threat_partitions() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-partitioned-retention-{unique}.jsonl"
        ));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let limits = super::DepositRetentionLimits {
            max_count: 4,
            max_bytes: 1024 * 1024,
            compacted_count: 3,
            compacted_bytes: 768 * 1024,
            max_journal_bytes: 1024 * 1024,
        };
        let memory = InMemoryPheromoneSubstrate::with_retention_limits(config.clone(), limits);
        let local = LocalJournalPheromoneSubstrate::open_with_retention_limits(
            config.clone(),
            &path,
            limits,
        )
        .unwrap();

        let execution = sample_deposit("execution-live", 100, 0.9);
        let mut credential = sample_deposit("credential-live", 101, 0.8);
        credential.threat_class = ThreatClass::CredentialAccess;
        sign_deposit(&mut credential, &signing_key_for_label("credential-live"));
        for deposit in [execution, credential] {
            memory.deposit(deposit.clone()).await.unwrap();
            local.deposit(deposit).await.unwrap();
        }

        for timestamp in 200..203 {
            let mut flood = sample_deposit("one-admitted-flood-signer", timestamp, 0.9);
            flood.threat_class = ThreatClass::DefenseEvasion;
            sign_deposit(
                &mut flood,
                &signing_key_for_label("one-admitted-flood-signer"),
            );
            memory.deposit(flood.clone()).await.unwrap();
            local.deposit(flood).await.unwrap();
        }

        for deposits in [
            memory.recent_deposits(10).await.unwrap(),
            local.recent_deposits(10).await.unwrap(),
        ] {
            assert_eq!(deposits.len(), 3);
            assert!(
                deposits
                    .iter()
                    .any(|deposit| deposit.threat_class == ThreatClass::Execution)
            );
            assert!(
                deposits
                    .iter()
                    .any(|deposit| deposit.threat_class == ThreatClass::CredentialAccess)
            );
            assert_eq!(
                deposits
                    .iter()
                    .filter(|deposit| deposit.threat_class == ThreatClass::DefenseEvasion)
                    .count(),
                1
            );
        }

        drop(local);
        let reopened =
            LocalJournalPheromoneSubstrate::open_with_retention_limits(config, &path, limits)
                .unwrap();
        let reopened_deposits = reopened.recent_deposits(10).await.unwrap();
        assert_eq!(reopened_deposits.len(), 3);
        assert!(
            reopened_deposits
                .iter()
                .any(|deposit| deposit.threat_class == ThreatClass::Execution)
        );
        assert!(
            reopened_deposits
                .iter()
                .any(|deposit| deposit.threat_class == ThreatClass::CredentialAccess)
        );
        drop(reopened);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[test]
    fn retention_compaction_separates_control_records_from_signed_evidence() {
        let limits = super::DepositRetentionLimits {
            max_count: 3,
            max_bytes: 1024 * 1024,
            compacted_count: 2,
            compacted_bytes: 768 * 1024,
            max_journal_bytes: 1024 * 1024,
        };
        let mut retained = super::RetainedDeposits::default();
        retained
            .push(
                super::VerifiedDeposit::admit(sample_deposit("shared-signer", 100, 0.9)).unwrap(),
                limits,
                3_600.0,
                0.01,
                None,
            )
            .unwrap();
        for timestamp in 101..104 {
            retained
                .push(
                    super::VerifiedDeposit::admit(sample_deposit("shared-signer", timestamp, 0.0))
                        .unwrap(),
                    limits,
                    3_600.0,
                    0.01,
                    None,
                )
                .unwrap();
        }

        assert_eq!(retained.len(), 2);
        assert_eq!(
            retained
                .entries
                .iter()
                .filter(|deposit| deposit.confidence > 0.0)
                .count(),
            1
        );
        assert_eq!(
            retained
                .entries
                .iter()
                .filter(|deposit| deposit.confidence == 0.0)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn expired_flood_cannot_consume_retention_or_evict_live_evidence() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("swarm-pheromone-expired-flood-{unique}.jsonl"));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let limits = super::DepositRetentionLimits {
            max_count: 2,
            max_bytes: 1024 * 1024,
            compacted_count: 1,
            compacted_bytes: 768 * 1024,
            max_journal_bytes: 1024 * 1024,
        };
        let memory = InMemoryPheromoneSubstrate::with_live_retention_limits(config.clone(), limits);
        let local = LocalJournalPheromoneSubstrate::open_with_live_retention_limits(
            config.clone(),
            &path,
            limits,
        )
        .unwrap();

        let trusted_now = super::trusted_system_unix_seconds().unwrap();
        let live = sample_deposit("live-evidence", trusted_now, 0.9);
        memory.deposit(live.clone()).await.unwrap();
        local.deposit(live).await.unwrap();

        let mut policy_mismatch = sample_deposit("policy-mismatch", trusted_now, 0.9);
        policy_mismatch.decay_half_life = 7_200.0;
        sign_deposit(
            &mut policy_mismatch,
            &signing_key_for_label("policy-mismatch"),
        );
        for result in [
            memory.deposit(policy_mismatch.clone()).await,
            local.deposit(policy_mismatch).await,
        ] {
            assert!(matches!(
                result,
                Err(super::SubstrateError::DepositPolicyMismatch {
                    declared_half_life_secs: 7_200.0,
                    effective_half_life_secs: 3_600.0,
                })
            ));
        }

        for index in 0..4 {
            let mut expired = sample_deposit(&format!("expired-flood-{index}"), index, 0.9);
            expired.threat_class = ThreatClass::DefenseEvasion;
            sign_deposit(
                &mut expired,
                &signing_key_for_label(&format!("expired-flood-{index}")),
            );
            assert!(matches!(
                memory.deposit(expired.clone()).await,
                Err(super::SubstrateError::ExpiredDeposit {
                    timestamp_high_water,
                    ..
                }) if timestamp_high_water >= trusted_now
            ));
            assert!(matches!(
                local.deposit(expired).await,
                Err(super::SubstrateError::ExpiredDeposit {
                    timestamp_high_water,
                    ..
                }) if timestamp_high_water >= trusted_now
            ));
        }

        let mut expired_control = sample_deposit("expired-control", 0, 0.0);
        expired_control.threat_class = ThreatClass::DefenseEvasion;
        sign_deposit(
            &mut expired_control,
            &signing_key_for_label("expired-control"),
        );
        assert!(matches!(
            memory.deposit(expired_control.clone()).await,
            Err(super::SubstrateError::ExpiredDeposit {
                timestamp_high_water,
                ..
            }) if timestamp_high_water >= trusted_now
        ));
        assert!(matches!(
            local.deposit(expired_control).await,
            Err(super::SubstrateError::ExpiredDeposit {
                timestamp_high_water,
                ..
            }) if timestamp_high_water >= trusted_now
        ));

        for deposits in [
            memory.recent_deposits(10).await.unwrap(),
            local.recent_deposits(10).await.unwrap(),
        ] {
            assert_eq!(deposits.len(), 1);
            assert_eq!(deposits[0].timestamp, trusted_now);
            assert_eq!(deposits[0].threat_class, ThreatClass::Execution);
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        drop(local);

        // Upgrade/recovery remains available if an older writer appended a
        // valid but already-evaporated delayed record before this admission
        // rule existed: startup drops it and rewrites the bounded journal.
        let mut persisted_expired = sample_deposit("legacy-expired-flood", 5, 0.9);
        persisted_expired.decay_half_life = f64::MAX;
        sign_deposit(
            &mut persisted_expired,
            &signing_key_for_label("legacy-expired-flood"),
        );
        super::append_jsonl_line(&path, &persisted_expired).unwrap();

        let reopened =
            LocalJournalPheromoneSubstrate::open_with_live_retention_limits(config, &path, limits)
                .unwrap();
        let reopened_deposits = reopened.recent_deposits(10).await.unwrap();
        assert_eq!(reopened_deposits.len(), 1);
        assert_eq!(reopened_deposits[0].timestamp, trusted_now);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        drop(reopened);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[tokio::test]
    async fn live_substrates_reject_future_deposits_without_persisting_them() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("swarm-pheromone-future-deposit-{unique}.jsonl"));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let memory = InMemoryPheromoneSubstrate::new(config.clone());
        let local = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
        let trusted_now = super::trusted_system_unix_seconds().unwrap();
        let future = sample_deposit("future-evidence", trusted_now.saturating_add(600), 0.9);

        for result in [
            memory.deposit(future.clone()).await,
            local.deposit(future.clone()).await,
        ] {
            assert!(matches!(
                result,
                Err(super::SubstrateError::FutureDeposit {
                    timestamp,
                    trusted_now: observed_now,
                    max_future_skew_secs: 300,
                }) if timestamp == future.timestamp && observed_now >= trusted_now
            ));
        }
        assert!(memory.recent_deposits(10).await.unwrap().is_empty());
        assert!(local.recent_deposits(10).await.unwrap().is_empty());
        assert!(
            !path.exists(),
            "rejected deposits must not create the journal"
        );
        drop(local);

        // A future record left by a legacy writer also fails closed at startup
        // rather than poisoning the per-class timestamp high-water.
        super::append_jsonl_line(&path, &future).unwrap();
        assert!(matches!(
            LocalJournalPheromoneSubstrate::open(config, &path),
            Err(super::SubstrateError::FutureDeposit {
                timestamp,
                max_future_skew_secs: 300,
                ..
            }) if timestamp == future.timestamp
        ));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[tokio::test]
    async fn legacy_deposit_decay_is_capped_by_current_policy_at_query_time() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-legacy-half-life-cap-{unique}.jsonl"
        ));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let mut legacy = sample_deposit("legacy-half-life", 100, 0.9);
        legacy.decay_half_life = f64::MAX;
        sign_deposit(&mut legacy, &signing_key_for_label("legacy-half-life"));
        super::append_jsonl_line(&path, &legacy).unwrap();

        let substrate = LocalJournalPheromoneSubstrate::open_for_replay(config, &path).unwrap();
        assert_eq!(substrate.recent_deposits(10).await.unwrap().len(), 1);
        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 36_100)
            .await
            .unwrap();
        assert_eq!(concentration.total_strength, 0.0);
        assert_eq!(concentration.distinct_sources, 0);
        drop(substrate);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_journal_path(&path));
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[test]
    fn deposit_retention_enforces_total_and_per_deposit_byte_limits() {
        let deposit =
            super::VerifiedDeposit::admit(sample_deposit("byte-limit", 100, 0.9)).unwrap();
        let limits = super::DepositRetentionLimits {
            max_count: 100,
            max_bytes: deposit.encoded_len * 3,
            compacted_count: 100,
            compacted_bytes: deposit.encoded_len * 2,
            max_journal_bytes: 1024 * 1024,
        };
        let mut retained = super::RetainedDeposits::default();
        for _ in 0..4 {
            retained
                .push(deposit.clone(), limits, 3_600.0, 0.01, None)
                .unwrap();
        }
        assert_eq!(retained.len(), 2);
        assert!(retained.encoded_bytes <= limits.compacted_bytes);

        let mut oversized = sample_deposit("oversized", 100, 0.9);
        oversized.indicator["oversized"] =
            serde_json::Value::String("x".repeat(super::MAX_SINGLE_DEPOSIT_BYTES));
        sign_deposit(&mut oversized, &signing_key_for_label("oversized"));
        assert!(matches!(
            super::VerifiedDeposit::admit(oversized),
            Err(super::SubstrateError::InvalidDeposit { reason })
                if reason.contains("hard limit")
        ));
    }

    #[test]
    fn deposit_retention_never_orphans_feedback_tombstones_from_related_replays() {
        let limits = super::DepositRetentionLimits {
            max_count: 3,
            max_bytes: 1024 * 1024,
            compacted_count: 2,
            compacted_bytes: 1024 * 1024,
            max_journal_bytes: 1024 * 1024,
        };
        let mut retained = super::RetainedDeposits::default();
        let entries = [
            sample_feedback_deposit("reviewer", "event-dismissed", "dismiss", 200),
            sample_deposit("unrelated-before", 210, 0.9),
            sample_event_deposit("delayed-replay", "event-dismissed", 100),
            sample_deposit("unrelated-after", 220, 0.9),
        ];
        for entry in entries {
            retained
                .push(
                    super::VerifiedDeposit::admit(entry).unwrap(),
                    limits,
                    3_600.0,
                    0.01,
                    None,
                )
                .unwrap();
        }

        assert_eq!(retained.len(), 1);
        assert_eq!(retained.entries[0].timestamp, 220);
        assert!(retained.entries.iter().all(|entry| {
            super::deposit_suppression_key(entry)
                .is_none_or(|key| key.event_id != "event-dismissed")
        }));
    }

    #[test]
    fn deposit_retention_preserves_evidence_when_final_confirmation_is_evicted() {
        let limits = super::DepositRetentionLimits {
            max_count: 3,
            max_bytes: 1024 * 1024,
            compacted_count: 2,
            compacted_bytes: 1024 * 1024,
            max_journal_bytes: 1024 * 1024,
        };
        let mut retained = super::RetainedDeposits::default();
        let entries = [
            sample_feedback_deposit("reviewer", "event-confirmed", "confirm", 200),
            sample_deposit("unrelated-before", 210, 0.9),
            sample_event_deposit("delayed-replay", "event-confirmed", 100),
            sample_deposit("unrelated-after", 220, 0.9),
        ];
        for entry in entries {
            retained
                .push(
                    super::VerifiedDeposit::admit(entry).unwrap(),
                    limits,
                    3_600.0,
                    0.01,
                    None,
                )
                .unwrap();
        }

        assert!(retained.entries.iter().any(|entry| {
            super::deposit_suppression_key(entry)
                .is_some_and(|key| key.event_id == "event-confirmed")
                && entry.indicator.get("schema").is_none()
        }));
    }

    #[test]
    fn feedback_suppression_uses_signed_millisecond_order_within_one_second() {
        fn feedback(action: &str, observed_at_ms: i64, confidence: f64) -> super::VerifiedDeposit {
            let mut deposit = sample_feedback_deposit(
                &format!("reviewer-{action}"),
                "event-same-second",
                action,
                200,
            );
            deposit.confidence = confidence;
            deposit.indicator["observed_at_ms"] = serde_json::json!(observed_at_ms);
            deposit.indicator["feedback_id"] =
                serde_json::json!(format!("feedback-{observed_at_ms}"));
            sign_deposit(
                &mut deposit,
                &signing_key_for_label(&format!("reviewer-{action}")),
            );
            super::VerifiedDeposit::admit(deposit).unwrap()
        }

        let evidence = super::VerifiedDeposit::admit(sample_event_deposit(
            "same-second-evidence",
            "event-same-second",
            199,
        ))
        .unwrap();
        let later_dismissal = feedback("dismiss", 200_900, 0.0);
        let earlier_confirmation = feedback("confirm", 200_100, 1.0);
        let deposits = vec![evidence.clone(), later_dismissal, earlier_confirmation];
        let visible = super::filter_deposits(&deposits, super::DepositQuery::recent(10));
        assert!(visible.iter().all(|deposit| {
            deposit
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                != Some("event-same-second")
                || deposit.indicator.get("schema").is_some()
        }));

        let earlier_dismissal = feedback("dismiss", 200_100, 0.0);
        let later_confirmation = feedback("confirm", 200_900, 1.0);
        let deposits = vec![evidence, later_confirmation, earlier_dismissal];
        let visible = super::filter_deposits(&deposits, super::DepositQuery::recent(10));
        assert!(visible.iter().any(|deposit| {
            deposit
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                == Some("event-same-second")
                && deposit.indicator.get("schema").is_none()
        }));
    }

    #[test]
    fn evicted_timestamp_scoped_dismissal_purges_only_its_governed_evidence() {
        let governed = super::VerifiedDeposit::admit(sample_event_deposit(
            "governed-evidence",
            "event-scoped-eviction",
            100,
        ))
        .unwrap();
        let other = super::VerifiedDeposit::admit(sample_event_deposit(
            "other-evidence",
            "event-scoped-eviction",
            101,
        ))
        .unwrap();
        let mut dismissal = sample_feedback_deposit(
            "reviewer-scoped-eviction",
            "event-scoped-eviction",
            "dismiss",
            200,
        );
        dismissal.indicator["governed_evidence_timestamp"] = serde_json::json!(100);
        sign_deposit(
            &mut dismissal,
            &signing_key_for_label("reviewer-scoped-eviction"),
        );
        let dismissal = super::VerifiedDeposit::admit(dismissal).unwrap();
        let deposits = vec![governed.clone(), other.clone(), dismissal];
        let mut removed = [false, false, true];

        let scopes =
            super::feedback_keys_requiring_evidence_purge_after_compaction(&deposits, &mut removed);
        assert_eq!(scopes.len(), 1);
        let scope = scopes.iter().next().unwrap();
        assert!(scope.governs(&governed));
        assert!(!scope.governs(&other));
    }

    #[test]
    fn feedback_suppression_binds_a_dismissal_to_future_skewed_evidence() {
        let evidence = super::VerifiedDeposit::admit(sample_event_deposit(
            "future-skewed-evidence",
            "event-future-skewed",
            500,
        ))
        .unwrap();
        let mut dismissal = sample_feedback_deposit(
            "reviewer-future-skewed",
            "event-future-skewed",
            "dismiss",
            200,
        );
        dismissal.indicator["governed_evidence_timestamp"] = serde_json::json!(500);
        sign_deposit(
            &mut dismissal,
            &signing_key_for_label("reviewer-future-skewed"),
        );
        let dismissal = super::VerifiedDeposit::admit(dismissal).unwrap();

        let visible =
            super::filter_deposits(&[evidence, dismissal], super::DepositQuery::recent(10));
        assert!(visible.iter().all(|deposit| {
            deposit
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                != Some("event-future-skewed")
                || deposit.indicator.get("schema").is_some()
        }));
    }

    #[test]
    fn compaction_uses_the_final_feedback_state_not_any_retained_marker() {
        let older_confirmation = super::VerifiedDeposit::admit(sample_feedback_deposit(
            "reviewer-confirm",
            "event-final-state",
            "confirm",
            200,
        ))
        .unwrap();
        let newer_dismissal = super::VerifiedDeposit::admit(sample_feedback_deposit(
            "reviewer-dismiss",
            "event-final-state",
            "dismiss",
            201,
        ))
        .unwrap();
        let deposits = vec![older_confirmation, newer_dismissal];
        let mut removed = [false, true];
        let purge =
            super::feedback_keys_requiring_evidence_purge_after_compaction(&deposits, &mut removed);
        assert_eq!(purge.len(), 1);
        assert_eq!(
            purge.iter().next().unwrap().key.event_id,
            "event-final-state"
        );
        assert_eq!(removed, [true, true]);

        let mut removed = [true, false];
        let purge =
            super::feedback_keys_requiring_evidence_purge_after_compaction(&deposits, &mut removed);
        assert!(purge.is_empty());
        assert_eq!(removed, [true, false]);

        let older_dismissal = super::VerifiedDeposit::admit(sample_feedback_deposit(
            "reviewer-dismiss-older",
            "event-confirm-final",
            "dismiss",
            200,
        ))
        .unwrap();
        let newer_confirmation = super::VerifiedDeposit::admit(sample_feedback_deposit(
            "reviewer-confirm-newer",
            "event-confirm-final",
            "confirm",
            201,
        ))
        .unwrap();
        let deposits = vec![older_dismissal, newer_confirmation];
        let mut removed = [false, true];
        let purge =
            super::feedback_keys_requiring_evidence_purge_after_compaction(&deposits, &mut removed);
        assert!(purge.is_empty());
        assert_eq!(
            removed,
            [true, true],
            "evicting the terminal confirmation must also remove the superseded dismissal"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_journal_fails_closed_and_reconciles_after_parent_sync_failure() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-parent-sync-failure-{unique}.jsonl"
        ));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let limits = super::DepositRetentionLimits {
            max_count: 2,
            max_bytes: 1024 * 1024,
            compacted_count: 1,
            compacted_bytes: 1024 * 1024,
            max_journal_bytes: 1024 * 1024,
        };
        let local = LocalJournalPheromoneSubstrate::open_with_retention_limits(
            config.clone(),
            &path,
            limits,
        )
        .unwrap();
        local
            .deposit(sample_deposit("sync-first", 100, 0.9))
            .await
            .unwrap();
        local
            .deposit(sample_deposit("sync-second", 200, 0.9))
            .await
            .unwrap();
        super::inject_rewrite_parent_sync_failure(&path);
        assert!(matches!(
            local
                .deposit(sample_deposit("sync-visible", 300, 0.9))
                .await,
            Err(super::SubstrateError::DurabilityOutcomeUnknown { .. })
        ));

        let visible = local.recent_deposits(10).await.unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].timestamp, 300);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        drop(local);

        let reopened =
            LocalJournalPheromoneSubstrate::open_with_retention_limits(config, &path, limits)
                .unwrap();
        assert_eq!(
            reopened.recent_deposits(10).await.unwrap()[0].timestamp,
            300
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[test]
    fn local_journal_verifies_signatures_once_at_load_and_bounds_each_line() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("swarm-pheromone-verified-load-{unique}.jsonl"));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let mut tampered = serde_json::to_value(sample_deposit("tampered-load", 100, 0.9)).unwrap();
        tampered["confidence"] = serde_json::json!(0.1);
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string(&tampered).unwrap()),
        )
        .unwrap();
        assert!(matches!(
            LocalJournalPheromoneSubstrate::open(config.clone(), &path),
            Err(super::SubstrateError::InvalidDeposit { .. })
        ));

        std::fs::write(&path, vec![b'x'; 33]).unwrap();
        let limits = super::DepositRetentionLimits {
            max_count: 4,
            max_bytes: 32,
            compacted_count: 2,
            compacted_bytes: 16,
            max_journal_bytes: 32,
        };
        assert!(matches!(
            LocalJournalPheromoneSubstrate::open_with_retention_limits(config, &path, limits),
            Err(super::SubstrateError::Decode { .. })
        ));

        std::fs::write(&path, vec![b'x'; super::MAX_SINGLE_DEPOSIT_BYTES + 1]).unwrap();
        assert!(matches!(
            LocalJournalPheromoneSubstrate::open(substrate_config(), &path),
            Err(super::SubstrateError::InvalidDeposit { reason })
                if reason.contains("journal line") && reason.contains("deposit limit")
        ));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn local_journal_stream_compacts_valid_legacy_file_above_steady_state_limit() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("swarm-pheromone-legacy-large-{unique}.jsonl"));
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let deposits = (100..105)
            .map(|timestamp| sample_deposit("legacy-large", timestamp, 0.9))
            .collect::<Vec<_>>();
        let full_journal = deposits
            .iter()
            .map(|deposit| serde_json::to_string(deposit).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let compacted_journal_bytes = deposits[3..]
            .iter()
            .map(|deposit| serde_json::to_string(deposit).unwrap().len() + 1)
            .sum::<usize>();
        let limits = super::DepositRetentionLimits {
            max_count: 4,
            max_bytes: 1024 * 1024,
            compacted_count: 2,
            compacted_bytes: 1024 * 1024,
            max_journal_bytes: u64::try_from(compacted_journal_bytes).unwrap(),
        };
        std::fs::write(&path, full_journal.as_bytes()).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > limits.max_journal_bytes);

        let substrate =
            LocalJournalPheromoneSubstrate::open_with_retention_limits(config, &path, limits)
                .unwrap();
        let retained = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(
            retained
                .iter()
                .map(|deposit| deposit.timestamp)
                .collect::<Vec<_>>(),
            vec![104, 103]
        );
        assert!(std::fs::metadata(&path).unwrap().len() <= limits.max_journal_bytes);
        drop(substrate);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::behavioral_baseline_sequence_path(&path));
    }

    #[tokio::test]
    async fn local_journal_recovers_legacy_deposits_without_schema_version_after_reopen() {
        let path = std::env::temp_dir().join("swarm-pheromone-legacy-journal.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };

        let mut legacy_deposit = sample_deposit("whisker-legacy", 100, 0.9);
        legacy_deposit.schema_version = PheromoneDeposit::previous_schema_version();
        sign_deposit(
            &mut legacy_deposit,
            &signing_key_for_label("whisker-legacy"),
        );
        let mut raw = serde_json::to_value(&legacy_deposit).unwrap();
        raw.as_object_mut().unwrap().remove("schema_version");
        std::fs::write(&path, format!("{}\n", serde_json::to_string(&raw).unwrap())).unwrap();

        let reopened = LocalJournalPheromoneSubstrate::open_for_replay(config, &path).unwrap();
        let deposits = reopened.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].schema_version,
            PheromoneDeposit::previous_schema_version()
        );
        assert_eq!(deposits[0].agent_id, legacy_deposit.agent_id);
        assert_eq!(deposits[0].timestamp, legacy_deposit.timestamp);

        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert!(health.durable);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
    }

    #[tokio::test]
    async fn local_journal_recovers_escalations_after_reopen() {
        let path = std::env::temp_dir().join("swarm-pheromone-escalations.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .record_escalation(sample_escalation(SwarmMode::Alert, 100))
                .await
                .unwrap();
            substrate
                .record_escalation(sample_escalation(SwarmMode::Incident, 200))
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
        let escalations = reopened.query_escalations(0).await.unwrap();
        assert_eq!(escalations.len(), 2);
        assert_eq!(escalations[0].mode, SwarmMode::Alert);
        assert_eq!(escalations[1].mode, SwarmMode::Incident);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
    }

    #[tokio::test]
    async fn local_journal_recovers_threat_class_configs_after_reopen() {
        let path = std::env::temp_dir().join("swarm-pheromone-threat-class-configs.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .store_threat_class_config(sample_threat_class_config(
                    ThreatClass::Execution,
                    180.0,
                    1.1,
                    4.2,
                ))
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
        let stored = reopened
            .query_threat_class_config(&ThreatClass::Execution)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.half_life_secs, 180.0);
        assert_eq!(stored.alert_threshold, 1.1);
        assert_eq!(stored.incident_threshold, 4.2);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
    }

    #[tokio::test]
    async fn local_journal_recovers_threat_intel_entries_after_reopen() {
        let path = std::env::temp_dir().join("swarm-pheromone-threat-intel.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .store_threat_intel_entry(sample_threat_intel_entry(
                    ThreatIntelIndicatorType::FileHash,
                    " ABCDEF123456 ",
                    0.88,
                    1_700_000_000_100,
                ))
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
        let stored = reopened
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::FileHash,
                "abcdef123456",
                1_700_000_000_000,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.value, "abcdef123456");
        assert_eq!(stored.confidence, 0.88);

        let expired = reopened
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::FileHash,
                "abcdef123456",
                1_700_000_000_100,
            )
            .await
            .unwrap();
        assert!(expired.is_none());

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
    }

    #[tokio::test]
    async fn local_journal_recovers_behavioral_baseline_snapshots_after_reopen() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-behavioral-baseline-{unique}.jsonl"
        ));
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let behavioral_baseline_path = super::behavioral_baseline_journal_path(&path);
        let behavioral_baseline_sequence_path = super::behavioral_baseline_sequence_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let snapshot = sample_behavioral_baseline_snapshot("behavioral_anomaly");
        let signer_agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .store_behavioral_baseline_snapshot(
                    snapshot.clone(),
                    &signer_agent_id,
                    &test_signing_key(),
                )
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
        let stored = reopened
            .query_behavioral_baseline_snapshot("behavioral_anomaly", &signer_agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, snapshot);

        let health = reopened.health().await.unwrap();
        assert!(
            health
                .details
                .contains(&behavioral_baseline_path.display().to_string())
        );

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
        let _ = std::fs::remove_file(behavioral_baseline_path);
        let _ = std::fs::remove_file(behavioral_baseline_sequence_path);
    }

    #[tokio::test]
    async fn local_journal_rejects_tampered_behavioral_baseline_snapshot_after_reopen() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-behavioral-baseline-tampered-{unique}.jsonl"
        ));
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let behavioral_baseline_path = super::behavioral_baseline_journal_path(&path);
        let behavioral_baseline_sequence_path = super::behavioral_baseline_sequence_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let snapshot = sample_behavioral_baseline_snapshot("behavioral_anomaly");
        let signer_agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .store_behavioral_baseline_snapshot(snapshot, &signer_agent_id, &test_signing_key())
                .await
                .unwrap();
        }

        let mut envelope: super::BehavioralBaselineEnvelope =
            serde_json::from_str(&std::fs::read_to_string(&behavioral_baseline_path).unwrap())
                .unwrap();
        let mut payload: BehavioralBaselineSnapshot =
            serde_json::from_str(&envelope.statement.payload_json).unwrap();
        payload.hosts[0].observation_count = 99;
        envelope.statement.payload_json = serde_json::to_string(&payload).unwrap();
        let tampered = format!("{}\n", serde_json::to_string(&envelope).unwrap());
        std::fs::write(&behavioral_baseline_path, tampered).unwrap();

        let error = LocalJournalPheromoneSubstrate::open(config, &path).unwrap_err();
        assert!(matches!(
            error,
            super::SubstrateError::InvalidBehavioralBaseline { .. }
        ));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
        let _ = std::fs::remove_file(behavioral_baseline_path);
        let _ = std::fs::remove_file(behavioral_baseline_sequence_path);
    }

    #[tokio::test]
    async fn local_journal_rejects_replayed_behavioral_baseline_snapshot_after_reopen() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "swarm-pheromone-behavioral-baseline-replay-{unique}.jsonl"
        ));
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let behavioral_baseline_path = super::behavioral_baseline_journal_path(&path);
        let behavioral_baseline_sequence_path = super::behavioral_baseline_sequence_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let signer_agent_id = AgentId::from_verifying_key(&test_signing_key().verifying_key());

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            let first = sample_behavioral_baseline_snapshot("behavioral_anomaly");
            substrate
                .store_behavioral_baseline_snapshot(first, &signer_agent_id, &test_signing_key())
                .await
                .unwrap();
            let original = std::fs::read_to_string(&behavioral_baseline_path).unwrap();

            let mut newer = sample_behavioral_baseline_snapshot("behavioral_anomaly");
            newer.captured_at += 60;
            newer.hosts[0].observation_count += 1;
            substrate
                .store_behavioral_baseline_snapshot(newer, &signer_agent_id, &test_signing_key())
                .await
                .unwrap();

            std::fs::write(&behavioral_baseline_path, original).unwrap();
        }

        let error = LocalJournalPheromoneSubstrate::open(config, &path).unwrap_err();
        assert!(matches!(
            error,
            super::SubstrateError::InvalidBehavioralBaseline { .. }
        ));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
        let _ = std::fs::remove_file(behavioral_baseline_path);
        let _ = std::fs::remove_file(behavioral_baseline_sequence_path);
    }

    #[tokio::test]
    async fn configured_substrate_uses_backend_selection() {
        let in_memory = ConfiguredPheromoneSubstrate::from_config(&substrate_config()).unwrap();
        let health = in_memory.health().await.unwrap();
        assert_eq!(health.backend, "in_memory");

        let path = std::env::temp_dir().join("configured-pheromone-journal.jsonl");
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let local = ConfiguredPheromoneSubstrate::from_config(&config).unwrap();
        let health = local.health().await.unwrap();
        assert_eq!(health.backend, "local_journal");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));

        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::JetStream {
                url: "nats://127.0.0.1:4222".to_string(),
                connect_timeout_ms: 5_000,
                gc_page_size: 512,
            },
            ..substrate_config()
        };
        let jetstream = ConfiguredPheromoneSubstrate::from_config(&config).unwrap();
        assert!(matches!(
            jetstream,
            ConfiguredPheromoneSubstrate::JetStream(_)
        ));
    }

    // --- Signature validation tests ---

    #[tokio::test]
    async fn deposit_rejects_empty_signature() {
        let substrate = in_memory();
        let deposit = unsigned_deposit();
        let err = substrate.deposit(deposit).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("empty signature"),
            "expected 'empty signature', got: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_rejects_empty_agent_key() {
        let substrate = in_memory();
        let mut deposit = unsigned_deposit();
        deposit.signature = vec![0u8; 64]; // non-empty but invalid
        let err = substrate.deposit(deposit).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("agent_key"),
            "expected 'agent_key', got: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_accepts_valid_signed_deposit() {
        let substrate = in_memory();
        let deposit = sample_deposit("whisker-test", 100, 0.9);
        substrate.deposit(deposit).await.unwrap();

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
    }

    #[tokio::test]
    async fn deposit_rejects_signed_invalid_numeric_fields() {
        let substrate = in_memory();
        let key = signing_key_for_label("invalid-numeric");

        for confidence in [-0.1, 1.1] {
            let mut deposit = sample_deposit("invalid-numeric", 100, 0.9);
            deposit.confidence = confidence;
            sign_deposit(&mut deposit, &key);
            assert!(matches!(
                substrate.deposit(deposit).await,
                Err(super::SubstrateError::InvalidDeposit { reason })
                    if reason.contains("confidence must be finite")
            ));
        }

        for decay_half_life in [0.0, -1.0] {
            let mut deposit = sample_deposit("invalid-numeric", 100, 0.9);
            deposit.decay_half_life = decay_half_life;
            sign_deposit(&mut deposit, &key);
            assert!(matches!(
                substrate.deposit(deposit).await,
                Err(super::SubstrateError::InvalidDeposit { reason })
                    if reason.contains("decay_half_life must be finite")
            ));
        }

        let mut deposit = sample_deposit("invalid-numeric", 100, 0.9);
        deposit.timestamp = -1;
        sign_deposit(&mut deposit, &key);
        assert!(matches!(
            substrate.deposit(deposit).await,
            Err(super::SubstrateError::InvalidDeposit { reason })
                if reason.contains("timestamp must be a nonnegative Unix timestamp")
        ));
    }

    #[tokio::test]
    async fn deposit_accepts_previous_schema_version_signed_deposit() {
        let substrate = in_memory();
        let mut deposit = sample_deposit("whisker-test", 100, 0.9);
        deposit.schema_version = PheromoneDeposit::previous_schema_version();
        sign_deposit(&mut deposit, &signing_key_for_label("whisker-test"));

        substrate.deposit(deposit).await.unwrap();

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].schema_version,
            PheromoneDeposit::previous_schema_version()
        );
    }

    #[tokio::test]
    async fn deposit_rejects_unsupported_schema_version() {
        let substrate = in_memory();
        let mut deposit = sample_deposit("whisker-test", 100, 0.9);
        deposit.schema_version = PheromoneDeposit::current_schema_version() + 1;
        sign_deposit(&mut deposit, &signing_key_for_label("whisker-test"));

        let err = substrate.deposit(deposit).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported pheromone deposit schema version"),
            "expected schema version rejection, got: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_accepts_strategy_scoped_agent_id_when_base_identity_matches_signing_key() {
        let substrate = in_memory();
        let key = signing_key_for_label("whisker-test");
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = sample_deposit("whisker-test", 100, 0.9);
        deposit.agent_id = AgentId(format!("{}:behavioral_anomaly", derived_agent_id.0));
        sign_deposit(&mut deposit, &key);

        substrate.deposit(deposit).await.unwrap();

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].agent_id.0,
            format!("{}:behavioral_anomaly", derived_agent_id.0)
        );
    }

    #[tokio::test]
    async fn deposit_rejects_invalid_signature_bytes() {
        let substrate = in_memory();
        let mut deposit = sample_deposit("whisker-test", 100, 0.9);
        deposit.signature[0] ^= 0xFF;

        let err = substrate.deposit(deposit).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("signature verification failed"),
            "expected verification failure, got: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_rejects_agent_id_that_does_not_match_signing_key() {
        let substrate = in_memory();
        let mut deposit = sample_deposit("whisker-test", 100, 0.9);
        deposit.agent_id = AgentId::new("whisker", "spoofed");
        sign_deposit(&mut deposit, &signing_key_for_label("whisker-test"));

        let err = substrate.deposit(deposit).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not match signing key identity"),
            "expected identity binding failure, got: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_rejects_unadmitted_identity_when_allowlist_is_configured() {
        let substrate = in_memory();
        substrate
            .set_admitted_identities([AgentId::new("whisker", "admitted")])
            .unwrap();

        let err = substrate
            .deposit(sample_deposit("whisker-test", 100, 0.9))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("is not admitted"),
            "expected admission failure, got: {msg}"
        );
    }

    #[tokio::test]
    async fn deposit_accepts_strategy_scoped_identity_when_base_identity_is_admitted() {
        let substrate = in_memory();
        let key = signing_key_for_label("whisker-test");
        let base_identity = AgentId::from_verifying_key(&key.verifying_key());
        substrate
            .set_admitted_identities([base_identity.clone()])
            .unwrap();

        let mut deposit = sample_deposit("whisker-test", 100, 0.9);
        deposit.agent_id = AgentId(format!("{}:behavioral_anomaly", base_identity.0));
        sign_deposit(&mut deposit, &key);

        substrate.deposit(deposit).await.unwrap();

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].agent_id.0,
            format!("{}:behavioral_anomaly", base_identity.0)
        );
    }

    #[tokio::test]
    async fn all_backends_reject_unsigned_deposits() {
        // InMemory
        let in_mem = in_memory();
        let err = in_mem.deposit(unsigned_deposit()).await.unwrap_err();
        assert!(err.to_string().contains("empty signature"));

        // LocalJournal
        let path = std::env::temp_dir().join("sig-validation-test.jsonl");
        let journal = LocalJournalPheromoneSubstrate::open(substrate_config(), &path).unwrap();
        let err = journal.deposit(unsigned_deposit()).await.unwrap_err();
        assert!(err.to_string().contains("empty signature"));

        // ConfiguredPheromoneSubstrate (InMemory variant)
        let configured = ConfiguredPheromoneSubstrate::from_config(&substrate_config()).unwrap();
        let err = configured.deposit(unsigned_deposit()).await.unwrap_err();
        assert!(err.to_string().contains("empty signature"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::escalation_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_class_config_journal_path(&path));
        let _ = std::fs::remove_file(super::threat_intel_journal_path(&path));
    }

    // --- Threat-intel GC tests ---

    #[tokio::test]
    async fn gc_expired_threat_intel_removes_expired_entries() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "expired.example.com",
                0.9,
                500,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::IpAddress,
                "10.0.0.1",
                0.8,
                2000,
            ))
            .await
            .unwrap();

        let purged = substrate.gc_expired_threat_intel(1000).await.unwrap();
        assert_eq!(purged, 1);

        let expired = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "expired.example.com", 0)
            .await
            .unwrap();
        assert!(expired.is_none());

        let still_present = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", 0)
            .await
            .unwrap();
        assert!(still_present.is_some());
    }

    #[tokio::test]
    async fn gc_expired_threat_intel_returns_zero_when_nothing_expired() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "active.example.com",
                0.9,
                2000,
            ))
            .await
            .unwrap();

        let purged = substrate.gc_expired_threat_intel(1000).await.unwrap();
        assert_eq!(purged, 0);
    }

    #[tokio::test]
    async fn local_journal_gc_expired_threat_intel_rewrites_file() {
        let path = std::env::temp_dir().join("swarm-pheromone-gc-threat-intel.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .store_threat_intel_entry(sample_threat_intel_entry(
                    ThreatIntelIndicatorType::Domain,
                    "expired.example.com",
                    0.9,
                    500,
                ))
                .await
                .unwrap();
            substrate
                .store_threat_intel_entry(sample_threat_intel_entry(
                    ThreatIntelIndicatorType::IpAddress,
                    "10.0.0.1",
                    0.8,
                    2000,
                ))
                .await
                .unwrap();

            let purged = substrate.gc_expired_threat_intel(1000).await.unwrap();
            assert_eq!(purged, 1);
        }

        // Reopen from disk — only the unexpired entry should be present
        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();

        let expired = reopened
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "expired.example.com", 0)
            .await
            .unwrap();
        assert!(expired.is_none());

        let still_present = reopened
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", 0)
            .await
            .unwrap();
        assert!(still_present.is_some());

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(escalation_path);
        let _ = std::fs::remove_file(config_path);
        let _ = std::fs::remove_file(threat_intel_path);
    }

    // --- Deposit, query, concentration, GC, and escalation tests ---

    #[tokio::test]
    async fn deposit_round_trip_preserves_all_fields() {
        let substrate = in_memory();
        let key = test_signing_key();
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({"cmd": "whoami"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.95,
            timestamp: 500,
            decay_half_life: 3600.0,
            agent_id: derived_agent_id.clone(),
            agent_identity: derived_agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        sign_deposit(&mut deposit, &key);
        substrate.deposit(deposit).await.unwrap();

        let deposits = substrate.recent_deposits(1).await.unwrap();
        assert_eq!(deposits.len(), 1);
        let d = &deposits[0];
        assert_eq!(d.indicator, serde_json::json!({"cmd": "whoami"}));
        assert_eq!(d.threat_class, ThreatClass::Execution);
        assert_eq!(d.severity, Severity::High);
        assert_eq!(d.schema_version, PheromoneDeposit::current_schema_version());
        assert!((d.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(d.timestamp, 500);
        assert!((d.decay_half_life - 3600.0).abs() < f64::EPSILON);
        assert!(!d.signature.is_empty());
        assert!(!d.agent_key.is_empty());
    }

    #[tokio::test]
    async fn concentration_decays_with_half_life() {
        let substrate = in_memory();
        let mut deposit = sample_deposit("decay-agent", 0, 1.0);
        deposit.decay_half_life = 3600.0;
        sign_deposit(&mut deposit, &signing_key_for_label("decay-agent"));
        substrate.deposit(deposit).await.unwrap();

        let c0 = substrate
            .query_concentration(&ThreatClass::Execution, 0)
            .await
            .unwrap();
        assert!((c0.total_strength - 1.0).abs() < 0.01);

        let c1 = substrate
            .query_concentration(&ThreatClass::Execution, 3600)
            .await
            .unwrap();
        assert!(
            (c1.total_strength - 0.5).abs() < 0.01,
            "expected ~0.5 at one half-life, got {}",
            c1.total_strength
        );

        let c2 = substrate
            .query_concentration(&ThreatClass::Execution, 7200)
            .await
            .unwrap();
        assert!(
            (c2.total_strength - 0.25).abs() < 0.01,
            "expected ~0.25 at two half-lives, got {}",
            c2.total_strength
        );
    }

    #[tokio::test]
    async fn gc_evaporated_preserves_fresh_deposits() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("old-agent", 0, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("fresh-agent", 99_000, 0.9))
            .await
            .unwrap();

        let removed = substrate.gc_evaporated(100_000).await.unwrap();
        assert_eq!(removed, 1);

        let remaining = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].timestamp, 99_000);
    }

    #[tokio::test]
    async fn query_deposits_no_filters_returns_all() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit("agent-1", 100, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("agent-2", 200, 0.8))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("agent-3", 300, 0.7))
            .await
            .unwrap();

        let deposits = substrate
            .query_deposits(DepositQuery {
                threat_class: None,
                since_timestamp: None,
                host_id: None,
                limit: 0,
            })
            .await
            .unwrap();
        assert_eq!(deposits.len(), 3);
        assert_eq!(deposits[0].timestamp, 300);
        assert_eq!(deposits[1].timestamp, 200);
        assert_eq!(deposits[2].timestamp, 100);
    }

    #[tokio::test]
    async fn empty_substrate_returns_zero_concentration() {
        let substrate = in_memory();
        let c = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();
        assert!((c.total_strength - 0.0).abs() < f64::EPSILON);
        assert_eq!(c.distinct_sources, 0);
        assert!((c.peak_confidence - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn query_escalations_empty_returns_empty_vec() {
        let substrate = in_memory();
        let escalations = substrate.query_escalations(0).await.unwrap();
        assert!(escalations.is_empty());
    }

    #[tokio::test]
    async fn escalation_records_full_lifecycle() {
        let substrate = in_memory();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Normal, 100))
            .await
            .unwrap();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Alert, 200))
            .await
            .unwrap();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Incident, 300))
            .await
            .unwrap();

        let all = substrate.query_escalations(0).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].mode, SwarmMode::Normal);
        assert_eq!(all[1].mode, SwarmMode::Alert);
        assert_eq!(all[2].mode, SwarmMode::Incident);

        let since_150 = substrate.query_escalations(150).await.unwrap();
        assert_eq!(since_150.len(), 2);
        assert_eq!(since_150[0].mode, SwarmMode::Alert);
        assert_eq!(since_150[1].mode, SwarmMode::Incident);

        let since_400 = substrate.query_escalations(400).await.unwrap();
        assert!(since_400.is_empty());
    }

    #[tokio::test]
    async fn health_reports_deposit_count() {
        let substrate = in_memory();

        let h0 = substrate.health().await.unwrap();
        assert_eq!(h0.deposit_count, 0);
        assert_eq!(h0.backend, "in_memory");
        assert!(h0.ready);

        substrate
            .deposit(sample_deposit("h-agent-1", 100, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("h-agent-2", 200, 0.8))
            .await
            .unwrap();

        let h2 = substrate.health().await.unwrap();
        assert_eq!(h2.deposit_count, 2);
    }

    // --- Threat-intel CRUD, ThreatClassConfig, and normalization tests ---

    #[tokio::test]
    async fn threat_intel_ip_address_normalization() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::IpAddress,
                " 192.168.1.1 ",
                0.85,
                999_999,
            ))
            .await
            .unwrap();

        let entry = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "192.168.1.1", 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.value, "192.168.1.1");
    }

    #[tokio::test]
    async fn threat_intel_file_hash_case_normalization() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::FileHash,
                " AABBCCDD ",
                0.9,
                999_999,
            ))
            .await
            .unwrap();

        let entry = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::FileHash, "aabbccdd", 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.value, "aabbccdd");
    }

    #[tokio::test]
    async fn threat_intel_multiple_types_coexist() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::IpAddress,
                "10.0.0.1",
                0.7,
                999_999,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "evil.com",
                0.8,
                999_999,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::FileHash,
                "deadbeef",
                0.9,
                999_999,
            ))
            .await
            .unwrap();

        let ip = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", 0)
            .await
            .unwrap()
            .unwrap();
        assert!((ip.confidence - 0.7).abs() < f64::EPSILON);

        let domain = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "evil.com", 0)
            .await
            .unwrap()
            .unwrap();
        assert!((domain.confidence - 0.8).abs() < f64::EPSILON);

        let hash = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::FileHash, "deadbeef", 0)
            .await
            .unwrap()
            .unwrap();
        assert!((hash.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn threat_intel_overwrite_same_key() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "replace.me",
                0.5,
                999_999,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "replace.me",
                0.99,
                999_999,
            ))
            .await
            .unwrap();

        let entry = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "replace.me", 0)
            .await
            .unwrap()
            .unwrap();
        assert!((entry.confidence - 0.99).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn threat_intel_gc_preserves_unexpired_across_types() {
        let substrate = in_memory();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::IpAddress,
                "1.2.3.4",
                0.8,
                100,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry(
                ThreatIntelIndicatorType::Domain,
                "safe.com",
                0.9,
                999_999,
            ))
            .await
            .unwrap();

        let purged = substrate.gc_expired_threat_intel(500).await.unwrap();
        assert_eq!(purged, 1);

        let expired = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "1.2.3.4", 0)
            .await
            .unwrap();
        assert!(expired.is_none());

        let alive = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "safe.com", 0)
            .await
            .unwrap();
        assert!(alive.is_some());
    }

    #[tokio::test]
    async fn threat_class_config_overwrite_updates_existing() {
        let substrate = in_memory();
        substrate
            .store_threat_class_config(sample_threat_class_config(
                ThreatClass::Execution,
                60.0,
                1.0,
                3.0,
            ))
            .await
            .unwrap();
        substrate
            .store_threat_class_config(sample_threat_class_config(
                ThreatClass::Execution,
                120.0,
                1.0,
                3.0,
            ))
            .await
            .unwrap();

        let config = substrate
            .query_threat_class_config(&ThreatClass::Execution)
            .await
            .unwrap()
            .unwrap();
        assert!((config.half_life_secs - 120.0).abs() < f64::EPSILON);

        let all = substrate.query_threat_class_configs().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn threat_class_config_missing_returns_none() {
        let substrate = in_memory();
        let config = substrate
            .query_threat_class_config(&ThreatClass::Persistence)
            .await
            .unwrap();
        assert!(config.is_none());
    }

    #[tokio::test]
    async fn query_threat_intel_nonexistent_returns_none() {
        let substrate = in_memory();
        let entry = substrate
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "nonexistent.example.com",
                0,
            )
            .await
            .unwrap();
        assert!(entry.is_none());
    }
}
