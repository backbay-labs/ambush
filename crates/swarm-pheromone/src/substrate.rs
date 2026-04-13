//! Core substrate operations.

use crate::jetstream::JetStreamPheromoneSubstrate;
use async_trait::async_trait;
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::agent::AgentRole;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, EscalationRecord, PheromoneConcentration, PheromoneDeposit,
    ThreatClass, ThreatClassConfig, ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::types::{AgentId, SWARM_PROVIDENCE_FEEDBACK_SCHEMA, Severity};

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

fn signing_payload_bytes_for_deposit(
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
) -> Result<PheromoneDeposit, SubstrateError> {
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
    serde_json::from_value::<PheromoneDeposit>(raw)
        .map_err(|source| SubstrateError::Decode { location, source })
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
        if let Some(admitted_identities) = guard.as_ref()
            && !admitted_identities.contains(&deposit.agent_id)
        {
            return Err(SubstrateError::InvalidDeposit {
                reason: format!("agent `{}` is not admitted", deposit.agent_id),
            });
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
struct FeedbackSuppressionKey {
    threat_class: ThreatClass,
    event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeedbackSuppressionState {
    Confirm,
    Dismiss,
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
        validate_deposit_signature(&deposit)?;
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
    ) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => {
                substrate.store_behavioral_baseline_snapshot(snapshot).await
            }
            Self::LocalJournal(substrate) => {
                substrate.store_behavioral_baseline_snapshot(snapshot).await
            }
            Self::JetStream(substrate) => {
                substrate.store_behavioral_baseline_snapshot(snapshot).await
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
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => {
                substrate
                    .query_behavioral_baseline_snapshot(strategy_id)
                    .await
            }
            Self::LocalJournal(substrate) => {
                substrate
                    .query_behavioral_baseline_snapshot(strategy_id)
                    .await
            }
            Self::JetStream(substrate) => {
                substrate
                    .query_behavioral_baseline_snapshot(strategy_id)
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
    deposits: Arc<RwLock<Vec<PheromoneDeposit>>>,
    escalations: Arc<RwLock<Vec<EscalationRecord>>>,
    threat_class_configs: Arc<RwLock<BTreeMap<ThreatClass, ThreatClassConfig>>>,
    threat_intel_entries: Arc<RwLock<BTreeMap<ThreatIntelKey, ThreatIntelEntry>>>,
    behavioral_baseline_snapshots: Arc<RwLock<BTreeMap<String, BehavioralBaselineSnapshot>>>,
}

impl InMemoryPheromoneSubstrate {
    pub fn new(config: PheromoneConfig) -> Self {
        Self {
            config,
            admission_control: AdmissionControl::default(),
            deposits: Arc::new(RwLock::new(Vec::new())),
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
}

#[async_trait]
impl PheromoneSubstrate for InMemoryPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        validate_deposit_signature(&deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.push(deposit);
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
    ) -> Result<(), SubstrateError> {
        let mut guard = self
            .behavioral_baseline_snapshots
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.insert(snapshot.strategy_id.clone(), snapshot);
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
        Ok(concentration_for(&guard, threat_class, now, &policy))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(filter_deposits(&guard, query))
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
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        let guard = self
            .behavioral_baseline_snapshots
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(guard.get(strategy_id).cloned())
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
        let before = guard.len();
        guard.retain(|deposit| {
            let policy = resolved_policy(&self.config, &config_guard, &deposit.threat_class);
            !deposit.is_evaporated(now, policy.evaporation_threshold)
        });
        Ok(before - guard.len())
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
    journal_path: PathBuf,
    escalation_journal_path: PathBuf,
    threat_class_config_journal_path: PathBuf,
    threat_intel_journal_path: PathBuf,
    behavioral_baseline_journal_path: PathBuf,
    deposits: Arc<RwLock<Vec<PheromoneDeposit>>>,
    escalations: Arc<RwLock<Vec<EscalationRecord>>>,
    threat_class_configs: Arc<RwLock<BTreeMap<ThreatClass, ThreatClassConfig>>>,
    threat_intel_entries: Arc<RwLock<BTreeMap<ThreatIntelKey, ThreatIntelEntry>>>,
    behavioral_baseline_snapshots: Arc<RwLock<BTreeMap<String, BehavioralBaselineSnapshot>>>,
}

impl LocalJournalPheromoneSubstrate {
    pub fn open(config: PheromoneConfig, path: impl AsRef<Path>) -> Result<Self, SubstrateError> {
        let journal_path = path.as_ref().to_path_buf();
        let escalation_journal_path = escalation_journal_path(&journal_path);
        let threat_class_config_journal_path = threat_class_config_journal_path(&journal_path);
        let threat_intel_journal_path = threat_intel_journal_path(&journal_path);
        let behavioral_baseline_journal_path = behavioral_baseline_journal_path(&journal_path);
        ensure_parent_dir(&journal_path)?;
        let deposits = load_deposit_jsonl(&journal_path)?;
        let escalations = load_jsonl(&escalation_journal_path)?;
        let threat_class_configs = load_threat_class_configs(&threat_class_config_journal_path)?;
        let threat_intel_entries = load_threat_intel_entries(&threat_intel_journal_path)?;
        let behavioral_baseline_snapshots =
            load_behavioral_baseline_snapshots(&behavioral_baseline_journal_path)?;

        Ok(Self {
            config,
            admission_control: AdmissionControl::default(),
            journal_path,
            escalation_journal_path,
            threat_class_config_journal_path,
            threat_intel_journal_path,
            behavioral_baseline_journal_path,
            deposits: Arc::new(RwLock::new(deposits)),
            escalations: Arc::new(RwLock::new(escalations)),
            threat_class_configs: Arc::new(RwLock::new(threat_class_configs)),
            threat_intel_entries: Arc::new(RwLock::new(threat_intel_entries)),
            behavioral_baseline_snapshots: Arc::new(RwLock::new(behavioral_baseline_snapshots)),
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
        validate_deposit_signature(&deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        append_jsonl_line(&self.journal_path, &deposit)?;
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.push(deposit);
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
    ) -> Result<(), SubstrateError> {
        let mut guard = self
            .behavioral_baseline_snapshots
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.insert(snapshot.strategy_id.clone(), snapshot);
        rewrite_jsonl(
            &self.behavioral_baseline_journal_path,
            &guard.values().collect::<Vec<_>>(),
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
        Ok(concentration_for(&guard, threat_class, now, &policy))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(filter_deposits(&guard, query))
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
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        let guard = self
            .behavioral_baseline_snapshots
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(guard.get(strategy_id).cloned())
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
        let before = guard.len();
        guard.retain(|deposit| {
            let policy = resolved_policy(&self.config, &config_guard, &deposit.threat_class);
            !deposit.is_evaporated(now, policy.evaporation_threshold)
        });
        rewrite_jsonl(&self.journal_path, &guard)?;
        Ok(before - guard.len())
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
        let ready = deposits_ready
            && escalations_ready
            && configs_ready
            && threat_intel_ready
            && behavioral_baseline_ready;

        Ok(SubstrateHealth {
            backend: "local_journal".to_string(),
            durable: true,
            ready,
            details: format!(
                "journal files at {}, {}, {}, {}, and {}",
                self.journal_path.display(),
                self.escalation_journal_path.display(),
                self.threat_class_config_journal_path.display(),
                self.threat_intel_journal_path.display(),
                self.behavioral_baseline_journal_path.display()
            ),
            deposit_count: guard.len(),
        })
    }
}

pub(crate) fn concentration_for(
    deposits: &[PheromoneDeposit],
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
        if deposit.is_evaporated(now, policy.evaporation_threshold) {
            continue;
        }
        if is_suppressed_by_feedback(deposit, &suppression) {
            continue;
        }
        let strength = deposit.strength_at(now);
        if strength <= 0.0 {
            continue;
        }
        total_strength += strength;
        peak_confidence = peak_confidence.max(deposit.confidence);
        sources.insert(deposit.agent_id.0.clone());
    }

    PheromoneConcentration {
        threat_class: threat_class.clone(),
        total_strength,
        distinct_sources: sources.len(),
        peak_confidence,
    }
}

pub(crate) fn filter_deposits(
    deposits: &[PheromoneDeposit],
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
        .cloned()
        .collect::<Vec<_>>();
    filtered.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
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
    deposits: &[PheromoneDeposit],
) -> BTreeMap<FeedbackSuppressionKey, (FeedbackSuppressionState, i64)> {
    let mut states = BTreeMap::new();
    for deposit in deposits {
        let Some((key, state)) = feedback_suppression_marker(deposit) else {
            continue;
        };
        let replace = states
            .get(&key)
            .is_none_or(|(_, timestamp)| *timestamp <= deposit.timestamp);
        if replace {
            states.insert(key, (state, deposit.timestamp));
        }
    }
    states
}

fn is_suppressed_by_feedback(
    deposit: &PheromoneDeposit,
    suppression: &BTreeMap<FeedbackSuppressionKey, (FeedbackSuppressionState, i64)>,
) -> bool {
    if is_providence_feedback_deposit(deposit) {
        return false;
    }
    let Some(key) = deposit_suppression_key(deposit) else {
        return false;
    };
    suppression.get(&key).is_some_and(|(state, timestamp)| {
        *state == FeedbackSuppressionState::Dismiss && *timestamp >= deposit.timestamp
    })
}

fn feedback_suppression_marker(
    deposit: &PheromoneDeposit,
) -> Option<(FeedbackSuppressionKey, FeedbackSuppressionState)> {
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
    Some((
        FeedbackSuppressionKey {
            threat_class: deposit.threat_class.clone(),
            event_id: event_id.to_string(),
        },
        state,
    ))
}

fn deposit_suppression_key(deposit: &PheromoneDeposit) -> Option<FeedbackSuppressionKey> {
    Some(FeedbackSuppressionKey {
        threat_class: deposit.threat_class.clone(),
        event_id: deposit
            .indicator
            .get("event_id")
            .and_then(serde_json::Value::as_str)?
            .to_string(),
    })
}

fn is_providence_feedback_deposit(deposit: &PheromoneDeposit) -> bool {
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
    filtered.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    filtered
}

fn ensure_parent_dir(path: &Path) -> Result<(), SubstrateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SubstrateError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
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

fn load_deposit_jsonl(path: &Path) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
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
        let location = format!("{} line {}", path.display(), index + 1);
        let entry = decode_deposit_payload(line.as_bytes(), location)?;
        entries.push(entry);
    }

    Ok(entries)
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
    })
}

fn rewrite_jsonl<T>(path: &Path, entries: &[T]) -> Result<(), SubstrateError>
where
    T: Serialize,
{
    ensure_parent_dir(path)?;
    let mut file = fs::File::create(path).map_err(|source| SubstrateError::Write {
        path: path.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let serialized = serde_json::to_string(entry).map_err(|source| SubstrateError::Parse {
            path: path.to_path_buf(),
            line: 0,
            source,
        })?;
        writeln!(file, "{serialized}").map_err(|source| SubstrateError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    }

    Ok(())
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
) -> Result<BTreeMap<String, BehavioralBaselineSnapshot>, SubstrateError> {
    let entries = load_jsonl::<BehavioralBaselineSnapshot>(path)?;
    let mut snapshots = BTreeMap::new();
    for entry in entries {
        snapshots.insert(entry.strategy_id.clone(), entry);
    }
    Ok(snapshots)
}

fn escalation_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("escalations.jsonl")
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
        ThreatIntelIndicatorType::IpAddress | ThreatIntelIndicatorType::FileHash => {
            trimmed.to_ascii_lowercase()
        }
    }
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
        BehavioralTelemetryFamilyBaseline, EscalationRecord, PheromoneDeposit, ThreatClass,
        ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, Severity};

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
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
        InMemoryPheromoneSubstrate::new(substrate_config())
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
    async fn query_counts_strategy_scoped_agent_ids_as_distinct_sources() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit(
                "whisker-primary:suspicious_process_tree",
                100,
                0.9,
            ))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-primary:dns_exfiltration", 100, 0.9))
            .await
            .unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();

        assert!(concentration.distinct_sources == 2);
    }

    #[tokio::test]
    async fn query_collapses_repeated_strategy_scoped_agent_ids_to_one_source() {
        let substrate = in_memory();
        substrate
            .deposit(sample_deposit(
                "whisker-primary:suspicious_process_tree",
                100,
                0.9,
            ))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit(
                "whisker-primary:suspicious_process_tree",
                100,
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
    async fn threat_class_override_affects_concentration_and_gc() {
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
        substrate
            .deposit(sample_deposit("whisker-a", 0, 0.03))
            .await
            .unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 0)
            .await
            .unwrap();
        assert_eq!(concentration.total_strength, 0.0);

        let removed = substrate.gc_evaporated(0).await.unwrap();
        assert_eq!(removed, 1);
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
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .deposit(sample_deposit("whisker-a", 100, 0.9))
                .await
                .unwrap();
            substrate
                .deposit(sample_deposit("whisker-b", 200, 0.8))
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
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

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
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
        let path = std::env::temp_dir().join("swarm-pheromone-behavioral-baseline.jsonl");
        let escalation_path = super::escalation_journal_path(&path);
        let config_path = super::threat_class_config_journal_path(&path);
        let threat_intel_path = super::threat_intel_journal_path(&path);
        let behavioral_baseline_path = super::behavioral_baseline_journal_path(&path);
        let config = PheromoneConfig {
            backend: PheromoneBackendConfig::LocalJournal {
                path: path.display().to_string(),
            },
            ..substrate_config()
        };
        let snapshot = sample_behavioral_baseline_snapshot("behavioral_anomaly");

        {
            let substrate = LocalJournalPheromoneSubstrate::open(config.clone(), &path).unwrap();
            substrate
                .store_behavioral_baseline_snapshot(snapshot.clone())
                .await
                .unwrap();
        }

        let reopened = LocalJournalPheromoneSubstrate::open(config, &path).unwrap();
        let stored = reopened
            .query_behavioral_baseline_snapshot("behavioral_anomaly")
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
            .deposit(sample_deposit("old-agent", 0, 0.001))
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
