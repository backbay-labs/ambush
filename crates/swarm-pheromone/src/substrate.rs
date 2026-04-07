//! Core substrate operations.

use crate::jetstream::JetStreamPheromoneSubstrate;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    EscalationRecord, PheromoneConcentration, PheromoneDeposit, ThreatClass, ThreatClassConfig,
    ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};

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
}

/// Query filters for reading persisted deposits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DepositQuery {
    pub threat_class: Option<ThreatClass>,
    pub since_timestamp: Option<i64>,
    pub limit: usize,
}

impl DepositQuery {
    pub fn recent(limit: usize) -> Self {
        Self {
            threat_class: None,
            since_timestamp: None,
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

    async fn recent_deposits(&self, limit: usize) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        self.query_deposits(DepositQuery::recent(limit)).await
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError>;

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

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.gc_evaporated(now).await,
            Self::LocalJournal(substrate) => substrate.gc_evaporated(now).await,
            Self::JetStream(substrate) => substrate.gc_evaporated(now).await,
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
    deposits: Arc<RwLock<Vec<PheromoneDeposit>>>,
    escalations: Arc<RwLock<Vec<EscalationRecord>>>,
    threat_class_configs: Arc<RwLock<BTreeMap<ThreatClass, ThreatClassConfig>>>,
    threat_intel_entries: Arc<RwLock<BTreeMap<ThreatIntelKey, ThreatIntelEntry>>>,
}

impl InMemoryPheromoneSubstrate {
    pub fn new(config: PheromoneConfig) -> Self {
        Self {
            config,
            deposits: Arc::new(RwLock::new(Vec::new())),
            escalations: Arc::new(RwLock::new(Vec::new())),
            threat_class_configs: Arc::new(RwLock::new(BTreeMap::new())),
            threat_intel_entries: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
impl PheromoneSubstrate for InMemoryPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
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
    journal_path: PathBuf,
    escalation_journal_path: PathBuf,
    threat_class_config_journal_path: PathBuf,
    threat_intel_journal_path: PathBuf,
    deposits: Arc<RwLock<Vec<PheromoneDeposit>>>,
    escalations: Arc<RwLock<Vec<EscalationRecord>>>,
    threat_class_configs: Arc<RwLock<BTreeMap<ThreatClass, ThreatClassConfig>>>,
    threat_intel_entries: Arc<RwLock<BTreeMap<ThreatIntelKey, ThreatIntelEntry>>>,
}

impl LocalJournalPheromoneSubstrate {
    pub fn open(config: PheromoneConfig, path: impl AsRef<Path>) -> Result<Self, SubstrateError> {
        let journal_path = path.as_ref().to_path_buf();
        let escalation_journal_path = escalation_journal_path(&journal_path);
        let threat_class_config_journal_path = threat_class_config_journal_path(&journal_path);
        let threat_intel_journal_path = threat_intel_journal_path(&journal_path);
        ensure_parent_dir(&journal_path)?;
        let deposits = load_jsonl(&journal_path)?;
        let escalations = load_jsonl(&escalation_journal_path)?;
        let threat_class_configs = load_threat_class_configs(&threat_class_config_journal_path)?;
        let threat_intel_entries = load_threat_intel_entries(&threat_intel_journal_path)?;

        Ok(Self {
            config,
            journal_path,
            escalation_journal_path,
            threat_class_config_journal_path,
            threat_intel_journal_path,
            deposits: Arc::new(RwLock::new(deposits)),
            escalations: Arc::new(RwLock::new(escalations)),
            threat_class_configs: Arc::new(RwLock::new(threat_class_configs)),
            threat_intel_entries: Arc::new(RwLock::new(threat_intel_entries)),
        })
    }
}

#[async_trait]
impl PheromoneSubstrate for LocalJournalPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
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
        let ready = deposits_ready && escalations_ready && configs_ready && threat_intel_ready;

        Ok(SubstrateHealth {
            backend: "local_journal".to_string(),
            durable: true,
            ready,
            details: format!(
                "journal files at {}, {}, {}, and {}",
                self.journal_path.display(),
                self.escalation_journal_path.display(),
                self.threat_class_config_journal_path.display(),
                self.threat_intel_journal_path.display()
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
        total_strength += deposit.strength_at(now);
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
        })
        .cloned()
        .collect::<Vec<_>>();
    filtered.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    if query.limit > 0 {
        filtered.truncate(query.limit);
    }
    filtered
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

fn escalation_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("escalations.jsonl")
}

fn threat_class_config_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("threat-class-configs.jsonl")
}

fn threat_intel_journal_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("threat-intel.jsonl")
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
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::pheromone::{
        EscalationRecord, PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry,
        ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, Severity};

    fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
        PheromoneDeposit {
            indicator: serde_json::json!({"signal": "process-tree"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: AgentId(agent_id.to_string()),
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

    fn substrate_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
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
        substrate.deposit(second).await.unwrap();

        let deposits = substrate
            .query_deposits(DepositQuery {
                threat_class: Some(ThreatClass::Execution),
                since_timestamp: Some(50),
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
}
