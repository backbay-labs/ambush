//! Core substrate operations.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{PheromoneConcentration, PheromoneDeposit, ThreatClass};

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

/// Async contract for pheromone substrates.
#[async_trait]
pub trait PheromoneSubstrate: Send + Sync {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError>;

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError>;

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError>;

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
        }
    }
}

#[async_trait]
impl PheromoneSubstrate for ConfiguredPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.deposit(deposit).await,
            Self::LocalJournal(substrate) => substrate.deposit(deposit).await,
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
        }
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.query_deposits(query).await,
            Self::LocalJournal(substrate) => substrate.query_deposits(query).await,
        }
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.gc_evaporated(now).await,
            Self::LocalJournal(substrate) => substrate.gc_evaporated(now).await,
        }
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        match self {
            Self::InMemory(substrate) => substrate.health().await,
            Self::LocalJournal(substrate) => substrate.health().await,
        }
    }
}

/// In-memory substrate used by the first vertical slice and replay tests.
#[derive(Debug, Clone)]
pub struct InMemoryPheromoneSubstrate {
    config: PheromoneConfig,
    deposits: Arc<RwLock<Vec<PheromoneDeposit>>>,
}

impl InMemoryPheromoneSubstrate {
    pub fn new(config: PheromoneConfig) -> Self {
        Self {
            config,
            deposits: Arc::new(RwLock::new(Vec::new())),
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

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        Ok(concentration_for(&guard, threat_class, now, &self.config))
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

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let before = guard.len();
        guard.retain(|deposit| !deposit.is_evaporated(now, self.config.evaporation_threshold));
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
    deposits: Arc<RwLock<Vec<PheromoneDeposit>>>,
}

impl LocalJournalPheromoneSubstrate {
    pub fn open(config: PheromoneConfig, path: impl AsRef<Path>) -> Result<Self, SubstrateError> {
        let journal_path = path.as_ref().to_path_buf();
        ensure_parent_dir(&journal_path)?;
        let deposits = load_journal(&journal_path)?;

        Ok(Self {
            config,
            journal_path,
            deposits: Arc::new(RwLock::new(deposits)),
        })
    }
}

#[async_trait]
impl PheromoneSubstrate for LocalJournalPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        append_journal_line(&self.journal_path, &deposit)?;
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        guard.push(deposit);
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
        Ok(concentration_for(&guard, threat_class, now, &self.config))
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

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self
            .deposits
            .write()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let before = guard.len();
        guard.retain(|deposit| !deposit.is_evaporated(now, self.config.evaporation_threshold));
        rewrite_journal(&self.journal_path, &guard)?;
        Ok(before - guard.len())
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        let guard = self
            .deposits
            .read()
            .map_err(|_| SubstrateError::PoisonedLock)?;
        let ready = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .is_ok();

        Ok(SubstrateHealth {
            backend: "local_journal".to_string(),
            durable: true,
            ready,
            details: format!("journal file at {}", self.journal_path.display()),
            deposit_count: guard.len(),
        })
    }
}

fn concentration_for(
    deposits: &[PheromoneDeposit],
    threat_class: &ThreatClass,
    now: i64,
    config: &PheromoneConfig,
) -> PheromoneConcentration {
    let mut sources = HashSet::new();
    let mut total_strength = 0.0;
    let mut peak_confidence: f64 = 0.0;

    for deposit in deposits
        .iter()
        .filter(|deposit| &deposit.threat_class == threat_class)
    {
        if deposit.is_evaporated(now, config.evaporation_threshold) {
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

fn filter_deposits(deposits: &[PheromoneDeposit], query: DepositQuery) -> Vec<PheromoneDeposit> {
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

fn ensure_parent_dir(path: &Path) -> Result<(), SubstrateError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SubstrateError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn load_journal(path: &Path) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(path).map_err(|source| SubstrateError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let reader = BufReader::new(file);
    let mut deposits = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line.map_err(|source| SubstrateError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let deposit = serde_json::from_str::<PheromoneDeposit>(&line).map_err(|source| {
            SubstrateError::Parse {
                path: path.to_path_buf(),
                line: index + 1,
                source,
            }
        })?;
        deposits.push(deposit);
    }

    Ok(deposits)
}

fn append_journal_line(path: &Path, deposit: &PheromoneDeposit) -> Result<(), SubstrateError> {
    ensure_parent_dir(path)?;
    let serialized = serde_json::to_string(deposit).map_err(|source| SubstrateError::Parse {
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

fn rewrite_journal(path: &Path, deposits: &[PheromoneDeposit]) -> Result<(), SubstrateError> {
    ensure_parent_dir(path)?;
    let mut file = fs::File::create(path).map_err(|source| SubstrateError::Write {
        path: path.to_path_buf(),
        source,
    })?;

    for deposit in deposits {
        let serialized =
            serde_json::to_string(deposit).map_err(|source| SubstrateError::Parse {
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

#[cfg(test)]
mod tests {
    use super::{
        ConfiguredPheromoneSubstrate, DepositQuery, InMemoryPheromoneSubstrate,
        LocalJournalPheromoneSubstrate, PheromoneSubstrate,
    };
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
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
    async fn local_journal_recovers_deposits_after_reopen() {
        let path = std::env::temp_dir().join("swarm-pheromone-journal.jsonl");
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
        let _ = std::fs::remove_file(path);
    }
}
