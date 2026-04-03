//! Core substrate operations.

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::{PheromoneConcentration, PheromoneDeposit, ThreatClass};

/// Errors raised by the pheromone substrate.
#[derive(Debug, thiserror::Error)]
pub enum SubstrateError {
    #[error("substrate lock poisoned")]
    PoisonedLock,
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

    async fn recent_deposits(&self, limit: usize) -> Result<Vec<PheromoneDeposit>, SubstrateError>;

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError>;
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
        let mut guard = self.deposits.write().map_err(|_| SubstrateError::PoisonedLock)?;
        guard.push(deposit);
        Ok(())
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let guard = self.deposits.read().map_err(|_| SubstrateError::PoisonedLock)?;
        let mut sources = HashSet::new();
        let mut total_strength = 0.0;
        let mut peak_confidence: f64 = 0.0;

        for deposit in guard.iter().filter(|deposit| &deposit.threat_class == threat_class) {
            if deposit.is_evaporated(now, self.config.evaporation_threshold) {
                continue;
            }
            total_strength += deposit.strength_at(now);
            peak_confidence = peak_confidence.max(deposit.confidence);
            sources.insert(deposit.agent_id.0.clone());
        }

        Ok(PheromoneConcentration {
            threat_class: threat_class.clone(),
            total_strength,
            distinct_sources: sources.len(),
            peak_confidence,
        })
    }

    async fn recent_deposits(&self, limit: usize) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let guard = self.deposits.read().map_err(|_| SubstrateError::PoisonedLock)?;
        let mut recent = guard.clone();
        recent.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        recent.truncate(limit);
        Ok(recent)
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        let mut guard = self.deposits.write().map_err(|_| SubstrateError::PoisonedLock)?;
        let before = guard.len();
        guard.retain(|deposit| !deposit.is_evaporated(now, self.config.evaporation_threshold));
        Ok(before - guard.len())
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
    use swarm_core::config::PheromoneConfig;
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

    fn substrate() -> InMemoryPheromoneSubstrate {
        InMemoryPheromoneSubstrate::new(PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
        })
    }

    #[tokio::test]
    async fn query_respects_source_diversity() {
        let substrate = substrate();
        substrate.deposit(sample_deposit("whisker-a", 100, 1.0)).await.unwrap();
        substrate.deposit(sample_deposit("whisker-a", 100, 0.8)).await.unwrap();
        substrate.deposit(sample_deposit("whisker-b", 100, 0.9)).await.unwrap();

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100)
            .await
            .unwrap();

        assert_eq!(concentration.distinct_sources, 2);
        assert!(concentration.total_strength > 2.0);
    }

    #[tokio::test]
    async fn recent_deposits_support_replay() {
        let substrate = substrate();
        substrate.deposit(sample_deposit("whisker-a", 100, 1.0)).await.unwrap();
        substrate.deposit(sample_deposit("whisker-b", 200, 0.9)).await.unwrap();
        substrate.deposit(sample_deposit("whisker-c", 300, 0.8)).await.unwrap();

        let deposits = substrate.recent_deposits(2).await.unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].timestamp, 300);
        assert_eq!(deposits[1].timestamp, 200);
    }

    #[tokio::test]
    async fn gc_removes_evaporated_deposits() {
        let substrate = substrate();
        substrate.deposit(sample_deposit("whisker-a", 0, 0.1)).await.unwrap();

        let removed = substrate.gc_evaporated(100_000).await.unwrap();
        assert_eq!(removed, 1);
    }
}
