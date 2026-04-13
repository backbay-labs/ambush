use crate::runtime_events::{
    EscalationLevel, RuntimeEvent, RuntimeEventBroadcaster, RuntimeThreatConcentration, now_ms,
};
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::agent::{SwarmMode, SwarmModeState};
use swarm_core::config::PheromoneConfig;
use swarm_core::pheromone::{EscalationRecord, ThreatClass};
use swarm_core::types::EscalationEvent;
use swarm_pheromone::{PheromoneSubstrate, SubstrateError};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

#[derive(Debug, Clone)]
pub struct EscalationOutcome {
    pub events: Vec<EscalationEvent>,
    pub mode_changed: bool,
    pub current_mode: SwarmMode,
}

pub struct ConcentrationMonitor<S: PheromoneSubstrate> {
    config: PheromoneConfig,
    substrate: Arc<S>,
    mode_state: SwarmModeState,
    below_threshold_since: Option<i64>,
    shared_mode_state: Option<Arc<ArcSwap<SwarmModeState>>>,
    runtime_events: Option<RuntimeEventBroadcaster>,
}

impl<S: PheromoneSubstrate> ConcentrationMonitor<S> {
    pub fn new(config: PheromoneConfig, substrate: Arc<S>) -> Self {
        Self {
            config,
            substrate,
            mode_state: SwarmModeState::new(),
            below_threshold_since: None,
            shared_mode_state: None,
            runtime_events: None,
        }
    }

    pub fn with_shared_mode_state(
        mut self,
        shared_mode_state: Arc<ArcSwap<SwarmModeState>>,
    ) -> Self {
        shared_mode_state.store(Arc::new(self.mode_state.clone()));
        self.shared_mode_state = Some(shared_mode_state);
        self
    }

    pub fn with_runtime_events(mut self, runtime_events: RuntimeEventBroadcaster) -> Self {
        self.runtime_events = Some(runtime_events);
        self
    }

    pub fn mode_state(&self) -> &SwarmModeState {
        &self.mode_state
    }

    pub async fn evaluate_threat_class(
        &mut self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<Option<EscalationEvent>, SubstrateError> {
        let threat_class_config = self
            .substrate
            .query_threat_class_config(threat_class)
            .await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        let concentration = self
            .substrate
            .query_concentration(threat_class, now)
            .await?;

        if concentration
            .exceeds_threshold(policy.incident_threshold, policy.min_sources_for_escalation)
        {
            return Ok(Some(EscalationEvent::Incident {
                threat_class: concentration.threat_class,
                total_strength: concentration.total_strength,
                distinct_sources: concentration.distinct_sources,
                peak_confidence: concentration.peak_confidence,
                timestamp: now,
            }));
        }

        if concentration
            .exceeds_threshold(policy.alert_threshold, policy.min_sources_for_escalation)
        {
            return Ok(Some(EscalationEvent::Alert {
                threat_class: concentration.threat_class,
                total_strength: concentration.total_strength,
                distinct_sources: concentration.distinct_sources,
                peak_confidence: concentration.peak_confidence,
                timestamp: now,
            }));
        }

        Ok(None)
    }

    pub async fn evaluate_all(&mut self, now: i64) -> Result<EscalationOutcome, SubstrateError> {
        let mut events = Vec::new();
        let mut mode_changed = false;
        let starting_mode = self.mode_state.current;

        for threat_class in standard_threat_classes() {
            if let Some(event) = self.evaluate_threat_class(&threat_class, now).await? {
                let target_mode = event_mode(&event);
                let event_threat_class = event_threat_class(&event).clone();
                let mut event_mode_changed = false;
                tracing::warn!(
                    module = module_path!(),
                    threat_class = %threat_class_name(&event_threat_class),
                    total_strength = event_total_strength(&event),
                    distinct_sources = event_distinct_sources(&event),
                    peak_confidence = event_peak_confidence(&event),
                    target_mode = ?target_mode,
                    "pheromone concentration crossed escalation threshold"
                );

                if target_mode > self.mode_state.current {
                    let record = escalation_record(&event);
                    self.substrate.record_escalation(record).await?;
                    let previous_mode = self.mode_state.current;
                    self.mode_state
                        .transition_to(target_mode, event_threat_class.clone(), now);
                    mode_changed = true;
                    event_mode_changed = true;
                    self.publish_mode_transition(
                        previous_mode,
                        target_mode,
                        Some(event_threat_class.clone()),
                        "threshold_crossed",
                    );
                    tracing::info!(
                        module = module_path!(),
                        to_mode = ?target_mode,
                        threat_class = %threat_class_name(&event_threat_class),
                        timestamp = now,
                        "swarm mode escalated"
                    );
                }

                self.publish_escalation(&event, event_mode_changed);
                events.push(event);
            }
        }

        if events.is_empty() {
            if self.mode_state.current != SwarmMode::Normal {
                let quiet_since = self.below_threshold_since.get_or_insert(now);
                if now - *quiet_since >= self.config.deescalation_cooldown_secs
                    && self.mode_state.transition_down(SwarmMode::Normal, now)
                {
                    mode_changed = true;
                    self.publish_mode_transition(
                        starting_mode,
                        SwarmMode::Normal,
                        None,
                        "deescalation_cooldown_elapsed",
                    );
                    self.below_threshold_since = None;
                    tracing::info!(
                        module = module_path!(),
                        to_mode = ?SwarmMode::Normal,
                        timestamp = now,
                        "swarm mode de-escalated after cooldown"
                    );
                }
            } else {
                self.below_threshold_since = None;
            }
        } else {
            self.below_threshold_since = None;
        }

        let concentrations = self.snapshot_concentrations(now).await?;
        self.publish_concentration_snapshot(concentrations);
        self.sync_shared_mode_state();

        Ok(EscalationOutcome {
            events,
            mode_changed,
            current_mode: self.mode_state.current,
        })
    }

    pub async fn run_until_shutdown(
        &mut self,
        interval_ms: u64,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if *shutdown.borrow() {
                        break;
                    }
                    let now = unix_timestamp_secs();
                    if let Err(error) = self.evaluate_all(now).await {
                        tracing::warn!(
                            module = module_path!(),
                            reason = %error,
                            "concentration monitor evaluation failed"
                        );
                    }
                }
            }
        }
    }

    fn sync_shared_mode_state(&self) {
        if let Some(shared_mode_state) = &self.shared_mode_state {
            shared_mode_state.store(Arc::new(self.mode_state.clone()));
        }
    }

    fn publish_escalation(&self, event: &EscalationEvent, mode_changed: bool) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::Escalation {
            emitted_at_ms: now_ms(),
            threat_class: event_threat_class(event).clone(),
            level: match event {
                EscalationEvent::Alert { .. } => EscalationLevel::Alert,
                EscalationEvent::Incident { .. } => EscalationLevel::Incident,
            },
            total_strength: event_total_strength(event),
            distinct_sources: event_distinct_sources(event),
            peak_confidence: event_peak_confidence(event),
            mode_changed,
            current_mode: self.mode_state.current,
        });
    }

    async fn snapshot_concentrations(
        &self,
        now: i64,
    ) -> Result<Vec<RuntimeThreatConcentration>, SubstrateError> {
        let mut concentrations = Vec::with_capacity(standard_threat_classes().len());
        for threat_class in standard_threat_classes() {
            let concentration = self
                .substrate
                .query_concentration(&threat_class, now)
                .await?;
            concentrations.push(RuntimeThreatConcentration::from(&concentration));
        }
        Ok(concentrations)
    }

    fn publish_concentration_snapshot(&self, concentrations: Vec<RuntimeThreatConcentration>) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::ConcentrationSnapshot {
            emitted_at_ms: now_ms(),
            current_mode: self.mode_state.current,
            concentrations,
        });
    }

    fn publish_mode_transition(
        &self,
        from: SwarmMode,
        to: SwarmMode,
        triggering_threat_class: Option<ThreatClass>,
        reason: &str,
    ) {
        let Some(runtime_events) = &self.runtime_events else {
            return;
        };

        runtime_events.publish(RuntimeEvent::ModeTransition {
            emitted_at_ms: now_ms(),
            from,
            to,
            triggering_threat_class,
            reason: reason.to_string(),
        });
    }
}

pub(crate) fn standard_threat_classes() -> Vec<ThreatClass> {
    vec![
        ThreatClass::LateralMovement,
        ThreatClass::DataExfiltration,
        ThreatClass::PrivilegeEscalation,
        ThreatClass::CommandAndControl,
        ThreatClass::InitialAccess,
        ThreatClass::Persistence,
        ThreatClass::SupplyChain,
        ThreatClass::DefenseEvasion,
        ThreatClass::CredentialAccess,
        ThreatClass::Discovery,
        ThreatClass::Execution,
        ThreatClass::Impact,
    ]
}

fn event_mode(event: &EscalationEvent) -> SwarmMode {
    match event {
        EscalationEvent::Alert { .. } => SwarmMode::Alert,
        EscalationEvent::Incident { .. } => SwarmMode::Incident,
    }
}

fn event_threat_class(event: &EscalationEvent) -> &ThreatClass {
    match event {
        EscalationEvent::Alert { threat_class, .. }
        | EscalationEvent::Incident { threat_class, .. } => threat_class,
    }
}

fn event_total_strength(event: &EscalationEvent) -> f64 {
    match event {
        EscalationEvent::Alert { total_strength, .. }
        | EscalationEvent::Incident { total_strength, .. } => *total_strength,
    }
}

fn event_distinct_sources(event: &EscalationEvent) -> usize {
    match event {
        EscalationEvent::Alert {
            distinct_sources, ..
        }
        | EscalationEvent::Incident {
            distinct_sources, ..
        } => *distinct_sources,
    }
}

fn event_peak_confidence(event: &EscalationEvent) -> f64 {
    match event {
        EscalationEvent::Alert {
            peak_confidence, ..
        }
        | EscalationEvent::Incident {
            peak_confidence, ..
        } => *peak_confidence,
    }
}

fn escalation_record(event: &EscalationEvent) -> EscalationRecord {
    EscalationRecord {
        mode: event_mode(event),
        threat_class: event_threat_class(event).clone(),
        total_strength: event_total_strength(event),
        distinct_sources: event_distinct_sources(event),
        peak_confidence: event_peak_confidence(event),
        timestamp: match event {
            EscalationEvent::Alert { timestamp, .. }
            | EscalationEvent::Incident { timestamp, .. } => *timestamp,
        },
    }
}

fn threat_class_name(threat_class: &ThreatClass) -> &str {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement",
        ThreatClass::DataExfiltration => "data_exfiltration",
        ThreatClass::PrivilegeEscalation => "privilege_escalation",
        ThreatClass::CommandAndControl => "command_and_control",
        ThreatClass::InitialAccess => "initial_access",
        ThreatClass::Persistence => "persistence",
        ThreatClass::SupplyChain => "supply_chain",
        ThreatClass::DefenseEvasion => "defense_evasion",
        ThreatClass::CredentialAccess => "credential_access",
        ThreatClass::Discovery => "discovery",
        ThreatClass::Execution => "execution",
        ThreatClass::Impact => "impact",
        ThreatClass::Custom(value) => value.as_str(),
    }
}

fn unix_timestamp_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::ConcentrationMonitor;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, EscalationEvent, Severity};
    use swarm_pheromone::{DepositSigningPayload, InMemoryPheromoneSubstrate, PheromoneSubstrate};

    fn test_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: Default::default(),
            backend: PheromoneBackendConfig::InMemory,
        }
    }

    fn signing_key_a() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn signing_key_b() -> SigningKey {
        SigningKey::from_bytes(&[43u8; 32])
    }

    fn make_deposit(key: &SigningKey, confidence: f64, timestamp: i64) -> PheromoneDeposit {
        let agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({"signal": "process-tree"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: agent_id.clone(),
            agent_identity: agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
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
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let sig = key.sign(&payload_bytes);
        deposit.signature = sig.to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        deposit
    }

    #[tokio::test]
    async fn below_threshold_returns_no_events() {
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
        substrate
            .deposit(make_deposit(&signing_key_a(), 0.3, 1_700_000_000))
            .await
            .unwrap();
        substrate
            .deposit(make_deposit(&signing_key_b(), 0.3, 1_700_000_000))
            .await
            .unwrap();
        let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));

        let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
        assert!(outcome.events.is_empty());
        assert!(!outcome.mode_changed);
        assert_eq!(outcome.current_mode, SwarmMode::Normal);
    }

    #[tokio::test]
    async fn single_source_above_threshold_returns_no_event() {
        let key = signing_key_a();
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
        substrate
            .deposit(make_deposit(&key, 0.9, 1_700_000_000))
            .await
            .unwrap();
        substrate
            .deposit(make_deposit(&key, 0.9, 1_700_000_000))
            .await
            .unwrap();
        substrate
            .deposit(make_deposit(&key, 0.9, 1_700_000_000))
            .await
            .unwrap();
        let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));

        let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
        assert!(outcome.events.is_empty());
        assert_eq!(outcome.current_mode, SwarmMode::Normal);
    }

    #[tokio::test]
    async fn dual_source_alert_threshold_emits_alert_event() {
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
        for key in [&signing_key_a(), &signing_key_b()] {
            substrate
                .deposit(make_deposit(key, 0.9, 1_700_000_000))
                .await
                .unwrap();
            substrate
                .deposit(make_deposit(key, 0.9, 1_700_000_000))
                .await
                .unwrap();
        }
        let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));

        let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
        assert_eq!(outcome.events.len(), 1);
        assert!(matches!(outcome.events[0], EscalationEvent::Alert { .. }));
        assert!(outcome.mode_changed);
        assert_eq!(outcome.current_mode, SwarmMode::Alert);
    }

    #[tokio::test]
    async fn dual_source_incident_threshold_emits_incident_event() {
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
        for key in [&signing_key_a(), &signing_key_b()] {
            for _ in 0..3 {
                substrate
                    .deposit(make_deposit(key, 0.9, 1_700_000_000))
                    .await
                    .unwrap();
            }
        }
        let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));

        let outcome = monitor.evaluate_all(1_700_000_000).await.unwrap();
        assert_eq!(outcome.events.len(), 1);
        assert!(matches!(
            outcome.events[0],
            EscalationEvent::Incident { .. }
        ));
        assert!(outcome.mode_changed);
        assert_eq!(outcome.current_mode, SwarmMode::Incident);
    }

    #[tokio::test]
    async fn mode_progresses_from_normal_to_alert_to_incident() {
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
        let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));

        for key in [&signing_key_a(), &signing_key_b()] {
            substrate
                .deposit(make_deposit(key, 1.1, 1_700_000_000))
                .await
                .unwrap();
        }
        let alert = monitor.evaluate_all(1_700_000_000).await.unwrap();
        assert_eq!(alert.current_mode, SwarmMode::Alert);

        for key in [&signing_key_a(), &signing_key_b()] {
            for _ in 0..3 {
                substrate
                    .deposit(make_deposit(key, 0.9, 1_700_000_010))
                    .await
                    .unwrap();
            }
        }
        let incident = monitor.evaluate_all(1_700_000_010).await.unwrap();
        assert_eq!(incident.current_mode, SwarmMode::Incident);
        assert!(incident.mode_changed);
    }

    #[tokio::test]
    async fn repeated_alerts_do_not_deescalate_incident_mode() {
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new(test_config()));
        let mut monitor = ConcentrationMonitor::new(test_config(), Arc::clone(&substrate));
        monitor.mode_state.transition_to(
            SwarmMode::Incident,
            ThreatClass::Execution,
            1_700_000_000,
        );

        for key in [&signing_key_a(), &signing_key_b()] {
            substrate
                .deposit(make_deposit(key, 1.1, 1_700_000_100))
                .await
                .unwrap();
        }
        let outcome = monitor.evaluate_all(1_700_000_100).await.unwrap();
        assert_eq!(outcome.current_mode, SwarmMode::Incident);
        assert!(!outcome.mode_changed);
        assert!(matches!(outcome.events[0], EscalationEvent::Alert { .. }));
    }
}
