use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::config::{
    DeceptionConfig, DeceptionMonitoringConfig, DeceptionPlacementStrategy,
    DeceptionPlaybookConfig, DeceptionPlaybookEntry, SwarmConfig,
};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity, SwarmAction};
use swarm_pheromone::{ConfiguredPheromoneSubstrate, DepositSigningPayload, PheromoneSubstrate};

const CALICO_LIFECYCLE_SCHEMA_VERSION: u32 = 1;
pub(crate) const CALICO_DECEPTION_INVENTORY_SCHEMA: &str = "calico_deception_inventory";
pub(crate) const CALICO_DECEPTION_INTERACTION_SCHEMA: &str = "calico_deception_interaction";
pub(crate) const CALICO_DECEPTION_INVENTORY_THREAT_CLASS: &str = "deception_inventory";

pub struct CalicoAgent {
    id: AgentId,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    playbook: DeceptionPlaybookConfig,
    deception_config: DeceptionConfig,
    substrate: ConfiguredPheromoneSubstrate,
    pheromone_config: swarm_core::config::PheromoneConfig,
    lifecycle_store: FileCalicoLifecycleStore,
    lifecycle: CalicoLifecycleSnapshot,
    role: AgentRole,
    health: AgentHealth,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeceptionMatch {
    signal: &'static str,
    matched_value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CalicoLifecycleStage {
    Deploy,
    Monitor,
    Rotate,
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CalicoMonitoringPayload {
    pub file_paths: Vec<String>,
    pub honeypot_ports: Vec<u16>,
    pub canary_credentials: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CalicoDeceptionInventoryPayload {
    pub schema: String,
    pub schema_version: u32,
    pub asset_id: String,
    pub playbook_entry: String,
    pub generation: usize,
    pub lifecycle_stage: CalicoLifecycleStage,
    pub decoy_type: String,
    pub target_zone: String,
    pub host_profile: String,
    pub placement_strategy: String,
    pub deployed_at_ms: i64,
    pub monitoring: CalicoMonitoringPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CalicoDeceptionInteractionPayload {
    pub schema: String,
    pub schema_version: u32,
    pub asset_id: String,
    pub playbook_entry: String,
    pub generation: usize,
    pub lifecycle_stage: CalicoLifecycleStage,
    pub decoy_type: String,
    pub target_zone: String,
    pub host_profile: String,
    pub placement_strategy: String,
    pub interaction_signal: String,
    pub matched_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hunt_id: Option<String>,
    pub source_agent_id: String,
    pub source_indicator: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CalicoLifecycleAsset {
    asset_id: String,
    playbook_entry: String,
    generation: usize,
    decoy_type: String,
    target_zone: String,
    host_profile: String,
    placement_strategy: String,
    lifecycle_stage: CalicoLifecycleStage,
    created_at_ms: i64,
    deployed_at_ms: i64,
    last_observed_at_ms: i64,
    deploy_requested_at_ms: Option<i64>,
    rotated_at_ms: Option<i64>,
    cleaned_up_at_ms: Option<i64>,
    last_interaction_at_ms: Option<i64>,
    interaction_count: usize,
}

impl CalicoLifecycleAsset {
    fn new(entry: &DeceptionPlaybookEntry, generation: usize, now_ms: i64) -> Self {
        Self {
            asset_id: format!("calico:{}:{}", sanitize_id(&entry.name), generation.max(1)),
            playbook_entry: entry.name.clone(),
            generation,
            decoy_type: entry.decoy_type.clone(),
            target_zone: entry.target_zone.clone(),
            host_profile: entry.host_profile.clone(),
            placement_strategy: placement_strategy_label(entry.placement_strategy).to_string(),
            lifecycle_stage: CalicoLifecycleStage::Deploy,
            created_at_ms: now_ms,
            deployed_at_ms: now_ms,
            last_observed_at_ms: now_ms,
            deploy_requested_at_ms: None,
            rotated_at_ms: None,
            cleaned_up_at_ms: None,
            last_interaction_at_ms: None,
            interaction_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CalicoLifecycleSnapshot {
    schema_version: u32,
    updated_at_ms: i64,
    assets: Vec<CalicoLifecycleAsset>,
    handled_observations: BTreeSet<String>,
}

impl Default for CalicoLifecycleSnapshot {
    fn default() -> Self {
        Self {
            schema_version: CALICO_LIFECYCLE_SCHEMA_VERSION,
            updated_at_ms: 0,
            assets: Vec::new(),
            handled_observations: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct FileCalicoLifecycleStore {
    snapshot_path: PathBuf,
}

impl FileCalicoLifecycleStore {
    fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|error| format!("failed to create Calico lifecycle root: {error}"))?;
        Ok(Self {
            snapshot_path: root.join("calico-lifecycle.json"),
        })
    }

    fn load(&self) -> Result<Option<CalicoLifecycleSnapshot>, String> {
        if !self.snapshot_path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&self.snapshot_path)
            .map_err(|error| format!("failed to read Calico lifecycle snapshot: {error}"))?;
        let snapshot = serde_json::from_str(&raw)
            .map_err(|error| format!("failed to parse Calico lifecycle snapshot: {error}"))?;
        Ok(Some(snapshot))
    }

    fn persist(&self, snapshot: &CalicoLifecycleSnapshot) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(snapshot)
            .map_err(|error| format!("failed to encode Calico lifecycle snapshot: {error}"))?;
        fs::write(&self.snapshot_path, encoded)
            .map_err(|error| format!("failed to write Calico lifecycle snapshot: {error}"))
    }
}

impl CalicoAgent {
    pub fn new(
        id: AgentId,
        config_path: impl Into<PathBuf>,
        runtime_config: SwarmConfig,
        substrate: ConfiguredPheromoneSubstrate,
    ) -> Result<Self, String> {
        Self::new_with_signing_key(
            id,
            SigningKey::generate(&mut OsRng),
            config_path,
            runtime_config,
            substrate,
        )
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        config_path: impl Into<PathBuf>,
        runtime_config: SwarmConfig,
        substrate: ConfiguredPheromoneSubstrate,
    ) -> Result<Self, String> {
        let config_path = config_path.into();
        let lifecycle_store = FileCalicoLifecycleStore::open(resolve_deception_root(
            &config_path,
            &runtime_config.deception,
        ))?;
        let lifecycle = lifecycle_store.load()?.unwrap_or_default();
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            id,
            signing_key,
            verifying_key,
            playbook: runtime_config.deception.playbook.clone(),
            deception_config: runtime_config.deception.clone(),
            substrate,
            pheromone_config: runtime_config.pheromone.clone(),
            lifecycle_store,
            lifecycle,
            role: AgentRole::Calico,
            health: AgentHealth::Healthy,
        })
    }

    fn reconcile_lifecycle(&mut self, now_ms: i64) -> bool {
        let mut changed = false;
        let active_entries = self
            .playbook
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        let cleanup_grace_ms = self
            .deception_config
            .cleanup_grace_secs
            .saturating_mul(1000);

        for asset in &mut self.lifecycle.assets {
            if !active_entries.contains(&asset.playbook_entry)
                && asset.lifecycle_stage != CalicoLifecycleStage::Cleanup
            {
                asset.lifecycle_stage = CalicoLifecycleStage::Cleanup;
                asset.cleaned_up_at_ms = Some(now_ms);
                asset.last_observed_at_ms = now_ms;
                changed = true;
            }

            match asset.lifecycle_stage {
                CalicoLifecycleStage::Deploy => {
                    if asset.deploy_requested_at_ms.is_some() && now_ms > asset.deployed_at_ms {
                        asset.lifecycle_stage = CalicoLifecycleStage::Monitor;
                        asset.last_observed_at_ms = now_ms;
                        changed = true;
                    }
                }
                CalicoLifecycleStage::Rotate => {
                    let rotated_at_ms = asset.rotated_at_ms.unwrap_or(asset.last_observed_at_ms);
                    if now_ms.saturating_sub(rotated_at_ms)
                        >= cleanup_grace_ms.min(i64::MAX as u64) as i64
                    {
                        asset.lifecycle_stage = CalicoLifecycleStage::Cleanup;
                        asset.cleaned_up_at_ms = Some(now_ms);
                        asset.last_observed_at_ms = now_ms;
                        changed = true;
                    }
                }
                CalicoLifecycleStage::Monitor | CalicoLifecycleStage::Cleanup => {}
            }
        }

        let rotation_interval_ms = self
            .deception_config
            .rotation_interval_secs
            .saturating_mul(1000)
            .min(i64::MAX as u64) as i64;
        for entry in self.playbook.entries.clone() {
            if let Some(index) = self.monitor_asset_index(&entry.name) {
                let should_rotate = now_ms
                    .saturating_sub(self.lifecycle.assets[index].deployed_at_ms)
                    >= rotation_interval_ms;
                if should_rotate {
                    self.lifecycle.assets[index].lifecycle_stage = CalicoLifecycleStage::Rotate;
                    self.lifecycle.assets[index].rotated_at_ms = Some(now_ms);
                    self.lifecycle.assets[index].last_observed_at_ms = now_ms;
                    changed = true;
                }
            }
            if self.active_asset_for_entry(&entry.name).is_none() {
                self.lifecycle.assets.push(CalicoLifecycleAsset::new(
                    &entry,
                    self.next_generation(&entry.name),
                    now_ms,
                ));
                changed = true;
            }
        }

        if changed {
            self.sort_lifecycle_assets();
        }
        changed
    }

    async fn deployment_actions(
        &mut self,
        env: &SwarmEnvironment,
        now_ms: i64,
    ) -> Result<(Vec<SwarmAction>, bool), SwarmError> {
        let deployments = self
            .lifecycle
            .assets
            .iter()
            .filter(|asset| {
                asset.lifecycle_stage == CalicoLifecycleStage::Deploy
                    && asset.deploy_requested_at_ms.is_none()
            })
            .filter_map(|asset| {
                self.playbook
                    .entries
                    .iter()
                    .find(|entry| entry.name == asset.playbook_entry)
                    .cloned()
                    .map(|entry| (asset.clone(), entry))
            })
            .collect::<Vec<_>>();

        let mut actions = Vec::new();
        let mut changed = false;
        for (asset, entry) in deployments {
            actions.push(SwarmAction::RequestResponse {
                hunt_id: HuntId(deployment_hunt_id(&asset)),
                action: ResponseAction::DeployDecoy {
                    decoy_type: entry.decoy_type.clone(),
                    target_zone: entry.target_zone.clone(),
                },
                evidence: deployment_evidence(&asset, &entry, env),
            });
            let persisted = self.persist_inventory_deposit(env, &asset, &entry).await?;
            actions.push(SwarmAction::DepositPheromone {
                threat_class: threat_class_name(&persisted.threat_class),
                severity: persisted.severity,
                indicator: persisted.indicator,
                confidence: persisted.confidence,
            });
            if let Some(stored) = self.asset_mut(&asset.asset_id) {
                stored.deploy_requested_at_ms = Some(now_ms);
                stored.last_observed_at_ms = now_ms;
                changed = true;
            }
        }
        Ok((actions, changed))
    }

    async fn interaction_actions(
        &mut self,
        env: &SwarmEnvironment,
        now_ms: i64,
    ) -> Result<(Vec<SwarmAction>, bool), SwarmError> {
        let mut actions = Vec::new();
        let mut changed = false;
        for entry in self.playbook.entries.clone() {
            let Some(asset) = self.active_asset_for_entry(&entry.name) else {
                continue;
            };
            for deposit in &env.pheromones {
                if matches!(deposit.agent_role, Some(AgentRole::Calico)) {
                    continue;
                }
                let Some(interaction) =
                    match_monitoring_rule(&entry.monitoring, &deposit.indicator)
                else {
                    continue;
                };

                let observation_key = handled_observation_key(&asset, deposit, &interaction);
                if !self.lifecycle.handled_observations.insert(observation_key) {
                    continue;
                }

                let persisted = self
                    .persist_interaction_deposit(env, deposit, &entry, &asset, &interaction)
                    .await?;
                actions.push(SwarmAction::DepositPheromone {
                    threat_class: threat_class_name(&persisted.threat_class),
                    severity: persisted.severity,
                    indicator: persisted.indicator,
                    confidence: persisted.confidence,
                });
                if let Some(stored) = self.asset_mut(&asset.asset_id) {
                    stored.last_interaction_at_ms = Some(now_ms);
                    stored.last_observed_at_ms = now_ms;
                    stored.interaction_count += 1;
                }
                changed = true;
            }
        }
        Ok((actions, changed))
    }

    async fn persist_inventory_deposit(
        &mut self,
        env: &SwarmEnvironment,
        asset: &CalicoLifecycleAsset,
        entry: &DeceptionPlaybookEntry,
    ) -> Result<PheromoneDeposit, SwarmError> {
        let policy = self.pheromone_config.resolve_threat_class_policy(None);
        let payload = CalicoDeceptionInventoryPayload {
            schema: CALICO_DECEPTION_INVENTORY_SCHEMA.to_string(),
            schema_version: CALICO_LIFECYCLE_SCHEMA_VERSION,
            asset_id: asset.asset_id.clone(),
            playbook_entry: asset.playbook_entry.clone(),
            generation: asset.generation,
            lifecycle_stage: asset.lifecycle_stage,
            decoy_type: asset.decoy_type.clone(),
            target_zone: asset.target_zone.clone(),
            host_profile: asset.host_profile.clone(),
            placement_strategy: asset.placement_strategy.clone(),
            deployed_at_ms: asset.deployed_at_ms,
            monitoring: monitoring_payload(&entry.monitoring),
        };
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::to_value(payload).map_err(internal_error)?,
            threat_class: ThreatClass::Custom(CALICO_DECEPTION_INVENTORY_THREAT_CLASS.to_string()),
            severity: Severity::Low,
            confidence: 1.0,
            timestamp: env.now,
            decay_half_life: policy.half_life_secs,
            agent_id: self.id.clone(),
            agent_identity: AgentId::from_verifying_key(&self.verifying_key).0,
            agent_role: Some(AgentRole::Calico),
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        sign_deposit(&mut deposit, &self.signing_key)?;
        self.substrate
            .deposit(deposit.clone())
            .await
            .map_err(internal_error)?;
        Ok(deposit)
    }

    async fn persist_interaction_deposit(
        &mut self,
        env: &SwarmEnvironment,
        source_deposit: &PheromoneDeposit,
        entry: &DeceptionPlaybookEntry,
        asset: &CalicoLifecycleAsset,
        interaction: &DeceptionMatch,
    ) -> Result<PheromoneDeposit, SwarmError> {
        let threat_class_config = self
            .substrate
            .query_threat_class_config(&entry.monitoring.threat_class)
            .await
            .map_err(internal_error)?;
        let policy = self
            .pheromone_config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        let payload = CalicoDeceptionInteractionPayload {
            schema: CALICO_DECEPTION_INTERACTION_SCHEMA.to_string(),
            schema_version: CALICO_LIFECYCLE_SCHEMA_VERSION,
            asset_id: asset.asset_id.clone(),
            playbook_entry: asset.playbook_entry.clone(),
            generation: asset.generation,
            lifecycle_stage: asset.lifecycle_stage,
            decoy_type: asset.decoy_type.clone(),
            target_zone: asset.target_zone.clone(),
            host_profile: asset.host_profile.clone(),
            placement_strategy: asset.placement_strategy.clone(),
            interaction_signal: interaction.signal.to_string(),
            matched_value: interaction.matched_value.clone(),
            source_event_id: indicator_string_field(&source_deposit.indicator, "event_id"),
            source_hunt_id: indicator_string_field(&source_deposit.indicator, "hunt_id"),
            source_agent_id: source_deposit.agent_id.to_string(),
            source_indicator: source_deposit.indicator.clone(),
        };
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::to_value(payload).map_err(internal_error)?,
            threat_class: entry.monitoring.threat_class.clone(),
            severity: entry.monitoring.severity,
            confidence: entry.monitoring.confidence,
            timestamp: env.now,
            decay_half_life: policy.half_life_secs,
            agent_id: self.id.clone(),
            agent_identity: AgentId::from_verifying_key(&self.verifying_key).0,
            agent_role: Some(AgentRole::Calico),
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        sign_deposit(&mut deposit, &self.signing_key)?;
        self.substrate
            .deposit(deposit.clone())
            .await
            .map_err(internal_error)?;
        Ok(deposit)
    }

    fn active_asset_for_entry(&self, entry_name: &str) -> Option<CalicoLifecycleAsset> {
        self.lifecycle
            .assets
            .iter()
            .filter(|asset| {
                asset.playbook_entry == entry_name
                    && matches!(
                        asset.lifecycle_stage,
                        CalicoLifecycleStage::Deploy | CalicoLifecycleStage::Monitor
                    )
            })
            .max_by_key(|asset| asset.generation)
            .cloned()
    }

    fn monitor_asset_index(&self, entry_name: &str) -> Option<usize> {
        self.lifecycle
            .assets
            .iter()
            .enumerate()
            .filter(|(_, asset)| {
                asset.playbook_entry == entry_name
                    && asset.lifecycle_stage == CalicoLifecycleStage::Monitor
            })
            .max_by_key(|(_, asset)| asset.generation)
            .map(|(index, _)| index)
    }

    fn next_generation(&self, entry_name: &str) -> usize {
        self.lifecycle
            .assets
            .iter()
            .filter(|asset| asset.playbook_entry == entry_name)
            .map(|asset| asset.generation)
            .max()
            .unwrap_or(0)
            + 1
    }

    fn asset_mut(&mut self, asset_id: &str) -> Option<&mut CalicoLifecycleAsset> {
        self.lifecycle
            .assets
            .iter_mut()
            .find(|asset| asset.asset_id == asset_id)
    }

    fn sort_lifecycle_assets(&mut self) {
        self.lifecycle.assets.sort_by(|left, right| {
            left.playbook_entry
                .cmp(&right.playbook_entry)
                .then(left.generation.cmp(&right.generation))
        });
    }

    fn persist_lifecycle(&mut self, now_ms: i64) -> Result<(), SwarmError> {
        self.sort_lifecycle_assets();
        self.lifecycle.updated_at_ms = now_ms;
        self.lifecycle_store
            .persist(&self.lifecycle)
            .map_err(|error| internal_error(std::io::Error::other(error)))
    }
}

#[async_trait]
impl SwarmAgent for CalicoAgent {
    fn identity(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        self.role
    }

    fn observe_event(&mut self, event: &SwarmEvent) -> Result<(), SwarmError> {
        match event {
            SwarmEvent::RoleShift {
                agent_id, new_role, ..
            } if agent_id == &self.id => {
                self.role = *new_role;
            }
            _ => {}
        }
        Ok(())
    }

    async fn tick(&mut self, env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        let now_ms = env.now.saturating_mul(1000);
        let mut changed = self.reconcile_lifecycle(now_ms);
        let (mut actions, deployment_changed) = self.deployment_actions(env, now_ms).await?;
        changed |= deployment_changed;
        let (mut interaction_actions, interaction_changed) =
            self.interaction_actions(env, now_ms).await?;
        changed |= interaction_changed;
        actions.append(&mut interaction_actions);
        if changed {
            self.persist_lifecycle(now_ms)?;
        }
        self.health = AgentHealth::Healthy;
        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

pub(crate) fn parse_calico_deception_inventory(
    indicator: &Value,
) -> Option<CalicoDeceptionInventoryPayload> {
    let payload =
        serde_json::from_value::<CalicoDeceptionInventoryPayload>(indicator.clone()).ok()?;
    (payload.schema == CALICO_DECEPTION_INVENTORY_SCHEMA
        && payload.schema_version == CALICO_LIFECYCLE_SCHEMA_VERSION)
        .then_some(payload)
}

pub(crate) fn parse_calico_deception_interaction(
    indicator: &Value,
) -> Option<CalicoDeceptionInteractionPayload> {
    let payload =
        serde_json::from_value::<CalicoDeceptionInteractionPayload>(indicator.clone()).ok()?;
    (payload.schema == CALICO_DECEPTION_INTERACTION_SCHEMA
        && payload.schema_version == CALICO_LIFECYCLE_SCHEMA_VERSION)
        .then_some(payload)
}

fn deployment_hunt_id(asset: &CalicoLifecycleAsset) -> String {
    format!(
        "calico:deploy:{}:g{}",
        asset.playbook_entry, asset.generation
    )
}

fn deployment_evidence(
    asset: &CalicoLifecycleAsset,
    entry: &DeceptionPlaybookEntry,
    env: &SwarmEnvironment,
) -> Value {
    json!({
        "lineage": {
            "hunt_id": deployment_hunt_id(asset),
            "source": "calico_playbook",
            "asset_id": asset.asset_id,
            "generation": asset.generation,
        },
        "escalation": {
            "mode": env.mode,
            "mode_transition_at": env.mode_transition_at(),
            "timestamp": env.now,
            "threat_class": entry.monitoring.threat_class,
            "severity": Severity::Medium,
            "confidence": 1.0,
        },
        "deception": {
            "playbook_entry": entry.name,
            "asset_id": asset.asset_id,
            "generation": asset.generation,
            "lifecycle_stage": asset.lifecycle_stage,
            "decoy_type": entry.decoy_type,
            "target_zone": entry.target_zone,
            "host_profile": entry.host_profile,
            "placement_strategy": placement_strategy_label(entry.placement_strategy),
            "monitoring": {
                "file_paths": entry.monitoring.file_paths,
                "honeypot_ports": entry.monitoring.honeypot_ports,
                "canary_credentials": entry.monitoring.canary_credentials,
            },
        },
    })
}

fn monitoring_payload(monitoring: &DeceptionMonitoringConfig) -> CalicoMonitoringPayload {
    CalicoMonitoringPayload {
        file_paths: monitoring.file_paths.clone(),
        honeypot_ports: monitoring.honeypot_ports.clone(),
        canary_credentials: monitoring.canary_credentials.clone(),
    }
}

fn handled_observation_key(
    asset: &CalicoLifecycleAsset,
    source_deposit: &PheromoneDeposit,
    interaction: &DeceptionMatch,
) -> String {
    let source_id = indicator_string_field(&source_deposit.indicator, "event_id")
        .or_else(|| indicator_string_field(&source_deposit.indicator, "hunt_id"))
        .unwrap_or_else(|| stable_value_fingerprint(&source_deposit.indicator));
    format!(
        "{}:{}:{}:{}",
        asset.asset_id, source_id, interaction.signal, interaction.matched_value
    )
}

fn match_monitoring_rule(
    monitoring: &DeceptionMonitoringConfig,
    indicator: &Value,
) -> Option<DeceptionMatch> {
    for path in &monitoring.file_paths {
        if json_contains_string_field(indicator, &["path", "file_path", "accessed_path"], path) {
            return Some(DeceptionMatch {
                signal: "file_path",
                matched_value: path.clone(),
            });
        }
    }
    for port in &monitoring.honeypot_ports {
        if json_contains_u64_field(
            indicator,
            &["destination_port", "port", "target_port"],
            *port,
        ) {
            return Some(DeceptionMatch {
                signal: "honeypot_port",
                matched_value: port.to_string(),
            });
        }
    }
    for credential in &monitoring.canary_credentials {
        if json_contains_string_field(
            indicator,
            &["credential_id", "credential", "username"],
            credential,
        ) {
            return Some(DeceptionMatch {
                signal: "canary_credential",
                matched_value: credential.clone(),
            });
        }
    }
    None
}

fn json_contains_string_field(indicator: &Value, fields: &[&str], needle: &str) -> bool {
    fields.iter().any(|field| {
        let mut values = Vec::new();
        collect_named_values(indicator, field, &mut values);
        values
            .into_iter()
            .any(|value| value_contains_string(value, needle))
    })
}

fn json_contains_u64_field(indicator: &Value, fields: &[&str], needle: u16) -> bool {
    let needle = u64::from(needle);
    fields.iter().any(|field| {
        let mut values = Vec::new();
        collect_named_values(indicator, field, &mut values);
        values
            .into_iter()
            .any(|value| value_contains_u64(value, needle))
    })
}

fn collect_named_values<'a>(value: &'a Value, field: &str, output: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if let Some(candidate) = map.get(field) {
                output.push(candidate);
            }
            for child in map.values() {
                collect_named_values(child, field, output);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_named_values(child, field, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn value_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(candidate) => candidate.trim() == needle.trim(),
        Value::Array(values) => values
            .iter()
            .any(|candidate| value_contains_string(candidate, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
    }
}

fn value_contains_u64(value: &Value, needle: u64) -> bool {
    match value {
        Value::Number(number) => number.as_u64() == Some(needle),
        Value::String(candidate) => candidate.trim().parse::<u64>().ok() == Some(needle),
        Value::Array(values) => values
            .iter()
            .any(|candidate| value_contains_u64(candidate, needle)),
        Value::Null | Value::Bool(_) | Value::Object(_) => false,
    }
}

fn indicator_string_field(indicator: &Value, field: &str) -> Option<String> {
    let mut values = Vec::new();
    collect_named_values(indicator, field, &mut values);
    values.into_iter().find_map(|value| match value {
        Value::String(candidate) if !candidate.trim().is_empty() => Some(candidate.clone()),
        _ => None,
    })
}

fn stable_value_fingerprint(value: &Value) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "null".to_string());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    encoded.hash(&mut hasher);
    format!("hash:{:016x}", hasher.finish())
}

fn placement_strategy_label(strategy: DeceptionPlacementStrategy) -> &'static str {
    match strategy {
        DeceptionPlacementStrategy::Baseline => "baseline",
        DeceptionPlacementStrategy::HighValuePath => "high_value_path",
        DeceptionPlacementStrategy::NetworkSegment => "network_segment",
        DeceptionPlacementStrategy::InvestigationZone => "investigation_zone",
    }
}

fn threat_class_name(threat_class: &ThreatClass) -> String {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement".to_string(),
        ThreatClass::DataExfiltration => "data_exfiltration".to_string(),
        ThreatClass::PrivilegeEscalation => "privilege_escalation".to_string(),
        ThreatClass::CommandAndControl => "command_and_control".to_string(),
        ThreatClass::InitialAccess => "initial_access".to_string(),
        ThreatClass::Persistence => "persistence".to_string(),
        ThreatClass::SupplyChain => "supply_chain".to_string(),
        ThreatClass::DefenseEvasion => "defense_evasion".to_string(),
        ThreatClass::CredentialAccess => "credential_access".to_string(),
        ThreatClass::Discovery => "discovery".to_string(),
        ThreatClass::Execution => "execution".to_string(),
        ThreatClass::Impact => "impact".to_string(),
        ThreatClass::Custom(value) => value.clone(),
    }
}

fn resolve_deception_root(config_path: &Path, deception: &DeceptionConfig) -> PathBuf {
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let root = Path::new(&deception.lifecycle_results_dir);
    if root.is_absolute() {
        root.to_path_buf()
    } else {
        base.join(root)
    }
}

fn sanitize_id(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else {
            sanitized.push('_');
        }
    }
    while sanitized.contains("__") {
        sanitized = sanitized.replace("__", "_");
    }
    sanitized.trim_matches('_').to_string()
}

fn sign_deposit(
    deposit: &mut PheromoneDeposit,
    signing_key: &SigningKey,
) -> Result<(), SwarmError> {
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
    let payload_bytes = serde_json::to_vec(&payload).map_err(internal_error)?;
    let sig = signing_key.sign(&payload_bytes);
    deposit.signature = sig.to_bytes().to_vec();
    deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
    Ok(())
}

fn internal_error(error: impl std::error::Error) -> SwarmError {
    SwarmError::Internal(std::io::Error::other(error.to_string()).into())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        CALICO_DECEPTION_INVENTORY_THREAT_CLASS, CalicoAgent, CalicoLifecycleStage,
        FileCalicoLifecycleStore, parse_calico_deception_interaction,
        parse_calico_deception_inventory,
    };
    use crate::config::load_config;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::{AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmMode};
    use swarm_core::config::{
        DeceptionMonitoringConfig, DeceptionPlacementStrategy, DeceptionPlaybookConfig,
        DeceptionPlaybookEntry,
    };
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{AgentId, Severity, SwarmAction};
    use swarm_pheromone::{ConfiguredPheromoneSubstrate, PheromoneSubstrate};

    fn temp_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-calico-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn config_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../rulesets/default.yaml")
            .canonicalize()
            .unwrap()
    }

    fn playbook() -> DeceptionPlaybookConfig {
        DeceptionPlaybookConfig {
            entries: vec![
                DeceptionPlaybookEntry {
                    name: "finance-canary".to_string(),
                    decoy_type: "canary_token".to_string(),
                    target_zone: "finance".to_string(),
                    host_profile: "linux-app".to_string(),
                    placement_strategy: DeceptionPlacementStrategy::HighValuePath,
                    monitoring: DeceptionMonitoringConfig {
                        file_paths: vec!["/srv/data/finance/payroll.xlsx".to_string()],
                        honeypot_ports: Vec::new(),
                        canary_credentials: Vec::new(),
                        threat_class: ThreatClass::InitialAccess,
                        severity: Severity::High,
                        confidence: 0.99,
                    },
                },
                DeceptionPlaybookEntry {
                    name: "dmz-honeypot".to_string(),
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                    host_profile: "ssh-bastion".to_string(),
                    placement_strategy: DeceptionPlacementStrategy::NetworkSegment,
                    monitoring: DeceptionMonitoringConfig {
                        file_paths: Vec::new(),
                        honeypot_ports: vec![2222],
                        canary_credentials: Vec::new(),
                        threat_class: ThreatClass::LateralMovement,
                        severity: Severity::High,
                        confidence: 0.99,
                    },
                },
            ],
        }
    }

    fn runtime_config(root: &Path) -> swarm_core::config::SwarmConfig {
        let mut config = load_config(config_path()).unwrap();
        config.deception.enabled = true;
        config.deception.playbook = playbook();
        config.deception.lifecycle_results_dir =
            root.join("deception-lifecycle").display().to_string();
        config.deception.rotation_interval_secs = 60;
        config.deception.cleanup_grace_secs = 30;
        config.deception.interaction_fitness_weight = 0.15;
        config
    }

    fn substrate(config: &swarm_core::config::SwarmConfig) -> ConfiguredPheromoneSubstrate {
        ConfiguredPheromoneSubstrate::from_config(&config.pheromone)
            .expect("test substrate should initialize")
    }

    fn env(now: i64, pheromones: Vec<PheromoneDeposit>) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones,
            mode: SwarmMode::Normal,
            mode_transition_at: None,
            now,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    fn source_deposit(indicator: serde_json::Value) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator,
            threat_class: ThreatClass::Discovery,
            severity: Severity::Medium,
            confidence: 0.8,
            timestamp: 1_699_999_950,
            decay_half_life: 3600.0,
            agent_id: AgentId::new("whisker", "primary"),
            agent_identity: "swarm:ed25519:source".to_string(),
            agent_role: Some(AgentRole::Whisker),
            signature: vec![1; 64],
            agent_key: vec![2; 32],
        }
    }

    fn lifecycle_store(root: &Path) -> FileCalicoLifecycleStore {
        FileCalicoLifecycleStore::open(root.join("deception-lifecycle")).unwrap()
    }

    #[tokio::test]
    async fn calico_agent_reports_role_and_health() {
        let root = temp_root("role");
        let config = runtime_config(&root);
        let signing_key = SigningKey::generate(&mut OsRng);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let agent = CalicoAgent::new_with_signing_key(
            agent_id.clone(),
            signing_key,
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .unwrap();

        assert_eq!(agent.role(), AgentRole::Calico);
        assert_eq!(agent.health(), AgentHealth::Healthy);
        assert_eq!(agent.id(), &agent_id);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn calico_agent_bootstraps_deploy_requests_once_per_playbook_entry() {
        let root = temp_root("bootstrap");
        let config = runtime_config(&root);
        let signing_key = SigningKey::generate(&mut OsRng);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let mut agent = CalicoAgent::new_with_signing_key(
            agent_id,
            signing_key,
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .unwrap();

        let first_tick = agent.tick(&env(1_700_000_000, Vec::new())).await.unwrap();
        let deploy_count = first_tick
            .iter()
            .filter(|action| matches!(action, SwarmAction::RequestResponse { .. }))
            .count();
        assert_eq!(deploy_count, 2);
        assert_eq!(
            first_tick
                .iter()
                .filter(|action| matches!(action, SwarmAction::DepositPheromone { .. }))
                .count(),
            2
        );

        let second_tick = agent.tick(&env(1_700_000_001, Vec::new())).await.unwrap();
        assert!(second_tick.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn calico_agent_deposits_high_confidence_finding_for_monitored_file_path() {
        let root = temp_root("file-hit");
        let config = runtime_config(&root);
        let substrate = substrate(&config);
        let signing_key = SigningKey::generate(&mut OsRng);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let mut agent = CalicoAgent::new_with_signing_key(
            agent_id.clone(),
            signing_key,
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .unwrap();

        agent.tick(&env(1_700_000_000, Vec::new())).await.unwrap();
        agent.tick(&env(1_700_000_001, Vec::new())).await.unwrap();

        let actions = agent
            .tick(&env(
                1_700_000_002,
                vec![source_deposit(serde_json::json!({
                    "event_id": "evt-file-1",
                    "evidence": {
                        "path": "/srv/data/finance/payroll.xlsx"
                    }
                }))],
            ))
            .await
            .unwrap();

        let deposit_action = actions
            .iter()
            .find_map(|action| match action {
                SwarmAction::DepositPheromone {
                    threat_class,
                    severity,
                    confidence,
                    indicator,
                } => Some((
                    threat_class.clone(),
                    *severity,
                    *confidence,
                    indicator.clone(),
                )),
                _ => None,
            })
            .expect("calico should emit a pheromone action");
        assert_eq!(deposit_action.0, "initial_access");
        assert_eq!(deposit_action.1, Severity::High);
        assert!(deposit_action.2 >= 0.95);
        let payload = parse_calico_deception_interaction(&deposit_action.3)
            .expect("interaction payload should decode");
        assert_eq!(payload.playbook_entry, "finance-canary");
        assert_eq!(payload.asset_id, "calico:finance_canary:1");

        let persisted = substrate.recent_deposits(10).await.unwrap();
        let calico_deposit = persisted
            .iter()
            .find(|deposit| {
                deposit.agent_role == Some(AgentRole::Calico)
                    && deposit.threat_class == ThreatClass::InitialAccess
            })
            .expect("calico deposit should persist");
        assert_eq!(calico_deposit.agent_id, agent_id);
        assert_eq!(calico_deposit.threat_class, ThreatClass::InitialAccess);
        assert!(calico_deposit.confidence >= 0.95);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn calico_agent_uses_lateral_movement_for_honeypot_port_hits() {
        let root = temp_root("port-hit");
        let config = runtime_config(&root);
        let substrate = substrate(&config);
        let signing_key = SigningKey::generate(&mut OsRng);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let mut agent = CalicoAgent::new_with_signing_key(
            agent_id,
            signing_key,
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .unwrap();

        agent.tick(&env(1_700_000_000, Vec::new())).await.unwrap();
        agent.tick(&env(1_700_000_001, Vec::new())).await.unwrap();

        let actions = agent
            .tick(&env(
                1_700_000_002,
                vec![source_deposit(serde_json::json!({
                    "event_id": "evt-net-1",
                    "evidence": {
                        "destination_port": 2222
                    }
                }))],
            ))
            .await
            .unwrap();

        assert!(actions.iter().any(|action| matches!(
            action,
            SwarmAction::DepositPheromone { threat_class, confidence, .. }
                if threat_class == "lateral_movement" && *confidence >= 0.95
        )));

        let persisted = substrate.recent_deposits(10).await.unwrap();
        assert!(persisted.iter().any(|deposit| {
            deposit.agent_role == Some(AgentRole::Calico)
                && deposit.threat_class == ThreatClass::LateralMovement
        }));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn lifecycle_persists_and_rotates_after_restart() {
        let root = temp_root("lifecycle-rotate");
        let config = runtime_config(&root);
        let substrate = substrate(&config);
        let signing_key = SigningKey::generate(&mut OsRng);
        let signing_key_bytes = signing_key.to_bytes();
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let mut agent = CalicoAgent::new_with_signing_key(
            agent_id.clone(),
            signing_key,
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .unwrap();

        let first_tick = agent.tick(&env(1_700_000_000, Vec::new())).await.unwrap();
        assert_eq!(
            first_tick
                .iter()
                .filter(|action| matches!(action, SwarmAction::RequestResponse { .. }))
                .count(),
            2
        );
        let snapshot = lifecycle_store(&root).load().unwrap().unwrap();
        assert_eq!(snapshot.assets.len(), 2);
        assert!(
            snapshot
                .assets
                .iter()
                .all(|asset| asset.lifecycle_stage == CalicoLifecycleStage::Deploy)
        );
        assert!(
            snapshot
                .assets
                .iter()
                .all(|asset| asset.deploy_requested_at_ms.is_some())
        );

        let restarted_signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let mut restarted = CalicoAgent::new_with_signing_key(
            agent_id,
            restarted_signing_key,
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .unwrap();
        let second_tick = restarted
            .tick(&env(1_700_000_001, Vec::new()))
            .await
            .unwrap();
        assert!(second_tick.is_empty());
        let snapshot = lifecycle_store(&root).load().unwrap().unwrap();
        assert!(
            snapshot
                .assets
                .iter()
                .all(|asset| asset.lifecycle_stage == CalicoLifecycleStage::Monitor)
        );

        let rotate_tick = restarted
            .tick(&env(1_700_000_061, Vec::new()))
            .await
            .unwrap();
        assert_eq!(
            rotate_tick
                .iter()
                .filter(|action| matches!(action, SwarmAction::RequestResponse { .. }))
                .count(),
            2
        );
        let snapshot = lifecycle_store(&root).load().unwrap().unwrap();
        assert_eq!(snapshot.assets.len(), 4);
        assert_eq!(
            snapshot
                .assets
                .iter()
                .filter(|asset| asset.lifecycle_stage == CalicoLifecycleStage::Rotate)
                .count(),
            2
        );
        assert_eq!(
            snapshot
                .assets
                .iter()
                .filter(|asset| asset.lifecycle_stage == CalicoLifecycleStage::Deploy)
                .count(),
            2
        );

        restarted
            .tick(&env(1_700_000_092, Vec::new()))
            .await
            .unwrap();
        let snapshot = lifecycle_store(&root).load().unwrap().unwrap();
        assert_eq!(
            snapshot
                .assets
                .iter()
                .filter(|asset| asset.lifecycle_stage == CalicoLifecycleStage::Cleanup)
                .count(),
            2
        );
        assert_eq!(
            snapshot
                .assets
                .iter()
                .filter(|asset| asset.lifecycle_stage == CalicoLifecycleStage::Monitor)
                .count(),
            2
        );

        let persisted = substrate.recent_deposits(10).await.unwrap();
        assert!(persisted.iter().any(|deposit| {
            deposit.agent_role == Some(AgentRole::Calico)
                && deposit.threat_class
                    == ThreatClass::Custom(CALICO_DECEPTION_INVENTORY_THREAT_CLASS.to_string())
        }));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn lifecycle_interaction_updates_persisted_asset_metadata() {
        let root = temp_root("lifecycle-interaction");
        let config = runtime_config(&root);
        let substrate = substrate(&config);
        let signing_key = SigningKey::generate(&mut OsRng);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let mut agent = CalicoAgent::new_with_signing_key(
            agent_id,
            signing_key,
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .unwrap();

        agent.tick(&env(1_700_000_000, Vec::new())).await.unwrap();
        agent.tick(&env(1_700_000_001, Vec::new())).await.unwrap();
        agent
            .tick(&env(
                1_700_000_002,
                vec![source_deposit(serde_json::json!({
                    "event_id": "evt-file-1",
                    "path": "/srv/data/finance/payroll.xlsx"
                }))],
            ))
            .await
            .unwrap();

        let snapshot = lifecycle_store(&root).load().unwrap().unwrap();
        let finance_asset = snapshot
            .assets
            .iter()
            .find(|asset| asset.playbook_entry == "finance-canary" && asset.generation == 1)
            .expect("finance asset should persist");
        assert_eq!(finance_asset.interaction_count, 1);
        assert_eq!(
            finance_asset.last_interaction_at_ms,
            Some(1_700_000_002_000)
        );

        let persisted = substrate.recent_deposits(10).await.unwrap();
        let inventory = persisted
            .iter()
            .filter_map(|deposit| parse_calico_deception_inventory(&deposit.indicator))
            .find(|payload| payload.playbook_entry == "finance-canary")
            .expect("inventory payload should persist");
        assert_eq!(inventory.playbook_entry, "finance-canary");
        let interaction = persisted
            .iter()
            .filter_map(|deposit| parse_calico_deception_interaction(&deposit.indicator))
            .find(|payload| payload.playbook_entry == "finance-canary")
            .expect("interaction payload should persist");
        assert_eq!(interaction.asset_id, inventory.asset_id);
        assert_eq!(interaction.playbook_entry, "finance-canary");

        let _ = fs::remove_dir_all(root);
    }
}
