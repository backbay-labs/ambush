use crate::calico_agent::{
    CalicoDeceptionInteractionPayload, CalicoDeceptionInventoryPayload,
    parse_calico_deception_interaction, parse_calico_deception_inventory,
};
use crate::strategy::RECENCY_HALF_LIFE_HOURS;
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use swarm_core::agent::{
    AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
};
use swarm_core::config::{MemoryConfig, SwarmConfig};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::types::{
    AgentId, ProvidenceFeedbackAction, SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
    SPHINX_MEMORY_THREAT_CLASS, SWARM_PROVIDENCE_FEEDBACK_SCHEMA, Severity, SphinxMemoryAnswer,
    SphinxMemoryContribution, SphinxMemoryPayloadKind, SphinxMemoryQuery, SwarmAction,
};
use swarm_crypto::sha256_hex;
use swarm_pheromone::{
    ConfiguredPheromoneSubstrate, DepositSigningPayload, PheromoneSubstrate, SubstrateError,
};

use crate::AgentTickBoundaryError;

const KNOWLEDGE_GRAPH_SCHEMA_VERSION: u32 = 1;

pub struct SphinxAgent {
    id: AgentId,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    substrate: ConfiguredPheromoneSubstrate,
    pheromone_config: swarm_core::config::PheromoneConfig,
    knowledge_retention_days: u64,
    role: AgentRole,
    health: AgentHealth,
    store: FileKnowledgeGraphStore,
    graph: KnowledgeGraphSnapshot,
    answered_query_ids: BTreeSet<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SphinxAgentTickError {
    #[error(transparent)]
    Store(#[from] KnowledgeGraphStoreError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error(transparent)]
    Substrate(#[from] SubstrateError),
}

impl SphinxAgentTickError {
    pub fn boundary(&self) -> &'static str {
        match self {
            Self::Store(_) => "knowledge_graph_store",
            Self::Serialization(_) => "serialization",
            Self::Substrate(_) => "substrate",
        }
    }
}

impl SphinxAgent {
    pub fn new(
        id: AgentId,
        config_path: impl Into<PathBuf>,
        runtime_config: SwarmConfig,
        substrate: ConfiguredPheromoneSubstrate,
    ) -> Result<Self, KnowledgeGraphStoreError> {
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
    ) -> Result<Self, KnowledgeGraphStoreError> {
        let config_path = config_path.into();
        let memory_root = resolve_memory_root(&config_path, &runtime_config.memory);
        let store = FileKnowledgeGraphStore::open(memory_root)?;
        let mut graph = store.load_snapshot()?.unwrap_or_else(|| {
            KnowledgeGraphSnapshot::new(runtime_config.memory.temporal_window_secs)
        });
        graph.temporal_window_secs = runtime_config.memory.temporal_window_secs;
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            id,
            signing_key,
            verifying_key,
            substrate,
            pheromone_config: runtime_config.pheromone.clone(),
            knowledge_retention_days: runtime_config.memory.knowledge_retention_days,
            role: AgentRole::Sphinx,
            health: AgentHealth::Healthy,
            store,
            graph,
            answered_query_ids: BTreeSet::new(),
        })
    }

    fn ingest_pheromone(
        &mut self,
        deposit: &PheromoneDeposit,
    ) -> Result<bool, KnowledgeGraphStoreError> {
        let observation_id = observation_id(deposit)?;
        if self
            .graph
            .processed_observation_ids
            .contains(&observation_id)
        {
            return Ok(false);
        }

        let observed_at_ms = observation_timestamp_ms(deposit);
        let threat_pattern_id = format!(
            "threat_pattern:{}",
            sanitize_id(&threat_class_key(&deposit.threat_class))
        );
        let techniques = extract_attack_techniques(deposit);
        let technique_ids = techniques
            .iter()
            .map(|technique| technique_node_id(&technique.technique_id))
            .collect::<BTreeSet<_>>();
        let entities = extract_entities(&deposit.indicator);
        let entity_ids = entities
            .iter()
            .map(|entity| entity_node_id(entity.kind, &entity.value))
            .collect::<BTreeSet<_>>();
        let engagement_id = format!("engagement:{}", sanitize_id(&observation_id));

        self.graph
            .upsert_node(KnowledgeGraphNode::ThreatPattern(ThreatPatternNode {
                node_id: threat_pattern_id.clone(),
                threat_class: threat_class_key(&deposit.threat_class),
                title: format!(
                    "{} threat pattern",
                    threat_class_label(&deposit.threat_class)
                ),
                first_observed_at_ms: observed_at_ms,
                last_observed_at_ms: observed_at_ms,
                observation_count: 1,
                latest_severity: deposit.severity,
                attack_technique_ids: technique_ids.clone(),
                kill_chain_stages: techniques
                    .iter()
                    .map(|technique| technique.kill_chain_stage.clone())
                    .collect(),
            }));

        for technique in &techniques {
            let node_id = technique_node_id(&technique.technique_id);
            self.graph
                .upsert_node(KnowledgeGraphNode::AttackTechnique(AttackTechniqueNode {
                    node_id: node_id.clone(),
                    technique_id: technique.technique_id.clone(),
                    name: technique.name.clone(),
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    observation_count: 1,
                }));
            self.graph
                .upsert_edge(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!(
                        "semantic:{}:{}",
                        sanitize_id(&threat_pattern_id),
                        sanitize_id(&node_id)
                    ),
                    from_node_id: threat_pattern_id.clone(),
                    to_node_id: node_id.clone(),
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    occurrence_count: 1,
                }));
            self.graph
                .upsert_edge(KnowledgeGraphEdge::Semantic(SemanticEdge {
                    edge_id: format!(
                        "semantic:{}:{}",
                        sanitize_id(&engagement_id),
                        sanitize_id(&node_id)
                    ),
                    from_node_id: engagement_id.clone(),
                    to_node_id: node_id,
                    relation: SemanticRelation::KillChainStage,
                    kill_chain_stage: technique.kill_chain_stage.clone(),
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    occurrence_count: 1,
                }));
        }

        let mut parent_process_node_id = None;
        let mut process_node_id = None;
        let mut source_ip_node_id = None;
        let mut destination_ip_node_id = None;

        for entity in &entities {
            let node_id = entity_node_id(entity.kind, &entity.value);
            self.graph
                .upsert_node(KnowledgeGraphNode::Entity(EntityNode {
                    node_id: node_id.clone(),
                    entity_kind: entity.kind,
                    value: entity.value.clone(),
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    observation_count: 1,
                }));
            self.graph
                .upsert_edge(KnowledgeGraphEdge::Entity(EntityEdge {
                    edge_id: format!(
                        "entity:{}:{}:{}",
                        sanitize_id(&engagement_id),
                        sanitize_id(&node_id),
                        sanitize_id(&entity.role)
                    ),
                    from_node_id: engagement_id.clone(),
                    to_node_id: node_id.clone(),
                    role: entity.role.clone(),
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    occurrence_count: 1,
                }));

            match entity.role.as_str() {
                "parent_process" => parent_process_node_id = Some(node_id),
                "process" => process_node_id = Some(node_id),
                "source_ip" => source_ip_node_id = Some(node_id),
                "destination_ip" => destination_ip_node_id = Some(node_id),
                _ => {}
            }
        }

        self.graph
            .upsert_node(KnowledgeGraphNode::Engagement(EngagementNode {
                node_id: engagement_id.clone(),
                observation_id: observation_id.clone(),
                source_agent_id: deposit.agent_id.to_string(),
                threat_class: threat_class_key(&deposit.threat_class),
                severity: deposit.severity,
                summary: observation_summary(deposit),
                observed_at_ms,
                related_entity_ids: entity_ids.clone(),
                attack_technique_ids: technique_ids,
                analyst_feedback_ids: BTreeSet::new(),
                analyst_disposition: None,
                analyst_note: None,
                analyst_feedback_at_ms: None,
                outcome_reward_override: None,
            }));

        if let (Some(parent), Some(process)) = (parent_process_node_id, process_node_id) {
            self.graph
                .upsert_edge(KnowledgeGraphEdge::Causal(CausalEdge {
                    edge_id: format!(
                        "causal:{}:{}:process_parent_child",
                        sanitize_id(&parent),
                        sanitize_id(&process)
                    ),
                    from_node_id: parent,
                    to_node_id: process,
                    relation: CausalRelation::ProcessParentChild,
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    occurrence_count: 1,
                }));
        }

        if let (Some(source), Some(destination)) = (source_ip_node_id, destination_ip_node_id) {
            self.graph
                .upsert_edge(KnowledgeGraphEdge::Causal(CausalEdge {
                    edge_id: format!(
                        "causal:{}:{}:network_flow_origin",
                        sanitize_id(&source),
                        sanitize_id(&destination)
                    ),
                    from_node_id: source,
                    to_node_id: destination,
                    relation: CausalRelation::NetworkFlowOrigin,
                    first_observed_at_ms: observed_at_ms,
                    last_observed_at_ms: observed_at_ms,
                    occurrence_count: 1,
                }));
        }

        for existing in self.graph.engagements() {
            if existing.node_id == engagement_id {
                continue;
            }
            let lower = existing.observed_at_ms.min(observed_at_ms);
            let upper = existing.observed_at_ms.max(observed_at_ms);
            if (upper - lower) > (self.graph.temporal_window_secs as i64 * 1000) {
                continue;
            }
            let shared_entities = existing
                .related_entity_ids
                .intersection(&entity_ids)
                .cloned()
                .collect::<BTreeSet<_>>();
            if shared_entities.is_empty() {
                continue;
            }
            let (from_node_id, to_node_id) = if existing.observed_at_ms <= observed_at_ms {
                (existing.node_id.clone(), engagement_id.clone())
            } else {
                (engagement_id.clone(), existing.node_id.clone())
            };
            self.graph
                .upsert_edge(KnowledgeGraphEdge::Temporal(TemporalEdge {
                    edge_id: format!(
                        "temporal:{}:{}",
                        sanitize_id(&from_node_id),
                        sanitize_id(&to_node_id)
                    ),
                    from_node_id,
                    to_node_id,
                    temporal_window_secs: self.graph.temporal_window_secs,
                    shared_entity_ids: shared_entities,
                    first_observed_at_ms: lower,
                    last_observed_at_ms: upper,
                    occurrence_count: 1,
                }));
        }

        self.graph.processed_observation_ids.insert(observation_id);
        Ok(true)
    }

    fn ingest_providence_feedback(
        &mut self,
        deposit: &PheromoneDeposit,
        feedback: &ProvidenceFeedbackSignal,
    ) -> bool {
        if self
            .graph
            .processed_observation_ids
            .contains(&feedback.feedback_id)
        {
            return false;
        }

        let updated_existing = feedback
            .event_id
            .as_deref()
            .or(feedback.hunt_id.as_deref())
            .and_then(|observation_id| self.graph.engagement_mut_by_observation_id(observation_id))
            .map(|engagement| {
                engagement
                    .analyst_feedback_ids
                    .insert(feedback.feedback_id.clone());
                engagement.analyst_disposition = Some(feedback.action);
                engagement.analyst_note = feedback.note.clone();
                engagement.analyst_feedback_at_ms = Some(feedback.observed_at_ms);
                engagement.outcome_reward_override = Some(analyst_outcome_reward(feedback.action));
                engagement.observed_at_ms = engagement.observed_at_ms.max(feedback.observed_at_ms);
            })
            .is_some();

        if !updated_existing {
            self.graph
                .upsert_node(KnowledgeGraphNode::Engagement(EngagementNode {
                    node_id: format!("engagement:{}", sanitize_id(&feedback.feedback_id)),
                    observation_id: feedback.feedback_id.clone(),
                    source_agent_id: deposit.agent_id.to_string(),
                    threat_class: threat_class_key(&deposit.threat_class),
                    severity: deposit.severity,
                    summary: feedback
                        .note
                        .clone()
                        .unwrap_or_else(|| "analyst disposition feedback".to_string()),
                    observed_at_ms: feedback.observed_at_ms,
                    related_entity_ids: BTreeSet::new(),
                    attack_technique_ids: BTreeSet::new(),
                    analyst_feedback_ids: BTreeSet::from([feedback.feedback_id.clone()]),
                    analyst_disposition: Some(feedback.action),
                    analyst_note: feedback.note.clone(),
                    analyst_feedback_at_ms: Some(feedback.observed_at_ms),
                    outcome_reward_override: Some(analyst_outcome_reward(feedback.action)),
                }));
        }

        self.graph
            .processed_observation_ids
            .insert(feedback.feedback_id.clone());
        true
    }

    fn ingest_deception_inventory(
        &mut self,
        payload: &CalicoDeceptionInventoryPayload,
        observed_at_ms: i64,
    ) -> bool {
        let registration_observation_id =
            format!("deception_asset:{}", sanitize_id(&payload.asset_id));
        if self
            .graph
            .processed_observation_ids
            .contains(&registration_observation_id)
        {
            return false;
        }

        self.graph
            .upsert_node(KnowledgeGraphNode::DeceptionAsset(DeceptionAssetNode {
                node_id: deception_asset_node_id(&payload.asset_id),
                registration_observation_id: registration_observation_id.clone(),
                asset_id: payload.asset_id.clone(),
                playbook_entry: payload.playbook_entry.clone(),
                generation: payload.generation,
                decoy_type: payload.decoy_type.clone(),
                target_zone: payload.target_zone.clone(),
                host_profile: payload.host_profile.clone(),
                placement_strategy: payload.placement_strategy.clone(),
                lifecycle_stage: deception_lifecycle_stage_label(payload.lifecycle_stage),
                first_observed_at_ms: observed_at_ms,
                last_observed_at_ms: observed_at_ms,
                deployed_at_ms: payload.deployed_at_ms,
                interaction_count: 0,
                last_interaction_at_ms: None,
            }));
        self.graph
            .processed_observation_ids
            .insert(registration_observation_id);
        true
    }

    fn link_deception_interaction(
        &mut self,
        observation_id: &str,
        deposit: &PheromoneDeposit,
        payload: &CalicoDeceptionInteractionPayload,
    ) -> bool {
        let observed_at_ms = observation_timestamp_ms(deposit);
        let asset_node_id = deception_asset_node_id(&payload.asset_id);
        let engagement_id = format!("engagement:{}", sanitize_id(observation_id));

        self.graph
            .upsert_node(KnowledgeGraphNode::DeceptionAsset(DeceptionAssetNode {
                node_id: asset_node_id.clone(),
                registration_observation_id: format!(
                    "deception_asset:{}",
                    sanitize_id(&payload.asset_id)
                ),
                asset_id: payload.asset_id.clone(),
                playbook_entry: payload.playbook_entry.clone(),
                generation: payload.generation,
                decoy_type: payload.decoy_type.clone(),
                target_zone: payload.target_zone.clone(),
                host_profile: payload.host_profile.clone(),
                placement_strategy: payload.placement_strategy.clone(),
                lifecycle_stage: deception_lifecycle_stage_label(payload.lifecycle_stage),
                first_observed_at_ms: observed_at_ms,
                last_observed_at_ms: observed_at_ms,
                deployed_at_ms: observed_at_ms,
                interaction_count: 1,
                last_interaction_at_ms: Some(observed_at_ms),
            }));
        self.graph
            .upsert_edge(KnowledgeGraphEdge::Entity(EntityEdge {
                edge_id: format!(
                    "entity:{}:{}:deception_asset",
                    sanitize_id(&engagement_id),
                    sanitize_id(&asset_node_id)
                ),
                from_node_id: engagement_id,
                to_node_id: asset_node_id,
                role: "deception_asset".to_string(),
                first_observed_at_ms: observed_at_ms,
                last_observed_at_ms: observed_at_ms,
                occurrence_count: 1,
            }));
        true
    }

    fn answer_memory_query(&self, query: &SphinxMemoryQuery, now_ms: i64) -> SphinxMemoryAnswer {
        let all_contributions = self.matching_contributions(query, now_ms);
        let matching_engagement_count = all_contributions.len();
        let contributions = all_contributions.into_iter().take(3).collect::<Vec<_>>();
        let retrieval_score = if matching_engagement_count == 0 {
            0.0
        } else {
            contributions.iter().map(|entry| entry.q_value).sum::<f64>()
                / matching_engagement_count as f64
        };

        SphinxMemoryAnswer {
            schema_version: SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
            kind: SphinxMemoryPayloadKind::Answer,
            query_id: query.query_id.clone(),
            strategy_id: query.strategy_id.clone(),
            answered_by_agent_id: self.id.to_string(),
            answered_at_ms: now_ms,
            matching_engagement_count,
            retrieval_score,
            sparse: matching_engagement_count < 2,
            contributions,
        }
    }

    fn matching_contributions(
        &self,
        query: &SphinxMemoryQuery,
        now_ms: i64,
    ) -> Vec<SphinxMemoryContribution> {
        let requested_threats = query
            .threat_classes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let requested_techniques = query
            .attack_technique_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let requested_entities = query.entity_values.iter().cloned().collect::<BTreeSet<_>>();
        let mut contributions = Vec::new();

        for engagement in self.graph.engagements() {
            let threat_match = requested_threats.contains(&engagement.threat_class);
            let matched_technique_ids = engagement
                .attack_technique_ids
                .iter()
                .filter_map(|node_id| {
                    self.graph
                        .attack_technique_for_node(node_id)
                        .map(|node| node.technique_id)
                })
                .filter(|technique_id| requested_techniques.contains(technique_id))
                .collect::<Vec<_>>();
            let matched_entity_values = engagement
                .related_entity_ids
                .iter()
                .filter_map(|node_id| self.graph.entity_value_for_node(node_id))
                .filter(|value| requested_entities.contains(value))
                .collect::<Vec<_>>();

            if !threat_match && matched_technique_ids.is_empty() && matched_entity_values.is_empty()
            {
                continue;
            }

            let relevance = context_relevance(
                threat_match,
                requested_techniques.len(),
                matched_technique_ids.len(),
                requested_entities.len(),
                matched_entity_values.len(),
            );
            let outcome_reward = engagement
                .outcome_reward_override
                .unwrap_or_else(|| severity_reward(engagement.severity));
            let recency_decay = q_value_recency_decay(engagement.observed_at_ms, now_ms);
            let q_value = relevance * outcome_reward * recency_decay;
            contributions.push(SphinxMemoryContribution {
                engagement_id: engagement.node_id,
                threat_class: engagement.threat_class,
                observed_at_ms: engagement.observed_at_ms,
                matched_technique_ids,
                matched_entity_values,
                relevance,
                outcome_reward,
                recency_decay,
                q_value,
                analyst_disposition: engagement.analyst_disposition,
                analyst_note: engagement.analyst_note,
            });
        }

        contributions.sort_by(|left, right| right.q_value.total_cmp(&left.q_value));
        contributions
    }

    async fn deposit_memory_answer(
        &self,
        env_now: i64,
        answer: &SphinxMemoryAnswer,
    ) -> Result<(), SwarmError> {
        let indicator = serde_json::to_value(answer).map_err(internal_runtime_error)?;
        let policy = self.pheromone_config.resolve_threat_class_policy(None);
        let threat_class = ThreatClass::Custom(SPHINX_MEMORY_THREAT_CLASS.to_string());
        let derived_agent_id = AgentId::from_verifying_key(&self.verifying_key);
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator,
            threat_class,
            severity: Severity::Low,
            confidence: 0.0,
            timestamp: env_now,
            decay_half_life: policy.half_life_secs,
            agent_id: derived_agent_id.clone(),
            agent_identity: derived_agent_id.0,
            agent_role: Some(self.role),
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        let signing_payload = DepositSigningPayload {
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
        let payload_bytes = serde_json::to_vec(&signing_payload).map_err(internal_runtime_error)?;
        let signature = self.signing_key.sign(&payload_bytes);
        deposit.signature = signature.to_bytes().to_vec();
        deposit.agent_key = self.signing_key.verifying_key().to_bytes().to_vec();
        self.substrate
            .deposit(deposit)
            .await
            .map_err(internal_runtime_error)?;
        Ok(())
    }
}

#[async_trait]
impl SwarmAgent for SphinxAgent {
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
        let mut changed = false;
        let mut actions = Vec::new();
        for deposit in &env.pheromones {
            if let Some(query) = parse_memory_query(deposit) {
                if self.answered_query_ids.insert(query.query_id.clone()) {
                    let answer = self.answer_memory_query(&query, env.now.saturating_mul(1000));
                    self.deposit_memory_answer(env.now, &answer).await?;
                    actions.push(SwarmAction::DepositPheromone {
                        threat_class: SPHINX_MEMORY_THREAT_CLASS.to_string(),
                        severity: Severity::Low,
                        indicator: serde_json::to_value(&answer).map_err(internal_runtime_error)?,
                        confidence: 0.0,
                    });
                }
                continue;
            }
            if let Some(feedback) = parse_providence_feedback_signal(deposit) {
                changed |= self.ingest_providence_feedback(deposit, &feedback);
                continue;
            }
            if is_memory_answer(deposit) {
                continue;
            }
            if let Some(payload) = parse_calico_deception_inventory(&deposit.indicator) {
                let observed_at_ms = observation_timestamp_ms(deposit);
                changed |= self.ingest_deception_inventory(&payload, observed_at_ms);
                continue;
            }

            let interaction_payload = parse_calico_deception_interaction(&deposit.indicator);
            let is_new_observation = interaction_payload.as_ref().and_then(|_| {
                observation_id(deposit).ok().map(|observation_id| {
                    !self
                        .graph
                        .processed_observation_ids
                        .contains(&observation_id)
                })
            });
            changed |= self.ingest_pheromone(deposit).map_err(internal_error)?;
            if let (Some(payload), Some(true)) = (interaction_payload, is_new_observation) {
                let observation_id = observation_id(deposit).map_err(internal_error)?;
                changed |= self.link_deception_interaction(&observation_id, deposit, &payload);
            }
        }
        changed |= self
            .graph
            .prune_stale(env.now.saturating_mul(1000), self.knowledge_retention_days);
        if changed {
            self.graph.updated_at_ms = env.now.saturating_mul(1000);
            self.store
                .persist_snapshot(&self.graph)
                .map_err(internal_error)?;
        }
        self.health = AgentHealth::Healthy;
        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeNodeKind {
    ThreatPattern,
    AttackTechnique,
    Entity,
    Engagement,
    DeceptionAsset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeEdgeKind {
    Temporal,
    Causal,
    Entity,
    Semantic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Host,
    User,
    Process,
    IpAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRelation {
    ProcessParentChild,
    NetworkFlowOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelation {
    KillChainStage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatPatternNode {
    pub node_id: String,
    pub threat_class: String,
    pub title: String,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub observation_count: usize,
    pub latest_severity: Severity,
    pub attack_technique_ids: BTreeSet<String>,
    pub kill_chain_stages: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackTechniqueNode {
    pub node_id: String,
    pub technique_id: String,
    pub name: String,
    pub kill_chain_stage: String,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub observation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityNode {
    pub node_id: String,
    pub entity_kind: EntityKind,
    pub value: String,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub observation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngagementNode {
    pub node_id: String,
    pub observation_id: String,
    pub source_agent_id: String,
    pub threat_class: String,
    pub severity: Severity,
    pub summary: String,
    pub observed_at_ms: i64,
    pub related_entity_ids: BTreeSet<String>,
    pub attack_technique_ids: BTreeSet<String>,
    #[serde(default)]
    pub analyst_feedback_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst_disposition: Option<ProvidenceFeedbackAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst_feedback_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_reward_override: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeceptionAssetNode {
    pub node_id: String,
    pub registration_observation_id: String,
    pub asset_id: String,
    pub playbook_entry: String,
    pub generation: usize,
    pub decoy_type: String,
    pub target_zone: String,
    pub host_profile: String,
    pub placement_strategy: String,
    pub lifecycle_stage: String,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub deployed_at_ms: i64,
    pub interaction_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_interaction_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub temporal_window_secs: u64,
    pub shared_entity_ids: BTreeSet<String>,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub occurrence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: CausalRelation,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub occurrence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub role: String,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub occurrence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticEdge {
    pub edge_id: String,
    pub from_node_id: String,
    pub to_node_id: String,
    pub relation: SemanticRelation,
    pub kill_chain_stage: String,
    pub first_observed_at_ms: i64,
    pub last_observed_at_ms: i64,
    pub occurrence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnowledgeGraphNode {
    ThreatPattern(ThreatPatternNode),
    AttackTechnique(AttackTechniqueNode),
    Entity(EntityNode),
    Engagement(EngagementNode),
    DeceptionAsset(DeceptionAssetNode),
}

impl KnowledgeGraphNode {
    fn node_id(&self) -> &str {
        match self {
            Self::ThreatPattern(node) => &node.node_id,
            Self::AttackTechnique(node) => &node.node_id,
            Self::Entity(node) => &node.node_id,
            Self::Engagement(node) => &node.node_id,
            Self::DeceptionAsset(node) => &node.node_id,
        }
    }

    fn kind(&self) -> KnowledgeNodeKind {
        match self {
            Self::ThreatPattern(_) => KnowledgeNodeKind::ThreatPattern,
            Self::AttackTechnique(_) => KnowledgeNodeKind::AttackTechnique,
            Self::Entity(_) => KnowledgeNodeKind::Entity,
            Self::Engagement(_) => KnowledgeNodeKind::Engagement,
            Self::DeceptionAsset(_) => KnowledgeNodeKind::DeceptionAsset,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::ThreatPattern(node) => node.title.clone(),
            Self::AttackTechnique(node) => node.name.clone(),
            Self::Entity(node) => node.value.clone(),
            Self::Engagement(node) => node.summary.clone(),
            Self::DeceptionAsset(node) => node.playbook_entry.clone(),
        }
    }

    fn last_observed_at_ms(&self) -> i64 {
        match self {
            Self::ThreatPattern(node) => node.last_observed_at_ms,
            Self::AttackTechnique(node) => node.last_observed_at_ms,
            Self::Entity(node) => node.last_observed_at_ms,
            Self::Engagement(node) => node.observed_at_ms,
            Self::DeceptionAsset(node) => node.last_observed_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnowledgeGraphEdge {
    Temporal(TemporalEdge),
    Causal(CausalEdge),
    Entity(EntityEdge),
    Semantic(SemanticEdge),
}

impl KnowledgeGraphEdge {
    fn edge_id(&self) -> &str {
        match self {
            Self::Temporal(edge) => &edge.edge_id,
            Self::Causal(edge) => &edge.edge_id,
            Self::Entity(edge) => &edge.edge_id,
            Self::Semantic(edge) => &edge.edge_id,
        }
    }

    fn kind(&self) -> KnowledgeEdgeKind {
        match self {
            Self::Temporal(_) => KnowledgeEdgeKind::Temporal,
            Self::Causal(_) => KnowledgeEdgeKind::Causal,
            Self::Entity(_) => KnowledgeEdgeKind::Entity,
            Self::Semantic(_) => KnowledgeEdgeKind::Semantic,
        }
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_node_id(&self) -> &str {
        match self {
            Self::Temporal(edge) => &edge.from_node_id,
            Self::Causal(edge) => &edge.from_node_id,
            Self::Entity(edge) => &edge.from_node_id,
            Self::Semantic(edge) => &edge.from_node_id,
        }
    }

    fn to_node_id(&self) -> &str {
        match self {
            Self::Temporal(edge) => &edge.to_node_id,
            Self::Causal(edge) => &edge.to_node_id,
            Self::Entity(edge) => &edge.to_node_id,
            Self::Semantic(edge) => &edge.to_node_id,
        }
    }

    fn last_observed_at_ms(&self) -> i64 {
        match self {
            Self::Temporal(edge) => edge.last_observed_at_ms,
            Self::Causal(edge) => edge.last_observed_at_ms,
            Self::Entity(edge) => edge.last_observed_at_ms,
            Self::Semantic(edge) => edge.last_observed_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeGraphSnapshot {
    pub schema_version: u32,
    pub temporal_window_secs: u64,
    pub updated_at_ms: i64,
    pub processed_observation_ids: BTreeSet<String>,
    pub nodes: Vec<KnowledgeGraphNode>,
    pub edges: Vec<KnowledgeGraphEdge>,
}

impl KnowledgeGraphSnapshot {
    pub fn new(temporal_window_secs: u64) -> Self {
        Self {
            schema_version: KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            temporal_window_secs,
            updated_at_ms: 0,
            processed_observation_ids: BTreeSet::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn upsert_node(&mut self, node: KnowledgeGraphNode) {
        if let Some(existing) = self
            .nodes
            .iter_mut()
            .find(|existing| existing.node_id() == node.node_id())
        {
            merge_node(existing, node);
        } else {
            self.nodes.push(node);
        }
    }

    fn upsert_edge(&mut self, edge: KnowledgeGraphEdge) {
        if let Some(existing) = self
            .edges
            .iter_mut()
            .find(|existing| existing.edge_id() == edge.edge_id())
        {
            merge_edge(existing, edge);
        } else {
            self.edges.push(edge);
        }
    }

    fn engagements(&self) -> Vec<EngagementNode> {
        self.nodes
            .iter()
            .filter_map(|node| match node {
                KnowledgeGraphNode::Engagement(engagement) => Some(engagement.clone()),
                _ => None,
            })
            .collect()
    }

    fn engagement_mut_by_observation_id(
        &mut self,
        observation_id: &str,
    ) -> Option<&mut EngagementNode> {
        self.nodes.iter_mut().find_map(|node| match node {
            KnowledgeGraphNode::Engagement(engagement)
                if engagement.observation_id == observation_id =>
            {
                Some(engagement)
            }
            _ => None,
        })
    }

    fn deception_assets(&self) -> Vec<DeceptionAssetNode> {
        self.nodes
            .iter()
            .filter_map(|node| match node {
                KnowledgeGraphNode::DeceptionAsset(asset) => Some(asset.clone()),
                _ => None,
            })
            .collect()
    }

    fn attack_technique_for_node(&self, node_id: &str) -> Option<AttackTechniqueNode> {
        self.nodes.iter().find_map(|node| match node {
            KnowledgeGraphNode::AttackTechnique(technique) if technique.node_id == node_id => {
                Some(technique.clone())
            }
            _ => None,
        })
    }

    fn entity_value_for_node(&self, node_id: &str) -> Option<String> {
        self.nodes.iter().find_map(|node| match node {
            KnowledgeGraphNode::Entity(entity) if entity.node_id == node_id => {
                Some(entity.value.clone())
            }
            _ => None,
        })
    }

    fn prune_stale(&mut self, now_ms: i64, retention_days: u64) -> bool {
        if retention_days == 0 {
            return false;
        }

        let retention_window_ms = retention_days.saturating_mul(86_400_000_u64);
        let cutoff_ms = now_ms.saturating_sub(retention_window_ms.min(i64::MAX as u64) as i64);

        let node_count_before = self.nodes.len();
        let edge_count_before = self.edges.len();
        let processed_before = self.processed_observation_ids.len();

        self.nodes
            .retain(|node| node.last_observed_at_ms() >= cutoff_ms);
        let retained_node_ids = self
            .nodes
            .iter()
            .map(|node| node.node_id().to_string())
            .collect::<BTreeSet<_>>();
        self.edges.retain(|edge| {
            edge.last_observed_at_ms() >= cutoff_ms
                && retained_node_ids.contains(edge.from_node_id())
                && retained_node_ids.contains(edge.to_node_id())
        });
        let mut processed_observation_ids = self
            .engagements()
            .into_iter()
            .flat_map(|engagement| {
                let mut ids = BTreeSet::new();
                ids.insert(engagement.observation_id);
                ids.extend(engagement.analyst_feedback_ids);
                ids
            })
            .collect::<BTreeSet<_>>();
        processed_observation_ids.extend(
            self.deception_assets()
                .into_iter()
                .map(|asset| asset.registration_observation_id),
        );
        self.processed_observation_ids = processed_observation_ids;

        node_count_before != self.nodes.len()
            || edge_count_before != self.edges.len()
            || processed_before != self.processed_observation_ids.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeNodeRecord {
    pub node_id: String,
    pub kind: KnowledgeNodeKind,
    pub label: String,
    pub last_observed_at_ms: i64,
    pub bundle_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnowledgeEdgeRecord {
    pub edge_id: String,
    pub kind: KnowledgeEdgeKind,
    pub from_node_id: String,
    pub to_node_id: String,
    pub last_observed_at_ms: i64,
    pub bundle_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct KnowledgeGraphIndex {
    schema_version: u32,
    temporal_window_secs: u64,
    updated_at_ms: i64,
    processed_observation_ids: BTreeSet<String>,
    nodes: Vec<KnowledgeNodeRecord>,
    edges: Vec<KnowledgeEdgeRecord>,
}

impl Default for KnowledgeGraphIndex {
    fn default() -> Self {
        Self {
            schema_version: KNOWLEDGE_GRAPH_SCHEMA_VERSION,
            temporal_window_secs: 0,
            updated_at_ms: 0,
            processed_observation_ids: BTreeSet::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KnowledgeGraphStoreError {
    #[error("failed to read knowledge-graph file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write knowledge-graph file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse knowledge-graph file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone)]
pub struct FileKnowledgeGraphStore {
    root: PathBuf,
}

impl FileKnowledgeGraphStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KnowledgeGraphStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("nodes")).map_err(|source| {
            KnowledgeGraphStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        fs::create_dir_all(root.join("edges")).map_err(|source| {
            KnowledgeGraphStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    pub fn load_snapshot(
        &self,
    ) -> Result<Option<KnowledgeGraphSnapshot>, KnowledgeGraphStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|source| KnowledgeGraphStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let index: KnowledgeGraphIndex =
            serde_json::from_str(&raw).map_err(|source| KnowledgeGraphStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        let mut nodes = Vec::with_capacity(index.nodes.len());
        for record in &index.nodes {
            let node_path = self.node_path(&record.node_id);
            nodes.push(read_json(&node_path)?);
        }
        let mut edges = Vec::with_capacity(index.edges.len());
        for record in &index.edges {
            let edge_path = self.edge_path(&record.edge_id);
            edges.push(read_json(&edge_path)?);
        }
        Ok(Some(KnowledgeGraphSnapshot {
            schema_version: index.schema_version,
            temporal_window_secs: index.temporal_window_secs,
            updated_at_ms: index.updated_at_ms,
            processed_observation_ids: index.processed_observation_ids,
            nodes,
            edges,
        }))
    }

    pub fn persist_snapshot(
        &self,
        snapshot: &KnowledgeGraphSnapshot,
    ) -> Result<(), KnowledgeGraphStoreError> {
        let mut retained_node_paths = BTreeSet::new();
        let mut node_records = Vec::with_capacity(snapshot.nodes.len());
        for node in &snapshot.nodes {
            let path = self.node_path(node.node_id());
            write_json(&path, node)?;
            retained_node_paths.insert(path.clone());
            node_records.push(KnowledgeNodeRecord {
                node_id: node.node_id().to_string(),
                kind: node.kind(),
                label: node.label(),
                last_observed_at_ms: node.last_observed_at_ms(),
                bundle_path: path.display().to_string(),
            });
        }
        self.cleanup_bundle_dir(&self.root.join("nodes"), &retained_node_paths)?;

        let mut retained_edge_paths = BTreeSet::new();
        let mut edge_records = Vec::with_capacity(snapshot.edges.len());
        for edge in &snapshot.edges {
            let path = self.edge_path(edge.edge_id());
            write_json(&path, edge)?;
            retained_edge_paths.insert(path.clone());
            edge_records.push(KnowledgeEdgeRecord {
                edge_id: edge.edge_id().to_string(),
                kind: edge.kind(),
                from_node_id: edge.from_node_id().to_string(),
                to_node_id: edge.to_node_id().to_string(),
                last_observed_at_ms: edge.last_observed_at_ms(),
                bundle_path: path.display().to_string(),
            });
        }
        self.cleanup_bundle_dir(&self.root.join("edges"), &retained_edge_paths)?;

        let index = KnowledgeGraphIndex {
            schema_version: snapshot.schema_version,
            temporal_window_secs: snapshot.temporal_window_secs,
            updated_at_ms: snapshot.updated_at_ms,
            processed_observation_ids: snapshot.processed_observation_ids.clone(),
            nodes: node_records,
            edges: edge_records,
        };
        write_json(&self.index_path(), &index)
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn node_path(&self, node_id: &str) -> PathBuf {
        self.root
            .join("nodes")
            .join(format!("{}.json", sanitize_id(node_id)))
    }

    fn edge_path(&self, edge_id: &str) -> PathBuf {
        self.root
            .join("edges")
            .join(format!("{}.json", sanitize_id(edge_id)))
    }

    fn cleanup_bundle_dir(
        &self,
        dir: &Path,
        retained_paths: &BTreeSet<PathBuf>,
    ) -> Result<(), KnowledgeGraphStoreError> {
        let entries = fs::read_dir(dir).map_err(|source| KnowledgeGraphStoreError::Read {
            path: dir.to_path_buf(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| KnowledgeGraphStoreError::Read {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            if retained_paths.contains(&path) {
                continue;
            }
            fs::remove_file(&path)
                .map_err(|source| KnowledgeGraphStoreError::Write { path, source })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct AttackTechniqueObservation {
    technique_id: String,
    name: String,
    kill_chain_stage: String,
}

#[derive(Debug, Clone)]
struct EntityObservation {
    kind: EntityKind,
    role: String,
    value: String,
}

fn merge_node(target: &mut KnowledgeGraphNode, incoming: KnowledgeGraphNode) {
    match (target, incoming) {
        (
            KnowledgeGraphNode::ThreatPattern(target),
            KnowledgeGraphNode::ThreatPattern(incoming),
        ) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.observation_count += incoming.observation_count;
            target.latest_severity = incoming.latest_severity;
            target
                .attack_technique_ids
                .extend(incoming.attack_technique_ids);
            target.kill_chain_stages.extend(incoming.kill_chain_stages);
        }
        (
            KnowledgeGraphNode::AttackTechnique(target),
            KnowledgeGraphNode::AttackTechnique(incoming),
        ) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.observation_count += incoming.observation_count;
            if target.name.trim().is_empty() {
                target.name = incoming.name;
            }
        }
        (KnowledgeGraphNode::Entity(target), KnowledgeGraphNode::Entity(incoming)) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.observation_count += incoming.observation_count;
        }
        (KnowledgeGraphNode::Engagement(target), KnowledgeGraphNode::Engagement(incoming)) => {
            target
                .related_entity_ids
                .extend(incoming.related_entity_ids);
            target
                .attack_technique_ids
                .extend(incoming.attack_technique_ids);
            target
                .analyst_feedback_ids
                .extend(incoming.analyst_feedback_ids);
            target.summary = incoming.summary;
            target.severity = incoming.severity;
            target.observed_at_ms = target.observed_at_ms.max(incoming.observed_at_ms);
            if incoming.analyst_disposition.is_some() {
                target.analyst_disposition = incoming.analyst_disposition;
            }
            if incoming.analyst_note.is_some() {
                target.analyst_note = incoming.analyst_note;
            }
            if incoming.analyst_feedback_at_ms.is_some() {
                target.analyst_feedback_at_ms = incoming.analyst_feedback_at_ms;
            }
            if incoming.outcome_reward_override.is_some() {
                target.outcome_reward_override = incoming.outcome_reward_override;
            }
        }
        (
            KnowledgeGraphNode::DeceptionAsset(target),
            KnowledgeGraphNode::DeceptionAsset(incoming),
        ) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.lifecycle_stage = incoming.lifecycle_stage;
            target.interaction_count += incoming.interaction_count;
            target.deployed_at_ms = target.deployed_at_ms.min(incoming.deployed_at_ms);
            target.last_interaction_at_ms = target
                .last_interaction_at_ms
                .max(incoming.last_interaction_at_ms);
        }
        (target, incoming) => *target = incoming,
    }
}

fn merge_edge(target: &mut KnowledgeGraphEdge, incoming: KnowledgeGraphEdge) {
    match (target, incoming) {
        (KnowledgeGraphEdge::Temporal(target), KnowledgeGraphEdge::Temporal(incoming)) => {
            target.shared_entity_ids.extend(incoming.shared_entity_ids);
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.occurrence_count += incoming.occurrence_count;
        }
        (KnowledgeGraphEdge::Causal(target), KnowledgeGraphEdge::Causal(incoming)) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.occurrence_count += incoming.occurrence_count;
        }
        (KnowledgeGraphEdge::Entity(target), KnowledgeGraphEdge::Entity(incoming)) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.occurrence_count += incoming.occurrence_count;
        }
        (KnowledgeGraphEdge::Semantic(target), KnowledgeGraphEdge::Semantic(incoming)) => {
            target.first_observed_at_ms = target
                .first_observed_at_ms
                .min(incoming.first_observed_at_ms);
            target.last_observed_at_ms =
                target.last_observed_at_ms.max(incoming.last_observed_at_ms);
            target.occurrence_count += incoming.occurrence_count;
        }
        (target, incoming) => *target = incoming,
    }
}

fn extract_entities(indicator: &Value) -> Vec<EntityObservation> {
    let mut entities = Vec::new();
    let mut seen = BTreeSet::new();
    let candidates = [
        ("host_id", EntityKind::Host),
        ("host", EntityKind::Host),
        ("user", EntityKind::User),
        ("username", EntityKind::User),
        ("process_name", EntityKind::Process),
        ("parent_process_name", EntityKind::Process),
        ("source_ip", EntityKind::IpAddress),
        ("destination_ip", EntityKind::IpAddress),
        ("remote_ip", EntityKind::IpAddress),
        ("ip_address", EntityKind::IpAddress),
    ];

    for (field, kind) in candidates {
        let Some(value) = indicator.get(field).and_then(Value::as_str) else {
            continue;
        };
        let normalized = value.trim();
        if normalized.is_empty() {
            continue;
        }
        let key = format!("{field}:{}", normalized.to_ascii_lowercase());
        if !seen.insert(key) {
            continue;
        }
        entities.push(EntityObservation {
            kind,
            role: field.to_string(),
            value: normalized.to_string(),
        });
    }
    entities
}

fn extract_attack_techniques(deposit: &PheromoneDeposit) -> Vec<AttackTechniqueObservation> {
    let mut techniques = Vec::new();
    let default_stage = default_kill_chain_stage(&deposit.threat_class);

    if let Some(entries) = deposit
        .indicator
        .get("attack_techniques")
        .and_then(Value::as_array)
    {
        for entry in entries {
            if let Some(technique) = parse_attack_technique(entry, default_stage) {
                techniques.push(technique);
            }
        }
    }

    if techniques.is_empty()
        && let Some(entry) = deposit.indicator.get("attack_technique")
        && let Some(technique) = parse_attack_technique(entry, default_stage)
    {
        techniques.push(technique);
    }

    if techniques.is_empty() {
        techniques.extend(default_attack_techniques(&deposit.threat_class));
    }

    let mut seen = BTreeSet::new();
    techniques
        .into_iter()
        .filter(|technique| seen.insert(technique.technique_id.clone()))
        .collect()
}

fn parse_attack_technique(
    value: &Value,
    default_stage: &str,
) -> Option<AttackTechniqueObservation> {
    match value {
        Value::String(technique_id) => {
            let trimmed = technique_id.trim();
            if trimmed.is_empty() {
                return None;
            }
            Some(AttackTechniqueObservation {
                technique_id: trimmed.to_string(),
                name: trimmed.to_string(),
                kill_chain_stage: default_stage.to_string(),
            })
        }
        Value::Object(map) => {
            let technique_id = map
                .get("id")
                .or_else(|| map.get("technique_id"))
                .and_then(Value::as_str)?
                .trim()
                .to_string();
            if technique_id.is_empty() {
                return None;
            }
            Some(AttackTechniqueObservation {
                name: map
                    .get("name")
                    .or_else(|| map.get("display_name"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(&technique_id)
                    .to_string(),
                kill_chain_stage: map
                    .get("kill_chain_stage")
                    .or_else(|| map.get("stage"))
                    .or_else(|| map.get("tactic"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(default_stage)
                    .to_string(),
                technique_id,
            })
        }
        _ => None,
    }
}

fn default_attack_techniques(threat_class: &ThreatClass) -> Vec<AttackTechniqueObservation> {
    let (technique_id, name, kill_chain_stage) = match threat_class {
        ThreatClass::Execution => ("T1059", "Command and Scripting Interpreter", "execution"),
        ThreatClass::CredentialAccess => ("T1110", "Brute Force", "credential-access"),
        ThreatClass::LateralMovement => ("T1021", "Remote Services", "lateral-movement"),
        ThreatClass::Persistence => ("T1547", "Boot or Logon Autostart Execution", "persistence"),
        ThreatClass::CommandAndControl => {
            ("T1071", "Application Layer Protocol", "command-and-control")
        }
        ThreatClass::DefenseEvasion => ("T1070", "Indicator Removal", "defense-evasion"),
        ThreatClass::Discovery => ("T1082", "System Information Discovery", "discovery"),
        ThreatClass::InitialAccess => ("T1566", "Phishing", "initial-access"),
        ThreatClass::PrivilegeEscalation => (
            "T1548",
            "Abuse Elevation Control Mechanism",
            "privilege-escalation",
        ),
        ThreatClass::DataExfiltration => ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
        ThreatClass::SupplyChain => ("T1195", "Supply Chain Compromise", "resource-development"),
        ThreatClass::Impact => ("T1489", "Service Stop", "impact"),
        ThreatClass::Custom(name) => {
            return vec![AttackTechniqueObservation {
                technique_id: format!("custom:{}", sanitize_id(name)),
                name: format!("{name} observation"),
                kill_chain_stage: "custom".to_string(),
            }];
        }
    };

    vec![AttackTechniqueObservation {
        technique_id: technique_id.to_string(),
        name: name.to_string(),
        kill_chain_stage: kill_chain_stage.to_string(),
    }]
}

fn threat_class_key(threat_class: &ThreatClass) -> String {
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
        ThreatClass::Custom(value) => sanitize_id(value),
    }
}

fn threat_class_label(threat_class: &ThreatClass) -> &'static str {
    match threat_class {
        ThreatClass::LateralMovement => "Lateral movement",
        ThreatClass::DataExfiltration => "Data exfiltration",
        ThreatClass::PrivilegeEscalation => "Privilege escalation",
        ThreatClass::CommandAndControl => "Command and control",
        ThreatClass::InitialAccess => "Initial access",
        ThreatClass::Persistence => "Persistence",
        ThreatClass::SupplyChain => "Supply chain",
        ThreatClass::DefenseEvasion => "Defense evasion",
        ThreatClass::CredentialAccess => "Credential access",
        ThreatClass::Discovery => "Discovery",
        ThreatClass::Execution => "Execution",
        ThreatClass::Impact => "Impact",
        ThreatClass::Custom(_) => "Custom",
    }
}

fn default_kill_chain_stage(threat_class: &ThreatClass) -> &'static str {
    match threat_class {
        ThreatClass::LateralMovement => "lateral-movement",
        ThreatClass::DataExfiltration => "exfiltration",
        ThreatClass::PrivilegeEscalation => "privilege-escalation",
        ThreatClass::CommandAndControl => "command-and-control",
        ThreatClass::InitialAccess => "initial-access",
        ThreatClass::Persistence => "persistence",
        ThreatClass::SupplyChain => "resource-development",
        ThreatClass::DefenseEvasion => "defense-evasion",
        ThreatClass::CredentialAccess => "credential-access",
        ThreatClass::Discovery => "discovery",
        ThreatClass::Execution => "execution",
        ThreatClass::Impact => "impact",
        ThreatClass::Custom(_) => "custom",
    }
}

fn observation_summary(deposit: &PheromoneDeposit) -> String {
    for field in [
        "summary",
        "lead",
        "description",
        "process_name",
        "event_id",
        "hunt_id",
    ] {
        if let Some(value) = deposit.indicator.get(field).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    format!(
        "{} observation from {}",
        threat_class_label(&deposit.threat_class),
        deposit.agent_id
    )
}

#[derive(Debug, Clone)]
struct ProvidenceFeedbackSignal {
    feedback_id: String,
    action: ProvidenceFeedbackAction,
    observed_at_ms: i64,
    event_id: Option<String>,
    hunt_id: Option<String>,
    note: Option<String>,
}

fn observation_timestamp_ms(deposit: &PheromoneDeposit) -> i64 {
    if let Some(value) = deposit
        .indicator
        .get("observed_at_ms")
        .and_then(Value::as_i64)
    {
        return value;
    }
    if let Some(value) = deposit
        .indicator
        .get("timestamp_ms")
        .and_then(Value::as_i64)
    {
        return value;
    }
    deposit.timestamp.saturating_mul(1000)
}

fn observation_id(deposit: &PheromoneDeposit) -> Result<String, KnowledgeGraphStoreError> {
    for field in ["observation_id", "event_id", "hunt_id"] {
        if let Some(value) = deposit.indicator.get(field).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "agent_id": deposit.agent_id,
        "threat_class": threat_class_key(&deposit.threat_class),
        "severity": deposit.severity,
        "timestamp": deposit.timestamp,
        "indicator": deposit.indicator,
    }))
    .map_err(|source| KnowledgeGraphStoreError::Parse {
        path: PathBuf::from("<observation-id>"),
        source,
    })?;
    Ok(format!("observation:{}", sha256_hex(&payload)))
}

fn parse_providence_feedback_signal(
    deposit: &PheromoneDeposit,
) -> Option<ProvidenceFeedbackSignal> {
    let schema = deposit.indicator.get("schema")?.as_str()?;
    if schema != SWARM_PROVIDENCE_FEEDBACK_SCHEMA {
        return None;
    }
    Some(ProvidenceFeedbackSignal {
        feedback_id: deposit
            .indicator
            .get("feedback_id")
            .and_then(Value::as_str)?
            .to_string(),
        action: serde_json::from_value(deposit.indicator.get("action")?.clone()).ok()?,
        observed_at_ms: deposit
            .indicator
            .get("observed_at_ms")
            .and_then(Value::as_i64)
            .unwrap_or(deposit.timestamp),
        event_id: deposit
            .indicator
            .get("event_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        hunt_id: deposit
            .indicator
            .get("hunt_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        note: deposit
            .indicator
            .get("reason")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

fn entity_node_id(kind: EntityKind, value: &str) -> String {
    let kind_label = match kind {
        EntityKind::Host => "host",
        EntityKind::User => "user",
        EntityKind::Process => "process",
        EntityKind::IpAddress => "ip_address",
    };
    format!(
        "entity:{}:{}",
        kind_label,
        sanitize_id(&value.to_ascii_lowercase())
    )
}

fn deception_asset_node_id(asset_id: &str) -> String {
    format!("deception_asset:{}", sanitize_id(asset_id))
}

fn deception_lifecycle_stage_label(stage: crate::calico_agent::CalicoLifecycleStage) -> String {
    match stage {
        crate::calico_agent::CalicoLifecycleStage::Deploy => "deploy",
        crate::calico_agent::CalicoLifecycleStage::Monitor => "monitor",
        crate::calico_agent::CalicoLifecycleStage::Rotate => "rotate",
        crate::calico_agent::CalicoLifecycleStage::Cleanup => "cleanup",
    }
    .to_string()
}

fn technique_node_id(technique_id: &str) -> String {
    format!(
        "attack_technique:{}",
        sanitize_id(&technique_id.to_ascii_lowercase())
    )
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

fn parse_memory_query(deposit: &PheromoneDeposit) -> Option<SphinxMemoryQuery> {
    if !is_memory_deposit(deposit) {
        return None;
    }
    let query = serde_json::from_value::<SphinxMemoryQuery>(deposit.indicator.clone()).ok()?;
    (query.kind == SphinxMemoryPayloadKind::Query).then_some(query)
}

fn is_memory_answer(deposit: &PheromoneDeposit) -> bool {
    if !is_memory_deposit(deposit) {
        return false;
    }
    serde_json::from_value::<SphinxMemoryAnswer>(deposit.indicator.clone())
        .map(|answer| answer.kind == SphinxMemoryPayloadKind::Answer)
        .unwrap_or(false)
}

fn is_memory_deposit(deposit: &PheromoneDeposit) -> bool {
    matches!(
        &deposit.threat_class,
        ThreatClass::Custom(value) if value == SPHINX_MEMORY_THREAT_CLASS
    )
}

fn context_relevance(
    threat_match: bool,
    requested_techniques: usize,
    matched_techniques: usize,
    requested_entities: usize,
    matched_entities: usize,
) -> f64 {
    let mut total_weight = 0.0;
    let mut score = 0.0;

    if threat_match {
        total_weight += 0.35;
        score += 0.35;
    }
    if requested_techniques > 0 {
        total_weight += 0.30;
        score += 0.30 * (matched_techniques as f64 / requested_techniques as f64);
    }
    if requested_entities > 0 {
        total_weight += 0.35;
        score += 0.35 * (matched_entities as f64 / requested_entities as f64);
    }

    if total_weight == 0.0 {
        0.0
    } else {
        (score / total_weight).clamp(0.0, 1.0)
    }
}

fn severity_reward(severity: Severity) -> f64 {
    match severity {
        Severity::Low => 0.25,
        Severity::Medium => 0.50,
        Severity::High => 0.75,
        Severity::Critical => 1.00,
    }
}

fn analyst_outcome_reward(action: ProvidenceFeedbackAction) -> f64 {
    match action {
        ProvidenceFeedbackAction::Confirm => 1.0,
        ProvidenceFeedbackAction::Dismiss => 0.0,
        ProvidenceFeedbackAction::Investigate => 0.35,
    }
}

fn q_value_recency_decay(observed_at_ms: i64, now_ms: i64) -> f64 {
    if now_ms <= observed_at_ms {
        return 1.0;
    }
    let elapsed_hours = (now_ms - observed_at_ms) as f64 / 3_600_000.0;
    (0.5_f64).powf(elapsed_hours / RECENCY_HALF_LIFE_HOURS)
}

fn resolve_memory_root(config_path: &Path, memory: &MemoryConfig) -> PathBuf {
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let root = Path::new(&memory.knowledge_graph_results_dir);
    if root.is_absolute() {
        root.to_path_buf()
    } else {
        base.join(root)
    }
}

fn read_json<T>(path: &Path) -> Result<T, KnowledgeGraphStoreError>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = fs::read_to_string(path).map_err(|source| KnowledgeGraphStoreError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| KnowledgeGraphStoreError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn write_json<T>(path: &Path, value: &T) -> Result<(), KnowledgeGraphStoreError>
where
    T: Serialize,
{
    let raw =
        serde_json::to_string_pretty(value).map_err(|source| KnowledgeGraphStoreError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    fs::write(path, raw).map_err(|source| KnowledgeGraphStoreError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn internal_error(error: KnowledgeGraphStoreError) -> SwarmError {
    SwarmError::Internal(AgentTickBoundaryError::from(SphinxAgentTickError::from(error)).into())
}

fn internal_runtime_error(error: impl Into<SphinxAgentTickError>) -> SwarmError {
    SwarmError::Internal(AgentTickBoundaryError::from(error.into()).into())
}

#[cfg(test)]
fn signed_memory_query_deposit(
    query: &SphinxMemoryQuery,
    config: &swarm_core::config::SwarmConfig,
    _agent_id: AgentId,
    timestamp: i64,
) -> PheromoneDeposit {
    let signing_key = SigningKey::generate(&mut OsRng);
    let threat_class = ThreatClass::Custom(SPHINX_MEMORY_THREAT_CLASS.to_string());
    let policy = config.pheromone.resolve_threat_class_policy(None);
    let indicator = serde_json::to_value(query).expect("query should encode");
    let derived_agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator,
        threat_class,
        severity: Severity::Low,
        confidence: 0.0,
        timestamp,
        decay_half_life: policy.half_life_secs,
        agent_id: derived_agent_id.clone(),
        agent_identity: derived_agent_id.0,
        agent_role: Some(AgentRole::Kitten),
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let signing_payload = DepositSigningPayload {
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
    let payload_bytes = serde_json::to_vec(&signing_payload).expect("payload should encode");
    let signature = signing_key.sign(&payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = signing_key.verifying_key().to_bytes().to_vec();
    deposit
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{
        DeceptionAssetNode, EntityKind, FileKnowledgeGraphStore, KnowledgeEdgeKind,
        KnowledgeGraphNode, KnowledgeNodeKind, SphinxAgent, SphinxAgentTickError,
        parse_memory_query, signed_memory_query_deposit,
    };
    use crate::AgentTickBoundaryError;
    use crate::calico_agent::{
        CALICO_DECEPTION_INVENTORY_THREAT_CLASS, CalicoDeceptionInteractionPayload,
        CalicoDeceptionInventoryPayload, CalicoLifecycleStage,
    };
    use crate::config::load_config;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::{
        AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmMode,
    };
    use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
    use swarm_core::types::{
        AgentId, ProvidenceFeedbackAction, SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
        SPHINX_MEMORY_THREAT_CLASS, SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
        SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION, Severity, SphinxMemoryPayloadKind,
        SphinxMemoryQuery, SwarmAction,
    };
    use swarm_pheromone::{ConfiguredPheromoneSubstrate, PheromoneSubstrate};

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn config_path() -> PathBuf {
        repo_root().join("rulesets/default.yaml")
    }

    fn temp_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "swarm-runtime-sphinx-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn configure_memory(config: &mut swarm_core::config::SwarmConfig, root: &std::path::Path) {
        config.memory.enabled = true;
        config.memory.knowledge_graph_results_dir =
            root.join("knowledge-graph").display().to_string();
        config.memory.temporal_window_secs = 3_600;
        config.memory.knowledge_retention_days = 90;
    }

    fn substrate(config: &swarm_core::config::SwarmConfig) -> ConfiguredPheromoneSubstrate {
        ConfiguredPheromoneSubstrate::from_config(&config.pheromone)
            .expect("test substrate should initialize")
    }

    fn pheromone(event_id: &str, timestamp: i64) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "event_id": event_id,
                "summary": "suspicious powershell execution",
                "host_id": "host-1",
                "user": "alice",
                "process_name": "powershell.exe",
                "parent_process_name": "winword.exe",
                "source_ip": "10.0.0.5",
                "destination_ip": "198.51.100.7",
                "attack_techniques": [
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "kill_chain_stage": "execution"}
                ],
                "observed_at_ms": timestamp * 1000
            }),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.97,
            timestamp,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("whisker", "primary"),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn pheromone_with_context(
        event_id: &str,
        timestamp: i64,
        host_id: &str,
        user: &str,
        process_name: &str,
        destination_ip: &str,
    ) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "event_id": event_id,
                "summary": format!("{process_name} execution"),
                "host_id": host_id,
                "user": user,
                "process_name": process_name,
                "parent_process_name": "winword.exe",
                "source_ip": "10.0.0.5",
                "destination_ip": destination_ip,
                "attack_techniques": [
                    {"id": "T1059", "name": "Command and Scripting Interpreter", "kill_chain_stage": "execution"}
                ],
                "observed_at_ms": timestamp * 1000
            }),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.97,
            timestamp,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("whisker", "primary"),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn providence_feedback_pheromone(
        feedback_id: &str,
        event_id: &str,
        timestamp: i64,
        action: ProvidenceFeedbackAction,
        reason: &str,
    ) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "schema_version": SWARM_PROVIDENCE_FEEDBACK_SCHEMA_VERSION,
                "feedback_id": feedback_id,
                "action": action,
                "status": match action {
                    ProvidenceFeedbackAction::Confirm => "confirm",
                    ProvidenceFeedbackAction::Dismiss => "dismiss",
                    ProvidenceFeedbackAction::Investigate => "investigate",
                },
                "incident_id": "incident-1",
                "finding_id": "finding-1",
                "event_id": event_id,
                "hunt_id": event_id,
                "strategy_id": "office_baseline_control_kitten",
                "analyst_id": "analyst-feedback",
                "reason": reason,
                "observed_at_ms": timestamp * 1000,
            }),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.0,
            timestamp: timestamp * 1000,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("ingest", "primary"),
            agent_identity: String::new(),
            agent_role: None,
            signature: vec![7; 64],
            agent_key: vec![9; 32],
        }
    }

    fn calico_inventory_pheromone(
        asset_id: &str,
        timestamp: i64,
        generation: usize,
    ) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::to_value(CalicoDeceptionInventoryPayload {
                schema: crate::calico_agent::CALICO_DECEPTION_INVENTORY_SCHEMA.to_string(),
                schema_version: 1,
                asset_id: asset_id.to_string(),
                playbook_entry: "finance-canary".to_string(),
                generation,
                lifecycle_stage: CalicoLifecycleStage::Monitor,
                decoy_type: "canary_token".to_string(),
                target_zone: "finance".to_string(),
                host_profile: "linux-app".to_string(),
                placement_strategy: "high_value_path".to_string(),
                deployed_at_ms: timestamp * 1000,
                monitoring: crate::calico_agent::CalicoMonitoringPayload {
                    file_paths: vec!["/srv/data/finance/payroll.xlsx".to_string()],
                    honeypot_ports: Vec::new(),
                    canary_credentials: Vec::new(),
                },
            })
            .unwrap(),
            threat_class: ThreatClass::Custom(CALICO_DECEPTION_INVENTORY_THREAT_CLASS.to_string()),
            severity: Severity::Low,
            confidence: 1.0,
            timestamp,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("calico", "primary"),
            agent_identity: String::new(),
            agent_role: Some(AgentRole::Calico),
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn calico_interaction_pheromone(asset_id: &str, timestamp: i64) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::to_value(CalicoDeceptionInteractionPayload {
                schema: crate::calico_agent::CALICO_DECEPTION_INTERACTION_SCHEMA.to_string(),
                schema_version: 1,
                asset_id: asset_id.to_string(),
                playbook_entry: "finance-canary".to_string(),
                generation: 1,
                lifecycle_stage: CalicoLifecycleStage::Monitor,
                decoy_type: "canary_token".to_string(),
                target_zone: "finance".to_string(),
                host_profile: "linux-app".to_string(),
                placement_strategy: "high_value_path".to_string(),
                interaction_signal: "file_path".to_string(),
                matched_value: "/srv/data/finance/payroll.xlsx".to_string(),
                source_event_id: Some("evt-calico-1".to_string()),
                source_hunt_id: None,
                source_agent_id: AgentId::new("whisker", "primary").to_string(),
                source_indicator: serde_json::json!({
                    "event_id": "evt-calico-1",
                    "summary": "unexpected finance file access",
                    "observed_at_ms": timestamp * 1000,
                }),
            })
            .unwrap(),
            threat_class: ThreatClass::InitialAccess,
            severity: Severity::High,
            confidence: 0.99,
            timestamp,
            decay_half_life: 3_600.0,
            agent_id: AgentId::new("calico", "primary"),
            agent_identity: String::new(),
            agent_role: Some(AgentRole::Calico),
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    fn env(pheromones: Vec<PheromoneDeposit>, now: i64) -> SwarmEnvironment {
        SwarmEnvironment {
            pheromones,
            mode: SwarmMode::Alert,
            mode_transition_at: Some(now - 5),
            now,
            peer_findings: Vec::new(),
            agent_health: Vec::new(),
        }
    }

    #[test]
    fn sphinx_agent_reports_role() {
        let root = temp_root("role");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);

        let agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        assert_eq!(agent.role(), AgentRole::Sphinx);
        assert_eq!(agent.health(), AgentHealth::Healthy);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn sphinx_agent_surfaces_store_failures_with_typed_boundary() {
        let root = temp_root("store-failure");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        fs::remove_dir_all(root.join("knowledge-graph")).unwrap();

        let error = agent
            .tick(&env(vec![pheromone("evt-1", 1_800_500_000)], 1_800_500_001))
            .await
            .unwrap_err();
        let boundary = match &error {
            SwarmError::Internal(error) => error
                .downcast_ref::<AgentTickBoundaryError>()
                .expect("sphinx agent should preserve typed boundary error"),
            other => panic!("expected internal boundary error, got {other:?}"),
        };

        assert!(matches!(
            boundary,
            AgentTickBoundaryError::Sphinx(SphinxAgentTickError::Store(_))
        ));
        assert_eq!(boundary.boundary(), "knowledge_graph_store");

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn file_knowledge_graph_store_persists_typed_nodes_and_edges_across_restart() {
        let root = temp_root("persist");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(vec![pheromone("evt-1", 1_800_500_000)], 1_800_500_001))
            .await
            .expect("sphinx tick should persist graph state");

        let store = FileKnowledgeGraphStore::open(root.join("knowledge-graph")).unwrap();
        let snapshot = store
            .load_snapshot()
            .expect("snapshot should load")
            .expect("snapshot should exist");

        let node_kinds = snapshot
            .nodes
            .iter()
            .map(KnowledgeGraphNode::kind)
            .collect::<Vec<_>>();
        assert!(node_kinds.contains(&KnowledgeNodeKind::ThreatPattern));
        assert!(node_kinds.contains(&KnowledgeNodeKind::AttackTechnique));
        assert!(node_kinds.contains(&KnowledgeNodeKind::Engagement));
        assert!(snapshot.nodes.iter().any(|node| matches!(
            node,
            KnowledgeGraphNode::Entity(entity) if entity.entity_kind == EntityKind::Host
        )));
        let edge_kinds = snapshot
            .edges
            .iter()
            .map(|edge| edge.kind())
            .collect::<Vec<_>>();
        assert!(edge_kinds.contains(&KnowledgeEdgeKind::Entity));
        assert!(edge_kinds.contains(&KnowledgeEdgeKind::Causal));
        assert!(edge_kinds.contains(&KnowledgeEdgeKind::Semantic));

        let mut restarted = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should restore graph state");
        restarted
            .tick(&env(vec![pheromone("evt-1", 1_800_500_000)], 1_800_500_002))
            .await
            .expect("duplicate observation should not fail");

        let restored = store
            .load_snapshot()
            .expect("snapshot should reload")
            .expect("snapshot should still exist");
        assert_eq!(snapshot.nodes.len(), restored.nodes.len());
        assert_eq!(snapshot.edges.len(), restored.edges.len());
        assert_eq!(restored.processed_observation_ids.len(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn sphinx_agent_links_related_engagements_with_temporal_edges() {
        let root = temp_root("temporal");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(vec![pheromone("evt-1", 1_800_600_000)], 1_800_600_001))
            .await
            .expect("first engagement should persist");
        agent
            .tick(&env(
                vec![
                    pheromone("evt-1", 1_800_600_000),
                    pheromone("evt-2", 1_800_600_030),
                ],
                1_800_600_031,
            ))
            .await
            .expect("second related engagement should link temporally");

        let store = FileKnowledgeGraphStore::open(root.join("knowledge-graph")).unwrap();
        let snapshot = store
            .load_snapshot()
            .expect("snapshot should load")
            .expect("snapshot should exist");

        let temporal_edges = snapshot
            .edges
            .iter()
            .filter(|edge| matches!(edge.kind(), KnowledgeEdgeKind::Temporal))
            .count();
        assert_eq!(temporal_edges, 1);
        assert_eq!(snapshot.processed_observation_ids.len(), 2);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn deception_inventory_registration_persists_across_restart() {
        let root = temp_root("deception-inventory");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(
                vec![calico_inventory_pheromone(
                    "calico:finance_canary:1",
                    1_800_650_000,
                    1,
                )],
                1_800_650_001,
            ))
            .await
            .expect("inventory registration should persist");

        let store = FileKnowledgeGraphStore::open(root.join("knowledge-graph")).unwrap();
        let snapshot = store
            .load_snapshot()
            .expect("snapshot should load")
            .expect("snapshot should exist");
        assert!(snapshot.nodes.iter().any(|node| matches!(
            node,
            KnowledgeGraphNode::DeceptionAsset(DeceptionAssetNode { asset_id, generation, .. })
                if asset_id == "calico:finance_canary:1" && *generation == 1
        )));

        let mut restarted = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should restore graph state");
        restarted
            .tick(&env(
                vec![calico_inventory_pheromone(
                    "calico:finance_canary:1",
                    1_800_650_000,
                    1,
                )],
                1_800_650_002,
            ))
            .await
            .expect("duplicate inventory registration should not re-add node");

        let restored = store
            .load_snapshot()
            .expect("snapshot should reload")
            .expect("snapshot should still exist");
        let deception_assets = restored
            .nodes
            .iter()
            .filter(|node| matches!(node, KnowledgeGraphNode::DeceptionAsset(_)))
            .count();
        assert_eq!(deception_assets, 1);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn deception_interaction_links_registered_asset_to_engagement() {
        let root = temp_root("deception-link");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(
                vec![
                    calico_inventory_pheromone("calico:finance_canary:1", 1_800_660_000, 1),
                    calico_interaction_pheromone("calico:finance_canary:1", 1_800_660_005),
                ],
                1_800_660_006,
            ))
            .await
            .expect("interaction linkage should persist");

        let store = FileKnowledgeGraphStore::open(root.join("knowledge-graph")).unwrap();
        let snapshot = store
            .load_snapshot()
            .expect("snapshot should load")
            .expect("snapshot should exist");
        assert!(snapshot.nodes.iter().any(|node| matches!(
            node,
            KnowledgeGraphNode::DeceptionAsset(DeceptionAssetNode {
                asset_id,
                interaction_count,
                last_interaction_at_ms,
                ..
            }) if asset_id == "calico:finance_canary:1"
                && *interaction_count == 1
                && *last_interaction_at_ms == Some(1_800_660_005_000)
        )));
        assert!(snapshot.edges.iter().any(|edge| matches!(
            edge,
            super::KnowledgeGraphEdge::Entity(edge)
                if edge.role == "deception_asset"
        )));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn sphinx_agent_answers_memory_queries_from_matching_graph_context() {
        let root = temp_root("query-answer");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);
        let substrate = substrate(&config);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(
                vec![
                    pheromone("evt-1", 1_800_700_000),
                    pheromone("evt-2", 1_800_700_030),
                ],
                1_800_700_031,
            ))
            .await
            .expect("graph seeding should succeed");

        let query = SphinxMemoryQuery {
            schema_version: SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
            kind: SphinxMemoryPayloadKind::Query,
            query_id: "sphinx-query-1".to_string(),
            requested_by_agent_id: AgentId::new("kitten", "primary").to_string(),
            strategy_id: "office_baseline_control_kitten".to_string(),
            selection_source: "restored_population".to_string(),
            observation_count: 2,
            base_fitness: 0.58,
            requested_at_ms: 1_800_700_040_000,
            threat_classes: vec!["execution".to_string()],
            attack_technique_ids: vec!["T1059".to_string()],
            entity_values: vec!["host-1".to_string(), "alice".to_string()],
        };
        substrate
            .deposit(signed_memory_query_deposit(
                &query,
                &config,
                AgentId::new("kitten", "primary"),
                1_800_700_040,
            ))
            .await
            .expect("query deposit should persist");
        let query_env = env(
            substrate
                .recent_deposits(10)
                .await
                .expect("recent deposits should load"),
            1_800_700_041,
        );

        let actions = agent
            .tick(&query_env)
            .await
            .expect("sphinx should answer matching memory query");
        assert_eq!(actions.len(), 1);
        let SwarmAction::DepositPheromone {
            threat_class,
            indicator,
            ..
        } = &actions[0]
        else {
            panic!("expected memory answer pheromone action");
        };
        assert_eq!(threat_class, SPHINX_MEMORY_THREAT_CLASS);
        let answer: swarm_core::types::SphinxMemoryAnswer =
            serde_json::from_value(indicator.clone()).expect("answer payload should decode");
        assert_eq!(answer.query_id, query.query_id);
        assert!(answer.matching_engagement_count >= 1);
        assert!(answer.retrieval_score > 0.0);

        let deposits = substrate
            .recent_deposits(10)
            .await
            .expect("answer deposits should be queryable");
        assert!(
            deposits
                .iter()
                .any(|deposit| parse_memory_query(deposit).is_some())
        );
        assert!(deposits.iter().any(|deposit| {
            serde_json::from_value::<swarm_core::types::SphinxMemoryAnswer>(
                deposit.indicator.clone(),
            )
            .map(|answer| answer.query_id == query.query_id)
            .unwrap_or(false)
        }));

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn providence_feedback_updates_matching_engagement_memory_reward() {
        let root = temp_root("feedback-memory");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);
        let substrate = substrate(&config);

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate.clone(),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(
                vec![pheromone("evt-feedback", 1_800_705_000)],
                1_800_705_001,
            ))
            .await
            .expect("graph seed should succeed");
        agent
            .tick(&env(
                vec![providence_feedback_pheromone(
                    "feedback-evt-feedback-1",
                    "evt-feedback",
                    1_800_705_010,
                    ProvidenceFeedbackAction::Dismiss,
                    "known false positive",
                )],
                1_800_705_011,
            ))
            .await
            .expect("feedback annotation should succeed");

        let query = SphinxMemoryQuery {
            schema_version: SPHINX_MEMORY_PHEROMONE_SCHEMA_VERSION,
            kind: SphinxMemoryPayloadKind::Query,
            query_id: "sphinx-feedback-query".to_string(),
            requested_by_agent_id: AgentId::new("kitten", "primary").to_string(),
            strategy_id: "office_baseline_control_kitten".to_string(),
            selection_source: "feedback_fixture".to_string(),
            observation_count: 1,
            base_fitness: 0.80,
            requested_at_ms: 1_800_705_020_000,
            threat_classes: vec!["execution".to_string()],
            attack_technique_ids: vec!["T1059".to_string()],
            entity_values: vec!["host-1".to_string(), "alice".to_string()],
        };
        substrate
            .deposit(signed_memory_query_deposit(
                &query,
                &config,
                AgentId::new("kitten", "primary"),
                1_800_705_020,
            ))
            .await
            .expect("query deposit should persist");

        let query_env = env(
            substrate
                .recent_deposits(10)
                .await
                .expect("recent deposits should load"),
            1_800_705_021,
        );
        let actions = agent
            .tick(&query_env)
            .await
            .expect("sphinx should answer feedback-adjusted query");
        let SwarmAction::DepositPheromone { indicator, .. } = &actions[0] else {
            panic!("expected memory answer pheromone action");
        };
        let answer: swarm_core::types::SphinxMemoryAnswer =
            serde_json::from_value(indicator.clone()).expect("answer payload should decode");
        assert_eq!(answer.matching_engagement_count, 1);
        assert_eq!(
            answer.contributions[0].analyst_disposition,
            Some(ProvidenceFeedbackAction::Dismiss)
        );
        assert_eq!(
            answer.contributions[0].analyst_note.as_deref(),
            Some("known false positive")
        );
        assert_eq!(answer.contributions[0].outcome_reward, 0.0);
        assert_eq!(answer.retrieval_score, 0.0);

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn sphinx_agent_prunes_stale_graph_records_using_retention_window() {
        let root = temp_root("retention-gc");
        let mut config = load_config(config_path()).unwrap();
        configure_memory(&mut config, &root);
        config.memory.knowledge_retention_days = 1;

        let two_days_secs = 2 * 86_400;
        let stale_timestamp = 1_800_800_000;
        let fresh_timestamp = stale_timestamp + two_days_secs;

        let mut agent = SphinxAgent::new(
            AgentId::new("sphinx", "primary"),
            config_path(),
            config.clone(),
            substrate(&config),
        )
        .expect("sphinx agent should initialize");
        agent
            .tick(&env(
                vec![pheromone_with_context(
                    "evt-stale",
                    stale_timestamp,
                    "host-stale",
                    "alice",
                    "powershell.exe",
                    "198.51.100.7",
                )],
                stale_timestamp + 1,
            ))
            .await
            .expect("stale seed should persist");
        agent
            .tick(&env(
                vec![pheromone_with_context(
                    "evt-fresh",
                    fresh_timestamp,
                    "host-fresh",
                    "bob",
                    "cmd.exe",
                    "198.51.100.8",
                )],
                fresh_timestamp + 1,
            ))
            .await
            .expect("fresh observation should trigger prune");

        let store = FileKnowledgeGraphStore::open(root.join("knowledge-graph")).unwrap();
        let snapshot = store
            .load_snapshot()
            .expect("snapshot should load")
            .expect("snapshot should exist");

        assert_eq!(snapshot.processed_observation_ids.len(), 1);
        assert!(snapshot.processed_observation_ids.contains("evt-fresh"));
        assert!(!snapshot.processed_observation_ids.contains("evt-stale"));
        assert!(snapshot.nodes.iter().all(|node| {
            let encoded = serde_json::to_string(node).expect("node should encode");
            !encoded.contains("host-stale") && !encoded.contains("evt-stale")
        }));
        assert!(snapshot.edges.iter().all(|edge| {
            let encoded = serde_json::to_string(edge).expect("edge should encode");
            !encoded.contains("host_stale") && !encoded.contains("evt_stale")
        }));

        let node_paths = fs::read_dir(root.join("knowledge-graph/nodes"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(node_paths.iter().all(|name| !name.contains("stale")));

        let _ = fs::remove_dir_all(root);
    }
}
