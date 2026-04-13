use crate::tom_agent::{GovernanceDecision, GovernancePolicy};
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::collections::BTreeSet;
use std::sync::Arc;
use swarm_core::agent::{
    AgentFinding, AgentHealth, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmEvent,
    SwarmMode,
};
use swarm_core::config::{
    ResponsePlaybookBranchResolution, ResponsePlaybookConfig, ResponsePlaybookRule,
};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{AgentId, HuntId, ResponseAction, SwarmAction};
use swarm_policy::static_gate::scope_for_response_action;

pub struct PounceAgent {
    id: AgentId,
    verifying_key: VerifyingKey,
    playbook: ResponsePlaybookConfig,
    role: AgentRole,
    health: AgentHealth,
    current_session: Option<PounceSession>,
    handled_actions: BTreeSet<HandledActionKey>,
    governance_policy: Arc<GovernancePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PounceSession {
    mode: SwarmMode,
    transition_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HandledActionKey {
    hunt_id: String,
    action_kind: String,
    scope: Option<String>,
}

#[derive(Debug, Clone)]
struct PlaybookMatch {
    hunt_id: HuntId,
    evidence: serde_json::Value,
    actions: Vec<ResponseAction>,
}

#[derive(Debug, Clone)]
struct MatchedPlaybookBranch {
    index: usize,
    name: Option<String>,
}

impl PounceAgent {
    pub fn new(id: AgentId, playbook: ResponsePlaybookConfig) -> Self {
        Self::new_with_signing_key(id, SigningKey::generate(&mut OsRng), playbook)
    }

    pub fn new_with_signing_key(
        id: AgentId,
        signing_key: SigningKey,
        playbook: ResponsePlaybookConfig,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();

        Self {
            id,
            verifying_key,
            playbook,
            role: AgentRole::Pouncer,
            health: AgentHealth::Healthy,
            current_session: None,
            handled_actions: BTreeSet::new(),
            governance_policy: Arc::new(GovernancePolicy::default()),
        }
    }

    pub fn with_governance_policy(mut self, governance_policy: Arc<GovernancePolicy>) -> Self {
        self.governance_policy = governance_policy;
        self
    }

    fn sync_session(&mut self, env: &SwarmEnvironment) {
        if env.mode == SwarmMode::Normal {
            self.current_session = None;
            self.handled_actions.clear();
            return;
        }

        let session = PounceSession {
            mode: env.mode,
            transition_at: env.mode_transition_at(),
        };
        if self.current_session.as_ref() != Some(&session) {
            self.current_session = Some(session);
            self.handled_actions.clear();
        }
    }

    fn select_match(&self, env: &SwarmEnvironment) -> Option<PlaybookMatch> {
        let session_start = env.mode_transition_at();

        for rule in &self.playbook.rules {
            let mut deposits = env
                .pheromones
                .iter()
                .filter(|deposit| {
                    deposit.threat_class == rule.threat_class
                        && deposit.severity == rule.severity
                        && deposit.confidence >= rule.min_confidence
                        && deposit.confidence <= rule.max_confidence
                        && match session_start {
                            Some(started_at) => deposit.timestamp >= started_at,
                            None => true,
                        }
                })
                .collect::<Vec<_>>();
            deposits.sort_by(|left, right| {
                right
                    .timestamp
                    .cmp(&left.timestamp)
                    .then_with(|| right.confidence.total_cmp(&left.confidence))
                    .then_with(|| extract_lineage_id(left).cmp(extract_lineage_id(right)))
            });

            let Some(deposit) = deposits.into_iter().next() else {
                continue;
            };
            let Some(hunt_id) = extract_hunt_id(deposit) else {
                continue;
            };
            let Some(resolution) = rule.resolve(
                &deposit.threat_class,
                deposit.severity,
                deposit.confidence,
                env.mode,
            ) else {
                continue;
            };

            return Some(PlaybookMatch {
                hunt_id: HuntId(hunt_id.to_string()),
                evidence: build_request_evidence(
                    deposit,
                    env,
                    rule,
                    hunt_id,
                    resolution
                        .branch
                        .as_ref()
                        .map(MatchedPlaybookBranch::from_resolution),
                ),
                actions: resolution.actions,
            });
        }

        None
    }
}

#[async_trait]
impl SwarmAgent for PounceAgent {
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
        self.sync_session(env);
        if env.mode == SwarmMode::Normal {
            return Ok(Vec::new());
        }

        let Some(playbook_match) = self.select_match(env) else {
            return Ok(Vec::new());
        };

        let mut actions = Vec::new();
        for action in playbook_match.actions {
            let scope = scope_for_response_action(&action);
            if scope
                .as_deref()
                .is_some_and(|value| peer_findings_cover_scope(&env.peer_findings, value))
            {
                continue;
            }

            let handled_key = HandledActionKey {
                hunt_id: playbook_match.hunt_id.0.clone(),
                action_kind: action.kind().to_string(),
                scope: scope.clone(),
            };
            if !self.handled_actions.insert(handled_key) {
                continue;
            }

            let mut evidence = playbook_match.evidence.clone();
            match self.governance_policy.can_act(&action) {
                GovernanceDecision::Allow {
                    receipt,
                    contingency_lease,
                } => {
                    if let Some(receipt) = receipt
                        && let Ok(receipt_value) = serde_json::to_value(receipt)
                    {
                        evidence["governance_receipt"] = receipt_value;
                    }
                    if let Some(contingency_lease) = contingency_lease
                        && let Ok(lease_value) = serde_json::to_value(contingency_lease)
                    {
                        evidence["contingency_lease"] = lease_value;
                    }
                    actions.push(SwarmAction::RequestResponse {
                        hunt_id: playbook_match.hunt_id.clone(),
                        action,
                        evidence,
                    })
                }
                GovernanceDecision::Veto {
                    governing_agent_id,
                    reason,
                    receipt,
                } => {
                    if let Some(receipt) = receipt
                        && let Ok(receipt_value) = serde_json::to_value(receipt)
                    {
                        evidence["governance_receipt"] = receipt_value;
                    }
                    actions.push(SwarmAction::GovernanceVeto {
                        hunt_id: playbook_match.hunt_id.clone(),
                        action,
                        evidence,
                        governing_agent_id,
                        reason,
                    })
                }
            }
        }

        Ok(actions)
    }

    fn health(&self) -> AgentHealth {
        self.health
    }
}

fn peer_findings_cover_scope(peer_findings: &[AgentFinding], scope: &str) -> bool {
    let needle = format!("scope={scope}");
    peer_findings.iter().any(|finding| {
        finding.kind == "request_response"
            && (finding.summary.contains(&needle) || finding.summary.contains(scope))
    })
}

fn extract_hunt_id(deposit: &PheromoneDeposit) -> Option<&str> {
    deposit
        .indicator
        .get("hunt_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            deposit
                .indicator
                .get("event_id")
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| {
            deposit
                .indicator
                .get("evidence")
                .and_then(|value| value.get("hunt_id"))
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| {
            deposit
                .indicator
                .get("evidence")
                .and_then(|value| value.get("event_id"))
                .and_then(serde_json::Value::as_str)
        })
}

fn extract_lineage_id(deposit: &PheromoneDeposit) -> &str {
    extract_hunt_id(deposit).unwrap_or("")
}

fn build_request_evidence(
    deposit: &PheromoneDeposit,
    env: &SwarmEnvironment,
    rule: &ResponsePlaybookRule,
    hunt_id: &str,
    branch: Option<MatchedPlaybookBranch>,
) -> serde_json::Value {
    serde_json::json!({
        "lineage": {
            "hunt_id": hunt_id,
            "event_id": deposit.indicator.get("event_id").cloned(),
            "indicator": deposit.indicator.clone(),
        },
        "escalation": {
            "mode": env.mode,
            "mode_transition_at": env.mode_transition_at(),
            "timestamp": env.now,
            "threat_class": deposit.threat_class,
            "severity": deposit.severity,
            "confidence": deposit.confidence,
        },
        "playbook_match": {
            "threat_class": rule.threat_class,
            "severity": rule.severity,
            "min_confidence": rule.min_confidence,
            "max_confidence": rule.max_confidence,
            "branch": branch.map(|matched| serde_json::json!({
                "index": matched.index,
                "name": matched.name,
            })),
        }
    })
}

impl MatchedPlaybookBranch {
    fn from_resolution(resolution: &ResponsePlaybookBranchResolution) -> Self {
        Self {
            index: resolution.index,
            name: resolution.name.clone(),
        }
    }
}
