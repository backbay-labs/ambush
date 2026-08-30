#![allow(clippy::unwrap_used, clippy::expect_used)]

use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{Json, Router, routing::post};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;
use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_agents::pounce_agent::PounceAgent;
use swarm_agents::tom_agent::{
    ContingencyLease, GovernanceDecision, GovernancePolicy, GovernancePolicyConfig,
};
use swarm_consensus::{
    ConsensusCommit, ConsensusCommittee, ConsensusGovernanceReceipt, ConsensusProposal,
    GovernanceReceiptDecision,
};
use swarm_core::ThreatClass;
use swarm_core::agent::{
    AgentHealth, AgentHealthEntry, AgentRole, SwarmAgent, SwarmEnvironment, SwarmError, SwarmMode,
    SwarmModeState,
};
use swarm_core::config::{
    CircuitBreakerConfig, PheromoneBackendConfig, PheromoneConfig, PolicyConfig,
    ResponseAdapterConfig, ResponsePlaybookConfig, ResponsePlaybookRule, RetryConfig, RuntimeMode,
    SwarmConfig, WebhookConfig,
};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity, SwarmAction};
use swarm_crypto::{Ed25519Signer, canonical_json_bytes, sha256_hex};
use swarm_governance::GovernanceAuthority;
use swarm_guard::{
    Guard, GuardAction, GuardContext, GuardPipeline, GuardResult, Severity as GuardSeverity,
};
use swarm_pheromone::{
    ConfiguredPheromoneSubstrate, InMemoryPheromoneSubstrate, PheromoneSubstrate,
};
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::governance::GovernedHumanAuthorizationHold;
use swarm_policy::static_gate::{StaticApprovalGate, scope_for_response_action};
use swarm_policy::{
    ActionRequest, ApprovalContext, ApprovalError, ApprovalGate, CapabilityLease, PolicyDecision,
    PolicyVerdict,
};
use swarm_response::containment::{
    ContainmentLeaseStore, ContainmentTtl, MemoryContainmentLeaseStore,
};
use swarm_response::{
    DispatchingExecutor, ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt,
    ResponseStatus,
};
use swarm_runtime::{
    RuntimeError, SwarmRuntime,
    approval::{
        ApprovalReceiptPackReport, DefaultApprovalHarness, ThresholdRule, build_receipt_pack,
        evaluate_verdict,
    },
    config::load_config,
    dispatcher::{
        AgentDispatcher, AgentDispatcherConfig, DispatcherPolicyPermit, DispatcherPolicyPreflight,
        GovernanceVetoRoute, GovernedHumanHoldRoute, HumanApprovalChallenge,
        HumanApprovalResumeDispatcher, RequestResponseRouter, RoutedActionRequest,
    },
    escalation::ConcentrationMonitor,
};
use swarm_spine::{AuditResponseRecord, AuditTrail};
use swarm_whisker::DetectionFinding;
use tokio::net::TcpListener;
use tokio::sync::watch;

struct FixedGuard {
    allow: bool,
    name: &'static str,
    message: &'static str,
}

impl Guard for FixedGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }

    fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if self.allow {
            GuardResult::allow(self.name)
        } else {
            GuardResult::block(self.name, GuardSeverity::Critical, self.message)
        }
    }
}

struct CountingGuard {
    calls: Arc<AtomicUsize>,
}

impl Guard for CountingGuard {
    fn name(&self) -> &str {
        "counting_guard"
    }

    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }

    fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        GuardResult::allow(self.name())
    }
}

#[derive(Clone, Copy)]
enum LeaseExpiry {
    Relative(i64),
    Absolute(i64),
}

#[derive(Clone)]
struct CountingApprovalGate {
    verdict: PolicyVerdict,
    evaluate_calls: Arc<AtomicUsize>,
    issue_lease_calls: Arc<AtomicUsize>,
    lease_expiry: LeaseExpiry,
}

impl CountingApprovalGate {
    fn allow_with_ttl(ttl_ms: i64) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let evaluate_calls = Arc::new(AtomicUsize::new(0));
        let issue_lease_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                verdict: PolicyVerdict::Allow,
                evaluate_calls: Arc::clone(&evaluate_calls),
                issue_lease_calls: Arc::clone(&issue_lease_calls),
                lease_expiry: LeaseExpiry::Relative(ttl_ms),
            },
            evaluate_calls,
            issue_lease_calls,
        )
    }

    fn allow_with_expiry(expires_at_ms: i64) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let evaluate_calls = Arc::new(AtomicUsize::new(0));
        let issue_lease_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                verdict: PolicyVerdict::Allow,
                evaluate_calls: Arc::clone(&evaluate_calls),
                issue_lease_calls: Arc::clone(&issue_lease_calls),
                lease_expiry: LeaseExpiry::Absolute(expires_at_ms),
            },
            evaluate_calls,
            issue_lease_calls,
        )
    }

    fn require_human_with_ttl(ttl_ms: i64) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let evaluate_calls = Arc::new(AtomicUsize::new(0));
        let issue_lease_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                verdict: PolicyVerdict::RequireHuman,
                evaluate_calls: Arc::clone(&evaluate_calls),
                issue_lease_calls: Arc::clone(&issue_lease_calls),
                lease_expiry: LeaseExpiry::Relative(ttl_ms),
            },
            evaluate_calls,
            issue_lease_calls,
        )
    }

    fn deny_with_ttl(ttl_ms: i64) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let evaluate_calls = Arc::new(AtomicUsize::new(0));
        let issue_lease_calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                verdict: PolicyVerdict::Deny,
                evaluate_calls: Arc::clone(&evaluate_calls),
                issue_lease_calls: Arc::clone(&issue_lease_calls),
                lease_expiry: LeaseExpiry::Relative(ttl_ms),
            },
            evaluate_calls,
            issue_lease_calls,
        )
    }
}

impl ApprovalGate for CountingApprovalGate {
    fn evaluate(
        &self,
        _request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.evaluate_calls.fetch_add(1, Ordering::SeqCst);
        let decision = match self.verdict {
            PolicyVerdict::Deny => PolicyDecision::deny_with_rule("test.deny", "denied in test"),
            PolicyVerdict::Allow => {
                PolicyDecision::allow_with_rule("test.allow", "allowed in test")
            }
            PolicyVerdict::RequireHuman => {
                PolicyDecision::require_human_with_rule("test.human", "held in test")
            }
        };
        Ok(decision)
    }

    fn issue_lease(
        &self,
        request: &ActionRequest,
        context: &ApprovalContext,
    ) -> Result<CapabilityLease, ApprovalError> {
        self.issue_lease_calls.fetch_add(1, Ordering::SeqCst);
        let expires_at_ms = match self.lease_expiry {
            LeaseExpiry::Relative(ttl_ms) => context.now_ms + ttl_ms,
            LeaseExpiry::Absolute(expires_at_ms) => expires_at_ms,
        };
        Ok(CapabilityLease {
            capability_id: format!("lease:{}:{}", request.hunt_id.0, context.now_ms),
            expires_at_ms,
            action: request.action.kind().to_string(),
            scope: scope_for_response_action(&request.action),
        })
    }
}

#[derive(Clone, Default)]
struct RecordingExecutor {
    calls: Arc<AtomicUsize>,
    modes: Arc<Mutex<Vec<ExecutionMode>>>,
}

#[async_trait]
impl ResponseExecutor for RecordingExecutor {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.modes.lock().unwrap().push(mode);
        Ok(ResponseReceipt {
            receipt_id: format!("receipt:{}:{}", request.hunt_id.0, lease.capability_id),
            action: request.action.kind().to_string(),
            mode,
            status: match mode {
                ExecutionMode::DryRun => ResponseStatus::Simulated,
                ExecutionMode::Enforced => ResponseStatus::Executed,
            },
            summary: "recorded in test".to_string(),
            details: serde_json::json!({
                "lineage": request.evidence.get("lineage").cloned(),
                "requested_by": request.requested_by,
                "scope": lease.scope,
            }),
            audit: Default::default(),
        })
    }
}

struct OneShotRequestAgent {
    id: AgentId,
    verifying_key: VerifyingKey,
    actions: Option<Vec<SwarmAction>>,
}

impl OneShotRequestAgent {
    fn new(id: AgentId, actions: Vec<SwarmAction>) -> Self {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        Self {
            id,
            verifying_key: signing_key.verifying_key(),
            actions: Some(actions),
        }
    }
}

#[async_trait]
impl SwarmAgent for OneShotRequestAgent {
    fn identity(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn id(&self) -> &AgentId {
        &self.id
    }

    fn role(&self) -> AgentRole {
        AgentRole::Pouncer
    }

    fn observe_event(&mut self, _event: &swarm_core::agent::SwarmEvent) -> Result<(), SwarmError> {
        Ok(())
    }

    async fn tick(&mut self, _env: &SwarmEnvironment) -> Result<Vec<SwarmAction>, SwarmError> {
        Ok(self.actions.take().unwrap_or_default())
    }

    fn health(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}

struct RuntimeBackedRouter<P, E> {
    runtime: Arc<SwarmRuntime<P, E>>,
    context: ApprovalContext,
    audits: Arc<Mutex<Vec<AuditTrail>>>,
    approval_harness: DefaultApprovalHarness,
    human_voter: Ed25519Signer,
    trusted_human_packs: Arc<Mutex<BTreeMap<String, ApprovalReceiptPackReport>>>,
    fail_routes_remaining: Arc<AtomicUsize>,
}

impl<P, E> RuntimeBackedRouter<P, E> {
    fn new(
        runtime: Arc<SwarmRuntime<P, E>>,
        context: ApprovalContext,
        audits: Arc<Mutex<Vec<AuditTrail>>>,
    ) -> Self {
        let approval_root = PathBuf::from(temp_jsonl_path("human-approvals"));
        Self {
            runtime,
            context,
            audits,
            approval_harness: DefaultApprovalHarness::from_path(
                approval_root.join("config"),
                approval_root.join("verdicts"),
                approval_root.join("packs"),
                approval_root.join("sets"),
                approval_root.join("ledgers"),
            )
            .unwrap(),
            human_voter: Ed25519Signer::from_secret_material("dispatcher-human-voter"),
            trusted_human_packs: Arc::new(Mutex::new(BTreeMap::new())),
            fail_routes_remaining: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn build_human_pack(
        &self,
        set_id: &str,
        approve: bool,
        evaluated_at_ms: i64,
    ) -> ApprovalReceiptPackReport {
        let voter_id = format!("swarm:ed25519:{}", self.human_voter.public_key_hex());
        let has_vote = self
            .approval_harness
            .list_ledgers(Some(set_id))
            .unwrap()
            .ledgers
            .first()
            .is_some_and(|ledger| ledger.vote_count > 0);
        if approve && !has_vote {
            self.approval_harness
                .append_vote(set_id, &voter_id, &self.human_voter)
                .unwrap();
        }
        let set = self
            .approval_harness
            .load_approval_set(set_id)
            .unwrap()
            .unwrap()
            .report;
        let ledger_id = self
            .approval_harness
            .list_ledgers(Some(&set.set_id))
            .unwrap()
            .ledgers[0]
            .ledger_id
            .clone();
        let ledger = self
            .approval_harness
            .load_ledger(&ledger_id)
            .unwrap()
            .unwrap()
            .report;
        let verdict = evaluate_verdict(&set, &ledger, evaluated_at_ms).unwrap();
        let signer = Ed25519Signer::from_secret_material("dispatcher-human-pack-signer");
        let pack = build_receipt_pack(
            &set,
            &ledger,
            &verdict,
            vec![set.promotion_evidence_ref.clone()],
            &signer,
            "dispatcher-human-pack-signer",
            evaluated_at_ms.saturating_add(1),
        )
        .unwrap();
        self.trusted_human_packs
            .lock()
            .unwrap()
            .insert(pack.pack_id.clone(), pack.clone());
        pack
    }

    fn approve_pending_human_hold(&self) -> ApprovalReceiptPackReport {
        let set_id = self
            .approval_harness
            .list_approval_sets()
            .unwrap()
            .sets
            .into_iter()
            .next()
            .expect("dispatcher persisted a human approval set")
            .set_id;
        self.build_human_pack(&set_id, true, unix_now_ms())
    }
}

#[async_trait]
impl<P, E> RequestResponseRouter for RuntimeBackedRouter<P, E>
where
    P: ApprovalGate + Send + Sync + 'static,
    E: ResponseExecutor + Send + Sync + 'static,
{
    async fn preflight_request(
        &self,
        request: ActionRequest,
    ) -> Result<DispatcherPolicyPreflight, RuntimeError> {
        let detection = detection_from_request(&request);
        self.runtime
            .preflight_dispatcher_request(request, detection, self.context.clone())
    }

    async fn route_preflight_audit(&self, audit: AuditTrail) -> Result<AuditTrail, RuntimeError> {
        self.audits.lock().unwrap().push(audit.clone());
        Ok(audit)
    }

    async fn route_request(
        &self,
        admitted: RoutedActionRequest,
    ) -> Result<AuditTrail, RuntimeError> {
        if self
            .fail_routes_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(RuntimeError::GovernanceAuthorization(
                "test router refused owned admission".into(),
            ));
        }
        let audit = self
            .runtime
            .audit_authorize_and_execute_admitted(admitted)
            .await?;
        self.audits.lock().unwrap().push(audit.clone());
        Ok(audit)
    }

    async fn route_human_hold(
        &self,
        route: GovernedHumanHoldRoute,
    ) -> Result<HumanApprovalChallenge, RuntimeError> {
        let voter_id = format!("swarm:ed25519:{}", self.human_voter.public_key_hex());
        let record = self
            .approval_harness
            .create_approval_set(
                vec![voter_id],
                ThresholdRule::AtLeast { required: 1 },
                &route.hold().approval_evidence_ref(),
            )
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))?;
        let report = self
            .approval_harness
            .load_approval_set(&record.set_id)
            .map_err(|error| RuntimeError::GovernanceAuthorization(error.to_string()))?
            .unwrap();
        self.audits
            .lock()
            .unwrap()
            .push(route.initial_audit().clone());
        route.challenge_for_persisted_set(&report.report)
    }

    async fn load_persisted_human_approval(
        &self,
        pack_id: &str,
    ) -> Result<Option<ApprovalReceiptPackReport>, RuntimeError> {
        Ok(self
            .trusted_human_packs
            .lock()
            .unwrap()
            .get(pack_id)
            .cloned())
    }

    async fn restore_human_preflight(
        &self,
        hold: &GovernedHumanAuthorizationHold,
        approval_pack_id: &str,
    ) -> Result<DispatcherPolicyPermit, RuntimeError> {
        let detection = detection_from_request(&hold.request);
        let context = self.context.clone();
        self.runtime
            .restore_human_dispatcher_preflight(hold, detection, context, approval_pack_id)
    }

    async fn route_governance_veto(
        &self,
        veto: GovernanceVetoRoute,
    ) -> Result<AuditTrail, RuntimeError> {
        let detection = detection_from_request(veto.request());
        let audit = self
            .runtime
            .audit_admitted_governance_veto(&detection, &veto, &self.context);
        self.audits.lock().unwrap().push(audit.clone());
        Ok(audit)
    }
}

fn repo_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
}

/// A per-run dead-letter journal outside the repository.
///
/// `dead_letter_path` defaults to the cwd-relative `./dead-letter.jsonl`, and
/// `cargo test`'s cwd is the crate root, so a test that takes the default
/// appends to the checked-out `crates/swarm-runtime/dead-letter.jsonl`.
fn temp_jsonl_path(label: &str) -> String {
    static TEMP_PATH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir()
        .join(format!(
            "swarm-runtime-dispatch-{label}-{}-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            TEMP_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ))
        .display()
        .to_string()
}

fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn sample_config() -> Result<SwarmConfig, Box<dyn Error>> {
    Ok(load_config(repo_config_path())?)
}

fn sample_context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: vec!["receipt-1".to_string()],
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}

fn sample_detection() -> DetectionFinding {
    DetectionFinding {
        finding_id: "finding-1".to_string(),
        event_id: "evt-1".to_string(),
        threat_class: ThreatClass::Execution,
        severity: Severity::High,
        confidence: 0.97,
        evidence: serde_json::json!({"signal": "integration-test"}),
        strategy_id: "strategy-1".to_string(),
    }
}

fn sample_request(action: ResponseAction, severity: Severity) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-1".to_string()),
        requested_by: AgentId("whisker-a".to_string()),
        action,
        severity,
        evidence: serde_json::json!({"signal": "integration-test"}),
    }
}

fn test_health_state() -> Arc<ArcSwap<Vec<AgentHealthEntry>>> {
    Arc::new(ArcSwap::from_pointee(Vec::new()))
}

fn test_substrate() -> ConfiguredPheromoneSubstrate {
    ConfiguredPheromoneSubstrate::InMemory(InMemoryPheromoneSubstrate::new(PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: PheromoneBackendConfig::InMemory,
    }))
}

fn phase127_playbook() -> ResponsePlaybookConfig {
    ResponsePlaybookConfig {
        rules: vec![
            ResponsePlaybookRule {
                threat_class: ThreatClass::Execution,
                severity: Severity::High,
                min_confidence: 0.90,
                max_confidence: 1.0,
                actions: vec![ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                }],
                branches: Vec::new(),
            },
            ResponsePlaybookRule {
                threat_class: ThreatClass::CommandAndControl,
                severity: Severity::Critical,
                min_confidence: 0.95,
                max_confidence: 1.0,
                actions: vec![ResponseAction::BlockEgress {
                    target: "203.0.113.10".to_string(),
                }],
                branches: Vec::new(),
            },
        ],
    }
}

fn phase127_pheromone_config() -> PheromoneConfig {
    PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 1.5,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: phase127_playbook(),
        backend: PheromoneBackendConfig::InMemory,
    }
}

fn shared_test_substrate(
    config: PheromoneConfig,
) -> (InMemoryPheromoneSubstrate, ConfiguredPheromoneSubstrate) {
    let substrate = InMemoryPheromoneSubstrate::new(config);
    (
        substrate.clone(),
        ConfiguredPheromoneSubstrate::InMemory(substrate),
    )
}

fn test_mode_state() -> Arc<ArcSwap<SwarmModeState>> {
    Arc::new(ArcSwap::from_pointee(SwarmModeState::new()))
}

fn make_signed_deposit(
    _agent_label: &str,
    seed: u8,
    event_id: &str,
    threat_class: ThreatClass,
    severity: Severity,
    confidence: f64,
    timestamp: i64,
) -> PheromoneDeposit {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({
            "event_id": event_id,
            "hunt_id": event_id,
            "evidence": {
                "event_id": event_id,
                "hunt_id": event_id,
                "host_id": "host-1",
                "sensor": "dispatch_integration"
            }
        }),
        threat_class,
        severity,
        confidence,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: derived_agent_id.clone(),
        agent_identity: derived_agent_id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    let payload = swarm_pheromone::DepositSigningPayload {
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

async fn deposit_execution_alert_pair(
    substrate: &InMemoryPheromoneSubstrate,
    event_id: &str,
    timestamp: i64,
) -> Result<(), Box<dyn Error>> {
    substrate
        .deposit(make_signed_deposit(
            "whisker-a",
            31,
            event_id,
            ThreatClass::Execution,
            Severity::High,
            0.97,
            timestamp,
        ))
        .await?;
    substrate
        .deposit(make_signed_deposit(
            "whisker-b",
            32,
            event_id,
            ThreatClass::Execution,
            Severity::High,
            0.97,
            timestamp,
        ))
        .await?;
    Ok(())
}

fn sample_request_response_action(
    hunt_id: &str,
    event_id: &str,
    action: ResponseAction,
    severity: Severity,
) -> SwarmAction {
    let mut evidence = json!({
        "lineage": {
            "hunt_id": hunt_id,
            "event_id": event_id,
            "indicator": {
                "event_id": event_id,
                "hunt_id": hunt_id,
                "sensor": "dispatch_integration"
            }
        },
        "escalation": {
            "mode": "alert",
            "mode_transition_at": 1_700_000_000,
            "timestamp": 1_700_000_010,
            "threat_class": ThreatClass::Execution,
            "severity": severity,
            "confidence": 0.97
        },
        "playbook_match": {
            "threat_class": ThreatClass::Execution,
            "severity": severity,
            "min_confidence": 0.90,
            "max_confidence": 1.0
        }
    });
    if action.requires_governance_receipt() {
        evidence["governance_receipt"] =
            sample_governance_receipt(&action, GovernanceReceiptDecision::Approve);
    }

    SwarmAction::RequestResponse {
        hunt_id: HuntId(hunt_id.to_string()),
        action,
        evidence,
    }
}

fn sample_governance_veto_action(
    hunt_id: &str,
    event_id: &str,
    action: ResponseAction,
    severity: Severity,
    governing_agent_id: AgentId,
    reason: &str,
) -> SwarmAction {
    let mut evidence = json!({
        "lineage": {
            "hunt_id": hunt_id,
            "event_id": event_id,
            "indicator": {
                "event_id": event_id,
                "hunt_id": hunt_id,
                "sensor": "dispatch_integration"
            }
        },
        "escalation": {
            "mode": "incident",
            "mode_transition_at": 1_700_000_000,
            "timestamp": 1_700_000_010,
            "threat_class": ThreatClass::CommandAndControl,
            "severity": severity,
            "confidence": 0.99
        },
        "playbook_match": {
            "threat_class": ThreatClass::CommandAndControl,
            "severity": severity,
            "min_confidence": 0.95,
            "max_confidence": 1.0
        }
    });
    evidence["governance_receipt"] =
        sample_governance_receipt(&action, GovernanceReceiptDecision::Veto);

    SwarmAction::GovernanceVeto {
        hunt_id: HuntId(hunt_id.to_string()),
        action,
        evidence,
        governing_agent_id,
        reason: reason.to_string(),
    }
}

fn fixture_action_request(agent_id: &AgentId, action: &SwarmAction) -> ActionRequest {
    let (hunt_id, response_action, evidence) = match action {
        SwarmAction::RequestResponse {
            hunt_id,
            action,
            evidence,
        }
        | SwarmAction::GovernanceVeto {
            hunt_id,
            action,
            evidence,
            ..
        } => (hunt_id, action, evidence),
        other => panic!("expected response fixture, got {other:?}"),
    };
    let severity = serde_json::from_value(evidence["escalation"]["severity"].clone())
        .expect("fixture escalation severity must decode");
    ActionRequest {
        hunt_id: hunt_id.clone(),
        requested_by: agent_id.clone(),
        action: response_action.clone(),
        severity,
        evidence: evidence.clone(),
    }
}

fn attach_issued_receipt(
    policy: &GovernancePolicy,
    agent_id: &AgentId,
    mut action: SwarmAction,
    expected_decision: GovernanceReceiptDecision,
) -> SwarmAction {
    let request = fixture_action_request(agent_id, &action);
    let receipt = match (expected_decision, policy.can_act(&request)) {
        (GovernanceReceiptDecision::Approve, GovernanceDecision::Authorize { receipt, .. }) => {
            receipt
        }
        (
            GovernanceReceiptDecision::Veto,
            GovernanceDecision::Veto {
                receipt: Some(receipt),
                ..
            },
        ) => receipt,
        (expected, other) => panic!("expected {expected:?} issuance, got {other:?}"),
    };
    match &mut action {
        SwarmAction::RequestResponse { evidence, .. }
        | SwarmAction::GovernanceVeto { evidence, .. } => {
            evidence["governance_receipt"] = serde_json::to_value(receipt).unwrap();
        }
        other => panic!("expected response fixture, got {other:?}"),
    }
    action
}

/// THE governor key these fixtures speak for.
///
/// `sample_governance_policy` registers it and `sample_governance_receipt` signs
/// with it, so a fixture receipt is signed by a governor the dispatcher's own
/// authority names. That pairing is load bearing since ADR 0011: the dispatcher
/// checks a receipt's signer against the installed authority's governor set, so
/// a fixture that minted an unrelated keypair -- which is what this file did --
/// is now indistinguishable from a forgery, and is asserted to be refused in
/// `destructive_request_response_is_refused_when_the_signer_is_not_a_governor`.
const SAMPLE_GOVERNOR_KEY_BYTES: [u8; 32] = [17; 32];

struct TestGovernance {
    policy: Option<Arc<GovernancePolicy>>,
    authority: Option<GovernanceAuthority>,
    root: PathBuf,
}

impl TestGovernance {
    fn authority(&self) -> GovernanceAuthority {
        self.authority
            .as_ref()
            .expect("test governance authority remains available")
            .clone()
    }
}

impl std::ops::Deref for TestGovernance {
    type Target = GovernancePolicy;

    fn deref(&self) -> &Self::Target {
        self.policy
            .as_deref()
            .expect("test governance policy remains available")
    }
}

impl Drop for TestGovernance {
    fn drop(&mut self) {
        drop(self.authority.take());
        drop(self.policy.take());
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn sample_governance_with_config(
    label: &str,
    config: GovernancePolicyConfig,
    key_bytes: [u8; 32],
) -> TestGovernance {
    static TEMP_PATH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "swarm-dispatch-{label}-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after unix epoch")
            .as_nanos(),
        TEMP_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    let policy = Arc::new(
        GovernancePolicy::initialize_persistence(
            config,
            root.join("governance.json"),
            AgentId::new("tom", "primary"),
            SigningKey::from_bytes(&key_bytes),
        )
        .expect("test governance should initialize signed persistence"),
    );
    let authority = policy
        .authority()
        .expect("persisted test governance should mint authority");
    TestGovernance {
        policy: Some(policy),
        authority: Some(authority),
        root,
    }
}

fn sample_governance_policy() -> TestGovernance {
    sample_governance_with_config(
        "healthy",
        GovernancePolicyConfig::default(),
        SAMPLE_GOVERNOR_KEY_BYTES,
    )
}

fn sample_governance_receipt(
    action: &ResponseAction,
    decision: GovernanceReceiptDecision,
) -> serde_json::Value {
    sample_governance_receipt_signed_by(
        action,
        decision,
        &SigningKey::from_bytes(&SAMPLE_GOVERNOR_KEY_BYTES),
    )
}

fn sample_governance_receipt_signed_by(
    action: &ResponseAction,
    decision: GovernanceReceiptDecision,
    signing_key: &SigningKey,
) -> serde_json::Value {
    let issued_by = AgentId::from_verifying_key(&signing_key.verifying_key());
    let committee = ConsensusCommittee::new(vec![issued_by.clone()], 0).unwrap();
    let proposal_payload = json!({
        "action": action,
        "decision": decision,
    });
    let commit = ConsensusCommit {
        height: 1,
        round: 0,
        committee_id: committee.committee_id().to_string(),
        proposal: ConsensusProposal {
            proposal_id: sha256_hex(&canonical_json_bytes(&proposal_payload).unwrap()),
            payload: proposal_payload,
        },
        prevote_tally: 1,
        precommit_tally: 1,
        commit_hash: sha256_hex(
            &canonical_json_bytes(&json!({
                "action": action,
                "decision": decision,
                "committee_id": committee.committee_id(),
            }))
            .unwrap(),
        ),
    };
    serde_json::to_value(
        ConsensusGovernanceReceipt::issue(
            &commit,
            "dispatch-integration-bootstrap",
            &committee,
            decision,
            issued_by,
            signing_key,
            1_700_000_000_010,
        )
        .unwrap(),
    )
    .unwrap()
}

fn sample_partition_governance_policy_with_ttl(ttl_ms: i64) -> TestGovernance {
    let base_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_millis() as i64;
    let policy = sample_governance_with_config(
        "partitioned",
        GovernancePolicyConfig {
            contingency_lease_ttl_ms: ttl_ms,
            contingency_blast_radius_cap: 1,
        },
        [23; 32],
    );
    policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms);
    policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "tom-primary".to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }],
        base_ms + 10_000,
    );
    policy
}

fn sample_partition_governance_policy() -> TestGovernance {
    sample_partition_governance_policy_with_ttl(60_000)
}

fn sample_partition_request_response_action(
    hunt_id: &str,
    event_id: &str,
    action: ResponseAction,
    severity: Severity,
    lease: &ContingencyLease,
) -> SwarmAction {
    let mut evidence = json!({
        "lineage": {
            "hunt_id": hunt_id,
            "event_id": event_id,
            "indicator": {
                "event_id": event_id,
                "hunt_id": hunt_id,
                "sensor": "dispatch_integration"
            }
        },
        "escalation": {
            "mode": "incident",
            "mode_transition_at": 1_700_000_000,
            "timestamp": 1_700_000_010,
            "threat_class": ThreatClass::CommandAndControl,
            "severity": severity,
            "confidence": 0.99
        },
        "playbook_match": {
            "threat_class": ThreatClass::CommandAndControl,
            "severity": severity,
            "min_confidence": 0.95,
            "max_confidence": 1.0
        },
        "contingency_lease": lease,
        "governance_receipt": lease.governance_receipt.clone(),
    });
    if !action.requires_governance_receipt() {
        evidence
            .as_object_mut()
            .expect("evidence must be object")
            .remove("contingency_lease");
    }
    SwarmAction::RequestResponse {
        hunt_id: HuntId(hunt_id.to_string()),
        action,
        evidence,
    }
}

fn detection_from_request(request: &ActionRequest) -> DetectionFinding {
    let event_id = request
        .evidence
        .get("lineage")
        .and_then(|value| value.get("event_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(request.hunt_id.0.as_str())
        .to_string();
    let threat_class = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("threat_class"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(ThreatClass::Execution);
    let severity = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("severity"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or(request.severity);
    let confidence = request
        .evidence
        .get("escalation")
        .and_then(|value| value.get("confidence"))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(1.0);

    DetectionFinding {
        finding_id: format!("pounceagent:{event_id}"),
        event_id,
        threat_class,
        severity,
        confidence,
        evidence: request.evidence.clone(),
        strategy_id: "pounce_agent".to_string(),
    }
}

async fn spawn_delayed_webhook(
    delay_ms: u64,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let delay = Duration::from_millis(delay_ms);
    let app = Router::new().route(
        "/",
        post(move || async move {
            tokio::time::sleep(delay).await;
            Json(serde_json::json!({"ok": true}))
        }),
    );

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok((format!("http://{addr}/"), handle))
}

#[tokio::test]
async fn dispatch_sandbox_via_config_records_success_receipt() -> Result<(), Box<dyn Error>> {
    let mut config = sample_config()?;
    config.runtime.mode = RuntimeMode::DetectOnly;
    config.response_adapter = ResponseAdapterConfig::Sandbox;

    let runtime = SwarmRuntime::new(
        config.runtime.mode,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(config.response_adapter.clone(), None)?,
    );
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(report.response_attempted);
    assert!(report.response_succeeded);

    let AuditResponseRecord::Success(receipt) = &report.audit.response else {
        panic!("expected success receipt, got {:?}", report.audit.response);
    };
    assert_eq!(receipt.mode, ExecutionMode::DryRun);
    assert_eq!(receipt.status, ResponseStatus::Simulated);
    Ok(())
}

#[tokio::test]
async fn guard_blocks_dispatched_executor_before_execution() -> Result<(), Box<dyn Error>> {
    let runtime = SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None)?,
    )
    .with_guard_pipeline(GuardPipeline::new(vec![Box::new(FixedGuard {
        allow: false,
        name: "fixed_guard",
        message: "guard blocked",
    })]));
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(!report.response_attempted);
    assert!(!report.response_succeeded);
    assert!(matches!(
        report.audit.response,
        AuditResponseRecord::GuardRejected { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn policy_deny_skips_dispatched_executor() -> Result<(), Box<dyn Error>> {
    let runtime = SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None)?,
    );
    let request = sample_request(
        ResponseAction::IsolateHost {
            host_id: "host-1".to_string(),
        },
        Severity::Low,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(!report.response_attempted);
    assert!(!report.response_succeeded);
    assert!(matches!(
        report.audit.response,
        AuditResponseRecord::Skipped { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn timeout_from_dispatched_webhook_records_failure() -> Result<(), Box<dyn Error>> {
    let (url, server) = spawn_delayed_webhook(75).await?;

    let runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(
            ResponseAdapterConfig::Webhook {
                config: WebhookConfig {
                    url,
                    timeout_ms: 10,
                    channel: None,
                    auth_token: None,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: temp_jsonl_path("webhook"),
                },
            },
            None,
        )?,
    );
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::Medium,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    server.abort();

    assert!(report.response_attempted);
    assert!(!report.response_succeeded);

    let AuditResponseRecord::Failure(failure) = &report.audit.response else {
        panic!("expected failure record, got {:?}", report.audit.response);
    };
    assert!(failure.message.contains("timed out"));
    assert_eq!(failure.details["status"], serde_json::json!("timeout"));
    Ok(())
}

#[tokio::test]
async fn expanded_response_action_routes_through_runtime_executor() -> Result<(), Box<dyn Error>> {
    let runtime = SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(ResponseAdapterConfig::Sandbox, None)?,
    );
    let request = sample_request(
        ResponseAction::TriggerEdrScan {
            host_id: "host-22".to_string(),
            scan_profile: "memory_quick".to_string(),
        },
        Severity::Medium,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(report.response_attempted);
    assert!(report.response_succeeded);
    let AuditResponseRecord::Success(receipt) = &report.audit.response else {
        panic!("expected success receipt, got {:?}", report.audit.response);
    };
    assert_eq!(receipt.action, "trigger_edr_scan");
    assert_eq!(receipt.status, ResponseStatus::Executed);
    assert_eq!(receipt.details["scope"], serde_json::json!("host-22"));
    Ok(())
}

#[tokio::test]
async fn unsupported_webhook_action_fails_closed_in_runtime_audit() -> Result<(), Box<dyn Error>> {
    let runtime = SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        StaticApprovalGate::default(),
        DispatchingExecutor::from_config(
            ResponseAdapterConfig::Webhook {
                config: WebhookConfig {
                    url: "http://127.0.0.1:1/".to_string(),
                    timeout_ms: 50,
                    channel: None,
                    auth_token: None,
                    retry: RetryConfig::default(),
                    circuit_breaker: CircuitBreakerConfig::default(),
                    dead_letter_path: temp_jsonl_path("webhook"),
                },
            },
            None,
        )?,
    )
    // `terminate_user_session` is a containment, and an enforced containment
    // with no lease store is now refused BEFORE the adapter is reached. This
    // test is about the ADAPTER's unsupported-action refusal, so the lease store
    // has to be present for that refusal to be the one under test.
    .with_containment_store(
        Arc::new(MemoryContainmentLeaseStore::new()),
        ContainmentTtl::from_config_ms(900_000).unwrap(),
    );
    let request = sample_request(
        ResponseAction::TerminateUserSession {
            host_id: "host-22".to_string(),
            session_id: "session-9".to_string(),
        },
        Severity::Medium,
    );
    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert!(report.response_attempted);
    assert!(!report.response_succeeded);
    let AuditResponseRecord::Failure(failure) = &report.audit.response else {
        panic!("expected failure receipt, got {:?}", report.audit.response);
    };
    assert!(failure.message.contains("does not support action"));
    assert_eq!(failure.details["status"], serde_json::json!("failed"));
    assert_eq!(
        failure.details["details"]["adapter"],
        serde_json::json!("webhook")
    );
    Ok(())
}

#[tokio::test]
async fn request_response_routes_through_authorize_and_execute() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let guard_calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(
        SwarmRuntime::new(RuntimeMode::LiveResponse, gate, executor.clone()).with_guard_pipeline(
            GuardPipeline::new(vec![Box::new(CountingGuard {
                calls: Arc::clone(&guard_calls),
            })]),
        ),
    );
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-route-1",
            "evt-route-1",
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(guard_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].hunt_id, "hunt-route-1");
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert_eq!(receipt.mode, ExecutionMode::Enforced);
    assert_eq!(receipt.status, ResponseStatus::Executed);
    Ok(())
}

#[tokio::test]
async fn destructive_request_response_persists_governance_receipt() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "primary");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governance-1",
            "evt-governance-1",
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    // The authority that NAMES the governor whose key signs the fixture
    // receipt. Without it the dispatcher has no trust anchor and refuses the
    // request outright (ADR 0011) -- which is asserted directly, alongside its
    // control, in the test below.
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;

    dispatcher.tick_once().await;

    let audits = audits.lock().unwrap();
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    let governance = receipt
        .audit
        .governance
        .as_ref()
        .expect("governance audit missing");
    assert_eq!(
        governance.reason,
        "consensus approved response action".to_string()
    );
    assert!(
        governance
            .receipt
            .as_ref()
            .is_some_and(serde_json::Value::is_object)
    );
    Ok(())
}

#[tokio::test]
async fn governed_human_hold_keeps_governance_pending_and_executes_nothing()
-> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::require_human_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "human-hold");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-human-hold",
            "evt-governed-human-hold",
            ResponseAction::BlockEgress {
                target: "203.0.113.41".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router.clone())
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].policy.verdict, PolicyVerdict::RequireHuman);
    assert!(matches!(
        audits[0].response,
        AuditResponseRecord::Skipped { .. }
    ));
    drop(audits);

    let approval_set = router
        .approval_harness
        .list_approval_sets()?
        .sets
        .into_iter()
        .next()
        .expect("the dispatcher must persist one approval set");
    let hold = governance.pending_human_authorization(&approval_set.set_id)?;
    assert_eq!(hold.request.hunt_id.0, "hunt-governed-human-hold");
    assert_eq!(hold.policy_decision.verdict, PolicyVerdict::RequireHuman);
    assert_eq!(
        hold.approval_set_id.as_deref(),
        Some(approval_set.set_id.as_str())
    );
    Ok(())
}

#[tokio::test]
async fn governed_policy_deny_does_not_consume_governance_authorization()
-> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::deny_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "governed-policy-deny");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-policy-deny",
            "evt-governed-policy-deny",
            ResponseAction::BlockEgress {
                target: "203.0.113.46".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let request = fixture_action_request(&pounce_id, &action);
    let receipt = request.evidence["governance_receipt"].clone();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;
    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        audits.lock().unwrap()[0].response,
        AuditResponseRecord::Skipped { .. }
    ));
    governance
        .verify_and_consume_action_authorization(&request, &receipt, unix_now_ms())
        .expect("ordinary policy denial must leave governance pending");
    Ok(())
}

#[tokio::test]
async fn governed_human_resume_executes_once_without_re_evaluating_policy()
-> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::require_human_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "human-resume");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-human-resume",
            "evt-governed-human-resume",
            ResponseAction::BlockEgress {
                target: "203.0.113.42".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router.clone())
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;
    dispatcher.tick_once().await;

    let pack = router.approve_pending_human_hold();
    let resume = HumanApprovalResumeDispatcher::new(
        governance.authority(),
        router,
        pack.approval_set.eligible_voters.clone(),
        pack.approval_set.threshold.clone(),
    );
    let audit = resume.resume(pack.clone()).await?;

    assert_eq!(audit.hunt_id, "hunt-governed-human-resume");
    assert!(matches!(audit.response, AuditResponseRecord::Success(_)));
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);

    let replay = resume
        .resume(pack)
        .await
        .expect_err("a human and governance approval pair must be one-shot");
    assert!(replay.to_string().contains("pending human authorization"));
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn fresh_human_approval_cannot_resume_a_stale_governance_receipt()
-> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::require_human_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "stale-governance-resume");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-stale-governance-resume",
            "evt-stale-governance-resume",
            ResponseAction::BlockEgress {
                target: "203.0.113.47".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let issued_at_ms = fixture_action_request(&pounce_id, &action).evidence
        ["governance_receipt"]["payload"]["issued_at_ms"]
        .as_i64()
        .expect("issued governance receipt carries its timestamp");
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router.clone())
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;
    dispatcher.tick_once().await;

    let set_id = router
        .approval_harness
        .list_approval_sets()?
        .sets
        .into_iter()
        .next()
        .expect("dispatcher persisted a human approval set")
        .set_id;
    let resume_at_ms = issued_at_ms.saturating_add(300_002);
    let fresh_pack = router.build_human_pack(&set_id, true, resume_at_ms.saturating_sub(1));
    let hold = governance.pending_human_authorization(&set_id)?;
    swarm_runtime::approval::verify_governed_human_receipt_pack(
        &fresh_pack,
        hold.approval_set_id.as_deref().unwrap(),
        hold.approval_set_digest.as_deref().unwrap(),
        &hold.approval_evidence_ref(),
        hold.created_at_ms,
        resume_at_ms,
    )?;
    let error = governance
        .verify_and_consume_human_authorization(
            &hold.hold_id,
            hold.approval_set_id.as_deref().unwrap(),
            hold.approval_set_digest.as_deref().unwrap(),
            resume_at_ms,
        )
        .expect_err("fresh human approval cannot refresh stale governance");
    assert!(
        error.to_string().contains("governance receipt is stale"),
        "{error}"
    );
    assert!(governance.pending_human_authorization(&set_id).is_ok());
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_human_approval_packs_do_not_consume_governance() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::require_human_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "human-hostile-packs");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-human-hostile",
            "evt-governed-human-hostile",
            ResponseAction::BlockEgress {
                target: "203.0.113.43".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router.clone())
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;
    dispatcher.tick_once().await;

    let set_id = router
        .approval_harness
        .list_approval_sets()?
        .sets
        .into_iter()
        .next()
        .expect("dispatcher persisted a human approval set")
        .set_id;
    let denied = router.build_human_pack(&set_id, false, unix_now_ms());
    let resume = HumanApprovalResumeDispatcher::new(
        governance.authority(),
        router.clone(),
        denied.approval_set.eligible_voters.clone(),
        denied.approval_set.threshold.clone(),
    );
    let denied_error = resume
        .resume(denied)
        .await
        .expect_err("a not-approved verdict must not consume governance");
    assert!(
        denied_error
            .to_string()
            .contains("not an internally valid approval"),
        "{denied_error}"
    );

    let future = router.build_human_pack(&set_id, true, unix_now_ms().saturating_add(600_000));
    let future_error = resume
        .resume(future)
        .await
        .expect_err("a genuine future-dated pack must be checked against the host clock");
    assert!(
        future_error.to_string().contains("future"),
        "{future_error}"
    );

    let valid = router.build_human_pack(&set_id, true, unix_now_ms());
    let mut forged = valid.clone();
    forged.audit_refs.clear();
    let forged_error = resume
        .resume(forged)
        .await
        .expect_err("a caller-mutated pack must not consume governance");
    assert!(forged_error.to_string().contains("persisted artifact"));

    let mut cross_request = valid.clone();
    cross_request.approval_set.promotion_evidence_ref =
        "governance-human-hold:unrelated".to_string();
    let cross_request_error = resume
        .resume(cross_request)
        .await
        .expect_err("a pack substituted across requests must not consume governance");
    assert!(
        cross_request_error
            .to_string()
            .contains("persisted artifact")
    );

    let hold = governance.pending_human_authorization(&set_id)?;
    let stale_error = swarm_runtime::approval::verify_governed_human_receipt_pack(
        &valid,
        hold.approval_set_id.as_deref().unwrap(),
        hold.approval_set_digest.as_deref().unwrap(),
        &hold.approval_evidence_ref(),
        hold.created_at_ms,
        valid.created_at_ms.saturating_add(300_001),
    )
    .expect_err("a stale human approval must not consume governance");
    assert!(stale_error.to_string().contains("stale"));
    let future_error = swarm_runtime::approval::verify_governed_human_receipt_pack(
        &valid,
        hold.approval_set_id.as_deref().unwrap(),
        hold.approval_set_digest.as_deref().unwrap(),
        &hold.approval_evidence_ref(),
        hold.created_at_ms,
        valid.created_at_ms.saturating_sub(30_001),
    )
    .expect_err("a future-dated human approval must not consume governance");
    assert!(future_error.to_string().contains("future"));

    assert!(governance.pending_human_authorization(&set_id).is_ok());
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

    resume.resume(valid).await?;
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn failed_router_burns_owned_human_and_governance_admission() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::require_human_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "human-route-failure");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-human-route-failure",
            "evt-governed-human-route-failure",
            ResponseAction::BlockEgress {
                target: "203.0.113.44".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router.clone())
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;
    dispatcher.tick_once().await;

    let pack = router.approve_pending_human_hold();
    router.fail_routes_remaining.store(1, Ordering::SeqCst);
    let resume = HumanApprovalResumeDispatcher::new(
        governance.authority(),
        router,
        pack.approval_set.eligible_voters.clone(),
        pack.approval_set.threshold.clone(),
    );
    let route_error = resume
        .resume(pack.clone())
        .await
        .expect_err("router failure is reported after durable consumption");
    assert!(route_error.to_string().contains("refused owned admission"));
    let replay_error = resume
        .resume(pack)
        .await
        .expect_err("a failed owned route must not make the admission reusable");
    assert!(
        replay_error
            .to_string()
            .contains("pending human authorization")
    );
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn governed_human_hold_and_consumption_survive_governance_restarts()
-> Result<(), Box<dyn Error>> {
    let persistence_path = temp_jsonl_path("governed-human-restart");
    let governance = Arc::new(GovernancePolicy::initialize_persistence(
        GovernancePolicyConfig::default(),
        &persistence_path,
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&SAMPLE_GOVERNOR_KEY_BYTES),
    )?);
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::require_human_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let pounce_id = AgentId::new("pounce", "human-restart");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-human-restart",
            "evt-governed-human-restart",
            ResponseAction::BlockEgress {
                target: "203.0.113.45".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router.clone())
    .with_governance_authority(
        governance
            .authority()
            .expect("persisted governance should mint an authority"),
    );
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;
    dispatcher.tick_once().await;
    let pack = router.approve_pending_human_hold();
    drop(dispatcher);
    drop(governance);

    let reloaded = Arc::new(GovernancePolicy::with_persistence(
        GovernancePolicyConfig::default(),
        &persistence_path,
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&SAMPLE_GOVERNOR_KEY_BYTES),
    )?);
    let resume = HumanApprovalResumeDispatcher::new(
        reloaded
            .authority()
            .expect("reloaded governance should mint an authority"),
        router.clone(),
        pack.approval_set.eligible_voters.clone(),
        pack.approval_set.threshold.clone(),
    );
    resume.resume(pack.clone()).await?;
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    drop(resume);
    drop(reloaded);

    let consumed_reload = Arc::new(GovernancePolicy::with_persistence(
        GovernancePolicyConfig::default(),
        &persistence_path,
        AgentId::new("tom", "primary"),
        SigningKey::from_bytes(&SAMPLE_GOVERNOR_KEY_BYTES),
    )?);
    let replay = HumanApprovalResumeDispatcher::new(
        consumed_reload
            .authority()
            .expect("consumed governance should mint an authority"),
        router,
        pack.approval_set.eligible_voters.clone(),
        pack.approval_set.threshold.clone(),
    )
    .resume(pack)
    .await
    .expect_err("restart must preserve one-time consumption");
    assert!(replay.to_string().contains("pending human authorization"));
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    drop(consumed_reload);
    let _ = std::fs::remove_file(&persistence_path);
    let _ = std::fs::remove_file(GovernancePolicy::persistence_sequence_path(
        &persistence_path,
    ));
    let _ = std::fs::remove_file(GovernancePolicy::persistence_lock_path(&persistence_path));
    Ok(())
}

#[tokio::test]
async fn governed_dispatcher_admission_reaches_containment_lease_persistence()
-> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let store = Arc::new(MemoryContainmentLeaseStore::new());
    let runtime = Arc::new(
        SwarmRuntime::new(RuntimeMode::LiveResponse, gate, executor.clone())
            .with_containment_store(store.clone(), ContainmentTtl::from_config_ms(60_000)?),
    );
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "primary");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governed-containment",
            "evt-governed-containment",
            ResponseAction::QuarantineFile {
                host_id: "host-7".to_string(),
                file_path: "/tmp/payload.exe".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    let leases = store.open_leases()?;
    assert_eq!(leases.len(), 1);
    assert_eq!(
        leases[0].blast_radius().scope_value,
        "host-7:/tmp/payload.exe"
    );
    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert!(receipt.audit.governance.is_some());
    assert_eq!(leases[0].origin_receipt_id(), receipt.receipt_id);
    Ok(())
}

#[tokio::test]
async fn destructive_request_response_refuses_an_issued_veto_receipt() -> Result<(), Box<dyn Error>>
{
    let (gate, evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let governance = sample_governance_policy();
    governance.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "whisker-primary".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }],
        1_700_000_000_000,
    );
    let pounce_id = AgentId::new("pounce", "primary");
    let action = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governance-route-swap",
            "evt-governance-route-swap",
            ResponseAction::BlockEgress {
                target: "203.0.113.99".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Veto,
    );
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![action])))?;

    dispatcher.tick_once().await;

    assert_eq!(audits.lock().unwrap().len(), 0);
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn destructive_approval_cannot_change_target() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "primary");
    let issued = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governance-binding",
            "evt-governance-binding",
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let SwarmAction::RequestResponse {
        hunt_id, evidence, ..
    } = issued
    else {
        panic!("fixture must be a response request");
    };
    let changed = SwarmAction::RequestResponse {
        hunt_id,
        action: ResponseAction::BlockEgress {
            target: "203.0.113.99".to_string(),
        },
        evidence: evidence.clone(),
    };
    let replay = changed.clone();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        pounce_id,
        vec![changed, replay],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(audits.lock().unwrap().len(), 0);
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn destructive_approval_routes_exactly_once() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        runtime,
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    let pounce_id = AgentId::new("pounce", "primary");
    let issued = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_request_response_action(
            "hunt-governance-once",
            "evt-governance-once",
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Critical,
        ),
        GovernanceReceiptDecision::Approve,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        pounce_id,
        vec![issued.clone(), issued],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(audits.lock().unwrap().len(), 1);
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn raw_live_runtime_refuses_governed_action_before_policy_or_executor()
-> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let store = Arc::new(MemoryContainmentLeaseStore::new());
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, executor.clone())
        .with_containment_store(store, ContainmentTtl::from_config_ms(60_000)?);
    let request = sample_request(
        ResponseAction::BlockEgress {
            target: "203.0.113.120".to_string(),
        },
        Severity::Critical,
    );

    let mut non_live_caller_context = sample_context();
    non_live_caller_context.live_mode = false;
    let error = runtime
        .authorize_and_execute(&request, &non_live_caller_context)
        .await
        .expect_err("raw live entry points must not accept governed actions");

    assert!(
        error
            .to_string()
            .contains("dispatcher governance admission")
    );
    let error = runtime
        .audit_authorize_and_execute(&sample_detection(), &request, &sample_context())
        .await
        .expect_err("raw audited entry point must also refuse");
    assert!(
        error
            .to_string()
            .contains("dispatcher governance admission")
    );
    let error = runtime
        .audit_authorize_and_execute_human_approved_instrumented(
            &sample_detection(),
            &request,
            &sample_context(),
        )
        .await
        .expect_err("human approval must not replace governance admission");
    assert!(
        error
            .to_string()
            .contains("dispatcher governance admission")
    );
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

/// What one destructive request did: `(audits, executor calls, gate evaluations)`.
///
/// The three numbers are read together on purpose. A request that is refused
/// before routing produces zero of each; asserting only on audits would not
/// distinguish "refused" from "executed but unrecorded", which is the shape of
/// defect this repository keeps finding.
async fn run_one_destructive_request(
    governance: Option<TestGovernance>,
    unissued_signing_key: Option<&SigningKey>,
    hunt_id: &str,
) -> Result<(usize, usize, usize), Box<dyn Error>> {
    let (gate, evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    if let Some(governance) = governance.as_ref() {
        dispatcher = dispatcher.with_governance_authority(governance.authority());
    }

    let action = ResponseAction::BlockEgress {
        target: "203.0.113.11".to_string(),
    };
    let SwarmAction::RequestResponse {
        hunt_id,
        action,
        mut evidence,
    } = sample_request_response_action(
        hunt_id,
        "evt-governance-anchor",
        action,
        Severity::Critical,
    )
    else {
        panic!("sample_request_response_action must build a request_response action");
    };
    let request = ActionRequest {
        hunt_id: hunt_id.clone(),
        requested_by: AgentId::new("pounce", "primary"),
        action: action.clone(),
        severity: Severity::Critical,
        evidence: evidence.clone(),
    };
    evidence["governance_receipt"] = if let Some(receipt_signing_key) = unissued_signing_key {
        sample_governance_receipt_signed_by(
            &action,
            GovernanceReceiptDecision::Approve,
            receipt_signing_key,
        )
    } else {
        let Some(governance) = governance.as_ref() else {
            panic!("issued receipt control requires a governance policy");
        };
        let GovernanceDecision::Authorize { receipt, .. } = governance.can_act(&request) else {
            panic!("healthy governance must issue the control receipt");
        };
        serde_json::to_value(receipt).unwrap()
    };
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![SwarmAction::RequestResponse {
            hunt_id,
            action,
            evidence,
        }],
    )))?;

    dispatcher.tick_once().await;

    let audit_count = audits.lock().unwrap().len();
    Ok((
        audit_count,
        executor.calls.load(Ordering::SeqCst),
        evaluate_calls.load(Ordering::SeqCst),
    ))
}

/// A destructive action needs a receipt signed by a governor the dispatcher's
/// own authority names -- not merely a receipt that verifies against itself.
///
/// `ConsensusGovernanceReceipt::verify` checks a detached signature against
/// `signature.public_key_hex`, a field OF THE RECEIPT, so before ADR 0011 any
/// agent that could attach evidence could mint a keypair, sign its own approval
/// and be routed. The control case is in the same test so a refusal cannot be
/// mistaken for the dispatcher refusing everything.
#[tokio::test]
async fn destructive_request_response_is_refused_when_the_signer_is_not_a_governor()
-> Result<(), Box<dyn Error>> {
    let governor_key = SigningKey::from_bytes(&SAMPLE_GOVERNOR_KEY_BYTES);
    let stranger_key = SigningKey::from_bytes(&[201; 32]);
    assert_ne!(
        governor_key.verifying_key(),
        stranger_key.verifying_key(),
        "the forged receipt must be signed by a different key than the governor's"
    );

    // CONTROL: the registered governor's own key routes.
    let (audits, executed, evaluated) = run_one_destructive_request(
        Some(sample_governance_policy()),
        None,
        "hunt-anchor-control",
    )
    .await?;
    assert_eq!(
        (audits, executed, evaluated),
        (1, 1, 1),
        "a receipt from the configured governor must still route"
    );

    // A receipt that is internally perfect and signed by nobody in particular.
    let (audits, executed, evaluated) = run_one_destructive_request(
        Some(sample_governance_policy()),
        Some(&stranger_key),
        "hunt-anchor-stranger",
    )
    .await?;
    assert_eq!(
        (audits, executed, evaluated),
        (0, 0, 1),
        "a self-signed receipt from outside the governor set must not pass governance after policy preflight"
    );

    // NO AUTHORITY AT ALL. The dispatcher cannot tell an approval from a
    // forgery, so it refuses -- the same posture `GovernancePolicy::can_act`
    // takes on an empty keyring (b4bf119). This is the case that used to route
    // on the strength of a key carried inside the request.
    let (audits, executed, evaluated) =
        run_one_destructive_request(None, Some(&governor_key), "hunt-anchor-anchorless").await?;
    assert_eq!(
        (audits, executed, evaluated),
        (0, 0, 1),
        "with no governance authority installed policy may preflight, but nothing may proceed"
    );
    Ok(())
}

#[tokio::test]
async fn partitioned_request_response_fails_closed_without_contingency_lease()
-> Result<(), Box<dyn Error>> {
    let governance_policy = sample_partition_governance_policy();
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance_policy.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-partition-blocked-1",
            "evt-partition-blocked-1",
            ResponseAction::BlockEgress {
                target: "203.0.113.200".to_string(),
            },
            Severity::Critical,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(audits.lock().unwrap().is_empty());
    assert_eq!(
        governance_policy
            .status_report()
            .unauthorized_partition_actions,
        1
    );
    Ok(())
}

#[tokio::test]
async fn partitioned_request_response_redeems_contingency_lease() -> Result<(), Box<dyn Error>> {
    let governance_policy = sample_partition_governance_policy();
    let action = ResponseAction::BlockEgress {
        target: "203.0.113.210".to_string(),
    };
    let lease = match governance_policy.can_act(&sample_request(action.clone(), Severity::Critical))
    {
        GovernanceDecision::Authorize {
            contingency_lease: Some(lease),
            ..
        } => lease,
        other => panic!("expected contingency lease, got {other:?}"),
    };

    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance_policy.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_partition_request_response_action(
            "hunt-partition-lease-1",
            "evt-partition-lease-1",
            action,
            Severity::Critical,
            &lease,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert_eq!(receipt.action, "block_egress");
    assert_eq!(
        governance_policy
            .status_report()
            .unauthorized_partition_actions,
        0
    );
    Ok(())
}

#[tokio::test]
async fn partitioned_request_response_rejects_expired_contingency_lease()
-> Result<(), Box<dyn Error>> {
    let base_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time should be after unix epoch")
        .as_millis() as i64;
    let governance_policy = sample_governance_with_config(
        "expired-partition",
        GovernancePolicyConfig {
            // 1000ms, was 200ms. This test needs the lease to be ALIVE when `can_act`
            // issues it and EXPIRED after the sleep, so two margins must hold at once:
            //   setup_time < ttl        (or the lease is already dead at issue)
            //   sleep       > ttl       (or it has not expired when re-checked)
            // At 200/250 the second margin was 50ms and the first was whatever the
            // machine took. On a shared CI runner the FIRST one broke: the lease expired
            // during setup and `can_act` returned Veto("...without active contingency
            // lease"), panicking at the `other =>` arm. Locally it passed 5/5 in 0.3s.
            // 1000/2000 gives ~1000ms of slack on both sides for ~2s of wall clock.
            //
            // The real fix is not here. `GovernancePolicy::can_act` reads the clock
            // itself (tom_agent.rs:508, `preview_matching_contingency_lease(.., now_ms())`)
            // while the lease's expiry derives from the caller-supplied `base_ms`, so
            // setup time is charged against the TTL and no test can advance time without
            // sleeping. v1.81 phase 292's DCORE-02 requires precisely that seam --
            // "can_act no longer calls now_ms() internally; the clock is caller-supplied"
            // -- at which point this becomes two supplied timestamps and the race is gone
            // rather than merely widened.
            contingency_lease_ttl_ms: 1000,
            contingency_blast_radius_cap: 1,
        },
        [29; 32],
    );
    governance_policy.observe_health(&AgentId::new("tom", "primary"), &[], base_ms);
    governance_policy.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "tom-primary".to_string(),
            role: AgentRole::Tom,
            health: AgentHealth::Failed,
        }],
        base_ms + 10,
    );
    let action = ResponseAction::BlockEgress {
        target: "203.0.113.211".to_string(),
    };
    let lease = match governance_policy.can_act(&sample_request(action.clone(), Severity::Critical))
    {
        GovernanceDecision::Authorize {
            contingency_lease: Some(lease),
            ..
        } => lease,
        other => panic!("expected contingency lease, got {other:?}"),
    };
    // 2000ms against a 1000ms TTL: 1000ms past expiry, matching the setup-side slack.
    std::thread::sleep(Duration::from_millis(2000));

    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance_policy.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_partition_request_response_action(
            "hunt-partition-expired-1",
            "evt-partition-expired-1",
            action,
            Severity::Critical,
            &lease,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(audits.lock().unwrap().is_empty());
    assert_eq!(
        governance_policy
            .status_report()
            .unauthorized_partition_actions,
        1
    );
    Ok(())
}

#[tokio::test]
async fn pounceagent_dry_run_routes_through_runtime_path() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let guard_calls = Arc::new(AtomicUsize::new(0));
    let runtime = Arc::new(
        SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor.clone()).with_guard_pipeline(
            GuardPipeline::new(vec![Box::new(CountingGuard {
                calls: Arc::clone(&guard_calls),
            })]),
        ),
    );
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-dry-run-1",
            "evt-dry-run-1",
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
        )],
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(guard_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        executor.modes.lock().unwrap().as_slice(),
        &[ExecutionMode::DryRun]
    );

    let audits = audits.lock().unwrap();
    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert_eq!(receipt.mode, ExecutionMode::DryRun);
    assert_eq!(receipt.status, ResponseStatus::Simulated);
    Ok(())
}

#[tokio::test]
async fn expired_capability_lease_fails_closed_before_execution() -> Result<(), Box<dyn Error>> {
    let context = sample_context();
    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::allow_with_expiry(context.now_ms);
    let executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, executor.clone());
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );

    let error = runtime
        .authorize_and_execute(&request, &context)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RuntimeError::Approval(ApprovalError::Denied(ref reason))
        if reason == "capability lease expired"
    ));
    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn pounceagent_routes_same_escalation_only_once_per_session() -> Result<(), Box<dyn Error>> {
    let config = phase127_pheromone_config();
    let (substrate, dispatcher_substrate) = shared_test_substrate(config.clone());
    let mode_state = test_mode_state();
    let mut monitor = ConcentrationMonitor::new(config.clone(), Arc::new(substrate.clone()))
        .with_shared_mode_state(Arc::clone(&mode_state));

    let start = 1_700_000_000;
    deposit_execution_alert_pair(&substrate, "evt-repeat-1", start).await?;
    let alert = monitor.evaluate_all(start).await?;
    assert_eq!(alert.current_mode, SwarmMode::Alert);

    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        dispatcher_substrate,
        test_health_state(),
    )
    .with_mode_state(mode_state)
    .with_request_response_router(router);
    dispatcher.register(Box::new(PounceAgent::new(
        AgentId::new("pounce", "primary"),
        config.response_playbook.clone(),
    )))?;

    dispatcher.tick_once().await;

    deposit_execution_alert_pair(&substrate, "evt-repeat-1", start + 1).await?;
    let still_alert = monitor.evaluate_all(start + 1).await?;
    assert_eq!(still_alert.current_mode, SwarmMode::Alert);
    assert!(!still_alert.mode_changed);

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(audits.lock().unwrap().len(), 1);
    Ok(())
}

#[tokio::test]
async fn empty_ruleset_policy_fails_closed_for_routed_pounce_request() -> Result<(), Box<dyn Error>>
{
    let config = phase127_pheromone_config();
    let (substrate, dispatcher_substrate) = shared_test_substrate(config.clone());
    let mode_state = test_mode_state();
    let mut monitor = ConcentrationMonitor::new(config.clone(), Arc::new(substrate.clone()))
        .with_shared_mode_state(Arc::clone(&mode_state));

    let start = 1_700_000_100;
    deposit_execution_alert_pair(&substrate, "evt-empty-rules-1", start).await?;
    let alert = monitor.evaluate_all(start).await?;
    assert_eq!(alert.current_mode, SwarmMode::Alert);

    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        ConfigurableApprovalGate::from_config(&PolicyConfig::default()),
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        dispatcher_substrate,
        test_health_state(),
    )
    .with_mode_state(mode_state)
    .with_request_response_router(router);
    dispatcher.register(Box::new(PounceAgent::new(
        AgentId::new("pounce", "primary"),
        config.response_playbook.clone(),
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(
        audits[0].policy.rule_name,
        "configurable.fail_closed.empty_ruleset"
    );
    let AuditResponseRecord::Skipped { reason } = &audits[0].response else {
        panic!(
            "expected skipped audit record, got {:?}",
            audits[0].response
        );
    };
    assert!(reason.contains("no configurable policy rules loaded"));
    Ok(())
}

#[tokio::test]
async fn expired_lease_routing_records_failure_audit_without_execution()
-> Result<(), Box<dyn Error>> {
    let context = sample_context();
    let config = phase127_pheromone_config();
    let (substrate, dispatcher_substrate) = shared_test_substrate(config.clone());
    let mode_state = test_mode_state();
    let mut monitor = ConcentrationMonitor::new(config.clone(), Arc::new(substrate.clone()))
        .with_shared_mode_state(Arc::clone(&mode_state));

    let start = 1_700_000_200;
    deposit_execution_alert_pair(&substrate, "evt-expired-route-1", start).await?;
    let alert = monitor.evaluate_all(start).await?;
    assert_eq!(alert.current_mode, SwarmMode::Alert);

    let (gate, evaluate_calls, issue_lease_calls) =
        CountingApprovalGate::allow_with_expiry(context.now_ms);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        context,
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        dispatcher_substrate,
        test_health_state(),
    )
    .with_mode_state(mode_state)
    .with_request_response_router(router);
    dispatcher.register(Box::new(PounceAgent::new(
        AgentId::new("pounce", "primary"),
        config.response_playbook.clone(),
    )))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].policy.rule_name, "test.allow");
    assert_eq!(
        audits[0]
            .policy
            .lease
            .as_ref()
            .map(|lease| lease.expires_at_ms),
        Some(sample_context().now_ms)
    );
    let AuditResponseRecord::Failure(failure) = &audits[0].response else {
        panic!("expected failure receipt, got {:?}", audits[0].response);
    };
    assert_eq!(failure.message, "capability lease expired");
    assert!(failure.receipt_id.contains("evt-expired-route-1"));
    assert_eq!(
        failure.details["details"]["lineage"]["event_id"],
        serde_json::json!("evt-expired-route-1")
    );
    assert_eq!(
        failure.details["details"]["lease"]["expires_at_ms"],
        serde_json::json!(sample_context().now_ms)
    );
    assert_eq!(
        failure.details["audit"]["policy"]["rule_name"],
        serde_json::json!("test.allow")
    );
    Ok(())
}

#[tokio::test]
async fn burst_decay_burst_does_not_retrigger_pounceagent_before_cooldown_reset()
-> Result<(), Box<dyn Error>> {
    let config = phase127_pheromone_config();
    let (substrate, dispatcher_substrate) = shared_test_substrate(config.clone());
    let mode_state = test_mode_state();
    let mut monitor = ConcentrationMonitor::new(config.clone(), Arc::new(substrate.clone()))
        .with_shared_mode_state(Arc::clone(&mode_state));

    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::DetectOnly,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        dispatcher_substrate,
        test_health_state(),
    )
    .with_mode_state(Arc::clone(&mode_state))
    .with_request_response_router(router);
    dispatcher.register(Box::new(PounceAgent::new(
        AgentId::new("pounce", "primary"),
        config.response_playbook.clone(),
    )))?;

    let first_burst = 1_700_000_000;
    deposit_execution_alert_pair(&substrate, "evt-flap-1", first_burst).await?;
    let alert = monitor.evaluate_all(first_burst).await?;
    assert_eq!(alert.current_mode, SwarmMode::Alert);
    dispatcher.tick_once().await;

    let quiet_start = first_burst + 3_601;
    let first_quiet = monitor.evaluate_all(quiet_start).await?;
    assert_eq!(first_quiet.current_mode, SwarmMode::Alert);
    assert!(!first_quiet.mode_changed);

    let second_burst = quiet_start + 1;
    deposit_execution_alert_pair(&substrate, "evt-flap-1", second_burst).await?;
    let still_alert = monitor.evaluate_all(second_burst).await?;
    assert_eq!(still_alert.current_mode, SwarmMode::Alert);
    assert!(!still_alert.mode_changed);
    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert_eq!(audits.lock().unwrap().len(), 1);

    let second_quiet = second_burst + 3_601;
    let quiet_again = monitor.evaluate_all(second_quiet).await?;
    assert_eq!(quiet_again.current_mode, SwarmMode::Alert);
    assert!(!quiet_again.mode_changed);

    let cooldown_reset = second_quiet + config.deescalation_cooldown_secs;
    let deescalated = monitor.evaluate_all(cooldown_reset).await?;
    assert_eq!(deescalated.current_mode, SwarmMode::Normal);
    assert!(deescalated.mode_changed);

    let third_burst = cooldown_reset + 1;
    deposit_execution_alert_pair(&substrate, "evt-flap-1", third_burst).await?;
    let realert = monitor.evaluate_all(third_burst).await?;
    assert_eq!(realert.current_mode, SwarmMode::Alert);
    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 2);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
    assert_eq!(audits.lock().unwrap().len(), 2);
    Ok(())
}

#[tokio::test]
async fn receipt_preserves_original_hunt_id_and_lineage_evidence() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router);
    dispatcher.register(Box::new(OneShotRequestAgent::new(
        AgentId::new("pounce", "primary"),
        vec![sample_request_response_action(
            "hunt-lineage-1",
            "evt-lineage-1",
            ResponseAction::DeployDecoy {
                decoy_type: "honeypot".to_string(),
                target_zone: "dmz".to_string(),
            },
            Severity::High,
        )],
    )))?;

    dispatcher.tick_once().await;

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].hunt_id, "hunt-lineage-1");
    assert_eq!(audits[0].detection.event_id, "evt-lineage-1");
    assert_eq!(
        audits[0].detection.evidence["lineage"]["event_id"],
        serde_json::json!("evt-lineage-1")
    );
    assert_eq!(
        audits[0].detection.evidence["lineage"]["hunt_id"],
        serde_json::json!("hunt-lineage-1")
    );

    let AuditResponseRecord::Success(receipt) = &audits[0].response else {
        panic!("expected success receipt, got {:?}", audits[0].response);
    };
    assert!(receipt.receipt_id.contains("hunt-lineage-1"));
    assert_eq!(
        receipt.details["lineage"]["event_id"],
        serde_json::json!("evt-lineage-1")
    );
    assert_eq!(
        receipt.details["lineage"]["hunt_id"],
        serde_json::json!("hunt-lineage-1")
    );
    assert_eq!(
        receipt
            .audit
            .policy
            .as_ref()
            .map(|policy| policy.rule_name.as_str()),
        Some("test.allow")
    );
    Ok(())
}

#[tokio::test]
async fn audit_trail_records_rule_name_and_reason() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor);
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );

    let report = runtime
        .audit_authorize_and_execute_instrumented(&sample_detection(), &request, &sample_context())
        .await?;

    assert_eq!(report.audit.policy.rule_name, "test.allow");
    assert_eq!(report.audit.policy.reason, "allowed in test");
    Ok(())
}

#[tokio::test]
async fn successful_receipts_embed_policy_audit() -> Result<(), Box<dyn Error>> {
    let (gate, _evaluate_calls, _issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = SwarmRuntime::new(RuntimeMode::DetectOnly, gate, executor);
    let request = sample_request(
        ResponseAction::DeployDecoy {
            decoy_type: "honeypot".to_string(),
            target_zone: "dmz".to_string(),
        },
        Severity::High,
    );

    let receipt = runtime
        .authorize_and_execute(&request, &sample_context())
        .await?;
    let policy = receipt.audit.policy.expect("policy audit missing");

    assert_eq!(policy.verdict, PolicyVerdict::Allow);
    assert_eq!(policy.rule_name, "test.allow");
    assert_eq!(policy.reason, "allowed in test");
    Ok(())
}

#[tokio::test]
async fn governance_veto_records_failure_receipt_without_execution() -> Result<(), Box<dyn Error>> {
    let (gate, evaluate_calls, issue_lease_calls) = CountingApprovalGate::allow_with_ttl(60_000);
    let executor = RecordingExecutor::default();
    let runtime = Arc::new(SwarmRuntime::new(
        RuntimeMode::LiveResponse,
        gate,
        executor.clone(),
    ));
    let audits = Arc::new(Mutex::new(Vec::new()));
    let router = Arc::new(RuntimeBackedRouter::new(
        Arc::clone(&runtime),
        sample_context(),
        Arc::clone(&audits),
    ));
    let governance = sample_governance_policy();
    governance.observe_health(
        &AgentId::new("tom", "primary"),
        &[AgentHealthEntry {
            id: "whisker-primary".to_string(),
            role: AgentRole::Whisker,
            health: AgentHealth::Degraded,
        }],
        1_700_000_000_000,
    );
    let pounce_id = AgentId::new("pounce", "primary");
    let veto = attach_issued_receipt(
        &governance,
        &pounce_id,
        sample_governance_veto_action(
            "hunt-veto-1",
            "evt-veto-1",
            ResponseAction::BlockEgress {
                target: "203.0.113.10".to_string(),
            },
            Severity::Critical,
            AgentId::new("tom", "primary"),
            "blocked destructive action while swarm unhealthy: whisker-primary:Degraded",
        ),
        GovernanceReceiptDecision::Veto,
    );
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dispatcher = AgentDispatcher::new(
        AgentDispatcherConfig::default(),
        shutdown_rx,
        test_substrate(),
        test_health_state(),
    )
    .with_request_response_router(router)
    .with_governance_authority(governance.authority());
    dispatcher.register(Box::new(OneShotRequestAgent::new(pounce_id, vec![veto])))?;

    dispatcher.tick_once().await;

    assert_eq!(evaluate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(issue_lease_calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

    let audits = audits.lock().unwrap();
    assert_eq!(audits.len(), 1);
    let AuditResponseRecord::Failure(failure) = &audits[0].response else {
        panic!("expected failure receipt, got {:?}", audits[0].response);
    };
    assert_eq!(audits[0].policy.rule_name, "governance.veto");
    assert_eq!(failure.action, "block_egress");
    assert!(failure.receipt_id.contains("hunt-veto-1"));
    assert_eq!(
        failure.details["audit"]["governance"]["governing_agent_id"],
        serde_json::json!("tom-primary")
    );
    assert_eq!(
        failure.details["audit"]["governance"]["reason"],
        serde_json::json!(
            "blocked destructive action while swarm unhealthy: whisker-primary:Degraded"
        )
    );
    assert!(failure.details["audit"]["governance"]["receipt"].is_object());
    assert!(
        audits[0]
            .all_receipt_ids()
            .iter()
            .any(|receipt_id| receipt_id == &failure.receipt_id)
    );
    Ok(())
}
