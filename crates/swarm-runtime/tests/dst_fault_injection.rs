#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Seeded crash/recovery tests for the production dispatch journal. A durable
//! intent precedes every sandbox effect. An interrupted intent remains outcome
//! unknown and suppresses redelivery; it is never called a completion receipt.
//! The local-journal pheromone backend supplies signed evidence and must retain
//! it across in-flight reopen. Scope: one process owning each journal at a time.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use swarm_core::ThreatClass;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, PolicyConfig, RuntimeMode};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_pheromone::{DepositSigningPayload, LocalJournalPheromoneSubstrate, PheromoneSubstrate};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalGate, CapabilityLease, PolicyVerdict};
use swarm_response::containment::{ContainmentTtl, FileContainmentLeaseStore};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
};
use swarm_runtime::dispatch_journal::{DispatchJournal, request_id};
use swarm_runtime::red_swarm::RedGenomeRng;
use swarm_runtime::{RuntimeError, SwarmRuntime};

const PR_SEEDS: u64 = 64;
const NIGHTLY_SEEDS: u64 = 5_000;
const MAX_POLLS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Allow,
    Deny,
    Human,
}
impl Verdict {
    fn policy(self) -> PolicyVerdict {
        match self {
            Self::Allow => PolicyVerdict::Allow,
            Self::Deny => PolicyVerdict::Deny,
            Self::Human => PolicyVerdict::RequireHuman,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Fault {
    Complete,
    DropUnpolled,
    DropBeforeEffect,
    DropAfterEffect,
    ReopenBeforeEffect,
    ReopenAfterEffect,
}
const FAULTS: [Fault; 6] = [
    Fault::Complete,
    Fault::DropUnpolled,
    Fault::DropBeforeEffect,
    Fault::DropAfterEffect,
    Fault::ReopenBeforeEffect,
    Fault::ReopenAfterEffect,
];
#[derive(Debug, Clone)]
struct Plan {
    seed: u64,
    verdict: Verdict,
    fault: Fault,
    before_gate: usize,
    before_effect: usize,
    after_effect: usize,
    after_return: usize,
    retries: usize,
    requests: usize,
}
impl Plan {
    fn from_seed(seed: u64) -> Self {
        let mut rng = RedGenomeRng::from_u64(seed);
        Self {
            seed,
            verdict: [Verdict::Allow, Verdict::Deny, Verdict::Human][rng.next_below(3) as usize],
            fault: FAULTS[rng.next_below(FAULTS.len() as u64) as usize],
            before_gate: rng.next_below(4) as usize,
            before_effect: 1 + rng.next_below(4) as usize,
            after_effect: 1 + rng.next_below(4) as usize,
            after_return: 1 + rng.next_below(3) as usize,
            retries: 1 + rng.next_below(3) as usize,
            requests: 1 + rng.next_below(2) as usize,
        }
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "ambush-dst-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Yields(usize);
impl Future for Yields {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 == 0 {
            Poll::Ready(())
        } else {
            self.0 -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..MAX_POLLS {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("bounded deterministic executor exhausted {MAX_POLLS} polls");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Initial,
    BeforeEffect,
    AfterEffect,
    Returned,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Executed,
    Rejected,
    Reserved,
    Error,
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Poll(usize),
    IntentObserved,
    IntentMissing,
    IntentCompleted,
    IntentInvalidBinding,
    IntentUnreadable,
    Effect,
    CompletedObserved,
    Returned(Disposition),
    Crash,
    Restart,
    SubstrateReopened,
    EvidenceRead(u64),
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trace {
    id: String,
    event: Event,
}
type Log = Arc<Mutex<Vec<Trace>>>;
fn record(log: &Log, id: &str, event: Event) {
    log.lock().unwrap().push(Trace {
        id: id.into(),
        event,
    });
}

/// The adapter's effect is an fsynced marker in a private sandbox. The marker
/// survives destruction of every runtime object, so restart cannot reset the
/// effect count. Fault suspension is inside execute, before it returns a result.
#[derive(Clone)]
struct EffectAdapter {
    journal: Arc<DispatchJournal>,
    evidence: EvidenceView,
    effects_path: PathBuf,
    stage: Arc<Mutex<Stage>>,
    log: Log,
    before: usize,
    after: usize,
}
#[async_trait]
impl ResponseExecutor for EffectAdapter {
    async fn execute(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        let id = request_id(request).unwrap();
        *self.stage.lock().unwrap() = Stage::BeforeEffect;
        Yields(self.before).await;
        record(
            &self.log,
            &id,
            Event::EvidenceRead(self.evidence.read().await),
        );
        // Observe the real bytes without enforcing the property ourselves.
        // A broken production boundary must be allowed to make its sandbox
        // effect so the named oracle can reject the actual observed history.
        let intent_event = match self.journal.lookup_persisted(&id) {
            Ok(Some(intent)) if intent.completion.is_some() => Event::IntentCompleted,
            Ok(Some(intent))
                if request_id(&intent.request)
                    .as_ref()
                    .is_ok_and(|found| found == &id)
                    && serde_json::to_value(&intent.request).ok()
                        == serde_json::to_value(request).ok()
                    && intent.lease.capability_id == lease.capability_id
                    && request.evidence == self.evidence.expected.indicator
                    && mode == ExecutionMode::Enforced =>
            {
                Event::IntentObserved
            }
            Ok(Some(_)) => Event::IntentInvalidBinding,
            Ok(None) => Event::IntentMissing,
            Err(_) => Event::IntentUnreadable,
        };
        record(&self.log, &id, intent_event.clone());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.effects_path)
            .unwrap();
        writeln!(
            file,
            "{}",
            serde_json::json!({
                "dispatch_id": id, "observed_intent": format!("{intent_event:?}")
            })
        )
        .unwrap();
        file.sync_all().unwrap();
        record(&self.log, &id, Event::Effect);
        *self.stage.lock().unwrap() = Stage::AfterEffect;
        Yields(self.after).await;
        record(
            &self.log,
            &id,
            Event::EvidenceRead(self.evidence.read().await),
        );
        Ok(ResponseReceipt {
            receipt_id: format!("dst-result:{id}"),
            action: request.action.kind().into(),
            mode,
            status: ResponseStatus::Executed,
            summary: "sandbox effect committed".into(),
            details: serde_json::json!({"dispatch_id": id}),
            audit: Default::default(),
        })
    }
}

type Runtime = SwarmRuntime<StaticApprovalGate, EffectAdapter>;
fn gate() -> StaticApprovalGate {
    StaticApprovalGate::from_config(&PolicyConfig {
        human_gate_severity: Severity::High,
        lease_ttl_ms: 60_000,
        max_actions_per_scope_per_minute: 100,
        rules: Vec::new(),
    })
}
fn context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: Vec::new(),
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}
fn request(plan: &Plan, index: usize, evidence: serde_json::Value) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId(format!("dst-{}-{index}", plan.seed)),
        requested_by: AgentId(format!("dst-principal-{}", plan.seed % 7)),
        action: ResponseAction::IsolateHost {
            host_id: format!("dst-{}-{index}.invalid", plan.seed),
        },
        severity: match plan.verdict {
            Verdict::Allow => Severity::Medium,
            Verdict::Deny => Severity::Low,
            Verdict::Human => Severity::High,
        },
        evidence,
    }
}
fn build_runtime(
    path: &Path,
    effects: &Path,
    plan: &Plan,
    log: &Log,
    evidence: &EvidenceView,
) -> (Runtime, Arc<DispatchJournal>, Arc<Mutex<Stage>>) {
    let journal = Arc::new(DispatchJournal::open(path).unwrap());
    let stage = Arc::new(Mutex::new(Stage::Initial));
    let adapter = EffectAdapter {
        journal: journal.clone(),
        evidence: evidence.clone(),
        effects_path: effects.into(),
        stage: stage.clone(),
        log: log.clone(),
        before: plan.before_effect,
        after: plan.after_effect,
    };
    (
        SwarmRuntime::new(RuntimeMode::LiveResponse, gate(), adapter)
            .with_dispatch_journal(journal.clone())
            .with_containment_store(
                Arc::new(FileContainmentLeaseStore::open(
                    path.join("containment.jsonl"),
                )),
                ContainmentTtl::from_config_ms(900_000).unwrap(),
            ),
        journal,
        stage,
    )
}

async fn episode(
    runtime: &Runtime,
    journal: &DispatchJournal,
    request: &ActionRequest,
    plan: &Plan,
    stage: &Mutex<Stage>,
    log: &Log,
) -> Disposition {
    let id = request_id(request).unwrap();
    Yields(plan.before_gate).await;
    let result = runtime.authorize_and_execute(request, &context()).await;
    let disposition = match result {
        Ok(receipt) => {
            assert_eq!(receipt.status, ResponseStatus::Executed);
            Disposition::Executed
        }
        Err(RuntimeError::Approval(_)) => Disposition::Rejected,
        Err(RuntimeError::Response(error))
            if error.failure.details["status"] == "dispatch_refused"
                && error.failure.details["prior_reservation"] == true
                && error.failure.details["response_attempted"] == false
                && error.failure.details["retry_permitted"] == false =>
        {
            Disposition::Reserved
        }
        Err(_) => Disposition::Error,
    };
    if journal
        .lookup_persisted(&id)
        .unwrap()
        .is_some_and(|r| r.completion.is_some())
    {
        record(log, &id, Event::CompletedObserved);
    }
    record(log, &id, Event::Returned(disposition));
    *stage.lock().unwrap() = Stage::Returned;
    Yields(plan.after_return).await;
    disposition
}

fn signed_evidence(seed: u64) -> PheromoneDeposit {
    let key = SigningKey::from_bytes(&[71; 32]);
    let public = key.verifying_key();
    let id = AgentId::from_verifying_key(&public);
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({"source": "dst-preexisting", "seed": seed, "host_id": "dst-host"}),
        threat_class: ThreatClass::CommandAndControl,
        severity: Severity::Medium,
        confidence: 0.8,
        timestamp: 1_700_000_000,
        decay_half_life: 3600.0,
        agent_id: id.clone(),
        agent_identity: id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: public.to_bytes().to_vec(),
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
    deposit.signature = key
        .sign(&serde_json::to_vec(&payload).unwrap())
        .to_bytes()
        .to_vec();
    deposit
}
fn substrate(path: &Path) -> LocalJournalPheromoneSubstrate {
    let config = PheromoneConfig {
        default_half_life_secs: 3600.0,
        evaporation_threshold: 0.01,
        min_sources_for_escalation: 2,
        alert_threshold: 2.0,
        incident_threshold: 5.0,
        deescalation_cooldown_secs: 300,
        response_playbook: Default::default(),
        backend: PheromoneBackendConfig::LocalJournal {
            path: path.display().to_string(),
        },
    };
    LocalJournalPheromoneSubstrate::open(config, path).unwrap()
}
#[derive(Clone)]
struct EvidenceView {
    live: Arc<Mutex<Option<LocalJournalPheromoneSubstrate>>>,
    epoch: Arc<AtomicU64>,
    expected: PheromoneDeposit,
}
impl EvidenceView {
    fn new(path: &Path, expected: PheromoneDeposit) -> Self {
        let store = substrate(path);
        ready(store.deposit(expected.clone())).unwrap();
        Self {
            live: Arc::new(Mutex::new(Some(store))),
            epoch: Arc::new(AtomicU64::new(0)),
            expected,
        }
    }
    fn close(&self) {
        drop(self.live.lock().unwrap().take());
    }
    fn reopen(&self, path: &Path) {
        self.close();
        *self.live.lock().unwrap() = Some(substrate(path));
        self.epoch.fetch_add(1, Ordering::SeqCst);
        ready(self.read());
    }
    async fn read(&self) -> u64 {
        let store = self
            .live
            .lock()
            .unwrap()
            .clone()
            .expect("episode read while substrate closed");
        let records = store.recent_deposits(4).await.unwrap();
        assert_eq!(
            records.len(),
            1,
            "preexisting signed evidence lost or duplicated"
        );
        assert_eq!(
            serde_json::to_value(&records[0]).unwrap(),
            serde_json::to_value(&self.expected).unwrap()
        );
        self.epoch.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
struct Observation {
    plan: Plan,
    log: Vec<Trace>,
    ids: Vec<String>,
    effects: Vec<String>,
    completed: BTreeSet<String>,
    reserved: BTreeSet<String>,
    initial_outcomes: Vec<Option<Disposition>>,
    retry_outcomes: Vec<Disposition>,
}

fn drive(plan: Plan) -> Observation {
    std::panic::catch_unwind(|| drive_inner(plan.clone())).unwrap_or_else(|failure| {
        let reason = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap_or("non-string panic");
        panic!("SWARM_DST_SEED={} plan={plan:?}: {reason}", plan.seed);
    })
}

fn drive_inner(plan: Plan) -> Observation {
    let scratch = Scratch::new();
    let journal_path = scratch.0.join("dispatch");
    let effects_path = scratch.0.join("effects.log");
    let substrate_path = scratch.0.join("pheromones.jsonl");
    let evidence = signed_evidence(plan.seed);
    let view = EvidenceView::new(&substrate_path, evidence.clone());
    ready(view.read());
    let log: Log = Arc::default();
    let mut observation = Observation {
        plan: plan.clone(),
        log: Vec::new(),
        ids: Vec::new(),
        effects: Vec::new(),
        completed: BTreeSet::new(),
        reserved: BTreeSet::new(),
        initial_outcomes: Vec::new(),
        retry_outcomes: Vec::new(),
    };

    let mut expected_records = BTreeMap::new();
    let mut submitted = Vec::new();
    for index in 0..plan.requests {
        view.reopen(&substrate_path);
        let request = request(&plan, index, evidence.indicator.clone());
        assert_eq!(
            gate().evaluate(&request, &context()).unwrap().verdict,
            plan.verdict.policy()
        );
        let id = request_id(&request).unwrap();
        observation.ids.push(id.clone());
        submitted.push(request.clone());
        let (runtime, journal, stage) =
            build_runtime(&journal_path, &effects_path, &plan, &log, &view);
        let mut future = Box::pin(episode(&runtime, &journal, &request, &plan, &stage, &log));
        let mut cx = Context::from_waker(Waker::noop());
        let mut initial = None;
        let mut fault_fired = false;
        if plan.fault != Fault::DropUnpolled {
            for poll in 0..MAX_POLLS {
                record(&log, &id, Event::Poll(poll));
                if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                    initial = Some(value);
                    break;
                }
                let current = *stage.lock().unwrap();
                let before = matches!(
                    plan.fault,
                    Fault::DropBeforeEffect | Fault::ReopenBeforeEffect
                );
                let after = matches!(
                    plan.fault,
                    Fault::DropAfterEffect | Fault::ReopenAfterEffect
                );
                // Target the actual execution stage even if a production
                // mutation wrongly dispatches a denied request. A correctly
                // denied request instead pauses after the gate returns.
                let checkpoint = (before && current == Stage::BeforeEffect)
                    || (after && current == Stage::AfterEffect)
                    || (plan.verdict != Verdict::Allow && current == Stage::Returned);
                if !fault_fired && (before || after) && checkpoint {
                    fault_fired = true;
                    if matches!(plan.fault, Fault::DropBeforeEffect | Fault::DropAfterEffect) {
                        break;
                    }
                    view.reopen(&substrate_path);
                    record(&log, &id, Event::SubstrateReopened);
                }
            }
        }
        let cancelled = matches!(
            plan.fault,
            Fault::DropUnpolled | Fault::DropBeforeEffect | Fault::DropAfterEffect
        );
        drop(future);
        if cancelled && initial.is_none() {
            record(&log, &id, Event::Crash);
        }
        assert_prefix(&log, &plan);
        if cancelled {
            assert!(
                initial.is_none(),
                "seed {} fault {:?} missed cancellation",
                plan.seed,
                plan.fault
            );
        } else {
            assert!(initial.is_some(), "seed {} exceeded poll budget", plan.seed);
            assert_eq!(
                initial,
                Some(if plan.verdict == Verdict::Allow {
                    Disposition::Executed
                } else {
                    Disposition::Rejected
                }),
                "initial disposition differs from policy verdict"
            );
        }
        if plan.fault != Fault::Complete && plan.fault != Fault::DropUnpolled {
            assert!(
                fault_fired,
                "seed {} did not reach selected checkpoint",
                plan.seed
            );
        }
        observation.initial_outcomes.push(initial);
        // No executor result may be invented for an interrupted effect.
        let first = journal.lookup_persisted(&id).unwrap();
        if plan.verdict == Verdict::Allow
            && matches!(plan.fault, Fault::DropBeforeEffect | Fault::DropAfterEffect)
        {
            assert!(
                first.as_ref().is_some_and(|r| r.completion.is_none()),
                "cancelled authorized dispatch must remain durably outcome unknown"
            );
        }
        if plan.verdict != Verdict::Allow || plan.fault == Fault::DropUnpolled {
            assert!(
                first.is_none(),
                "unpolled or forbidden request created a dispatch intent"
            );
        }
        drop(runtime);
        drop(journal);
        view.close();

        // Restart, reopen both stores, and redeliver the identical request. The
        // sandbox effect file and trace survive destruction of the runtime.
        let mut expected_record = first.map(|record| serde_json::to_value(record).unwrap());
        for _ in 0..plan.retries {
            record(&log, &id, Event::Restart);
            view.reopen(&substrate_path);
            let (runtime, journal, stage) =
                build_runtime(&journal_path, &effects_path, &plan, &log, &view);
            let previous = journal.lookup_persisted(&id).unwrap();
            assert_eq!(
                previous
                    .as_ref()
                    .map(|record| serde_json::to_value(record).unwrap()),
                expected_record,
                "durable dispatch record changed across reopen"
            );
            let disposition = ready(episode(&runtime, &journal, &request, &plan, &stage, &log));
            assert_prefix(&log, &plan);
            let expected = if plan.verdict != Verdict::Allow {
                Disposition::Rejected
            } else if previous.is_some() {
                Disposition::Reserved
            } else {
                Disposition::Executed
            };
            assert_eq!(
                disposition, expected,
                "seed {} redelivery disposition",
                plan.seed
            );
            observation.retry_outcomes.push(disposition);
            let recovered = journal.lookup_persisted(&id).unwrap();
            if expected_record.is_some() {
                assert_eq!(
                    recovered
                        .as_ref()
                        .map(|record| serde_json::to_value(record).unwrap()),
                    expected_record,
                    "redelivery changed an existing dispatch record"
                );
            }
            expected_record = recovered
                .as_ref()
                .map(|record| serde_json::to_value(record).unwrap());
            observation.reserved.remove(&id);
            observation.completed.remove(&id);
            if let Some(entry) = recovered {
                assert_eq!(request_id(&entry.request).unwrap(), id);
                observation.reserved.insert(id.clone());
                if let Some(completion) = entry.completion {
                    let receipt =
                        completion.expect("sandbox adapter always succeeds when returned");
                    assert_eq!(receipt.status, ResponseStatus::Executed);
                    assert_eq!(receipt.receipt_id, format!("dst-result:{id}"));
                    observation.completed.insert(id.clone());
                }
            }
            drop(runtime);
            drop(journal);
            view.close();
        }
        expected_records.insert(id, expected_record);
    }
    // Inserting a newer request must not erase an older reservation. Reopen
    // once more and redeliver every prior identity after all insertions.
    view.reopen(&substrate_path);
    let (runtime, journal, stage) = build_runtime(&journal_path, &effects_path, &plan, &log, &view);
    observation.reserved.clear();
    observation.completed.clear();
    for request in &submitted {
        let id = request_id(request).unwrap();
        record(&log, &id, Event::Restart);
        let before = journal.lookup_persisted(&id).unwrap();
        assert_eq!(
            before.as_ref().map(|r| serde_json::to_value(r).unwrap()),
            expected_records[&id],
            "newer request erased older durable dispatch state"
        );
        let disposition = ready(episode(&runtime, &journal, request, &plan, &stage, &log));
        assert_prefix(&log, &plan);
        assert_eq!(
            disposition,
            if plan.verdict == Verdict::Allow {
                Disposition::Reserved
            } else {
                Disposition::Rejected
            },
            "old-request redelivery was not suppressed"
        );
        let after = journal.lookup_persisted(&id).unwrap();
        assert_eq!(
            after.as_ref().map(|r| serde_json::to_value(r).unwrap()),
            expected_records[&id]
        );
        if let Some(entry) = after {
            observation.reserved.insert(id.clone());
            if entry.completion.is_some() {
                observation.completed.insert(id);
            }
        }
    }
    drop(runtime);
    drop(journal);
    view.close();
    observation.effects = match std::fs::read_to_string(&effects_path) {
        Ok(contents) => contents
            .lines()
            .map(|line| {
                let effect: serde_json::Value = serde_json::from_str(line).unwrap();
                effect["dispatch_id"].as_str().unwrap().to_string()
            })
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read sandbox effects: {error}"),
    };
    observation.log = log.lock().unwrap().clone();
    observation
}

/// The same named prefix oracles run immediately after cancellation and
/// redelivery, before result/state expectations can mask a forbidden effect.
fn prefix_violations(log: &[Trace], verdict: Verdict) -> Vec<&'static str> {
    let mut failures = Vec::new();
    let mut intents = BTreeSet::new();
    let mut counts = BTreeMap::new();
    for entry in log {
        match entry.event {
            Event::IntentObserved => {
                intents.insert(entry.id.clone());
            }
            Event::IntentMissing
            | Event::IntentCompleted
            | Event::IntentInvalidBinding
            | Event::IntentUnreadable => {
                intents.remove(&entry.id);
            }
            Event::Effect => {
                if !intents.contains(&entry.id) {
                    failures.push("ordering: effect preceded durable intent");
                }
                if verdict != Verdict::Allow {
                    failures.push("disposition: forbidden effect despite cancellation");
                }
                let count = counts.entry(entry.id.clone()).or_insert(0usize);
                *count += 1;
                if *count > 1 {
                    failures.push("at-most-once: duplicate effect across restart");
                }
            }
            Event::CompletedObserved if counts.get(&entry.id).copied().unwrap_or_default() != 1 => {
                failures.push("ordering: completion without exactly one preceding effect");
            }
            Event::Returned(disposition)
                if verdict != Verdict::Allow && disposition != Disposition::Rejected =>
            {
                failures.push("disposition: forbidden request returned an incorrect disposition");
            }
            _ => {}
        }
    }
    failures
}
fn assert_prefix(log: &Log, plan: &Plan) {
    let trace = log.lock().unwrap();
    let failures = prefix_violations(&trace, plan.verdict);
    assert!(
        failures.is_empty(),
        "SWARM_DST_SEED={} plan={plan:?} named_oracles={failures:?} trace={trace:?}",
        plan.seed
    );
}

/// Final checks additionally compare recovered journal state and durable
/// sandbox effects. Safety never depends on a future returning a Result.
fn violations(observation: &Observation) -> Vec<&'static str> {
    let mut failures = prefix_violations(&observation.log, observation.plan.verdict);
    let mut counts = BTreeMap::new();
    let mut traced_effects = Vec::new();
    for entry in &observation.log {
        if !observation.ids.contains(&entry.id) {
            failures.push("unexpected request identity in trace");
        }
        if entry.event == Event::Effect {
            *counts.entry(entry.id.clone()).or_insert(0usize) += 1;
            traced_effects.push(entry.id.clone());
        }
    }
    if traced_effects != observation.effects {
        failures.push("trace disagrees with durable sandbox effects");
    }
    for id in &observation.ids {
        let count = counts.get(id).copied().unwrap_or_default();
        if observation.plan.verdict != Verdict::Allow {
            if observation.reserved.contains(id) || observation.completed.contains(id) {
                failures.push("forbidden request acquired dispatch authority");
            }
        } else {
            if !observation.reserved.contains(id) {
                failures.push("reservation lost across restart");
            }
            let before_crash = observation.plan.fault == Fault::DropBeforeEffect;
            if count != usize::from(!before_crash) {
                failures.push("wrong effect disposition");
            }
            let unknown = matches!(
                observation.plan.fault,
                Fault::DropBeforeEffect | Fault::DropAfterEffect
            );
            if observation.completed.contains(id) == unknown {
                failures.push("unknown outcome relabeled as completion");
            }
        }
    }
    failures
}
fn check(observation: &Observation) {
    let failures = violations(observation);
    assert!(
        failures.is_empty(),
        "SWARM_DST_SEED={} plan={:?}: {:?}",
        observation.plan.seed,
        observation.plan,
        failures
    );
}
fn replay_seed() -> Option<u64> {
    std::env::var("SWARM_DST_SEED")
        .ok()
        .map(|value| value.parse().expect("SWARM_DST_SEED must be u64"))
}
fn run_corpus(count: u64) {
    let mut schedules = BTreeSet::new();
    let mut matrix = BTreeSet::new();
    for seed in 0..count {
        let observation = drive(Plan::from_seed(seed));
        check(&observation);
        matrix.insert((observation.plan.verdict, observation.plan.fault));
        // Exclude identities and seed labels: diversity must change executed
        // polls/restarts/effects, rather than merely the random plan's text.
        schedules.insert(format!(
            "{:?}",
            observation.log.iter().map(|e| &e.event).collect::<Vec<_>>()
        ));
    }
    assert!(
        matrix.len() >= 16,
        "corpus missed verdict/fault combinations: {matrix:?}"
    );
    assert!(
        schedules.len() >= 40,
        "{count} seeds exercised only {} behavioral traces",
        schedules.len()
    );
}

#[test]
fn dst_pr_corpus_or_exact_seed_replays_real_crash_recovery() {
    if let Some(seed) = replay_seed() {
        let observation = drive(Plan::from_seed(seed));
        check(&observation);
        println!(
            "SWARM_DST_SEED={seed} plan={:?} trace={:?}",
            observation.plan, observation.log
        );
    } else {
        run_corpus(PR_SEEDS);
    }
}
#[test]
#[ignore = "5000-seed nightly crash/recovery corpus"]
fn dst_nightly_deep_corpus_replays_real_crash_recovery() {
    run_corpus(NIGHTLY_SEEDS);
}

#[test]
fn dst_every_verdict_survives_every_cancellation_and_reopen_boundary() {
    if replay_seed().is_some() {
        return;
    }
    for verdict in [Verdict::Allow, Verdict::Deny, Verdict::Human] {
        for fault in FAULTS {
            let mut plan = Plan::from_seed(286);
            plan.verdict = verdict;
            plan.fault = fault;
            check(&drive(plan));
        }
    }
}
#[test]
fn dst_same_seed_produces_identical_executed_trace_and_durable_effects() {
    if replay_seed().is_some() {
        return;
    }
    for seed in [0, 17, 286, u64::MAX] {
        let first = drive(Plan::from_seed(seed));
        let second = drive(Plan::from_seed(seed));
        check(&first);
        check(&second);
        assert_eq!(first.log, second.log);
        assert_eq!(first.effects, second.effects);
        assert_eq!(first.reserved, second.reserved);
        assert_eq!(first.completed, second.completed);
    }
}
#[test]
fn dst_oracles_reject_reordered_intent_forbidden_cancelled_effect_and_duplicate() {
    if replay_seed().is_some() {
        return;
    }
    let mut plan = Plan::from_seed(19);
    plan.verdict = Verdict::Allow;
    plan.fault = Fault::DropAfterEffect;
    let good = drive(plan);
    check(&good);
    let mut reordered = good.clone();
    let intent = reordered
        .log
        .iter()
        .position(|e| e.event == Event::IntentObserved)
        .unwrap();
    let effect = reordered
        .log
        .iter()
        .position(|e| e.event == Event::Effect)
        .unwrap();
    reordered.log.swap(intent, effect); // Identical final store contents.
    assert!(violations(&reordered).contains(&"ordering: effect preceded durable intent"));
    for verdict in [Verdict::Deny, Verdict::Human] {
        let mut forbidden = good.clone();
        forbidden.plan.verdict = verdict;
        assert!(forbidden.initial_outcomes.iter().all(Option::is_none));
        assert!(
            violations(&forbidden).contains(&"disposition: forbidden effect despite cancellation")
        );
    }
    let mut duplicated = good;
    let id = duplicated.effects[0].clone();
    duplicated.effects.push(id.clone());
    duplicated.log.push(Trace {
        id,
        event: Event::Effect,
    });
    assert!(violations(&duplicated).contains(&"at-most-once: duplicate effect across restart"));
}
