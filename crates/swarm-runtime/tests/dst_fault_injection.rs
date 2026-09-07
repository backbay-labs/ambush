#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Phase 286 Task 1 -- the deterministic-simulation fault-injection harness
//! foundation (DST-01, DST-05).
//!
//! This file drives the REAL `SwarmRuntime::authorize_and_execute`, a real
//! `StaticApprovalGate`, and a real `InMemoryPheromoneSubstrate` -- no mocks
//! of any of the three -- through a hand-rolled deterministic executor with
//! no wall clock, no OS entropy, and no tokio. Only `FaultClass::NoFault` is
//! wired here; Task 2 adds the three DST-02 fault classes on top of the
//! shapes below. See `.superpowers/sdd/286-01-PLAN/task-1-report.md` for the
//! full account, in particular:
//!
//! - **Entry point.** Neither `authorize_and_execute` nor
//!   `audit_authorize_and_execute` writes to any substrate. Both simply
//!   return a value (`ResponseReceipt` / `AuditTrail`) to their caller, and
//!   grep confirms `authorize_and_execute` is called from nowhere in this
//!   crate except tests -- there is no production "receipt persist" call to
//!   drive. This harness therefore drives `authorize_and_execute` directly
//!   (satisfying DST-01's text, and the ONLY of the two audit wrappers that
//!   literally calls it -- `audit_authorize_and_execute_instrumented_internal`
//!   never calls `self.authorize_and_execute`, it independently re-implements
//!   the same policy/guard/containment/lease/execute sequence) and then
//!   performs its OWN real substrate write as the persist step.
//! - **Receipt-before-action ground truth.** The engine dispatches, THEN
//!   would persist if anything persisted at all; there is no atomic journal
//!   tying the two together. This harness's persist step is a real, signed
//!   `PheromoneDeposit` -- a genuine substrate write, not a bookkeeping side
//!   channel -- so Task 2's fault classes have a real boundary to split.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use swarm_core::ThreatClass;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, PolicyConfig, RuntimeMode};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_pheromone::{
    DepositSigningPayload, InMemoryPheromoneSubstrate, PheromoneSubstrate, SubstrateError,
};
use swarm_policy::static_gate::StaticApprovalGate;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalGate, CapabilityLease, PolicyVerdict};
use swarm_response::{
    ExecutionMode, ResponseError, ResponseExecutor, ResponseReceipt, ResponseStatus,
};
use swarm_runtime::red_swarm::RedGenomeRng;
use swarm_runtime::{RuntimeError, SwarmRuntime};

// ---------------------------------------------------------------------------
// 1. The deterministic single-threaded executor.
// ---------------------------------------------------------------------------

/// Build a `RawWaker` whose clone/wake/wake_by_ref/drop are all no-ops.
fn noop_raw_waker() -> RawWaker {
    fn clone_waker(_: *const ()) -> RawWaker {
        noop_raw_waker()
    }
    fn no_op(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_waker, no_op, no_op, no_op);
    RawWaker::new(std::ptr::null(), &VTABLE)
}

/// A `Waker` that does nothing. This harness's executor never parks and
/// never relies on a wake notification to re-poll -- it just loops -- so a
/// waker that does nothing is exactly correct, not a shortcut.
fn noop_waker() -> Waker {
    // SAFETY: every vtable function ignores its `data` pointer and does
    // nothing; `clone_waker` returns an equally inert raw waker with the
    // same null data pointer. There is no reference count and nothing to
    // free, so cloning, waking, and dropping this waker are safe in any
    // order, any number of times.
    unsafe { Waker::from_raw(noop_raw_waker()) }
}

/// Outcome of polling a future under a bounded poll budget.
enum BudgetedPoll<'a, T> {
    /// The future resolved within budget, after this many total polls.
    Ready(T, u32),
    /// The budget was exhausted before the future resolved. The future is
    /// handed back ALIVE -- this call never polls it again -- so the caller
    /// decides what exhaustion means: drop it now (Task 2's future-drop
    /// fault classes simulate a crash this way) or act on the world around
    /// it and resume polling it to completion (Task 2's substrate
    /// close/reopen fault class, which is not a drop at all).
    Exhausted(Pin<Box<dyn Future<Output = T> + 'a>>, u32),
}

/// Poll `future` at most `max_polls` times using a deterministic,
/// single-threaded executor: a manual loop over `Pin<&mut dyn Future>` (via
/// `.as_mut()` on the owned `Pin<Box<dyn Future>>`) with the no-op `Waker`
/// above. No wall clock, no entropy, no tokio -- the same future polls in
/// the same order every time, on every machine.
///
/// This is the primitive [`FaultPlan`]'s drop/checkpoint machinery is built
/// on: Task 1 only ever calls it with an unbounded budget (see
/// [`run_to_completion`]); Task 2 calls it directly with a small, seed-derived
/// budget for the future-drop fault classes.
fn poll_bounded<'a, T>(
    mut future: Pin<Box<dyn Future<Output = T> + 'a>>,
    max_polls: u32,
) -> BudgetedPoll<'a, T> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut polls = 0u32;
    while polls < max_polls {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return BudgetedPoll::Ready(value, polls + 1),
            Poll::Pending => polls += 1,
        }
    }
    BudgetedPoll::Exhausted(future, polls)
}

/// Run `future` to completion under the deterministic executor and report
/// how many polls it took. Task 1's only exercised path
/// (`FaultClass::NoFault`): no budget, no drop, ever.
fn run_to_completion<'a, T>(future: Pin<Box<dyn Future<Output = T> + 'a>>) -> (T, u32) {
    match poll_bounded(future, u32::MAX) {
        BudgetedPoll::Ready(value, polls) => (value, polls),
        BudgetedPoll::Exhausted(future, polls) => {
            drop(future);
            unreachable!(
                "poll budget of u32::MAX exhausted after {polls} polls without resolving: no \
                 episode in this harness should legitimately need this many"
            )
        }
    }
}

/// A future that is `Pending` exactly once, then `Ready(())`.
///
/// This harness's own synthetic checkpoint primitive. It exists because the
/// real components underneath are not guaranteed to yield where a checkpoint
/// is needed -- `InMemoryPheromoneSubstrate::deposit` never yields at all,
/// its body is synchronous `RwLock` bookkeeping wrapped in an `async fn` --
/// so a real, controllable poll boundary has to be manufactured rather than
/// discovered. Two call sites use it: inside
/// [`RecordingResponseAdapter::execute`] (before the dispatch effect fires)
/// and inside [`run_episode`] (after `authorize_and_execute` resolves,
/// before the substrate persist call begins). Task 2's future-drop fault
/// classes stop the deterministic executor's poll budget at exactly these
/// two boundaries; its substrate close/reopen class acts at the second one
/// without dropping.
struct YieldOnce {
    yielded: bool,
}

impl YieldOnce {
    fn new() -> Self {
        Self { yielded: false }
    }
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

// ---------------------------------------------------------------------------
// 2. FaultPlan + seed mapping (DST-05).
// ---------------------------------------------------------------------------

/// The one fault class Task 1 wires: run the episode to completion. Task 2
/// adds the three DST-02 fault classes (future-drop before dispatch,
/// future-drop after dispatch but before receipt persistence, substrate
/// close/reopen) as further variants and gives the executor logic to act on
/// them. This task only needs the enum to exist so `FaultPlan`'s shape does
/// not change out from under Task 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultClass {
    NoFault,
}

/// One seed's deterministic fault injection plan (DST-05).
///
/// `checkpoint` is a raw deterministic draw from the seed's own
/// [`RedGenomeRng`] stream. Task 1 does not interpret it -- there is only one
/// fault class, and it needs no checkpoint -- but the field exists now so
/// Task 2 can give it meaning (e.g. a poll count to drop at) without
/// changing `FaultPlan`'s shape or re-deriving how seeds map to plans. If
/// Task 2 also needs to draw a class selector, it should do so BEFORE
/// drawing `checkpoint` from the same stream and document the new order --
/// this task guarantees only that `for_seed` itself is deterministic, not
/// that today's draw order is permanently frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FaultPlan {
    seed: u64,
    class: FaultClass,
    checkpoint: u64,
}

impl FaultPlan {
    /// Map a seed to its `FaultPlan`, deterministically: same seed, same
    /// plan, every time, on every machine (no wall clock, no OS entropy --
    /// `RedGenomeRng` is seeded only from `seed`).
    fn for_seed(seed: u64) -> Self {
        let mut rng = RedGenomeRng::from_u64(seed);
        let checkpoint = rng.next_below(u64::MAX);
        Self {
            seed,
            class: FaultClass::NoFault,
            checkpoint,
        }
    }
}

// ---------------------------------------------------------------------------
// 3. The real no-mock stack: recording ResponseAdapter, real gate, real
//    substrate.
// ---------------------------------------------------------------------------

/// One dispatch the recording adapter observed, in poll order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DispatchRecord {
    hunt_id: String,
    order: u64,
}

/// The real [`ResponseExecutor`] this harness instantiates `SwarmRuntime`
/// over. It performs no external side effect -- there is nothing outside
/// this process for a DST episode to affect -- but it IS a real adapter the
/// generic runtime is instantiated over (`SwarmRuntime<P, E>`, `E =` this
/// type), not a mock of the runtime, gate, or substrate (which stay real per
/// DST-01). This is idiomatic in this crate's own integration tests: see
/// `dispatch_integration.rs`'s `AtomicUsize` recording-counter pattern --
/// real components observed, not mocked.
///
/// Its `execute` yields exactly once (via [`YieldOnce`]) before the dispatch
/// effect becomes observable: a controllable checkpoint Task 2's
/// future-drop fault class (a) stops the executor at (before this ever
/// resolves, the dispatch log stays empty -- the action never took effect).
#[derive(Clone, Default)]
struct RecordingResponseAdapter {
    dispatch_sequence: Arc<AtomicU64>,
    log: Arc<Mutex<Vec<DispatchRecord>>>,
}

impl RecordingResponseAdapter {
    fn dispatch_log(&self) -> Vec<DispatchRecord> {
        self.log.lock().unwrap().clone()
    }

    /// Record one dispatch and return its monotonic order. Called from
    /// exactly one place: after `execute`'s deliberate [`YieldOnce`]
    /// checkpoint, so this line running IS "the action took effect."
    fn record_dispatch(&self, hunt_id: &str) -> u64 {
        let order = self.dispatch_sequence.fetch_add(1, Ordering::SeqCst);
        self.log.lock().unwrap().push(DispatchRecord {
            hunt_id: hunt_id.to_string(),
            order,
        });
        order
    }
}

#[async_trait]
impl ResponseExecutor for RecordingResponseAdapter {
    async fn execute(
        &self,
        request: &ActionRequest,
        _lease: &CapabilityLease,
        mode: ExecutionMode,
    ) -> Result<ResponseReceipt, ResponseError> {
        // Checkpoint: nothing above this line is observable; nothing below
        // it runs until this resolves. Task 2's fault class (a) drops the
        // episode while stuck exactly here.
        YieldOnce::new().await;

        let order = self.record_dispatch(&request.hunt_id.0);
        Ok(ResponseReceipt {
            receipt_id: format!("dst-receipt:{}:{order}", request.hunt_id.0),
            action: request.action.kind().to_string(),
            mode,
            status: match mode {
                ExecutionMode::DryRun => ResponseStatus::Simulated,
                ExecutionMode::Enforced => ResponseStatus::Executed,
            },
            summary: "dst harness dispatch recorded".to_string(),
            details: serde_json::json!({ "dispatch_order": order }),
            audit: Default::default(),
        })
    }
}

// ---------------------------------------------------------------------------
// 4. The receipt-persist step: Task 1's chosen entry point's other half.
// ---------------------------------------------------------------------------

/// A fixed, non-secret signing identity used only to produce a validly
/// signed [`PheromoneDeposit`]. Infrastructure for a real substrate write,
/// not something under test: this harness's determinism guarantee is about
/// the episode's observable shape, not about which key signs its persist
/// step, so the key does not vary by seed.
const HARNESS_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];

/// Task 1's chosen receipt-persist step (see task-1-report.md for the full
/// entry-point decision): a real, signature-validated [`PheromoneDeposit`]
/// into the real substrate, carrying the receipt's identifying fields in its
/// `indicator` payload.
///
/// Nothing in `SwarmRuntime` performs a substrate write on its own --
/// `authorize_and_execute` and `audit_authorize_and_execute` both simply
/// return a value, and grep confirms no `substrate`/`deposit` reference
/// exists anywhere in `crates/swarm-runtime/src/lib.rs`. This function IS
/// the harness's persist step, and deliberately a REAL substrate write (real
/// signature validation via `validate_deposit_signature`, real
/// `RwLock`-guarded storage), not a synthetic bookkeeping side channel --
/// so DST-02's fault points (b) and (c) have a real substrate boundary to
/// act on in Task 2.
fn deposit_for_receipt(receipt: &ResponseReceipt, timestamp_secs: i64) -> PheromoneDeposit {
    let signing_key = SigningKey::from_bytes(&HARNESS_SIGNING_KEY_BYTES);
    let verifying_key = signing_key.verifying_key();
    let agent_id = AgentId::from_verifying_key(&verifying_key);

    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({
            "harness": "dst_fault_injection",
            "receipt_id": receipt.receipt_id,
            "action": receipt.action,
            "status": receipt.status,
        }),
        threat_class: ThreatClass::Custom("dst_harness_receipt_persist".to_string()),
        severity: Severity::Low,
        confidence: 1.0,
        timestamp: timestamp_secs,
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
    let signature = signing_key.sign(&payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = verifying_key.to_bytes().to_vec();
    deposit
}

// ---------------------------------------------------------------------------
// 5. The episode: allow -> dispatch -> receipt-persist.
// ---------------------------------------------------------------------------

/// What one episode's `authorize_and_execute` call, and (on success) its
/// persist attempt, produced.
#[derive(Debug)]
struct EpisodeOutcome {
    authorize_result: Result<ResponseReceipt, RuntimeError>,
    persist_result: Option<Result<(), SubstrateError>>,
}

/// The episode (DST-01): allow -> dispatch -> receipt-persist, for one
/// `ActionRequest` against the real stack.
///
/// The checkpoint between `authorize_and_execute` resolving and the
/// substrate persist call beginning is a SECOND, independent [`YieldOnce`].
/// Deliberately: without it, `authorize_and_execute` resolving and the
/// (eagerly-ready) deposit future's first poll would both complete inside
/// the SAME outer poll, and Task 2's fault class (b) -- "after dispatch, but
/// before receipt persistence" -- would have no real boundary to stop at.
///
/// A response that dispatches but reports failure (`ResponseStatus::Failed`)
/// makes `authorize_and_execute` itself return `Err`, even though the
/// adapter's dispatch WAS recorded -- see `RuntimeError::Response` in
/// `lib.rs`. This episode's fixed request always succeeds, so that split
/// never arises here, but Task 3's oracles must key off the adapter's
/// dispatch log, not off `authorize_result`'s `Ok`/`Err` split, to stay
/// correct for that case too.
async fn run_episode(
    runtime: &SwarmRuntime<StaticApprovalGate, RecordingResponseAdapter>,
    substrate: &InMemoryPheromoneSubstrate,
    request: &ActionRequest,
    context: &ApprovalContext,
) -> EpisodeOutcome {
    let authorize_result = runtime.authorize_and_execute(request, context).await;

    // Checkpoint: dispatch (if any) has already happened; persistence has
    // not started. Task 2's fault class (b) drops here; its substrate
    // close/reopen class (c) acts on the substrate here, then lets the
    // episode continue.
    YieldOnce::new().await;

    let persist_result = match &authorize_result {
        Ok(receipt) => Some(
            substrate
                .deposit(deposit_for_receipt(receipt, context.now_ms / 1_000))
                .await,
        ),
        Err(_) => None,
    };

    EpisodeOutcome {
        authorize_result,
        persist_result,
    }
}

// ---------------------------------------------------------------------------
// 6. The fixed harness stack + episode driver.
// ---------------------------------------------------------------------------

/// A deterministic policy configuration under which this harness's fixed
/// request has a known ground-truth verdict.
///
/// `Escalate` is not in `StaticApprovalGate::destructive_action`'s list and
/// is not `DeployDecoy`, so `evaluate` (`crates/swarm-policy/src/static_gate.rs`)
/// falls through to `static.default_allow` regardless of severity or these
/// threshold values. Written out explicitly (matching
/// `PolicyConfig::default()`) so the ground truth is legible in this file
/// without cross-referencing another crate.
fn harness_policy_config() -> PolicyConfig {
    PolicyConfig {
        human_gate_severity: Severity::High,
        lease_ttl_ms: 60_000,
        max_actions_per_scope_per_minute: 1_000,
        rules: Vec::new(),
    }
}

/// A deterministic substrate configuration. Values are inconsequential to
/// this harness (one request, one deposit, no concentration/escalation
/// queries) but must be present and valid to construct a real
/// `InMemoryPheromoneSubstrate`.
fn harness_pheromone_config() -> PheromoneConfig {
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

/// The one `ActionRequest` Task 1's episode drives -- fixed, not seeded: only
/// the `FaultPlan` varies by seed this task. `Escalate` is deliberately
/// non-destructive and not a containment action
/// (`swarm_runtime::containment::is_containment_action` matches only
/// `QuarantineFile`, `SuspendProcess`, `IsolateHost`, and
/// `TerminateUserSession`), so no containment lease store is needed and
/// `prepare_containment` short-circuits to `Ok(None)`.
fn harness_action_request() -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("dst-hunt-episode".to_string()),
        requested_by: AgentId("dst-harness".to_string()),
        action: ResponseAction::Escalate {
            summary: "dst fault-injection harness episode".to_string(),
            urgency: Severity::Medium,
        },
        severity: Severity::Medium,
        evidence: serde_json::json!({ "signal": "dst_fault_injection_harness" }),
    }
}

/// The fixed `ApprovalContext` Task 1's episode drives under. `live_mode` and
/// `now_ms` are constants, not the wall clock, so every episode's context is
/// byte-identical.
fn harness_approval_context() -> ApprovalContext {
    ApprovalContext {
        live_mode: true,
        receipt_chain: Vec::new(),
        correlation_id: None,
        now_ms: 1_700_000_000_000,
    }
}

/// Everything one seed's episode produced: this task's own ground-truth
/// tests, and the oracles Task 3 will add, both read this.
#[derive(Debug)]
struct EpisodeObservation {
    plan: FaultPlan,
    outcome: EpisodeOutcome,
    dispatch_log: Vec<DispatchRecord>,
    persisted_deposits: Vec<PheromoneDeposit>,
    polls: u32,
}

/// Build a fresh, real, no-mock stack and drive exactly one episode for
/// `seed`'s `FaultPlan`.
///
/// A fresh stack every call: episodes must not share mutable state (an
/// adapter's dispatch log, a substrate's deposits) across seeds, or a later
/// seed's observation would be contaminated by an earlier one's.
fn drive_episode_for_seed(seed: u64) -> EpisodeObservation {
    let plan = FaultPlan::for_seed(seed);
    assert_eq!(
        plan.class,
        FaultClass::NoFault,
        "Task 1 wires only the no-fault plan"
    );

    let adapter = RecordingResponseAdapter::default();
    let gate = StaticApprovalGate::from_config(&harness_policy_config());
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, adapter.clone());
    let substrate = InMemoryPheromoneSubstrate::new(harness_pheromone_config());
    let request = harness_action_request();
    let context = harness_approval_context();

    let episode: Pin<Box<dyn Future<Output = EpisodeOutcome> + '_>> =
        Box::pin(run_episode(&runtime, &substrate, &request, &context));
    let (outcome, polls) = run_to_completion(episode);

    let query: Pin<Box<dyn Future<Output = Result<Vec<PheromoneDeposit>, SubstrateError>> + '_>> =
        Box::pin(substrate.recent_deposits(16));
    let (persisted_deposits, _query_polls) = run_to_completion(query);

    EpisodeObservation {
        plan,
        outcome,
        dispatch_log: adapter.dispatch_log(),
        persisted_deposits: persisted_deposits.unwrap(),
        polls,
    }
}

// ---------------------------------------------------------------------------
// 7. SWARM_DST_SEED (DST-05).
// ---------------------------------------------------------------------------

/// The seed Task 1's env-driven replay test uses when `SWARM_DST_SEED` is
/// unset, so the scoped test suite still runs green with no special
/// environment.
const DEFAULT_REPLAY_SEED: u64 = 0;

/// The seed a `SWARM_DST_SEED=<n>` value names, or `default` if `raw` is
/// `None` or is not a valid `u64`.
///
/// Pure and independently testable: it takes the raw string the environment
/// would have handed back rather than reading `std::env::var` itself, so
/// `dst_seed_env_selection_parses_a_valid_value_and_falls_back_otherwise`
/// below exercises the actual selection logic without reading or mutating
/// the real process environment.
fn seed_from_raw_env(raw: Option<&str>, default: u64) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// DST-05's real entry point: `SWARM_DST_SEED=<n>` selects seed `n`.
fn seed_from_env() -> u64 {
    seed_from_raw_env(
        std::env::var("SWARM_DST_SEED").ok().as_deref(),
        DEFAULT_REPLAY_SEED,
    )
}

// ---------------------------------------------------------------------------
// 8. Tests.
// ---------------------------------------------------------------------------

#[test]
fn dst_no_fault_episode_dispatches_exactly_once_and_persists_a_matching_receipt() {
    let observation = drive_episode_for_seed(0);

    assert_eq!(
        observation.dispatch_log.len(),
        1,
        "the action must dispatch exactly once, got {:?}",
        observation.dispatch_log
    );

    let receipt = match &observation.outcome.authorize_result {
        Ok(receipt) => receipt,
        Err(error) => panic!("expected Ok(receipt), got RuntimeError: {error}"),
    };
    assert_eq!(receipt.status, ResponseStatus::Executed);

    let persisted = observation
        .outcome
        .persist_result
        .as_ref()
        .expect("a successful dispatch must attempt a substrate persist");
    assert!(
        persisted.is_ok(),
        "the substrate persist must succeed: {persisted:?}"
    );

    assert_eq!(
        observation.persisted_deposits.len(),
        1,
        "exactly one deposit must have persisted to the real substrate"
    );
    assert_eq!(
        observation.persisted_deposits[0].indicator["receipt_id"],
        receipt.receipt_id
    );
}

#[test]
fn dst_no_fault_episode_disposition_matches_the_deterministic_allow_verdict() {
    let policy_config = harness_policy_config();
    let gate = StaticApprovalGate::from_config(&policy_config);
    let request = harness_action_request();
    let context = harness_approval_context();
    let verdict = gate.evaluate(&request, &context).unwrap().verdict;
    assert_eq!(
        verdict,
        PolicyVerdict::Allow,
        "this harness's fixed request must be a deterministic Allow so the no-fault episode \
         actually dispatches"
    );

    let observation = drive_episode_for_seed(0);
    let receipt = observation
        .outcome
        .authorize_result
        .as_ref()
        .expect("an Allow verdict must produce Ok(receipt)");
    assert_eq!(
        receipt.status,
        ResponseStatus::Executed,
        "Allow + RuntimeMode::LiveResponse must produce an Executed disposition"
    );
}

#[test]
fn dst_no_fault_episode_polls_through_both_real_checkpoints_before_resolving() {
    let observation = drive_episode_for_seed(0);
    assert_eq!(
        observation.polls, 3,
        "expected exactly 3 polls (pending pre-dispatch, pending post-dispatch/pre-persist, then \
         ready) -- got {}; the checkpoint machinery Task 2 extends is not shaped as designed",
        observation.polls
    );
}

#[test]
fn dst_fault_plan_for_seed_is_byte_identical_across_repeated_calls() {
    let first = FaultPlan::for_seed(4242);
    let second = FaultPlan::for_seed(4242);
    assert_eq!(
        first, second,
        "the same seed must map to a byte-identical FaultPlan every time"
    );
}

#[test]
fn dst_fault_plan_differs_across_seeds_via_its_checkpoint_draw() {
    let a = FaultPlan::for_seed(1);
    let b = FaultPlan::for_seed(2);
    assert_ne!(
        a.checkpoint, b.checkpoint,
        "two different seeds must not collide on their checkpoint draw"
    );
    assert_eq!(a.class, FaultClass::NoFault);
    assert_eq!(b.class, FaultClass::NoFault);
}

#[test]
fn dst_seed_env_selection_parses_a_valid_value_and_falls_back_otherwise() {
    assert_eq!(seed_from_raw_env(Some("42"), 0), 42);
    assert_eq!(
        seed_from_raw_env(Some("  7  "), 0),
        7,
        "surrounding whitespace (as a shell export can leave) must still parse"
    );
    assert_eq!(
        seed_from_raw_env(None, 9),
        9,
        "unset must fall back to the default seed"
    );
    assert_eq!(
        seed_from_raw_env(Some("not-a-number"), 9),
        9,
        "an invalid value must fall back rather than panic"
    );
}

#[test]
fn dst_swarm_dst_seed_env_selects_exactly_one_seed_when_set() {
    let seed = seed_from_env();
    let observation = drive_episode_for_seed(seed);
    // Visible with `--nocapture`, so `SWARM_DST_SEED=<n> cargo test -p
    // swarm-runtime dst_swarm_dst_seed_env_selects_exactly_one_seed_when_set
    // -- --nocapture` shows a human exactly which seed and plan replayed --
    // the one-command reproduction DST-05 asks for.
    println!(
        "SWARM_DST_SEED replay: seed={} plan={:?}",
        observation.plan.seed, observation.plan
    );
    assert_eq!(
        observation.plan.seed, seed,
        "the episode driven must be exactly the seed SWARM_DST_SEED named (or the default when unset)"
    );
    assert_eq!(observation.dispatch_log.len(), 1);
    assert!(observation.outcome.authorize_result.is_ok());
    assert!(matches!(observation.outcome.persist_result, Some(Ok(()))));
}
