#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Phase 286 -- the deterministic-simulation fault-injection harness
//! (DST-01, DST-02, DST-05).
//!
//! This file drives the REAL `SwarmRuntime::authorize_and_execute`, a real
//! `StaticApprovalGate`, and a real `InMemoryPheromoneSubstrate` -- no mocks
//! of any of the three -- through a hand-rolled deterministic executor with
//! no wall clock, no OS entropy, and no tokio. Task 1 built the foundation
//! and wired only `FaultClass::NoFault`; Task 2 (this extension) adds the
//! three DST-02 fault classes and the machinery that fires them --
//! `RecordingResponseAdapter`'s dispatch-boundary checkpoint (precise
//! before/after-dispatch drop control) and `SubstrateSeam` (the real
//! close/reopen seam for class (c)). See
//! `.superpowers/sdd/286-01-PLAN/task-1-report.md` (the foundation) and
//! `.superpowers/sdd/286-01-PLAN/task-2-report.md` (this extension) for the
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
//!   channel -- so the three fault classes below have a real boundary to
//!   split.
//! - **The three fault classes (DST-02), and how each fires.** (a)
//!   `DropBeforeDispatch`: the executor polls the episode to budget 1 and
//!   drops it -- stuck inside the adapter's dispatch checkpoint, before
//!   `record_dispatch` ever runs. (b) `DropAfterDispatchBeforePersist`:
//!   polls to budget 2 and drops -- dispatch recorded exactly once, but the
//!   substrate `.deposit(..)` call never begins. (c) `SubstrateCloseReopen`:
//!   polls to the SAME budget 2 as (b), but instead of dropping, closes then
//!   reopens the real substrate (`SubstrateSeam::close_then_reopen`) while
//!   the future sits suspended, then resumes it to completion -- the
//!   episode's persist call then executes against the newly reopened real
//!   instance. A seed selects a class deterministically
//!   (`FaultPlan::for_seed`, via `RedGenomeRng::choose` over
//!   `ALL_FAULT_CLASSES`).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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

/// Poll `future` to exactly `budget` polls and hand it back `Exhausted`,
/// still alive -- panicking if it resolves any earlier. Every fault
/// checkpoint budget this file uses ([`BEFORE_DISPATCH_POLL_BUDGET`],
/// [`AFTER_DISPATCH_POLL_BUDGET`]) is derived from the hand-traced, pinned
/// poll sequence: an early `Ready` here means that sequence silently
/// changed shape, which every one of Task 2's fault classes depends on
/// being false, so this is a loud diagnostic, not a silent mismatch.
fn poll_to_checkpoint<'a, T>(
    future: Pin<Box<dyn Future<Output = T> + 'a>>,
    budget: u32,
) -> (Pin<Box<dyn Future<Output = T> + 'a>>, u32) {
    match poll_bounded(future, budget) {
        BudgetedPoll::Ready(value, polls) => {
            drop(value);
            unreachable!(
                "episode resolved after only {polls} poll(s), before the intended checkpoint at \
                 budget {budget}: the hand-traced poll sequence this fault class relies on has \
                 changed shape"
            )
        }
        BudgetedPoll::Exhausted(future, polls) => (future, polls),
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

/// Poll budget for DST-02 fault class (a): the outer episode future's FIRST
/// poll always stalls inside `RecordingResponseAdapter::execute`'s
/// `YieldOnce`, before `record_dispatch` ever runs -- hand-traced (and
/// pinned by Task 1's `dst_no_fault_episode_polls_through_both_real_checkpoints_before_resolving`,
/// which asserts the full no-fault sequence resolves in exactly 3 polls
/// total). Stopping at budget 1 lands exactly there, every time.
const BEFORE_DISPATCH_POLL_BUDGET: u32 = 1;

/// Poll budget for DST-02 fault classes (b) and (c): by poll 2, the
/// adapter's `YieldOnce` has resolved (dispatch recorded exactly once) and
/// `authorize_and_execute`'s fully-synchronous tail has completed, but
/// `run_episode`'s own second `YieldOnce` -- polled for the first time in
/// this same poll -- is `Pending`, so the substrate `.deposit(..)` call has
/// not yet begun. Stopping at budget 2 lands exactly there, every time; see
/// `BEFORE_DISPATCH_POLL_BUDGET`'s doc comment for the same hand-traced
/// sequence.
const AFTER_DISPATCH_POLL_BUDGET: u32 = 2;

/// The four fault classes DST-02 requires. Task 1 wired only `NoFault`;
/// Task 2 adds the other three variants AND the executor logic
/// (`run_episode_under_fault`) that acts on them.
///
/// - `NoFault`: run the episode to completion, no injected fault.
/// - `DropBeforeDispatch` (DST-02 class (a)): the deterministic executor
///   drops the episode future at [`BEFORE_DISPATCH_POLL_BUDGET`] -- BEFORE
///   `RecordingResponseAdapter::execute`'s dispatch effect becomes
///   observable. The action never takes effect; the dispatch log stays
///   empty.
/// - `DropAfterDispatchBeforePersist` (DST-02 class (b)): the executor drops
///   the episode future at [`AFTER_DISPATCH_POLL_BUDGET`] -- the dispatch IS
///   recorded, but the substrate persist call never begins. A real
///   crash-window split between action and receipt, not a bug in the fault
///   injector (see Task 1's report on the engine's receipt-before-action
///   ground truth).
/// - `SubstrateCloseReopen` (DST-02 class (c)): NOT a drop. The executor
///   stops the episode future at the SAME [`AFTER_DISPATCH_POLL_BUDGET`]
///   checkpoint as `DropAfterDispatchBeforePersist`, but instead of dropping
///   it, closes then reopens the real substrate
///   ([`SubstrateSeam::close_then_reopen`]) while the future sits suspended,
///   then resumes the SAME future to completion -- so the episode's persist
///   call executes against the newly reopened real substrate instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultClass {
    NoFault,
    DropBeforeDispatch,
    DropAfterDispatchBeforePersist,
    SubstrateCloseReopen,
}

/// Every fault class, in the fixed order [`FaultPlan::for_seed`] hands to
/// [`RedGenomeRng::choose`] for its class-selector draw. Also this file's
/// own enumeration of "all classes" for coverage tests and the
/// determinism sweep below.
const ALL_FAULT_CLASSES: [FaultClass; 4] = [
    FaultClass::NoFault,
    FaultClass::DropBeforeDispatch,
    FaultClass::DropAfterDispatchBeforePersist,
    FaultClass::SubstrateCloseReopen,
];

/// One seed's deterministic fault injection plan (DST-05).
///
/// `class` is drawn first from the seed's [`RedGenomeRng`] stream, via
/// `choose` over [`ALL_FAULT_CLASSES`] -- Task 2's addition: "each class is
/// selected deterministically by seed." `checkpoint` is drawn immediately
/// after, from the same stream, exactly as Task 1 left it.
///
/// Task 2 does NOT give `checkpoint` further meaning, despite Task 1's
/// report speculating it would "most likely" become a poll budget: this
/// harness's fixed episode has exactly two real, controllable poll
/// checkpoints ([`BEFORE_DISPATCH_POLL_BUDGET`], [`AFTER_DISPATCH_POLL_BUDGET`]),
/// and every active fault class's poll budget is an intrinsic property of
/// the class itself (there is only one sensible checkpoint for "before
/// dispatch" and only one for "after dispatch, before persist" -- no free
/// parameter for a per-seed `checkpoint` value to usefully vary). So
/// `checkpoint` remains a reserved, uninterpreted-but-deterministic draw,
/// left for a future task that needs it without reshaping `FaultPlan`
/// again.
///
/// Changing the draw order (this task adds the `class` draw BEFORE
/// `checkpoint`) reassigns which checkpoint value every seed gets --
/// expected and pre-documented by Task 1's own report; only `for_seed`'s
/// determinism (same seed, same plan, forever, given the current
/// implementation) is guaranteed, never a specific seed's mapping across
/// task boundaries.
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
        let class = *rng
            .choose(&ALL_FAULT_CLASSES)
            .expect("ALL_FAULT_CLASSES is a fixed, non-empty array");
        let checkpoint = rng.next_below(u64::MAX);
        Self {
            seed,
            class,
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
// 5. The substrate seam for DST-02 fault class (c): real close/reopen.
// ---------------------------------------------------------------------------

/// One lifecycle transition [`SubstrateSeam`] observed, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubstrateLifecycleEvent {
    Closed,
    Reopened,
}

/// A REAL `InMemoryPheromoneSubstrate` behind a handle the deterministic
/// executor can close and reopen from OUTSIDE the episode future -- DST-02
/// fault class (c).
///
/// `InMemoryPheromoneSubstrate` has no close/reopen operation of its own --
/// there is no OS handle for a pure in-memory store to close -- so this seam
/// manufactures a real one the only honest way available: dropping the real
/// instance (releasing its storage, exactly what an in-memory substrate
/// restart means -- this IS the DST-06 evidence boundary, not a shortcut
/// around it) and constructing a genuinely new real
/// `InMemoryPheromoneSubstrate::new(..)` in its place. This mirrors this
/// crate's OWN test idiom for "close then reopen" a real substrate --
/// `local_journal_recovers_deposits_after_reopen`
/// (`crates/swarm-pheromone/src/substrate.rs`) drops a
/// `LocalJournalPheromoneSubstrate` handle and calls `::open` again on the
/// same path; there is no other concept of substrate close/reopen anywhere
/// in this crate to be faithful to.
///
/// `run_episode` closes over `&SubstrateSeam` for its (single, checkpointed)
/// `.deposit(..)` call, so whichever real instance is current AT THE MOMENT
/// that call actually executes is the one it observes: `close_then_reopen`
/// runs synchronously, entirely between two polls of the suspended episode
/// future (never concurrently with it), so the future itself never
/// observes a `None` ("closed") state -- it only ever sees the substrate
/// that is current when it resumes.
///
/// This is not a mock of `InMemoryPheromoneSubstrate` or
/// `PheromoneSubstrate`: every `deposit`/`recent_deposits` call this seam
/// forwards executes against a real instance. The seam only owns WHICH real
/// instance is live.
struct SubstrateSeam {
    config: PheromoneConfig,
    inner: RwLock<Option<InMemoryPheromoneSubstrate>>,
    lifecycle: Mutex<Vec<SubstrateLifecycleEvent>>,
}

impl SubstrateSeam {
    /// Construct a seam holding one freshly opened real substrate.
    fn open(config: PheromoneConfig) -> Self {
        let substrate = InMemoryPheromoneSubstrate::new(config.clone());
        Self {
            config,
            inner: RwLock::new(Some(substrate)),
            lifecycle: Mutex::new(Vec::new()),
        }
    }

    /// DST-02 fault class (c)'s seam: drop the current real substrate
    /// instance (close), then construct and install a genuinely new one
    /// (reopen). Called synchronously by the deterministic executor while
    /// the episode future is suspended (`Exhausted`) -- never concurrently
    /// with a live `deposit`/`recent_deposits` call from that future, so a
    /// plain `std::sync::RwLock` (never held across an `.await` -- see
    /// `deposit`/`recent_deposits` below) is sufficient; no async lock is
    /// needed.
    fn close_then_reopen(&self) {
        *self.inner.write().unwrap() = None; // close: drop the real instance
        self.lifecycle
            .lock()
            .unwrap()
            .push(SubstrateLifecycleEvent::Closed);

        let fresh = InMemoryPheromoneSubstrate::new(self.config.clone());
        *self.inner.write().unwrap() = Some(fresh); // reopen: a genuinely new real instance
        self.lifecycle
            .lock()
            .unwrap()
            .push(SubstrateLifecycleEvent::Reopened);
    }

    /// The lifecycle transitions observed so far, in order. Empty for every
    /// fault class except `SubstrateCloseReopen`, where it must read
    /// exactly `[Closed, Reopened]`.
    fn lifecycle_log(&self) -> Vec<SubstrateLifecycleEvent> {
        self.lifecycle.lock().unwrap().clone()
    }

    /// Delegate to whichever real substrate is current.
    /// `InMemoryPheromoneSubstrate`'s fields are all `Arc`-backed handles
    /// (`crates/swarm-pheromone/src/substrate.rs`), so cloning it out from
    /// under the read lock is cheap, and the lock is held only long enough
    /// to do that -- never across the `.await` below.
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        let substrate = self
            .inner
            .read()
            .unwrap()
            .clone()
            .expect("SubstrateSeam.deposit called while closed");
        substrate.deposit(deposit).await
    }

    /// Delegate to whichever real substrate is current. See `deposit` for
    /// why the lock is not held across the `.await`.
    async fn recent_deposits(&self, limit: usize) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let substrate = self
            .inner
            .read()
            .unwrap()
            .clone()
            .expect("SubstrateSeam.recent_deposits called while closed");
        substrate.recent_deposits(limit).await
    }
}

// ---------------------------------------------------------------------------
// 6. The episode: allow -> dispatch -> receipt-persist.
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
/// the SAME outer poll, and fault class (b) -- "after dispatch, but before
/// receipt persistence" -- would have no real boundary to stop at.
///
/// `substrate` is the [`SubstrateSeam`], not a bare `InMemoryPheromoneSubstrate`
/// directly, so fault class (c)'s close/reopen (triggered from OUTSIDE this
/// future, while it sits suspended at the checkpoint below) changes which
/// real instance THIS `.deposit(..)` call observes once the executor
/// resumes it.
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
    substrate: &SubstrateSeam,
    request: &ActionRequest,
    context: &ApprovalContext,
) -> EpisodeOutcome {
    let authorize_result = runtime.authorize_and_execute(request, context).await;

    // Checkpoint: dispatch (if any) has already happened; persistence has
    // not started. Fault class (b) drops here; fault class (c)'s substrate
    // close/reopen acts on `substrate` here (from outside this future),
    // then lets the episode continue.
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
// 7. The fixed harness stack + episode driver.
// ---------------------------------------------------------------------------

/// A deterministic policy configuration under which this harness's fixed
/// request has a known ground-truth verdict.
///
/// `Escalate` is not in `StaticApprovalGate::destructive_action`'s list and
/// is not `DeployDecoy`, so `evaluate` (`crates/swarm-policy/src/static_gate.rs`)
/// falls through to `static.default_allow` regardless of severity or these
/// threshold values. Written out explicitly so the ground truth is legible in
/// this file without cross-referencing another crate. `max_actions_per_scope_per_minute`
/// is `1_000` — deliberately NOT the crate default of `5` — as headroom: the
/// `Escalate`/Medium episode never reaches the rate-limit branch, and this leaves
/// room for a future shared-gate corpus without a per-scope cap biting.
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

/// A request the REAL `StaticApprovalGate` genuinely DENIES: `IsolateHost` is a
/// destructive action, and a destructive action at `Severity::Low` hits the
/// gate's `static.minimum_severity` rule -> `PolicyVerdict::Deny` (mirrors the
/// gate's own `low_severity_isolation_is_denied` test). `authorize_and_execute`
/// returns `Err(ApprovalError::Denied)` at the verdict match, BEFORE the
/// dispatch await and before `prepare_containment`, so this never dispatches
/// and needs no containment store. Used only by the denied-disposition fixture,
/// so Oracle 2's denied branch is positively exercised, not merely present.
fn harness_denied_action_request() -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("dst-hunt-denied".to_string()),
        requested_by: AgentId("dst-harness".to_string()),
        action: ResponseAction::IsolateHost {
            host_id: "dst-denied-host".to_string(),
        },
        severity: Severity::Low,
        evidence: serde_json::json!({ "signal": "dst_fault_injection_harness_denied" }),
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
///
/// `outcome` is `None` exactly when the deterministic executor dropped the
/// episode future before it resolved (fault classes `DropBeforeDispatch`
/// and `DropAfterDispatchBeforePersist`): a simulated crash produces no
/// return value at all, matching a real process crash -- there is no
/// `authorize_and_execute` `Result` and no persist-attempt `Result` to read,
/// only what is externally observable (`dispatch_log`, `persisted_deposits`,
/// `substrate_lifecycle`), exactly as a real caller recovering from a crash
/// would have. `outcome` is `Some(..)` for `NoFault` and
/// `SubstrateCloseReopen`, which both run the episode to completion (class
/// (c) is explicitly NOT a drop).
#[derive(Debug)]
struct EpisodeObservation {
    plan: FaultPlan,
    outcome: Option<EpisodeOutcome>,
    dispatch_log: Vec<DispatchRecord>,
    persisted_deposits: Vec<PheromoneDeposit>,
    substrate_lifecycle: Vec<SubstrateLifecycleEvent>,
    polls: u32,
}

/// Drive `episode` to whatever `class` demands, on the real `substrate` seam
/// behind it. Returns the `EpisodeOutcome` if one was produced (`NoFault`,
/// `SubstrateCloseReopen`) and the total poll count actually taken (for the
/// drop classes, exactly their fixed checkpoint budget, by construction).
///
/// This is the executor-side half of DST-02: `FaultPlan`'s `class` selects
/// which of the three fault behaviors (or none) fires, deterministically.
fn run_episode_under_fault(
    episode: Pin<Box<dyn Future<Output = EpisodeOutcome> + '_>>,
    class: FaultClass,
    substrate: &SubstrateSeam,
) -> (Option<EpisodeOutcome>, u32) {
    match class {
        FaultClass::NoFault => {
            let (outcome, polls) = run_to_completion(episode);
            (Some(outcome), polls)
        }
        FaultClass::DropBeforeDispatch => {
            let (future, polls) = poll_to_checkpoint(episode, BEFORE_DISPATCH_POLL_BUDGET);
            drop(future); // the simulated crash: no more polls, ever
            (None, polls)
        }
        FaultClass::DropAfterDispatchBeforePersist => {
            let (future, polls) = poll_to_checkpoint(episode, AFTER_DISPATCH_POLL_BUDGET);
            drop(future); // the simulated crash: no more polls, ever
            (None, polls)
        }
        FaultClass::SubstrateCloseReopen => {
            let (future, paused_polls) = poll_to_checkpoint(episode, AFTER_DISPATCH_POLL_BUDGET);
            // NOT a drop: act on the world around the still-alive, suspended
            // future, then resume polling the SAME future to completion.
            substrate.close_then_reopen();
            let (outcome, resumed_polls) = run_to_completion(future);
            (Some(outcome), paused_polls + resumed_polls)
        }
    }
}

/// Build a fresh, real, no-mock stack and drive exactly one episode for
/// `plan`, using the fixed `Allow` harness request.
///
/// A fresh stack every call: episodes must not share mutable state (an
/// adapter's dispatch log, a substrate's deposits) across episodes, or one
/// episode's observation would be contaminated by another's.
fn drive_episode(plan: FaultPlan) -> EpisodeObservation {
    drive_episode_with_request(plan, &harness_action_request())
}

/// Drive one episode for `plan` against a caller-supplied `request` on a fresh
/// real stack. Factored out of [`drive_episode`] so the denied-disposition
/// fixture can drive a request the real gate genuinely denies (which never
/// dispatches, so there is no fault surface) through the SAME real
/// `authorize_and_execute` path every other episode uses -- no mock, no second
/// code path.
fn drive_episode_with_request(plan: FaultPlan, request: &ActionRequest) -> EpisodeObservation {
    let adapter = RecordingResponseAdapter::default();
    let gate = StaticApprovalGate::from_config(&harness_policy_config());
    let runtime = SwarmRuntime::new(RuntimeMode::LiveResponse, gate, adapter.clone());
    let substrate = SubstrateSeam::open(harness_pheromone_config());
    let context = harness_approval_context();

    let episode: Pin<Box<dyn Future<Output = EpisodeOutcome> + '_>> =
        Box::pin(run_episode(&runtime, &substrate, request, &context));
    let (outcome, polls) = run_episode_under_fault(episode, plan.class, &substrate);

    let query: Pin<Box<dyn Future<Output = Result<Vec<PheromoneDeposit>, SubstrateError>> + '_>> =
        Box::pin(substrate.recent_deposits(16));
    let (persisted_deposits, _query_polls) = run_to_completion(query);

    EpisodeObservation {
        plan,
        outcome,
        dispatch_log: adapter.dispatch_log(),
        persisted_deposits: persisted_deposits.unwrap(),
        substrate_lifecycle: substrate.lifecycle_log(),
        polls,
    }
}

/// Drive exactly one episode for `seed`'s `FaultPlan` (DST-05's real path:
/// a seed determines everything, including which fault class fires).
fn drive_episode_for_seed(seed: u64) -> EpisodeObservation {
    drive_episode(FaultPlan::for_seed(seed))
}

/// Build the `FaultPlan` for a specific `class` directly, bypassing the
/// seed's RNG class-selector draw entirely. `seed` and `checkpoint` are
/// otherwise unused by any current fault class (see `FaultPlan`'s doc
/// comment), so fixed placeholder values are honest, not a shortcut.
///
/// Used only by this task's own focused, one-class-at-a-time tests below,
/// so each proves its fault class fires at the intended point without
/// depending on which concrete seed the RNG's class-selector draw happens to
/// land on. `FaultPlan::for_seed`'s own seed -> class mapping (exercised by
/// `dst_fault_plan_for_seed_deterministically_selects_one_of_the_four_classes`
/// and the corpus Task 3 adds) is what DST-05/replay actually relies on.
fn fault_plan_for_class(class: FaultClass) -> FaultPlan {
    FaultPlan {
        seed: 0,
        class,
        checkpoint: 0,
    }
}

/// Drive exactly one episode forcing `class`, bypassing seed-based class
/// selection. See `fault_plan_for_class`.
fn drive_episode_for_class(class: FaultClass) -> EpisodeObservation {
    drive_episode(fault_plan_for_class(class))
}

// ---------------------------------------------------------------------------
// 8. SWARM_DST_SEED (DST-05).
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
// 9. The three oracles (DST-03).
// ---------------------------------------------------------------------------
//
// Each oracle is a pure function over ONE episode's `EpisodeObservation`,
// returning `Ok(())` when its correctness property holds and
// `Err(OracleViolation)` -- carrying a human-readable reason -- when it does
// not. They are scoped to the guarantee the engine ACTUALLY makes (Task 1's
// ground truth: the engine dispatches, then -- if anything persists at all --
// persists after, with no atomic journal tying the two together), and they
// name, rather than paper over, what it does NOT (the DST-06 evidence
// boundary: a single-process crash between dispatch and persist legitimately
// leaves an action with no receipt -- fault class (b)).
//
// See `.superpowers/sdd/286-01-PLAN/task-3-report.md` for each oracle's
// precise definition, the defense that it is a real safety property, green on
// the correct engine for all four fault classes, and non-vacuous (would catch
// a regression), plus the per-fault-class coverage-vs-boundary table.

/// The number of deterministic seeds the PR-lane corpus drives: seeds
/// `0..PR_CORPUS_SEED_COUNT`. Sixty-four is small enough for the PR lane
/// (each episode is a handful of synchronous polls) yet wide enough that all
/// four fault classes appear many times over -- the corpus asserts that
/// coverage so a green result is never vacuous.
const PR_CORPUS_SEED_COUNT: u64 = 64;

/// The nightly deep corpus (DST-04) drives seeds `0..NIGHTLY_CORPUS_SEED_COUNT`
/// -- the SAME per-seed episode and three oracles the PR corpus runs, at a
/// scale (>= 5,000) too slow for the PR lane but wide enough to surface a rare
/// seed the 64-seed lane would miss. Its test is `#[ignore]`d so `cargo test`
/// skips it in the PR lane; `.github/workflows/dst-nightly.yml` runs it with
/// `-- --ignored`. Fixed, not env-tunable, so the ">= 5,000 nightly" guarantee
/// is unconditional.
const NIGHTLY_CORPUS_SEED_COUNT: u64 = 5_000;

/// Which correctness property a violation came from. Named in the corpus
/// failure text so a human sees WHICH property broke, not merely that one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Oracle {
    /// Oracle 1: receipt-before-action ordering (the safe direction).
    ReceiptBeforeAction,
    /// Oracle 2: the episode disposition equals what the deterministic gate
    /// verdict demands.
    ExactDisposition,
    /// Oracle 3: a request is dispatched at most once (no double-dispatch).
    NoDoubleDispatch,
}

/// One oracle's finding on one episode: which property, and why it broke.
#[derive(Debug, Clone)]
struct OracleViolation {
    oracle: Oracle,
    detail: String,
}

impl OracleViolation {
    fn new(oracle: Oracle, detail: impl Into<String>) -> Self {
        Self {
            oracle,
            detail: detail.into(),
        }
    }
}

/// Decode the dispatch identity `(hunt_id, order)` a harness receipt-persist
/// deposit claims to record, from its `receipt_id`
/// (`dst-receipt:{hunt_id}:{order}`, minted in
/// `RecordingResponseAdapter::execute` from the monotonic dispatch order that
/// `record_dispatch` returned). The embedded `order` is what lets Oracle 1
/// match a receipt to the SPECIFIC dispatch it claims to record, not merely to
/// "some" dispatch.
///
/// `None` when the deposit is not a harness receipt-persist record (it lacks
/// the `"harness": "dst_fault_injection"` tag every such deposit carries) or
/// its `receipt_id` is malformed -- Oracle 1 treats either as a violation,
/// since the ONLY writes this harness makes to the substrate are
/// receipt-persist deposits, and a receipt whose identity cannot be decoded
/// cannot be shown to record a real dispatch.
fn decode_persisted_receipt(deposit: &PheromoneDeposit) -> Option<(String, u64)> {
    if deposit
        .indicator
        .get("harness")
        .and_then(|value| value.as_str())
        != Some("dst_fault_injection")
    {
        return None;
    }
    let receipt_id = deposit.indicator.get("receipt_id")?.as_str()?;
    // rsplit so a hunt_id containing ':' would still decode; this harness's
    // hunt_id has none, but the parse should not silently depend on that.
    let (hunt_id, order) = receipt_id.strip_prefix("dst-receipt:")?.rsplit_once(':')?;
    Some((hunt_id.to_string(), order.parse::<u64>().ok()?))
}

/// **Oracle 1 -- receipt-before-action ordering (the safe direction).**
///
/// The engine has no journal, so a single-process crash after dispatch but
/// before persist (fault class (b)) legitimately ends with an action
/// dispatched and NO receipt persisted. That action-without-receipt is the
/// DST-06 evidence boundary, NOT a violation -- asserting "every action has a
/// receipt" would be red on every class-(b) seed, which is wrong. So this
/// oracle asserts only the SAFE, always-held direction: no receipt is ever
/// persisted without a corresponding real dispatch that preceded it, and a
/// persisted receipt records the dispatch that actually happened.
///
/// Concretely: every persisted receipt must be backed by a DISTINCT real
/// dispatch it faithfully identifies. Each persisted deposit decodes to the
/// `(hunt_id, order)` it claims to record; that identity must appear in the
/// dispatch log, and no two receipts may claim the same dispatch (a duplicated
/// audit record asserts an action-effect that did not separately happen -- as
/// much a false record as an invented one). Equivalently: the multiset of
/// dispatch identities carried by persisted receipts is contained in the
/// multiset actually dispatched. A phantom/premature receipt -- the genuinely
/// dangerous direction, a false audit record telling responders an action
/// happened when it did not -- carries an identity absent from the dispatch
/// log and is caught here. "Preceded" is observed through the final dispatch
/// log: a completed episode persists only after its dispatch resolved, and a
/// dropped one persists nothing, so a persisted receipt whose dispatch is not
/// in the log is exactly one that got ahead of, or entirely without, its
/// action.
fn oracle_receipt_before_action(observation: &EpisodeObservation) -> Result<(), OracleViolation> {
    let dispatched: Vec<(String, u64)> = observation
        .dispatch_log
        .iter()
        .map(|record| (record.hunt_id.clone(), record.order))
        .collect();
    // A dispatch, once matched by a receipt, cannot back a second receipt.
    let mut claimed = vec![false; dispatched.len()];

    for (index, deposit) in observation.persisted_deposits.iter().enumerate() {
        let Some((hunt_id, order)) = decode_persisted_receipt(deposit) else {
            return Err(OracleViolation::new(
                Oracle::ReceiptBeforeAction,
                format!(
                    "persisted deposit #{index} is not a decodable harness receipt \
                     (indicator={}); a record in the audit substrate must identify a real \
                     dispatch",
                    deposit.indicator
                ),
            ));
        };
        let backing = (0..dispatched.len())
            .find(|&i| !claimed[i] && dispatched[i].0 == hunt_id && dispatched[i].1 == order);
        match backing {
            Some(i) => claimed[i] = true,
            None => {
                // Distinguish the two dangerous shapes so a failing seed's
                // diagnostic says which it is: the identity was recorded (but
                // already accounted for by an earlier persisted receipt) -- a
                // DUPLICATE audit record -- versus never recorded at all -- a
                // PHANTOM record for an action-effect that did not happen.
                let ever_dispatched = dispatched.iter().any(|d| d.0 == hunt_id && d.1 == order);
                let (label, why) = if ever_dispatched {
                    (
                        "duplicate receipt",
                        "was recorded but is already accounted for by an earlier persisted receipt \
                         (two receipts for one dispatch)",
                    )
                } else {
                    (
                        "phantom receipt",
                        "was never recorded -- an action-effect that did not happen",
                    )
                };
                return Err(OracleViolation::new(
                    Oracle::ReceiptBeforeAction,
                    format!(
                        "{label}: persisted deposit #{index} records dispatch \
                         (hunt_id={hunt_id:?}, order={order}), which {why}; dispatch_log={:?}",
                        observation.dispatch_log
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// **Oracle 2 -- exact disposition vs the deterministic verdict.**
///
/// The episode's observable disposition must equal what the real,
/// deterministic gate verdict demands. `expected_verdict` is the ground truth
/// the corpus computes once from the real `StaticApprovalGate`
/// ([`harness_ground_truth_verdict`]), so this oracle is genuinely checked
/// against the gate rather than a hardcoded guess; the non-vacuity proof
/// passes a deliberately wrong verdict to show the coupling is real.
///
/// The disposition depends on BOTH the verdict and whether the fault class
/// runs the episode to completion:
/// - Drop classes ((a), (b)) simulate a crash -- the future is dropped before
///   resolving, so no `Result` is produced at all (exactly as a real process
///   crash yields none). The only disposition consistent with a crash is "no
///   outcome," whatever the verdict was (the gate still ran synchronously, but
///   nothing is observable after the drop); a fabricated outcome for a dropped
///   future is caught here.
/// - Completing classes (`NoFault`, (c)) under an `Allow` verdict must yield
///   `Ok(receipt)` with an `Executed` status (Allow + `LiveResponse` +
///   `Enforced`), and must persist that receipt exactly once. Under a
///   `Deny`/`RequireHuman` verdict (`RequireHuman` is denied under
///   `LiveResponse` -- INVARIANT `RuntimeRequireHumanBlocksLiveExecution`),
///   they must surface an authorization `Err` and never dispatch.
fn oracle_exact_disposition(
    observation: &EpisodeObservation,
    expected_verdict: PolicyVerdict,
) -> Result<(), OracleViolation> {
    let class = observation.plan.class;
    let completes = matches!(
        class,
        FaultClass::NoFault | FaultClass::SubstrateCloseReopen
    );

    if !completes {
        if observation.outcome.is_some() {
            return Err(OracleViolation::new(
                Oracle::ExactDisposition,
                format!(
                    "class {class:?} is a simulated crash: expected no EpisodeOutcome, observed \
                     {:?}",
                    observation.outcome
                ),
            ));
        }
        return Ok(());
    }

    let outcome = match &observation.outcome {
        Some(outcome) => outcome,
        None => {
            return Err(OracleViolation::new(
                Oracle::ExactDisposition,
                format!("class {class:?} runs to completion but produced no EpisodeOutcome"),
            ));
        }
    };

    match expected_verdict {
        PolicyVerdict::Allow => {
            let receipt = match &outcome.authorize_result {
                Ok(receipt) => receipt,
                Err(error) => {
                    return Err(OracleViolation::new(
                        Oracle::ExactDisposition,
                        format!("verdict Allow demands Ok(receipt); observed Err({error})"),
                    ));
                }
            };
            if receipt.status != ResponseStatus::Executed {
                return Err(OracleViolation::new(
                    Oracle::ExactDisposition,
                    format!(
                        "verdict Allow under LiveResponse demands an Executed receipt; observed \
                         {:?}",
                        receipt.status
                    ),
                ));
            }
            if !matches!(outcome.persist_result, Some(Ok(()))) {
                return Err(OracleViolation::new(
                    Oracle::ExactDisposition,
                    format!(
                        "a completing Allow episode must persist its receipt; observed \
                         persist_result={:?}",
                        outcome.persist_result
                    ),
                ));
            }
            if observation.persisted_deposits.len() != 1 {
                return Err(OracleViolation::new(
                    Oracle::ExactDisposition,
                    format!(
                        "a completing Allow episode must leave exactly one persisted receipt; \
                         observed {}",
                        observation.persisted_deposits.len()
                    ),
                ));
            }
            Ok(())
        }
        PolicyVerdict::Deny | PolicyVerdict::RequireHuman => {
            match &outcome.authorize_result {
                Err(RuntimeError::Approval(_)) => {}
                other => {
                    return Err(OracleViolation::new(
                        Oracle::ExactDisposition,
                        format!(
                            "verdict {expected_verdict:?} demands an authorization Err with no \
                             dispatch; observed authorize_result={other:?}"
                        ),
                    ));
                }
            }
            if !observation.dispatch_log.is_empty() {
                return Err(OracleViolation::new(
                    Oracle::ExactDisposition,
                    format!(
                        "verdict {expected_verdict:?} must NOT dispatch; observed dispatch_log={:?}",
                        observation.dispatch_log
                    ),
                ));
            }
            Ok(())
        }
    }
}

/// **Oracle 3 -- no double-dispatch.**
///
/// A request is dispatched AT MOST once. Dispatching the same response twice
/// -- a host quarantined twice, a user session terminated twice -- is the
/// genuinely dangerous direction an at-most-once response guarantee exists to
/// prevent, and it must hold across whatever crash/pause/resume the fault plan
/// models. Fault class (c) is the sharp case: the episode future is polled,
/// paused mid-flight, and RESUMED -- a naive resume that re-entered `execute`
/// would double-dispatch; this oracle proves it does not. The expected
/// dispatch count per class is 0/1/1/1 for (a)/(b)/(c)/`NoFault` -- never 2.
///
/// Stated per request (grouped by `hunt_id`) so it is correct even if an
/// episode ever drove more than one request; no `HashMap` -- a linear scan
/// over distinct hunt_ids, which stays deterministic.
fn oracle_no_double_dispatch(observation: &EpisodeObservation) -> Result<(), OracleViolation> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for record in &observation.dispatch_log {
        match counts
            .iter_mut()
            .find(|(hunt_id, _)| *hunt_id == record.hunt_id)
        {
            Some((_, count)) => *count += 1,
            None => counts.push((record.hunt_id.clone(), 1)),
        }
    }
    for (hunt_id, count) in &counts {
        if *count > 1 {
            return Err(OracleViolation::new(
                Oracle::NoDoubleDispatch,
                format!(
                    "double dispatch: request hunt_id={hunt_id:?} was dispatched {count} times \
                     (dispatch_log={:?}); an at-most-once response must never repeat, even across \
                     the crash/pause/resume the fault plan models",
                    observation.dispatch_log
                ),
            ));
        }
    }
    Ok(())
}

/// Evaluate all three oracles for one episode against the deterministic
/// ground-truth `expected_verdict`, returning every violation found (an
/// episode can break more than one property; the corpus reports them all).
fn evaluate_oracles(
    observation: &EpisodeObservation,
    expected_verdict: PolicyVerdict,
) -> Vec<OracleViolation> {
    let mut violations = Vec::new();
    if let Err(violation) = oracle_receipt_before_action(observation) {
        violations.push(violation);
    }
    if let Err(violation) = oracle_exact_disposition(observation, expected_verdict) {
        violations.push(violation);
    }
    if let Err(violation) = oracle_no_double_dispatch(observation) {
        violations.push(violation);
    }
    violations
}

/// The deterministic ground-truth verdict for `request`, computed from the
/// REAL `StaticApprovalGate` (not hardcoded) -- the `Allow`/`Deny`/`RequireHuman`
/// decision Oracle 2 measures an episode's disposition against. Both the Allow
/// corpus and the denied-disposition fixture derive their expected verdict
/// through this one path, so neither is a guess.
fn ground_truth_verdict_for(request: &ActionRequest) -> PolicyVerdict {
    let gate = StaticApprovalGate::from_config(&harness_policy_config());
    let context = harness_approval_context();
    gate.evaluate(request, &context)
        .expect("evaluating the harness request against the real gate must not error")
        .verdict
}

/// The ground-truth verdict for this harness's fixed corpus request.
/// `Escalate`/Medium falls through to `default_allow`, so this is `Allow`; the
/// corpus asserts that, so a policy-config change that silently altered it
/// would surface rather than quietly skew every oracle.
fn harness_ground_truth_verdict() -> PolicyVerdict {
    ground_truth_verdict_for(&harness_action_request())
}

/// Format one oracle violation for a corpus/replay failure: names the seed
/// (with the exact `SWARM_DST_SEED` value that replays that one episode), the
/// fault class, and the oracle -- so any failure is reproducible in isolation
/// with a single command.
fn format_corpus_violation(
    observation: &EpisodeObservation,
    violation: &OracleViolation,
) -> String {
    format!(
        "seed {seed} [SWARM_DST_SEED={seed}] class={class:?} oracle={oracle:?}: {detail}",
        seed = observation.plan.seed,
        class = observation.plan.class,
        oracle = violation.oracle,
        detail = violation.detail,
    )
}

/// Drive a completing (`NoFault`) episode carrying an arbitrary, distinctive
/// `seed`, bypassing the RNG's seed->class draw. The non-vacuity proofs use it
/// so their forced-violation failure text names a real, recognisable seed
/// without coupling to today's seed->class mapping (deterministic, but not
/// guaranteed stable across tasks).
fn drive_completing_observation(seed: u64) -> EpisodeObservation {
    drive_episode(FaultPlan {
        seed,
        class: FaultClass::NoFault,
        checkpoint: 0,
    })
}

// ---------------------------------------------------------------------------
// 10. Tests.
// ---------------------------------------------------------------------------

#[test]
fn dst_no_fault_episode_dispatches_exactly_once_and_persists_a_matching_receipt() {
    let observation = drive_episode_for_class(FaultClass::NoFault);

    assert_eq!(
        observation.dispatch_log.len(),
        1,
        "the action must dispatch exactly once, got {:?}",
        observation.dispatch_log
    );

    let outcome = observation
        .outcome
        .as_ref()
        .expect("NoFault always runs the episode to completion");
    let receipt = match &outcome.authorize_result {
        Ok(receipt) => receipt,
        Err(error) => panic!("expected Ok(receipt), got RuntimeError: {error}"),
    };
    assert_eq!(receipt.status, ResponseStatus::Executed);

    let persisted = outcome
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

    let observation = drive_episode_for_class(FaultClass::NoFault);
    let receipt = observation
        .outcome
        .as_ref()
        .expect("NoFault always runs the episode to completion")
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
    let observation = drive_episode_for_class(FaultClass::NoFault);
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
}

#[test]
fn dst_fault_plan_for_seed_deterministically_selects_one_of_the_four_classes() {
    // Same seed -> same class, every time (Task 2's addition to `for_seed`).
    for seed in [0_u64, 1, 7, 42] {
        assert_eq!(
            FaultPlan::for_seed(seed).class,
            FaultPlan::for_seed(seed).class,
            "seed {seed} must select the same fault class every time"
        );
    }

    // The selector draw must actually be able to reach all four variants,
    // not just one or two by a construction bug -- scan enough seeds to see
    // every class at least once.
    let mut seen: Vec<FaultClass> = Vec::new();
    for seed in 0_u64..256 {
        let class = FaultPlan::for_seed(seed).class;
        if !seen.contains(&class) {
            seen.push(class);
        }
    }
    assert_eq!(
        seen.len(),
        ALL_FAULT_CLASSES.len(),
        "expected all four fault classes to appear across seeds 0..256, only saw {seen:?}"
    );
}

#[test]
fn dst_drive_episode_for_seed_is_byte_identical_across_repeated_calls() {
    for seed in [0_u64, 1, 2, 3, 4, 5, 100, 4242] {
        let first = drive_episode_for_seed(seed);
        let second = drive_episode_for_seed(seed);
        assert_eq!(
            first.plan.class, second.plan.class,
            "seed {seed} must select the same fault class every time"
        );
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "seed {seed} (class {:?}) must produce a byte-identical observation across repeated \
             runs",
            first.plan.class
        );
    }
}

#[test]
fn dst_drive_episode_for_class_is_byte_identical_across_repeated_calls_for_every_class() {
    for class in ALL_FAULT_CLASSES {
        let first = drive_episode_for_class(class);
        let second = drive_episode_for_class(class);
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "class {class:?} must produce a byte-identical observation across repeated runs"
        );
    }
}

#[test]
fn dst_fault_class_drop_before_dispatch_leaves_the_dispatch_log_empty() {
    let observation = drive_episode_for_class(FaultClass::DropBeforeDispatch);
    assert!(
        observation.outcome.is_none(),
        "a before-dispatch drop simulates a crash: no EpisodeOutcome is ever produced, got {:?}",
        observation.outcome
    );
    assert_eq!(
        observation.polls, BEFORE_DISPATCH_POLL_BUDGET,
        "must drop after exactly the before-dispatch checkpoint's poll budget"
    );
    assert!(
        observation.dispatch_log.is_empty(),
        "the action must never take effect: got {:?}",
        observation.dispatch_log
    );
    assert!(
        observation.persisted_deposits.is_empty(),
        "nothing dispatched means nothing to persist: got {:?}",
        observation.persisted_deposits
    );
    assert!(
        observation.substrate_lifecycle.is_empty(),
        "this class never touches the substrate seam: got {:?}",
        observation.substrate_lifecycle
    );
}

#[test]
fn dst_fault_class_drop_after_dispatch_before_persist_dispatches_once_but_persists_nothing() {
    let observation = drive_episode_for_class(FaultClass::DropAfterDispatchBeforePersist);
    assert!(
        observation.outcome.is_none(),
        "an after-dispatch drop simulates a crash: no EpisodeOutcome is ever produced, got {:?}",
        observation.outcome
    );
    assert_eq!(
        observation.polls, AFTER_DISPATCH_POLL_BUDGET,
        "must drop after exactly the after-dispatch checkpoint's poll budget"
    );
    assert_eq!(
        observation.dispatch_log.len(),
        1,
        "the action must dispatch exactly once before the simulated crash: got {:?}",
        observation.dispatch_log
    );
    assert!(
        observation.persisted_deposits.is_empty(),
        "the crash must land strictly before the substrate persist call begins: got {:?}",
        observation.persisted_deposits
    );
}

#[test]
fn dst_fault_class_substrate_close_reopen_persists_against_the_reopened_substrate() {
    let observation = drive_episode_for_class(FaultClass::SubstrateCloseReopen);
    assert_eq!(
        observation.substrate_lifecycle,
        vec![
            SubstrateLifecycleEvent::Closed,
            SubstrateLifecycleEvent::Reopened
        ],
        "the seam must close then reopen exactly once, in that order: got {:?}",
        observation.substrate_lifecycle
    );
    assert_eq!(
        observation.dispatch_log.len(),
        1,
        "the action must still dispatch exactly once: got {:?}",
        observation.dispatch_log
    );
    assert_eq!(
        observation.polls, 3,
        "closing/reopening the substrate must not change how many polls the SAME future needs \
         (2 to reach the checkpoint, 1 more to resolve after resuming): got {}",
        observation.polls
    );

    let outcome = observation
        .outcome
        .as_ref()
        .expect("class (c) is not a drop; the episode must run to completion");
    assert!(
        outcome.authorize_result.is_ok(),
        "got {:?}",
        outcome.authorize_result
    );
    assert!(
        matches!(outcome.persist_result, Some(Ok(()))),
        "the persist call must succeed against the reopened substrate: got {:?}",
        outcome.persist_result
    );
    assert_eq!(
        observation.persisted_deposits.len(),
        1,
        "the episode must observe the reopened substrate and persist successfully against it"
    );
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
    // -- --nocapture` shows a human exactly which seed, fault class, and
    // plan replayed -- the one-command reproduction DST-05 asks for.
    println!(
        "SWARM_DST_SEED replay: seed={} plan={:?} dispatch_log={:?} persisted_deposits={} \
         substrate_lifecycle={:?}",
        observation.plan.seed,
        observation.plan,
        observation.dispatch_log,
        observation.persisted_deposits.len(),
        observation.substrate_lifecycle
    );
    assert_eq!(
        observation.plan.seed, seed,
        "the episode driven must be exactly the seed SWARM_DST_SEED named (or the default when unset)"
    );
    // DST-05 promises exact reproduction of whatever that seed's plan is --
    // NOT that every seed is a full-success episode (Task 2 introduces
    // fault classes precisely so that is no longer universally true). What
    // "correct" looks like depends on the replayed plan's OWN class.
    match observation.plan.class {
        FaultClass::NoFault => {
            assert_eq!(observation.dispatch_log.len(), 1);
            let outcome = observation
                .outcome
                .as_ref()
                .expect("NoFault always runs the episode to completion");
            assert!(outcome.authorize_result.is_ok());
            assert!(matches!(outcome.persist_result, Some(Ok(()))));
        }
        FaultClass::DropBeforeDispatch => {
            assert!(observation.outcome.is_none());
            assert!(observation.dispatch_log.is_empty());
            assert!(observation.persisted_deposits.is_empty());
        }
        FaultClass::DropAfterDispatchBeforePersist => {
            assert!(observation.outcome.is_none());
            assert_eq!(observation.dispatch_log.len(), 1);
            assert!(observation.persisted_deposits.is_empty());
        }
        FaultClass::SubstrateCloseReopen => {
            assert_eq!(observation.dispatch_log.len(), 1);
            let outcome = observation
                .outcome
                .as_ref()
                .expect("class (c) is not a drop; the episode must run to completion");
            assert!(outcome.authorize_result.is_ok());
            assert_eq!(observation.persisted_deposits.len(), 1);
            assert_eq!(
                observation.substrate_lifecycle,
                vec![
                    SubstrateLifecycleEvent::Closed,
                    SubstrateLifecycleEvent::Reopened
                ]
            );
        }
    }
}

// --- DST-03 / DST-04 (PR half): the three oracles + the 64-seed corpus. -----

/// The PR-lane corpus (DST-04, PR half): 64 deterministic seeds, all three
/// oracles per episode, run against the REAL engine stack. Green here is the
/// phase's core claim -- every correctness property holds under every fault
/// the plan models. On ANY violation this fails, listing each offending seed
/// (with its `SWARM_DST_SEED` replay value), fault class, and oracle, so a
/// failure is one-command reproducible.
///
/// It also asserts the corpus actually EXERCISES all four fault classes: a
/// green result would be vacuous if, say, only `NoFault` ever ran.
#[test]
fn dst_sixtyfour_seed_corpus_upholds_all_three_oracles_on_the_real_engine() {
    let expected_verdict = harness_ground_truth_verdict();
    assert_eq!(
        expected_verdict,
        PolicyVerdict::Allow,
        "the fixed harness request must be a deterministic Allow so completing episodes dispatch; \
         if this ever changes, Oracle 2's expected dispositions must be revisited"
    );

    let mut classes_seen: Vec<FaultClass> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for seed in 0..PR_CORPUS_SEED_COUNT {
        let observation = drive_episode_for_seed(seed);
        if !classes_seen.contains(&observation.plan.class) {
            classes_seen.push(observation.plan.class);
        }
        for violation in evaluate_oracles(&observation, expected_verdict) {
            failures.push(format_corpus_violation(&observation, &violation));
        }
    }

    assert_eq!(
        classes_seen.len(),
        ALL_FAULT_CLASSES.len(),
        "the {PR_CORPUS_SEED_COUNT}-seed corpus must exercise all four fault classes so a green \
         result is not vacuous; only saw {classes_seen:?}"
    );

    assert!(
        failures.is_empty(),
        "oracle violations across the {PR_CORPUS_SEED_COUNT}-seed corpus (each reproducible in \
         isolation via its SWARM_DST_SEED):\n{}",
        failures.join("\n")
    );
}

/// DST-04 (nightly half): the deterministic deep corpus. The SAME three oracles
/// and per-seed episode as `dst_sixtyfour_seed_corpus_upholds_all_three_oracles_on_the_real_engine`,
/// over `NIGHTLY_CORPUS_SEED_COUNT` (>= 5,000) seeds -- a scale that would slow
/// the PR lane but is exactly where a rare oracle-violating seed the 64-seed
/// lane never reached would surface. `#[ignore]`d, so it never runs in the PR
/// lane; `.github/workflows/dst-nightly.yml` runs it via `cargo test --
/// --ignored`. On any violation it names the exact seed so the one failing
/// episode replays in isolation via `SWARM_DST_SEED=<n>`.
#[test]
#[ignore = "nightly deep corpus (DST-04, >= 5000 seeds); runs in .github/workflows/dst-nightly.yml via `cargo test -- --ignored`, too slow for the PR lane"]
fn dst_nightly_deep_corpus_upholds_all_three_oracles_across_at_least_five_thousand_seeds() {
    let expected_verdict = harness_ground_truth_verdict();
    assert_eq!(
        expected_verdict,
        PolicyVerdict::Allow,
        "the fixed harness request must be a deterministic Allow so completing episodes dispatch; \
         if this ever changes, Oracle 2's expected dispositions must be revisited"
    );

    let mut classes_seen: Vec<FaultClass> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for seed in 0..NIGHTLY_CORPUS_SEED_COUNT {
        let observation = drive_episode_for_seed(seed);
        if !classes_seen.contains(&observation.plan.class) {
            classes_seen.push(observation.plan.class);
        }
        for violation in evaluate_oracles(&observation, expected_verdict) {
            failures.push(format_corpus_violation(&observation, &violation));
        }
    }

    assert_eq!(
        classes_seen.len(),
        ALL_FAULT_CLASSES.len(),
        "the {NIGHTLY_CORPUS_SEED_COUNT}-seed nightly corpus must exercise all four fault classes \
         so a green result is not vacuous; only saw {classes_seen:?}"
    );

    assert!(
        failures.is_empty(),
        "oracle violations across the {NIGHTLY_CORPUS_SEED_COUNT}-seed nightly corpus (each \
         reproducible in isolation via its SWARM_DST_SEED):\n{}",
        failures.join("\n")
    );
}

/// The `SWARM_DST_SEED` drill-in for the oracles: replay exactly the one seed
/// the environment names (or the default when unset) and evaluate all three
/// oracles against it, so a seed the corpus flags is reproducible in isolation
/// with a single command --
/// `SWARM_DST_SEED=<n> cargo test -p swarm-runtime --test dst_fault_injection \
///  dst_swarm_dst_seed_replay_upholds_all_three_oracles_for_the_selected_seed \
///  -- --nocapture`.
#[test]
fn dst_swarm_dst_seed_replay_upholds_all_three_oracles_for_the_selected_seed() {
    let seed = seed_from_env();
    let observation = drive_episode_for_seed(seed);
    let expected_verdict = harness_ground_truth_verdict();
    let violations = evaluate_oracles(&observation, expected_verdict);
    // Visible with `--nocapture`: exactly which seed, class, verdict, and how
    // many oracle violations replayed.
    println!(
        "SWARM_DST_SEED oracle replay: seed={} class={:?} verdict={:?} violations={}",
        seed,
        observation.plan.class,
        expected_verdict,
        violations.len()
    );
    let formatted: Vec<String> = violations
        .iter()
        .map(|violation| format_corpus_violation(&observation, violation))
        .collect();
    assert!(
        formatted.is_empty(),
        "SWARM_DST_SEED={seed} replayed with oracle violations:\n{}",
        formatted.join("\n")
    );
}

/// Non-vacuity proof for Oracle 1: a correct completing episode passes, but a
/// phantom receipt (a persisted receipt whose dispatch never happened -- the
/// genuinely dangerous false-audit-record direction) is caught AND the failure
/// names the seed. The forcing is a temporary local construction; the real
/// corpus never sees it and stays green.
#[test]
fn dst_oracle_receipt_before_action_catches_a_phantom_receipt_and_names_the_seed() {
    let mut observation = drive_completing_observation(710411);
    assert!(
        oracle_receipt_before_action(&observation).is_ok(),
        "a correct completing episode must uphold receipt-before-action"
    );

    // Force the dangerous direction: a real, signed deposit whose recorded
    // dispatch order (99) has no matching dispatch -- a receipt for an
    // action-effect that did not happen. Built via the real persist builder so
    // only its identity, not its shape, is anomalous.
    let phantom_receipt = ResponseReceipt {
        receipt_id: "dst-receipt:dst-hunt-episode:99".to_string(),
        action: "escalate".to_string(),
        mode: ExecutionMode::Enforced,
        status: ResponseStatus::Executed,
        summary: "phantom".to_string(),
        details: serde_json::json!({}),
        audit: Default::default(),
    };
    observation
        .persisted_deposits
        .push(deposit_for_receipt(&phantom_receipt, 0));

    let violation =
        oracle_receipt_before_action(&observation).expect_err("a phantom receipt must be caught");
    assert_eq!(violation.oracle, Oracle::ReceiptBeforeAction);
    let formatted = format_corpus_violation(&observation, &violation);
    assert!(
        formatted.contains("SWARM_DST_SEED=710411"),
        "the violation must name the seed for one-command reproduction: {formatted}"
    );
    assert!(
        formatted.contains("phantom receipt") && !formatted.contains("duplicate receipt"),
        "a never-dispatched receipt must read as 'phantom', distinct from 'duplicate': {formatted}"
    );

    // Also the DUPLICATE-persist direction: a SECOND receipt claiming the same
    // dispatch (order 0) as the real one. Multiset containment -- not mere
    // existence -- is what makes this a violation too: two audit records
    // asserting an action-effect that happened once is as false as an invented
    // record. (This is why Oracle 1 tracks claimed dispatches, not just
    // presence.) Its diagnostic must read 'duplicate', NOT 'phantom' -- the two
    // shapes are distinguished so a failing seed says which it is.
    let mut duplicated = drive_completing_observation(710411);
    let dup_receipt = ResponseReceipt {
        receipt_id: "dst-receipt:dst-hunt-episode:0".to_string(),
        action: "escalate".to_string(),
        mode: ExecutionMode::Enforced,
        status: ResponseStatus::Executed,
        summary: "duplicate".to_string(),
        details: serde_json::json!({}),
        audit: Default::default(),
    };
    duplicated
        .persisted_deposits
        .push(deposit_for_receipt(&dup_receipt, 0));
    let dup_violation = oracle_receipt_before_action(&duplicated)
        .expect_err("a duplicated receipt (two for one dispatch) must be caught");
    assert_eq!(dup_violation.oracle, Oracle::ReceiptBeforeAction);
    let dup_formatted = format_corpus_violation(&duplicated, &dup_violation);
    assert!(
        dup_formatted.contains("duplicate receipt") && !dup_formatted.contains("phantom receipt"),
        "a repeated receipt must read as 'duplicate', distinct from 'phantom': {dup_formatted}"
    );
}

/// Non-vacuity proof for Oracle 2: the SAME real completing episode
/// (`Ok`/`Executed`/persisted) passes against its true `Allow` verdict but is
/// flagged when the oracle is told to expect a `Deny` -- proving the
/// disposition check is genuinely coupled to the verdict, not a constant
/// pass. The failure names the seed.
#[test]
fn dst_oracle_exact_disposition_catches_a_wrong_verdict_expectation_and_names_the_seed() {
    let observation = drive_completing_observation(220722);
    assert!(
        oracle_exact_disposition(&observation, PolicyVerdict::Allow).is_ok(),
        "the real completing episode is an Allow disposition"
    );

    let violation = oracle_exact_disposition(&observation, PolicyVerdict::Deny)
        .expect_err("an Executed disposition must not satisfy a Deny expectation");
    assert_eq!(violation.oracle, Oracle::ExactDisposition);
    let formatted = format_corpus_violation(&observation, &violation);
    assert!(
        formatted.contains("SWARM_DST_SEED=220722"),
        "the violation must name the seed for one-command reproduction: {formatted}"
    );
}

/// POSITIVE coverage for Oracle 2's denied branch: drive a request the REAL
/// gate genuinely DENIES (`IsolateHost` at Low -> `Deny`) through the same real
/// `authorize_and_execute`, and prove Oracle 2 accepts the denied disposition
/// against the verdict the real gate returns (derived, not hardcoded). Without
/// this the corpus only ever drove `Allow`, leaving the denied arm logically
/// sound but unexercised. A denied request never dispatches, so there is no
/// fault surface -- this is a focused no-fault positive test, and Oracle 1 (no
/// receipts) and Oracle 3 (no dispatches) must also hold.
#[test]
fn dst_oracle_exact_disposition_accepts_a_denied_disposition_for_a_genuinely_denied_request() {
    let request = harness_denied_action_request();
    // Ground truth from the REAL gate, exactly as the Allow corpus derives its
    // own verdict -- not hardcoded.
    let verdict = ground_truth_verdict_for(&request);
    assert_eq!(
        verdict,
        PolicyVerdict::Deny,
        "a destructive action (IsolateHost) at Low severity must be a deterministic Deny"
    );

    // A denied request never dispatches -> no fault surface -> NoFault. A
    // distinctive seed so any failure names it.
    let observation = drive_episode_with_request(
        FaultPlan {
            seed: 286286,
            class: FaultClass::NoFault,
            checkpoint: 0,
        },
        &request,
    );

    // Oracle 2's denied branch, positively exercised: the disposition equals
    // what the real Deny verdict demands (an authorization Err, no dispatch).
    assert!(
        oracle_exact_disposition(&observation, verdict).is_ok(),
        "Oracle 2 must accept the denied disposition against the real Deny verdict; observed \
         outcome={:?}",
        observation.outcome
    );

    // It is genuinely a denial, observed against the real engine, not a crash.
    let outcome = observation
        .outcome
        .as_ref()
        .expect("a denied NoFault episode runs to completion");
    assert!(
        matches!(outcome.authorize_result, Err(RuntimeError::Approval(_))),
        "a Deny verdict under LiveResponse must surface an authorization Err; observed {:?}",
        outcome.authorize_result
    );
    assert!(
        outcome.persist_result.is_none(),
        "a denied request persists no receipt: {:?}",
        outcome.persist_result
    );

    // Oracle 1 (no receipts -> trivially holds) and Oracle 3 (0 dispatches).
    assert!(
        observation.dispatch_log.is_empty(),
        "a denied request never dispatches"
    );
    assert!(observation.persisted_deposits.is_empty());
    assert!(oracle_receipt_before_action(&observation).is_ok());
    assert!(oracle_no_double_dispatch(&observation).is_ok());

    // The coupling is real in the other direction too: the SAME denied episode
    // must be FLAGGED when the oracle is told to expect Allow -- exercising the
    // Allow arm's "demands Ok(receipt); observed Err" path against a real Err.
    let mis = oracle_exact_disposition(&observation, PolicyVerdict::Allow)
        .expect_err("a denied disposition must not satisfy an Allow expectation");
    assert_eq!(mis.oracle, Oracle::ExactDisposition);
}

/// Non-vacuity proof for Oracle 3: a correct episode dispatches the request at
/// most once and passes, but a second dispatch of the same request (the
/// dangerous double-execution direction) is caught. The failure names the
/// seed.
#[test]
fn dst_oracle_no_double_dispatch_catches_a_repeated_dispatch_and_names_the_seed() {
    let mut observation = drive_completing_observation(330733);
    assert!(
        oracle_no_double_dispatch(&observation).is_ok(),
        "a correct episode dispatches the request at most once"
    );

    // Force a double dispatch: the same request recorded a second time.
    observation.dispatch_log.push(DispatchRecord {
        hunt_id: "dst-hunt-episode".to_string(),
        order: 1,
    });

    let violation = oracle_no_double_dispatch(&observation)
        .expect_err("a repeated dispatch of one request must be caught");
    assert_eq!(violation.oracle, Oracle::NoDoubleDispatch);
    let formatted = format_corpus_violation(&observation, &violation);
    assert!(
        formatted.contains("SWARM_DST_SEED=330733"),
        "the violation must name the seed for one-command reproduction: {formatted}"
    );
    assert!(
        formatted.contains("double dispatch"),
        "the violation must name the failure mode: {formatted}"
    );
}
