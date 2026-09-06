# 15 — Hold-path durability: W3-38 and W3-39, resolved

**Status:** implementation plan, 2026-09-06. Resolves the two defects the walking skeleton
filed on 2026-09-05 (`00-DECISIONS.md` W3-38, W3-39; `evidence/walking-skeleton.md`,
"Found by this run, filed rather than fixed"). Both were reproduced live: a spool written
against an abandoned relay database blocked every later hold for twenty-five minutes, and a
hold whose filing steps were lost stayed `created` with no notice while the daemon still
reported it durable.

**Spec authority.** `01-DESIGN.md` §5 ("The bridge never blocks the daemon", "The relay is
never the record") and §10 (every failure has a rendered state, none is silent);
`13-PLAN-THE-HOLD.md` Task 9 (the sweep exists so that "nothing a restart forgets is lost");
ADR 0012 (the daemon is the sole writer of hold state; the bridge writes back exactly
`mark_case_channel` and `mark_notified`). Where this plan and those documents disagree, they
win and this plan is wrong.

**The two promises, and which side keeps each.**

| Promise | Owner | Mechanism |
|---|---|---|
| A refused relay step for one case never delays another case's hold | the bridge (`swarm-perch-bridge`) | heal the ledger on a channel-state refusal; park a record after a bounded refusal budget; retry parked records on idle ticks |
| A hold the relay never learned of is re-filed until it is | the daemon (`swarm-runtime` sweep) | the sweep re-publishes `ResponseHeld { state: Created }` for any unfiled hold older than `refile_after_ms`, throttled per hold |

They converge: a re-filed record plans from durable state (the store record and the routing
ledger), so every step the relay already accepted is skipped, and a parked record whose plan
comes back empty is dropped. Neither mechanism is complete without the other: re-filing alone
would queue behind the blocked head, and parking alone would leave an unfiled hold to its TTL
when the parked retry also fails.

## Global constraints

- Engine toolchain: root `rust-toolchain.toml` (Rust 1.97.1, edition 2024). `cargo fmt --all`,
  `cargo clippy --workspace -- -D warnings`, and the workspace lints `unwrap_used = "deny"`,
  `expect_used = "deny"` apply. Test modules take
  `#[allow(clippy::unwrap_used, clippy::expect_used)]` on the `mod tests` declaration, never a
  crate-wide prologue (root `Cargo.toml` comment block).
- No new configuration knob on the bridge. The bridge's budgets are `pub const`s with doc
  comments deriving the value. The daemon gains exactly one setting, `refile_after_ms`.
- ADR 0012 stands: the bridge writes no new field to the hold store, and the store trait gains
  no new method. The sweep's per-hold throttle is in-memory on purpose; after a restart the
  first tick re-files every stale unfiled hold at once, which is the promise.
- ADR 0014/0015 stand: nothing here touches the decide route, the sign gate, or the console.
- Every new failure mode is counted (a `prometheus_client` counter on `BridgeMetrics` or a
  `HoldSweepReport` field) and logged with the ids it concerns. No silent path.
- `tools/check-runtime-panic-contract.sh` enumerates `crates/*/src`; no `unwrap`/`expect`
  outside test modules, no `panic!`, no `todo!()`.
- Tests are behaviour tests with real state: a `MemoryHeldActionStore`, a `MemorySpool` /
  temp-dir `DiskSpool`, and the existing recording `FramePublisher` mock in
  `crates/swarm-perch-bridge/src/alarm.rs` tests. A test that asserts only a receipt-shaped
  value against a publisher that sent nothing is the failure `STATE.md` records for phase 320;
  every test here asserts the frames that left or did not leave.
- Commit per task with `git commit -s` and a Conventional Commits subject.
- Do not edit `00-DECISIONS.md` or the evidence records; the controller updates the decision
  rows after the live re-run.

---

### Task 1: The sweep re-files unfiled holds (W3-39)

**Files.**
- `crates/swarm-core/src/config/runtime.rs` — `ResponseHoldSettings` gains `refile_after_ms`.
- `crates/swarm-core/src/config/defaults.rs` — `default_hold_refile_after_ms() -> u64 { 30_000 }`,
  doc comment: "Thirty seconds: thirty alarm-drainer ticks at the bridge's 1 Hz cadence, which
  is also the bridge's head-refusal budget (`swarm_perch_bridge::alarm::HEAD_REFUSAL_BUDGET`),
  so a hold is re-filed no sooner than the bridge could have parked whatever blocked it."
- `crates/swarm-core/src/config/validation.rs` — `refile_after_ms == 0` is
  `InvalidField { field: "runtime.response.refile_after_ms", reason: "must be greater than zero; a hold re-filed on every tick floods the alarm spool" }`,
  placed beside the `decide_stall_ms` check.
- `crates/swarm-runtime/src/hold_sweep.rs` — the re-file pass.
- `crates/swarm-runtime-http/src/bin/swarm_detect.rs` — pass `hold_settings.refile_after_ms`
  to `HoldSweep::new` and add `refile_after_ms` to the "hold sweep started" log line.
- `docs/CONFIGURATION.md` — a `runtime.response` block. Measure first: `grep -n 'runtime.response\|hold_ttl_ms' docs/CONFIGURATION.md`. If the block does not exist, add one beside `runtime.containment` documenting every `ResponseHoldSettings` field in the file's existing style (one bullet per field, default named); if it exists, add the one field.
- Any test fixture or ruleset that constructs `ResponseHoldSettings` by struct literal: `grep -rn 'ResponseHoldSettings {' crates` and add the field. Rulesets under `rulesets/`, `rulesets-dev/` and `scenarios/` need no change because the field is `#[serde(default)]`; verify with `cargo run -p swarm-runtime-http --bin swarmctl -- validate --config rulesets-dev/perch-hold-dev.yaml` (expect `Status: valid`) — the signed sidecar is unaffected because the YAML bytes do not change.

**Behaviour.**

`HoldSweep::new(store, events, decide_stall_ms, refile_after_ms)` (a fourth `u64` parameter,
in that order). `HoldSweep` holds `refile_after_ms: u64` and `refiled_at: BTreeMap<String, i64>`
(hold id → the instant of the last re-file). `tick` becomes `pub fn tick(&mut self, now_ms: i64)`;
`run_until_shutdown` becomes `pub async fn run_until_shutdown(mut self, …)` — it is the only
caller that loops, and the sweep is owned by exactly one task (`swarm_detect.rs` spawns it by
value already; confirm and adjust the spawn if it borrowed).

`tick` runs a third pass after expiry and stall resolution, `refile_unfiled(now_ms)`:

1. `store.list(false, usize::MAX)` — open holds only, sorted by the store.
2. A hold is **unfiled** when `state == HoldState::Created && notice_event_id.is_none()`.
   `Notified`, `Armed`, `Deciding` are filed by definition (`notified` is the bridge's own
   `mark_notified` callback, `armed` is client-reported, so both prove the console saw the
   row). Terminal states are never listed.
3. A hold is **due** when `held_at_ms + refile_after_ms <= now_ms` and
   `refiled_at.get(hold_id).is_none_or(|&last| last + refile_after_ms <= now_ms)`.
4. For every unfiled, due hold: publish `RuntimeEvent::ResponseHeld` through the existing
   `publish` helper with `state: HoldState::Created` and `emitted_at_ms: now_ms`, insert
   `refiled_at[hold_id] = now_ms`, push the id onto `report.refiled`, and
   `tracing::warn!(module = module_path!(), hold_id, age_ms = now_ms - held_at_ms, "hold is not filed on the relay; re-publishing its created event so the bridge re-plans it")`.
5. Retain in `refiled_at` only ids present in this tick's open list, so the map is bounded by
   the number of open holds.
6. A store error is `report.failures.push(format!("refile_unfiled: {error}"))`, exactly like the
   two existing passes. The sweep never panics.

`HoldSweepReport` gains `pub refiled: Vec<String>` (doc: "Holds still `created` with no notice
past `refile_after_ms`, whose `ResponseHeld { Created }` was published again."). The run-loop
log gains `refiled = report.refiled.len()` and fires when it is non-empty.

Module docs: extend the `hold_sweep.rs` header with a paragraph naming W3-39 and the two
promises table above in one sentence each; extend the `held_action.rs` header sentence that
describes the sweep.

**Tests** (in `hold_sweep.rs`'s existing `mod tests`, same fixtures and style; every test
subscribes to the broadcaster and asserts on the events that were or were not published):

1. `an_unfiled_hold_younger_than_refile_after_ms_is_left_alone` — a `created` hold held at
   `now - 10_000` with `refile_after_ms = 30_000`: no event, `report.refiled` empty.
2. `an_unfiled_hold_older_than_refile_after_ms_is_re_filed_exactly_once_per_interval` — held at
   `now - 31_000`: first tick publishes one `ResponseHeld { state: Created, hold_id }` and
   reports it; a second tick at `now + 1_000` publishes nothing; a tick at `now + 30_000`
   publishes again.
3. `a_notified_hold_is_never_re_filed` — `mark_notified` first; ticks at any age publish nothing.
4. `a_hold_that_becomes_notified_stops_being_re_filed` — re-file once, `mark_notified`, tick
   past the interval: nothing.
5. `a_fresh_sweep_re_files_a_stale_hold_on_its_first_tick` — build a second `HoldSweep` over
   the same store after the first re-filed: its first tick re-files again (restart semantics).
6. `re_filing_does_not_touch_the_store` — after re-filing, `store.get(hold_id)` is byte-for-byte
   the record before (compare the serialized JSON); the sweep publishes, it does not mutate.
7. `the_spawned_loop_re_files_with_no_manual_tick` — mirror
   `the_spawned_loop_expires_a_due_hold_with_no_manual_tick` with `refile_after_ms = 1`.
8. `the_throttle_map_forgets_holds_that_are_no_longer_open` — after a hold expires, the map no
   longer contains it (expose a `#[cfg(test)] fn throttled_hold_count(&self) -> usize`).
9. In `swarm-core`: the default is `30_000`; validation rejects `0` with the field name above
   (follow the shape of the existing `decide_stall_ms` validation test — find it with
   `grep -rn 'decide_stall_ms' crates/swarm-core/src`).

**Verification.** `cargo fmt --all --check`; `cargo clippy -p swarm-core -p swarm-runtime -p swarm-runtime-http --all-targets -- -D warnings`;
`cargo test -p swarm-core -p swarm-runtime`; `cargo test -p swarm-runtime-http --bin swarm_detect` if
that binary has tests touching the sweep (check with `grep -n hold_sweep crates/swarm-runtime-http/src/bin/swarm_detect.rs`);
`bash tools/check-runtime-panic-contract.sh`; the `swarmctl validate` line above.

---

### Task 2: The alarm drainer heals the ledger, parks after a budget, and retries parked records (W3-38)

**Files.**
- `crates/swarm-perch-bridge/src/alarm.rs` — the head-refusal budget and the parked-retry
  tick; the two `pub const`s; the healing call on channel-state refusals.
- `crates/swarm-perch-bridge/src/alarm/parked.rs` (new; declare `mod parked;` in `alarm.rs`
  and re-export `ParkedLedger`, `ParkedRecord`, `ParkReason` as `pub use`) — the durable
  dead-letter. If `alarm.rs` is a file module, convert it to `alarm/mod.rs` **only if** the
  crate already uses that layout (`spool/mod.rs` does), otherwise use a sibling file
  `alarm_parked.rs` with `#[path]`-free `mod alarm_parked;` in `lib.rs` and `pub use` from
  `alarm`. Prefer the `alarm/mod.rs` conversion; the git rename keeps history.
- `crates/swarm-perch-bridge/src/channels.rs` — `CaseRouting::forget_channel_created`.
- `crates/swarm-perch-bridge/src/metrics.rs` — two counters.
- `crates/swarm-perch-bridge/src/lib.rs` — the `//! ## Owns` / `//! ## Does not own` headings
  mention the parked ledger; the drainer is built with the ledger path beside
  `case-routing.json` (find where `CaseRouting::open` is called and derive
  `parked-alarms.json` in the same directory).

**Constants**, in `alarm.rs`, each with a doc comment stating the derivation:

```rust
/// Consecutive relay REFUSALS of one head record before it is parked. Thirty ticks at the
/// 1 Hz cadence is thirty seconds: a relay that is down is a transport error and never
/// counts, so thirty refusals in a row means the relay's state disagrees with the ledger
/// and no further tick will change its answer. Equals the daemon's default
/// `runtime.response.refile_after_ms`.
pub const HEAD_REFUSAL_BUDGET: u32 = 30;
/// A parked record is retried no sooner than this after it was parked or last retried.
pub const PARKED_RETRY_INTERVAL_MS: i64 = 30_000;
/// The dead-letter holds at most this many records; the oldest is dropped past it, counted
/// as `perch_bridge_dropped_events_total{stream="alarm",cause="parked_overflow"}`.
pub const PARKED_CAPACITY: usize = 256;
```

**Behaviour, part 1 — healing.** In `publish_hold_sequence`, when a step's outcome is
`OkOutcome::NotAChannelMember`, or `OkOutcome::Rejected { message }` where `message` contains
`"channel not found"`, and `step.channel()` is `Some(case)`: call
`holds.routing_mut().forget_channel_created(case)?` before returning `Ok(false)`, and log at
warn: `"the relay no longer knows case channel {case}; its create is re-planned before the next step"`.
The next tick's `plan_open` (via `ensure_case_channel`, which already re-plans a routed but
unconfirmed channel) then emits the idempotent `9007` and the `9000`s before the card and the
notice. Apply the same healing in the `CasePromoted` arm: `publish_step` returns
`BridgeError::RelayRejected { message }`; when `message` is `"not_a_channel_member"` or
contains `"channel not found"`, forget the created fact for that case before the `continue`.

`CaseRouting::forget_channel_created(&mut self, channel: Uuid) -> Result<(), BridgeError>`:
remove the id from `created_channels`; persist only if it was present; doc comment explains
that this is the one write that moves the ledger backwards and why (the relay's state is the
ground truth for channel existence; the ledger records acceptances, and an acceptance the relay
has since forgotten — a restore, a migration, a wiped database — must not be believed over a
fresh refusal).

**Behaviour, part 2 — the budget.** The drainer keeps `head: Option<HeadBudget>` where
`struct HeadBudget { key: (IssuerIdx, Seq), refusals: u32, first_refused_at_ms: i64 }`. Only a
**refusal** advances it: `publish_hold_sequence` returning `Ok(false)` because
`!outcome.is_success()`, or a `CasePromoted` step returning `RelayRejected`. Transport errors
(`Err(_)` from the publisher) and `AlarmAdmission::Deferred` never count — make
`publish_hold_sequence` return a three-valued `enum SequenceOutcome { Landed, Refused, Stalled }`
so the caller cannot conflate them. When the head record's key changes, the budget resets.
When `refusals >= HEAD_REFUSAL_BUDGET`:

1. `ParkedLedger::park(ParkedRecord { issuer, seq, payload: record.payload.clone(), parked_at_ms: now_ms, retries: 0, reason })` where `reason: ParkReason` is `RefusalBudgetExhausted { last: &'static str }` carrying the last `OkOutcome::reason()`; the ledger persists atomically via `crate::spool::cursor::write_atomic`.
2. `commit(&spools, record.issuer, record.seq)?` — the cursor moves past it.
3. `metrics.alarm_parked(reason_label)` and
   `tracing::error!(module = module_path!(), hold_id or case_id, refusals, reason, "a hold sequence was refused {n} times in a row and is parked; later holds no longer wait behind it")`.
   Derive the id label by deserializing the payload (`ResponseHeld.hold_id` / `CasePromoted.case_id`).
4. The budget resets.

**Behaviour, part 3 — parked retry.** On a tick where the alarm spool head is `None` (idle),
`ParkedLedger::next_due(now_ms, PARKED_RETRY_INTERVAL_MS)` returns at most one record (oldest
`parked_at_ms` first) whose `parked_at_ms + PARKED_RETRY_INTERVAL_MS <= now_ms`. Deserialize its
payload and run it through the same planning and publishing as a head record (extract the
existing match on `RuntimeEvent` into `async fn drain_one(...) -> Result<Drained, BridgeError>`
with `enum Drained { Landed, Refused, Stalled, Discarded }`, used by both paths, so the code is
not duplicated). On `Landed` or `Discarded` (undeliverable, empty plan, conflict): remove it
from the ledger and `metrics.alarm_unparked(outcome_label)`. On `Refused`: `retries += 1`,
`parked_at_ms = now_ms`, persist. On `Stalled`: leave it untouched (the relay is down; the
next idle tick past the interval tries again). Never retry a parked record on a tick that
drained a head record: the head is always served first, and parked retries can never starve
it.

`ParkedLedger` (`alarm/parked.rs`): `open(path) -> Result<Self, BridgeError>` (a missing file is
empty; a corrupt file is `BridgeError::SpoolIo`, never silently reset — same rule as
`CaseRouting::open`), `park(&mut self, record) -> Result<(), BridgeError>` (enforces
`PARKED_CAPACITY` by evicting the oldest and returning it so the caller can count the drop),
`next_due(&self, now_ms, interval_ms) -> Option<&ParkedRecord>`, `remove(&mut self, issuer, seq) -> Result<(), BridgeError>`,
`touch(&mut self, issuer, seq, now_ms) -> Result<(), BridgeError>` (retries += 1, parked_at_ms = now_ms),
`len(&self)`. On disk: pretty JSON, `{ "version": 1, "records": [...] }`, payload bytes as
base64 (the crate already depends on `base64` through the workspace; confirm with
`grep base64 crates/swarm-perch-bridge/Cargo.toml` and add the workspace dependency if absent).

**Metrics** (`metrics.rs`, registered in `BridgeMetrics::new` beside `hold_undeliverable`):
`perch_bridge_alarm_parked_total{reason}` and `perch_bridge_alarm_unparked_total{outcome}`;
the overflow drop reuses `dropped_event(Stream::Alarm, "parked_overflow")`. Add both to the
metrics test that enumerates registered names, if one exists (`grep -n 'hold_undeliverable' crates/swarm-perch-bridge/src/metrics.rs`).

**Tests** (in `alarm.rs`'s existing `mod tests`, using its `drainer(...)` harness and recording
publisher — read those helpers first; extend the mock publisher with a programmable refusal
`Fn(&Frame) -> Option<OkOutcome>` if it does not already have one — and a new `mod tests` in
`alarm/parked.rs`):

1. `a_not_a_channel_member_refusal_forgets_the_created_channel_and_the_next_tick_recreates_it`
   — the publisher refuses the first `9000` for case A with `NotAChannelMember` when A is not in
   its "known channels" set and accepts `9007`; after two ticks the frames are, in order:
   `9007, 9000(refused), 9007, 9000, 9, 46010, 26006`; the routing ledger has A created;
   exactly one card.
2. `a_permanently_refused_sequence_is_parked_after_the_budget_and_the_record_behind_it_drains`
   — two `ResponseHeld` records A then B; the publisher refuses every `9000` for case A
   forever (`NotAChannelMember`, and `9007` answers `ChannelAlreadyExists`); after
   `HEAD_REFUSAL_BUDGET` ticks A is parked (ledger file has one entry naming A's hold id,
   `perch_bridge_alarm_parked_total{reason="not_a_channel_member"} == 1`), and within the next
   six ticks B's five frames landed in order.
3. `transport_errors_never_count_toward_the_budget` — the publisher returns `Err` for
   `HEAD_REFUSAL_BUDGET + 5` ticks; nothing is parked, the record is still at the head, the
   ledger file does not exist.
4. `a_deferred_alarm_never_counts_toward_the_budget` — `submit_alarm` answers `Deferred` for
   `HEAD_REFUSAL_BUDGET + 5` ticks; not parked.
5. `a_parked_record_is_retried_on_an_idle_tick_and_removed_when_it_lands` — park A as in test
   2, then make the publisher accept; advance the clock past `PARKED_RETRY_INTERVAL_MS` (the
   drainer reads `now_ms` through a clock it can be built with — add `clock: Arc<dyn Fn() -> i64 + Send + Sync>`
   to `AlarmDrainer` defaulting to `chrono::Utc::now`, or the equivalent the harness already
   uses; measure before inventing); on the next idle tick A's remaining steps land, the ledger
   is empty, `unparked_total{outcome="landed"} == 1`.
6. `a_parked_record_is_never_retried_while_the_head_has_work` — park A; queue C; the tick that
   drains C does not touch A even though A is due.
7. `a_parked_hold_whose_plan_is_empty_is_discarded` — park A; then record A's open card,
   notice and alarm in the ledger/store as accepted; on retry the plan is empty: removed,
   `unparked_total{outcome="discarded"} == 1`.
8. `the_parked_ledger_survives_a_reopen_and_refuses_a_corrupt_file` (`parked.rs`).
9. `the_parked_ledger_evicts_the_oldest_past_capacity` (`parked.rs`).
10. The existing `a_refused_step_leaves_the_record_at_the_head_and_publishes_no_duplicate_card`
    must still pass unchanged: its refusal count is below the budget.

**Verification.** `cargo fmt --all --check`; `cargo clippy -p swarm-perch-bridge --all-targets -- -D warnings`;
`cargo test -p swarm-perch-bridge`; `bash tools/check-runtime-panic-contract.sh`;
`bash tools/check-workspace-layering.sh` (the bridge stays out of the TCB and links nothing new).
Do not run the `relay_live` ignored tests; the controller runs the live reproduction.
