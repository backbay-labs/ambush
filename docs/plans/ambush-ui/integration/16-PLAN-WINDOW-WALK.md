# 16 — What the first real window showed: the fixes

**Status:** implementation plan, 2026-09-07. Every task below is a defect `evidence/window-walk.md`
found on a real Tauri window against the live relay and daemon, numbered there as found-1 …
found-14. Found-11, found-12 and found-13 were fixed in the same sitting (`97adf18b6`); the
rest are here.

**Spec authority.** `01-DESIGN.md` §5 (the four load-bearing properties: the bridge never
blocks, the relay is never the record, writes are two-legged and never optimistic, a verdict has
somewhere to live), §7 (the console feature area: seven REQs, no more; the ephemeral store;
INV-15 admission), §10 (every failure mode has a rendered state); `../07-REALTIME-AND-DATA.md`
(the frames and the strip); `00-DECISIONS.md` W3-5 (a case renders as a case only at
`/cases/$caseId`); ADR 0012 (the bridge writes back exactly `mark_case_channel` and
`mark_notified`). Where a task and those documents disagree, they win.

## Global constraints

- Desktop tasks: TypeScript under `workspace/desktop`, Biome (`pnpm exec biome check .`),
  `pnpm typecheck`, `pnpm test` (Node's runner, `*.test.mjs` beside the code), `pnpm check`
  (px-text, pubkey truncation, community resetters, copy ban list, route tree). The 1000-line
  file ceiling is enforced by `just file-size-check`; `tauri.ts`, `relayClientSession.ts`,
  `types.ts` and `markdown.tsx` are on the do-not-edit list (`../build/15-FILE-SPLIT-PLAN.md`).
  Features never import each other; cross-feature code lives in `shared/`. Every module-level
  singleton is a named entry in `communityScopedRegistry.ts` (INV-23).
- Engine/bridge tasks: root toolchain (Rust 1.97.1, edition 2024), `cargo fmt --all`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `unwrap_used`/`expect_used` denied
  outside `mod tests`, `tools/check-runtime-panic-contract.sh`, `tools/check-workspace-layering.sh`
  (the bridge stays out of the TCB; `swarm-perch-wire` depends on no `swarm-*` crate).
- The seven-REQ inventory in `perchSubscriptions.ts::buildPerchSubscriptions` is closed. No task
  adds a REQ; Task 1 makes the existing ones actually open.
- INV-15: nothing renders from an unadmitted issuer. INV-28/INV-33/INV-36: leg 1 and leg 2 are
  rendered as separate facts and there is no undo.
- Copy: `Perch`, `Swarm Team Six` and `clowder` never appear in a rendered string
  (`tools/check-copy-banned-terms.sh`). New copy goes in the feature's `copy.ts`/`*Copy.ts`
  module, not inline.
- Commits: `git commit -s`, Conventional Commits. No push from a task.
- Tests assert behaviour: frames applied or refused, REQs sent or not, the rendered text.

---

### Task 1: Open the seven REQs and feed the ephemeral store (found-2, and the admission race)

**Files.**
- `workspace/desktop/src/shared/api/perchLaneMovement.ts` — this is the perch subscription
  manager (the name is historical: it grew from the one lane-movement REQ and never took the
  rest). Rename it `perchSubscriptionManager.ts` with `git mv`, update every import (`grep -rn
  perchLaneMovement src`) and the registry entry in `communityScopedRegistry.ts`; keep
  `readLaneMovementEnvelope` and `LaneMovementEnvelope` exported from the new name.
- `workspace/desktop/src/shared/api/perchEphemeralStore.ts` — the pre-admission buffer.
- `workspace/desktop/src/shared/api/perchTelemetryWanted.ts` (new) — a mount-counted flag.
- `workspace/desktop/src/features/perch/ui/GovernanceStrip.tsx`,
  `workspace/desktop/src/features/perch-policy/ui/WatchfloorScreen.tsx`,
  `workspace/desktop/src/features/perch-evidence/ui/LaneScreen.tsx`,
  `workspace/desktop/src/features/perch-containment/usePartitionFacts.ts` — each declares itself
  a telemetry consumer.
- `workspace/desktop/src/app/perchViews.ts` — already resolves `/cases/<id>`; the manager reads
  the open case from it (or from the router's location; measure which the existing code uses).
- Tests beside each file; `workspace/desktop/src/testing/perch/e2ePerchBridge.ts` gains a way to
  emit an ephemeral frame (`__AMBUSH_E2E_EMIT_MOCK_FRAME__` or the equivalent the messages hook
  uses — measure `__AMBUSH_E2E_EMIT_MOCK_MESSAGE__` and mirror it) and one Playwright spec
  `tests/e2e/perch-telemetry.spec.ts`.

**Behaviour.**

1. `desiredSpecs()` builds the full inventory from real inputs:
   - `telemetryWanted` is `perchTelemetryWanted()`: a module-level mount count in
     `perchTelemetryWanted.ts` with `usePerchTelemetryConsumer()` (increments on mount,
     decrements on unmount, schedules a manager sync on each change) and `resetPerchTelemetryWanted`
     registered in `communityScopedRegistry.ts`. The four consumers above call the hook.
   - `activeCaseIds`: the ids of the channels the operator is a member of whose name starts
     with `case-` (the sidebar already has them: find the channels query the sidebar renders
     from and derive without a second fetch), newest first, capped at 128 as the filter demands.
   - `openCaseId`: the `/cases/$caseId` param when the location is a case, else `null`.
2. The sink routes by subscription id: `watch-alarm` and `telemetry` events become
   `applyPerchEphemeralFrame({ kind, pubkey, body: JSON.parse(content) or {}, receivedAtMs: Date.now() })`
   — this function has no caller today; that is the whole reason the strip and the Watchfloor
   are blank. `case-live` and `case-activity` invalidate the channel's message queries the way
   `lane-movement` does, and a `46010` on `case-activity` invalidates the needs-action feed
   query the Watch reads. `lane-movement` keeps its current behaviour.
3. Admission race: a frame that arrives while `admittedIssuersKnown()` is false is neither
   applied nor counted as unadmitted; it waits in a bounded buffer (32 frames, oldest dropped)
   in `perchEphemeralStore.ts` and is replayed through the admission check when
   `setPerchAdmittedIssuers` runs. A frame from a pubkey that is then unadmitted counts as
   unadmitted at that moment. The buffer is reset by the store's existing resetter.
4. A parse failure of a frame's content counts as `droppedFrames` (a new counter beside
   `unadmittedFrames`, rendered on the Watch's counter row as `undecodable frames N`), never a
   throw.

**Tests.**
1. `desiredSpecs` unit tests: no consumers → no telemetry REQ; one consumer → the telemetry
   REQ; two case channels joined → `case-activity` with both ids; on `/cases/x` → `case-live`
   with `since = nowSecs`; nothing else changes.
2. Sink tests: a `26004` on `telemetry` from an admitted pubkey lands in
   `getPerchEphemeralSnapshot().telemetry.get(26004)` with its body; the same from an
   unadmitted pubkey increments `unadmittedFrames`; a frame before the admitted set is known
   is buffered and applied after `setPerchAdmittedIssuers`; a 33rd buffered frame evicts the
   oldest; unparseable content increments `droppedFrames`.
3. Consumer hook test: mount two consumers, unmount one, the flag stays true; unmount the
   second, false; the community reset clears it.
4. Playwright `perch-telemetry.spec.ts`: with the perch feature on and the strip mounted, the
   mock emits a `26004` body `{ partition_state: "healthy", total_governors: 1, healthy_governors: 1 }`
   from the admitted issuer and the strip reads `GOVERNANCE healthy · committee of 1 (solo transport) · recv 0s ago`
   (Task 2 lands the interpolation; if it has not, assert `data-governance-mode="healthy"`);
   an unadmitted issuer's frame leaves the strip on `bridge-down` and the counter at 1.

**Verification.** `pnpm exec biome check .`, `pnpm typecheck`, `pnpm test`, `pnpm check`,
`pnpm build:e2e && pnpm exec playwright test --project=smoke tests/e2e/perch-telemetry.spec.ts tests/e2e/perch-queue-lifecycle.spec.ts tests/e2e/perch-marker-admission.spec.ts`,
`just file-size-check` from `workspace/`.

---

### Task 2: The governance strip says what it knows (found-1)

**Files.** `workspace/desktop/src/features/perch/lib/governanceCopy.ts`,
`workspace/desktop/src/features/perch/ui/GovernanceStrip.tsx`, a new
`workspace/desktop/src/features/perch/lib/governanceCopy.test.mjs`, and
`workspace/desktop/src/features/perch/lib/governanceMode.ts` only if the mode derivation needs
to expose the last-seen instant (measure first; it may already be in the snapshot).

**Behaviour.** `fillGovernanceCopy(template: string, values: Record<string, string | number>): string`
replaces every `{name}` with `String(values[name])` and throws on a placeholder the values do
not cover (a rendered `{x}` is a defect, and throwing in a unit test is how it stays one). The
strip supplies: `ago` — the age of the newest `26004` frame, formatted `<60 s → "Ns"`,
`<60 min → "Nm Ss"`, else `"Nh Nm"`; `lastSeen` — `"never"` when no frame has ever arrived,
else `"<ago> ago"`; `n` — `total_governors`; `unauthorized` — `unauthorized_partition_actions`
from the frame body (0 when absent); `mode`, `seconds`, `holder`, `since` for the copies that
carry them, wherever those copies are rendered (measure the mode-down, cooldown and watch-claim
renderers; leave a copy unrendered rather than half-filled).

**Tests.** Every key of `GOVERNANCE` whose value contains `{` has a test that renders it
through `fillGovernanceCopy` with the values the strip supplies and asserts no `{` survives;
`fillGovernanceCopy` throws on a missing value; the strip's existing E2E (if any: `grep -rln
perch-governance-strip tests/e2e`) asserts the bridge-down line reads
`bridge: down (last envelope never) · holds may not be reaching the console` on a fresh mount.

**Verification.** As Task 1's, plus `bash tools/check-copy-banned-terms.sh` from the root.

---

### Task 3: A governance-status frame exists (found-3)

**Files.**
- `crates/swarm-runtime/src/runtime_events.rs` — `RuntimeEvent::GovernanceStatus { emitted_at_ms, partition_state, total_governors, healthy_governors, quorum_threshold, unauthorized_partition_actions, active_contingency_leases }`, the exhaustive classifier in the bridge (`crates/swarm-perch-bridge/src/stream.rs`) gains the arm, and every other exhaustive `match` on `RuntimeEvent` compiles (grep `RuntimeEvent::` for the match sites; the bridge's classifier is the one that must route it to `Stream::Telemetry`).
- The publisher: wherever the daemon evaluates governance health on its tick (the readyz
  `governance` component is built from it — start at `crates/swarm-runtime-http/src/bin/swarm_detect.rs` and the governance authority it wires; find the loop that produces `healthy_governors`/`quorum_threshold`), publish one `GovernanceStatus` per evaluation and, if evaluations are event-driven rather than periodic, a 1 Hz heartbeat task beside the hold sweep that publishes the current reading.
- `crates/swarm-perch-bridge/src/telemetry.rs` (+ `coalesce.rs` if the reducers live there) — the 26004 producer: the frame body `swarm.perch.frame.governance_status.v1` exactly as `workspace/desktop/src/features/perch/wire/golden/frame-26004-governance-status.json` and `crates/swarm-perch-wire` define it (field names and types from the golden; `shedding` from the bridge's own shed state), keyed by frame kind per W3-37, signed by the telemetry identity, published at the pacer's cadence; coalescing keeps the newest reading.
- `crates/swarm-perch-bridge/tests/relay_live.rs` — an `#[ignore]` live assertion `an_authenticated_subscriber_receives_a_26004_within_three_seconds`, in the family already there.

**Behaviour.** A daemon with a governance authority publishes a reading at least once per
second; the bridge turns each into one 26004 frame (newest wins within a tick); the console's
strip (Task 1 + Task 2) reads healthy on the dev profile.

**Tests.** Engine: the heartbeat publishes with the authority's current numbers; a daemon with
no authority publishes nothing (and the strip stays bridge-down, which is the truth). Bridge:
a `GovernanceStatus` event becomes a 26004 whose body round-trips through the wire crate's
zod/serde parity check; two events in one tick coalesce to the newest; the frame's `schema`
string and every field match the golden vector. The live assertion above, run by the controller.

**Verification.** `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`;
`cargo test -p swarm-runtime -p swarm-perch-bridge -p swarm-perch-wire -p swarm-runtime-http`;
`bash tools/check-perch-wire-parity.sh`; `bash tools/check-runtime-panic-contract.sh`;
`bash tools/check-workspace-layering.sh`; the OpenAPI gate is untouched (no HTTP route).

---

### Task 4: The pane tells the truth after a decision, and a case is a case (found-10, found-14, found-8)

**Files.** `workspace/desktop/src/features/perch-watch/lib/verdictWrite.ts` and its tests;
`workspace/desktop/src/features/perch-watch/ui/WatchScreen.tsx` (the "no record" copy at the
selected-hold pane) and the pane component it renders; `workspace/desktop/src/features/perch-watch/lib/holdRows.ts`
only if the selected hold must be looked up in the terminal-inclusive list; the sidebar's
channel item (find it: `grep -rn "case-" src/features/channels src/features/sidebar src/shared/ui/sidebar.tsx`)
and the perch route helpers in `workspace/desktop/src/app/perchViews.ts`; Playwright specs
`tests/e2e/perch-verdict-pane.spec.ts` (extend) and `tests/e2e/perch-queue-lifecycle.spec.ts` (extend).

**Behaviour.**
1. **A failed leg 1 is a failed leg 1.** When `perch_record_hold_verdict` fails, the pane renders
   one register: `Nothing was recorded: <reason>. The daemon was not asked.` — never the
   `recorded` sentence and never `the daemon did not answer`. Measure how the composed sentence
   at found-14 came to be (three copies concatenated across states) and make the state machine
   own one sentence per phase.
2. **After leg 2 the pane keeps its hold.** The selected hold is resolved against the
   terminal-inclusive daemon list (`include_terminal=true`, which the Watch already fetches for
   its expired rows), so a hold that just left the open queue still renders: the hold's card, then
   `recorded <at>` and the leg-2 outcome — `acknowledged · granted_executed · receipt <id>`,
   `acknowledged · refused`, `refused_late · <rule>`, `superseded by <intent id>` — with the
   receipt id copyable. "The daemon has no record of this hold" is rendered only for a hold
   absent from that list.
3. **A `case-*` channel is opened as a case.** Clicking one in the sidebar navigates to
   `/cases/$caseId`; the ordinary channel view is never the destination for a case channel while
   the perch feature is on. With the feature off nothing changes.

**Tests.** Reducer: leg-1 failure yields `{ phase: "failed_to_record", reason }` and the
rendered sentence is exactly the one above; leg-2 outcomes render their own sentences. Pane:
after a mocked grant the pane renders the receipt id and never the no-record copy; after a
mocked leg-1 failure the pane renders the failure sentence only. Sidebar: with the feature on,
clicking `case-…` lands on `/cases/<id>` (assert the URL and the case surface's testid); with
it off, `/channels/<id>`.

**Verification.** As Task 1's, plus `pnpm exec playwright test --project=smoke tests/e2e/perch-verdict-pane.spec.ts tests/e2e/perch-queue-lifecycle.spec.ts`.

---

### Task 5: A hold on an already-routed case learns its channel (found-6)

**Files.** `crates/swarm-perch-bridge/src/holds.rs` (and its tests). Nothing else; ADR 0012's
two write-backs are the only store writes and `mark_case_channel` is one of them.

**Behaviour.** In `HoldPublisher::plan_open`, after `ensure_case_channel` returns a case the
routing ledger already records as created (`channel_is_created(case)`), and `record.case_channel`
is `None`, call `self.mark_case_channel(case)` before planning the card and the notice — the
same write-back `on_ok(CreateChannel)` performs for a first hold. It is idempotent and
informational (a hold is decidable without it), but leg 1 of the operator's write reads exactly
this field, so a null here refuses every decision on a second hold of a hunt.

**Tests.** `a_second_hold_on_a_routed_hunt_learns_its_case_channel`: two holds on one hunt; after
the second is planned, `store.get(second).case_channel == Some(case)`; the existing
`a_second_hold_on_a_routed_hunt_reuses_the_case_and_reasserts_membership` still passes; a hold
whose record already names the channel is not written again (count the store's
`mark_case_channel` calls with the existing mock store, or a counting wrapper).

**Verification.** `cargo fmt --all --check`; `cargo clippy -p swarm-perch-bridge --all-targets -- -D warnings`;
`cargo test -p swarm-perch-bridge holds`; `bash tools/check-runtime-panic-contract.sh`.

---

### Task 6: The escalation gate logs a crossing once (found-4's flood)

**Files.** `crates/swarm-runtime/src/escalation.rs` and its tests.

**Behaviour.** `evaluate_all` currently emits the WARN "pheromone concentration crossed
escalation threshold" AND publishes a `RuntimeEvent::Escalation` (`publish_escalation`, called
per evaluation) on every evaluation while a class stays above its threshold — every 100 ms on
the dev profile: 1,572 log lines in eight minutes, and 20,436 evidence records spooled into the
bridge in forty-five minutes against a pacer that drains one per second, so no finding card
reached the relay after the restart (`evidence/window-walk.md`, the evidence-stream counters).
Both the warn and the event are emitted on the rising edge only — the evaluation in which a
class first exceeds its threshold, or its target mode rises above the current mode — and the
steady state is logged at `debug!` with the same fields and publishes nothing. A class that
drops below and crosses again warns and publishes again. The events returned to the caller,
the mode transitions and the substrate records are exactly what they were; only the log level
and the runtime-event publication change. Measure the `mode_changed` flag `publish_escalation`
already carries: the edge rule may be expressible through it.

**Tests.** Drive `evaluate_all` through ten evaluations with a concentration held above the
threshold: exactly one `RuntimeEvent::Escalation` on the subscribed broadcaster and one warn
(use the crate's existing log-capture approach if it has one — `grep -rn 'tracing_test\|with_default\|MockWriter' crates/swarm-runtime`
— else assert on a counter the evaluator exposes for tests); drop below and cross again: a
second event; the existing escalation tests unchanged.

**Verification.** `cargo fmt --all --check`; `cargo clippy -p swarm-runtime --all-targets -- -D warnings`;
`cargo test -p swarm-runtime escalation`; `bash tools/check-runtime-panic-contract.sh`.

---

### Task 7: The pacer does not spend a tick on a record it will never publish (found-15)

**Files.** `crates/swarm-perch-bridge/src/pacer.rs` (and its tests); `crates/swarm-perch-bridge/src/metrics.rs`
if a counter is added; `crates/swarm-perch-bridge/src/stream.rs` only if a variant moves to
`DroppedAtSource` (see below).

**Behaviour.** `Pacer::tick` peeks one evidence record; when no producer turns it into a card
it counts `skipped_unpublished`, commits it, and the tick is over (`pacer.rs` ≈ 309–311). Under
a producer that emits faster than 1 Hz that is a queue that only grows: the walk measured
20,436 evidence records ingested, 2,127 skipped, zero cards published in forty-five minutes.
The invariant is *at most one relay frame per tick*, not one spool record per tick. So a tick
discharges every consecutive unpublishable record it meets — commit, count, peek again — up to
`PACER_SKIP_BUDGET` records (a `pub const`, 4,096, doc-commented: the bound exists only so a
poisoned spool cannot pin the task; at 1 Hz it clears a day of the 10 Hz flood in seconds), and
publishes the first publishable record it reaches in the same tick. A record that fails to
build (`BridgeError` from a producer) keeps its current handling.

Separately, decide per variant at `classify` time: a variant for which no producer exists and
none is planned in `14-PLAN-OPERATOR-COMPLETE.md` (measure: `Escalation` has a planned producer
— "the durable escalation producer and its edge coalescer", W3-29 — so it stays `Evidence`)
belongs in `DroppedAtSource`, counted, never spooled. Move only variants that meet that test,
and state each move in the commit message.

**Tests.** A spool of 100 unpublishable records followed by one `Finding`: a single tick
publishes the finding and reports 100 skipped; the skip budget bounds one tick (a spool of
`PACER_SKIP_BUDGET + 1` unpublishable records leaves one for the next tick); an interleaving of
publishable records still produces exactly one frame per tick (the invariant test that already
exists must still pass); the `classify_has_no_wildcard_arm` test still passes.

**Verification.** `cargo fmt --all --check`; `cargo clippy -p swarm-perch-bridge --all-targets -- -D warnings`;
`cargo test -p swarm-perch-bridge pacer`; `bash tools/check-runtime-panic-contract.sh`.
