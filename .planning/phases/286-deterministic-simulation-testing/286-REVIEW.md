# Phase 286 Recovery And Blocking Review

**Disposition: BLOCK — original candidate rejected; repair in progress.**
**Date:** 2026-09-07. **Confidence:** high for the recovery facts and source-level
findings below. This record does not claim that the replacement implementation,
corpus, mutation controls or repository gates have passed.

## Scope and immutable candidate

- Original base: `5ad9b685025bc8b84c2eef7d473f21c42a1f3668`.
- Rejected candidate: `1a5c9003bb346176d393a529d6d440e01d874cfc`.
- Candidate branch/check-out: `feat/dst-286` at
  `/Users/connor/Medica/backbay/standalone/swarm-team-six-dst-286`.
- Recovery branch/check-out: `codex/dst-286-recovery` at
  `/private/tmp/ambush-dst-286-recovery-20260907`.
- Original candidate contains eight commits, including its premature planning
  closure. Its checkout was clean when recovered; original objects are retained.
- Binding requirements: `.planning/REQUIREMENTS.md` DST-01..06 and ROADMAP Phase
  286. Plan 01's permission to weaken safety oracles to fit current code is
  rejected. Repair acceptance is defined in [286-02-PLAN.md](286-02-PLAN.md).

The source references below all refer to the immutable original file
`1a5c9003b:crates/swarm-runtime/tests/dst_fault_injection.rs`, not the evolving
recovery checkout. Reproduce that source with:

```sh
git show 1a5c9003bb346176d393a529d6d440e01d874cfc:crates/swarm-runtime/tests/dst_fault_injection.rs
```

## Exact interrupted-session evidence

Authoritative controller transcript:

```text
/Users/connor/.claude/projects/-Users-connor-Medica-backbay-standalone-swarm-team-six/f0a6eaa1-2081-4bbe-b871-588454af7600.jsonl
```

- Line 287, `2026-09-06T23:12:36.170Z`: proposed the whole gameplan, including
  desktop acceptance, hold-durability repair, engine phases and open-agent-protocol.
- Lines 294–296, `2026-09-06T23:34:14.947Z`: user `/goal` authorized the entire
  gameplan plus canonical engine phases 285–313, with packaging after that work.
- Lines 9221–9229, `2026-09-07T20:31:55.091Z` through `20:33:01.066Z`:
  controller recorded candidate `1a5c9003b` and launched its final review over
  `5ad9b6850..1a5c9003b`.
- Line 9248, `2026-09-07T20:33:22.443Z`: controller called all five tasks complete
  pending final review, then intended to integrate and proceed to Phase 287.
- Line 9279, `2026-09-07T20:35:21.618Z`: user stopped the background agents.
- Line 9281, `2026-09-07T20:35:25.551Z`: controller transcript ends with
  `[Request interrupted by user]`.

The final review's local output is:

```text
/private/tmp/claude-501/-Users-connor-Medica-backbay-standalone-swarm-team-six/f0a6eaa1-2081-4bbe-b871-588454af7600/tasks/aaa4c98102e047e51.output
```

It ends with `[Request interrupted by user]` at `2026-09-07T20:35:21.571Z`.
The planned `.superpowers/sdd/286-01-PLAN/whole-branch-review.md` did not exist
when inspected. Source-reading activity preceded the interruption, but no final
verdict or fresh terminal test evidence was delivered. The controller's assertion
that this reviewer had worked about 60 minutes confused a goal-hook duration with
review runtime: launch-to-interruption was approximately 2 minutes 20 seconds.

**Scope correction:** the user did not independently defer open-agent-protocol.
The proposed and approved milestone admits a signed external deposit identity,
verifies deposit ingress in the daemon, and grants no response authority. Its
initial participant is an Ambush persona reading finding cards and depositing
corroboration. Later design-input deferrals were assistant rulings. Canonical
provenance phases 296–299 retain their 292–294 prerequisite; old PR #5's
"Phase 286 collective hypothesis graph" uses obsolete numbering and is input
for the provenance work, not this DST phase.

## Blocking findings against the original candidate

### B1 — Reversed receipt predicate accepts effects without durable prerequisites

`oracle_receipt_before_action` (lines 1032–1087) constructs dispatch identities
and iterates only persisted deposits (line 1041). Zero deposits immediately yield
success at line 1087, regardless of effects. It checks
`persisted_receipt_identities ⊆ dispatched_identities`; it never proves a durable
record existed before each effect. Matching final identities also cannot establish
temporal order without independently observed persistence/dispatch ordering.

`run_episode` (633–645) executes before its persistence checkpoint. The
post-dispatch drop branch (794–797), and its named test (1524–1545), explicitly
produce one dispatch, no persisted receipt and no returned outcome. This trace
passes all three original oracles: the receipt loop is empty, dropped disposition
returns success, and a dispatch count of one meets the at-most-once oracle.

**Required correction:** record a durable authorization intent before dispatch
at production entry sites. Completion remains a separate post-effect record;
uncertainty must preserve the reservation. Reject an observed effect lacking its
prior durable intent through a production-ordering mutation control.

### B2 — Cancellation hides forbidden effects from the policy oracle

`oracle_exact_disposition` (1117–1134) returns success for either drop class as
soon as `outcome` is absent, before inspecting `expected_verdict`. Its explicit
denial prohibition appears only in the completing branch (1190–1211).

Control-flow counterexample: a `DropAfterDispatchBeforePersist` observation with
`outcome=None`, one dispatch, zero deposits and policy verdict `Deny` or
`RequireHuman` passes exact disposition (1134), receipt consistency (1087) and
at-most-once (1255). `evaluate_oracles` (1261–1275) then reports no violation.
This is proof of an oracle blind spot, not an assertion that the current
production gate already bypasses denial.

**Required correction:** forbidden effect counts must be checked independently
of whether the future returned. A production policy-bypass mutation combined
with cancellation must make the ordinary harness fail.

### B3 — No request is retried against retained crash-recovery state

`drive_episode_with_request` (826–835) creates a fresh gate, runtime, adapter and
substrate, then executes one episode once. Drop branches (789–797) destroy the
future without retry. Close/reopen (799–805) resumes the same suspended future.
The corpus's next invocation creates new state, so a request's effects cannot
accumulate over attempts in `oracle_no_double_dispatch` (1231–1255).

The essential failure history — request dispatches, crashes, is redelivered,
and dispatches again — is absent. Inserting duplicate records into a fabricated
observation only checks that the counter notices a supplied duplicate.

**Required correction:** preserve a durable immutable request reservation,
reconstruct runtime/store state, redeliver the same request, and independently
observe the complete effect history. Removing duplicate refusal in production
must make this history fail the oracle.

### B4 — Seed count measures four repeated schedules

`FaultPlan::for_seed` (316–325) draws a class and checkpoint, but the driver
(833–835) passes only `plan.class` into `run_episode_under_fault` (784–805).
Each of the four classes uses a fixed path and fixed poll checkpoint; request
(697–714), context (737–746), and newly constructed state (826–830) are fixed.
Comments at 287–297 and 857–860 confirm the checkpoint draw has no operational
effect. The 5,000-seed loop (1749–1763) repeats those four schedules.

**Required correction:** make seeded values alter effective scheduling and
request/recovery histories, then report measured schedule diversity. Metadata
changing while execution stays identical is not deeper coverage.

### B5 — Substrate reopen does not recover persisted data

`SubstrateSeam::open` (525–530) creates an in-memory instance.
`close_then_reopen` (542–550) discards it and calls
`InMemoryPheromoneSubstrate::new` with the same config. No durable path is opened.
The driver deposits nothing before the episode; replacement occurs after dispatch
and before the only deposit (641–645, 799–804).

The actual history is empty A → dispatch → discard A → empty B → first deposit
into B. The lifecycle test (1549–1590) cannot expose lost journal entries,
corruption, replay errors or recovery of prior authorization/receipt state.

**Required correction:** close and reopen the same persistent local substrate,
observe retained records, and include malformed/torn persistence and request
redelivery. Keep the dispatch journal's unsigned intent distinct from signed
substrate/audit evidence.

## Required repaired behavior and explicit limitations

The repair must apply its reservation protocol to both
`SwarmRuntime::authorize_and_execute` and
`audit_authorize_and_execute_instrumented_internal`, including its public audit
and human-approved wrappers. Store ownership supplies bounded capacity, durable
flushes, exclusive writer control, immutable request bindings and fail-closed
recovery. Runtime composition binds the audit directory and keeps the store's
`Arc` across reload. Effectful resilience retries must not repeat an ambiguous
adapter call inside a single journal reservation.

A pre-effect authorization intent is not a successful response receipt. After a
crash, a durable intent without a trustworthy completion means unresolved; it
must never be silently retried or reported complete. At-most-once dispatch can
sacrifice availability: an intent written before a crash may block a request
whose external effect never occurred. This repair does not claim automatic
exactly-once completion, atomic external effects, or rollback of an uncertain
remote action. The unsigned local journal depends on OS/filesystem protection;
existing signed audit has separate provenance and verification.

Future-drop tests model cancellation. Process-kill/restart evidence must be
identified separately if executed. Scope is one host/process recovery model and
one logical local persistent substrate; distributed JetStream failover and
cross-node consensus remain outside this phase's harness.

## Replacement acceptance evidence — partial; phase not accepted

The owner of final integration must fill this table only from terminal evidence
against the final immutable repaired tree. Do not copy the rejected candidate's
passing claims or mark source inspection as a passed runtime test.

| Obligation | Required evidence | Current status |
|---|---|---|
| Exact repaired tree | Commit/tree hash and clean diff boundaries after all source edits | Production/source checkpoint `92df4f4c8`; all three production mutations restored exactly; later edits are evidence documents |
| Durable store | Bounded capacity, fsync/failure, exclusive writer, malformed/torn/conflicting records and immutable reservation tests | All journal unit tests pass in restored runtime suite; physical power-loss and privileged rollback are outside scope |
| Both runtime paths | Real effects and refusals for direct, audit and human-approved routing, with missing storage and duplicates | Current unit tests and both new negative integration tests pass; actual current HTTP transport checks remain sandbox-blocked |
| Composition/reload | Configured persistent audit directory, shared store across reload and same-request redelivery | Eleven new composition tests and first-run replay publication regression passed in current 177-test ingest suite; five unrelated listener setups remain sandbox-blocked |
| Internal adapter retry | Ambiguous first effect is never executed a second time by resilience logic | Current non-HTTP resilience tests pass; current real HTTP effect/timeout checks blocked at local listener creation |
| DST-01 / DST-02 | Real sandbox effects, runtime/gate, persistent substrate reopen and redelivery with named fault schedules | Corrected ordinary DST suite passes before and after production mutations, including 64 seeds and full verdict/fault matrix |
| DST-03 | Effect-before-intent, denied-cancellation and duplicate-redelivery production mutations cause the expected oracle failures | All three actual production mutations rejected with named failures; restored positive suite passes; see retained patches/results/logs |
| DST-04 | Exact PR/nightly commands, 64 and >=5,000 seeds, measured effective schedule diversity and terminal exit statuses | Final 64 seeds pass with 53 traces / 16 pairs; 5,000 nightly pass with 897 traces / all 18 pairs at af250a8e8; CI command selection verified in source |
| DST-05 | Repeated selected-seed executions reproduce effective schedules and observations | Same-seed trace/durable-effect test passes; two explicit seed-57 commands passed with identical full plan/trace; explicit seed-11 passed |
| DST-06 | Final MAPPING claims match demonstrated storage/process scope and journal/audit distinctions | Pending |
| Required regressions | Formatting, affected suites, existing negative tests, Clippy, layering/mapping/routing/gate-wiring and all applicable existing gates | Local static gates, all 17 registered negatives and full Clippy pass; network-enabled affected regressions pending |
| Independent review | Final-tree review disposition plus fixes and re-review where needed | Scoped source/evidence PASS at af250a8e8, moderate confidence; final one-line Clippy delta acknowledgment pending; no HTTP/full-phase acceptance claimed |

Phase 286 remains **IN PROGRESS / REOPENED** until every obligation is supported.
The full goal remains the approved gameplan and canonical phases 285–313.


## Recovery checkpoint evidence (2026-09-07; acceptance still open)

Production checkpoint: `5df3c228bcb8a6801a2ac2c6d016cc36c6860466` on
`codex/dst-286-recovery`. Its source review passed for dispatch journal, helper
and runtime enforcement. The reviewer explicitly excluded Cargo execution and
phase acceptance. The final two-line delta restricts reservation/completion
writes to `pub(crate)`; the reviewer acknowledged this exact immutable hash.

Terminal observations, retained separately from final-tree acceptance:

- Runtime library command `cargo test --locked -j 2 -p swarm-runtime --lib --
  --test-threads=1` exited 101: **583 passed, 1 failed**. The failed existing
  `process_event_with_investigation_stays_nonblocking_and_persists_bundle`
  asserted elapsed time below 75 ms and observed 184.947625 ms. A deterministic
  asynchronous-completion proof is being prepared; no timing-threshold waiver
  or whole-suite pass is claimed. This build began before the final source
  visibility/client retry edits and is not exact-final-tree acceptance.
- Current response command `cargo test --locked -j2 -p swarm-response --lib --
  --test-threads=1 --quiet` at the production checkpoint compiled successfully
  and exited 101: **43 passed, 28 failed**. All 28 failures rejected local TCP
  listener creation with OS error 1 (`Operation not permitted`) in this
  restricted environment. Log: `/private/tmp/ambush-response-5df3c228b.log`.
  An earlier snapshot passed 71 tests before the four explicit reqwest
  `retry(never())` additions. That older pass is not current-tree HTTP evidence.
- Current static gates exited zero: `check-no-unrouted-authorize.sh` (zero
  production callers), `check-workspace-layering.sh` (11 fixture cases and live
  graph), `check-red-swarm-no-execution-authority.sh`,
  `check-visibility-baseline.sh`, and `check-no-include-files.sh` (12 fixture
  cases). Mapping, negative registry, gate wiring and runtime panic gates also
  passed in the immediately preceding checkpoint; their final rerun remains
  part of acceptance after all test-source changes.
- Mutation preparation found the replacement sandbox adapter still asserted a
  durable intent before writing its effect marker. That would kill a bad
  ordering mutation before observing the forbidden effect. The harness is
  being refined into a passive observer so the named independent oracles,
  rather than an adapter-side safety guard, reject production mutations.

Current progress does not close any pending obligation in the acceptance table.
The sandbox TCP restriction is a concrete limitation on local HTTP verification;
no approval escalation or alternative-environment result is claimed.


### Subsequent checkpoint and regression progress

- `8086b8cd512bc50f3a064fcdf108a24f02b9204f` replaces the fragile
  investigation duration assertion with a started/release latch and fixes the
  live HTTP approval fixture's durable audit configuration. Execution pending.
- `3051f1ab0811b326e803af8eb479dfe8ffe54e3e` makes the DST effect adapter
  observation-only. It persists the observed intent status with its actual
  sandbox effect and runs named safety oracles after cancellation and after
  redelivery, before generic result assertions. Execution pending.
- The ingest library command `cargo test --locked -j2 -p swarm-ingest-runtime
  --lib -- --test-threads=1 --quiet` exited 101: **171 passed, 5 failed**. The
  eleven new composition tests passed. All five failures were local TCP
  listener creation rejected with `Operation not permitted`. Log:
  `/private/tmp/ambush-ingest-5df3c228b.log`. This result precedes the first-run
  replay correction described below.
- An independent composition review found no journal ownership/reload bypass,
  but identified two real integration regressions: the shipped hold development
  profile still selected live mode with Memory audit storage, and first-run's
  isolated audit directory made its result unavailable to the configured
  replay lookup. Both remain open until their corrections and regressions pass.

Production mutation recipes, to execute independently after a clean baseline:

1. Ordering, seed 57: move the enforced executor await in `dispatch.rs` before
   `journal.reserve`. Expect an actual `IntentMissing -> Effect -> Crash` trace
   and `ordering: effect preceded durable intent`.
2. Duplicate, seed 57: make `reserve` return the existing ID rather than
   `AlreadyReserved`. Expect a second fsynced effect after reopen and
   `at-most-once: duplicate effect across restart`.
3. Disposition, seed 11: remove only the direct runtime's `Deny` return, leaving
   StaticApprovalGate unchanged. Expect actual post-effect cancellation and
   `disposition: forbidden effect despite cancellation`.

For each: `SWARM_DST_SEED=<seed> cargo test --locked -j2 -p swarm-runtime
--test dst_fault_injection dst_pr_corpus_or_exact_seed_replays_real_crash_recovery
-- --exact --nocapture --test-threads=1`. Preserve exact source patches, immutable
base and terminal logs in a disposable checkout, restore the source, and rerun
positive controls. These recipes are source-reviewed; none has executed yet.


### Executed production mutation controls at 92df4f4c8

The ordinary corrected DST baseline passed: four tests (including 64 seeds,
verdict/fault matrix and deterministic replay), one nightly corpus ignored.
Both new negative invariant tests passed. The subsequent development-profile
commit changes no Rust source. Exact retained artifacts:
[evidence/recovery-92df4f4c8](evidence/recovery-92df4f4c8/README.md).

Each production mutation ran independently in the disposable recovery clone at
`92df4f4c8f3bdeaf55539bd2964b417d7d313a6f`; exact source bytes were restored
and the Git diff verified clean between cases. Original checkouts were untouched.

| Production mutation | Seed | Cargo exit | Observed named rejection |
|---|---:|---:|---|
| Executor awaited before durable reserve | 57 | 101 | `ordering: effect preceded durable intent`; trace `IntentMissing`, fsynced `Effect`, `Crash` |
| Existing reservation returns permission | 57 | 101 | `at-most-once: duplicate effect across restart`; second fsynced `Effect` after `Restart` |
| Direct Deny return removed | 11 | 101 | `disposition: forbidden effect despite cancellation`; denied `Effect` followed by `Crash` before returned result |

The outer runner exited zero only after verifying all three expected nonzero
Cargo outcomes and exact restoration. A final positive rerun is in progress.
The large nightly corpus and network-enabled full regressions remain unverified.

### Replay-index finding: corrected provenance

Review correctly identified `FileReplayBundleStore::persist` as an unlocked
index read/modify/write. Concurrent independent writers can lose index entries.
Root compared the ORIGINAL rejected candidate `1a5c9003b`, rather than only an
intermediate recovery snapshot: `control.rs:436-440` already created a separate
IngestState for first-run from guided config; `guided_first_run_config` at 739
cloned the config and never changed `audit.bundle_store`. Its `store.rs:404-415`
has the same unlocked persistence sequence. A concurrent daemon and first-run
therefore already shared independent writers to that audit index.

This is a preexisting replay-store concurrency finding, not a newly introduced
first-run regression or dispatch-journal bypass. Restoring discoverable first-run
bundles retains that existing limitation. The new dispatch journal does not use
this replay index for reservations or refusal. Any future repair must coordinate
ALL writers at the store boundary and prove concurrent publication; locking only
the first-run caller would be insufficient. No concurrency safety for the replay
index or fix of this existing issue is claimed by Phase 286.


### Positive rerun after removing all production mutations

`cargo test --locked -j2 -p swarm-runtime --lib --test dst_fault_injection
--test negative_runtime_dispatch --test dispatch_integration --no-fail-fast --
--test-threads=1 --quiet` ran against restored `92df4f4c8` source:

- Runtime unit library: **578 passed / 6 failed**. All six failures are local
  TCP listener permission errors. The new journal tests, both runtime entry
  tests, containment-completion preservation and deterministic investigation
  latch passed.
- Dispatch integration: **20 passed / 1 failed**. The one failure is the same
  local TCP listener prohibition in the dispatched-webhook timeout test.
- Corrected DST suite: **4 passed / 1 nightly ignored**, including the normal
  64-seed corpus, matrix, replay and oracle controls. This closes the positive
  restoration control after all three bad production mutations.
- New negative invariant integration: **2 passed / 0 failed**.

The combined Cargo command exited **101** because two targets contained the
seven network setup failures. It is not a full regression-suite pass. Exact log:
[evidence/recovery-92df4f4c8/runtime-restored.log](evidence/recovery-92df4f4c8/runtime-restored.log).

The development hold profile's new signature was independently verified using
its canonical statement (ASCII keys sorted as `canonical_json_bytes` does),
Ed25519, exact YAML digest/length/name, expected development public key, key-ID
hash, and a changed-statement rejection. An initial ad hoc verifier incorrectly
used declaration order and rejected the signature; inspecting the actual signer
identified canonical serialization, and the corrected verifier passed. No
production signature or daemon-startup result is claimed.


The subsequent complete ingest library run at restored `92df4f4c8` exited 101:
**172 passed / 5 failed**. The new first-run publication/reopen regression and all
11 dispatch-journal composition tests passed. All five remaining failures are
TCP listener permission errors. See
[evidence/recovery-92df4f4c8/ingest-final.log](evidence/recovery-92df4f4c8/ingest-final.log).

A subsequent test-only diagnostic prints the exact seed count, verdict/fault
pair count and effective executed trace count after corpus assertions succeed.
It changes no oracle, schedule, cancellation, or production logic. Its final
positive/deep-corpus runs are still required; prior mutation evidence remains
explicitly bound to the preserved `92df4f4c8` source snapshot.


### Final corpus and explicit replay terminal evidence

At source checkpoint `af250a8e883695f92cdbf9f21f3175ff1f1e5d19`, the ordinary
suite passed with **64 seeds / 53 effective traces / 16 verdict-fault pairs**.
Two exact `SWARM_DST_SEED=57` commands passed and produced identical full printed
plan/traces; `SWARM_DST_SEED=11` also passed. The ignored nightly command passed
with **5,000 seeds / 897 effective traces / all 18 verdict-fault pairs** in
693.741 seconds. All five Cargo invocations exited zero. Exact records:
[evidence/final-af250a8e8](evidence/final-af250a8e8/README.md).

The engine PR test lane calls `cargo test -p swarm-runtime -p
swarm-ingest-runtime -- --test-threads=1`, which selects the unignored 64-seed
suite; the nightly workflow calls the same integration target with `--ignored`,
which executed exactly the one 5,000-seed test. This is source-selection and local
execution evidence; no hosted GitHub run is claimed. The later registry, Clippy
and source-review results follow below. Network-enabled regressions remain open.


### Registered negatives, full Clippy and final source review

All **17 registered invariant test functions** executed and passed, grouped into
3 policy, 7 runtime, 4 spine and 3 response entries. The runner required each exact
registered function name to appear with `ok` in terminal output; registry parsing
alone was not counted as execution. The canonicalization unreachability deviation
remains documented. Grouped commands, logs and results are retained in
[evidence/final-af250a8e8](evidence/final-af250a8e8/README.md).

Full workspace all-targets Clippy initially exited 101 for one unnecessary
`ok_or_else` closure in first-run replay publication. Changing only that call to
`ok_or` yielded a clean rerun of `CARGO_INCREMENTAL=0 cargo clippy --locked -j2
--workspace --all-targets -- -D warnings`, terminal exit 0. The source delta changes
no policy, journal, retry or DST code. All four selected first-run regressions then passed, including same-config replay
lookup beside a live daemon. The one-line source delta was independently reviewed
without findings; an immutable checkpoint acknowledgment follows.

Independent final source/evidence review at `af250a8e8` returned **PASS**, with
moderate confidence and no introduced P0/P1/P2 finding. It verified mutation patch
and restored-source digests, the unchanged production source between 92df4f4c8
and af250a8e8, actual named mutation failures, final corpus results and explicit
replay equality. It did not claim HTTP-regression or whole-phase acceptance.

The diversity metric counts complete event traces, including actual `Poll(n)`
variation. **897 yielded event traces is not a claim of 897 distinct crash/effect
orderings**. Requests are sequential, with one shared verdict per seed. The
three production mutations independently establish the named safety-oracle
failures. These boundaries remain part of any final acceptance claim.

The targeted HTTP approval/proof-export test compiled after the Clippy fix, then
failed at `http/tests.rs:1745` when binding its local listener (`Operation not
permitted`), before the updated live-response fixture ran. This remains an
environment-blocked regression, not a passing HTTP test. The PR workflow includes
all affected runtime/ingest tests and the response/HTTP crates, with no draft
exclusion; hosted terminal results are still required.
