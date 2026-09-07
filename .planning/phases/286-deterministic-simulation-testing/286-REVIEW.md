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

## Replacement acceptance evidence — all pending

The owner of final integration must fill this table only from terminal evidence
against the final immutable repaired tree. Do not copy the rejected candidate's
passing claims or mark source inspection as a passed runtime test.

| Obligation | Required evidence | Current status |
|---|---|---|
| Exact repaired tree | Commit/tree hash and clean diff boundaries after all source edits | Pending |
| Durable store | Bounded capacity, fsync/failure, exclusive writer, malformed/torn/conflicting records and immutable reservation tests | Pending |
| Both runtime paths | Real effects and refusals for direct, audit and human-approved routing, with missing storage and duplicates | Pending |
| Composition/reload | Configured persistent audit directory, shared store across reload and same-request redelivery | Pending |
| Internal adapter retry | Ambiguous first effect is never executed a second time by resilience logic | Pending |
| DST-01 / DST-02 | Real sandbox effects, runtime/gate, persistent substrate reopen and redelivery with named fault schedules | Pending |
| DST-03 | Effect-before-intent, denied-cancellation and duplicate-redelivery production mutations cause the expected oracle failures | Pending |
| DST-04 | Exact PR/nightly commands, 64 and >=5,000 seeds, measured effective schedule diversity and terminal exit statuses | Pending |
| DST-05 | Repeated selected-seed executions reproduce effective schedules and observations | Pending |
| DST-06 | Final MAPPING claims match demonstrated storage/process scope and journal/audit distinctions | Pending |
| Required regressions | Formatting, affected suites, existing negative tests, Clippy, layering/mapping/routing/gate-wiring and all applicable existing gates | Pending |
| Independent review | Final-tree review disposition plus fixes and re-review where needed | Pending |

Phase 286 remains **IN PROGRESS / REOPENED** until every obligation is supported.
The full goal remains the approved gameplan and canonical phases 285–313.
