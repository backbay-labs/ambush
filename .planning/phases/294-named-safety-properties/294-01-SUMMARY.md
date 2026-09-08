# Phase 294 Plan 01 Summary

Named Safety Properties And Partition-Lease Model (v1.81 Machine-Checked Decision Core). The THIRD
and FINAL v1.81 phase — states the decision core's guarantees as named, mapped, falsifiable
properties (P1–P6), registers the two remaining trust assumptions, and model-checks the
partition-contingency-lease protocol — the highest-risk concurrent logic in the system — with
Apalache, including negative falsifiability that reproduces real defects. Executed 2026-09-08 as a
4-task pipeline (T1 properties + mapping + assumptions -> T2 the TLA+ model -> T3 negatives + CI ->
T4 this close) on branch `feat/safep-294` off `main` `9f8c591c8`. **Closing this phase completes the
v1.81 Machine-Checked Decision Core milestone (292–294).**

## Delivered

- **Named properties, mapping, and assumptions (SAFEP-01/02/03; `adcae375c`):** `formal/PROPERTIES.md`
  names P1 (fail-closed evaluation) through P6 (rate-limit boundedness) over the decision core Phase
  292 extracted and Phase 293 proved with Kani. Each property states its plain-language guarantee,
  names the exact Rust symbol(s) it constrains, and names the Kani harness(es) that check it; P3/P4/P5
  also note the TLA+ invariant Task 2 adds. Every cited symbol and harness name was verified against
  the source tree before the document was written. `docs/assurance/MAPPING.md` gains a "Named safety
  properties" section — a distinct table headed `Property` (not `Name`), placed after the existing
  Loom section and documented the same way: `tools/check-mapping.sh` only parses the first table whose
  header starts with the literal column `Name`, so this table sits outside that gate's parse entirely.
  It cross-links P1–P6 to the existing invariant table's `Name`s where one genuinely already exists
  (P1/P6 -> `PolicyMalformedRequestRejected`, `PolicyHumanGateOnDestructiveAction`,
  `PolicyScopeRateLimitDeniesBurst`) and states plainly, for P2–P5, where none exists yet rather than
  inventing one — adding six new markers and six new `negative_*` tests for symbols like
  `ContingencyLease::verify`, `lease_redeem`, and `governance_quorum_threshold` would have been Task
  3's TLA+-level falsifiability work, not Task 1's. `check-mapping.sh` and `check-negative-registry.sh`
  stay green with the same 17 rows/17 markers they had before this commit (verified non-vacuous:
  before/after counts match exactly). `docs/assurance/assumptions.toml` registers
  `ASSUME-INJECTED-CLOCK` (every `formal_core` entry point receives `now_ms` as a caller-supplied
  parameter, never reads the OS clock itself; owner `swarm-policy`; dependents P1/P2/P4/P6) and
  `ASSUME-GOVERNOR-KEY-CUSTODY` (exactly one governor key is registered and its custody is not
  adversarially shared; owner `swarm-agents`; dependents P3/P5), each with a `dependent_properties`
  list alongside the existing `dependent_invariants` field. No Rust source file was touched.
- **The partition-contingency-lease TLA+ model (SAFEP-04; `1fca04400`):** `formal/tla/PartitionContingency.tla`,
  a typed Apalache model (`\* @type: ...;` annotations throughout — Apalache is a typed checker and
  rejects bare TLA+). It models the four partition states (`Healthy`/`Degraded`/`Partitioned`/`Healing`),
  contingency-lease issuance (partition-only, gated on an approved receipt, with a fresh
  `blast_radius_cap` budget), redemption (cap-bounded and expiry-denied), and reconciliation on heal.
  Four named safety invariants — the TLA+ statements of P3/P4/P5 — are checked clean:
  `BlastRadiusNeverExceeded` (`redeemedCount <= BlastRadiusCap`), `OverrideRequiresReceipt`
  (`leaseActive => leaseHasReceipt`), `NoRedemptionAfterExpiry` (`~redeemedWhileExpired`), and
  `NoLeaseWhenHealthy` (`partitionState = "Healthy" => ~leaseActive`). `scripts/run-apalache-partition.sh`
  runs `apalache-mc check --inv=<Inv> --length=8` for each and requires `NoError`; `_apalache-out/` is
  gitignored and the script uses a temp output directory so repeated runs stay clean. No Rust change.
- **Negative falsifiability + Apalache CI (SAFEP-05, SC3; `2c19b8d3f`):** three deliberately-broken
  model variants under `formal/tla/negative/`, each dropping exactly one guard from the clean model —
  `NoCapGuard.tla` (drops the `redeemedCount < BlastRadiusCap` guard in `Redeem`, VIOLATES
  `BlastRadiusNeverExceeded`), `NoExpiryGuard.tla` (drops the `clock < leaseExpiry` guard in `Redeem`,
  VIOLATES `NoRedemptionAfterExpiry`), `NoReceiptRequired.tla` (`IssueLease` sets
  `leaseHasReceipt := FALSE`, VIOLATES `OverrideRequiresReceipt`). `formal/tla/NEGATIVE.md` is the
  registry — the TLA+ analog of the phase-285 negative-test registry — and each row names the Rust
  runtime regression test pinning the identical defect: `NoCapGuard` ↔ swarm-policy
  `lease_redeem_fails_closed_on_mismatch_expiry_and_cap`; `NoExpiryGuard` ↔ swarm-policy
  `lease_can_redeem_denies_an_expired_lease`; `NoReceiptRequired` ↔ swarm-agents
  `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases` (all three verified to exist).
  `scripts/check-apalache-negatives.sh` proves both directions in one pass — the clean model's 4
  invariants hold AND all 3 negatives produce a genuine "state invariant violated" `Error` outcome —
  so a negative that stops violating (model drift) fails the check; it is non-vacuous by construction.
  A new, dedicated `apalache` job in `.github/workflows/ci.yml` (engine-path-gated, like the other
  engine-lane jobs) installs Java + Apalache 0.50.1 from the pinned GitHub release and runs both
  scripts. `check-gates-wired.sh` stays 0 — these are CI runners wired by their own job, not
  `tools/check-*.sh` gates that script enumerates.
- **Ledger close (this task, T4):** `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, and
  `.planning/STATE.md` updated to record Phase 294 complete, SAFEP-01..05 satisfaction, and — since
  this is the third and final v1.81 phase — the v1.81 Machine-Checked Decision Core milestone
  COMPLETE, with STATE.md's frontmatter and body reconciled so neither contradicts the other or
  REQUIREMENTS/ROADMAP, and the blocked state of the next roadmap work (296-299, open-agent-protocol)
  stated plainly rather than glossed as "not yet planned."

## Why SAFEP-02's rows are a separate table, not new invariant-table rows

`docs/assurance/MAPPING.md`'s existing invariant table is exactly what `tools/check-mapping.sh`
enforces: every row's `Name` must resolve to a real `crate::module::function` path AND that path must
carry a `// INVARIANT: <Name>` marker, and `tools/check-negative-registry.sh` in turn requires a
`[negative.<Name>]` falsifiability entry for every such `Name`. Three of P1–P6 (P3, P4, P5) name
symbols — `ContingencyLease::verify`, `lease_redeem`, `governance_quorum_threshold` — that carry
neither today. Adding them as literal rows in the gate-checked table would have forced six brand-new
markers and six brand-new `negative_*.rs` tests into this task's scope, which is exactly the
TLA+-level falsifiability work Task 3 (SAFEP-05) does instead, at the state-machine level rather than
the function level. So P1–P6 are recorded as a distinct, named `Property`-headed list — documented
the same way the pre-existing Loom section already is — that cites the same symbols and harnesses
`formal/PROPERTIES.md` names, and cross-references the invariant table's `Name`s only where one
genuinely already exists. `check-mapping.sh`'s table parser looks for the first table whose header
starts with the literal column `Name`; a table headed `Property` is invisible to it by construction,
not by omission — confirmed directly: the gate reports the same 17 rows / 17 markers before and after
this commit.

## Task authorship note

Task 1 was implemented by a subagent and independently verified by the controller (worktree-sharing
hazard noted and resolved: three of Task 2's files appeared mid-task in the same working tree; Task 1's
implementer correctly left them untouched and committed only its own three intended paths, confirmed
by `git diff --stat` on the resulting commit). Tasks 2 and 3 — the TLA+ model and its negative variants
— were authored directly by the controller rather than dispatched to a subagent, since both are
specialized, iterative TLA+/Apalache work where a subagent-review round-trip would have added latency
without adding scrutiny the controller could not perform itself; both were self-verified by running
the real `apalache-mc check` end to end (not just reading the model) before being counted done. One
authoring lesson recorded for the record: never `sed`-transform a `.tla` file to produce a negative
variant — a stray edit broke the module's comment header once, producing a TLA+ parse error that
looked like a genuine invariant violation until inspected; each negative variant was instead written
as a clean, independent heredoc from the start.

## Final verification (this task, on the closing tree)

- `bash tools/check-mapping.sh` — `check-mapping: OK 17 row(s) 17 marker(s)`, exit 0.
- `bash tools/check-negative-registry.sh` — `check-negative-registry: OK`, exit 0.
- `bash tools/check-gates-wired.sh` — every gate script wired into a workflow, exit 0 (30 gate scripts
  across 6 workflows, including the pre-existing set; the `apalache` job is a CI runner, not one of
  the `tools/check-*.sh` gates this script enumerates).
- `cargo test -p swarm-policy` — 7 `test result: ok` blocks (39 lib tests, 1 manifest-completeness
  test, 3 negative-registry tests, 2 zero-test blocks for loom-under-non-loom and doc-tests), 0 failed
  anywhere — unchanged from Phase 293's close, since this phase touched no Rust source.
- `bash scripts/run-apalache-partition.sh` — all 4 named invariants `NoError`, exit 0.
- `bash scripts/check-apalache-negatives.sh` — the clean model's 4 invariants hold AND all 3 negatives
  (`NoCapGuard`/`NoExpiryGuard`/`NoReceiptRequired`) VIOLATE their respective invariant as required,
  exit 0. (Both Apalache scripts were run in full at this close, not skipped — they completed quickly
  enough not to need deferring.)
- `git diff --stat` for this close's commit — `.planning/` files only.

## v1.81 Machine-Checked Decision Core: COMPLETE

With Phase 294 closed, all three executable phases of v1.81 are done: **292** (Pure Decision Core
Extraction, `eb64f7c85`/`f5cb3d8df`/`49121d577`) carved the approval, severity, rate-limit, and lease
predicates into pure, clock-injected, mutex-free functions in `formal_core.rs`; **293** (Kani Bounded
Model Checking, `f0e2067b0`/`86cd1cc41`/`de0628490`/`df364bc94`) bounded-model-checked 14 properties of
that core (8 REAL + 6 MODEL-ONLY) in CI; **294** (this phase) named those guarantees as six falsifiable
properties, registered the two trust assumptions they lean on, and model-checked the highest-risk
concurrent protocol — the partition-contingency-lease state machine — in Apalache, with negative
falsifiability proving the checks are not vacuous. All fifteen requirements (DCORE-01..05, KANI-01..05,
SAFEP-01..05) are Satisfied. Phase 295 (Z3-Backed Promotion Gate) is not part of this count — it is an
orphan roadmap row superseded by Phase 322, whose ZGATE-01..05 requirements were satisfied in v1.78.1,
ahead of this milestone.

## Reconciliation ahead

With v1.81 complete, the next roadmap-numbered phase is 296 (Provenance Graph Substrate, opening
v1.82), but it is not unblocked the way 292 and 293 were when their predecessors closed. Phase 296
depends on v1.81 being complete (now true) AND on the user's call on whether to fold the held PR
#11/#5 hypothesis graph into it — a source-grounded integration decision that has been open since the
v1.79 close and was never a phase-numbered dependency to begin with. Separately, the open-agent-protocol
milestone has no `REQUIREMENTS.md` rows at all today — it needs design intent from the user before it
is even a numbered phase, not just an unblock. v1.81 completing is the natural point to take both back
to the user rather than guess a direction on either. `.planning/STATE.md` states this as a genuine
block, not as "the next phase is simply not yet planned."

## Notes

- This phase changed zero Rust source and zero Rust behavior; every SAFEP requirement is documentation,
  a TLA+ model, or CI wiring over already-existing, already-proved decision-core logic. The Rust test
  suite for `swarm-policy` is byte-for-byte unchanged in pass/fail shape from Phase 293's close.
- Full session ledger: `.superpowers/sdd/294-01-PLAN/progress.md`, `task-1-report.md`.
