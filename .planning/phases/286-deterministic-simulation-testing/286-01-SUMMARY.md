# Phase 286 Plan 01 Summary

Deterministic Simulation Testing (v1.79). The assurance floor's second phase — where 285 made
"fail-closed" *auditable*, 286 proves **receipt-before-action ordering** and **no-double-dispatch**
survive adversarial scheduling and mid-operation crashes, not only the happy path. A seeded,
deterministic fault-injection harness drives the REAL `SwarmRuntime::authorize_and_execute`, a real
approval gate, and the real pheromone substrate — no mocks — and asserts three oracles over every
seed, naming any failing seed for one-command replay. Executed 2026-09-07 with
subagent-driven-development as a sequential pipeline (T1→T5). The phase adds NO production behaviour
change — it is a test harness, a CI workflow, and a MAPPING.md section.

## Delivered

- **The harness foundation + the ground truth (DST-01, DST-05; 761a65bdc, nit 0b8b8f45b):**
  `crates/swarm-runtime/tests/dst_fault_injection.rs` — a hand-rolled deterministic single-thread
  executor (a manual `poll` loop with a no-op waker; no wall clock, no OS entropy, no tokio), the
  real no-mock stack (a real `SwarmRuntime` over a real recording `ResponseAdapter`, a real
  `StaticApprovalGate` with a deterministic verdict, a real `InMemoryPheromoneSubstrate`), the
  episode, and `SWARM_DST_SEED=<n>` replay. **The load-bearing finding:** the engine has NO atomic
  dispatch→receipt journal — `authorize_and_execute` (at `lib.rs:972`; DST-01's `:753` was stale)
  dispatches the response and returns the receipt, and persistence is the *caller's* responsibility
  (response-receipt writes live in `sphinx_agent`/`escalation`/`strategy`/`held_action`, not in the
  authorize path). So the harness composes dispatch + its own real substrate deposit, and
  receipt-before-action is proven as a *correct-caller-composition* property with the no-journal gap
  named as the evidence boundary.
- **The three fault classes (DST-02; bd9f5b251):** future-drop before dispatch, future-drop after
  dispatch but before receipt-persist, and substrate close/reopen between policy-allow and persist —
  each fires at a REAL boundary. A `BudgetedPoll::Exhausted` primitive hands the future back alive so
  a class either drops it (crash simulation) or acts on the world and resumes it (the close/reopen
  class). The recording adapter's async dispatch-boundary checkpoint pins the poll budget to the
  intended boundary *by construction* (verified: `authorize_and_execute` has exactly one `.await`),
  not by lucky poll counts.
- **The three oracles + the 64-seed PR corpus (DST-03, DST-04 PR half; d7d03b868, fix 9925a7e2e):**
  Oracle 1 (receipt-before-action) is **multiset containment** — the multiset of dispatch identities
  `(hunt_id, order)` carried by persisted receipts must be contained in the multiset actually
  dispatched, forbidding a phantom *and* a duplicated audit record (the dangerous direction) while
  leaving class (b)'s honest action-without-receipt green as the boundary. Oracle 2 (exact
  disposition) compares the outcome to the real gate's verdict (Allow *and* Deny both positively
  exercised). Oracle 3 (no double-dispatch) holds the at-most-once count. The 64-seed corpus runs on
  every PR, exercises all four fault classes, and names the failing seed; each oracle is proven
  non-vacuous by a forced violation.
- **The nightly deep corpus + the evidence boundary (DST-04 nightly, DST-06; fb80d8a90):** an
  `#[ignore]`-d `dst_nightly_deep_corpus_...` test runs the same oracles + per-seed episode over a
  fixed 5,000 seeds (so ">= 5,000" is unconditional), driven by `.github/workflows/dst-nightly.yml`
  (the repo's first scheduled workflow: nightly cron + `workflow_dispatch`, single-threaded,
  timeout-guarded). `docs/assurance/MAPPING.md` gains a DST harness section stating the evidence
  boundary (single-process, single-substrate-instance, NOT distributed JetStream failover) and the
  no-journal honesty. Verified green: 5,000 seeds, all four fault classes, 3.54s.

## Success criteria (mirror ROADMAP)

1. **Real harness, real gate, real substrate, no mocks** — met: 761a65bdc.
2. **≥3 fault classes at the named injection points** — met: bd9f5b251, all three at real boundaries.
3. **64-seed PR corpus + 5,000-seed nightly, naming the failing seed** — met: d7d03b868 (PR corpus +
   three non-vacuous oracles) + fb80d8a90 (`dst-nightly.yml`, 5,000-seed deep corpus, verified green).
4. **`SWARM_DST_SEED` replay + MAPPING evidence boundary** — met: 761a65bdc (`SWARM_DST_SEED`) +
   fb80d8a90 (MAPPING single-process/single-substrate boundary).

## Notes

- **The engine makes no receipt-before-action guarantee — and that honesty is the point.** There is
  no atomic journal binding dispatch to a persisted receipt, so a crash after dispatch but before
  persist legitimately splits action from receipt. Rather than assert a guarantee the engine does not
  make, Oracle 1 asserts only the safe, always-held direction (no phantom or duplicated audit
  record), and the MAPPING.md section names the action-without-receipt gap as the evidence boundary.
  DST discovers and encodes the *real* contract, it does not presume correctness.
- **DST-01's line ref (`lib.rs:753`) was stale** — `authorize_and_execute` is at `lib.rs:972` at
  HEAD; the harness targets it by name. Requirement text kept verbatim (the 285/291 path-slip
  convention).
- **No production code changed:** the diff is confined to `crates/swarm-runtime/tests/`,
  `.github/workflows/`, and `docs/assurance/` — 0 edits under any crate's `src/`.
- **The harness's "receipt persist" repurposes a real, signed `PheromoneSubstrate::deposit`** as its
  persistence step (pheromone deposits are domain-modeled as threat indicators, not response
  receipts) — a harness convention exercising the real substrate, not a claim that a literal
  production receipt-persistence path exists today. Stated plainly in the MAPPING.md section.
- **v1.79 "Assurance Foundation" progress:** Phase 284 (fixture determinism), 285 (assumption
  registry), and 286 (this) are complete; Phase 287 (fuzz, loom, supply-chain hardening) remains.
