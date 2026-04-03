---
phase: 13-evaluation-and-regression-gates
plan: 01
subsystem: evaluation
tags:
  - replay
  - regression
  - ci
  - operators
one-liner: `swarmctl replay-evaluate` can now gate one replay run, one scenario, or the full tracked scenario corpus, and the runtime test suite executes the tracked scenarios as a regression baseline.
requires:
  - 12-deterministic-replay-harness
provides:
  - Suite-level replay evaluation over tracked scenarios
  - Nonzero CLI failure semantics for replay regressions
  - Executable repo-wide regression test over `scenarios/`
affects: []
tech-stack:
  added: []
  patterns:
    - tracked YAML scenarios as executable regression contracts
    - suite reports layered on top of single-run evaluation reports
    - CLI and test gates sharing the same replay harness
key-files:
  created:
    - .planning/phases/13-evaluation-and-regression-gates/13-CONTEXT.md
    - .planning/phases/13-evaluation-and-regression-gates/13-01-PLAN.md
  modified:
    - crates/swarm-runtime/src/replay.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "The tracked `scenarios/` directory is now the canonical offline regression corpus for this milestone."
  - "Suite-level evaluation stays in the existing `replay-evaluate` command instead of adding a second gate binary."
  - "The same replay harness powers both operator evaluation and the runtime regression test so drift is measured one way."
patterns-established:
  - "Repo-owned scenario directories should be directly executable as regression suites."
requirements-completed:
  - EVAL-01
  - EVAL-02
duration: 20min
completed: 2026-04-03
---

# Phase 13: Evaluation And Regression Gates Summary

**Replay evaluation is now a real gate: operators can evaluate one run or the entire tracked scenario corpus, and the runtime test suite executes the repo scenarios as an executable regression baseline.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-04-03T15:40:00Z
- **Completed:** 2026-04-03T15:59:49Z
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Extended `crates/swarm-runtime/src/replay.rs` with `ReplaySuiteReport`, directory-level scenario evaluation, and a regression test that executes the tracked `scenarios/` directory against the repo config.
- Extended `swarmctl replay-evaluate` so it can evaluate a single run, a single scenario, or the full tracked scenario directory, and fail nonzero when any gate fails.
- Documented the end-to-end replay and evaluation flow in `docs/CONFIGURATION.md`, including local or CI usage of `--scenarios-dir`.

## Decisions Made

- The tracked `scenarios/` directory is now the regression contract for this milestone.
- Suite output stays textual and concise by default, but JSON remains available for automation.
- The gate is intentionally offline-only; it does not mutate runtime policy or detector state.

## Deviations from Plan

None.

## Issues Encountered

Formatting had to be re-applied after adding the suite report paths, but there were no design or verification blockers.

## User Setup Required

To gate the tracked corpus locally or in CI:

```bash
cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --scenarios-dir scenarios
```

## Next Phase Readiness

`v1.3` is now complete. The next cycle can either deepen offline red-team or evolution work, or move toward richer operator surfaces, without reopening the replay contract.

---
*Phase: 13-evaluation-and-regression-gates*
*Completed: 2026-04-03*
