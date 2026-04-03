---
phase: 16-experiment-reports-and-offline-safety-gates
plan: 01
subsystem: experiment-gates
tags:
  - replay
  - experiments
  - gates
  - docs
one-liner: Offline detector experiments now persist lineage and score summaries, expose explicit gate verdicts, and attribute regressions by scenario or technique group.
requires:
  - 15-candidate-strategy-evaluation
provides:
  - explicit offline gate verdicts for detector experiments
  - persisted lineage, corpus version, and score summaries
  - operator docs for named suites and experiment workflows
affects: []
tech-stack:
  added: []
  patterns:
    - pass/fail experiment manifests tracked in the repo
    - gate verdicts rendered alongside stored experiment reports
    - suite metadata used to attribute detector regressions
key-files:
  created:
    - experiments/office-python-parent-broadening.yaml
  modified:
    - .gitignore
    - crates/swarm-runtime/src/replay.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Use adversarial scenario misses as the first known-bad coverage signal."
  - "Keep gate verdicts manifest-driven and explicit instead of inferring tolerance from historical runs."
  - "Track one intentionally failing experiment in the repo as living documentation for nonzero exit behavior."
patterns-established:
  - "Offline detector changes should be explainable at the scenario and technique level before any future promotion workflow exists."
requirements-completed:
  - RED-03
  - EVO-03
  - EVO-04
duration: 30min
completed: 2026-04-03
---

# Phase 16: Experiment Reports And Offline Safety Gates Summary

**Detector experiments now behave like real offline gates: reports persist lineage and score summaries, `swarmctl` fails nonzero on threshold regressions, and the CLI output identifies the exact scenario or technique that regressed.**

## Performance

- **Duration:** 30 min
- **Completed:** 2026-04-03T16:30:26Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- Added explicit gate verdicts for known-bad coverage, false-positive delta, and detect-latency delta.
- Persisted lineage, corpus version, and comparison metrics in every experiment report.
- Surfaced scenario regressions and technique regressions in the rendered experiment output.
- Documented named suite and detector experiment workflows in `docs/CONFIGURATION.md`.
- Added `data/experiments/` to `.gitignore` and kept one failing broadened-parent candidate as a tracked manifest.

## Decisions Made

- Known-bad coverage is measured against adversarial scenarios in the tracked suite corpus.
- Nonzero exit behavior remains the operator and CI contract for failing offline gates.
- The broadened Python-parent experiment stays in the repo as a concrete example of a failing gate.

## Deviations from Plan

The persisted experiment store landed alongside the Phase 15 comparison work because it was the cleanest way to keep reports stable across reruns.

## Issues Encountered

Parallel `cargo run` verification briefly serialized on Cargo’s package cache lock, but all commands completed cleanly once builds finished.

## User Setup Required

Passing control experiment:

```bash
cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-baseline-control.yaml
```

Failing broadened candidate:

```bash
cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-python-parent-broadening.yaml
```

## Next Phase Readiness

`v1.4` is complete. The next milestone can build on this offline bench for richer operator review, formal verification, or promotion workflows without reopening the replay or experiment contracts.

---
*Phase: 16-experiment-reports-and-offline-safety-gates*
*Completed: 2026-04-03*
