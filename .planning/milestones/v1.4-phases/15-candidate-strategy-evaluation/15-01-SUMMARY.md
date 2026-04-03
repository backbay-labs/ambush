---
phase: 15-candidate-strategy-evaluation
plan: 01
subsystem: detector-experiments
tags:
  - replay
  - candidate
  - experiments
one-liner: Repo-owned detector experiments now compare baseline and candidate profiles offline, persist reports, and reload them by stable experiment ID.
requires:
  - 14-adversarial-scenario-corpus
provides:
  - serializable suspicious process-tree detector profiles
  - offline baseline-vs-candidate experiment reports
  - stable experiment lookup in `swarmctl`
affects: []
tech-stack:
  added: []
  patterns:
    - detector candidates declared as YAML manifests
    - experiment reports persisted to a dedicated local store
    - side-by-side suite comparison reusing the replay harness
key-files:
  created:
    - experiments/office-baseline-control.yaml
    - experiments/office-python-parent-broadening.yaml
  modified:
    - crates/swarm-whisker/src/detector.rs
    - crates/swarm-whisker/src/lib.rs
    - crates/swarm-runtime/src/replay.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
key-decisions:
  - "Keep the first candidate surface narrow: one configurable suspicious process-tree profile."
  - "Treat the repo config as the baseline detector and experiment manifests as candidate-only inputs."
  - "Persist experiment reports immediately so Phase 16 can reason over stable artifacts instead of rerunning every comparison."
patterns-established:
  - "Offline detector changes should enter the repo as manifests, not ad hoc flags."
requirements-completed:
  - EVO-01
  - EVO-02
duration: 40min
completed: 2026-04-03
---

# Phase 15: Candidate Strategy Evaluation Summary

**The replay harness now runs baseline-vs-candidate detector experiments from repo-owned manifests, persists the result, and reloads it by stable experiment ID.**

## Performance

- **Duration:** 40 min
- **Completed:** 2026-04-03T16:30:26Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Added `SuspiciousProcessTreeProfile` so candidate detector settings can be declared in YAML.
- Added experiment manifest parsing, comparison metrics, lineage capture, and durable experiment storage in `crates/swarm-runtime/src/replay.rs`.
- Added `swarmctl experiment-evaluate` and `swarmctl experiment-result`.
- Added one passing control experiment and one failing broadened-parent experiment.
- Added replay tests covering suite execution and experiment persistence or regression behavior.

## Decisions Made

- Candidate evaluation reuses the same suite-selection path as baseline evaluation.
- Experiment reports are stored separately from replay-run bundles under `data/experiments/`.
- The first comparison metrics stay scenario-level and technique-attributed instead of trying to model the full evolution system early.

## Deviations from Plan

The broadened-parent failing candidate was kept as a tracked manifest, not just a test fixture, because it is useful documentation for the false-positive gate semantics.

## Issues Encountered

One early compile pass failed on an `Eq` derive for a float-backed detector profile; removing that derive fixed the integration.

## User Setup Required

Run the control experiment:

```bash
cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-baseline-control.yaml
```

Reload the persisted report:

```bash
cargo run -p swarm-runtime --bin swarmctl -- experiment-result --experiment-id experiment:office_baseline_control:office_baseline_control
```

## Next Phase Readiness

Experiment persistence and comparison now exist, so the remaining work is to formalize the offline gate semantics and operator documentation.

---
*Phase: 15-candidate-strategy-evaluation*
*Completed: 2026-04-03*
