---
phase: 14-adversarial-scenario-corpus
plan: 01
subsystem: replay-corpus
tags:
  - replay
  - adversarial
  - suites
one-liner: Named adversarial suites now execute through `swarmctl`, and tracked scenarios carry campaign, technique, and benign-vs-adversarial metadata.
requires:
  - 12-deterministic-replay-harness
  - 13-evaluation-and-regression-gates
provides:
  - scenario metadata across tracked replay manifests
  - named suite manifests under `scenario-suites/`
  - suite-level replay execution with technique-group rollups
affects: []
tech-stack:
  added: []
  patterns:
    - suite manifests composed from repo-owned scenario manifests
    - benign controls embedded inside adversarial corpora
    - technique-group rendering layered on top of suite evaluation
key-files:
  created:
    - scenario-suites/hellcat-office-v1.yaml
    - scenarios/pdf-lolbin-execution.yaml
    - scenarios/python-maintenance-benign.yaml
  modified:
    - crates/swarm-runtime/src/replay.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - scenarios/office-dropper-correlation.yaml
    - scenarios/benign-baseline.yaml
key-decisions:
  - "Keep tracked scenarios in `scenarios/` and add a separate `scenario-suites/` layer instead of overloading the scenario directory."
  - "Use suite execution as an extension of `replay-evaluate` rather than creating another binary."
  - "Include benign control traffic inside the suite so later candidate experiments can measure false positives against the same corpus."
patterns-established:
  - "Replay corpora should stay manifest-driven and attributable by technique."
requirements-completed:
  - RED-01
  - RED-02
duration: 35min
completed: 2026-04-03
---

# Phase 14: Adversarial Scenario Corpus Summary

**The replay corpus now has a named adversarial suite, richer scenario metadata, and a direct `swarmctl` path for suite execution.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T16:30:26Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments

- Extended `ReplayScenarioManifest` with class, campaign, technique, and tag metadata.
- Added named suite manifests plus suite-level replay reporting in `crates/swarm-runtime/src/replay.rs`.
- Extended `swarmctl replay-evaluate` with `--suite`.
- Added two new tracked scenarios: one adversarial PDF LOLBIN chain and one benign Python maintenance control.
- Added `scenario-suites/hellcat-office-v1.yaml` as the first tracked adversarial corpus.

## Decisions Made

- Named suites live beside scenarios instead of inside the tracked scenario directory.
- Technique-group rollups are rendered as part of suite output so operators can see corpus coverage without opening raw JSON.
- Benign controls stay inside the named corpus to prepare for offline false-positive analysis.

## Deviations from Plan

None.

## Issues Encountered

None beyond routine replay model refactoring.

## User Setup Required

Run the tracked suite:

```bash
cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --suite scenario-suites/hellcat-office-v1.yaml
```

## Next Phase Readiness

The named suite and metadata model are now ready for baseline-vs-candidate detector experiments.

---
*Phase: 14-adversarial-scenario-corpus*
*Completed: 2026-04-03*
