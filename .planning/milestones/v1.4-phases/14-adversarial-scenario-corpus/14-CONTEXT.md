# Phase 14: Adversarial Scenario Corpus - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Expand the offline replay corpus from standalone scenarios into a named adversarial suite with scenario metadata. The result should stay Rust-first, repo-owned, and executable through the existing replay harness instead of inventing a separate red-team subsystem.

</domain>

<decisions>
## Implementation Decisions

### Corpus Shape
- Keep tracked scenarios in `scenarios/` and add explicit metadata to each manifest instead of moving the corpus into a new format.
- Add named suite manifests under `scenario-suites/` so operators can execute one curated adversarial corpus without scanning the whole directory.
- Treat benign controls as first-class suite members so later candidate experiments can measure false positives against the same corpus.

### Execution Path
- Reuse `DefaultReplayHarness` for suite execution instead of introducing a second harness.
- Keep suite output as an aggregate replay report with per-scenario status plus technique-group rollups.
- Keep everything offline-only and deterministic; suite execution still uses `detect_only` and `SandboxExecutor`.

### Metadata
- Scenario manifests now carry `class`, `campaign`, `techniques`, and `tags`.
- Suite manifests carry `corpus_version` plus suite-level campaign and technique metadata.
- Technique IDs are surfaced directly in operator-readable suite output so later experiment reports can attribute regressions cleanly.

</decisions>

<specifics>
## Specific Ideas

The existing replay contract already knows how to execute one manifest and one directory. The missing piece is a repo-owned middle layer: explicit suite manifests that point at tracked scenarios and preserve adversarial metadata all the way into the rendered report.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/milestones/v1.3-phases/12-deterministic-replay-harness/12-01-SUMMARY.md`
- `.planning/milestones/v1.3-phases/13-evaluation-and-regression-gates/13-01-SUMMARY.md`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/EVOLUTION.md`
- `scenario-suites/`
- `scenarios/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DefaultReplayHarness` already executes tracked scenarios deterministically and persists durable replay-run bundles.
- `ReplaySuiteReport` already exists conceptually from directory-wide evaluation and can be extended to carry richer metadata.
- The tracked scenario corpus already exercises both suspicious and benign flows.

### Established Patterns
- Repo-owned YAML manifests are the preferred operator and CI contract.
- Offline workflows should remain CLI-first and serializable.
- New review surfaces should layer on the replay harness instead of bypassing it.

### Integration Points
- Extend `ReplayScenarioManifest` with metadata.
- Add `ReplaySuiteManifest` loading in `crates/swarm-runtime/src/replay.rs`.
- Extend `swarmctl replay-evaluate` with `--suite`.

</code_context>

<deferred>
## Deferred Ideas

- Automatically synthesizing new adversarial scenarios
- Live red-swarm execution
- Promotion or governance logic for detectors

</deferred>

---
*Phase: 14-adversarial-scenario-corpus*
*Context gathered: 2026-04-03*
