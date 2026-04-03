# Phase 16: Experiment Reports And Offline Safety Gates - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn persisted detector experiment reports into practical offline safety gates. The output should explain not only that a candidate failed, but which scenarios, suites, or technique groups caused the failure.

</domain>

<decisions>
## Implementation Decisions

### Gate Semantics
- Start with three deterministic offline gates: known-bad coverage, false-positive delta, and detect-latency delta.
- Treat adversarial scenario misses as the known-bad coverage signal.
- Keep gate inputs manifest-driven and explicit rather than inferred from runtime history.

### Reporting
- Persist experiment lineage, corpus version, and score summaries with every report.
- Surface scenario regressions and technique regressions in the rendered CLI report.
- Keep pass/fail semantics in `experiment-evaluate` so operators and CI can use the same command.

### Documentation
- Document named suites, experiment manifests, result persistence, and failure semantics in `docs/CONFIGURATION.md`.
- Track one intentionally failing experiment manifest in the repo so the gate behavior remains concrete.
- Keep the milestone offline-only; no promotion, canary, or governance code is introduced here.

</decisions>

<specifics>
## Specific Ideas

Phase 15 already persists experiment reports. Phase 16’s job is to make those reports actionable: explicit gates, attributed regressions, and operator docs that explain the full replay suite to experiment result workflow.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/phases/15-candidate-strategy-evaluation/15-01-SUMMARY.md`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/CONFIGURATION.md`
- `experiments/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Experiment reports already persist baseline and candidate suite output.
- Suite reports already group scenarios by technique.
- The CLI already uses nonzero exits for replay evaluation failures.

### Established Patterns
- Persistent offline artifacts use a small file store plus stable IDs.
- CLI commands should remain the operator and CI interface first.
- Regression attribution belongs in the report, not in ad hoc console spelunking.

### Integration Points
- Extend comparison logic with explicit gate verdicts and attributed regressions.
- Render gate verdicts plus regression details in `render_experiment_report`.
- Update `docs/CONFIGURATION.md` with the end-to-end suite and experiment workflow.

</code_context>

<deferred>
## Deferred Ideas

- Z3 safety proof integration
- Shadow or canary rollout
- Promotion governance or rollback policies

</deferred>

---
*Phase: 16-experiment-reports-and-offline-safety-gates*
*Context gathered: 2026-04-03*
