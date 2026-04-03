# Phase 13: Evaluation And Regression Gates - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn the replay-run bundle format from Phase 12 into a practical regression gate: operators should be able to evaluate one run or the whole tracked scenario corpus, and local or CI verification should fail when expectations or latency thresholds regress.

</domain>

<decisions>
## Implementation Decisions

### Gate Shape
- Build on the replay bundle format that already stores expectations and latency snapshots.
- Keep the operator entrypoint in `swarmctl`; do not add a separate evaluation binary.
- Add one suite-level report for tracked scenarios so CI can use a single command.

### Verification Strategy
- Back the gate with an automated test that evaluates the tracked `scenarios/` directory against the canonical repo config.
- Make the CLI exit nonzero when any replay evaluation fails.
- Keep reports readable enough to debug detector, policy, or incident drift without opening raw JSON.

### Scope Control
- Stay focused on offline evaluation only.
- Do not add detector promotion or adaptive policy behavior.
- Treat the tracked scenario corpus as the canonical regression baseline for this milestone.

</decisions>

<specifics>
## Specific Ideas

Phase 12 already introduced single-scenario evaluation primitives. Phase 13 should package them into one suite-level gate and make the tracked `scenarios/` directory executable as a regression contract.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/phases/12-deterministic-replay-harness/12-01-SUMMARY.md`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/CONFIGURATION.md`
- `scenarios/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ReplayEvaluationReport` already compares one replay run against expected outputs and latency thresholds.
- `DefaultReplayHarness` already knows how to load tracked scenarios and persist offline run bundles.
- The tracked scenarios already encode both suspicious and benign baselines.

### Established Patterns
- CLI commands should return concise human-readable output but keep JSON available.
- Repo-owned regression assets live in tracked YAML under `scenarios/`.
- Gating should be reproducible through code, not manual operator inspection.

### Integration Points
- Extend the replay module with suite-level directory evaluation and rendering.
- Extend `swarmctl replay-evaluate` so it can sweep a scenarios directory.
- Add a regression test that executes the real tracked scenario corpus through the default config.

</code_context>

<deferred>
## Deferred Ideas

- Historical run-to-run trend analysis
- HTML or TUI evaluation dashboards
- Automatic detector or policy mutation from regression outcomes

</deferred>

---
*Phase: 13-evaluation-and-regression-gates*
*Context gathered: 2026-04-03*
