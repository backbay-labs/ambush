# Phase 15: Candidate Strategy Evaluation - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a repo-owned offline experiment path that compares the production detector with one candidate detector against the same suite. The runtime should never mutate live configuration or hot-load the candidate into production.

</domain>

<decisions>
## Implementation Decisions

### Candidate Shape
- Keep the first candidate format narrow: one suspicious process-tree profile with configurable parent and child lists plus thresholds.
- Use repo-owned experiment manifests under `experiments/` instead of adding detector-editing flags to the CLI.
- Treat the production config as the baseline detector source of truth.

### Comparison Model
- Compare baseline and candidate over the same suite manifest, not the whole tracked directory.
- Compute coarse but useful metrics: adversarial detection rate, benign false positive rate, and max detect latency.
- Attribute regressions back to scenarios and techniques, not just aggregate counts.

### Persistence
- Persist experiment reports to a dedicated local store under `data/experiments/`.
- Keep result lookup in `swarmctl` so operators can reload an experiment by stable ID.
- Record lineage metadata in every experiment report so future offline evolution work has a durable audit trail.

</decisions>

<specifics>
## Specific Ideas

The suite work in Phase 14 already provides a stable replay corpus. Phase 15 should bind that corpus to candidate detector profiles so one command can compare baseline and candidate side by side without touching the live runtime config.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/phases/14-adversarial-scenario-corpus/14-01-SUMMARY.md`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-whisker/src/detector.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/EVOLUTION.md`
- `scenario-suites/`
- `experiments/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DefaultReplayHarness` already executes one suite deterministically.
- `SuspiciousProcessTreeDetector` is the only production detector today and is the correct candidate surface to profile first.
- CLI replay output already supports both human-readable text and JSON.

### Established Patterns
- Repo-owned manifests define offline operator workflows.
- Storage uses stable IDs plus a simple local index.
- Comparison tooling should stay offline-only and non-destructive.

### Integration Points
- Extend `swarm-whisker` with a serializable detector profile.
- Extend `crates/swarm-runtime/src/replay.rs` with experiment manifests, comparison reports, and persistence.
- Extend `swarmctl` with `experiment-evaluate` and `experiment-result`.

</code_context>

<deferred>
## Deferred Ideas

- Automatic mutation or search over candidate space
- Shadow or canary deployment
- Z3 integration for detector promotion

</deferred>

---
*Phase: 15-candidate-strategy-evaluation*
*Context gathered: 2026-04-03*
