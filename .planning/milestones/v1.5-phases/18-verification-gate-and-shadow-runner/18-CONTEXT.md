# Phase 18: Verification Gate And Shadow Runner - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn the repo-owned verification corpus into two persisted offline workflows: a candidate verification gate with per-invariant results, and a shadow report that compares baseline and candidate behavior over the same recorded replay corpus without emitting pheromones or response actions.

</domain>

<decisions>
## Implementation Decisions

### Verification Gate
- Reuse experiment manifests as the candidate entrypoint so lineage and detector settings come from one tracked file.
- Persist verification reports under a dedicated local store with stable IDs, mirroring replay-run and experiment stores.
- Model each invariant as explicit pass/fail output with preserved failing references or counterexamples.

### Shadow Runner
- Treat shadow as an offline baseline-vs-candidate comparison stage built on the same replay suite contract as the current experiment flow.
- Persist shadow reports separately from experiment reports so the promotion workflow can reason over a distinct artifact type.
- Keep shadow execution fully `detect_only`; no pheromone deposits or response actions are emitted.

### CLI And Failure Semantics
- Extend `swarmctl` with `verification-*` and `shadow-*` commands instead of mutating existing replay commands.
- Use nonzero exit codes for both failed verification and failed shadow gates so the commands are CI-safe.
- Update docs and `.gitignore` for the new stores as part of the same phase.

</decisions>

<specifics>
## Specific Ideas

The current experiment comparison already computes detection, false positives, and latency over the same suite. Phase 18 should keep that logic but wrap it in a persisted shadow artifact, while the new verification report focuses on invariant-level proofs and failing references.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/phases/17-verification-corpus-and-invariants/17-01-SUMMARY.md`
- `docs/EVOLUTION.md`

### Existing Code
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/CONFIGURATION.md`
- `experiments/`
- `verifications/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DefaultReplayHarness` already evaluates named suites deterministically in `detect_only` mode.
- Experiment reports already compute baseline-vs-candidate deltas and explicit gate verdicts.
- The replay module already has file-backed stores for replay runs and experiment reports.

### Established Patterns
- New offline workflows get repo-owned manifests plus stable-ID result stores.
- CLI commands print human-readable text or JSON and exit nonzero on failed gates.
- Persisted artifact stores maintain an index plus one JSON report per stable ID.

### Integration Points
- Extend `crates/swarm-runtime/src/replay.rs` with verification reports, shadow reports, and their stores.
- Extend `crates/swarm-runtime/src/bin/swarmctl.rs` with evaluate/result subcommands for both artifact types.
- Update `.gitignore` and `docs/CONFIGURATION.md` for `data/verifications/` and `data/shadows/`.

</code_context>

<deferred>
## Deferred Ideas

- Real Z3 or SMT proof objects
- Live shadowing against production runtime events
- Canary rollout and promotion approval

</deferred>

---
*Phase: 18-verification-gate-and-shadow-runner*
*Context gathered: 2026-04-03*
