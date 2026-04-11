# Phase 138: Fitness Evaluation And Population Persistence - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 138 makes the new runtime evolution loop measurable and durable. Kitten can now produce validated candidates, but it still forgets them between cycles, has no restart-safe population state, and uses mutation ranking as a transient per-cycle artifact rather than a persisted evolutionary population.

</domain>

<decisions>
## Implementation Decisions

### Reuse Validation And Ranking Artifacts As Fitness Inputs
- Phase 137 already produces durable validation bundles, proofs, scorecards, and ranked mutation batches for every Kitten cycle.
- Phase 138 should build fitness and population state from those repo-owned artifacts instead of introducing a second evaluation format.

### Extend `SwarmConfig.evolution` Instead Of Adding A Parallel Fitness Config
- Evolution settings now exist in `SwarmConfig`, so fitness weights, population persistence paths, and proposal-rate throttles belong in that same config surface.
- Keeping the settings in one place avoids split ownership between runtime and extracted evolution crates.

### Persist Population As Repo-Owned Evolution State
- The extracted evolution modules already use file-backed JSON stores throughout the draft, mutation, validation, ranking, selection, and portfolio lanes.
- The lowest-risk Phase 138 implementation is another durable repo-owned evolution store for population and generation state, restored by Kitten on startup and updated after each completed generation.

### Keep Formal Safety And Canary Routing Deferred
- Phase 138 should evaluate, retain, and throttle candidates, but it should not own formal invariant verification or canary admission.
- Phase 139 still owns the safety gate and the real `ProposeStrategy` downstream routing contract.

</decisions>

<code_context>
## Existing Code Insights

### Kitten Already Produces Durable Candidate Evidence
- `crates/swarm-runtime/src/kitten_agent.rs` now materializes mutation batches, refreshes validation bundles, and emits ranked proposal candidates using the extracted evolution harnesses.
- The runtime already has enough durable artifacts to derive per-candidate fitness without re-running the entire mutation path from scratch.

### No Population Or Fitness Store Exists Yet
- There is still no population state, generation counter, replay-corpus fitness weighting, or per-hour proposal throttle in `swarm-runtime`, `swarm-evolution`, or `swarm-core`.
- A search across the current workspace shows no existing `fitness_weights`, `population`, `pareto`, or `max_proposals_per_hour` implementation to reuse directly.

### Mutation Ranking Is Per-Cycle, Not Cross-Generation
- `crates/swarm-evolution/src/mutation.rs` can rank one validation batch, but it does not retain a population across cycles or restarts.
- Phase 138 needs a cross-generation store and a stable update policy that Kitten can restore after restart.

### Restart Semantics Need Runtime Ownership
- Serve mode now registers Kitten as a real runtime agent, so restoring population and throttle state must happen inside runtime-owned Kitten initialization and tick handling rather than through an offline CLI path.

</code_context>

<specifics>
## Specific Ideas

- Extend `EvolutionConfig` with fitness weights, population sizing and persistence settings, and a `max_proposals_per_hour` throttle.
- Add a durable evolution population store in `swarm-evolution` or `swarm-runtime` that records generation number, candidate genomes, objective scores, last-proposed timestamps, and parentage.
- Teach Kitten to restore the persisted population on startup, fold completed validation batches into the population, run Pareto tournament selection over scored candidates, and enforce the proposal throttle before surfacing a new candidate.

</specifics>

<deferred>
## Deferred Ideas

- Formal safety invariants and optional Z3-backed proofs remain Phase 139 work.
- SSE and CLI status surfaces for the evolution subsystem remain Phase 140 work.

</deferred>
