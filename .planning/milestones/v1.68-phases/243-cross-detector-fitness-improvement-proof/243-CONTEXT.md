# Phase 243: Cross-Detector Fitness Improvement Proof - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 243 closes the milestone by proving that at least one non-process-tree
detector improves its measured autonomous fitness above a conservative baseline
through the shared benchmark harness.

</domain>

<decisions>
## Implementation Decisions

- Use the fileless-execution detector as the bounded proof target because it
  already has a conservative staged baseline fixture and meaningful threshold
  knobs for one-generation improvement.
- Reuse the benchmark report surface from Phase 242 instead of creating a
  detector-specific proof artifact format.
- Keep the milestone claim explicit: fileless execution is proven improved;
  behavioral anomaly and DNS exfiltration are benchmarkable but not yet claimed
  as improved in this milestone.

</decisions>

<code_context>
## Existing Code Insights

- [kitten_agent.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/kitten_agent.rs) now persists comparable baseline and generation metrics for all supported detector families.
- The staged conservative fileless fixture is enough to prove both measured fitness and catch-rate improvement in one bounded benchmark generation.

</code_context>
