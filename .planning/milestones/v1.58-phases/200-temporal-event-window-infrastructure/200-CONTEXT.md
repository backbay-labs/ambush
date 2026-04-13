# Phase 200: Temporal Event Window Infrastructure - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 200 starts once `v1.57` is closed and the roadmap advances to
multi-event sequence detection. The immediate boundary is not ATT&CK chain
matching yet. It is the shared bounded event-window substrate that later
sequence rules can query without widening the hot-path safety or memory
contract.

</domain>

<decisions>
## Implementation Decisions

- Keep the first step detector-agnostic: build a reusable sliding-window event
  buffer and predicate-matching seam before introducing sequence-specific YAML
  rules.
- Bound retention explicitly by config so the future sequence detector cannot
  grow memory without an operator-visible limit.
- Reuse existing telemetry event structures and runtime-owned detector wiring
  instead of inventing a parallel sequence-only ingestion format.

</decisions>

<code_context>
## Existing Code Insights

- Current detectors evaluate events independently through the `swarm-whisker`
  strategy interface, so multi-event detection needs a shared event-memory seam
  before a sequence rule engine can exist.
- Pheromone escalation, review, and platform surfaces already know how to
  consume detector findings, which means Phase 200 should stop at retaining and
  querying event windows rather than publishing new findings.
- The runtime now has stronger benchmark and evolution hygiene from `v1.57`,
  so the new sequence infrastructure should preserve that same bounded,
  fail-closed style.

</code_context>

<deferred>
## Deferred Ideas

- YAML-authored ATT&CK sequence rules land in Phase 201, not here.
- New scenario suites and chain-only ground truth land in Phase 202.
- Pheromone integration for partial and complete sequence matches lands in
  Phase 203.

</deferred>
