# Phase 196: Algorithmic Parameter Variant Generation - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 196 starts `v1.57` by teaching Kitten to generate bounded parameter
variants automatically from existing winning genomes. The boundary is candidate
generation only; measured fitness evaluation and generation-over-generation
reporting stay in Phases 197 through 199.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing genome, proposal, and mutation ownership already split into
  `swarm-evolution` rather than inventing a parallel experiment-spec format.
- Generate only bounded perturbation and crossover candidates from top
  performers so autonomous generation stays operator-auditable and compatible
  with the current safety and canary pipeline.
- Keep candidate generation deterministic enough to replay later by persisting
  the generation inputs and mutation choices alongside the produced variants.

</decisions>

<code_context>
## Existing Code Insights

- `swarm-evolution` already owns mutation, strategy-genome, proposal, canary,
  and promotion seams, so Phase 196 should extend those existing modules instead
  of widening runtime-side orchestration.
- The runtime already routes Kitten proposals through typed strategy-routing and
  queue review boundaries, so new algorithmic variants should still enter the
  same proposal lane.
- Existing replay, assurance, and evasion-corpus artifacts give later phases a
  measured evaluation seam; this phase should only prepare candidates for that
  loop.

</code_context>

<deferred>
## Deferred Ideas

- Measured catch-rate, false-positive, and latency fitness remain Phase 197.
- Generation-over-generation benchmark reporting remains Phases 198 and 199.

</deferred>
