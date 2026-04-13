# Phase 204: Readiness Diagnostic And Guided Setup - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 204 starts `v1.59` and focuses on operator onboarding rather than new
detector breadth. The first deliverable is a repo-owned readiness diagnostic
that can tell an operator whether telemetry connectivity, detector activation,
and substrate health are actually good enough to start a guided first run.

</domain>

<decisions>
## Implementation Decisions

- Build on existing control and health surfaces instead of inventing a second
  one-off readiness state machine.
- Keep the first phase diagnostic and read-only; the guided replay and tutorial
  flow belongs to Phase 205.
- Make detector activation explicit so onboarding can fail fast when operators
  misconfigure strategies or telemetry sources.

</decisions>

<code_context>
## Existing Code Insights

- The runtime already surfaces substrate health, bridge health, and detector
  config through the operator and ingest paths, which gives Phase 204 most of
  the raw ingredients for a readiness diagnostic.
- `swarmctl validate` already checks config shape, so the missing gap is live
  operational readiness rather than YAML syntax.
- The newly completed sequence milestone adds one more detector family and a
  shared temporal-window substrate, so onboarding should verify those runtime
  surfaces only when the chosen strategy set requires them.

</code_context>

<deferred>
## Deferred Ideas

- Guided synthetic first-run replay and walkthrough UX is Phase 205 work.
- Per-detector false-positive tracking and tuning recommendations remain Phases
  206 and 207.

</deferred>
