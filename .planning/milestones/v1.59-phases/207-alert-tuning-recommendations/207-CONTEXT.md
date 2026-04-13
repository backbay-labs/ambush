# Phase 207: Alert Tuning Recommendations - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 207 turns the measured false-positive state from Phase 206 into bounded
advisory detector-tuning recommendations. The goal is operator guidance, not
automatic config mutation: Swarm should explain where host exclusions,
threshold changes, or detector-specific review would likely reduce noisy
alerts, while leaving the final tuning decision to operators.

</domain>

<decisions>
## Implementation Decisions

- Consume the normalized incident-backed false-positive measurements from Phase
  206 instead of re-scanning raw feedback audit payloads.
- Keep recommendation output advisory and repo-owned; do not write config
  changes, exclusions, or detector thresholds automatically in this phase.
- Surface the recommendation set through existing operator read paths so
  `swarmctl` and the platform API can present the same bounded advice.

</decisions>

<code_context>
## Existing Code Insights

- `swarm_spine::FalsePositiveMeasurement` now persists the latest signed
  analyst disposition per reviewed finding on correlated incidents.
- `summarize_false_positive_measurements` already produces bounded detector and
  host rollups for `OperatorStatusReport` and `PlatformRuntimeStatus`.
- `swarmctl status` and `GET /v2/api/runtime/status` now expose
  `false_positive_tracking`, making them the natural surfaces for tuning
  recommendations without inventing a second operator workflow.

</code_context>

<deferred>
## Deferred Ideas

- Automatic config patch generation or exclusion-list writes remain out of
  scope.
- Any broader analyst-quality scoring beyond the new false-positive
  measurements remains deferred.

</deferred>
