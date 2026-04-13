# Phase 205: Time-To-First-Detection Wizard - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 205 builds the first bounded onboarding walkthrough on top of the new
Phase 204 readiness contract. The goal is not a generic demo shell; it is one
operator-guided first-run flow that proves Swarm can inject synthetic
telemetry, produce a first detection, pass through the approval surface, and
export proof within a short install-time loop.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing demo replay, approval, and evidence paths instead of
  inventing a second onboarding-only execution lane.
- Make the wizard depend on the Phase 204 readiness report before any
  synthetic telemetry runs so first-run failure stays explicit and bounded.
- Keep the flow repo-owned and auditable: the wizard should record what step it
  is on and what artifacts it produced, not rely on operator memory.

</decisions>

<code_context>
## Existing Code Insights

- Phase 204 now provides one structured readiness report through `swarmctl`
  and the control surface, which Phase 205 can use as its gate into the guided
  walkthrough.
- The runtime already ships demo replay injection, approval-in-the-loop demo
  flow, and signed proof export paths that should be composed into one
  onboarding wizard instead of reimplemented.
- Review, approval, and evidence artifacts already have durable IDs and render
  surfaces, which gives the wizard a bounded way to hand operators from one
  onboarding step to the next.

</code_context>

<deferred>
## Deferred Ideas

- Analyst-derived false-positive scoring remains Phase 206 work.
- Concrete alert tuning recommendations remain Phase 207 work.

</deferred>
