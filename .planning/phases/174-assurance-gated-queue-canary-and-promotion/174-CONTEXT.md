# Phase 174: Assurance-Gated Queue, Canary, And Promotion - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 174 pushes the assurance policy into the live rollout ladder so queue acceptance, canary launch, and production promotion all fail closed when assurance requirements are not met.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing queue blocking-reason model and canary or promotion threshold surfaces instead of inventing a separate rollout gate service.
- Preserve exact assurance lineage on the rollout artifacts that were blocked so later review and waiver flows can reuse it.
- Keep fail-closed enforcement deterministic and artifact-backed rather than log-only.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-evolution/src/evolution.rs` already gates proposal acceptance and queue-to-canary handoff based on proof and blocking reasons.
- `crates/swarm-evolution/src/canary.rs` and `crates/swarm-evolution/src/promotion.rs` already have explicit fail-closed threshold logic and durable report artifacts.
- `crates/swarm-runtime/src/evolution_status.rs` already summarizes queue, canary, and proof state from durable artifacts, which is the right place to add assurance gate visibility.

</code_context>

<deferred>
## Deferred Ideas

- Signed operator waivers and exported assurance lineage belong to Phase 175.

</deferred>
