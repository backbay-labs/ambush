# Phase 181: Recovery Drills And Durability Validation - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 181 proves backup, restore, upgrade, rollback, and durability behavior against the supported state roots established in Phase 180. The focus is repeatable recovery evidence for the shipped runtime PVC and the optional JetStream dependency, not generic Kubernetes disaster-recovery advice.

</domain>

<decisions>
## Implementation Decisions

- Treat the Phase 180 production profile as the supported topology baseline and explicitly compare it with the local-journal bootstrap topology where durability expectations differ.
- Reuse repo-owned runbooks, Helm values, and runtime validation flows instead of introducing a separate recovery toolchain.
- Persist recovery evidence in repo-owned artifacts or documents so later milestones can reference repeatable drills rather than narrative-only guidance.

</decisions>

<code_context>
## Existing Code Insights

- Phase 180 now defines the authoritative runtime state root at `/var/lib/swarm` and the optional JetStream dependency root at `/data`, which gives Phase 181 one concrete backup and restore boundary to validate.
- [DR-RUNBOOK.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/DR-RUNBOOK.md) already covers governance, JetStream loss, dead-letter disk-full, and policy blockage detection, but it does not yet provide repeatable backup, restore, upgrade, or rollback drills for the new supported packaging profile.
- `swarmctl validate` can already validate rendered config before and after recovery steps, which makes it a useful guardrail in the recovery workflow without adding new runtime code first.

</code_context>

<deferred>
## Deferred Ideas

- Capacity, SLO, and alert-baseline work remains Phase 182.
- Multi-operator authentication, approval attribution, and supported operator access remain Phase 183.

</deferred>
