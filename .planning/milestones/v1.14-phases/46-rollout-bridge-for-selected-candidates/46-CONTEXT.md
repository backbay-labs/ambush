# Phase 46 Context

## Goal

Let accepted ranked-candidate selections feed the existing handoff and canary path using preserved evidence instead of re-materializing candidate manifests.

## Inputs

- Phases 44-45 now persist stable ranked-candidate selections plus explicit operator review decisions.
- The runtime already ships queue, handoff, and bounded canary workflows for accepted proposals.
- The missing seam was a fail-closed bridge that could convert one accepted selection back into that existing rollout ladder.

## Constraints

- Keep bridge creation operator-triggered and conservative.
- Reuse preserved experiment, validation, proof, advisory, and shadow references.
- Fail closed on blocked or stale selections while still persisting inspectable bridge artifacts.
