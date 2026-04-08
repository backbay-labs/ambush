# Phase 126: TomAgent Governance - Research

**Date:** 2026-04-08
**Status:** Complete

## Key Findings

- `SwarmEnvironment` currently exposes pheromones, mode, and peer findings, but not agent-health summaries. TomAgent cannot satisfy TOM-01 without widening that environment contract.
- `AgentHealthEntry` is defined in `dispatcher.rs`, which is too low-level for cross-agent access. It needs to move into `swarm-core`.
- `SwarmAction::RoleShift` and `SwarmAction::HealthReport` currently target only the emitting agent because the dispatcher applies them using `completed.agent_id`.
- `PounceAgent` is the correct veto insertion point: it chooses actions synchronously inside `tick()` before the dispatcher reconstructs `ActionRequest`s.
- The existing runtime and operator surfaces can already query persisted bundles by receipt id, but only when `AuditTrail.response` contains a success or failure record. `Skipped` responses have no receipt id.

## Implementation Direction

1. Add governance runtime config for degraded-to-failed threshold.
2. Move `AgentHealthEntry` into `swarm-core`, add health summaries to `SwarmEnvironment`, and extend lifecycle actions to target explicit agents.
3. Add `TomAgent` plus shared `GovernancePolicy`.
4. Register TomAgent in serve mode and let it update governance state from dispatcher-visible health summaries.
5. Teach `PounceAgent` to consult `GovernancePolicy::can_act()` before emitting destructive actions.
6. Add a dedicated governance-veto routing path that records a synthetic, receipt-id-bearing veto artifact without calling the response executor.
7. Extend receipt audit metadata with governance provenance.

## Risks To Control

- Do not allow governance veto routing to call `authorize_and_execute()` under the hood; that would violate the phase’s synchronous pre-execution requirement.
- Avoid broad config fallout by placing the threshold under an existing config section with `serde(default)` behavior.
- Make targeted lifecycle actions explicit enough that old self-targeted role-shift behavior still works in tests and existing agents.
- Keep veto receipts queryable by receipt id so operator surfaces do not need a separate storage lane just for governance.
