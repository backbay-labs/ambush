# Phase 116: Agent Safety Hardening - Context

**Gathered:** 2026-04-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the three agent-safety audit findings: unsigned pheromone deposits, missing tick timeout, and silently dropped dispatcher actions. Pure infrastructure hardening with no user-facing behavior changes.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — pure infrastructure phase. The audit findings define the exact changes needed:
- HARDEN-01: Sign deposits with agent keys, reject unsigned at substrate
- HARDEN-02: Wrap tick() in tokio::time::timeout(), mark Degraded on timeout
- HARDEN-03: Log structured warnings for unhandled SwarmAction variants

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `swarm-crypto` provides Ed25519 signing via `SigningKey` and `VerifyingKey`
- `PheromoneDeposit` already has `signature: Vec<u8>` and `agent_key: Vec<u8>` fields
- `AgentDispatcher` tick loop in `swarm-runtime/src/dispatcher.rs`
- `AgentHealth::Degraded` variant already exists
- `RuntimeSettings` struct in `swarm-core/src/config.rs`

### Established Patterns
- Agents return `Vec<SwarmAction>` from `tick()`
- Deposits go through `PheromoneSubstrate::deposit()`
- Health overrides tracked in dispatcher via `health_overrides` map

### Integration Points
- `WhiskerAgent` and `StalkerAgent` in `swarm-runtime/src/` create deposits
- `apply_actions()` in dispatcher processes returned actions
- `RuntimeSettings` loaded from `SwarmConfig` YAML

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase driven by audit findings.

</specifics>

<deferred>
## Deferred Ideas

- Arc-shared pheromone snapshots (performance optimization) — lower priority than correctness fixes
- Role shift authorization rules — not in current milestone scope

</deferred>
