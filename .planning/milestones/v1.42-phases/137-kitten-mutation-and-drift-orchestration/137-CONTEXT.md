# Phase 137: Kitten Mutation And Drift Orchestration - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 137 introduces the first runtime-owned evolution agent. It needs to register a real `KittenAgent`, detect when detector quality is drifting, and advance a bounded multi-tick mutation state machine without exceeding the existing dispatcher timeout budget.

</domain>

<decisions>
## Implementation Decisions

### Keep Kitten Runtime-Owned, Reuse Evolution Harnesses
- `swarm-runtime` explicitly kept agent ownership in Phase 136, so `KittenAgent` should live alongside `WhiskerAgent`, `TomAgent`, `PounceAgent`, `StalkerAgent`, and `WeaverAgent`.
- The new agent should orchestrate existing `swarm-evolution` primitives instead of inventing parallel draft, mutation, or scorecard stores. Phase 136 already extracted those harnesses into a dedicated crate.

### Treat `Proposing` As Internal State In Phase 137
- `AgentRole::Kitten` and `SwarmAction::ProposeStrategy` already exist, but the dispatcher still logs `ProposeStrategy` as unhandled.
- Phase 139 owns the actual safety-gated submission and canary handoff path (`KITTEN-04`, `SAFETY-01-03`), so Phase 137 should reach a durable `Proposing` state without relying on dispatcher routing that does not exist yet.

### Add Repo-Owned Evolution Config Before Adding Agent Logic
- `SwarmConfig` currently has no `evolution` block, which means there is nowhere to define drift thresholds, minimum observation windows, cooldowns, or mutation batch sizing.
- Phase 137 needs a minimal config seam first so the agent can be enabled and tuned from repo-owned YAML instead of hard-coded values.

### Drift Must Be Derived From Available Truth Signals
- The runtime already has live findings, strategy memories, scorecards, and verification-drift pressure artifacts, but it does not have a generic live ground-truth oracle for detection-rate or false-positive-rate drift.
- The first implementation should therefore anchor drift to durable evidence the repo already owns: scorecard outcomes, strategy memories, and replay-backed verification deltas, rather than inventing unsupported live labels.

</decisions>

<code_context>
## Existing Code Insights

### The Swarm Role And Action Types Already Reserve Space For Kitten
- `AgentRole::Kitten` already exists in `crates/swarm-core/src/agent.rs`.
- `SwarmAction::ProposeStrategy` already exists in `crates/swarm-core/src/types.rs`, but `AgentDispatcher::apply_actions()` still treats it as an unhandled warning path in `crates/swarm-runtime/src/dispatcher.rs`.

### Serve-Mode Agent Registration Has No Evolution Hook Yet
- `crates/swarm-runtime/src/bin/swarm_detect.rs` currently registers `Whisker`, `Tom`, `Pounce`, and optional `Stalker`/`Weaver`, but never registers a Kitten agent.
- That means Phase 137 needs both the agent implementation and the serve-mode wiring.

### Evolution Building Blocks Already Exist In `swarm-evolution`
- `drafting.rs`, `mutation.rs`, `selection.rs`, `evolution.rs`, and `strategy.rs` already provide durable stores and harnesses for drafts, mutation batches, proofs, rankings, selections, scorecards, and rollout memory.
- Those harnesses are the natural substrate for Kitten orchestration in later phases, and Phase 137 should build on them instead of duplicating file formats or IDs.

### No Evolution Config Exists Yet
- `SwarmConfig` in `crates/swarm-core/src/config.rs` currently exposes runtime, detection, pheromone, policy, canary, promotion, platform API, operator, and TLS settings, but no evolution section.
- Adding Kitten without config would force hard-coded thresholds and disable repo-owned control over drift and cooldown behavior.

</code_context>

<specifics>
## Specific Ideas

- Add `EvolutionConfig` plus nested drift settings to `SwarmConfig`, with validation covering thresholds, minimum observations, and cooldown windows.
- Implement a `ConceptDriftDetector` that consumes existing durable evidence windows and answers a simple `idle` / `drift_detected` decision plus next-eligible tick time.
- Implement `KittenAgent` with an internal multi-tick state machine (`AwaitingDrift -> Mutating -> Evaluating -> Verifying -> Proposing`) that advances one bounded step per tick and preserves intermediate state in memory for this phase.
- Register Kitten in `swarm_detect --serve` when evolution is enabled and add focused dispatcher tests proving the agent can run without tripping the 500ms timeout path.

</specifics>

<deferred>
## Deferred Ideas

- Population persistence, generation history, and replay-corpus fitness scoring belong to Phase 138.
- Safety verification and actual `ProposeStrategy` routing through the evolution queue and canary lane belong to Phase 139.
- SSE and CLI observability for the evolution subsystem belong to Phase 140.

</deferred>
