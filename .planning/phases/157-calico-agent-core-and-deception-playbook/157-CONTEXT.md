# Phase 157: Calico Agent Core And Deception Playbook - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 157 adds the first runtime-owned deception lane: a repo-configured `CalicoAgent` that can deploy baseline decoys and treat decoy interaction as high-confidence detection. Lifecycle persistence, Sphinx registration, and Kitten fitness feedback remain Phase 158.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing `ResponseAction::DeployDecoy` and routed `SwarmAction::RequestResponse` seam instead of inventing a second deception-execution path.
- Add a top-level repo-owned `deception` config section with a typed `DeceptionPlaybook` so decoy types, placement strategies, and monitoring rules live in YAML and validate fail closed.
- Keep Phase 157 focused on baseline deployment plus high-confidence interaction deposits; durable decoy lifecycle management and Sphinx/Kitten integrations are deferred to Phase 158.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-core/src/types.rs` already defines `ResponseAction::DeployDecoy`, so Calico can route through the same policy and runtime execution lane as existing response actions.
- `crates/swarm-runtime/src/bin/swarm_detect.rs` already has the identity-admission and optional-agent registration pattern used by Sphinx and is the right serve-mode seam for Calico.
- `crates/swarm-runtime/src/stalker_agent.rs` and `crates/swarm-runtime/src/sphinx_agent.rs` already show the signed direct-deposit pattern Calico should reuse for high-confidence pheromone publication.

</code_context>

<deferred>
## Deferred Ideas

- Deployed decoy inventory persistence and Sphinx knowledge-graph registration remain Phase 158.
- Feeding decoy-trigger signals into `KittenAgent` fitness remains Phase 158.
- New telemetry variants or dedicated deception sensors are not required for this phase; the agent will match monitored file paths, honeypot ports, and canary credentials against existing pheromone evidence.

</deferred>
