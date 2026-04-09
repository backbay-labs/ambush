---
gsd_state_version: 1.0
milestone: v1.46
milestone_name: Distributed Governance
current_phase: 153
current_phase_name: Consensus Protocol Core
status: phase_defined
last_updated: "2026-04-09T19:00:00Z"
last_activity: 2026-04-09 — v1.46 activated after v1.45 completion
progress:
  total_phases: 4
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-09)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** v1.46 Distributed Governance — phases 153-156 defined, ready for planning

## Current Position

Phase: 153 Consensus Protocol Core
Current Phase: 153
Current Phase Name: Consensus Protocol Core
Status: Phases 153-156 defined for v1.46; planning not yet started
Last activity: 2026-04-09 — v1.46 activated after v1.45 shipped
Total Phases: 4
Total Plans in Phase: 0

Progress: [..........] 0%

## Memory

- v1.38 shipped CompositeDetector, NetworkConnectDetector with C2 beaconing and threat-intel enrichment, cross-strategy distinct-source escalation, and multi-strategy integration proof.
- `AgentDispatcher::apply_actions()` now routes `RequestResponse` through a type-erased runtime seam, and request-response peer findings publish `scope=...` metadata for live dedupe visibility.
- Research confirmed TomAgent veto must be synchronous inside PounceAgent's tick (before `execute()`), not a post-hoc deposit; the `Arc<GovernancePolicy>` shared ref is the design anchor.
- Phase 126 implemented `TomAgent`, shared `GovernancePolicy`, synchronous destructive-action veto in `PounceAgent`, and synthetic governance-veto receipts routed through the dispatcher/runtime seam.
- `ConfigurableApprovalGate` must default to deny on empty or parse-error ruleset — fail-open here is a security defect.
- De-escalation lands in Phase 124 (not Phase 126) so PounceAgent is never permanently stuck in elevated mode from day one.
- Phase 124 proved dispatcher-owned autonomous routing, fail-closed lease expiry, and cooldown de-escalation across `swarm-core`, `swarm-policy`, and `swarm-runtime`.
- Phase 125 proved repository-owned YAML policy rules, static scope burst limiting, configured runtime gate wiring, and durable rule attribution across logs, audit trails, and successful receipts.
- Phase 126 package re-verification stayed green after the repo-owned `office_detector_safety_v1` detect-latency budget was aligned with the current debug-test runtime envelope.
- Phase 127 added routed proofs for same-session dedupe, fail-closed empty rules, auditable expired-lease denial, and cooldown reset without regressing dry-run parity, audit lineage, or governance veto coverage.
- The v1.39 lifecycle is complete: requirements and audit are archived in `.planning/milestones/`, and phase directories `124` through `127` now live in `.planning/milestones/v1.39-phases/`.
- v1.39 research is archived in `.planning/milestones/v1.39-research/` so the live `.planning/research/` folder is clean for v1.40-specific work.
- v1.40 scope is anchored to the queued demo and Providence requirements already captured in `.planning/REQUIREMENTS.md`.
- v1.40 phases are now defined: 128 replay plus SSE backbone, 129 live dashboard, 130 approval plus proof export, 131 Providence delivery.
- Phase 128 is complete: `runtime.demo_mode` now gates `POST /v1/demo/replay`, runtime events flow through a shared broadcaster, and `GET /v1/events/stream` emits typed filtered SSE for downstream demo surfaces.
- Phase 129 is complete: the review home page now boots a live demo dashboard from `GET /v1/demo/dashboard`, subscribes to runtime SSE, and shows swarm mode, agent health, concentrations, and a live timeline in one operator-facing surface.
- Phase 130 is complete: demo replay can pause on `RequireHuman`, operator approval votes resume paused actions through the runtime, and `GET /v1/demo/proof` exports the signed approval chain plus timeline and incident context.
- Signed approval votes bind `voter_id` to the signer-derived `swarm:ed25519:...` identity, so approval-eligible operator IDs must match that signer identity for end-to-end quorum to succeed.
- Phase 131 is complete: `providence_webhook` now emits Providence-shaped finding payloads with absolute Swarm drilldown links, live runtime state, and bridge-health summary via the existing notification router.
- Package-level verification surfaced and cleared an unrelated brittle portfolio fixture ordering assumption, restoring `cargo test -p swarm-runtime` to green on the current tree.
- The v1.40 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `128` through `131` now live in `.planning/milestones/v1.40-phases/`.
- v1.41 is complete with phases 132-136 covering the platform API, deployment experience, serve-surface hardening, crate extraction, and structured tracing.
- The v1.43 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `141` through `144` now live in `.planning/milestones/v1.43-phases/`.
- Phase 132 is complete: the detect server now exposes authenticated `/v2/api/findings`, `/v2/api/incidents`, and `/v2/api/runtime/status` envelopes with scoped platform API keys, cursor pagination, and runtime-auth identity attached to request context for downstream logging.
- Phase 133 is complete: `/v2/api/assets/{host_id}/posture` now returns host-scoped pheromone posture plus active investigations and recent findings, and `/v2/api/stream/findings` now streams canonical `SwarmFindingEnvelope` SSE events from the live runtime.
- Phase 134 is complete: `swarmctl` now ships repo-owned `validate` and `init` deployment flows, and `deploy/helm/swarm-team-six/` now renders a probe-wired `swarm_detect --serve` deployment with secret mounts, persistent storage, and an optional NATS subchart.
- Phase 135 is complete: default detector construction is panic-free, demo proof export no longer uses `expect`, `/v2/api/*` now requires bearer plus scoped API-key auth, and both serve surfaces share optional TLS plus mTLS via `SwarmConfig.tls`.
- Phase 136 is complete: `swarm-evolution` and `swarm-cli` now exist as workspace crates, the hot path carries `trace_id` spans with optional OTLP export, and evolution validation reuses one replay evaluation for both experiment and shadow artifacts to avoid flaky control-path blocking.
- The v1.41 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `132` through `136` now live in `.planning/milestones/v1.41-phases/`.
- Phase 137 is complete: the runtime now has repo-owned evolution config, a durable-evidence concept-drift detector, a bounded `KittenAgent` state machine, serve-mode registration, and regression coverage for validation and proposal emission.
- Phase 138 is complete: evolution fitness now comes from repo-owned replay and verification artifacts, the candidate population persists across restart with Pareto survivor selection, and Kitten restores and throttles proposal-ready candidates through one durable state file.
- Phase 139 is complete: Kitten proposals now route through repo-owned formal safety invariants, durable selection review state, and real canary handoff instead of a warning-only dispatcher branch.
- Phase 140 is complete: evolution status now comes from durable population, selection, canary, and Kitten-state artifacts, emits over SSE as `evolution_status`, and is visible through both `swarmctl status` and `swarmctl evolution status`.
- The v1.42 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `137` through `140` now live in `.planning/milestones/v1.42-phases/`.
- Phase 141 is complete: Sphinx now exists as a real runtime-owned agent with a file-backed typed knowledge graph, repo-owned memory config, restart-safe graph persistence, and serve-mode registration behind `memory.enabled`.
- Phase 142 is complete: Sphinx now answers signed memory-query pheromones with Q-value-style retrieval results, Kitten can enrich proposal fitness from those answers, and replay-only fallback remains bounded when memory is unavailable or sparse.
- Phase 143 is complete: Sphinx now enforces repo-owned knowledge retention with stale bundle-file cleanup, and the runtime owns a deterministic `RedSwarmAdapter` plus `MockRedSwarm` seam backed directly by `scenario-suites/` manifests.
- Phase 144 is complete: Kitten now freezes one adversarial corpus snapshot per generation, applies red-side pressure after replay and memory fitness, persists durable `EvolutionEpisode` history, and surfaces corpus plus best-genome status through the existing evolution status lane.
- Phase 145 is complete: runtime agents now persist one Ed25519 seed per slot under repo-owned `identity.agent_key_dir`, serve mode reuses those keys across restart, runtime-facing serve identities derive as `swarm:ed25519:<hex>`, and signed deposits now bind explicit `agent_identity` plus `agent_role` metadata into the canonical signature payload.
- Phase 146 is complete: serve mode now admits persisted identities through a durable registry, governance actions fail closed for unadmitted agent IDs, and `swarmctl identity rotate` persists continuity proofs plus retired-key history for historical verification.
- Phase 147 is complete: the shared telemetry schema now includes infrastructure health, thermal anomaly, and resource-exhaustion events, the repo owns Sentinel bridge config, and `BridgeRuntimeRegistry` can run Sentinel through the same health and metrics path as other bridges.
- Phase 148 is complete: `InfrastructureAnomalyDetector` now turns the Sentinel infrastructure lane into live execution, impact, and defense-evasion findings, and infrastructure plus behavioral execution signals can converge through the existing distinct-source escalation path.
- Phase 149 is complete: Providence delivery now uses a shared `SwarmProvidenceWebhookContract`, `providence_webhook` can sign canonical JSON with `X-Swarm-Signature`, and both Providence bearer and HMAC secrets resolve through the existing `@secret:` config path.
- Phase 150 is complete: correlated incidents now persist generic Providence external references, a dedicated `ProvidenceIncidentAdapter` owns signed create/update/resolve lifecycle sync with retry and dead-letter, and `/healthz` plus `/readyz` now expose Providence reachability/auth/write health.
- Phase 151 is complete: signed Providence analyst feedback now lands on `POST /v1/providence/feedback`, persists durable incident-linked audit evidence, and forwards false-positive dismissals into Kitten or pending durable storage.
- Phase 152 is complete: Providence can now embed `/v1/demo/widget`, consume scoped runtime SSE, and open read-only findings/incidents drilldowns through short-lived signed context tokens.
- The v1.45 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `149` through `152` now live in `.planning/milestones/v1.45-phases/`.

## Issues

- None active. v1.46 phases defined; ready for planning.

## Next Command

`/gsd:plan-phase 153`
