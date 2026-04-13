---
gsd_state_version: 1.0
milestone: v1.63
milestone_name: Evolution Crate Decomposition And Schema Migration
current_phase: none
current_phase_name: none
status: completed
last_updated: "2026-04-12T23:00:51Z"
last_activity: 2026-04-12 — Completed Phase 223 API response schema migration and closed v1.63 with no next milestone queued
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 4
  completed_plans: 4
  percent: 100
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-11)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** No active milestone. `v1.63 Evolution Crate Decomposition And Schema Migration` is complete, and the next milestone has not been defined yet.

## Current Position

Phase: none
Current Phase: none
Current Phase Name: none
Status: No active milestone; v1.63 is complete
Last activity: 2026-04-12 — Completed Phase 223 API response schema migration and closed v1.63 with no next milestone queued
Total Phases: 4
Total Plans in Phase: 0

Progress: [##########] 100%

## Memory

- Phase 223 is complete: operator-facing control and platform API envelopes
  now carry explicit `schema_version` metadata, both authenticated surfaces
  negotiate through the shared `x-swarm-schema-version` header, and `swarmctl`
  now validates `--output-schema-version` while preserving the current
  compatibility lane at schema version `1`.
- The v1.63 lifecycle is complete: milestone audit passed, roadmap and
  requirements snapshots are current, and phase directories `220` through
  `223` are archived under `.planning/milestones/v1.63-phases/`.
- Phase 222 is complete: `PheromoneDeposit` now carries an explicit shared
  `schema_version`, the substrate and JetStream hydration paths accept only the
  current and previous wire versions with explicit fail-closed rejection for
  unsupported versions, and repo-owned tests now prove both previous-version
  signature compatibility and local-journal recovery for legacy deposits that
  omitted the new field.
- Phase 221 is complete: `swarm-evolution/src/mutation.rs` is now a thin
  composition root over an extracted `mutation/` module tree with explicit
  `#[path]` wiring, shared internal helpers behind `pub(crate)` boundaries, and
  split unit coverage across `tests_core.rs` and `tests_autonomous.rs`; the
  focused extracted mutation suite passed 12 unit tests and every extracted file
  stayed below the 2000-line cap.
- Phase 220 is complete: `swarm-evolution/src/evolution.rs` is now a thin
  composition root over the extracted `evolution/` module tree, the public
  crate contract stayed stable through explicit re-exports, and the focused
  extracted test module passed 34 unit tests after the relocation-safe path
  fix for the moved `include_str!` fixture.
- Phase 219 is complete: the repo now ships a labeled-telemetry behavioral
  anomaly benchmark in `crates/swarm-runtime/examples/behavioral_anomaly_quality_benchmark.rs`
  with a checked-in artifact in `docs/benchmarks/behavioral-anomaly-quality.md`,
  and the measured reference run preserved catch rate at `1.000` while reducing
  actionable false-positive rate from `1.000` to `0.000` relative to the
  bounded legacy fixed-arithmetic control.
- The v1.62 lifecycle is complete: milestone audit passed, roadmap and
  requirements snapshots are current, and phase directories `216` through
  `219` are archived under `.planning/milestones/v1.62-phases/`.
- Phase 218 is complete: `BehavioralAnomalyDetector` now evaluates network, DNS, authentication, registry access, registry persistence, file persistence, and process memory telemetry through the same explicit deviation-scoring model, and the shared behavioral snapshot seam now persists per-family learned state for those non-process telemetry families.
- Phase 217 is complete: `BehavioralAnomalyDetector` now derives finding confidence from an explicit support-weighted z-score model built on the persisted per-scope novelty distributions, and finding evidence now exposes `deviation_scoring` with per-scope z-scores, sample support, and aggregate deviation score.
- Phase 216 is complete: `BehavioralAnomalyDetector` now persists per-scope online novelty distributions through the shared baseline snapshot seam, derives confidence from learned scope pressure instead of the old fixed signal-count arithmetic, and emits the learned-distribution state needed for the explicit deviation model now shipped in Phase 217.
- Phase 215 is complete: `ResponsePlaybookConfig` and `PounceAgent` now share deterministic rule-plus-branch resolution, `RuntimeService::playbook_preview` reuses the typed rehearsal and approval seams for dry-run projection, and `swarmctl playbook-preview` plus the control plane now expose one bounded repo-owned preview report without live side effects.
- The v1.61 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `212` through `215` now live under `.planning/milestones/v1.61-phases/`.
- Phase 214 is complete: repo-owned `pheromone.response_playbook` rules now support deterministic ordered branches with bounded selectors over threat class, severity, confidence, and runtime mode; Pounce records matched branch identity in request evidence and still routes the resulting actions through the normal guarded response lane.
- Phase 213 is complete: the expanded response action catalog now carries typed blast-radius, scope, and rollback metadata through the shared rehearsal seam, and rehearsal no longer fails closed for the new actions added in Phase 212.
- Phase 212 is complete: the shared response seam now supports fifteen concrete action types, policy and governance understand the expanded action catalog, sandbox and HTTP EDR route the new actions through the normal executor lane, and webhook now fails closed when asked to execute unsupported live actions.
- The v1.60 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `208` through `211` are archived under `.planning/milestones/v1.60-phases/`.
- Phase 211 is complete: repo-owned runtime tests now prove JetStream outage forces `detect_only`, replay-store write-path failure forces `read_only` with ingest rejection, and high heap pressure forces `emergency_drain` on `/readyz`.
- Phase 210 is complete: the runtime now owns an explicit degradation ladder with shared triggers, capabilities, transition timestamps, bounded ingest gating for `read_only` and `emergency_drain`, and the same degradation contract now surfaces on `/readyz`, `/healthz`, `swarmctl status`, and `/v2/api/runtime/status`.
- Phase 209 is complete: the dispatcher now owns per-agent restart factories, replaces only failed agents in-place once health crosses the failed boundary, keeps restarted agents degraded until a clean tick clears them, and `swarm_detect` now registers every runtime agent through the same reusable startup-and-restart construction path.
- Phase 208 is complete: the dispatcher now wraps each agent tick in a runtime-owned async panic boundary, preserves typed panic attribution with agent identity and role, degrades only the crashing agent, and keeps healthy peers ticking in the same run loop.
- The v1.59 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `204` through `207` are archived under `.planning/milestones/v1.59-phases/`.
- Phase 207 is complete: the runtime now derives bounded advisory alert-tuning recommendations from persisted false-positive measurements, and both `swarmctl status` and `/v2/api/runtime/status` surface the same `alert_tuning` report for operators.
- Phase 206 is complete: signed Providence analyst feedback now persists one bounded latest-disposition measurement per reviewed finding on incidents, `swarmctl status` now exposes recent detector and host false-positive rollups, and `/v2/api/runtime/status` carries the same `false_positive_tracking` report for operator API consumers.
- Phase 205 is complete: `swarmctl first-run` now reruns the repo-owned readiness gate, launches a sandboxed synthetic approval-gated replay, exports a signed receipt pack plus proof bundle, and returns one bounded walkthrough report with approval, incident, and proof identifiers.
- Phase 204 is complete: `swarmctl` now ships a structured readiness diagnostic backed by repo-owned telemetry, detector, and substrate checks, `swarmctl init` prints the readiness follow-up command, and `/readyz` now surfaces telemetry source summary alongside the existing detector and substrate health components.
- The v1.58 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `200` through `203` are archived under `.planning/milestones/v1.58-phases/`.
- Phase 203 is complete: sequence findings now reuse the normal signed pheromone, replay, investigation, and incident lanes, and the replay harness now attaches the configured sequence detector just like the live runtime service.
- Phase 202 is complete: the repo now ships three chain-only replay scenarios plus the `kill_chain_sequences_v1` suite, and focused runtime integration proof shows the shipped deterministic single-event detectors stay quiet on those chains.
- Phase 201 is complete: Swarm now loads ATT&CK kill-chain rules from repo-owned YAML in `sequences/kill-chain-v1.yaml` and emits bounded partial or full matches against the shared temporal window.
- Phase 200 is complete: the runtime now owns a bounded temporal event window with configurable retention, span, and predicate-count limits, and accepted telemetry is recorded into that window on the hot path before detection runs.
- Phase 199 is complete: the bounded benchmark now derives pressure from the staged seed experiment, `swarm-evolution` can materialize a bounded `autonomous_gap_expansion` recipe from focused evasion scenarios, and the checked-in benchmark artifact now records a real conservative-seed gain from measured fitness `0.633` / catch-rate `0.086` to `0.656` / `0.143`.
- The v1.57 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `196` through `199` are archived under `.planning/milestones/v1.57-phases/`.
- Phase 198 is complete: the repo now runs a bounded multi-generation autonomous benchmark through the normal mutation and validation seams, persists durable generation-over-generation fitness deltas plus latest benchmark status, and ships a checked-in benchmark artifact that records the current no-gain baseline for `suspicious_process_tree`.
- Phase 197 is complete: autonomous population candidates now persist measured catch-rate, false-positive, and latency fitness with replayable lineage, Kitten keeps that attribution runtime-owned through adversarial episode persistence, and the shared evolution status surface now exposes the bounded autonomous fitness state for operators.
- Phase 196 is complete: `swarm-evolution` now generates bounded perturbation and crossover variants from durable winning genomes with replayable parent lineage, and Kitten requests that autonomous generator directly while keeping the existing proposal lane unchanged.
- The v1.56 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `192` through `195` now live under `.planning/milestones/v1.56-phases/`.
- Phase 195 is complete: first-party workspace dependencies are explicitly version-pinned, CI now runs the shared supply-chain gate, `cargo audit` exceptions are documented, and release automation publishes one CycloneDX SBOM per workspace crate without leaving generated JSON in the repo tree.
- Phase 194 is complete: the runtime now evaluates Linux anti-tamper signals for debugger attachment and unexpected library loads before serve startup, continues the monitor in the background, emits structured tamper alerts, and surfaces the latest anti-tamper report on `/readyz`, `/healthz`, and `/v2/api/runtime/status`.
- Phase 193 is complete: file-backed runtime config now requires a detached `.sig.json` sidecar signed by a trusted Ed25519 key, and both startup and full config reload fail closed on unsigned or tampered config files.
- Phase 192 is complete: `swarm_detect` now verifies a signed repo ruleset manifest plus adjacent binary sidecar at startup, refuses `live_response` mode on failed attestation, and surfaces `startup_attestation` through `/startupz`, `/readyz`, and `/healthz`.
- The v1.55 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are current, and phase directories `188` through `191` now live under `.planning/milestones/v1.55-phases/`.
- Phase 191 is complete: the shipped `end_to_end_ingest_bench` now supports both fixed steady-state measurement and a monotonic `ramp_until_shed` mode, and the checked-in reference run captures the first `/readyz` shed threshold on the measured host.
- Phase 190 is complete: `swarm-runtime` now ships a Criterion-owned `hot_path` benchmark with checked-in `in_memory` and `local_journal` percentile baselines for ingest -> detect -> deposit -> escalate.
- Phase 189 is complete: JetStream now runs the same deposit, query, escalation, threat-class-config, threat-intel, and GC assertions as the in-memory substrate contract through the compose-backed harness, CI executes that broader suite, and policy-aware GC now preserves parity when threat-class overrides tighten evaporation thresholds.
- Phase 188 is complete: the repo now owns a compose-backed JetStream harness with deterministic lifecycle, dynamic loopback port export, and CI smoke coverage, and the old ignored JetStream tests now build signed deposits that satisfy the current substrate validation contract.
- Phase 187 is complete: CI now runs a repo-owned `#[cfg(test)]`-aware checker that fails on new live `.unwrap(` or `.expect(` in `swarm-runtime`, and integration tests now prove malformed ingest and Kitten proposal payloads fail closed instead of panicking.
- Phase 164 is complete: the canonical doc set now distinguishes active runtime contract material from historical reference material, and the architecture, agent, governance, evolution, and config references now describe the shipped Rust runtime instead of the removed Python-heavy plan.
- Phase 165 is complete: the canonical docs now define one bounded governance contract spanning observation, guarded response, receipt-backed destructive response, maintenance-only operation, identity admission, approval lineage, and continuity-preserving rotation.
- Phase 166 is complete: degraded, partitioned, and healing governance states now have one fail-closed contract across the architecture doc, governance doc, config reference, and disaster-recovery runbook.
- Phase 167 is complete: queue, proof, canary, promotion, review, and export now read as one bounded operator contract across the architecture doc, evolution doc, config reference, and project summary.
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
- Phase 153 is complete: `swarm-consensus` now owns deterministic committee rotation, JetStream subject layout, timeout-driven propose/prevote/precommit round progress, and an in-process three-node proof covering ten sequential commits.
- Phase 154 is complete: governance and exclusion receipts are now signed and verified, destructive Pounce actions carry consensus receipts through the routed runtime lane, and the pheromone substrate now rejects spoofed or unadmitted identities when admission state is configured.
- Phase 155 is complete: Tom now tracks explicit quorum-loss partition state with durable persistence, pre-stages signed contingency leases during healthy periods, enforces lease-only destructive response during partition, emits runtime partition/reconciliation events, and exposes governance status on `/healthz`.
- Phase 156 is complete: the consensus harness now proves invalid signatures and equivocation never produce unauthorized commits, partition routing now proves expired leases fail closed, and resilience integration now persists reconciliation across partition recovery and restart.
- Phase 157 is complete: the repo now owns a typed `deception` config surface, `CalicoAgent` can bootstrap baseline `DeployDecoy` requests from that playbook, and monitored decoy interactions now emit signed high-confidence `initial_access` or `lateral_movement` pheromone deposits.
- Phase 158 is complete: Calico now persists decoy lifecycle state across restart, Sphinx registers durable deception assets for correlation, and Kitten folds deception interactions into durable proposal and episode fitness artifacts.
- Phase 159 is complete: shared telemetry now includes `ProcessMemoryAccess`, `FilelessExecutionDetector` is wired through repo-owned runtime config, and fileless execution findings reach the standard strategy-scoped pheromone lane with correct `DefenseEvasion` or `PrivilegeEscalation` mapping.
- Phase 160 is complete: `BehavioralAnomalyDetector` now maintains per-host decaying baselines backed by durable substrate snapshots, the runtime hydrates or persists that state around live evaluation, and durable signature validation now accepts strategy-scoped detector IDs when their base signer identity matches the Ed25519 key.
- The v1.47 lifecycle is complete: milestone audit passed, phase summaries and verification artifacts are on disk for phases 157-160, and the workspace now waits for `$gsd-new-milestone`.
- v1.48 is now activated with phases 161-163 mapped in the roadmap and requirements: 161 builds the evasion corpus and coverage metrics, 162 feeds those measured gaps into Kitten mutation and canary flow, and 163 adds the optional `z3` formal verification tier.
- Phase 161 is complete: the repo now owns an evasion corpus and ATT&CK technique catalog, the runtime exposes `/api/v1/evasion/coverage` and `/v2/api/evasion/coverage`, and Prometheus publishes per-detector evasion catch-rate gauges from the same coverage snapshot.
- Phase 162 is complete: Kitten now derives bounded evasion pressure from the shared coverage snapshot, durable population and episode artifacts retain replay-vs-evasion fitness plus gap-closure metadata, replay scenarios execute under a signer-derived Ed25519 identity, and `critical_path_integration` now proves evasion-gap-to-canary admission.
- Phase 163 is complete: `custom_z3` invariants now compile through an optional Z3-backed solver lane, proof and counterexample artifacts persist through the shared evolution proof store, timeout stays configurable through `SWARM_EVOLUTION_Z3_TIMEOUT_MS` with a 30s default, and the shared evolution-status surface now shows the latest solver-backed proof outcome.
- The v1.50 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `168` through `171` are archived under `.planning/milestones/v1.50-phases/`.
- Milestone `v1.51 Assurance-Gated Evolution And Counterexample Loop` executed across phases 172 through 175 with complete context, plan, summary, and verification artifacts on disk.
- Phase 172 is complete: the repo now owns an `evolution.assurance` policy, queue proposals persist one shared assurance decision from evasion coverage plus solver proof outcomes, and the shared evolution-status surface exposes the latest assurance block state from durable artifacts.
- Phase 173 is complete: blocked queue proposals now harvest durable replay-ready assurance cases from coverage-floor failures and solver counterexamples, and mutation ranking now carries harvested case counts and lineage into candidate summaries and review packets.
- Phase 174 is complete: queue review, handoff creation, canary admission, promotion start, and shared runtime status now all fail closed on missing or blocked assurance lineage instead of treating robustness artifacts as advisory only.
- Phase 175 is complete: signed bounded assurance waivers now attach directly to blocked assurance lineage, queue review can proceed only when the active waiver clears the remaining assurance blocker, and waiver details surface through handoff, canary, promotion, and shared evolution status artifacts.
- The v1.51 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots live in `.planning/milestones/`, and phase directories `172` through `175` are archived under `.planning/milestones/v1.51-phases/`.
- Phase 176 is complete: Providence now accepts authenticated lifecycle callbacks, persists explicit reconciliation state and callback audit on incidents, surfaces reconciliation on `/v2/api/incidents`, and blocks automatic outbound sync while review-required drift is unresolved.
- Phase 177 is complete: Providence analyst feedback now preserves durable signed evidence on incident audit entries, dismiss feedback continues to drive bounded Kitten penalties, and Sphinx now annotates the matching engagement so analyst disposition and note change memory reward on later retrieval.
- Phase 178 is complete: replay bundles now support bounded rehearsal proof with typed blast-radius and rollback previews, rehearsal reuses the live policy and executor lane in forced `DryRun`, and rehearsal starts from persisted replay artifacts so it does not create new detection-side effects.
- Phase 179 is complete: the operator review surface now joins scoped replay, rehearsal proof, and Providence reconciliation on one bounded page, Providence handoff links land on that scoped review context, platform findings and incidents expose latest rehearsal metadata alongside reconciliation, and rehearsal replay bundles export as signed proof through the existing evidence contract.
- Phase 180 is complete: the Helm chart now ships a supported secure production profile with explicit runtime and JetStream state roots, normalized rendered config paths under `/var/lib/swarm`, declared chart dependency wiring for bundled NATS, and hardened pod packaging for non-root read-only deployments.
- Phase 181 is complete: the repo now defines a recovery evidence packet, runtime PVC and JetStream durability boundaries, repeatable backup or restore and upgrade or rollback drills, and a supported durability matrix for both bootstrap `local_journal` and production `jet_stream` topologies.
- Phase 182 is complete: the runtime now exposes ingest request latency and accepted-event counters on `/metrics`, the repo ships a runnable end-to-end ingest benchmark, and the configuration plus architecture docs now anchor SLO and scaling guidance to measured runtime behavior instead of heuristic population tables.
- Phase 183 is complete: operator auth now supports scoped multi-principal read, rehearse, approve, and maintenance access, approval and maintenance actions are attributable to the authenticated operator identity, and the platform API plus Providence context-token surfaces now align with that operator model.
- The v1.53 lifecycle is complete: milestone audit passed, roadmap and requirements snapshots are archived in `.planning/milestones/`, and phase directories `180` through `183` now live under `.planning/milestones/v1.53-phases/`.
- Phase 184 is complete: the runtime panic audit confirms zero live non-test `unwrap()` and `expect()` sites across `swarm-runtime` entrypoints, the serve and TLS seam now has an explicit `ServeError` boundary, and the deferred string-only propagation work for ingest, service, and HTTP is mapped for Phase 185.
- Phase 185 is complete: request-facing ingest paths now use typed `IngestRequestError` and `IngestProcessingError`, service rehearsal and readiness seams now use typed sub-errors under `ServiceError`, and the operator HTTP surface maps typed runtime, evidence, portfolio, governance, and maintenance failures through explicit adapters instead of inline blanket string flattening.
- Phase 186 is complete: runtime-owned `AgentTickBoundaryError` and `StrategyProposalRouteError` now preserve typed Stalker, Sphinx, drafting, mutation, selection, formal-safety, queue, proposal-store, and canary failure context through the agent tick and Kitten proposal-routing seams instead of flattening those paths into strings.

## Issues

- No known implementation blockers are open. No next milestone is queued yet.

## Next Command

`$gsd-new-milestone` — define and activate the next milestone
