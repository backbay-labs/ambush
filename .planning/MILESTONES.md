# Milestones

## Latest Completed Milestone

### v1.78.1 Runtime Safety Corrections
**Executable phases:** 320-322
**Status:** Complete with explicitly deferred distributed extensions
**Shipped:** 2026-08-14
**Goal:** Close reversible containment and promotion-solver safety defects while keeping the single-node fail-closed boundary explicit.
**Progress:** QRT-01..04 and ZGATE-01..05 are satisfied; the networked pheromone exchange and multi-process governance round remain deferred to the later distributed-governance queue.

## Active Milestone

### v1.79 Collective Cyber Reasoning
**Executable phases:** 284-289
**Status:** Active
**Started:** 2026-08-21
**Goal:** Turn the runtime from parallel detectors into a collective reasoning system that constructs, contests, and refines causal attack theories, then learns from bounded adversarial pressure.
**Progress:** Phase 284 complete; Phase 285 passed under its revised local-and-hosted assurance scope; Phases 286-289 are accepted and ready for planning.

## Queued Milestones

### v1.74 Structural Integrity
**Executable phases:** 264-267
**Status:** Deferred
**Goal:** Stabilize the codebase by fixing failing tests, removing dead code, decomposing oversized files, and beginning swarm-runtime crate extraction.
**Progress:** Preserved for later reactivation; it is not an active v1.79 blocker.

### v1.78 Runtime Decomposition And TCB Boundary
**Executable phases:** 280-283
**Status:** Complete
**Goal:** Green the verification gates, eliminate the core.inc pattern, split the runtime along its real seams, and enforce the trusted-computing-base boundary.
**Progress:** Phases 280-283 complete as scoped; measured remainder and deliberate limitations remain in the historical planning record.

### Historical v1.80 Red Swarm (superseded; not queued)
**Executable phases:** 288-291 (historical only)
**Status:** Superseded by v1.79 Collective Cyber Reasoning
**Goal:** The former catalog-bounded red-swarm proposal is retained for provenance, but its OPFOR/ATKSCORE/COEVOLVE/ARMSCI acceptance set is replaced by ARENA/SYNTH in active v1.79.
**Progress:** No v1.80 acceptance gate is active in this reset; phases 290-291 remain historical entries and are not silently counted as complete.

### v1.81 Machine-Checked Decision Core
**Executable phases:** 292-294
**Status:** Queued
**Goal:** Extract pure decision predicates, bind them to bounded model checking, and model the highest-risk lease and governance properties.
**Progress:** Original phase numbering is preserved after the v1.79 reset; no future phase was compressed or renumbered.

### v1.82 Provenance Memory And Correlation
**Executable phases:** 296-299
**Status:** Queued
**Goal:** Deepen causal provenance, reconstruct kill chains, correlate hunts through graph traversal, and reduce false positives with dependency-aware scoring.
**Progress:** Original phase numbering is preserved; the active v1.79 hypothesis graph owns the first collective-reasoning vertical slice.

### v1.83 Distributed Governance
**Executable phases:** 301-303
**Status:** Queued
**Goal:** Move from the single-node governance seam to unpredictable committees, quorum-authorized revocation, and re-verified fail-closed recovery.
**Progress:** Original phase numbering is preserved; the superseded BFT row remains historical and does not create an acceptance phase.

### v1.84 Herd Immunity
**Executable phases:** 305-307
**Status:** Queued
**Goal:** Compose taint-aware flow control, no-single-publisher cross-instance immunity, and adaptive deception after the distributed governance boundary is ready.
**Progress:** Original phase numbering is preserved.

### v1.85 The Detection Commons
**Executable phases:** 308-311
**Status:** Queued
**Goal:** Publish a normative spec, external conformance suite, detector-authoring SDK, and generated coverage claim.
**Progress:** Original phase numbering is preserved.

### v1.86 Federation
**Executable phases:** 312-315
**Status:** Queued
**Goal:** Exchange verifiable evidence across operator boundaries without shared servers or automatic local authorization.
**Progress:** Original phase numbering is preserved.

### v1.87 Fleet Scale
**Executable phases:** 316-319
**Status:** Queued
**Goal:** Scale to a multi-instance fleet with blast-radius control, tenant isolation, measured capacity, and enforced release provenance.
**Progress:** Original phase numbering is preserved.

### Numbering and historical-scope decision

The old v1.79 DST/FUZZ/LOOM backlog and v1.80 OPFOR/ATKSCORE/COEVOLVE/ARMSCI backlog are retained below as historical scope only. They are not active acceptance gates. Future v1.81+ phase numbering is unchanged, and no protected GitHub App check is implied by any phase status.

## History

## v1.77 Integration Proof (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The repo ships a resilient CrowdStrike RTR response adapter with OAuth2 service authentication, session management, host isolation, process kill, file quarantine, and repo-owned mock-server coverage.
- The repo ships a resilient Splunk HEC delivery adapter with CIM-compliant field mapping, configurable batching, secret-resolved token authentication, delivery metrics, and repo-owned mock-endpoint coverage.
- The Compose-backed integration proof executes the complete telemetry -> detection -> policy-gated response -> CrowdStrike RTR -> Splunk HEC path with observable response receipts and CIM-mapped delivery artifacts.
- `bash tools/run-integration-proof.sh` validates the documented integration architecture, component health, metrics, and audit evidence without live vendor credentials.

---

## v1.72 OpenAPI Spec And SOAR Bidirectional Sync (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The repo now emits and validates one checked-in OpenAPI 3.1 contract for the authenticated `/v2/api/` platform surface from one repo-owned generator.
- The repo now ships a generated Python client plus a live router smoke test proving the emitted contract against real platform API responses.
- The detect runtime now accepts bounded signed Splunk SOAR, Sentinel SOAR, and Chronicle SOAR verdicts on one ingress route and routes them into the existing feedback lane.
- Incident audit entries and normalized false-positive measurements now persist durable SOAR source-system lineage and explicitly reject duplicate or incomplete verdict sync inputs.

---

## v1.71 CI Hardening And Versioned Releases (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The repo CI surface now runs bounded parallel jobs for format, panic-contract proof, build, clippy, tests, JetStream, benchmark regression, and supply-chain validation with shared cargo cache reuse.
- The JetStream-backed `swarm-pheromone` integration suites now execute through a repo-owned NATS container harness instead of staying local-only proof.
- The hot-path Criterion benchmark is now enforced by a repo-owned p99 regression gate with a tracked baseline JSON and refresh guidance in the repo docs.
- Tagged releases now generate changelogs, build and publish multi-arch GHCR images, emit SBOM artifacts, sign image digests, attach provenance attestations, and publish a GitHub release through one repo-owned workflow.

## v1.70 Telemetry Source Breadth (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The runtime config surface now supports repo-owned `windows_event_log`, `sysmon`, and `auditd` bridge-backed telemetry sources.
- `swarm-ingest-json` now ships three host-log adapters that normalize representative Windows Event Log, Sysmon, and auditd records into the shared telemetry schema.
- The runtime bridge registry and operator readiness surface now validate and build the new bridge family through the same generic path as the earlier bridges.
- The milestone closes with an end-to-end proof that the three new host-log bridges report shared health and metrics and drive existing detector families through one Whisker pipeline.

---

## v1.69 Command-Line Deobfuscation Pipeline (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The `swarm-whisker` detector family now shares one bounded command-line normalization seam with raw-to-normalized evidence lineage instead of duplicating raw lowercase string checks in each detector.
- The normalization seam now handles caret insertion, bounded environment-variable expansion, common Unicode homoglyph and fullwidth forms, and PowerShell-style encoded command decoding.
- The repo now ships a dedicated command-line deobfuscation corpus plus baseline-vs-normalized benchmark helpers on the existing `evasion_coverage` surface.
- The milestone closes with an executable proof that the targeted execution and defense-evasion lanes improve beyond the required catch-rate threshold while benign command-line controls remain zero-false-positive.

---

## v1.68 Multi-Detector Evolution Genomes (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Autonomous evolution now persists typed detector genomes for behavioral anomaly, fileless execution, and DNS exfiltration instead of assuming every mutation is a suspicious process-tree profile.
- The bounded autonomous mutation lane now emits replayable seed-control, perturbation, and crossover variants for all supported detector genome families.
- The measured benchmark harness now evaluates process-tree, behavioral anomaly, fileless execution, and DNS exfiltration detector families through one comparable generation-report surface.
- The milestone closes with an executable proof that the fileless-execution detector improves above a conservative seed baseline on measured fitness and catch rate.

---

## v1.67 Secret Zeroization And API Token Lifecycle (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Secret-bearing config and auth seams now use shared zeroizing storage instead of long-lived raw heap strings.
- The shipped release binaries now prove `panic = "abort"` and `overflow-checks = true` through a repo-owned verification script.
- Operator and platform bearer tokens now support expiry metadata and env-backed rotation without process restart.
- The authenticated operator and platform HTTP surfaces now enforce shared per-source burst and sustained request limits with `429` plus recent-violation status visibility.

---

## v1.66 Learned-State Integrity Signing (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `swarm_core::signed_state` now provides typed signed envelopes, signer binding, and sequence-aware verification for learned-state persistence.
- Behavioral baseline snapshots now sign before persistence and fail closed on tamper or replay during reload.
- Sphinx graph snapshots plus evolution population and episode artifacts now restore only from trusted signed authoritative state.
- Every signed learned-state artifact now carries a monotonic `sequence`, and restore paths reject replayed older state.

---

## v1.65 Config Crate Extraction And service.rs Decomposition (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The former 6009-line `swarm-core/src/config.rs` monolith is now a focused `config/` module tree while preserving the stable `swarm_core::config` API.
- Touching `config/policy.rs` rebuilt 14 of 15 workspace crates, exactly matching the `swarm-core` reverse dependency set and leaving only `swarm-crypto` untouched.
- `swarm-runtime/src/service.rs` is now a focused `service/` module tree that preserves the shipped `swarm_runtime::service::{...}` surface and keeps every extracted file under the 2000-line ceiling.
- Request-facing execution now uses a separately swapped shared runtime handle, so ingest routing and human-approved demo replay no longer clone the full configured stack just to reach audited execution.

---

## v1.64 Cross-Crate Path Hack Elimination (Shipped: 2026-04-13)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The repo now has a concrete inventory of the ten runtime path hacks plus a phased migration plan to replace them with a normal crate boundary.
- The former path-hacked evolution modules now live under `swarm-runtime`, and `swarm-evolution` has been reduced to a compatibility facade.
- The runtime/evolution seam now compiles through normal crate and module paths with no remaining `#[path]` directives in `swarm-runtime`.
- The path-hack removal is build, library-test, and production-target clippy proven across `swarm-runtime` and `swarm-evolution`.

---

## v1.63 Evolution Crate Decomposition And Schema Migration (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `swarm-evolution/src/evolution.rs` is now a thin composition root over a focused internal module tree, keeping the public crate contract stable while removing the earlier oversized file bottleneck.
- `swarm-evolution/src/mutation.rs` now routes through extracted submodules with explicit responsibilities and stable public re-exports instead of one monolithic implementation file.
- `PheromoneDeposit` now carries explicit wire-version metadata, and the substrate plus local-journal reopen paths accept only the current and bounded previous legacy version with fail-closed rejection for unsupported payloads.
- Operator-facing control and platform API envelopes now carry explicit `schema_version` metadata, negotiate through one bounded `x-swarm-schema-version` request header, and keep repo-owned CLI compatibility on schema version `1`.

## v1.62 Statistical Anomaly Scoring And Behavioral Breadth (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `BehavioralAnomalyDetector` now derives confidence from restart-safe learned online distributions instead of the older fixed signal-count arithmetic.
- Behavioral findings now expose explicit support-weighted z-score evidence so operator surfaces can explain why an event scored as anomalous.
- The learned baseline seam now spans network, DNS, authentication, registry, file, and process-memory telemetry rather than remaining process-start only.
- The repo now ships a reproducible labeled-telemetry benchmark showing the widened deviation-scoring detector preserved catch rate while reducing actionable false positives relative to the bounded legacy control.

## v1.61 Response Action Library And Playbook Builder (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The shared response seam now carries fifteen concrete action types through the existing guarded executor path instead of the earlier narrow adapter set.
- Every supported response action now exposes typed blast-radius scope plus rollback metadata through the shared rehearsal contract.
- Repo-owned response playbooks now support deterministic ordered conditional branches with fail-closed fallback behavior.
- Operators can now dry-run one matched playbook through `swarmctl playbook-preview` and inspect projected blast radius, rollback expectations, and approval requirements without live side effects.

## v1.60 Agent Lifecycle Isolation And Graceful Degradation (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The dispatcher now wraps each agent tick in a runtime-owned async panic boundary, so a single panicking agent degrades in place instead of unwinding the shared runtime task.
- Persistent agent-boundary failures now trigger dispatcher-owned in-place restart factories that replace only the failed agent while healthy peers keep running.
- The runtime now exposes explicit `full`, `detect_only`, `read_only`, and `emergency_drain` degradation levels with bounded capabilities and operator-visible status surfaces.
- Repo-owned transition tests now prove the shipped degradation ladder reaches detect-only on JetStream outage, read-only on replay-store write failure, and emergency-drain under heap pressure.

## v1.59 Guided First-Run And Alert Quality Scoring (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `swarmctl` now ships a repo-owned readiness diagnostic that gives one bounded verdict over telemetry, detector activation, and substrate health before the first-run walkthrough begins.
- `swarmctl first-run` now reuses that readiness contract, drives a sandboxed synthetic detection -> approval -> proof walkthrough, and returns durable artifact identifiers in one operator-visible report.
- Signed Providence analyst feedback now persists bounded per-finding false-positive measurements with detector and host attribution, and both `swarmctl status` and `/v2/api/runtime/status` expose the resulting rollups.
- The runtime now derives concrete advisory alert-tuning recommendations from those measured false-positive patterns and surfaces the same `alert_tuning` contract on both repo-owned status surfaces.

## v1.58 Multi-Event Sequence Detection (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The runtime now owns a bounded shared temporal event window with configurable retention, span, and predicate-count limits, and the service records accepted telemetry into that substrate before detection executes.
- Swarm now ships a repo-owned kill-chain detector that loads ATT&CK chain metadata from `sequences/kill-chain-v1.yaml` and evaluates partial or full matches against the shared temporal window.
- The repo now includes three chain-only replay scenarios plus a named suite that stay quiet under deterministic single-event detectors and pass with the sequence detector active.
- Sequence findings now reuse the normal signed pheromone, replay, investigation, and incident lanes, and partial matches emit lower-confidence intermediate deposits instead of a special-case persistence artifact.

## v1.57 Autonomous Parameter Evolution With Measured Fitness (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `swarm-evolution` now generates bounded perturbation, crossover, and gap-expansion variants from durable winning genomes with replayable parent lineage instead of requiring operator-authored experiment specs.
- Autonomous population candidates and episode artifacts now persist measured catch-rate, false-positive, and latency fitness against the tracked evasion corpus, and the shared status surface exposes that bounded evaluation state.
- The repo now owns a reproducible multi-generation benchmark with durable generation reports and an explicit no-gain reference artifact for the production-like suspicious-process-tree baseline.
- Phase 199 closed the loop with a conservative-seed benchmark that shows a real bounded gain: `suspicious_process_tree` improves from catch-rate `0.086` to `0.143` and from measured fitness `0.633` to `0.656` through `autonomous_gap_expansion`.

## v1.56 Binary Attestation And Configuration Integrity (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `swarm_detect` now verifies signed startup artifacts for the binary, repo-owned ruleset manifest, and file-backed runtime config before `live_response` mode can start.
- Full config reload now uses the same detached-signature contract as startup, so unsigned or tampered file-backed config cannot silently replace trusted runtime state.
- The runtime now monitors live Linux anti-tamper signals for debugger attachment and unexpected shared-library loads, surfaces the latest report on health and platform status routes, and can fail closed when configured for `live_response`.
- CI and release automation now use shared repo-owned supply-chain scripts, enforce dependency-policy gates, and publish one CycloneDX SBOM per workspace crate.

## v1.55 JetStream Integration Tests And Load Baselines (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The repo now owns a compose-backed JetStream harness with deterministic lifecycle and CI coverage, so real-backend tests no longer depend on manually started infrastructure.
- The pheromone substrate contract now runs against JetStream with the same assertion breadth as the in-memory backend, including policy-aware garbage-collection parity under threat-class overrides.
- `swarm-runtime` now ships a Criterion-owned hot-path benchmark with checked-in `in_memory` and `local_journal` percentile baselines for ingest -> detect -> deposit -> escalate.
- The operator-facing ingest benchmark now measures both steady-state HTTP ingest behavior and the first `/readyz` shed threshold, giving the docs a measured host-profile and throughput-ceiling artifact.

## v1.54 Panic Eradication And Error Contracts (Shipped: 2026-04-12)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The runtime now has a repo-owned audit baseline and typed top-level error contracts for serve, ingest, service, agent, and strategy-routing seams instead of relying on ad hoc panic cleanup.
- Ingest, service, and operator-facing request paths now fail closed with typed runtime-owned errors on malformed input or dependency failures instead of string-only propagation or implicit panic.
- Agent tick, replay-store, knowledge-graph, and Kitten proposal-routing seams now preserve typed boundary classification through the runtime dispatcher without changing the outward execution contract.
- CI now enforces the runtime panic contract with a `#[cfg(test)]`-aware checker, and integration tests prove malformed ingest and Kitten proposal inputs return errors instead of crashing the process.

## v1.53 Production Packaging, Recovery, And Operator Access (Shipped: 2026-04-11)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The Helm chart now ships one supported secure production profile with explicit runtime and JetStream state roots, hardened packaging defaults, and a consistent config-root contract under `/var/lib/swarm`.
- Recovery evidence now covers backup, restore, upgrade, rollback, and durability boundaries for both bootstrap local-journal and production JetStream-backed deployments.
- Measured ingest latency and capacity baselines now anchor published SLOs, scaling guidance, and alert thresholds instead of heuristic operator estimates.
- Operator access now supports scoped multi-principal read, rehearse, approve, and maintenance authority with attributable approval and maintenance audit lineage across the operator and platform surfaces.

## v1.52 Providence Reconciliation And Response Rehearsal (Shipped: 2026-04-11)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Swarm now accepts authenticated Providence lifecycle callbacks, persists explicit reconciliation state on incidents, and blocks automatic outbound synchronization while review-required drift is unresolved.
- Providence analyst feedback now persists as signed durable evidence and feeds the matching Sphinx engagement plus bounded Kitten false-positive handling without widening the analyst side-effect lane.
- Replay bundles now support typed rehearsal proof with blast-radius and rollback previews, and rehearsal reuses the live policy plus executor lane in forced `DryRun` mode from persisted replay artifacts.
- The local operator review and platform API surfaces now join rehearsal proof with Providence reconciliation, Providence drilldown links land on that bounded review context, and rehearsal replay bundles export as signed proof through the existing evidence contract.

## v1.51 Assurance-Gated Evolution And Counterexample Loop (Shipped: 2026-04-11)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Swarm now owns one repo-defined assurance policy that turns evasion coverage floors and solver proof outcomes into explicit rollout gate inputs instead of advisory evidence only.
- Blocked assurance outcomes now harvest durable replay-ready cases from coverage misses and solver counterexamples and feed that lineage into mutation ranking and review summaries.
- Queue review, handoff creation, canary admission, and promotion start now fail closed on unsatisfied assurance lineage through one shared rollout contract.
- Signed bounded operator waivers now attach directly to the assurance decision they override and surface through the normal proof, review, canary, promotion, and runtime-status lanes.

## v1.50 Async Enrichment And Correlation Depth (Shipped: 2026-04-10)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Weaver now correlates across temporal, causal, entity, and semantic graph dimensions and persists explainable incident evidence with bounded confidence.
- The async investigation lane now schedules by bounded priority, queue budget, starvation protection, and durable ambiguity-vote lineage instead of FIFO-only ordering.
- Behavioral anomaly detection now learns and persists host, identity, and peer-group baselines independently with readable scope attribution on findings.
- Shared runtime, control, and platform status surfaces now expose async backlog, pressure, degradation, and correlation outcomes, and the full detect -> investigate -> correlate path is integration-proven.

## v1.48 Adversarial Robustness (Shipped: 2026-04-10)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- Swarm now owns a repo-tracked evasion corpus, threat-technique catalog, and shared coverage metrics surfaced through both API and Prometheus lanes.
- Kitten now converts measured evasion gaps into bounded mutation pressure, persists replay-vs-evasion fitness through durable evolution artifacts, and proves the evasion-gap-to-canary flow end to end.
- The formal safety gate now has an optional Z3-backed `custom_z3` tier with signed proof artifacts, machine-readable counterexamples, fail-closed timeout handling, and shared evolution-status visibility.

---

## v1.47 Calico And Detection Breadth (Shipped: 2026-04-09)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `CalicoAgent` now owns repo-configured deception playbooks, baseline decoy deployment, and high-confidence tripwire findings for canary file, port, and credential interactions.
- Calico lifecycle state now persists across restart, deception assets register in Sphinx, and attacker interactions feed durable positive fitness into Kitten evolution artifacts.
- The runtime now owns a first-class `ProcessMemoryAccess` telemetry payload plus a `FilelessExecutionDetector` that maps reflective injection, encoded PowerShell, and syscall gadget activity into the normal pheromone lane.
- Swarm now has a restart-safe `BehavioralAnomalyDetector` backed by durable substrate snapshots, runtime hydration, configurable decay, and strategy-scoped durable deposit validation that still honors the signer-derived Ed25519 identity.

---

## v1.46 Distributed Governance (Shipped: 2026-04-09)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `swarm-consensus` now owns deterministic committee rotation, signed message verification, exclusion receipts, and round-driven consensus proof over a reusable JetStream subject layout.
- Tom governance now routes destructive decisions through signed committee receipts, binds runtime and substrate trust to admitted Ed25519 identities, and fail-closes unadmitted governance participation.
- The runtime now tracks durable partition state, pre-stages bounded contingency leases, exposes governance status on serve-mode health surfaces, and reconciles partition-era activity when quorum returns.
- The milestone now closes with deterministic resilience proof covering Byzantine invalid-signature plus equivocation rejection, expired-lease fail-closed routing, and persisted reconciliation across partition recovery and restart.

---

## v1.45 Providence Native (Shipped: 2026-04-09)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Swarm now owns a typed Providence webhook contract with bearer-token service auth and canonical JSON HMAC signing.
- Correlated incidents now synchronize through a dedicated `ProvidenceIncidentAdapter` that creates, updates, and resolves incidents with retry, dead-lettering, and runtime health reporting.
- Providence analysts can now send signed confirm, dismiss, and investigate actions back into Swarm, and those actions persist durable incident-linked audit evidence while feeding false-positive dismissals into Kitten or pending durable storage.
- Providence can now embed a minimal live `/v1/demo/widget` surface, stream scoped runtime activity, and open read-only findings and incidents drilldowns through short-lived signed context tokens.

---

## v1.44 Agent Identity And Infrastructure Signals (Shipped: 2026-04-09)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Serve-mode agents now persist durable Ed25519 identities, derive stable `swarm:ed25519:<hex>` IDs, and sign canonical `agent_identity` plus `agent_role` metadata into deposits and receipts.
- The runtime now enforces registry-backed identity admission, fail-closed governance action gating for unadmitted identities, and continuity-proof key rotation through `swarmctl identity rotate`.
- Swarm now owns a first-class Sentinel infrastructure bridge with normalized health, thermal, and resource-exhaustion payloads surfaced through the existing bridge runtime health and metrics path.
- A stateful `InfrastructureAnomalyDetector` now turns those normalized Sentinel payloads into live execution, impact, and defense-evasion findings.
- Infrastructure execution pressure can now combine with behavioral execution findings through the existing distinct-source pheromone concentration and escalation model.

---

## v1.43 Swarm Memory And Adversarial Pressure (Shipped: 2026-04-09)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `SphinxAgent` now owns a durable typed knowledge graph with repo-owned persistence, temporal correlation, and restart-safe storage.
- Other agents can query Sphinx indirectly through signed pheromone query and answer deposits, and Kitten now blends that Q-value retrieval into proposal fitness with replay-only fallback when memory is sparse.
- Memory retention is now bounded by repo-owned TTL controls, and Sphinx removes stale bundle files as part of garbage collection instead of only dropping them from in-memory state.
- The runtime now owns a deterministic Rust-native red-swarm adapter, generation-scoped adversarial corpus freezing, and durable `EvolutionEpisode` history with corpus metadata, genome hashes, per-threat-class coverage, and red-blue fitness vectors.
- `swarmctl evolution status` and the runtime `evolution_status` event lane now surface current generation, latest episode, corpus version, and best genome state from the same durable evolution artifacts.

---

## v1.42 Evolution Engine Core
**Executable phases:** 137-140
**Shipped:** 2026-04-09

## v1.42 Evolution Engine Core (Shipped: 2026-04-09)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- `KittenAgent` now runs in serve mode with repo-owned drift detection, bounded mutation orchestration, and durable proposal emission.
- Replay-backed population scoring, Pareto survivor selection, restart-safe restore, and persisted hourly proposal throttling now make evolution state durable across process restarts.
- Verified Kitten winners now flow through formal safety bundles, ranked selection, selection-bridge handoff, and bounded canary admission without leaving the runtime-owned lane.
- Operators can now watch the evolution subsystem through typed SSE `evolution_status` events and `swarmctl evolution status`, with population, verification, admission, and Kitten-cycle summaries derived from durable artifacts.

---

## v1.41 Deployment And Hardening (Shipped: 2026-04-09)

**Phases completed:** 5 phases, 5 plans, 0 tasks

**Key accomplishments:**
- The detect server now exposes authenticated `/v2/api/*` platform reads with stable envelopes, host posture summaries, and live findings SSE.
- The repo now ships a deployable Helm chart plus `swarmctl validate` and `swarmctl init` operator workflows.
- Production serve surfaces now enforce the hardened bearer plus TLS/mTLS contract and no longer rely on panic-prone detector defaults or demo-proof `expect()` calls.
- Evolution and CLI ownership now live in dedicated workspace crates, and the runtime hot path carries structured `trace_id` fields with optional OTLP export.
- Control-candidate evolution validation is now stable because experiment and shadow artifacts are derived from a single replay evaluation instead of divergent double runs.

---

## v1.40 Killer Demo And Providence Integration (Shipped: 2026-04-08)

**Phases completed:** 4 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Demo replay can inject repo-owned scenarios into the live telemetry lane behind runtime-owned demo-mode gating.
- The operator review surface now boots a live dashboard from runtime snapshot plus SSE, showing swarm mode, agent health, pheromone pressure, and the escalation timeline.
- Human-gated demo responses now pause, collect signed approval votes, resume through the canonical runtime authorization path, and export a signed proof package.
- Providence webhook delivery now ships Providence-shaped finding envelopes with absolute drilldown links, runtime status, and bridge-health context through the existing notification router.
- Milestone-closeout regression reruns passed for replay injection, dashboard snapshot, approval resume and proof export, and Providence runtime-context delivery.

---

## v1.39 PounceAgent And Policy Gate Hardening (Shipped: 2026-04-08)

**Phases completed:** 4 phases, 15 plans, 0 tasks

**Key accomplishments:**
- PounceAgent now consumes escalation pheromones and routes autonomous responses through the canonical policy, guard, and executor path with dry-run parity.
- Policy control is now repo-owned and fail-closed, with configurable YAML rules, static same-scope burst limiting, and durable rule attribution in logs, audit trails, and receipts.
- TomAgent now provides synchronous governance veto over destructive autonomous actions, and vetoes persist receipt-bearing failure artifacts without touching the executor.
- Routed integration coverage now pins the v1.39 correctness pitfalls: no double-trigger, fail-closed empty rules, auditable lease expiry, cooldown-gated re-trigger resistance, dry-run parity, and audit lineage.
- The settled v1.39 tree passes `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

---

## v1.37.1 Runtime Hardening And Audit Debt (Shipped: 2026-04-08)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- PheromoneSubstrate now rejects deposits with empty signatures or invalid Ed25519 keys; WhiskerAgent and StalkerAgent sign every deposit before submission.
- AgentDispatcher wraps every tick() in configurable timeout (default 500ms) and marks timed-out agents Degraded; apply_actions() has exhaustive match arms with structured warnings.
- gc_expired_threat_intel() runs on all three substrate backends and LocalJournal rewrites the threat-intel journal during GC to prevent unbounded disk growth.
- TetragonBridge wraps stream.next() in configurable timeout (default 30s) with reconnect-backoff and accepts init-spawned processes with `<none>` sentinel.
- SwarmSecretProvider file-watch monitors secret_dir independently and re-resolves @secret: references without full config reload.
- Dead-letter journals rotate when exceeding configurable max_dead_letter_bytes; production wiring threads config through all dispatch and notification constructors.
- swarm-pheromone now has 37+ focused substrate tests covering deposit, query, GC, escalation, threat-intel CRUD, and ThreatClassConfig — up from zero before this milestone.

## v1.37 Persistence And Supply Chain Detection (Shipped: 2026-04-07)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- Shared telemetry schema ownership now includes `RegistryPersistence`, `FilePersistence`, and optional signer metadata for `ProcessStart` events.
- The shared pheromone taxonomy now includes `ThreatClass::SupplyChain`, and runtime-facing label helpers surface it consistently.
- `PersistenceDetector` now recognizes run keys, cron entries, systemd timers, and scheduled-task artifacts with ATT&CK-tagged evidence.
- `SupplyChainDetector` now recognizes unsigned trusted-path execution, DLL side-loading, and signed-binary abuse with ATT&CK-tagged evidence.
- Live runtime, replay, canary, and promotion surfaces can all construct `persistence` and `supply_chain` strategies from repo-owned config.
- Runtime integration proof now shows persistence and supply-chain telemetry flow through config-selected detectors into non-zero pheromone deposits without regressing workspace verification.

## v1.36 SIEM/SOAR Forward And Alert Routing (Shipped: 2026-04-07)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- The response layer now owns a canonical `swarm_finding` schema and a resilient `SiemForwardAdapter` for Splunk HEC, ELK bulk ingest, and Chronicle delivery.
- The shared runtime path now enriches every finding with `parent_process_ancestry`, `host_metadata`, and deterministic `time_to_detect_ms` before persistence or external delivery.
- Repo-owned `notification_channels` and `notification_routing.rules` now route enriched findings to named notification sinks using severity, threat class, and UTC time-window matching.
- Notification delivery now deduplicates bursts, enforces per-channel in-memory rate limits, and persists replay-ready suppressed alerts into per-channel dead-letter journals.
- The authenticated local operator surface now exposes `GET|POST /v1/notifications/dead-letter/{channel}` so operators can list and replay suppressed notifications without touching storage directly.
- Workspace verification remained green through focused core, response, and runtime tests, strict clippy, and a full workspace build after the delivery milestone landed.

## v1.35 Production Hardening And Kubernetes Lifecycle (Shipped: 2026-04-07)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- Serve mode now supports PreStop-driven drain handling, bounded in-flight shutdown, and a startup-only `/startupz` probe contract for Kubernetes rollouts.
- Runtime config now enforces a required `schema_version`, migrates supported legacy shapes deterministically, and rejects future or unrecognized versions fail closed.
- Response adapters can now resolve `@secret:` auth references from mounted files or environment variables, and secret-directory file changes trigger live config reload.
- Prometheus now exposes live heap bytes and heap-pressure ratio gauges derived from the running process and its container memory budget.
- `/readyz` now fails closed when heap pressure exceeds `RuntimeSettings.max_heap_pressure`, while `/livez` and `/startupz` remain semantically separate.
- The repo now ships a disaster-recovery runbook and updated configuration guidance covering schema versioning, startup probes, drain behavior, secrets, and heap-pressure readiness.

## v1.34 Queryable Substrate And Threat Intel Cache (Shipped: 2026-04-07)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- The substrate now persists durable `EscalationRecord`, `ThreatClassConfig`, and `ThreatIntelEntry` state across in-memory, local-journal, and JetStream backends.
- Agents now receive explicit mode-aware environment helpers, and live runtime escalation writes only true upward mode transitions back into the substrate.
- Per-threat-class pheromone policy can now be listed and upserted through the authenticated operator surface and is resolved live without process restart.
- Operators can now seed and query exact TTL-bound threat-intel entries through the authenticated control surface instead of editing backend storage directly.
- The shared live detection pipeline now enriches DNS and network findings from substrate-backed threat intel before pheromone deposits are written.
- Integration proof now shows a seeded DNS threat-intel entry can raise a live finding above alert threshold and record an alert escalation in the substrate.

## v1.33 Telemetry Bridge Architecture (Shipped: 2026-04-07)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- Shared telemetry schema ownership and the `TelemetryBridge` contract now live in `swarm-core`, which removes crate-cycle blockers for runtime-managed bridge orchestration.
- `TetragonBridge`, `CloudTrailBridge`, and `GenericJsonBridge` now all implement the same normalized bridge contract and can be described from repo-owned config.
- `swarm-detect --serve` now builds only configured bridge instances, runs one worker per bridge, and feeds bridge output into the same shared `telemetry_tx` lane already used by live detection.
- Bridge readiness, processed-event counts, error counts, and lag now surface on operator status, `/healthz`, and `/metrics` without degrading the core detector readiness contract.
- Integration coverage now proves two bridge workers can feed the shared detection pipeline concurrently and deposit pheromones end to end.
- Workspace verification remained green through `cargo test --workspace` and `cargo clippy --workspace --tests -- -D warnings` after the bridge milestone landed.

## v1.32 Multi-Agent Runtime And Role Shifts (Shipped: 2026-04-06)

**Phases completed:** 2 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The dispatcher now owns a keyed multi-agent registry with runtime role-shift propagation, peer-finding snapshots, and shared lifecycle telemetry exposed on `/metrics`.
- `whisker-primary`, `stalker-primary`, and `weaver-primary` can now run together inside one live serve-mode registry using the existing runtime stack and config toggles.
- `StalkerAgent` now turns Whisker pheromones into persisted investigation work and republishes completed investigation output back into the pheromone substrate.
- `WeaverAgent` now consumes investigation pheromones and persists `CorrelatedIncident` records through the existing correlation engine and incident store.
- Integration coverage now proves the bounded detect -> pheromone deposit -> investigation -> correlation -> incident assembly pipeline with the real in-memory runtime stack.
- Workspace verification remained green through `cargo build --workspace`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace`.

## v1.31 Runtime Agent Dispatcher And Pheromone-Driven Escalation (Shipped: 2026-04-06)

**Phases completed:** 2 phases, 3 plans, 0 tasks

**Key accomplishments:**
- `swarm-detect` now runs a configurable `AgentDispatcher` loop that manages registered `SwarmAgent` implementations and reports agent health through `/healthz`.
- `WhiskerAgent` now wraps the shipped detection pipeline, drains buffered ingest telemetry, and deposits agent-owned pheromones on dispatcher ticks.
- Live ingest serve mode now fans accepted telemetry into the agent loop without changing the existing HTTP request/response contract.
- A live `ConcentrationMonitor` now evaluates pheromone strength plus `min_sources_for_escalation` and emits typed alert and incident escalation outcomes.
- Shared `SwarmModeState` now drives monotonic `Normal` -> `Alert` -> `Incident` transitions that are visible to runtime agents during serve mode.
- Integration coverage now proves below-threshold silence, single-source suppression, dual-source alert and incident escalation, and the full workspace build, clippy, and test suite remained green.

## v1.30 Structured Observability And Adapter Resilience (Shipped: 2026-04-05)

**Phases completed:** 2 phases, 3 plans, 0 tasks

**Key accomplishments:**
- ingest now assigns per-request correlation IDs, returns them in HTTP responses, and threads them through structured JSON logging across the runtime path
- Prometheus metrics now include verdict, guard-rejection, adapter-outcome, and finding counters alongside the existing critical-path latency histograms
- HTTP EDR and webhook adapters now execute behind retry, exponential backoff, circuit-breaker, and dead-letter persistence logic configured from repo-owned runtime config
- detector profile overrides now validate at config load time and are resolved consistently across control, ingest, CLI, replay, canary, and promotion code paths
- the detect server now exposes distinct `/readyz` and `/livez` semantics while keeping `/healthz` as the readiness-compatible legacy surface
- `cargo test --workspace`, `cargo test -p swarm-runtime`, and strict clippy across the touched crates all remained green after the milestone landed

## v1.29 Runtime Decomposition And Test Coverage (Shipped: 2026-04-05)

**Phases completed:** 2 phases, 5 plans, 0 tasks

**Key accomplishments:**
- `swarmctl` now resolves through a library-owned `cli/` module tree and the binary entrypoint is a thin wrapper.
- The operator surface, review workbench, and replay logic now sit behind dedicated `http/`, `workbench/`, and `replay/` module boundaries with compatibility facades preserved for callers.
- The hot-path detection lane now resolves through `crate::detection`, and all known runtime consumers were updated to that boundary.
- Added 29 focused regression tests across ingest, CLI parsing, operator maintenance, workbench rendering, and replay manifest handling.
- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` both remained green after the refactor.
- `cargo llvm-cov -p swarm-runtime --lib --summary-only` measured 74.46% line coverage across swarm-runtime library sources.

## v1.28 Durable Substrate And Multi-Instance Coordination (Shipped: 2026-04-05)

**Phases completed:** 2 phases, 3 plans, 0 tasks

**Key accomplishments:**
- `swarm-pheromone` now supports a durable JetStream KV backend selected from repo-owned config without forcing an async bootstrap refactor through the runtime stack.
- Live-NATS integration coverage now proves restart-safe JetStream persistence, evaporation GC, cross-instance visibility, shared deposit queries, and `min_sources_for_escalation` enforcement across two substrate instances.
- The JetStream backend now preserves repeated same-agent deposits as distinct persisted records while keeping the threat/timestamp/agent prefix needed for bucket scans.
- The dead `swarm-bridge` crate, legacy `kernel/` tree, and `pyproject.toml` manifest were removed from the live repo surface.
- Canonical docs now reflect the Rust-only workspace, while older Python-centric docs remain explicitly historical reference material.

## v1.27 Live Response Adapters And Deployment (Shipped: 2026-04-05)

**Phases completed:** 2 phases, 4 plans, 0 tasks

**Key accomplishments:**
- The runtime now supports `sandbox`, `http_edr`, and `webhook` response adapters selected from repo-owned config instead of being hard-wired to the sandbox executor.
- HTTP EDR and webhook adapters now emit dry-run, success, timeout, and failure receipts with structured adapter metadata preserved through the audit trail.
- `swarm-detect` now serves `/healthz`, reloads config on file changes or `SIGHUP`, and shuts down cleanly on `SIGTERM`.
- The repo now ships a multi-stage `Dockerfile`, compose orchestration, and an optional internal NATS sidecar profile.
- The verified `swarm-team-six-swarm-detect` image is about 39.8 MB and passed compose build, health, profile, and shutdown checks.

## v1.26 Detection Breadth And Telemetry Ingestion (Shipped: 2026-04-05)

**Phases completed:** 3 phases, 4 plans, 0 tasks

**Key accomplishments:**
- swarm-whisker now understands DNS, registry, and authentication telemetry and ships four configurable detectors for DNS exfiltration, lateral movement, credential access, and suspicious scripting.
- All five detector strategies are now selectable through control and replay surfaces, and MITRE ATT&CK-tagged scenarios plus integration tests prove end-to-end detection for each new threat family.
- swarm-detect now serves `/v1/ingest/events` alongside `/metrics`, validating each JSON event independently and returning per-event accepted or rejected status.
- A new `swarm-ingest-tetragon` workspace crate now compiles Tetragon gRPC protos, maps `ProcessExec` events into normalized `TelemetryEvent`s, and forwards them through a retrying bridge loop.

---

## v1.25 Operational Hardening And Service Extraction (Shipped: 2026-04-05)

**Phases completed:** 3 phases, 5 plans, 0 tasks

**Key accomplishments:**
- `swarm-detect` now runs the detection hot path as a standalone binary separate from the operator workbench CLI.
- Rulesets and scenario fixtures are now loaded through shared runtime config and replay helpers instead of only through `swarmctl`.
- Detection, policy, and response stages now emit Prometheus histogram metrics and the operator surface exposes them at `/metrics`.
- Integration tests now cover the full detect-to-receipt flow, including benign no-op and policy-deny behavior, inside `cargo test --workspace`.
- Workspace clippy denial for `unwrap_used` and `expect_used` is now active across all crates and enforced by the existing CI validation path.

---

## v1.24 Approval Ledger And Quorum Readiness (Shipped: 2026-04-05)

**Phases completed:** 3 phases, 4 plans, 0 tasks

**Key accomplishments:**
- Operators can now define durable local approval sets with threshold rules and supporting promotion evidence refs.
- Signed approval ledgers now preserve detached vote signatures, spine-backed lineage hashes, and explicit missing-quorum state.
- Deterministic approval verdicts and portable signed receipt packs now preserve approval lineage for later offline verification.
- Critical-severity promotions now enter an explicit human-approval-pending state instead of advancing directly.
- Promotion records now preserve signed approval votes, optional durable consensus receipts, and structural quorum-gate configuration.
- Workspace verification remained green through `cargo fmt`, `cargo build`, `cargo clippy`, and `cargo test` after the governance changes landed.

---

## v1.23 Cryptographic Foundation And Guard Pipeline (Shipped: 2026-04-05)

**Phases completed:** 4 phases, 7 plans, 0 tasks

**Key accomplishments:**
- RFC 8785 canonical JSON and typed SHA-256 hashing now back swarm-crypto.
- swarm-crypto now ships real Ed25519 signing, RFC 6962 Merkle proofs, and backward-compatible runtime shims.
- A fail-closed guard pipeline now blocks forbidden filesystem paths and dangerous shell commands.
- Secret and egress guards complete a four-guard pipeline for response safety.
- swarm-spine now signs envelopes, co-signs checkpoints, and verifies issuer chains through swarm-crypto.
- Runtime response execution is now guard-gated and records explicit guard rejections in audit trails.
- GitHub Actions now enforces workspace formatting, lint, build, test, and cargo-deny gates on main-bound changes.

---

## v1.22 Portable Review Capsules And External Handoff (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now export signed portable review capsules from cross-lane sessions and promotion-readiness artifacts through both `swarmctl` and the authenticated local review surface
- imported review capsules now preserve remote signer lineage, local trust status, verification checks, and related stable refs as durable local artifacts
- advisory-only delegation packets now preserve signed review continuity across trust boundaries without granting rollout, promotion, or governance authority

---

## v1.21 Cross-Lane Promotion Review (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now assemble lane-aware review sessions from governance-prep, canary, and production stable refs through both `swarmctl` and the authenticated local review surface
- cross-lane comparison exports now preserve per-lane summaries, derived verification state, and unresolved evidence gaps above the existing signed evidence stores
- promotion-readiness reviews now persist advisory recommendations and fail-closed gaps without bypassing maintenance, canary, or production controls

---

## v1.20 Evidence Workbench And Review Handoffs (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now assemble durable review sessions from signed evidence bundles, verification reports, and promotion evidence packets through both `swarmctl` and the authenticated local review surface
- review sessions now support side-by-side evidence comparison plus stable export snapshots that preserve digests, signer metadata, verification status, and related stable references
- review-driven maintenance handoffs can now re-verify selected evidence bundles while preserving session lineage, operator rationale, resulting maintenance action IDs, and the existing bounded audit trail

---

## v1.19 Local Evidence Review Surface (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now open a local authenticated HTML review shell above the existing operator API instead of relying on raw JSON-first inspection
- signed evidence and verification review now support filtering, stable-ID drill-down, signer metadata, verification checks, and related-lineage navigation
- promotion evidence packets can now be reviewed with recommendation, fallback lineage, and supporting evidence status in one advisory-only flow

---

## v1.18 Signed Evidence And External Verification (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- stable-ID runtime, rollout, and maintenance artifacts can now be exported as signed evidence bundles with canonical payloads, digests, signer metadata, and receipt-chain context
- local verification reports now detect payload, digest, signature, or signer drift and can be reloaded through both `swarmctl` and the authenticated operator surface
- advisory promotion evidence packets now tie rollout outcome, fallback lineage, and verified supporting evidence into one governance-ready artifact without implementing quorum approval

---

## v1.17 Authenticated Operator Surface (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now run a local authenticated HTTP control surface in addition to `swarmctl`
- runtime status, stable-ID runtime artifact lookup, and governance-prep review artifacts are now available through authenticated local endpoints
- bounded maintenance actions now persist durable stable-ID audit trails for applied and blocked requests

---

## v1.16 Governance Packet Sets And Portfolio History (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now group multiple governance-ready review packets into durable packet-set artifacts and split child subsets while preserving source evidence lineage
- portfolio history snapshots now derive cross-cohort survival, rollout outcomes, and review debt from existing strategy memories instead of duplicating canary or promotion state
- packet-set and portfolio-history review surfaces are now available through `swarmctl` with stable-ID reload and cohort filtering

---

## v1.15 Cross-Batch Portfolio And Governance Prep (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now assemble durable cross-batch portfolio artifacts from multiple ranked selections and campaign cohorts through `swarmctl`
- portfolio entries now preserve ranking, selection, mutation-batch, validation-batch, cohort, and rollout-lineage context while supporting explicit include, defer, or drop decisions
- curated portfolio entries can now produce governance-ready review packets that reuse existing evidence and fail closed with persisted blocked artifacts instead of implementing distributed governance

---

## v1.14 Ranked Candidate Rollout Bridge (Shipped: 2026-04-04)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- ranked shortlist packets can now be turned into durable ranked-candidate selections without re-materializing experiment manifests
- operators can now inspect, list, and explicitly accept, defer, or reject ranked-candidate selections through `swarmctl`
- accepted ranked-candidate selections can now bridge back into the existing queue, handoff, and bounded canary path while blocked or stale selections fail closed with persisted bridge artifacts

---

## v1.13 Guided Mutation And Candidate Ranking (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- operators can now derive durable mutation specs from reviewed drafts or materialized candidates without hand-editing multiple manifests
- one mutation spec can now materialize and validate a deterministic batch of candidate variants while preserving per-candidate lineage, proof, advisory, and validation evidence
- deterministic candidate rankings and shortlist review packets now preserve materialization, validation, and reviewed queue references without mutating the later rollout lanes

---

## v1.12 Draft Materialization And Validation Bundles (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- reviewed draft proposals can now be materialized into repo-owned detector experiment manifests with preserved lineage, source experiment references, digests, and applied profile changes
- materialized candidates can now refresh experiment, verification, proof, shadow, and advisory scorecard evidence through one fail-closed validation bundle
- draft-backed queue proposals can now be reconciled in place and marked handoff-ready for the existing accepted-queue canary path without creating duplicate rollout state

---

## v1.11 Proposal Drafting And Selection Pressure (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- replay regressions, verification drift, and strategy-memory gaps can now be materialized as durable selection-pressure reports with stable IDs, explicit rationale, and source-artifact references
- operators can now persist proposal draft artifacts with explicit strategy and lineage hints through `swarmctl` without auto-enqueueing them into rollout
- draft promotion now creates a durable reviewed-queue entry plus a separate promotion record that preserves the pressure source, draft, operator reason, and resulting queue proposal reference

---

## v1.10 Queue Handoff And Canary Launch (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- accepted evolution proposals can now be packaged into durable queue-to-canary handoff packets with stable IDs, proof references, verification references, and shadow evidence
- handoff creation now fails closed on unaccepted proposal state, invalid proof status, missing experiment path, or inconsistent shadow evidence while still preserving blocked packets
- operators can now launch bounded canary directly from a stable handoff packet through `swarmctl`, and the handoff artifact retains the resulting canary run ID

---

## v1.9 Verified Evolution Queue (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- candidate detector updates can now be persisted as proof-backed evolution proposals with stable IDs, lineage, verification references, advisory summaries, and durable review state
- proof artifacts now attest experiment, verification, and lineage evidence with deterministic SHA-256 digests and fail queue admission closed when evidence is missing or inconsistent
- operators can create proofs, inspect queue entries, and record accept, defer, or reject decisions through `swarmctl` without mutating canary or production state

---

## v1.8 Production Memory And Strategy Scoring (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- completed canary and production-promotion artifacts now produce durable strategy-memory records keyed by stable memory IDs
- strategy-memory histories now preserve latest rollout state, rollout lineage, and source-artifact references for operator reload through `swarmctl`
- advisory scorecards now compare the production baseline and verified candidates with deterministic context-aware scores, replay fallback, and explicit contribution breakdowns

---

## v1.7 Controlled Production Promotion (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- canary-approved detectors can now be promoted into the production role with explicit fallback retention and stable production-promotion IDs
- production observation windows now record divergence, latency, and detection-volume metrics and automatically roll back to the retained baseline on threshold failure
- operators can start, inspect, halt, and roll back production promotions through `swarmctl`, and the promotion artifact persists embedded canary evidence plus rollback history

---

## v1.6 Bounded Canary And Rollback (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- verified candidate detectors can now be attached to a repo-owned canary slot with explicit config, stable run IDs, and fail-closed assignment checks against verification and shadow evidence
- bounded live canary observation now records detection deltas, latency, deposit budgets, threshold results, and promotion recommendations without mutating the production baseline
- operators can start, inspect, halt, and roll back canary runs through `swarmctl`, and rollback history persists the slot, reason, and reverted baseline strategy

---

## v1.5 Formal Verification And Shadow Readiness (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- The repo now ships a canonical verification corpus manifest that captures known-bad coverage, benign controls, threat-class templates, and resource budgets for candidate detectors.
- Candidate verification and offline shadow are now first-class persisted workflows with stable IDs, explicit failure output, and `swarmctl` commands for evaluation and reload.
- Promotion review packets now tie candidate lineage, verification evidence, and shadow evidence together as a durable operator handoff artifact.

---

## v1.4 Adversarial Replay And Strategy Bench (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- named replay suites now execute through `swarmctl`, and tracked scenarios carry campaign, technique, and benign-vs-adversarial metadata
- repo-owned detector experiments now compare baseline and candidate profiles offline and persist reports by stable experiment ID
- offline safety gates now fail on known-bad coverage or threshold regressions and attribute failures back to specific scenarios or technique groups

---

## v1.3 Operator Control And Replay Evaluation (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- `swarmctl` now exposes runtime status plus stable-ID lookup for replay bundles, investigation bundles, and incidents
- offline replay now executes tracked scenarios or replay-bundle fixtures in forced `detect_only` mode and persists durable replay-run bundles
- replay evaluation now gates single runs or the full tracked `scenarios/` directory, and the runtime tests execute that corpus as a regression baseline

---

## v1.2 Async Investigation And Correlation (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- replay bundles now seed a config-backed background investigation queue with durable queued, completed, failed, and timed-out investigation artifacts
- durable incidents now assemble from investigation bundles with explicit inclusion and rejection reasons
- one operator review report now combines hot-path decisions, async investigation state, incidents, and freshness markers

---

## v1.1 Durability And Operators (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- self-contained local-journal substrate durability now survives restart and live-response mode fails closed when durability is required
- replay bundles now persist to configurable stores and can be reloaded by hunt or receipt ID without re-executing actions
- runtime stage metrics, component readiness, and recent decision correlation now ship in one operator status report

---

## v1.0 (Shipped: 2026-04-03)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- strict repository-owned runtime config loading with explicit `detect_only` and `live_response` modes
- concrete suspicious process-tree detector with an in-memory pheromone substrate and published hot-path benchmarks
- deterministic policy verdicts, scoped capability leases, and normalized sandbox response records
- typed audit trails, replay bundles, and an end-to-end tested detect -> authorize -> execute flow

---


---

## v1.2 Async Investigation And Correlation (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- replay bundles now seed a config-backed background investigation queue with durable queued, completed, failed, and timed-out investigation artifacts
- durable incidents now assemble from investigation bundles with explicit inclusion and rejection reasons
- one operator review report now combines hot-path decisions, async investigation state, incidents, and freshness markers

---

## v1.1 Durability And Operators (Shipped: 2026-04-03)

**Phases completed:** 3 phases, 3 plans, 0 tasks

**Key accomplishments:**
- self-contained local-journal substrate durability now survives restart and live-response mode fails closed when durability is required
- replay bundles now persist to configurable stores and can be reloaded by hunt or receipt ID without re-executing actions
- runtime stage metrics, component readiness, and recent decision correlation now ship in one operator status report

---

## v1.0 (Shipped: 2026-04-03)

**Phases completed:** 4 phases, 8 plans, 0 tasks

**Key accomplishments:**
- strict repository-owned runtime config loading with explicit `detect_only` and `live_response` modes
- concrete suspicious process-tree detector with an in-memory pheromone substrate and published hot-path benchmarks
- deterministic policy verdicts, scoped capability leases, and normalized sandbox response records
- typed audit trails, replay bundles, and an end-to-end tested detect -> authorize -> execute flow

---
