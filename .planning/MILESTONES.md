# Milestones

## Latest Completed Milestone

### v1.36 SIEM/SOAR Forward And Alert Routing
**Executable phases:** 108-111
**Shipped:** 2026-04-07

## Active Milestone

No active milestone. `v1.36 SIEM/SOAR Forward And Alert Routing` shipped on 2026-04-07, and the queue is ready for `v1.37 Persistence And Supply Chain Detection`.

## Queued Milestones

| Milestone | Name | Requirements | Tier |
|-----------|------|--------------|------|
| v1.37 | Persistence And Supply Chain Detection | PERSIST-01–05 (5) | Detection Breadth |
| v1.38 | Fileless Execution And Behavioral Baselines | FILELESS-01–06 (6) | Detection Breadth |
| v1.39 | Adversarial Robustness And Evasion Bench | EVASION-01–05 (5) | Detection Breadth |

## History

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
