# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live-response runtime for operators who need to act within the response window. The shipped system can already detect multiple threat families, evaluate narrow response actions through deterministic policy, survive restart with durable local storage, attach async investigation to persisted replay bundles, assemble explainable incidents, surface the full chain in one operator review report, execute offline replay plus regression evaluation over a tracked scenario corpus, ingest real telemetry through HTTP plus Tetragon-derived process events, and now drive a live demo path with streamed operator visibility, approval-in-the-loop proof export, and Providence delivery.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Milestone Status

`v1.75 Operator Packaging` active (phases 268-271). `v1.74 Structural Integrity` deferred.

**Goal:**
- Package the runtime for first external operator use with curated defaults, deployment docs, quickstart workflow, and adversary-emulation validation.

**Delivered:**
- The repo already ships `swarmctl init`, `swarmctl validate`, `swarmctl readiness`, `swarmctl first-run`, and `swarmctl status` scaffolding that can be turned into an operator-facing first-run path.
- The runtime already has a checked-in default ruleset, a shared bridge-health/status surface, and replayable scenario infrastructure that can support external-operator packaging.
- The next milestone will harden those surfaces into curated defaults, deployment guidance, an adversary-emulation corpus, and a one-command quickstart proof.

**Supporting foundation:**
- `v1.70` expanded telemetry-source breadth across Windows Event Log, Sysmon, and auditd so the packaging work can target more than one ingest source.
- `v1.71` hardened CI, JetStream coverage, hot-path benchmark gating, and tagged releases so operator-packaged flows can rely on reproducible build and validation paths.
- `v1.72` added a checked-in OpenAPI contract plus generated Python client proof, which broadens the operator-facing integration surface that packaging must document clearly.

## Current Milestone: v1.75 Operator Packaging

**Goal:** Package the runtime for first external operator use with curated defaults, deployment docs, quickstart workflow, and adversary-emulation validation.

**Target features:**
- Curated `detect_only` defaults that let an operator run `swarmctl init`, `swarmctl validate`, and boot the runtime without hand-editing config
- A one-screen `swarmctl status` summary and remediation-grade startup or bridge errors that keep first-run diagnosis self-serve
- Deployment documentation covering Docker single-container, Docker Compose with NATS, Helm, and bare-metal paths
- A mapped adversary-emulation corpus plus a one-command quickstart that proves time-to-first-detection end-to-end

## Current State

`v1.75` is active. The repo has completed the contiguous milestone run from `v1.52` through `v1.73`, covering Providence reconciliation, production packaging, panic and self-protection hardening, autonomous evolution, sequence detection, guided onboarding, agent isolation, response expansion, anomaly depth, large-file decomposition, runtime/evolution crate-boundary cleanup, config and service monolith decomposition, learned-state integrity signing, secret zeroization, release-build hardening, restart-free bearer lifecycle handling, shipped HTTP request throttling, multi-detector evolution breadth, command-line deobfuscation hardening, telemetry-source breadth across Windows Event Log, Sysmon, and auditd, hardened CI plus repo-owned versioned release automation, a machine-readable platform API contract with generated client proof plus inbound SOAR verdict sync and lineage, and stigmergic feedback plus baseline-resistance proof. `v1.74` structural-integrity work remains deferred while operator packaging executes.

**What is now real:**
- The live runtime can detect, investigate, correlate, rehearse, review, and export signed evidence through one Rust-first operator workflow.
- Serve mode now carries production packaging, recovery guidance, measured SLO baselines, binary/config attestation, anti-tamper reporting, and scoped multi-operator auth.
- Autonomous evaluation, sequence detection, statistical anomaly scoring, and bounded response playbooks are all shipped on the same runtime and replay substrate.
- The former runtime/evolution source-inclusion escape hatch is gone, the config and service monoliths are now split into focused module trees, learned-state persistence rejects tampered or replayed older artifacts, secret-bearing seams zeroize shared plaintext, the shipped HTTP auth surfaces now support restart-free token rotation plus bounded request throttling, the evolution lane now benchmarks multiple detector genome families instead of only process-tree variants, the command-line detector family now shares one bounded deobfuscation seam with measured gain and benign-regression proof, the runtime now ingests Windows Event Log, Sysmon, and auditd telemetry through the same shared bridge runtime, the repo now ships one hardened CI plus tagged-release path to prove and publish that surface, and the command-and-control lane now recruits corroboration from trusted pheromone pressure while stale behavioral baselines lose confidence instead of being silently trusted.

## Historical Milestone Notes

- `v1.47 Calico And Detection Breadth` is complete.
- `v1.48 Adversarial Robustness` is complete.
- Phase 161 `Evasion Test Corpus And Coverage Metrics` is complete.
- Phase 162 `KittenAgent Evasion Mutation Cycle` is complete.
- Phase 163 `Z3 Formal Verification` is complete with optional Z3-backed proof persistence and shared status surfacing.
- `v1.40 Killer Demo And Providence Integration` is complete.
- `v1.41 Deployment And Hardening` is complete.
- `v1.42 Evolution Engine Core` is complete with phases 137-140.
- `v1.43 Swarm Memory And Adversarial Pressure` is complete with phases 141-144.
- `v1.44 Agent Identity And Infrastructure Signals` is complete with phases 145-148.
- Phase 145 added repo-owned `identity.agent_key_dir`, restart-stable Ed25519 key persistence for serve-mode agents, `swarm:ed25519:<hex>` identity derivation, and signed pheromone metadata carrying explicit `agent_identity` plus `agent_role`.
- Phase 146 added repo-owned `identity.registry_dir`, durable serve-mode identity admission, dispatcher fail-closed governance checks for unadmitted identities, and `swarmctl identity rotate` continuity-proof rotation with retired-key retention.
- Phase 147 added shared infrastructure telemetry payloads, repo-owned Sentinel bridge config, the `swarm-ingest-sentinel` crate, and runtime bridge-health integration for Sentinel sources.
- Phase 148 added `InfrastructureAnomalyDetector`, runtime config/factory wiring for `infrastructure_anomaly`, and cross-signal execution escalation proof through the existing distinct-source pheromone lane.
- Phase 157 added repo-owned deception playbooks, `CalicoAgent` baseline decoy deployment, and signed high-confidence decoy-interaction pheromones for canary files, honeypot ports, and credential lures.
- Phase 158 added durable Calico lifecycle state, typed Sphinx deception-asset registration, and deception-weighted Kitten fitness that now persists through the existing evolution episode artifacts.
- Phase 153 added the reusable `swarm-consensus` protocol core with deterministic proposer rotation, JetStream subject layout, timeout-driven round advance, and an in-process three-node sequential consensus proof.
- Phase 154 bound governance and substrate trust to signer-derived Ed25519 identities, added signed governance/exclusion receipts, and moved destructive response routing onto receipt-backed Tom consensus with registry-backed deposit admission.
- Phase 155 added durable partition-state tracking, consensus-issued contingency lease pre-staging, partition-aware destructive-response enforcement, runtime partition/reconciliation events, and governance health visibility through the serve-mode status surfaces.
- Phase 156 added deterministic resilience proof for the distributed-governance lane: Byzantine invalid-signature and equivocation rejection in `swarm-consensus`, expired-lease fail-closed routing on the live dispatcher path, and persisted reconciliation across partition recovery and restart.
- Phase 142 added signed Sphinx memory query and answer pheromone contracts, dispatcher-shared substrate wiring for Kitten and Sphinx, Q-value-style retrieval scoring over the durable graph, and bounded replay fallback when no usable memory answer arrives.
- Phase 143 added repo-owned `knowledge_retention_days`, Sphinx graph garbage collection with stale bundle cleanup, and a deterministic `RedSwarmAdapter` plus `MockRedSwarm` seam backed by the tracked `scenario-suites/` corpus.
- Phase 144 added generation-scoped adversarial corpus freezing in Kitten, durable `EvolutionEpisode` persistence with corpus and genome metadata, and adversarial corpus plus best-genome visibility through the evolution status surface.
- Phase 137 added a runtime-owned `KittenAgent`, repo-owned evolution config, a concept-drift detector over durable evidence, and bounded proposal emission backed by the extracted evolution harnesses.
- Phase 104 added bounded drain control, PreStop coordination, and `/startupz` startup-probe semantics for serve mode.
- Phase 105 added schema-aware config migration and `@secret:` resolution for live response adapters with secret-directory reload.
- Phase 106 added live heap metrics and readiness shedding before the runtime reaches an OOM boundary.
- Phase 107 added the disaster-recovery runbook, configuration guidance, and milestone verification/archive closeout.
- Phases 108-111 completed canonical SIEM finding delivery, finding enrichment, rule-based notification routing, and replayable suppressed-alert queues.

## Requirements

### Validated

- ✓ Operator can run a pure-Rust detect -> authorize -> execute slice with repository-owned config and explicit runtime modes — v1.0
- ✓ Runtime can evaluate a concrete detector, deposit to an in-memory substrate, and publish benchmarked hot-path latency — v1.0
- ✓ Runtime can gate live response through deterministic policy, scoped leases, sandboxed execution, and normalized receipts — v1.0
- ✓ Runtime can emit auditable replay bundles and cover the critical path with integration tests — v1.0
- ✓ Operator can switch between in-memory and local-journal substrate backends and require durable live response at runtime boundaries — v1.1
- ✓ Operator can persist replay bundles to a configured store and reload them by hunt or receipt ID after restart — v1.1
- ✓ Operator can inspect one status surface with stage metrics, component readiness, and recent decision correlation — v1.1
- ✓ Operator can queue async investigation off persisted replay bundles and retrieve durable investigation artifacts by hunt or receipt ID — v1.2
- ✓ Operator can assemble explainable incidents from investigation bundles using shared evidence and time windows — v1.2
- ✓ Operator can review hot-path decisions, async investigation state, incidents, and freshness markers from one serializable report — v1.2
- ✓ Operator can bootstrap the async investigation and correlation stack from repository-owned config instead of test-only manual wiring — v1.2

### Recently Completed

- ✓ Operator can inspect runtime status, recent decisions, investigations, and incidents through a repo-owned control surface — v1.3
- ✓ Operator can retrieve replay bundles, investigation bundles, and incidents by stable IDs without reading raw storage files — v1.3
- ✓ Team can run deterministic offline replay from persisted bundles or fixture corpora without executing live response actions — v1.3
- ✓ Team can define replay scenarios with expected outcomes and reproduce them locally or in CI — v1.3
- ✓ Team can generate regression reports and fail when replay behavior or hot-path latency drifts past configured limits — v1.3
- ✓ Team can run Hellcat-inspired adversarial scenario corpora against the offline replay harness — v1.4
- ✓ Team can organize adversarial scenarios into named suites with campaign and technique metadata for repeatable execution — v1.4
- ✓ Evaluation reports can identify which adversarial scenarios, suites, or technique groups regressed — v1.4
- ✓ Team can register a candidate detection strategy as a repo-owned experiment input without changing the production detector configuration — v1.4
- ✓ Team can compare baseline and candidate strategies against the same replay corpus on detection quality, false positives, and latency — v1.4
- ✓ Candidate strategy experiments persist lineage, corpus version, and score summaries for offline review — v1.4
- ✓ Offline experiment gates fail when a candidate regresses known-bad coverage or misses configured comparison thresholds — v1.4

### Rollout Milestones

- ✓ Team can assign a verified candidate detector to a bounded canary slot without replacing the production baseline — v1.6
- ✓ Canary execution emits live detections only within the scoped canary lane and cannot by itself trigger fleet-wide escalation semantics — v1.6
- ✓ Canary observation records detection, false-positive, latency, and resource metrics over a configurable live window — v1.6
- ✓ Canary runs automatically roll back when configured metrics diverge beyond thresholds or resource budgets — v1.6
- ✓ Operator can manually halt or roll back a canary and retrieve the reason, affected slot, and reverted baseline — v1.6
- ✓ Team can assemble a canary evaluation report that links verification, shadow, and canary evidence into one ready-for-promotion or blocked recommendation — v1.6
- ✓ Operator CLI can inspect active or completed canary runs and rollback history by stable ID — v1.6

### Previous Milestone

- ✓ Team can promote a canary-approved detector to production while retaining the previous production detector as an explicit rollback target — v1.7
- ✓ Operator can start a production promotion from a ready canary artifact and persist a stable promotion ID with baseline lineage — v1.7
- ✓ Production promotion records detection, divergence, latency, and budget metrics over a configurable post-promotion observation window — v1.7
- ✓ Production promotion automatically rolls back when observation-window metrics diverge beyond configured thresholds or resource budgets — v1.7
- ✓ Operator can manually halt or roll back a production promotion and retrieve the reason, restored baseline, and affected observation window — v1.7
- ✓ Promotion records persist canary evidence, promoted strategy lineage, rollback target, and final recommendation in one durable artifact — v1.7
- ✓ Operator CLI can inspect active or completed production promotions and rollback history by stable ID — v1.7

### Just Shipped

- ✓ Team can persist strategy outcome memories from completed canary and production-promotion artifacts without rerunning telemetry — v1.8
- ✓ Team can reload strategy-memory records by stable memory ID or strategy ID without reading raw store files — v1.8
- ✓ Team can compute deterministic context-aware utility scores for verified strategies using production memories plus replay-fitness fallback — v1.8
- ✓ Utility scoring preserves contributing memories, outcome weights, recency effects, and context matches for operator inspection — v1.8
- ✓ Memory-backed strategy scoring remains advisory only and cannot by itself promote, mutate, or replace a production detector — v1.8
- ✓ Team can assemble a strategy scorecard that compares the production baseline and verified candidates using memory-backed scores, rollout lineage, and current promotion state — v1.8
- ✓ Operator can inspect strategy memory histories, score explanations, and advisory selection scorecards through `swarmctl` — v1.8

### Just Shipped

- ✓ Team can persist verified detector proposals in a repo-owned evolution queue with stable IDs, lineage, and evidence references — v1.9
- ✓ Team can attach proof-backed safety artifacts and fail-closed admission checks to queued detector proposals — v1.9
- ✓ Operator can inspect and triage queued proposals with advisory review through `swarmctl` — v1.9

### Most Recently Shipped

- ✓ Operators can now execute response actions through repo-owned sandbox, HTTP EDR, or webhook adapters selected from config while preserving guard and policy safety gates — v1.27
- ✓ Runtime audit trails now preserve dispatched success, skipped, guard-rejected, timeout, and failure outcomes for live response adapters — v1.27
- ✓ `swarm-detect` now exposes `/healthz`, reloads config on file-watch or `SIGHUP`, and runs cleanly inside a compose-managed container image — v1.27
- ✓ Operators can now export one signed portable review capsule from a cross-lane session or a promotion-readiness artifact without granting direct store access — v1.22
- ✓ Imported review capsules now preserve remote signer lineage, local trust status, and related stable refs as durable inspectable artifacts — v1.22
- ✓ Advisory-only delegation packets now preserve signed review continuity across trust boundaries without widening rollout, promotion, or governance authority — v1.22
- ✓ Operators can now assemble one lane-aware cross-lane review session from `promotion_review`, `canary_run`, and `production_promotion` refs or direct evidence refs and reload it by stable session ID — v1.21
- ✓ Cross-lane session exports now preserve per-lane summaries, derived verification state, and unresolved evidence gaps above the existing signed evidence stores — v1.21
- ✓ Operators can now derive durable promotion-readiness reviews from one cross-lane session while remaining advisory-only above maintenance, canary, and production controls — v1.21
- ✓ Operators can now assemble durable multi-artifact review sessions from signed evidence and promotion artifact stable IDs and reload them by stable session ID — v1.20
- ✓ Review sessions now support side-by-side evidence comparison plus stable reviewed export snapshots with digests, signer metadata, verification state, and related refs — v1.20
- ✓ The local review surface and `swarmctl` can now launch bounded evidence re-verification handoffs that preserve session lineage, selected refs, operator rationale, and maintenance action IDs — v1.20
- ✓ Operators can now open a local authenticated HTML review shell above the existing operator API for signed evidence, verification results, and promotion evidence packets — v1.19
- ✓ Evidence review now supports subject-kind and verification-status filtering, stable-ID drill-down, signer metadata, verification checks, and related lineage links — v1.19
- ✓ Promotion evidence review now presents recommendation state, fallback lineage, and supporting evidence status in one advisory-only flow without bypassing audit trails — v1.19

### Historical Milestone Notes

- `v1.48 Adversarial Robustness` is complete.
- `v1.49 Canonical Runtime Contract And Governance Modes` is complete.
- `v1.50 Async Enrichment And Correlation Depth` is complete.
- `v1.51 Assurance-Gated Evolution And Counterexample Loop` is complete.
- Phase 164 completed the source-of-truth reset across `docs/REFERENCE-STATUS.md`, `docs/ARCHITECTURE.md`, `docs/AGENTS.md`, `docs/CONSENSUS.md`, `docs/EVOLUTION.md`, `docs/INTEGRATION.md`, and `docs/CONFIGURATION.md`.
- Phase 165 completed the bounded governance vocabulary across architecture, governance, config, and agent docs, including maintenance-only behavior, receipt lineage, and identity admission continuity.
- Phase 166 completed the fail-closed degraded-governance and partition-recovery contract across the canonical docs and the disaster-recovery runbook.
- Phase 167 completed the bounded queue-to-proof-to-canary-to-promotion-to-review contract across the architecture doc, evolution doc, config reference, and project summary.
- Phase 172 is complete: the repo now owns one shared assurance policy over evasion coverage floors and solver proof outcomes, queue proposals persist durable assurance summaries, and the shared evolution status surface now exposes the latest assurance decision.
- Phase 173 is complete: blocked queue proposals now harvest replay-ready assurance cases from coverage misses and solver counterexamples, and mutation ranking now carries assurance-case lineage into candidate summaries and review packets.
- Phase 174 is complete: queue review, handoff creation, assurance-aware canary admission, promotion start, and shared evolution status now all fail closed on missing or blocked assurance lineage.
- Phase 175 is complete: signed bounded waivers now attach directly to blocked assurance lineage, and the shipped proof, review, canary, promotion, and runtime-status surfaces all preserve the resulting waiver lineage without bypassing fail-closed rollout policy.
- `v1.52` and `v1.53` remain phase-defined and queued for explicit activation.
- `v1.39 PounceAgent And Policy Gate Hardening` is complete.
- `v1.40 Killer Demo And Providence Integration` is shipped with replay injection, live dashboard visibility, approval-in-the-loop demo response, signed proof export, and Providence delivery.
- `v1.41 Deployment And Hardening` is complete with platform APIs, deployment experience, serve-surface hardening, crate extraction, and tracing shipped.
- `v1.42 Evolution Engine Core` is complete with phases 137-140 for KittenAgent, formal safety, and operator-visible evolution observability.
- `v1.43 Swarm Memory And Adversarial Pressure` is complete with phases 141-144 for SphinxAgent, durable swarm memory, and Rust-native adversarial pressure.
- `v1.44 Agent Identity And Infrastructure Signals` is complete with persistent agent keys, registry-backed admission, Sentinel bridge ownership, and infrastructure anomaly detection.
- `v1.45 Providence Native` is complete with outbound incident lifecycle, analyst feedback, and the embeddable widget.
- `v1.46 Distributed Governance` is complete with consensus core, signed Tom governance, partition authority, and resilience proof across phases 153-156.

### Out of Scope

- Distributed governance / quorum approvals — still premature without independent nodes and trust boundaries
- Multi-user or internet-exposed operator control plane — the operator surface remains local, authenticated, and single-node
- Actual quorum voting or distributed consensus for promotion — independent trust boundaries still do not exist, so the review surface remains advisory-only
- Fleet-wide or partial-fleet rollout of evolved strategies — the runtime still supports only a bounded single-node promotion path
- Automatic ranked-candidate or portfolio promotion from batch scores — portfolio curation remains explicit and operator-reviewed
- Automatic canary or production launch from portfolio entries — rollout gates remain explicit and separate from offline ranking
- Automatic expansion of governance beyond the current bounded receipt-backed model — broader independent trust-boundary quorum remains deferred until real multi-operator deployment needs exist
- Direct rollout, promotion, or governance actions from the review surface — any browser-triggered writes must stay bounded to the existing maintenance scope and audit trail
- Automatic strategy mutation or self-evolution in the runtime hot path — the production lane remains deterministic and operator-controlled
- Response-action evolution — response behavior remains static and policy-controlled
- Python runtime resurrection or PyO3 expansion — conflicts with the Rust-first critical lane

## Context

v1.0 shipped the first trusted Rust vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response execution, and replayable audit artifacts. v1.1 hardened that slice with local durability, persistent replay storage, and operator status or metrics surfaces. v1.2 layered in async investigation, explainable incident assembly, and one operator review report without compromising the hot path. v1.3 completed the operator CLI plus replay and regression loop. v1.4 turned that replay loop into an offline adversarial bench with named suites, candidate detector experiments, persisted reports, and explicit offline safety gates. v1.5 added repo-owned verification corpora, invariant-based verification, shadow comparison artifacts, and promotion review packets without widening live autonomy. v1.6 completed bounded canary execution, persisted canary evidence, and explicit rollback workflows. v1.7 completed controlled production promotion, bounded production observation, and rollback to the retained baseline detector. v1.8 turned those rollout artifacts into durable strategy memories and advisory scorecards. v1.9-v1.12 extended the deferred evolution lane through proof-backed queueing, operator drafting, draft materialization, validation refresh, and queue reconciliation. v1.13 widened that lane into a multi-candidate offline mutation bench.

The project now has an end-to-end rollout ladder plus an offline mutation, ranking, portfolio, governance-prep, authenticated operator bridge, signed evidence lane, local review surface, approval hardening, broader detector coverage, live HTTP ingest, a shared core-owned telemetry bridge contract, real response adapters, deployment packaging, runtime health and reload surfaces, and a durable shared JetStream substrate: experiment -> verification -> shadow -> canary -> production promotion -> strategy memory -> advisory scorecard -> pressure report -> draft -> reviewed queue -> mutation spec -> materialization batch -> validation batch -> ranking packet -> ranked selection -> portfolio -> governance-ready packet -> packet set -> portfolio history -> authenticated local operator review and maintenance -> signed evidence export -> local evidence verification -> advisory promotion evidence packets -> local HTML evidence review -> multi-artifact evidence workbench sessions -> cross-lane promotion review -> approval ledgers and guard-gated promotion -> multi-detector telemetry ingest -> shared multi-instance pheromone coordination -> shared telemetry bridge normalization -> production-hardened Kubernetes lifecycle controls. `v1.23` through `v1.28` moved the runtime from governance-readiness preparation into safer execution, real telemetry intake, durable response infrastructure, and shared substrate coordination without widening autonomy beyond single-node operator control. The latest shipped milestone hardened the serve-mode runtime for rollouts, config evolution, secret rotation, memory-pressure shedding, and operator recovery without widening autonomy beyond that same model.

## Constraints

- **Tech stack**: Production runtime remains pure Rust — adversarial replay and strategy experiments must extend the same type system and CLI path
- **Security**: Replay and candidate evaluation must stay offline and non-destructive — no live-response side effects
- **Architecture**: Keep the critical lane composition-friendly and Rust-first — bounded multi-instance governance is shipped, but gossip meshes, distributed red-swarm work, and uncontrolled coordination expansion remain out of scope
- **Operations**: Prefer repo-owned manifests and CLI workflows over external services
- **Performance**: Strategy memory extraction and scoring must stay off the hot path and preserve the fast-detection proof point through comparable latency measurements

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Move the production runtime to pure Rust | Fast detection and live response are easier to measure, secure, and operate with one runtime | ✓ Good |
| Remove the legacy Python tree from the live repo surface | The Python stubs were useful inspiration but not part of the viable hot path | ✓ Completed in v1.28 |
| Remove `swarm-bridge` from the live repo surface | PyO3 is unnecessary for the current product direction | ✓ Completed in v1.28 |
| Start with a narrow response safety model | Deterministic policy and scoped leases proved the basic live-response boundary without fake distributed consensus | ✓ Good |
| Copy focused upstream code into `vendor/reference/` | Local references reduced upstream dependency risk while preserving freedom to refactor inward | ✓ Good |
| Tackle durability before async investigation | The shipped lane needed restart safety and operator visibility before more reasoning features | ✓ Good |
| Use a repo-owned local journal as the first durable substrate target | Keeps the milestone self-contained and testable without a hard external dependency | ✓ Good |
| Make operator visibility API-first | A serializable Rust status report can back later CLI or HTTP surfaces without rework | ✓ Good |
| Keep investigation asynchronous | Enrichment should improve operator trust and triage without blocking detection or response | ✓ Good |
| Build correlation from durable findings and receipts | The runtime now has enough stable artifacts to group and explain related detections | ✓ Good |
| Treat correlated incidents as operator context first | Correlation should sharpen review before it influences automated action policy | ✓ Good |
| Seed investigation from replay bundles | Durable hot-path artifacts already carry the identifiers and evidence needed for async review | ✓ Good |
| Persist rejected incident candidates | Correlation stays auditable when rejected inputs remain visible instead of being discarded | ✓ Good |
| Extend operator status instead of forking a new API | One serializable report keeps hot-path and async review data aligned for future tooling | ✓ Good |
| Prioritize replay/evaluation over advanced governance for the next cycle | Governance is explicitly optional in the roadmap, while replay and operator tooling unlock immediate validation value | ✓ Chosen |
| Start with a CLI-backed operator surface | The existing runtime already exposes serializable reports and stores; CLI is the smallest practical control seam | ✓ Chosen |
| Keep replay offline and deterministic | Evaluation should strengthen trust in production behavior without widening the live-response blast radius | ✓ Chosen |
| Choose adversarial replay and strategy evaluation as the next milestone | `docs/ROADMAP.md` and `docs/EVOLUTION.md` both place offline red-team and detector bench work ahead of live promotion workflows | ✓ Chosen |
| Complete formal verification and shadow readiness before any live promotion work | `docs/EVOLUTION.md` places verification and shadow before canary or production, while governance remains explicitly deferred | ✓ Good |
| Choose bounded canary and rollback as the next milestone | The canonical staged deployment path moves from shadow to canary, while consensus promotion remains deferred | ✓ Chosen |
| Choose controlled production promotion as the next milestone | The canary artifact is now the documented handoff into production, and the roadmap still defers governance until after a real promotion path exists | ✓ Chosen |
| Keep production promotion CLI-first and single-node | The runtime still lacks independent trust boundaries and multi-node rollout needs, so CLI plus durable artifacts is the smallest credible promotion surface | ✓ Good |
| Choose production memory and strategy scoring as the next milestone | `docs/EVOLUTION.md` made production utility memory the next missing capability once real promotion evidence existed | ✓ Good |
| Keep memory-backed ranking advisory only | The runtime still lacks quorum governance and proof-backed evolution, so scores guide operators instead of auto-promoting strategies | ✓ Good |
| Choose a verified evolution queue as the next milestone | `docs/EVOLUTION.md` and the shipped advisory layer now point to proof-backed proposal handling as the next missing capability before governance | ✓ Good |
| Keep the evolution queue operator-controlled and non-promoting | The runtime still lacks independent trust boundaries, so queued proposals must not advance to production automatically | ✓ Good |
| Choose queue-to-canary handoff as the next milestone | The accepted queue state currently stops at review; the next missing bridge is a durable operator-launched handoff into the existing canary lane | ✓ Chosen |
| Keep handoff launch operator-driven | The runtime still avoids automatic rollout mutation, so accepted proposals should prepare canary launch rather than start it implicitly | ✓ Chosen |
| Choose proposal drafting and selection pressure as the next milestone | With queue-to-canary handoff now real, the next deferred gap is generating better proposal candidates from replay drift and live memory without widening autonomy | ✓ Chosen |
| Keep draft promotion operator-reviewed | Proposal drafts should enrich operator choice, not auto-enqueue or auto-launch rollout | ✓ Chosen |
| Choose draft materialization and validation bundles as the next milestone | `docs/EVOLUTION.md` still expects evaluate and verify artifacts before proposal deployment, and `v1.11` currently stops at draft-backed queue entries with missing proof and experiment linkage | ✓ Chosen |
| Keep the draft-to-rollout bridge artifact-first and operator-triggered | Materializing candidates and refreshing evidence should reduce manual translation, not introduce automatic mutation or rollout | ✓ Chosen |
| Choose guided mutation and candidate ranking as the next milestone | Governance remains deferred, while `docs/EVOLUTION.md` and deferred `EVOL-*` requirements now point to structured mutation, batch evaluation, and evidence-backed ranking as the next offline evolution step | ✓ Good |
| Keep multi-candidate evolution offline and operator-controlled | Batch mutation and ranking should expand review surface area without introducing automatic promotion or autonomous rollout | ✓ Good |
| Choose ranked-candidate rollout bridging as the next milestone | `v1.13` now stops at shortlist packets; the next documented gap is turning selected ranked candidates back into rollout-ready review artifacts without re-materializing evidence | ✓ Chosen |
| Keep ranked-candidate re-entry operator-driven | Ranked batches should reduce artifact translation, not auto-mutate queue, canary, or production state | ✓ Chosen |
| Choose cross-batch portfolio review and governance-prep packets as the next milestone | Future `EVOL-23` and `EVOL-24` were the remaining evolution requirements that advanced the roadmap without violating the deferred-governance constraint | ✓ Good |
| Keep governance prep artifact-first | The runtime can prepare review packets and preserved evidence for a future quorum lane, but still should not implement distributed governance before independent trust boundaries exist | ✓ Good |
| Choose governance packet sets and portfolio history as the next milestone | Governance is still explicitly deferred, while the next future evolution requirements are richer packet grouping and durable cohort history above the existing CLI lane | ✓ Chosen |
| Keep the next cycle CLI-first and single-node | HTTP/TUI surfaces and quorum receipts remain secondary until packet sets and history workflows are proven in the repo-owned runtime | ✓ Chosen |
| Derive portfolio history from existing strategy memories | Strategy memories already encode the durable rollout outcomes needed for cohort survival and debt tracking, so history should not duplicate canary or promotion state | ✓ Good |
| Keep packet-set operations non-mutating | Packet grouping and splitting should widen operator review context without changing queue, canary, or production artifacts | ✓ Good |
| Choose an authenticated operator surface as the next milestone | Governance is still blocked on real trust boundaries, while the runtime already exposes serializable reports and stable-ID artifact views that can back a local authenticated surface now | ✓ Chosen |
| Start with a local HTTP surface instead of TUI or multi-user control | The repo has no UI stack today, and an authenticated API layer is the smallest extension beyond `swarmctl` that preserves the existing single-node operating model | ✓ Chosen |
| Choose signed evidence and external verification as the next milestone | The operator surface and durable artifact lanes are now real, while the docs still defer actual quorum governance until independent trust boundaries exist | ✓ Chosen |
| Choose a local evidence review surface as the next milestone | Future requirements now point to a richer local review client, while quorum governance is still explicitly deferred until independent trust boundaries exist | ✓ Chosen |
| Keep the next review layer read-only and local-first | The authenticated HTTP surface and signed evidence contracts already exist, so the next step should improve inspection without creating a second mutating control plane | ✓ Chosen |
| Choose evidence workbench sessions and review handoffs as the next milestone | The next explicit unmet operator requirements are multi-artifact comparison/export and bounded review-driven actions, while quorum governance is still deferred | ✓ Chosen |
| Keep review-driven actions bounded to existing maintenance scope | The browser surface can improve operator flow, but rollout and governance mutations must continue to pass through the existing narrow audited action lane | ✓ Chosen |
| Choose cross-lane promotion review as the next milestone | The remaining operator gap is no longer basic evidence inspection; it is comparing governance-prep, canary, and production evidence in one advisory session before any quorum work starts | ✓ Chosen |
| Queue portable review capsules after cross-lane review | External trust boundaries are not real yet, but the evidence and session model can still be made portable and independently verifiable ahead of multi-user governance | ✓ Chosen |
| Queue approval ledgers before real quorum governance | Signed approval sets and threshold math can be prepared locally first so later quorum work reuses stable evidence and receipt shapes instead of changing the promotion model again | ✓ Chosen |
| Choose portable review capsules as the next milestone | Cross-lane review is now local-only; the next documented gap is packaging that evidence for external verification without granting direct store access | ✓ Chosen |
| Queue approval receipt packs and human-gate prep after ledgers | The consensus docs require signed receipts and critical-action human approval, but those contracts can be prepared locally before any distributed quorum exists | ✓ Chosen |
| Insert crypto foundation and guard pipeline before governance milestones | Approval ledgers will sign votes and verify quorum signatures; building on full hush-core Merkle and canonical JSON is stronger than the current minimal crypto. Guards on response actions are a prerequisite for governance that widens autonomy. | ✓ Chosen |
| Port from clawdstrike vendor references rather than arc | ClawdStrike guards are security-domain-native and map directly to swarm response pipeline; arc guards are designed for tool-call mediation. Crypto primitives come from hush-core which is already vendored. | ✓ Chosen |

---
*Last updated: 2026-04-13 after defining v1.77 Integration Proof*
