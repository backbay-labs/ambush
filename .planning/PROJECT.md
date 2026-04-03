# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live-response runtime for operators who need to act within the response window. The shipped system can already detect suspicious behavior, evaluate narrow response actions through deterministic policy, survive restart with durable local storage, attach async investigation to persisted replay bundles, assemble explainable incidents, surface the full chain in one operator review report, and execute offline replay plus regression evaluation over a tracked scenario corpus.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Current State

`v1.5 Formal Verification And Shadow Readiness` shipped on 2026-04-03.

**What is now real:**
- named adversarial replay suites with campaign, technique, and benign-vs-adversarial metadata
- repo-owned detector experiment manifests with baseline-vs-candidate evaluation
- persisted experiment reports with lineage, corpus version, score summaries, and explicit offline gates
- canonical verification corpus manifests with known-bad coverage, benign controls, threat templates, and resource budgets
- persisted verification reports, shadow reports, and promotion-review packets addressable by stable IDs through `swarmctl`

## Current Milestone: v1.6 Bounded Canary And Rollback

**Goal:** Add a bounded live canary lane for verified candidate detectors, with observation metrics and rollback, without introducing fleet-wide promotion or quorum governance.

**Target features:**
- assign a verified candidate detector to a scoped canary slot without replacing the production baseline
- observe live canary metrics and bounded live outputs over a configurable window
- roll back automatically or manually and emit a canary decision artifact for later promotion review

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

### Just Shipped

- ✓ Team can run a repo-owned verification gate against a candidate detector and get per-invariant pass/fail results before any promotion workflow — v1.5
- ✓ Verification failures preserve counterexamples or failing corpus references so operators can inspect exactly what broke — v1.5
- ✓ Canonical known-bad indicators, benign controls, and resource budgets are stored in repo-owned manifests or config, not hardcoded in tests — v1.5
- ✓ Team can run a candidate detector in shadow mode against recorded replay or runtime artifacts without emitting pheromones or response actions — v1.5
- ✓ Shadow reports compare candidate and production baseline on detection deltas, false positives, and latency over the same artifact window — v1.5
- ✓ Team can assemble a promotion review packet with lineage, verification verdicts, and shadow comparison summaries for manual approval — v1.5
- ✓ Operator CLI can load the latest verification, shadow, or promotion-review artifacts by stable ID — v1.5

### Active

- [ ] Team can assign a verified candidate detector to a bounded canary slot without replacing the production baseline — v1.6
- [ ] Canary execution emits live detections only within the scoped canary lane and cannot by itself trigger fleet-wide escalation semantics — v1.6
- [ ] Canary observation records detection, false-positive, latency, and resource metrics over a configurable live window — v1.6
- [ ] Canary runs automatically roll back when configured metrics diverge beyond thresholds or resource budgets — v1.6
- [ ] Operator can manually halt or roll back a canary and retrieve the reason, affected slot, and reverted baseline — v1.6
- [ ] Team can assemble a canary evaluation report that links verification, shadow, and canary evidence into one ready-for-promotion or blocked recommendation — v1.6
- [ ] Operator CLI can inspect active or completed canary runs and rollback history by stable ID — v1.6

### Out of Scope

- Distributed governance / quorum approvals — still premature without independent nodes and trust boundaries
- HTTP or multi-user operator control plane — still secondary to verification and shadow-readiness work
- Fleet-wide production promotion of evolved strategies — this milestone stops at bounded canary and rollback
- Automatic strategy mutation or self-evolution in the runtime hot path — the production lane remains deterministic and operator-controlled
- Response-action evolution — response behavior remains static and policy-controlled
- Python runtime resurrection or PyO3 expansion — conflicts with the Rust-first critical lane

## Context

v1.0 shipped the first trusted Rust vertical slice: config loading, detection, in-memory substrate, deterministic policy, sandboxed response execution, and replayable audit artifacts. v1.1 hardened that slice with local durability, persistent replay storage, and operator status or metrics surfaces. v1.2 layered in async investigation, explainable incident assembly, and one operator review report without compromising the hot path. v1.3 completed the operator CLI plus replay and regression loop. v1.4 turned that replay loop into an offline adversarial bench with named suites, candidate detector experiments, persisted reports, and explicit offline safety gates. v1.5 added repo-owned verification corpora, invariant-based verification, shadow comparison artifacts, and promotion review packets without widening live autonomy.

The next milestone follows the staged deployment path that the docs already describe: shadow is complete, so the next bounded step is canary. `docs/EVOLUTION.md` and `docs/INTEGRATION.md` both sequence the rollout as `shadow -> canary -> production`, while the Rust-first roadmap still keeps quorum governance optional and deferred. That makes `v1.6` the right place to introduce a narrowly scoped live canary lane, observation metrics, and rollback without yet attempting consensus promotion or fleet-wide rollout.

## Constraints

- **Tech stack**: Production runtime remains pure Rust — adversarial replay and strategy experiments must extend the same type system and CLI path
- **Security**: Replay and candidate evaluation must stay offline and non-destructive — no live-response side effects
- **Architecture**: Keep the runtime single-node and composition-friendly — no BFT, gossip, or distributed red-swarm work
- **Operations**: Prefer repo-owned manifests and CLI workflows over external services
- **Performance**: Candidate strategy evaluation must continue to preserve the fast-detection proof point through comparable latency measurements

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Move the production runtime to pure Rust | Fast detection and live response are easier to measure, secure, and operate with one runtime | ✓ Good |
| Keep `kernel/` as reference only | The Python tree is useful inspiration but not a viable hot path | ✓ Good |
| Keep `swarm-bridge` as legacy only | PyO3 is unnecessary for the current product direction | ✓ Good |
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

---
*Last updated: 2026-04-03 after starting v1.6*
