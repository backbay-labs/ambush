---
gsd_state_version: 1.0
milestone: v1.78
milestone_name: Runtime Decomposition And TCB Boundary
current_phase: 282
current_phase_name: Crate Extraction From swarm-runtime
current_plan: null
status: active
last_updated: "2026-08-10T00:00:00Z"
last_activity: 2026-08-10
progress:
  total_phases: 4
  completed_phases: 3
  total_plans: 0
  completed_plans: 0
  percent: 75
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-13)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** `v1.78 Runtime Decomposition And TCB Boundary` — green the verification gates, eliminate `core.inc`, split `swarm-runtime`, and enforce a TCB boundary. Phase 284 (test isolation) is pulled forward from v1.79 as a hard prerequisite for parallel work.

## Current Position

**Current Phase:** 282 — Crate Extraction From swarm-runtime
**Total Phases:** 4 (280-283), plus 320-322 in v1.78.1
**Current Plan:** None started yet
**Total Plans in Phase:** TBD
**Status:** Ready to plan
**Last Activity:** 2026-08-10
**Last Activity Description:** Merged PR #1 (feat/milestones-v1.74-v1.77, 29 commits) into main, making one authoritative ref carrying both the shipped v1.75-v1.77 implementation and the v1.78-v1.87 plan.

Progress: [░░░░░░░░░░] 0%

## Memory

- v1.62 shipped Welford-backed anomaly learning, statistical deviation scoring, and broader behavioral baselines.
- v1.63 shipped evolution.rs and mutation.rs decomposition plus pheromone/API schema versioning.
- v1.64 removed the ten runtime `#[path]` hacks by moving the former bridge-owned modules under `swarm-runtime` and leaving `swarm-evolution` as a compatibility facade.
- v1.65 completed the remaining config/service monolith decomposition work and narrowed request-facing runtime execution to a smaller shared handle.
- v1.66 added signed learned-state envelopes plus tamper and replay rejection across behavioral baseline, Sphinx graph, and evolution persistence.
- v1.67 completed zeroized secret-bearing config storage, explicit release hardening, restart-free bearer-token rotation and expiry handling, and shared per-source HTTP rate limiting on shipped operator/platform surfaces.
- v1.68 completed typed multi-detector evolution genomes for behavioral anomaly, fileless execution, and DNS exfiltration, plus a shared benchmark harness and a fileless improvement proof above a conservative baseline.
- v1.69 completed a shared command-line normalization seam across the detector family, added a repo-owned deobfuscation corpus and benchmark surface, and proved improved catch rate with zero benign false-positive regression.
- v1.70 completed telemetry-source breadth by adding repo-configured Windows Event Log, Sysmon, and auditd bridges on the shared runtime bridge surface with end-to-end detector proof.
- v1.71 completed parallel CI decomposition, containerized JetStream CI coverage, a repo-owned p99 benchmark regression gate, and tagged multi-arch release automation with changelog, SBOM, signing, and provenance.
- v1.72 completed a repo-owned OpenAPI 3.1 contract for `/v2/api/`, a generated Python client with live-router proof, and bounded signed SOAR verdict sync with durable lineage on incident audit and false-positive records.
- v1.73 completed pheromone-driven threshold recruitment (positive-feedback and inhibitory signaling), a kill-chain benchmark showing 33.3% faster alerting, and staleness-aware confidence reduction for aged behavioral baselines.
- v1.74 remains phase-defined but deferred: Phase 264 (test fixes + dead code), Phase 265 (kitten_agent.rs decomp), Phase 266 (drafting.rs + ingest/tests.rs decomp), Phase 267 (swarm-agents extraction).
- v1.75 completed operator packaging with a signed detect-only bootstrap path, repo-owned deployment docs, adversary-emulation coverage proof, and a packaged `swarmctl quickstart` flow.
- v1.76 completed bounded STIX/TAXII feed ingestion, threat-intel finding enrichment, CloudTrail and Kubernetes audit bridge normalization, and cross-cloud signed-deposit proof on the shared runtime path.
- v1.77 completed CrowdStrike RTR execution, Splunk HEC finding delivery, the compose-backed detect -> respond -> deliver proof, and the integration architecture validation pass.
- The repo-owned proof now passes end-to-end through `bash tools/run-integration-proof.sh`, producing a replay bundle plus mocked CrowdStrike RTR and Splunk HEC delivery artifacts.
- 2026-08-10: PR #1 merged into main. The v1.78-v1.87 roadmap was authored against the branch tree, not main's - its LOC premises (97,709 .rs / 22,762 .inc / 115,156 combined) match the branch exactly and main not at all. The merge preserves main's two shipped fixes: BFT (n-1)/3 (f55c3bd) and ContainmentLease/RollbackExecutor (4d03543).
- Merged tree gates: `cargo build --workspace` exit 0, `cargo fmt --all -- --check` exit 0 (after one style commit), `cargo clippy --workspace --all-targets -- -D warnings` exit 0 with zero warnings.

## Issues

- Phase 280 COMPLETE 2026-08-11 (GATEFIX-01..04). All 9 baseline swarm-runtime failures fixed (roadmap said 7; fail-fast undercount). Two real product defects repaired: the guided first-run wizard never reached its own human gate, and the SIEM forward task was detached rather than owned. The panic-contract gate needed its own repair after the first pass made every `include!`d file silently unscanned.
- OPEN, unowned by any requirement: `crates/swarm-cli/src/core.inc:2988` hard-codes `ed25519_dalek::SigningKey::from_bytes(&[85u8; 32])` inside `pub async fn run(cli: Cli)` with no `#[cfg(test)]` above it. This is shipping production code keyed on a public constant.
- OPEN: a second intermittent `kitten_agent` benchmark flake, `measured_evolution_benchmark_improves_over_conservative_seed`, distinct from `..._persists_generation_deltas`. Both belong to phase 284.
- Phase 281 COMPLETE 2026-08-11 (INCFIX-01, INCFIX-03). 17,480 lines across http/replay/workbench converted from `.inc` to ordinary modules; 4 tasks, 4 approved first time, 0 fix rounds. Purity proven with a token-level per-item comparator: 643 items, 0 missing, 0 added, 311 inserted visibility tokens all `pub(super)`.
- CORRECTION carried forward: INCFIX-01's rationale is half wrong. rustc, clippy AND rustfmt all follow `#[path]`; only rust-analyzer and `*.rs`-globbing LOC tools skip a `.inc`. Phase 281 criterion 3 is unsatisfiable as written and is marked superseded. Do not repeat the claim in 282/283.
- OPEN, filed from phase 281's final review: a vacuous-verification bug in replay, proven pre-existing. `ReplayScenarioClass` derives `Default` with `#[default] Mixed` and `ReplayScenarioMetadata.class` is `#[serde(default)]`, while `verify_known_bad_coverage` requires `class == Adversarial` and `verify_false_positive_bound` filters on `scenario_is_benign`. A manifest omitting `class:` is exempt from BOTH invariants and passes vacuously.
- Phase 284 COMPLETE 2026-08-11 (FIXTURE-01..04). The suite no longer writes into the repository: a full G1+G2 leaves all four drift assertions clean. Parallel phase work is now unblocked.
- The kitten_agent flake was NOT prior-run state. `Option::unwrap_or` evaluates eagerly, so `load_source_seed` scanned every manifest under `experiments/` even when given an override, racing four `mutation::tests_autonomous` tests that write transient files there. 11 failures in 107 runs.
- The CI drift gate now carries four assertions; the fourth (no empty directories anywhere) is unscoped and is what catches leaks the path-scoped checks miss.
- Phase 320 is 2/4: QRT-01 and QRT-02 shipped in 4d03543. QRT-03 (TTL sweep) and QRT-04 (`swarmctl quarantine release`) remain.
- Phase 321 is 2/5, NOT complete: f55c3bd's own message says "Implements BFT-01 and BFT-02". BFT-03 (remove `simulate_governance_commit`'s co-located-key path, still live at `crates/swarm-runtime/src/tom_agent.rs:1147`), BFT-04, and BFT-05 remain.
- Phase 322 cannot run where it is sequenced: it gates `crates/swarm-evolution/src/promotion.rs`, which does not exist on the merged tree (`swarm-evolution` is the 8-line facade). Phase 282 must restore real source first.
- BFT-04 has no matching success criterion in the phase 321 ROADMAP block; criteria 1-4 cover BFT-01, BFT-02, BFT-03, BFT-05 only.
- Phases 295, 300, and 304 are orphan roadmap rows with no body block and no mapped requirements; they are superseded by 322, 321, and 320 respectively.
- `.gitignore` covers `crates/swarm-runtime/data/evolution-assurance-cases/reports/` but not the `crates/swarm-evolution/` twin, and the tracked `index.json` points at gitignored directories, so it dangles on a clean clone.
- v1.74 remains deferred rather than completed; its structural-integrity work is preserved for later re-activation.

## Next Command

Plan and execute Phase 282 (Crate Extraction From swarm-runtime). It now also owns INCFIX-02 and crates/swarm-cli/src/core.inc.
