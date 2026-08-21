---
phase: 286
slug: collective-hypothesis-graph
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-21
---

# Phase 286 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust libtest through `cargo test`; existing `proptest` for properties and `trybuild` for compile-boundary tests |
| **Config file** | Workspace `Cargo.toml`; strict benchmark manifest to be added at `scenarios/collective-hypothesis-graph/manifest.yaml` in Wave 0 |
| **Quick run command** | `cargo test -p swarm-core hypothesis_graph --lib && cargo test -p swarm-spine hypothesis_graph --lib && cargo test -p swarm-runtime hypothesis_graph --lib` |
| **Full suite command** | `cargo test --workspace --all-targets --locked && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check` |
| **Estimated runtime** | Quick checks under 90 seconds after warm compilation; full combined-tree gate approximately 4 minutes |

---

## Sampling Rate

- **After every task commit:** Run the narrowest exact test named by the task, plus `cargo fmt --all -- --check` and `git diff --check`.
- **After every plan wave:** Run the quick graph package command and every completed exact integration test in `collective_hypothesis_graph`.
- **Before `$gsd-verify-work`:** `bash tools/check-collective-hypothesis-graph.sh` and the full combined-tree suite must be green.
- **Max feedback latency:** 90 seconds for targeted checks; the full suite is an explicit wave/phase gate.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 286-W0-01 | TBD | 0 | COG-01, COG-02, COG-04 | strict schema + property | `cargo test -p swarm-core hypothesis_graph --lib` | ❌ W0 | ⬜ pending |
| 286-W0-02 | TBD | 0 | COG-03, COG-07 | store parity + restart + adversarial CAS | `cargo test -p swarm-spine hypothesis_graph --lib` | ❌ W0 | ⬜ pending |
| 286-W0-03 | TBD | 0 | COG-01..COG-08 | integration fixture seam | `cargo test -p swarm-runtime --test collective_hypothesis_graph` | ❌ W0 | ⬜ pending |
| 286-COG-01 | TBD | TBD | COG-01 | unit + property + negative | `cargo test -p swarm-core hypothesis_graph --lib` | ❌ W0 | ⬜ pending |
| 286-COG-02 | TBD | TBD | COG-02 | state-machine unit | `cargo test -p swarm-runtime hypothesis_competing --lib` | ❌ W0 | ⬜ pending |
| 286-COG-03 | TBD | TBD | COG-03 | two-writer/restart integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact duplicate_claim_fixture_100 --nocapture` | ❌ W0 | ⬜ pending |
| 286-COG-04 | TBD | TBD | COG-04 | adapter + cross-source integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact cross_telemetry_fixture_preserves_conflicts --nocapture` | ❌ W0 | ⬜ pending |
| 286-COG-05 | TBD | TBD | COG-05 | withheld-evidence integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact withheld_kill_chain_reports_missing_evidence --nocapture` | ❌ W0 | ⬜ pending |
| 286-COG-06 | TBD | TBD | COG-06 | unit + negative authority boundary | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact containment_plan_is_simulation_only --nocapture && cargo test -p swarm-runtime --test negative_graph_response_boundary` | ❌ W0 | ⬜ pending |
| 286-COG-07 | TBD | TBD | COG-07 | signed store/replay/privacy integration | `cargo test -p swarm-spine strategy_memory --lib && cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact memory_replay_changes_priority_deterministically --nocapture` | ❌ W0 | ⬜ pending |
| 286-COG-08 | TBD | TBD | COG-08 | deterministic benchmark + mutation controls | `bash tools/check-collective-hypothesis-graph.sh` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/swarm-core/src/hypothesis_graph.rs` unit/property test module — strict schemas, stable IDs, resource limits, competing-hypothesis primitives, malformed-edge controls.
- [ ] `crates/swarm-spine/src/hypothesis_graph_store.rs` tests — memory/file parity, restart, tamper, same-sequence/different-digest CAS, lease fencing, stale completion.
- [ ] `crates/swarm-spine/src/strategy_memory.rs` tests — signed redacted memory, replay rejection, bounded retrieval.
- [ ] `crates/swarm-runtime/tests/collective_hypothesis_graph.rs` — exact integration tests covering COG-01..08.
- [ ] `crates/swarm-runtime/tests/negative_graph_response_boundary.rs` — graph planning cannot import or reach response execution/authority.
- [ ] `scenarios/collective-hypothesis-graph/manifest.yaml` and fixtures — six telemetry families, corroboration/conflict, ambiguity, withheld stage, adjudicated truth, fixed logical clock, 100-task duplicate case.
- [ ] `docs/benchmarks/collective-hypothesis-graph-baseline.json` — explicit denominators and deterministic threshold values.
- [ ] `tools/check-collective-hypothesis-graph.sh` — exact-test execution assertion, report-schema validation, threshold comparison, and negative manifest/test-name mutations.

No framework installation is required; all test dependencies are already locked in the workspace.

---

## Manual-Only Verifications

All phase behaviors have automated verification. Operator-facing artifact readability may receive an additional manual review, but it is not an acceptance substitute.

---

## Validation Sign-Off

- [ ] All planned tasks have an automated verification command or an explicit Wave 0 dependency.
- [ ] Sampling continuity: no three consecutive implementation tasks lack an automated check.
- [ ] Wave 0 covers every missing test, fixture, and benchmark reference.
- [ ] No watch-mode flags are used.
- [ ] Deterministic verdicts exclude wall-clock measurements; wall-clock data is labeled observational.
- [ ] Exact test execution is asserted so zero matched tests cannot pass the gate.
- [ ] Targeted feedback latency is under 90 seconds.
- [ ] `nyquist_compliant: true` is set after the plan/checker aligns task IDs and commands.

**Approval:** pending plan checker
