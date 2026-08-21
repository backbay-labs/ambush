---
phase: 286
slug: collective-hypothesis-graph
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-08-21
---

# Phase 286 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust libtest through `cargo test`; existing `proptest` for properties and `trybuild` for compile-boundary tests |
| **Config file** | Workspace `Cargo.toml`; strict benchmark manifest exists at `scenarios/collective-hypothesis-graph/manifest.yaml` from GSD preflight |
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
| 286-00-01 | 00 | 1 | COG-02, COG-04, COG-05, COG-08 | sealed strict adjudicated oracle + pinned digests | `cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict -- --exact` | ✅ | ✅ green |
| 286-00-02 | 00 | 1 | COG-01..COG-07 | integration and authority-test infrastructure | `cargo test -p swarm-runtime --test negative_graph_response_boundary boundary_checker_rejects_broken_fixture -- --exact` | ✅ | ✅ green |
| 286-00-03 | 00 | 1 | COG-01..COG-08 | exact gate infrastructure + adversarial self-test | `bash -n tools/check-collective-hypothesis-graph.sh && bash tools/check-collective-hypothesis-graph.sh --self-test` | ✅ | ✅ green |
| 286-01-01 | 01 | 2 | COG-01, COG-04 | strict schema + property + negative | `cargo test -p swarm-core hypothesis_graph --lib` | ⬜ not created | ⬜ pending |
| 286-01-02 | 01 | 2 | COG-02, COG-03, COG-05, COG-06, COG-07 | contract/state-machine unit | `cargo test -p swarm-core hypothesis_graph --lib` | ⬜ not created | ⬜ pending |
| 286-01-03 | 01 | 2 | COG-01..COG-07 | fail-closed config | `cargo test -p swarm-core config::tests::hypothesis_graph --lib` | ⬜ not created | ⬜ pending |
| 286-02-01 | 02 | 3 | COG-03, COG-08 | injected logical clock + scheduler perturbation | `cargo test -p swarm-runtime hypothesis_graph::clock --lib` | ⬜ not created | ⬜ pending |
| 286-02-02 | 02 | 3 | COG-04 | adapter unit | `cargo test -p swarm-runtime hypothesis_graph::normalize --lib` | ⬜ not created | ⬜ pending |
| 286-02-03 | 02 | 3 | COG-01, COG-04 | cross-source witness/conflict integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact cross_telemetry_fixture_preserves_conflicts --nocapture` | ⬜ not created | ⬜ pending |
| 286-03-01 | 03 | 3 | COG-01, COG-03 | ledger state machine | `cargo test -p swarm-spine hypothesis_graph_store --lib` | ⬜ not created | ⬜ pending |
| 286-03-02 | 03 | 3 | COG-03 | file CAS/restart/backend parity | `cargo test -p swarm-spine hypothesis_graph_store --lib` | ⬜ not created | ⬜ pending |
| 286-03-03 | 03 | 3 | COG-07 | signed memory/privacy | `cargo test -p swarm-spine strategy_memory --lib` | ⬜ not created | ⬜ pending |
| 286-04-01 | 04 | 4 | COG-02, COG-03 | reasoning state machine | `cargo test -p swarm-runtime hypothesis_graph::hypotheses --lib && cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact ambiguous_seed_retains_competing_hypotheses --nocapture` | ⬜ not created | ⬜ pending |
| 286-04-02 | 04 | 4 | COG-05 | withheld-evidence integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact withheld_kill_chain_reports_missing_evidence --nocapture` | ⬜ not created | ⬜ pending |
| 286-04-03 | 04 | 4 | COG-06 | simulation + negative authority boundary | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact containment_plan_is_simulation_only --nocapture && cargo test -p swarm-runtime --test negative_graph_response_boundary` | ⬜ not created | ⬜ pending |
| 286-05-01 | 05 | 5 | COG-03 | real-agent ledger integration | `cargo test -p swarm-agents stalker_agent --lib && cargo test -p swarm-agents weaver_agent --lib` | ⬜ not created | ⬜ pending |
| 286-05-02 | 05 | 5 | COG-03 | 100-task concurrency/restart | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact duplicate_claim_fixture_100 --nocapture` | ⬜ not created | ⬜ pending |
| 286-05-03 | 05 | 5 | COG-07 | memory replay/prioritization | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact memory_replay_changes_priority_deterministically --nocapture` | ⬜ not created | ⬜ pending |
| 286-06-01 | 06 | 6 | COG-01..COG-07 | enabled real-runtime end to end + disabled legacy-path regression | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact seed_signal_converges_through_real_runtime --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact disabled_hypothesis_graph_preserves_legacy_runtime --nocapture` | ⬜ not created | ⬜ pending |
| 286-06-02 | 06 | 6 | COG-06 | full policy/governance/operator/receipt/dispatcher handoff + mutations | `cargo test -p swarm-runtime --test graph_authority_handoff selected_simulation_requires_full_existing_authority_chain -- --exact --test-threads=1 && cargo test -p swarm-runtime --test negative_graph_response_boundary` | ⬜ not created | ⬜ pending |
| 286-06-03 | 06 | 6 | COG-01, COG-05, COG-06 | authenticated additive operator integration + disabled byte-shape regression | `cargo test -p swarm-runtime-http hypothesis_graph --lib && cargo test -p swarm-runtime-http disabled_hypothesis_graph_preserves_existing_operator_shapes --lib` | ⬜ not created | ⬜ pending |
| 286-06-04 | 06 | 6 | COG-01, COG-02, COG-05, COG-06, COG-07 | CLI parser/render | `cargo test -p swarm-cli hypothesis_graph --lib` | ⬜ not created | ⬜ pending |
| 286-07-01 | 07 | 7 | COG-02, COG-04, COG-05, COG-08 | strict truth corpus | `cargo test -p swarm-runtime hypothesis_graph::benchmark::tests::manifest --lib` | ⬜ not created | ⬜ pending |
| 286-07-02 | 07 | 7 | COG-03, COG-08 | deterministic paired benchmark + host-clock/scheduler perturbation | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact collective_reasoning_beats_single_agent_baseline --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact host_clock_and_scheduler_perturbation_do_not_change_verdict --nocapture` | ⬜ not created | ⬜ pending |
| 286-07-03 | 07 | 7 | COG-01..COG-08 | exact mutation-controlled phase gate | `bash tools/check-collective-hypothesis-graph.sh` | ⬜ not created | ⬜ pending |
| 286-07-04 | 07 | 7 | COG-01..COG-08 | independent P0/P1/P2 + goal-backward verification | `bash tools/check-collective-hypothesis-graph.sh && cargo test --workspace --all-targets --locked && cargo clippy --workspace --all-targets --all-features -- -D warnings` | ⬜ not created | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## GSD Preflight Requirements

- [x] `crates/swarm-runtime/tests/collective_hypothesis_oracle.rs` — sealed strict fixture parser, semantic mutations, and pinned digest verification owned only by Plan 00.
- [x] `crates/swarm-runtime/tests/negative_graph_response_boundary.rs` — mutation-tested boundary scanner in Plan 00, then real graph-module coverage in Plan 04/06.
- [x] `scenarios/collective-hypothesis-graph/manifest.yaml` and fixtures — six telemetry families, corroboration/conflict, ambiguity, withheld stage, adjudicated truth, fixed logical clock, 100-task duplicate case (Plan 00).
- [x] `docs/benchmarks/collective-hypothesis-graph-baseline.json` — explicit denominators, pinned oracle digests, single-agent baseline, and deterministic threshold values (Plan 00).
- [x] `tools/check-collective-hypothesis-graph.sh` — complete exact-test/report/mutation gate installed by Plan 00 and made green by Plan 07; `--self-test` proves zero-test/count, schema, threshold, oracle, authority, and wall-clock failure modes before implementation.

`wave_0_complete` is the GSD preflight-infrastructure flag, not the numeric execution wave. It becomes true only when the five items above exist and self-test; later behavior remains pending.

## Scheduled Behavior Validation Artifacts

- [ ] `crates/swarm-core/src/hypothesis_graph.rs` unit/property tests — Plan 01.
- [ ] `crates/swarm-runtime/src/hypothesis_graph/clock.rs` injected clock/scheduler tests — Plan 02.
- [ ] `crates/swarm-spine/src/hypothesis_graph_store.rs` backend parity/fencing/restart tests — Plan 03.
- [ ] `crates/swarm-spine/src/strategy_memory.rs` privacy/replay/retrieval tests — Plan 03.
- [ ] `crates/swarm-runtime/tests/collective_hypothesis_graph.rs` behavior integrations only — Plans 02-07; it cannot own oracle truth.
- [ ] `crates/swarm-runtime/tests/graph_authority_handoff.rs` full existing-authority-chain proof — Plan 06.

No framework installation is required; all test dependencies are already locked in the workspace.

---

## Manual-Only Verifications

All phase behaviors have automated verification. Operator-facing artifact readability may receive an additional manual review, but it is not an acceptance substitute.

---

## Validation Sign-Off

- [x] All planned tasks have an automated verification command or an explicit GSD preflight dependency.
- [ ] Sampling continuity: no three consecutive implementation tasks lack an automated check.
- [x] GSD preflight covers every missing test, fixture, and benchmark reference it owns; later behavior artifacts have explicit plan ownership.
- [ ] No watch-mode flags are used.
- [ ] Deterministic verdicts exclude wall-clock measurements; wall-clock data is labeled observational.
- [ ] Exact test execution is asserted so zero matched tests cannot pass the gate.
- [ ] Targeted feedback latency is under 90 seconds.
- [x] `nyquist_compliant: true` is set after the plan/checker aligned task IDs, dependencies, and commands.

**Approval:** approved 2026-08-21; GSD preflight complete, behavior execution pending
