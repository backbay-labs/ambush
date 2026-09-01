---
phase: 286
slug: collective-hypothesis-graph
status: approved
nyquist_compliant: true
preflight_complete: true
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
| **Quick run command** | `cargo test -p swarm-core hypothesis_graph --lib --locked --offline && cargo test -p swarm-spine hypothesis_graph --lib --locked --offline && cargo test -p swarm-runtime hypothesis_graph --lib --locked --offline` |
| **Full suite command** | `cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check` |
| **Estimated runtime** | Quick checks under 90 seconds after warm compilation; full combined-tree gate approximately 4 minutes |

---

## Sampling Rate

- **After every task commit:** Run the narrowest exact test named by the task, plus `cargo fmt --all -- --check` and `git diff --check`.
- **After every plan wave:** Run the quick graph package command and every completed exact integration test in `collective_hypothesis_graph`.
- **Before `$gsd-verify-work`:** `bash tools/check-collective-hypothesis-graph.sh` and the full combined-tree suite must be green.
- **Max feedback latency:** 90 seconds for targeted checks; the full suite is an explicit wave/phase gate.

---

## Per-Task Verification Map

The matrix columns are the strict per-task contract: `Test Type` names the
positive and negative/mutation control, `Automated Command` is the executable
checker, `Artifact Evidence` records whether the owned artifacts are verified,
and `Status` records
the evidence state. `tools/check-phase286-validation-matrix.py --strict`
cross-checks these rows against every task in every current Phase 286 plan;
its self-test proves missing, duplicate, ambiguous, watch-mode, and empty-cell
mutations fail closed.

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | Artifact Evidence | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 286-00-01 | 00 | 1 | COG-02, COG-04, COG-05, COG-08 | sealed strict adjudicated oracle + pinned digests | `cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict --locked --offline -- --exact` | ✅ | ✅ green |
| 286-00-02 | 00 | 1 | COG-01..COG-07 | integration and authority-test infrastructure | `cargo test -p swarm-runtime --test negative_graph_response_boundary boundary_checker_rejects_broken_fixture --locked --offline -- --exact` | ✅ | ✅ green |
| 286-00-03 | 00 | 1 | COG-01..COG-08 | exact gate infrastructure + adversarial self-test | `bash -n tools/check-collective-hypothesis-graph.sh && bash tools/check-collective-hypothesis-graph.sh --self-test && cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict --locked --offline -- --exact && cargo test -p swarm-runtime --test negative_graph_response_boundary boundary_checker_rejects_broken_fixture --locked --offline -- --exact && git diff --check` | ✅ | ✅ green |
| 286-00B-01 | 00B | 2 | COG-08 | validation matrix ownership, metadata binding, fail-closed mutations, and preflight/execution terminology | `python3 tools/check-phase286-validation-matrix.py --strict --self-test --cwd . && git diff --check` | ✅ | ✅ green |
| 286-01-01 | 01 | 3 | COG-01, COG-04 | strict schema + property + negative | `cargo test -p swarm-core hypothesis_graph --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-01-02 | 01 | 3 | COG-02, COG-03, COG-05, COG-06, COG-07 | contract/state-machine unit | `cargo test -p swarm-core hypothesis_graph --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-01-03 | 01 | 3 | COG-01..COG-07 | fail-closed config | `cargo test -p swarm-core config::tests::hypothesis_graph --lib --locked --offline && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-01B-01 | 01B | 4 | COG-01..COG-03 | runtime support config migration and signed/default compatibility mutation tests | `cargo test -p swarm-runtime --lib --locked --offline canary::tests::canary_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo test -p swarm-runtime --lib --locked --offline promotion::tests::promotion_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo test -p swarm-runtime --lib --locked --offline service::tests::service_support_config_preserves_disabled_graph_and_legacy_runtime_bytes -- --exact --nocapture && cargo fmt --all -- --check && git diff --check` | ✅ | ✅ green |
| 286-02-01 | 02 | 5 | COG-03, COG-08 | injected logical clock + scheduler perturbation | `cargo test -p swarm-runtime hypothesis_graph::clock --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-02-02 | 02 | 5 | COG-04 | adapter unit | `cargo test -p swarm-runtime hypothesis_graph::normalize --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-02-03 | 02 | 5 | COG-01, COG-04 | cross-source witness/conflict integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact graph_record_signer_binds_edge_and_decision --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact cross_telemetry_fixture_preserves_conflicts --nocapture` | ⬜ pending | ⬜ pending |
| 286-03-01 | 03 | 5 | COG-01, COG-03 | ledger state machine | `cargo test -p swarm-spine hypothesis_graph_store --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-03-02 | 03 | 5 | COG-03 | file CAS/restart/backend parity | `cargo test -p swarm-spine hypothesis_graph_store --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-03-03 | 03 | 5 | COG-07 | signed memory/privacy | `cargo test -p swarm-spine strategy_memory --lib --locked --offline && cargo clippy -p swarm-spine --all-targets --locked --offline -- -D warnings` | ⬜ pending | ⬜ pending |
| 286-01C-01 | 01C | 6 | COG-03, COG-07 | post-Plan-03 core task lineage/capability/TTL contract | `cargo test -p swarm-core hypothesis_graph --lib --locked --offline -- --test-threads=1` | ⬜ pending | ⬜ pending |
| 286-01C-02 | 01C | 6 | COG-06, COG-08 | policy mode, scheduler direction, and budget mutation | `cargo test -p swarm-core hypothesis_graph --lib --locked --offline -- --test-threads=1` | ⬜ pending | ⬜ pending |
| 286-01C-03 | 01C | 6 | COG-07, COG-08 | logical StrategyMemory expiry/config bounds | `cargo test -p swarm-core config::tests::hypothesis_graph --lib --locked --offline && cargo test -p swarm-core hypothesis_graph --lib --locked --offline && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-01D-01 | 01D | 7 | COG-01, COG-03, COG-04, COG-08 | source-record EventNode identity and signed/untrusted witness mutation regressions | `cargo test -p swarm-core --lib --locked --offline hypothesis_graph::tests::event_node_same_time_different_source_records_are_distinct -- --exact --test-threads=1 && cargo test -p swarm-core --lib --locked --offline hypothesis_graph::tests::unsigned_witness_is_untrusted -- --exact --test-threads=1` | ⬜ pending | ⬜ pending |
| 286-01D-02 | 01D | 7 | COG-01, COG-03, COG-04, COG-08 | validated direct payload deserialize and checked graph-version overflow mutations | `cargo test -p swarm-core --lib --locked --offline hypothesis_graph::tests::typed_evidence_payload_direct_deserialize_is_validated -- --exact --test-threads=1 && cargo test -p swarm-core --lib --locked --offline hypothesis_graph::tests::graph_version_overflow_is_fail_closed -- --exact --test-threads=1 && cargo test -p swarm-core config::tests::hypothesis_graph --lib --locked --offline && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-02B-01 | 02B | 7 | COG-01, COG-03 | admitted-key capability and witness role/scope boundary | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact unadmitted_graph_signer_is_rejected --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact role_scope_mutation_invalidates_witness --nocapture && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-02B-02 | 02B | 7 | COG-01, COG-04 | source-record-bound EventNode adapter with preserved CloudTrail regression | `cargo test -p swarm-runtime hypothesis_graph::normalize --lib --locked --offline && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact event_node_same_time_different_source_records_are_distinct --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact cloudtrail_unknown_identity_is_event_scoped --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact typed_evidence_payload_direct_deserialize_is_validated --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact graph_version_overflow_is_fail_closed --nocapture` | ⬜ pending | ⬜ pending |
| 286-02B-03 | 02B | 7 | COG-03, COG-08 | logical scheduler future-task non-consumption | `cargo test -p swarm-runtime hypothesis_graph::clock --lib --locked --offline && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact future_task_is_not_consumed_before_ready_time --nocapture && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-03B-01 | 03B | 7 | COG-03 | post-Plan-03 task validation at existing CAS seam | `cargo test -p swarm-spine hypothesis_graph_store --lib --locked --offline -- --test-threads=1` | ⬜ pending | ⬜ pending |
| 286-03B-02 | 03B | 7 | COG-07 | logical memory expiry backend parity | `cargo test -p swarm-spine strategy_memory --lib --locked --offline -- --test-threads=1 && cargo test -p swarm-spine --test reasoning_state_contract --locked --offline -- --exact strategy_memory_expiry_is_backend_identical --nocapture` | ⬜ pending | ⬜ pending |
| 286-03B-03 | 03B | 7 | COG-03, COG-08 | post-Plan-03 compile/mutation boundary | `cargo test -p swarm-spine --test reasoning_state_contract --locked --offline && cargo clippy -p swarm-spine --all-targets --locked --offline -- -D warnings && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-04-01 | 04 | 8 | COG-02, COG-03 | explicit neutral seed/assessment, durable hypothesis map + decision history, signed terminal CAS/high-water/migration round-trip | `cargo test -p swarm-core hypothesis_graph --lib --locked --offline && cargo test -p swarm-runtime --lib hypothesis_graph::hypotheses --locked --offline && for task_test in hypothesis_graph::tasks::tests::coordinator_durably_commits_competing_tasks_once hypothesis_graph::tasks::tests::coordinator_persists_signed_support_challenge_and_falsify_histories hypothesis_graph::tasks::tests::coordinator_rejects_caller_signed_decision_before_cas hypothesis_graph::tasks::tests::coordinator_signs_empty_support_with_admitted_signer hypothesis_graph::tasks::tests::descriptor_identity_excludes_claimant_retry_fields hypothesis_graph::tasks::tests::failed_budget_probe_is_byte_identical hypothesis_graph::tasks::tests::forced_claim_cas_refusal_rolls_back_budget hypothesis_graph::tasks::tests::forced_coordinator_cas_refusal_rolls_back_budget hypothesis_graph::tasks::tests::forced_task_cas_refusal_rolls_back_budget hypothesis_graph::tasks::tests::forced_terminal_cas_refusal_after_validation_is_byte_identical hypothesis_graph::tasks::tests::rejected_claim_does_not_charge_budget hypothesis_graph::tasks::tests::restart_and_state_deserialize_restore_budget_without_reset hypothesis_graph::tasks::tests::restart_preserves_claim_usage_and_idempotent_retry_does_not_recharge hypothesis_graph::tasks::tests::unadmitted_signer_cannot_construct_coordinator_authority hypothesis_graph::tasks::tests::unsupported_budget_backend_fails_closed_without_mutation; do cargo test -p swarm-runtime --lib --locked --offline -- --exact "$task_test" --nocapture \|\| exit 1; done && for test_name in ambiguous_seed_retains_competing_hypotheses normalized_seed_remains_unresolved terminal_publication_is_atomic terminal_memory_is_not_visible_before_outbox_cas stale_terminal_publishes_nothing challenge_completion_retains_edge_lineage falsification_completion_retains_hypothesis_lineage claimant_key_and_completion_kind_are_checked logical_task_descriptor_is_persisted_and_verified same_logical_descriptor_is_idempotent different_seed_creates_distinct_task logical_task_id_is_not_claimant_idempotency production_complete_task_enforces_signed_lineage coordinator_uses_config_bound_budget_per_logical_tick; do cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact "$test_name" --nocapture \|\| exit 1; done && for spine_test in hypothesis_graph_store::tests::legacy_signed_bytes_are_verified_before_reasoning_defaults hypothesis_graph_store::tests::legacy_graph_state_migrates_v0_to_v1_preserving_logical_time_high_water hypothesis_graph_store::tests::unknown_graph_state_migration_marker_is_rejected hypothesis_graph_store::tests::spine_rejects_tampered_intrinsic_witness; do cargo test -p swarm-spine --lib --locked --offline -- --exact "$spine_test" --nocapture \|\| exit 1; done` | ⬜ pending | ⬜ pending |
| 286-04-02 | 04 | 8 | COG-05 | withheld-evidence integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact withheld_kill_chain_reports_missing_evidence --nocapture` | ⬜ pending | ⬜ pending |
| 286-04-03 | 04 | 8 | COG-06 | simulation + synthetic-target mutation + negative authority boundary | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact containment_plan_is_simulation_only --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact containment_rejects_synthetic_target_node --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact containment_rejects_duplicate_unknown_and_malformed_ids --nocapture && cargo test -p swarm-runtime --test negative_graph_response_boundary --locked --offline` | ⬜ pending | ⬜ pending |
| 286-05-01 | 05 | 9 | COG-03 | real-agent ledger integration + identity/outbox controls | `cargo test -p swarm-agents stalker_agent --lib --locked --offline && cargo test -p swarm-agents weaver_agent --lib --locked --offline && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact producer_identity_is_key_derived_and_admitted --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact terminal_outbox_precedes_publication --nocapture` | ⬜ pending | ⬜ pending |
| 286-05-02 | 05 | 9 | COG-03 | 100-task concurrency/restart/duplicate/fence controls | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact duplicate_claim_fixture_100 --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact duplicate_claim_fixture_100_reversed_order_is_byte_identical --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact restart_reclaim_fences_stale_worker --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact one_terminal_result_per_logical_task --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact scheduler_priority_and_budget_are_deterministic --nocapture` | ⬜ pending | ⬜ pending |
| 286-05-03 | 05 | 9 | COG-07 | memory replay/prioritization, expiry, authority, and CAS controls | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact memory_replay_changes_priority_deterministically --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact memory_expiry_is_logical_and_fail_closed --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact memory_cannot_change_confidence_or_authority --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact memory_forced_cas_failure_publishes_nothing --nocapture` | ⬜ pending | ⬜ pending |
| 286-06-01 | 06 | 10 | COG-01..COG-07 | enabled service/runtime wiring + projection + disabled legacy-path regression | `cargo test -p swarm-runtime --lib hypothesis_graph --locked --offline && cargo test -p swarm-runtime --test graph_incident_projection --locked --offline -- --exact graph_projection_preserves_digest_and_evidence_links --nocapture && cargo test -p swarm-ingest-runtime --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-06-02 | 06 | 10 | COG-06 | full policy/governance/operator/receipt/dispatcher handoff + exact production-boundary mutation coverage | `cargo test -p swarm-runtime --test graph_authority_handoff --locked --offline -- selected_simulation_requires_full_existing_authority_chain --exact --test-threads=1 && cargo test -p swarm-runtime --test negative_graph_response_boundary --locked --offline -- production_graph_modules_preserve_response_authority_boundary --exact && cargo test -p swarm-runtime --test negative_graph_response_boundary --locked --offline -- boundary_checker_rejects_broken_fixture --exact` | ⬜ pending | ⬜ pending |
| 286-06-03 | 06 | 10 | COG-01, COG-05, COG-06 | ingest-side handoff and graph-enabled/disabled refusal | `cargo test -p swarm-ingest-runtime --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-06C-01 | 06C | 11 | COG-06, COG-07 | authenticated HTTP, deterministic CLI, read-only surface/refusal controls | `cargo test -p swarm-runtime-http hypothesis_graph --lib --locked --offline && cargo test -p swarm-cli hypothesis_graph --lib --locked --offline && cargo test -p swarm-runtime --test collective_hypothesis_graph_surface --locked --offline -- --exact authenticated_graph_surface_is_read_only --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph_surface --locked --offline -- --exact disabled_or_tampered_graph_is_refused --nocapture && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-06B-01 | 06B | 11 | COG-01, COG-02, COG-05, COG-06, COG-07 | one-shot/no-action handoff, zero authority calls, and event-local counter mutation proofs | `cargo test -p swarm-runtime --test phase286_bridge_handoff --locked --offline -- --exact no_action_returns_zero_authority_calls --nocapture && cargo test -p swarm-runtime --test phase286_bridge_handoff --locked --offline -- --exact one_graph_result_feeds_outcome_and_planner --nocapture && cargo test -p swarm-runtime --test phase286_bridge_handoff --locked --offline -- --exact second_event_uses_independent_deltas --nocapture && cargo test -p swarm-runtime --test phase286_bridge_handoff --locked --offline -- --exact no_finding_returns_no_capture --nocapture` | ⬜ pending | ⬜ pending |
| 286-06B-02 | 06B | 11 | COG-01, COG-02, COG-05, COG-06, COG-07 | post-Plan-06 public Phase 286 compile contract | `cargo test -p swarm-runtime --test collective_hypothesis_graph_contract --locked --offline -- --exact public_phase286_graph_contract_compiles --nocapture` | ⬜ pending | ⬜ pending |
| 286-07-01 | 07 | 12 | COG-02, COG-04, COG-05, COG-08 | strict truth corpus | `cargo test -p swarm-runtime hypothesis_graph::benchmark::tests::manifest --lib --locked --offline` | ⬜ pending | ⬜ pending |
| 286-07-02 | 07 | 12 | COG-03, COG-08 | deterministic paired benchmark + host-clock/scheduler perturbation | `cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact collective_reasoning_beats_single_agent_baseline --nocapture && cargo test -p swarm-runtime --test collective_hypothesis_graph --locked --offline -- --exact host_clock_and_scheduler_perturbation_do_not_change_verdict --nocapture` | ⬜ pending | ⬜ pending |
| 286-07-03 | 07 | 12 | COG-01..COG-08 | exact locked/offline mutation-controlled gate, baseline/digest/seed/HEAD provenance, retained reports, bridge and authority controls | `python3 tools/check-phase286-validation-matrix.py --strict --self-test --cwd . && bash tools/check-collective-hypothesis-graph.sh && cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |
| 286-07B-01 | 07B | 13 | COG-08 | independent parser recomputing P0/P1/P2 from both artifacts, current-HEAD evidence, and combined-tree verification | `python3 tools/check-phase286-review.py --root . --self-test && bash tools/check-collective-hypothesis-graph.sh && cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check && git diff --check` | ⬜ pending | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## GSD Preflight Requirements

- [x] `crates/swarm-runtime/tests/collective_hypothesis_oracle.rs` — sealed strict fixture parser, semantic mutations, and pinned digest verification owned only by Plan 00.
- [x] `crates/swarm-runtime/tests/negative_graph_response_boundary.rs` — mutation-tested boundary scanner in Plan 00, then real graph-module coverage in Plan 04/06.
- [x] `scenarios/collective-hypothesis-graph/manifest.yaml` and fixtures — six telemetry families, corroboration/conflict, ambiguity, withheld stage, adjudicated truth, fixed logical clock, 100-task duplicate case (Plan 00).
- [x] `docs/benchmarks/collective-hypothesis-graph-baseline.json` — explicit denominators, pinned oracle digests, single-agent baseline, and deterministic threshold values (Plan 00).
- [x] `tools/check-collective-hypothesis-graph.sh` — complete exact-test/report/mutation gate installed by Plan 00 and made green by Plan 07; `--self-test` proves zero-test/count, schema, threshold, oracle, authority, and wall-clock failure modes before implementation.
- [ ] `tools/check-phase286-review.py` — Plan 07B's independent parser; it recomputes severity counts from both review artifacts, binds them to the current HEAD/tree digest, rejects summary-only self-attestation, and runs its own mutation self-test.
- [ ] `.github/workflows/ci.yml` — Plan 07's credential-free Phase 286 job runs the direct locked/offline closure commands and uploads retained machine-readable reports/evidence.

`preflight_complete` is the authoritative GSD preflight-infrastructure flag. `wave_0_complete` is retained for compatibility and means exactly the same thing: Plans 00 and 00B's preflight artifacts exist and self-test. It is not numeric execution-wave completion. Preflight waves are 1 (Plan 00) and 2 (Plan 00B); execution waves 3 through 13 remain pending until their per-task rows and final evidence pass. Supplementary 01C and 03B are execution plans, not preflight markers.

## Scheduled Behavior Validation Artifacts

- [ ] `crates/swarm-core/src/hypothesis_graph.rs` unit/property tests — Plan 01.
- [ ] `crates/swarm-runtime/src/hypothesis_graph/clock.rs` injected clock/scheduler tests — Plan 02.
- [ ] `crates/swarm-spine/src/hypothesis_graph_store.rs` backend parity/fencing/restart tests — Plan 03.
- [ ] `crates/swarm-spine/src/strategy_memory.rs` privacy/replay/retrieval tests — Plan 03.
- [ ] `crates/swarm-runtime/tests/collective_hypothesis_graph.rs` behavior integrations only — Plans 02-07; it cannot own oracle truth.
- [ ] `crates/swarm-runtime/tests/graph_authority_handoff.rs` full existing-authority-chain proof — Plan 06.
- [ ] `crates/swarm-runtime/tests/collective_hypothesis_graph_contract.rs` and `phase286_bridge_handoff.rs` — Plan 06B only, after Plan 06 owns the bridge, planner, receipt, and configured-stack symbols.
- [ ] `.planning/phases/286-collective-hypothesis-graph/286-VALIDATION-EVIDENCE.md` and `286-07-SUMMARY.md` — Plan 07's retained exact command, passed/failed count, report digest, and current-HEAD provenance records.
- [ ] `.planning/phases/286-collective-hypothesis-graph/286-P0-P2-REVIEW.md`, `286-VERIFICATION.md`, and `286-07B-SUMMARY.md` — Plan 07B only; independent severity and goal-backward closure artifacts, with no verification-artifact ownership in Plan 07.

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

Plan 02 owns the historical normalization/clock implementation; additive Plan
02B owns only the post-01C corrective pass over those same runtime files and
does not create a second normalizer or clock. Neither owns the cross-phase
compile artifact. Plan 06B is deliberately scheduled after Plan 06
so the compile contract, no-action zero-call proof, and single-execution
counter test cannot pass against a pre-implementation sketch of the graph API.
Plan 06C owns the HTTP/CLI and real integration target; Plan 07 consumes 06B
and 06C; Plan 07B is the independent final review/verification gate.

**Approval:** approved 2026-08-21; GSD preflight complete, behavior execution pending. Closure plans were reconciled 2026-08-22: Plan 07 owns the final locked/offline gate, CI wiring, retained reports, validation evidence, and `286-07-SUMMARY.md`; Plan 07B exclusively owns the independent severity parser, `286-VERIFICATION.md`, and `286-07B-SUMMARY.md`.
