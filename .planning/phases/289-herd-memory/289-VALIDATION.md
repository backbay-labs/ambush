---
phase: 289-herd-memory
slug: herd-memory
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-21
---

# Phase 289 — Validation Strategy

> Validation contract for privacy-minimized, registry-trusted herd memory. The
> first wave owns independent public semantic outcomes, expected arm results,
> the canonical unseen-evasion fingerprint recipe, evaluator-only fingerprints,
> denominators, pinned baseline/digests, and a self-testing gate; implementation
> plans must not replace those truths with production-generated fixtures or
> expose evaluator-only expected material.

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `cargo test`/libtest with `tokio::test` where runtime integration needs async execution; strict YAML/JSON fixtures use Serde; shell gate uses Bash. |
| **Config file** | Workspace `Cargo.toml`/package manifests; phase oracle at `scenarios/herd-memory/manifest.yaml`; evaluator-only digest at `scenarios/herd-memory/evaluator-only/withheld-manifest.yaml`. |
| **Quick run command** | `cargo test -p swarm-runtime --test herd_memory_oracle -- --test-threads=1 && cargo test -p swarm-runtime --test negative_herd_memory_boundary -- --test-threads=1 && bash tools/check-herd-memory.sh --self-test` |
| **Full suite command** | `bash tools/check-herd-memory.sh && cargo test -p swarm-runtime --test herd_memory_phase_gate -- --exact independent_closure_artifact_mutations_fail_closed --test-threads=1 && bash tools/check-gates-wired.sh && cargo test --workspace --all-targets --locked && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check && git diff --check` |
| **Estimated runtime** | Quick feedback ~30 seconds after compilation; full phase gate is bounded by the workspace suite and must be run on the combined tree. |

## Sampling Rate

- **After every task commit:** Run the task's exact focused command and `git diff --check`. No task is accepted from a renamed, ignored, zero-match, or wall-clock-only test.
- **After every plan wave:** Run the wave's package tests plus `bash tools/check-herd-memory.sh --self-test`.
- **Before `$gsd-verify-work`:** one canonical `bash tools/check-herd-memory.sh` run, the outer `herd_memory_phase_gate` test (which performs two independent typed benchmark runs with equal deterministic report digests), `bash tools/check-gates-wired.sh`, the full workspace test/clippy/format suite, and the privacy/authority mutation controls must be green.
- **CI wiring:** in job `test`, steps `Run Herd Memory canonical gate` and `Run Herd Memory closure gate` must invoke the exact `bash tools/check-herd-memory.sh` and exact `cargo test -p swarm-runtime --test herd_memory_phase_gate -- --exact independent_closure_artifact_mutations_fail_closed --test-threads=1` commands; `bash tools/check-gates-wired.sh` must parse those named steps and fail omission/recursion mutations.
- **Max feedback latency:** 60 seconds for focused tests after compilation; full-suite latency is reported as an observation, never as an acceptance metric.

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 289-00-01 | 00 | 1 | HERDMEM-01, HERDMEM-04, HERDMEM-06 | independent oracle/negative fixture | `cargo test -p swarm-runtime --test herd_memory_oracle -- --exact allowlist_oracle_rejects_nested_privacy_fields --test-threads=1` | ✅ W0 | ⬜ pending |
| 289-00-02 | 00 | 1 | HERDMEM-01, HERDMEM-03 | source-boundary mutation | `cargo test -p swarm-runtime --test negative_herd_memory_boundary -- --exact boundary_checker_rejects_privacy_and_authority_fixture --test-threads=1` | ✅ W0 | ⬜ pending |
| 289-00-03 | 00 | 1 | HERDMEM-01..HERDMEM-06 | exact shell gate/self-test | `bash tools/check-herd-memory.sh --self-test` | ✅ W0 | ⬜ pending |
| 289-01-01 | 01 | 2 | HERDMEM-01, HERDMEM-02, HERDMEM-05 | config unit/TDD | `cargo test -p swarm-core config::tests::herd_memory --lib` | ❌ W0 | ⬜ pending |
| 289-01B-01 | 01B | 3 | HERDMEM-01 | strict serialization/privacy unit | `cargo test -p swarm-spine --test herd_memory_export -- --exact typed_body_rejects_unknown_and_prohibited_fields --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-01B-02 | 01B | 3 | HERDMEM-01, HERDMEM-05 | file-provider custody/bootstrap/rotation | `cargo test -p swarm-spine --test herd_key_resolver -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-01C-01 | 01C | 4 | HERDMEM-01, HERDMEM-05 | config-bound runtime factory | `cargo test -p swarm-runtime --test herd_memory_factory -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-02-01 | 02 | 4 | HERDMEM-02 | registry/rotation unit | `cargo test -p swarm-spine --test herd_memory_negative -- --exact registry_rotation_requires_continuity_and_scope --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-02-02 | 02 | 4 | HERDMEM-02 | mutation/integration negative | `cargo test -p swarm-spine --test herd_memory_negative -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-03-01 | 03 | 5 | HERDMEM-02, HERDMEM-05 | lifecycle state-machine | `cargo test -p swarm-spine --test herd_memory_lifecycle -- --exact durable_refusal_quarantine_and_equivocation_survive_restart --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-03-02 | 03 | 5 | HERDMEM-05 | restart/fault/GC integration | `cargo test -p swarm-spine --test herd_memory_lifecycle -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-04-01 | 04 | 5 | HERDMEM-01 | projection TDD/privacy | `cargo test -p swarm-runtime --test herd_memory_projection -- --exact projection_is_allowlist_only_and_hmac_opaque --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-04-02 | 04 | 5 | HERDMEM-01, HERDMEM-02 | import serialization negative | `cargo test -p swarm-runtime --test herd_memory_projection -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-05-01 | 05 | 6 | HERDMEM-03, HERDMEM-05 | import/corroboration integration | `cargo test -p swarm-runtime --test herd_memory_integration -- --exact restart_revocation_and_quarantine_remove_actionable_memory --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-05-02 | 05 | 6 | HERDMEM-03, HERDMEM-04 | advisory authority negative | `cargo test -p swarm-runtime --test negative_herd_memory_authority -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-06-01 | 06 | 7 | HERDMEM-04, HERDMEM-06 | deterministic three-arm benchmark | `cargo test -p swarm-runtime --test herd_memory_benchmark -- --exact three_arms_emit_identical_input_digests --test-threads=1` | ❌ W0 | ⬜ pending |
| 289-06-02 | 06 | 7 | HERDMEM-06 | acceptance/mutation/benchmark gate | `bash tools/check-herd-memory.sh` | ❌ W0 | ⬜ pending |
| 289-07-01 | 07 | 8 | HERDMEM-01..HERDMEM-06 | CI wiring/independent closure | `bash tools/check-gates-wired.sh && bash tools/check-herd-memory.sh && cargo test -p swarm-runtime --test herd_memory_phase_gate -- --exact independent_closure_artifact_mutations_fail_closed --test-threads=1` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

## Wave 0 Requirements

- [ ] `scenarios/herd-memory/manifest.yaml` — independent typed allowlist, privacy mutation matrix, lifecycle mutation matrix, three-arm metric schema, Phase 286 ceilings, and exact HERDMEM-06 thresholds.
- [ ] `scenarios/herd-memory/evaluator-only/withheld-manifest.yaml` — separately digested held-out corpus selected only by the evaluator after export/calibration; no candidate-facing path or content.
- [ ] `crates/swarm-runtime/tests/herd_memory_oracle.rs` — strict local oracle for allowlist, nested prohibited-field, digest-disjointness, and non-vacuous benchmark-manifest mutations; it must not import production herd-memory projection code.
- [ ] `crates/swarm-runtime/tests/negative_herd_memory_boundary.rs` — clean/broken privacy and response-authority source fixtures proving the scanner can fail.
- [ ] `tools/check-herd-memory.sh` — exact named-test execution count, report-schema/threshold checks, evaluator-only contamination checks, source/privacy/authority mutations, no ignored/stubbed production tests, and `--self-test`; missing behavior remains a deliberate failure.
- [ ] Benchmark report/parser/CI schema — the exact integer `withheld_relative_gap_basis_points` field is required end-to-end; missing, duplicate, extra, renamed, float, and legacy short-form fields fail closed, and report digests use self-field-excluded canonical bytes.
- [ ] `crates/swarm-spine/src/herd_key_resolver.rs` and `crates/swarm-runtime/src/herd_memory_factory.rs` — repository-owned `FileOpaqueKeyProvider` at the validated `HerdMemoryConfig.opaque_key_root`, owner-only 0700/0600 custody, atomic rotation/restart state, and config-bound resolver factory; no process-local/test fallback.
- [ ] `crates/swarm-spine/Cargo.toml` — explicit `zeroize.workspace = true` dependency for provider key-byte cleanup.
- [ ] `Cargo.lock` — locked zeroize resolution/checksum metadata; provider/build verification must use `--locked`.
- [ ] Signed-default preservation — `rulesets/default.yaml` and `rulesets/attestation.json` are read-only; config tests recompute the pinned default digest/size and fail any byte mutation.
- [ ] First-run provisioning — explicit key-provider and trusted-issuer bootstrap operations use owner-only 0700/0600 custody, create-new/CSPRNG/atomic sync, and fail closed on missing/insecure/foreign/tampered state; runtime startup never auto-bootstraps.
- [ ] Spine/runtime ownership — `HerdMemoryQuery` and `HerdMemoryContextKey` are spine-neutral exports; runtime `HerdMemoryContext` converts field-by-field and no spine module imports runtime types.
- [ ] `crates/swarm-runtime/tests/herd_memory_factory.rs` and `crates/swarm-spine/tests/herd_key_resolver.rs` — missing/retired/revoked/rotated-key, scope, and restart mutation tests.
- [ ] `docs/benchmarks/herd-memory-baseline.json` — Plan 00-owned immutable public semantic expected outcomes, public fingerprint recipe, metric denominators, pinned source/memory/baseline digests, and an opaque withheld version/digest handle; it must contain no withheld expected fingerprint or per-case content digest, and Plan 06 only consumes/revalidates it.
- [ ] `.github/workflows/ci.yml` — exact Herd Memory gate invocation recognized by `tools/check-gates-wired.sh`.
- [ ] `tools/check-gates-wired.sh` — exact-command parser and omission/rename/flag/path/duplicate/local-only mutations for both canonical CI commands.
- [ ] `.planning/phases/289-herd-memory/289-P0-P2-REVIEW.md` and `.planning/phases/289-herd-memory/289-VERIFICATION.md` — independent final review, goal-backward evidence, and zero open P0/P1/P2 counters.
- [ ] Final reviewer provenance — root-controlled reviewer assignment/provenance evidence IDs are distinct from implementer evidence and linked in both final artifacts.

## Manual-Only Verifications

All Phase 289 behaviors have automated verification. No manual-only checkpoint is permitted to substitute for the privacy, trust, lifecycle, advisory-boundary, or benchmark gates.

## Validation Sign-Off

This planning artifact is intentionally pre-execution with draft status,
nyquist_compliant false, and wave_0_complete false. Plan 289-07-01
must replace those three values only after the canonical checker, outer
phase-gate, exact CI wiring parser, full combined-tree suite, and independent
review evidence pass: status: complete, nyquist_compliant: true, and
wave_0_complete: true. The final artifact must contain no pending task/approval
status and must link the root-assigned reviewer evidence IDs.

- [ ] All tasks have an `<automated>` verify command or a Wave 0 dependency that creates the command's target.
- [ ] Sampling continuity: no three consecutive tasks without automated verification.
- [ ] Wave 0 covers every initially missing oracle, mutation fixture, exact-test target, and withheld-digest reference.
- [ ] No watch-mode flags, ignored tests, `todo!`, `unimplemented!`, placeholder success, or production stubs are accepted.
- [ ] Feedback latency is bounded for focused tests; wall-clock measurements are observations only.
- [ ] `nyquist_compliant: true` may be set only after the exact gate and full combined-tree suite pass; `wave_0_complete` remains `false` in this pre-execution artifact.

**Approval:** pending
