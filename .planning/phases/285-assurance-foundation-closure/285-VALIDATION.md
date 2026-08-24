---
phase: 285
slug: assurance-foundation-closure
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-24
---

# Phase 285 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness, shell/Python repository gates, Docker Compose JetStream harness, Helm render checks, GitHub Actions hosted Linux |
| **Config file** | Workspace `Cargo.toml`, `.github/workflows/ci.yml`, `deploy/helm/swarm-team-six/Chart.yaml`, `.planning/phases/285-assurance-foundation-closure/285-WITNESS-ADAPTER-CONTRACT.md` |
| **Quick run command** | `cargo test -p swarm-governance --lib --locked --offline` |
| **Full suite command** | `bash tools/check-phase285-closure.sh --local` |
| **Estimated runtime** | quick ~30 seconds; affected-plan gates <=300 seconds; final local gate may be longer and records per-lane durations |

---

## Sampling Rate

- **After every task commit:** Run the task's exact non-vacuous command from the map below, then affected-package strict clippy, formatting, and `git diff --check`.
- **After every plan wave:** Run `bash tools/check-phase285-closure.sh --through-plan <plan-number>` and require every selected lane to report executed > 0, passed = executed, failed = 0, ignored = 0.
- **Before `$gsd-verify-work`:** `bash tools/check-phase285-closure.sh --local` must be green on an immutable commit with a clean tree.
- **After any review-driven edit:** Invalidate the prior evidence record and rerun the exact task, wave, and independent review against the new commit.
- **Max feedback latency:** 300 seconds for task/wave sampling. Long workspace, JetStream restart, and hosted lanes run only at their declared checkpoint/final gates and publish measured duration.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 285-01-01 | 01 | 0 | ASSURE-06 | wire/failure unit + mutation | `bash tools/check-phase285-witness-conformance.sh response-failure-wire` | ❌ W0 | ⬜ pending |
| 285-01-02 | 01 | 1 | ASSURE-06 | candidate verifier mutation | `bash tools/check-phase285-witness-conformance.sh candidate-verifier` | ❌ W0 | ⬜ pending |
| 285-01-03 | 01 | 1 | ASSURE-04, ASSURE-06 | slice gate | `bash tools/check-phase285-witness-conformance.sh protocol-checkpoint` | ❌ W0 | ⬜ pending |
| 285-02-01 | 02 | 2 | ASSURE-06 | atomic-store contract | `bash tools/check-phase285-witness-conformance.sh atomic-store-contract` | ❌ W0 | ⬜ pending |
| 285-02-02 | 02 | 2 | ASSURE-06 | model differential/fault injection | `bash tools/check-phase285-witness-conformance.sh in-memory-differential` | ❌ W0 | ⬜ pending |
| 285-02-03 | 02 | 2 | ASSURE-04, ASSURE-06 | typed-proxy conformance | `bash tools/check-phase285-witness-conformance.sh typed-proxy` | ❌ W0 | ⬜ pending |
| 285-03-01 | 03 | 3 | ASSURE-02, ASSURE-06 | dependency/layering negative | `bash tools/check-phase285-witness-conformance.sh transport-layering` | ❌ W0 | ⬜ pending |
| 285-03-02 | 03 | 3 | ASSURE-06 | JetStream CAS/header mutation | `bash tools/with-nats-jetstream.sh bash tools/check-phase285-witness-conformance.sh jetstream-cas` | ❌ W0 | ⬜ pending |
| 285-03-03 | 03 | 3 | ASSURE-04, ASSURE-06 | JetStream restart/non-skip | `bash tools/with-nats-jetstream.sh bash tools/check-phase285-witness-conformance.sh jetstream-checkpoint` | ❌ W0 | ⬜ pending |
| 285-04-01 | 04 | 4 | ASSURE-06 | nine-operation dispatcher | `bash tools/check-phase285-witness-conformance.sh public-dispatcher` | ❌ W0 | ⬜ pending |
| 285-04-02 | 04 | 4 | ASSURE-06 | full request/reply isolation | `bash tools/with-nats-jetstream.sh bash tools/check-phase285-witness-conformance.sh full-service-path` | ❌ W0 | ⬜ pending |
| 285-04-03 | 04 | 4 | ASSURE-04, ASSURE-06 | kill/restart/client attestation | `bash tools/with-nats-jetstream.sh bash tools/check-phase285-witness-conformance.sh service-checkpoint` | ❌ W0 | ⬜ pending |
| 285-05-01 | 05 | 5 | ASSURE-06 | fixed-lane seam/race matrix | `bash tools/check-phase285-governance-persistence.sh fixed-lanes` | ❌ W0 | ⬜ pending |
| 285-05-02 | 05 | 5 | ASSURE-06 | witness transaction crash/recovery | `bash tools/check-phase285-governance-persistence.sh transaction-recovery` | ❌ W0 | ⬜ pending |
| 285-05-03 | 05 | 5 | ASSURE-04, ASSURE-06 | no-witness/no-fallback mutation | `bash tools/check-phase285-governance-persistence.sh enforced-checkpoint` | ❌ W0 | ⬜ pending |
| 285-06-01 | 06 | 6 | ASSURE-06 | retention/pool exhaustion mutation | `bash tools/check-phase285-governance-persistence.sh retention-maintenance` | ❌ W0 | ⬜ pending |
| 285-06-02 | 06 | 6 | ASSURE-06 | detector production construction | `bash tools/check-phase285-governance-persistence.sh detector-integration` | ❌ W0 | ⬜ pending |
| 285-06-03 | 06 | 6 | ASSURE-04, ASSURE-06 | combined governance/detector checkpoint | `bash tools/check-phase285-closure.sh --through-plan 06` | ❌ W0 | ⬜ pending |
| 285-07-01 | 07 | 7 | ASSURE-03, ASSURE-05, ASSURE-06 | Helm/init/isolation mutation | `bash tools/check-phase285-deployment.sh` | ❌ W0 | ⬜ pending |
| 285-07-02 | 07 | 7 | ASSURE-01, ASSURE-02, ASSURE-04, ASSURE-06 | final local combined-tree gate | `bash tools/check-phase285-closure.sh --local` | ❌ W0 | ⬜ pending |
| 285-07-03 | 07 | 8 | ASSURE-01, ASSURE-02, ASSURE-03, ASSURE-04, ASSURE-05, ASSURE-06 | exact-head hosted/review closure | `bash tools/check-phase285-evidence.sh --commit "$(git rev-parse HEAD)" --tree "$(git rev-parse HEAD^{tree})"` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Every checker above must reject a missing test target, zero execution, ignored execution, partial lane selection, dirty tree where immutability is required, or evidence from a different commit/tree.

---

## Wave 0 Requirements

- [ ] `tools/check-phase285-witness-conformance.sh` — exact named-test registry and nonzero execution parser for pure, in-memory, proxy, JetStream, and full-service lanes.
- [ ] `tools/check-phase285-governance-persistence.sh` — exact fault/mutation registry for fixed lanes, transaction recovery, retention, maintenance, detector handoff, and no-witness refusal.
- [ ] `tools/check-phase285-deployment.sh` — Helm/bootstrap/serving render and live-isolation checker with deliberate bad mount/account/image/bucket/init/anchor fixtures.
- [ ] `tools/check-phase285-closure.sh` — dependency-ordered local orchestrator that records command, exit, duration, test counts, commit, tree, and cleanliness without treating a sub-lane as final acceptance.
- [ ] `tools/check-phase285-evidence.sh` — machine checker for exact local/hosted/review evidence, reviewer independence, zero P0/P1/P2, and truthful `wired`/`executed`/`passed`/`protected-required` states.
- [ ] `.github/workflows/ci.yml` — unconditional credential-free hosted witness/Phase 285 lanes wired through the repository gate inventory.
- [ ] `crates/swarm-governance/tests/phase285_witness_conformance.rs` or an equivalent explicit integration target — shared named conformance registry that cannot pass through substring filters alone.
- [ ] Transport-package JetStream/full-service integration targets — `#[ignore]` is permitted only when the checked wrapper explicitly selects and proves execution; ordinary skip-on-unavailable behavior is forbidden.

Wave 0 is complete only when each checker self-test demonstrates one green control and deliberate red fixtures for missing, zero, ignored, failed, stale-hash, and omitted-lane evidence.

---

## Manual-Only Verifications

All phase behaviors have automated verification. Hosted execution and independent hostile review are external actors, but `tools/check-phase285-evidence.sh` mechanically verifies their exact commit/tree binding, identities, outputs, and verdict before closure.

---

## Final Immutable-Tree Matrix

`tools/check-phase285-closure.sh --local` must include, at minimum:

```text
cargo test -p swarm-governance --lib --locked --offline
cargo test -p swarm-runtime-http --bin swarm-detect --locked --offline
cargo test --workspace --exclude swarm-runtime --exclude swarm-ingest-runtime --locked --offline
cargo test -p swarm-runtime -p swarm-ingest-runtime --locked --offline -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo fmt --all -- --check
bash tools/check-mapping.sh
bash tools/check-negative-registry.sh
bash tools/check-fixture-freshness.sh
bash tools/check-supply-chain.sh
bash tools/check-single-governor-key.sh
bash tools/check-workspace-layering.sh
bash tools/check-gates-wired.sh
bash tools/check-phase285-witness-conformance.sh all-local
bash tools/with-nats-jetstream.sh bash tools/check-phase285-witness-conformance.sh all-jetstream
bash tools/check-phase285-governance-persistence.sh all
bash tools/check-phase285-deployment.sh
git diff --check
bash tools/check-worktree-clean.sh "the Phase 285 final run"
```

The hosted lane reruns the declared credential-free subset from a fresh checkout. If a platform dependency prevents a local lane from running on hosted Linux, the evidence contract must name the separate trusted runner; it may not mark the omitted lane passed.

---

## Validation Sign-Off

- [x] All planned tasks have an automated verification command or explicit Wave 0 dependency.
- [x] Sampling continuity: no three consecutive tasks lack automated verification.
- [x] Wave 0 enumerates every currently missing checker and integration target.
- [x] No watch-mode flags are used.
- [x] Exact-test wrappers must prove nonzero execution and reject ignored/skipped results.
- [x] Task/wave feedback target is <=300 seconds; intentionally longer final lanes publish measured durations.
- [x] `nyquist_compliant: true` is set in frontmatter.

**Approval:** pending plan-checker verification and Wave 0 execution
