---
gsd_state_version: 1.0
milestone: v1.78
milestone_name: Runtime Decomposition And TCB Boundary
current_phase: 320
current_phase_name: Reversible Quarantine Execution
current_plan: null
status: active
last_updated: "2026-08-13T00:00:00Z"
last_activity: 2026-08-13
progress:
  total_phases: 4
  completed_phases: 4
  total_plans: 0
  completed_plans: 0
  percent: 100
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-13)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** `v1.78 Runtime Decomposition And TCB Boundary` — green the verification gates, eliminate `core.inc`, split `swarm-runtime`, and enforce a TCB boundary. Phase 284 (test isolation) is pulled forward from v1.79 as a hard prerequisite for parallel work.

## Current Position

**Current Phase:** 320 — Reversible Quarantine Execution (v1.78.1); phase 283 (TCB Boundary) is the remaining v1.78 phase
**Total Phases:** 4 (280-283), plus 320-322 in v1.78.1
**Current Plan:** None started yet
**Total Plans in Phase:** TBD
**Status:** Ready to plan
**Last Activity:** 2026-08-13
**Last Activity Description:** Merged phase 282 (0a09358) into main after a five-lens adversarial review — 15 findings raised, 9 survived independent refutation, 3 fixed as merge blockers. Then measured phases 320/321/322 against the code and found three of their recorded statuses false.

Progress: v1.78 phases 280/281/282 complete, 283 open; v1.78.1 phases 320/321/322 open

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
- v1.78 phase 282 COMPLETE (partial by design) and MERGED to main 2026-08-13 as 0a09358. `swarm-runtime/src` 120,431 -> 77,868 LOC; 16 -> 20 crates (`swarm-runtime-http` 10,381, `swarm-ingest-runtime` 17,956, `swarm-evolution` 7,066 real source replacing the facade, `swarm-runtime-workbench` 4,064, `swarm-agents` 3,366). Three cycles broken first: sealed `swarm_core::agent` tick trait, `OperatorSurfacePaths` moved to swarm-core, sealed `swarm_policy::governance::GovernanceAuthority` replacing the dispatcher's concrete Tom handle.
- MERGE EVIDENCE for 282, measured not asserted: fmt/build/clippy `--all-targets -D warnings` all exit 0 with zero warnings; test lane 1 564 passed 0 failed, lane 2 562 passed 0 failed; and the test NAME SET is byte-identical to main's green CI run 31709806943 in BOTH directions — 1152 names, 0 added, 0 lost. That last check is the one that matters for a 47-rename code motion: commit b86576d records that root `#[cfg(test)]` items go invisible across a new crate edge, and a count alone would hide N lost against N gained.
- - Merged tree gates: `cargo build --workspace` exit 0, `cargo fmt --all -- --check` exit 0 (after one style commit), `cargo clippy --workspace --all-targets -- -D warnings` exit 0 with zero warnings.

## Issues

- Phase 280 COMPLETE 2026-08-11 (GATEFIX-01..04). All 9 baseline swarm-runtime failures fixed (roadmap said 7; fail-fast undercount). Two real product defects repaired: the guided first-run wizard never reached its own human gate, and the SIEM forward task was detached rather than owned. The panic-contract gate needed its own repair after the first pass made every `include!`d file silently unscanned.
- OPEN, unowned by any requirement: `crates/swarm-cli/src/core.inc:2988` hard-codes `ed25519_dalek::SigningKey::from_bytes(&[85u8; 32])` inside `pub async fn run(cli: Cli)` with no `#[cfg(test)]` above it. This is shipping production code keyed on a public constant.
- OPEN: a second intermittent `kitten_agent` benchmark flake, `measured_evolution_benchmark_improves_over_conservative_seed`, distinct from `..._persists_generation_deltas`. Both belong to phase 284.
- 2026-08-11: wall-clock latency no longer gates any verdict at five sites (merge 8cfbfb0, option F). Diagnosed after TWO wrong hypotheses of mine: it was never floating point (u64 <= u64, no f32 in crates/) and never architecture (arm64 showed 6.4% of reports over budget in one gate run). It was a benchmark of an opt-level=0 crypto path asserted as a safety invariant. The two SILENT sites mattered most: latency fed the f64 `speed` objective in population_fitness and the advisory score, so two machines ranked evolved detectors differently with green suites on both.
- 2026-08-11: evidence lane hardened (merge b78bbfb). Site 6 fixed — the latency DELTA gate no longer refuses canary admission. Vacuous verification fixed — `metadata:` is mandatory, Default removed from ReplayScenarioClass and ReplayScenarioMetadata, and a new `scenario_class_declared` invariant fails Mixed with a named error. Fail-closed chosen per this repo's own CLAUDE.md convention.
- OPTION F CONFIRMED ON x86_64 CI (run 31550975167): 529 passed / 3 failed / 0 VerificationFailed, down from 473 / 45 / 38. Two of the three residual failures were site 6, exactly as predicted from a 1327us idle-machine spread; the third is task #11.
- 2026-08-12: replay lane complete (merge 3315c32). Site 7 demoted, the class/suite mismatch closed in both directions, a third vacuity hole found and closed (an experiment counted 3 scenarios but scored 2), and harvested counterexamples reclassified — the evolution lane had been generating scenarios its own verification would reject.
- OPEN (task #13): an EIGHTH site at evolution/formal_safety.rs:738. A z3 WALL-CLOCK timeout collapses to `passed: false` with a synthesized counterexample, so UNPROVED is reported as REFUTED. Unreachable in shipped configs (z3 feature off, enable_z3: false). The remedy is z3 `rlimit` — counting work, not time — which belongs with phase 322's ZGATE work, not a demotion.
- METHOD NOTE for the next sweep: three sweeps declared the wall-clock list complete by grepping identifiers containing "latency" and all three were wrong. Site 7's variables are named actual_max/expected_max. Sweep by DATAFLOW — from every production clock read forward to a bool, an ordering, a score, an early return, an exit code, or a serialized field a consumer compares.
- SUPERSEDED (task #12): a SEVENTH wall-clock verdict at replay/helpers.rs:35 gates `swarmctl replay-evaluate` and fails CLOSED. Two prior sweeps missed it because they grepped identifiers containing "latency"; these are named actual_max/expected_max. The sweep is at six of seven, NOT complete — assume the next claim of completeness is also wrong.
- SUPERSEDED (task #10): a SIXTH wall-clock verdict survived at replay/metrics.rs:252 and fails CLOSED into CanaryError::ShadowFailed, refusing canary admission. The option-F diagnosis dismissed it as "immune to a uniform slowdown" -- true but irrelevant, since it compares candidate against baseline and a DIFFERENTIAL stall flips it. Idle-machine spread is already 1327us against a 2000us budget.
- Phase 281 COMPLETE 2026-08-11 (INCFIX-01, INCFIX-03). 17,480 lines across http/replay/workbench converted from `.inc` to ordinary modules; 4 tasks, 4 approved first time, 0 fix rounds. Purity proven with a token-level per-item comparator: 643 items, 0 missing, 0 added, 311 inserted visibility tokens all `pub(super)`.
- CORRECTION carried forward: INCFIX-01's rationale is half wrong. rustc, clippy AND rustfmt all follow `#[path]`; only rust-analyzer and `*.rs`-globbing LOC tools skip a `.inc`. Phase 281 criterion 3 is unsatisfiable as written and is marked superseded. Do not repeat the claim in 282/283.
- OPEN, filed from phase 281's final review: a vacuous-verification bug in replay, proven pre-existing. `ReplayScenarioClass` derives `Default` with `#[default] Mixed` and `ReplayScenarioMetadata.class` is `#[serde(default)]`, while `verify_known_bad_coverage` requires `class == Adversarial` and `verify_false_positive_bound` filters on `scenario_is_benign`. A manifest omitting `class:` is exempt from BOTH invariants and passes vacuously.
- Phase 284 COMPLETE 2026-08-11 (FIXTURE-01..04). The suite no longer writes into the repository: a full G1+G2 leaves all four drift assertions clean. Parallel phase work is now unblocked.
- The kitten_agent flake was NOT prior-run state. `Option::unwrap_or` evaluates eagerly, so `load_source_seed` scanned every manifest under `experiments/` even when given an override, racing four `mutation::tests_autonomous` tests that write transient files there. 11 failures in 107 runs.
- The CI drift gate now carries four assertions; the fourth (no empty directories anywhere) is unscoped and is what catches leaks the path-scoped checks miss.
- CORRECTED 2026-08-13: phase 320 is 0/4, not 2/4. 4d03543 shipped TYPES ONLY — `rg -l 'ContainmentLease|ContainmentLedger|RollbackExecutor|RollbackReceipt'` returns only `swarm-response/src/lib.rs` (the re-export) and `swarm-response/src/rollback.rs` (definitions plus their `#[cfg(test)]` tests). Zero production code constructs a lease. `SandboxRollbackExecutor::rollback` never branches on `ResponseRollbackStepKind` and performs no side effect. The roadmap's own "highest-blast-radius gap" — containment with no undo — is fully open. See task #19.
- Phase 321 is 2/5, NOT complete: f55c3bd's own message says "Implements BFT-01 and BFT-02". BFT-03, BFT-04, and BFT-05 remain. PATH CORRECTED 2026-08-13: `simulate_governance_commit` is at `crates/swarm-agents/src/tom_agent.rs:1132` after phase 282, not `swarm-runtime/src/tom_agent.rs:1147`.
- CORRECTED 2026-08-13, was wrong on all three counts: phase 322 CAN run and always could. `promotion.rs` exists at `crates/swarm-runtime/src/promotion.rs` (2,901 lines) and phase 282 was never going to move it — ADR 0005 records that the crate root closes over all seven pinned evolution modules. The facade was 40 lines, not 8. The requirement text simply names the wrong path.
- BFT-04 has no matching success criterion in the phase 321 ROADMAP block; criteria 1-4 cover BFT-01, BFT-02, BFT-03, BFT-05 only.
- Phases 295, 300, and 304 are orphan roadmap rows with no body block and no mapped requirements; they are superseded by 322, 321, and 320 respectively.
- `.gitignore` covers `crates/swarm-runtime/data/evolution-assurance-cases/reports/` but not the `crates/swarm-evolution/` twin, and the tracked `index.json` points at gitignored directories, so it dangles on a clean clone.
- v1.74 remains deferred rather than completed; its structural-integrity work is preserved for later re-activation.
- 2026-08-13: phase 282's own new gate `tools/check-visibility-baseline.sh` COULD NOT FAIL, found by the pre-merge review and fixed in 8186a08. Two holes, each proven by construction: (a) `const` was an item keyword but not a modifier, so every `pub const fn` normalized to the one token `const fn` — 90 restricted const fns invisible; (b) keys were `<keyword> <name>` with no path, and the baseline-`pub` exclusion then dropped any name shared anywhere in 20 crates — 20 tokens covering 152 of 829 restricted declarations, 18% of the surface, while the success line said "no others". Now keyed on `<path-under-src> <keyword> <name>` with the exclusion deleted outright. Subpath keying was chosen over crate keying because crate keying opens a NEW hole phase 283 will hit: a widening riding along with a cross-crate move keys to the old crate at baseline and the new one at HEAD, so it never matches. Verified by four constructed probes including that one.
- METHOD NOTE, second instance of the same lesson: the wall-clock sweep failed three times by grepping identifiers. This gate failed the same way — it compared NAMES where it claimed to compare ITEMS. When a check subtracts one set from another, state what the subtraction MEANS in terms of identity, then construct a violation and confirm it exits non-zero. `tools/check-visibility-baseline.sh` now carries a self-test that pins its parser on every run, because a NORMALIZE regression is indistinguishable from a clean tree.
- OPEN (task #17), CRITICAL and live: the automated evolution route reaches production promotion having never run the solver gate, and PERSISTS A FABRICATED ATTESTATION saying it passed. `selection.rs:1045` mints a proposal with `assurance: None, review_state: AcceptedForCanary` without calling `evaluate_proposal_assurance`; `crates/swarm-ingest-runtime/src/ingest/mod.rs:436-463` then fabricates `EvolutionProposalAssuranceSummary { decision: Passed, solver: { required: false, status: None } }` and writes it. `promotion.rs:690` does call `promotion_assurance_block_reason`, but that only reads the recorded `decision` field. So ZGATE-01/02 are the ONLY gate on that route, not a redundant second one.
- OPEN (task #18), CRITICAL and live: `GovernancePolicy::can_act` fails OPEN when no governor signing key is registered, against CLAUDE.md's "live response must fail closed" contract. Production registers exactly one governor today (`swarm-runtime-http/src/bin/swarm_detect.rs:815` is the only `AgentRole::Tom` registration), so `state.governors.len() == 1` and the multi-key leak BFT-03 describes is a property of the TYPE, not of the deployment.
- OPEN (task #20): CI never passes `--features z3`, so the entire solver lane (`evolution/formal_safety.rs:717-857`) is uncompiled, unlinted and unrun. Task #13's rlimit fix would land completely unverified. Same shape as task #11's python smoke test. Wire the lane WITH the fix, not after.
- CORRECTED 2026-08-13: there are TEN `tools/check-*.sh` and CI runs SEVEN, not "nine and six" — phase 282 added and wired `check-visibility-baseline.sh` in the same commit. The three unwired ones are as filed (task #15), but wiring them AS-IS adds zero coverage: `check-adversary-emulation-coverage.sh` and `check-stigmergic-feedback-benchmark.sh` invoke `cargo test <filter>`, which exits 0 when the filter matches nothing, and every test they name already runs in the existing `test` job. Their published numbers (23 techniques, 100%) are asserted nowhere.

## Next Command

Plan and execute Phase 320 (Reversible Quarantine Execution), which is 0/4 rather than 2/4 — see the correction above. Phase 283 (TCB Boundary) is the remaining v1.78 phase and is unblocked by 282's merge. Implementation-ready plans for 320, 321, 322 and task #15 were produced 2026-08-13 and each was independently critiqued; they carry measured file:line and name the requirement text that is factually wrong about the code.
