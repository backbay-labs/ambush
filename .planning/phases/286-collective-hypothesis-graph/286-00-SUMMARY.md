---
phase: 286-collective-hypothesis-graph
plan: 00
subsystem: validation
tags: [collective-reasoning, oracle, mutation-testing, authority-boundary]
requirements-completed: []
one-liner: "Phase 286 now has a sealed adjudicated corpus, pinned oracle digests, a mutation-proven response-authority boundary, and an exact non-vacuous gate."
completed: 2026-08-21
---

# Phase 286 Plan 00 Summary

Phase 286 now starts from independent evidence rather than implementation-owned
success criteria. The graph behavior remains intentionally unimplemented and no
COG requirement is marked complete.

## Accomplishments

- Froze strict ambiguous and withheld fixtures with all six telemetry families,
  corroborating and conflicting evidence, two competing hypotheses, an explicit
  missing kill-chain edge, fixed logical time, and 100 stable task identities.
- Added a sealed `collective_hypothesis_oracle` test target that later behavior
  plans do not own. It rejects missing/duplicate source families, duplicate IDs,
  absent truth, training/withheld overlap, missing denominators or thresholds,
  unbounded work, unknown fields, and changed oracle bytes.
- Pinned the manifest and fixture SHA-256 values in the baseline alongside exact
  denominators, thresholds, and the single-agent control.
- Added a lexical response-authority scanner with clean and deliberately broken
  fixtures. Graph modules cannot import response executors, policy/governance,
  leases, receipts, actions, or execution entry points.
- Installed the final-form checker with exact one-test assertions, strict report
  schema and metric validation, deterministic-repeat comparison, and self-tests
  for zero tests, wrong counts, renamed tests, schema drift, threshold/oracle
  mutations, verdict inversion, authority leakage, and wall-clock gating.
- Revised the remaining Phase 286 plans to add an injected logical clock and
  scheduler, protect oracle ownership, and require a full
  policy/governance/operator/receipt/dispatcher handoff proof.

## Verification

- `cargo test -p swarm-runtime --test collective_hypothesis_oracle benchmark_manifest_is_strict -- --exact`
- `cargo test -p swarm-runtime --test negative_graph_response_boundary boundary_checker_rejects_broken_fixture -- --exact`
- `bash -n tools/check-collective-hypothesis-graph.sh`
- `bash tools/check-collective-hypothesis-graph.sh --self-test`
- `cargo clippy -p swarm-runtime --test collective_hypothesis_oracle --test negative_graph_response_boundary -- -D warnings`
- `cargo fmt --all -- --check`
- `git diff --check`

The normal phase gate fails with an explicit message that Plan 02 has not yet
created the separate graph behavior target. It cannot pass from a missing test,
zero matched tests, a renamed test, or a weakened oracle.

## Boundary

This plan creates evidence and tests only. It adds no graph implementation,
agent behavior, response authority, live target, policy mutation, or deployment.
