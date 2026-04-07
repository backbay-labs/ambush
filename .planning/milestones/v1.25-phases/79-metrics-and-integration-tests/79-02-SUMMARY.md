---
phase: 79-metrics-and-integration-tests
plan: 02
subsystem: runtime
tags: [integration-tests, critical-path, telemetry, receipts]
requirements-completed: [OPS-29]
one-liner: "Critical-path integration tests now exercise detect-to-receipt, benign no-op, scenario-fixture, and policy-deny flows as part of `cargo test --workspace`."
completed: 2026-04-05
---

# Phase 79: Metrics And Integration Tests Summary

**Critical-path integration tests now exercise detect-to-receipt, benign no-op, scenario-fixture, and policy-deny flows as part of `cargo test --workspace`.**

## Accomplishments

- Added a dedicated integration test target under `crates/swarm-runtime/tests/` that exercises the runtime through its public API as an external consumer.
- Covered the full detect-to-receipt happy path, benign no-op behavior, scenario-fixture replay, and policy-deny behavior where the response stage is skipped but the replay bundle still persists the audit decision.
- Verified that findings, pheromone deposits, policy results, response outcomes, and stable IDs all survive the end-to-end path instead of only being covered by narrower unit tests.
- Integrated the new tests into the standard workspace suite so regressions now surface during the same `cargo test --workspace` run as the rest of the runtime coverage.

## Files Created Or Modified

- `crates/swarm-runtime/tests/critical_path_integration.rs` - added the end-to-end runtime integration tests and scenario-fixture coverage.

## Key Decisions

- The integration tests use public crate APIs and shared config fixtures so they validate the same external seams future service binaries and tooling will consume.
- The deny-path test intentionally proves that policy rejection still emits a persisted audit artifact, preserving operator visibility even when no live response executes.
- Scenario-fixture coverage reuses the repo-owned replay YAML corpus so phase 78 service extraction and phase 79 end-to-end verification stay coupled to the same canonical fixtures.

## Verification

- `cargo test -p swarm-runtime --test critical_path_integration --no-fail-fast`
- `cargo test --workspace`

## Notes

- The integration suite remains fixture-driven and deterministic; it does not require external services, real telemetry ingress, or non-local dependencies.
