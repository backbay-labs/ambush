# Phase 190 Plan 01 Summary

## Delivered

- Added first-class Criterion benchmark wiring to
  [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/Cargo.toml)
  so `swarm-runtime` now owns a repo-runnable benchmark target instead of
  relying only on example binaries.
- Added
  [hot_path.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/benches/hot_path.rs),
  which measures the bounded ingest -> detect -> deposit -> escalate slice with
  stable synthetic suspicious-process telemetry and env-selectable
  `in_memory` or `local_journal` substrate backends.
- Updated
  [fast-detection.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/fast-detection.md)
  with the shipped Criterion invocation contract and the first checked-in
  percentile baseline: p50 `103.04 us`, p95 `109.29 us`, p99 `139.21 us`, and
  `8,401.69` events/sec on the reference host.

## Notes

- The checked-in baseline intentionally stays bounded to the runtime hot path
  and does not try to claim the full HTTP ingest envelope.
- Sustained throughput and readiness-shedding behavior remain Phase 191 work;
  Phase 190 ends at the Criterion-owned percentile regression slice.
