# Phase 89: Test Coverage And Hot-Path Consolidation

## Decisions

- **Test style follows approval.rs model**: Tests exercise public API, state transitions, error cases, and round-trip persistence. No internal implementation testing.
- **Hot-path consolidation target is `src/detection/`**: `pipeline.rs` and `metrics.rs` move into `detection/` submodule; `ingest.rs` stays at the crate root (it is HTTP/axum infrastructure, not detection logic).
- **Coverage target is 2% measured by `cargo llvm-cov`**: The metric is line coverage across swarm-runtime, not function or branch coverage.
- **The 5 largest previously-untested modules**: `ingest.rs` (391 lines, 0 tests), plus the 4 largest post-split modules from Phase 88 that lack tests. The exact post-split filenames depend on Phase 88 output, so Plan 89-02 must discover them.

## Deferred Ideas

- Full crate extraction (splitting swarm-runtime into separate crates) -- out of scope for v1.29
- Rewriting the evolution module mesh -- decompose first, refactor later
- Adding new detectors or response adapters -- structural work only in v1.29

## Claude's Discretion

- Exact test helper placement (inline in each module vs shared test utilities)
- Whether to add a `test_helpers.rs` module for shared fixtures
- Number of test cases per module beyond the "at least one" minimum -- use judgment to cover the primary code path plus important edge cases
