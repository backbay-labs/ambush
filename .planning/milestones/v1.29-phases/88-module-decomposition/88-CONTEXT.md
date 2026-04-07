# Phase 88: Module Decomposition -- Context

## Decisions

- **Structural refactoring only** -- no behavioral changes. All 319 existing tests must continue to pass.
- **swarmctl binary becomes thin wrapper** -- all CLI parsing, dispatch, and formatting moves into `swarm-runtime` library modules.
- **operator_http.rs splits into http/ subdirectory** -- route handlers grouped by domain (approval, evolution, evidence, review, control).
- **review_workbench.rs splits into workbench/ subdirectory** -- types, stores, harness, rendering separated.
- **replay.rs splits into replay/ subdirectory** -- types, stores, harness, rendering, validation separated.
- **lib.rs re-exports new module structure** -- `pub mod operator_http` becomes `pub mod http`, etc. Existing external consumers (swarmctl) update imports.
- **Each new submodule file stays under 1.5K lines** -- measured by `wc -l`.

## Deferred Ideas

- Full crate extraction (splitting swarm-runtime into separate crates)
- Rewriting the evolution module mesh
- Adding new detectors or response adapters
- detection/ submodule consolidation (Phase 89)
- Test coverage improvements (Phase 89)

## Claude's Discretion

- Exact file naming within subdirectories (e.g., `http/approval.rs` vs `http/approval_routes.rs`)
- Whether to keep a thin `operator_http.rs` facade that re-exports from `http/` or replace it entirely with `mod http`
- Internal helper placement (shared utilities can live in a `mod helpers` or stay in the most relevant submodule)
- Ordering of items within files

## Current File Sizes

| File | Lines | Tests |
|------|-------|-------|
| `src/bin/swarmctl.rs` | 3,512 | 0 (binary) |
| `src/operator_http.rs` | 5,392 | ~100 (integration) |
| `src/review_workbench.rs` | 3,805 | 0 |
| `src/replay.rs` | 5,345 | ~50 |

## Key Structural Observations

### swarmctl.rs
- Lines 1-74: imports
- Lines 75-252: `Cli` struct with ~40 global path args
- Lines 254-373: `Command` enum (120+ variants) and arg structs
- Lines 375-1487: More arg structs and enum conversions
- Lines 1488-3512: `async fn main()` -- harness construction (~100 lines) then massive match dispatch

### operator_http.rs
- Lines 1-130: imports, `OperatorSurfacePaths`, `OperatorHttpError`, `LocalOperatorSurface` struct
- Lines 131-280: `OperatorHttpState`, `OperatorApiError`, `OperatorReviewError` types
- Lines 280-715: `impl LocalOperatorSurface` (router construction, serve, setup)
- Lines 716-1600: API route handler functions (status, replay, review, evidence, approval, evolution, maintenance)
- Lines 1601-2055: Auth middleware, parsers, helper factories
- Lines 2055-2330: HTML rendering helpers (layout, pills, filters)
- Lines 2330-3736: Full-page HTML renderers (sessions, exports, capsules, evidence, promotion)
- Lines 3737-5392: Tests

### review_workbench.rs
- Lines 1-990: Domain types (enums, structs, error types)
- Lines 990-1990: File store implementations (7 stores)
- Lines 1990-2930: `DefaultReviewWorkbenchHarness` impl (the main harness)
- Lines 2930-3190: `pub fn render_*` functions
- Lines 3190-3800: Internal helpers (normalization, lane classification, crypto)

### replay.rs
- Lines 1-630: Domain types (scenarios, manifests, expectations, stores)
- Lines 630-810: Store implementations (memory + file stores)
- Lines 810-1300: More domain types (evaluation, experiments, verification, shadow, promotion review)
- Lines 1300-1810: More file stores (experiment, verification, shadow, promotion review)
- Lines 1810-2650: `DefaultReplayHarness` impl
- Lines 2650-2975: `pub fn render_*` functions
- Lines 2975-4093: Internal helpers (loaders, validators, comparison, gates)
- Lines 4094-5345: Tests
