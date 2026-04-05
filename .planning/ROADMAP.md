# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.28) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-87 shipped across milestones v1.0 through v1.28. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

### v1.29 Runtime Decomposition And Test Coverage (In Progress)

**Milestone Goal:** Split the 49K-line swarm-runtime monolith into focused modules, extract swarmctl CLI logic into testable library harnesses, and raise test coverage from 0.23% to 2-3% across the crate.

## Phases

- [ ] **Phase 88: Module Decomposition** - Split the 4 largest monolithic files and extract swarmctl binary logic into testable library harnesses
- [ ] **Phase 89: Test Coverage And Hot-Path Consolidation** - Add tests to newly-split modules and consolidate hot-path detection into a detection/ submodule

## Phase Details

### Phase 88: Module Decomposition
**Goal**: The 4 largest monolithic files in swarm-runtime are split into focused, bounded modules and the swarmctl binary is reduced to a thin CLI wrapper
**Depends on**: Nothing (first phase of v1.29)
**Requirements**: REFAC-01, REFAC-02, REFAC-03, REFAC-04
**Success Criteria** (what must be TRUE):
  1. `swarmctl` binary is under 300 lines and all CLI parsing, dispatch, and formatting logic lives in library modules that can be tested with `cargo test`
  2. `operator_http.rs` no longer exists as a single file; its route handlers live in 4-5 focused modules (approval, evolution, evidence, governance, review) each under 1.5K lines
  3. `review_workbench.rs` no longer exists as a single file; its logic lives in focused modules (sessions, capsules, exports, readiness) each with clear public API boundaries
  4. `replay.rs` no longer exists as a single file; its logic lives in focused modules (scenarios, execution, store, experiments) each under 1.5K lines
  5. `cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings` passes with zero regressions against the existing 114+ test suite
**Plans**: TBD

Plans:
- [ ] 88-01: TBD
- [ ] 88-02: TBD

### Phase 89: Test Coverage And Hot-Path Consolidation
**Goal**: The newly-split modules have meaningful test coverage and hot-path detection modules are consolidated into a detection/ submodule with clear boundaries
**Depends on**: Phase 88
**Requirements**: TEST-01, TEST-02, TEST-03
**Success Criteria** (what must be TRUE):
  1. `cargo test --workspace` reports at least 2% line coverage across swarm-runtime (up from 0.23%), measurable via `cargo llvm-cov` or equivalent
  2. `ingest.rs` has tests covering event validation (valid and malformed payloads), HTTP error responses (bad content-type, oversized body), and batch processing edge cases (empty batch, partial failure)
  3. Hot-path modules (pipeline, service, detection logic) live under a `detection/` submodule with a single public re-export boundary, and existing imports compile without manual fixups outside the crate
  4. The 5 largest previously-untested modules each have at least one test exercising their primary code path
**Plans**: 2 plans

Plans:
- [ ] 89-01-PLAN.md -- Consolidate pipeline.rs and metrics.rs into detection/ submodule with public re-export boundary
- [ ] 89-02-PLAN.md -- Add test coverage to ingest.rs and the 4 other largest previously-untested modules

## Progress

**Execution Order:**
Phases execute in numeric order: 88 -> 89

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 88. Module Decomposition | 0/? | Not started | - |
| 89. Test Coverage And Hot-Path Consolidation | 0/2 | Planned | - |

---
*Last shipped milestone: v1.28 Durable Substrate And Multi-Instance Coordination on 2026-04-05*
