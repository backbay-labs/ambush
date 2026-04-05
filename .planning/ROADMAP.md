# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.24) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-77 shipped across milestones v1.0 through v1.24. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

### v1.25 Operational Hardening And Service Extraction (In Progress)

**Milestone Goal:** Extract the detection hot path into a standalone service binary, wire rulesets and scenarios into detection config, add Prometheus metrics on the critical path, cover the full critical path with integration tests, and enforce strict clippy lints across the workspace.

## Phases

- [ ] **Phase 78: Service Extraction And Detection Binary** - Standalone `swarm-detect` binary runs the detection hot path with repo-owned rulesets and scenarios
- [ ] **Phase 79: Metrics And Integration Tests** - Critical path emits Prometheus metrics and integration tests prove the full detect-to-receipt flow
- [ ] **Phase 80: Clippy Enforcement** - Workspace denies `unwrap_used` and `expect_used` across all crates

## Phase Details

### Phase 78: Service Extraction And Detection Binary
**Goal**: Detection hot path runs as a standalone binary that loads rulesets and scenarios from repo-owned config independent of the operator workbench
**Depends on**: v1.24 (stable runtime to extract from)
**Requirements**: OPS-26, OPS-27
**Success Criteria** (what must be TRUE):
  1. Operator can build and run a `swarm-detect` binary that performs detection, pheromone deposit, and policy evaluation without the `swarmctl` operator workbench
  2. Rulesets from `rulesets/default.yaml` and scenarios from `scenarios/*.yaml` are loaded by the detection binary at startup via detection config
  3. The `swarm-detect` binary supports both `detect_only` and `live_response` runtime modes with the same semantics as the library runtime
**Plans**: TBD

Plans:
- [ ] 78-01: TBD
- [ ] 78-02: TBD

### Phase 79: Metrics And Integration Tests
**Goal**: Critical path emits structured Prometheus metrics and integration tests exercise the full telemetry-to-receipt flow
**Depends on**: Phase 78
**Requirements**: OPS-28, OPS-29
**Success Criteria** (what must be TRUE):
  1. Detection latency, policy evaluation time, and response execution time are recorded as Prometheus histogram metrics on every critical-path execution
  2. A `/metrics` endpoint on the detection service serves OpenMetrics-format text that external scrapers can consume
  3. Integration tests exercise the complete critical path from telemetry event ingestion through whisker detection, pheromone deposit, policy authorization, response execution, and receipt verification
  4. Integration tests run as part of `cargo test --workspace` and fail on any critical-path regression
**Plans**: 2 plans

Plans:
- [ ] 79-01-PLAN.md -- Prometheus histogram metrics for critical-path stages and /metrics endpoint
- [ ] 79-02-PLAN.md -- Integration tests for the full telemetry-to-receipt critical path

### Phase 80: Clippy Enforcement
**Goal**: Workspace enforces strict error-handling lints to eliminate panic-inducing unwrap and expect calls across all crates
**Depends on**: Nothing (independent of Phases 78-79)
**Requirements**: OPS-30
**Success Criteria** (what must be TRUE):
  1. Workspace `Cargo.toml` `[lints.clippy]` section denies `unwrap_used` and `expect_used`
  2. All existing crate code compiles cleanly under the new lint rules with zero violations
  3. CI workflow validates the stricter lints on every push to main
**Plans**: TBD

Plans:
- [ ] 80-01: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 78 -> 79 -> 80 (Phase 80 may run in parallel with 78 or 79 if desired)

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 78. Service Extraction And Detection Binary | 0/? | Not started | - |
| 79. Metrics And Integration Tests | 0/2 | Planned | - |
| 80. Clippy Enforcement | 0/? | Not started | - |
