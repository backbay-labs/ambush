---
phase: 78-service-extraction-and-detection-binary
verified: 2026-04-05T03:06:02Z
status: passed
score: 5/5 must-haves verified
---

# Phase 78: Service Extraction And Detection Binary Verification Report

**Phase Goal:** Detection hot path runs as a standalone binary that loads rulesets and scenarios from repo-owned config independent of the operator workbench.
**Verified:** 2026-04-05T03:06:02Z
**Status:** passed

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Operator can build and run `swarm-detect` without the `swarmctl` workbench | ✓ VERIFIED | `crates/swarm-runtime/src/bin/swarm_detect.rs` now builds as a standalone binary and passed `cargo build -p swarm-runtime --bin swarm_detect`. |
| 2 | Rulesets from `rulesets/default.yaml` and scenarios from repo-owned YAML fixtures load at startup | ✓ VERIFIED | `swarm_detect` uses `load_config`, `scenario_paths_in_dir`, and `load_scenario_manifest` to load repo-owned configuration and scenario fixtures directly. |
| 3 | Scenario events execute through detection, pheromone deposit, policy evaluation, and response handling | ✓ VERIFIED | The binary reuses `RuntimeService::process_event`, and the scenario run over `scenarios/` produced findings, deposits, policy verdicts, and response kinds. |
| 4 | The standalone binary respects `detect_only` and `live_response` runtime semantics | ✓ VERIFIED | `swarm_detect` constructs `SwarmRuntime` from the loaded runtime mode and reports the mode at startup before processing events. |
| 5 | JSON and human-readable output both expose per-event and summary results | ✓ VERIFIED | The binary emits structured JSON fields for `scenario`, `event_id`, `finding_count`, `deposit_count`, `policy_verdict`, and `response_kind`, while the text mode prints equivalent per-event and per-scenario summaries. |

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/swarm-runtime/src/bin/swarm_detect.rs` | Standalone detection binary | ✓ EXISTS + SUBSTANTIVE | Handles config loading, detector selection, scenario discovery, event processing, and text/JSON output. |
| `crates/swarm-runtime/src/control.rs` | Public detector factory | ✓ EXISTS + SUBSTANTIVE | `SupportedDetector` and `supported_detector` are now public and reused by binaries and tests. |
| `crates/swarm-runtime/src/replay.rs` | Public scenario loader | ✓ EXISTS + SUBSTANTIVE | `LoadedReplayScenario`, `load_scenario_manifest`, and `scenario_paths_in_dir` are public for shared scenario loading. |

## Requirements Coverage

| Requirement | Status | Evidence |
|-------------|--------|----------|
| OPS-26 | ✓ SATISFIED | `swarm-detect` is a standalone detection binary separate from the operator workbench CLI. |
| OPS-27 | ✓ SATISFIED | Rulesets and scenario fixtures now load through shared runtime config and replay helpers instead of only through `swarmctl`. |

## Automated Verification

- `cargo build -p swarm-runtime --bin swarm_detect`
- `cargo run -p swarm-runtime --bin swarm_detect -- --config rulesets/default.yaml --scenarios-dir scenarios/`
- `cargo run -p swarm-runtime --bin swarm_detect -- --config rulesets/default.yaml`
- `cargo test -p swarm-runtime --lib -- --quiet`

## Gaps Summary

**No gaps found.** Phase goal achieved.

---
*Verified: 2026-04-05T03:06:02Z*
*Verifier: Codex*
