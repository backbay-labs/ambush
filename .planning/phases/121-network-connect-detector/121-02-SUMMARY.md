---
phase: 121-network-connect-detector
plan: 02
subsystem: runtime
tags: [rust, runtime, network, rollout, replay, threat-intel]
requires:
  - phase: 121-network-connect-detector
    plan: 01
    provides: NetworkConnectDetector and validated NetworkConnectProfile in swarm-whisker
provides:
  - runtime profile merge and factory support for `strategy: network_connect`
  - rollout, promotion, and replay manifest acceptance for `network_connect`
  - runtime-owned destination-IP threat-intel enrichment proof for network findings
  - single-strategy runtime integration coverage for signed `CommandAndControl` deposits
affects:
  - phase-123
  - canary
  - promotion
  - replay
tech-stack:
  added: []
  patterns:
    - runtime-owned threat-intel enrichment stays in `detect_and_deposit()`
    - rollout/replay detector families reuse shared runtime detector-factory seams
key-files:
  created:
    - crates/swarm-runtime/tests/network_connect_integration.rs
    - .planning/phases/121-network-connect-detector/121-02-SUMMARY.md
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/control.rs
    - crates/swarm-runtime/src/canary.rs
    - crates/swarm-runtime/src/promotion.rs
    - crates/swarm-runtime/src/replay/core.inc
    - crates/swarm-runtime/src/detection/pipeline.rs
    - crates/swarm-runtime/tests/critical_path_integration.rs
    - rulesets/default.yaml
    - .planning/ROADMAP.md
    - .planning/REQUIREMENTS.md
    - .planning/STATE.md
key-decisions:
  - Kept `NetworkConnectDetector::evaluate()` synchronous and substrate-free; destination-IP threat-intel lookup remains runtime-owned in `detect_and_deposit()`.
  - Extended rollout and replay surfaces by accepting `network_connect` through the existing shared detector-family switchboards instead of adding a detector-specific side path.
  - Reconciled roadmap and requirement wording to the actual runtime architecture so later phases do not regress toward an async detector-contract expansion.
patterns-established:
  - "If a detector family is supported in the shipped runtime, canary/promotion/replay manifests should accept it through the same detector-factory surface."
  - "Threat-intel boosts for NetworkConnect findings should be proven in pipeline tests, not by widening the detector interface."
requirements-completed: [NETWORK-01, NETWORK-02, NETWORK-03]
completed: 2026-04-08
---

# Phase 121 Plan 02 Summary

**`network_connect` now builds through the live runtime path, rollout tooling, and replay manifests, with IP threat-intel enrichment proven in the existing pipeline and single-strategy signed deposits covered by focused integration tests**

## Accomplishments

- Added `profiles.network_connect` to `DetectorProfilesConfig`, implemented `network_connect_profile()` merge/validation support, and covered override-merging with `network_connect_profile_merges_overrides`.
- Wired `NetworkConnectDetector` into `build_composite_detector()` and extended rollout/replay family switchboards so canary, promotion, and replay candidate manifests no longer reject `network_connect`.
- Added `network_findings_are_enriched_by_matching_ip_threat_intel` in the runtime pipeline tests to prove destination-IP threat-intel matches raise confidence and annotate evidence in `detect_and_deposit()`.
- Added `crates/swarm-runtime/tests/network_connect_integration.rs` to prove suspicious-port and low-jitter beacon detections produce signed `ThreatClass::CommandAndControl` deposits through the live runtime path.
- Updated `rulesets/default.yaml`, `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, and `.planning/STATE.md` so the documented contract matches the runtime-owned enrichment architecture and the completed Phase 121 status.

## Task Commits

No commits were created. Changes remain as targeted local edits.

## Deviations From Plan

### Auto-fixed compile and refactor alignment

1. The workspace already had in-progress rollout/refactor changes that introduced a shared `detector_factory` path for canary, promotion, and replay. To keep the plan changes compiling cleanly, I aligned `crates/swarm-runtime/src/canary.rs`, `crates/swarm-runtime/src/promotion.rs`, and `crates/swarm-runtime/src/replay/core.inc` to that current worktree shape instead of forcing the older duplicated switchboards back in.
2. Two files outside the original ownership list required minimal compile-safe updates because they already participated in that shared rollout path:
   - `crates/swarm-runtime/src/detector_factory.rs` needed the new `DetectorCandidateManifest::NetworkConnect` branch.
   - `crates/swarm-runtime/src/strategy.rs` needed `strategy_id: None` in rollout test fixtures after the active rollout-scope config fields landed.
3. `ExperimentLineage` in `crates/swarm-runtime/src/replay/core.inc` needed `PartialEq, Eq` so the already-present canary lineage checks compiled.
4. `cargo clippy -D warnings` required removing one `expect()` from the promotion rollout-scope helper.

**Impact on plan:** These were compile- and lint-driven adjustments only. They stayed within the runtime rollout/replay support seam that Plan 02 already targeted and did not expand into Phase 123 cross-strategy proof work.

## Verification Notes

- `cargo test -p swarm-runtime network_connect_profile_merges_overrides` passed
- `cargo test -p swarm-runtime --test network_connect_integration` passed
- `cargo test -p swarm-runtime network_findings_are_enriched_by_matching_ip_threat_intel` passed
- `cargo test -p swarm-runtime --test critical_path_integration composite_detector_factory_covers_all_runtime_strategies` passed
- `cargo test -p swarm-runtime --lib canary` passed
- `cargo test -p swarm-runtime --lib promotion` passed
- `cargo test -p swarm-runtime --lib replay` passed
- `cargo clippy -p swarm-runtime --all-targets -- -D warnings` passed

## Issues Encountered

None remain. The known unrelated workspace-level failure in `evolution::tests::evolution_handoff_persists_pending_launch_packet` was not part of this targeted verification set.

## Next Phase Readiness

Phase 123 can now assume:

- `strategy: network_connect` is supported across runtime config resolution, control construction, canary, promotion, and replay candidate manifests
- destination-IP threat-intel enrichment for network findings is runtime-owned and already covered by tests
- single-strategy `network_connect` findings already flow through to signed `CommandAndControl` deposits, so the remaining work is the broader multi-strategy proof
