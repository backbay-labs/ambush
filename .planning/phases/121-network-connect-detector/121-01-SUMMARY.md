---
phase: 121-network-connect-detector
plan: 01
subsystem: infra
tags: [rust, whisker, network, beaconing, c2]
requires:
  - phase: 120-02
    provides: composite detector wiring and shared detector profile validation patterns
provides:
  - stateful `NetworkConnectDetector` for `TelemetryPayload::NetworkConnect`
  - validated `NetworkConnectProfile` with suspicious port and per-process allowlist controls
  - focused whisker tests for beaconing, anomalous ports, and timestamp normalization
affects: [phase-121-02, runtime-wiring, phase-123]
tech-stack:
  added: []
  patterns: [Arc<Mutex<HashMap<BeaconKey, VecDeque<i64>>>> state tracking, one-finding-per-event heuristic aggregation]
key-files:
  created: [crates/swarm-whisker/src/network_connect.rs]
  modified: [crates/swarm-whisker/src/lib.rs, .planning/phases/121-network-connect-detector/121-01-SUMMARY.md]
key-decisions:
  - "Kept `DetectionStrategy::evaluate()` synchronous and detector-local, with no substrate or threat-intel lookup."
  - "Aggregated suspicious-port, allowlist-mismatch, and beaconing heuristics into a single `ThreatClass::CommandAndControl` finding per event."
  - "Normalized beacon state on host/process/ip/port/protocol and reused the existing seconds-vs-ms timestamp guard."
patterns-established:
  - "Network connect detectors should key sliding-window state on normalized destination tuples plus host identity."
  - "Port anomaly heuristics should stay medium confidence unless beaconing elevates the event."
requirements-completed: [NETWORK-01, NETWORK-03]
duration: 4m
completed: 2026-04-08
---

# Phase 121: Network Connect Detector Summary

**Network connect C2 detection now covers suspicious ports, process-to-port mismatches, and low-jitter beaconing with a single finding per event**

## Performance

- **Duration:** 4m
- **Started:** 2026-04-08T03:51:54Z
- **Completed:** 2026-04-08T03:56:14Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Added `NetworkConnectProfile` defaults and validation for suspicious ports, allowlist controls, beacon thresholds, and confidence thresholds.
- Implemented `NetworkConnectDetector` with bounded sliding-window beacon tracking keyed by host/process/destination tuple and emitting `ThreatClass::CommandAndControl`.
- Added deterministic whisker tests covering validation failure, non-network silence, suspicious ports, allowlist mismatch, allowlisted pairs, beacon positives, noisy negatives, timestamp normalization, and overlapping heuristic single-finding behavior.

## Task Commits

No commits were created. The repository already had unrelated in-progress changes, so this plan was left as targeted local edits in the owned files plus the required summary artifact.

## Files Created/Modified
- `crates/swarm-whisker/src/network_connect.rs` - New detector module with profile validation, stateful beacon analysis, anomaly heuristics, and focused unit tests.
- `crates/swarm-whisker/src/lib.rs` - Exported the new module and public detector/profile types.
- `.planning/phases/121-network-connect-detector/121-01-SUMMARY.md` - Recorded execution outcome, verification, and decisions.

## Decisions Made
- Used a narrow built-in suspicious port set for classic C2/backdoor ports to keep port-anomaly findings intentionally conservative.
- Stored normalized allowlist keys and deduped port lists inside the detector so evidence and matching stay deterministic.
- Emitted high severity only when beaconing is present; pure port anomalies remain medium severity and medium confidence.

## Deviations from Plan

None. The implementation stayed within the two owned source files and the required summary file.

## Verification Notes

- `cargo test -p swarm-whisker network_connect` passed.
- `cargo test -p swarm-whisker --lib` passed.
- `cargo clippy -p swarm-whisker --all-targets -- -D warnings` passed.
- Acceptance grep checks for detector/profile exports, beacon state shape, and required tests matched in the owned files.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The whisker crate now exposes `NetworkConnectDetector` and `NetworkConnectProfile` for runtime wiring in Plan 02.
- No detector contract changes were required, so runtime integration can reuse the existing synchronous composite path and later threat-intel enrichment stage.

---
*Phase: 121-network-connect-detector*
*Completed: 2026-04-08*
