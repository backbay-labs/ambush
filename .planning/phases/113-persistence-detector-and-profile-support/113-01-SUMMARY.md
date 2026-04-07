---
phase: 113-persistence-detector-and-profile-support
plan: 01
subsystem: detection
tags: [detection, persistence, mitre, profiles]
requirements-completed: [PERSIST-01, PERSIST-04]
one-liner: "A first-class `PersistenceDetector` now recognizes run-key, cron, systemd-timer, and scheduled-task footholds with ATT&CK-tagged evidence."
completed: 2026-04-07
---

# Phase 113 Plan 01 Summary

**A first-class `PersistenceDetector` now recognizes run-key, cron, systemd-timer, and scheduled-task footholds with ATT&CK-tagged evidence.**

## Accomplishments

- Added `PersistenceProfile` defaults and validation for suspicious registry paths, cron directories, systemd timer directories, and confidence thresholds.
- Implemented registry-run-key heuristics that emit `ThreatClass::Persistence` with ATT&CK technique `T1547.001`.
- Implemented file-based persistence heuristics for cron (`T1053.003`), systemd timers (`T1053.006`), and scheduled tasks (`T1053.005`).
- Attached `mitre_technique_id`, operating mode, and supporting persistence context directly into the finding evidence payload.
- Re-exported the new detector family through `swarm-whisker` so the runtime can construct it like the existing detector set.

## Files Created Or Modified

- `crates/swarm-whisker/src/persistence.rs`
- `crates/swarm-whisker/src/lib.rs`

## Verification

- `cargo test -p swarm-whisker --lib`
- `cargo test --workspace`

## Notes

- The persistence detector stays explicit about write-like operations so read-only registry or file activity does not produce false positives.
- ATT&CK IDs are emitted directly with each heuristic branch so later replay, enrichment, and operator surfaces do not need separate lookup tables.
