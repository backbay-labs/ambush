---
phase: 108-canonical-siem-forward-adapter
plan: 02
subsystem: runtime
tags: [siem, runtime, delivery]
requirements-completed: [SIEM-01]
one-liner: "The live runtime now forwards findings through the configured SIEM adapter even when no response action is proposed."
completed: 2026-04-07
---

# Phase 108 Plan 02 Summary

**The live runtime now forwards findings through the configured SIEM adapter even when no response action is proposed.**

## Accomplishments

- Wired optional `SiemFindingForwarder` creation into `RuntimeService::new` from repo-owned runtime config.
- Forwarded each emitted finding from `RuntimeService::process_event` before response-action selection, which keeps SIEM delivery independent from live response execution.
- Logged successful, degraded, and failed SIEM outcomes explicitly without breaking replay persistence or the hot path.
- Added a runtime test proving canonical finding delivery reaches the SIEM path from real event processing.
- Preserved the existing response-action lane so response execution and SIEM forwarding can coexist.

## Files Created Or Modified

- `crates/swarm-runtime/src/service.rs`

## Verification

- `cargo test -p swarm-runtime --lib`
- `cargo build --workspace`

## Notes

- Runtime forwarding intentionally happens before `request_builder` decides whether a host action should run, so passive external delivery does not depend on response policy outcomes.
