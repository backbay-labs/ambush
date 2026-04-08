---
gsd_state_version: 1.0
milestone: v1.38
milestone_name: Multi-Detector Composition And Network Detection
status: active
last_updated: "2026-04-08T03:00:00Z"
progress:
  total_phases: 4
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-08)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** v1.38 Multi-Detector Composition And Network Detection

## Current Position

Phase: 120 of 123 (Composite Detector And Config Migration)
Plan: --
Status: Ready to plan Phase 120
Last activity: 2026-04-08 -- Roadmap created for v1.38 (4 phases, 10 requirements)

Progress: [░░░░░░░░░░] 0%

## Memory

- `v1.37.1` shipped signed deposits, tick timeout, threat-intel GC, bridge resilience, secret hot-rotation, dead-letter rotation, and pheromone test suite.
- v1.38 has 10 requirements across 4 phases: composition foundation (120), network detector (121), cross-strategy signals (122), integration proof (123).
- Phase 121 and 122 can execute in parallel after 120 completes. Phase 123 depends on both 121 and 122.
- Currently `SupportedDetector` in control.rs dispatches a single strategy. CompositeDetector will hold Vec<Box<dyn DetectionStrategy>>.
- `TelemetryPayload::NetworkConnect` exists but zero detectors evaluate it -- C2 beaconing is completely blind.
- `ThreatClass::CommandAndControl` exists in the enum but nothing emits it.
- `PheromoneConcentration.distinct_sources` already counts unique agent_ids -- cross-strategy deposits need distinct agent_id per strategy.

## Next Command

`/gsd:plan-phase 120`
