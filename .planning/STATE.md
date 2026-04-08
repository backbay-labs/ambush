---
gsd_state_version: 1.0
milestone: v1.38
milestone_name: Multi-Detector Composition And Network Detection
status: active
last_updated: "2026-04-08T02:00:00Z"
progress:
  total_phases: 0
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

Phase: Not started (defining roadmap)
Plan: —
Status: Defining roadmap for v1.38
Last activity: 2026-04-08 — Milestone v1.38 started

Progress: [░░░░░░░░░░] 0%

## Memory

- `v1.37.1` shipped signed deposits, tick timeout, threat-intel GC, bridge resilience, secret hot-rotation, dead-letter rotation, and pheromone test suite.
- v1.38 has 10 requirements: COMPOSE-01–05 (multi-detector composition) and NETWORK-01–05 (C2/network detection).
- Currently `SupportedDetector` in control.rs dispatches a single strategy. CompositeDetector will hold Vec<Box<dyn DetectionStrategy>>.
- `TelemetryPayload::NetworkConnect` exists but zero detectors evaluate it — C2 beaconing is completely blind.
- `ThreatClass::CommandAndControl` exists in the enum but nothing emits it.
- `PheromoneConcentration.distinct_sources` already counts unique agent_ids — cross-strategy deposits need distinct agent_id per strategy.

## Next Command

`spawn roadmapper to create phases for v1.38`
