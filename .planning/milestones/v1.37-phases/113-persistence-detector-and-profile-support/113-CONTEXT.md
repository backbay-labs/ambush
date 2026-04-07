---
phase: 113-persistence-detector-and-profile-support
type: context
created_at: 2026-04-07
depends_on: [112]
---

# Phase 113 Context

## Goal

Add a validated `PersistenceDetector` that identifies common durable foothold mechanisms from normalized persistence telemetry.

## Why This Phase Exists

The runtime already sees process, registry, and filesystem-adjacent events, but it still lacks a detector family dedicated to adversaries attempting to survive reboot or operator cleanup. The milestone requirements call out scheduled tasks, cron, systemd timers, and run-key writes as the first persistence coverage surface.

## What Is Already True

- Existing detectors already follow a stable `Profile` plus `Detector` pattern with `from_profile()`, `validate()`, and structured evidence output.
- `findings_to_deposits` already converts detector findings into pheromone deposits once threat class, severity, and confidence are set.
- Registry and file persistence telemetry will be available once phase 112 lands.

## Constraints

- Keep heuristics deterministic and low-latency; no filesystem lookups or signature verification in this detector.
- Prefer path and operation heuristics that work across Windows and Unix-like persistence mechanisms.
- Emit `mitre_technique_id` in every persistence finding so the new milestone keeps ATT&CK alignment explicit.

## Decisions

- Use `ThreatClass::Persistence` for every finding in this detector family.
- Keep profile controls focused on suspicious paths/directories and threshold tuning instead of building a full rules engine.
- Treat scheduled-task artifacts in file persistence as high-confidence findings because they map directly to durable execution footholds.

## Phase Direction

- Implement the profile and detector in `swarm-whisker`.
- Then add focused unit tests for positive and negative persistence paths plus runtime-facing smoke coverage for strategy selection.
