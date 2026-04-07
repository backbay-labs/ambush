---
phase: 114-supply-chain-detector-and-profile-support
type: context
created_at: 2026-04-07
depends_on: [112]
---

# Phase 114 Context

## Goal

Add a validated `SupplyChainDetector` that recognizes suspicious trusted-path execution, DLL side-loading, and signed-binary abuse patterns from normalized telemetry.

## Why This Phase Exists

The runtime already covers execution, credential access, lateral movement, and scripting abuse, but it still lacks a detector family for adversaries abusing trust rather than obviously malicious binaries. The next breadth milestone needs explicit supply-chain semantics and ATT&CK tagging so those findings can escalate and route distinctly.

## What Is Already True

- `ProcessStart` telemetry already carries parent, child, command line, and user context.
- The new `FilePersistence` payload can describe dropped libraries or executable artifacts in trusted paths.
- Existing detector families already model confidence thresholds and structured evidence in a way this detector can follow.

## Constraints

- Keep heuristics deterministic and local to the event payload; no external signer verification service in the hot path.
- Model "unsigned" or "untrusted signer" via normalized event fields supplied by telemetry rather than runtime filesystem inspection.
- Preserve the new `SupplyChain` threat class across status, escalation, metrics, and replay outputs.

## Decisions

- Treat supply-chain findings as a first-class `ThreatClass::SupplyChain` rather than collapsing them into execution or persistence.
- Use ATT&CK IDs in evidence for side-loading and signed-binary abuse so the detector outputs remain review-friendly.
- Keep the profile explicit about trusted paths, trusted signers, and suspicious loader/library pairs.

## Phase Direction

- Implement the supply-chain profile and heuristics in `swarm-whisker`.
- Then add focused coverage for each heuristic family and verify runtime/replay selection under `strategy: supply_chain`.
