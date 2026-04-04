---
gsd_state_version: 1.0
milestone: v1.20
milestone_name: evidence-workbench-and-review-handoffs
status: planning
last_updated: "2026-04-04T22:02:48Z"
progress:
  total_phases: 3
  completed_phases: 0
  total_plans: 3
  completed_plans: 0
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-04)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** `v1.20 Evidence Workbench And Review Handoffs` is active and Phase 62 is next.

## Memory

- `v1.16` added durable packet-set artifacts, portfolio-history snapshots, and CLI review surfaces above governance-ready packets.
- `v1.17` extended that operator lane into an authenticated local HTTP surface and durable maintenance audit trails.
- `v1.18` added signed evidence bundle export, local verification records, authenticated evidence reads, and advisory promotion evidence packets.
- `v1.19` completed the next ergonomics layer with a read-only local HTML review shell above the authenticated operator API.
- Operators can now browse evidence bundles by subject kind and verification status, inspect verification checks and signer metadata, and review promotion evidence packets without raw JSON-first workflows.
- The review surface still reuses the existing bearer-auth boundary, stable IDs, and underlying authenticated JSON routes instead of creating a second control plane.
- `v1.20` will focus on turning that review shell into a practical operator workbench for multi-artifact sessions, evidence comparison and export, and bounded review-driven maintenance handoff.
- Quorum governance, multi-user control, and internet-exposed operator workflows remain deferred until independent trust boundaries exist.

## Next Command

`$gsd-plan-phase 62`
