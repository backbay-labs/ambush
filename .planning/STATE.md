---
gsd_state_version: 1.0
milestone: v1.22
milestone_name: Portable Review Capsules And External Handoff
status: defining-requirements
last_updated: "2026-04-04T23:25:21Z"
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
**Current focus:** `v1.22 Portable Review Capsules And External Handoff` is active. The next planned work is to make cross-lane review portable and independently verifiable without opening live multi-user control.

## Memory

- `v1.16` added durable packet-set artifacts, portfolio-history snapshots, and CLI review surfaces above governance-ready packets.
- `v1.17` extended that operator lane into an authenticated local HTTP surface and durable maintenance audit trails.
- `v1.18` added signed evidence bundle export, local verification records, authenticated evidence reads, and advisory promotion evidence packets.
- `v1.19` completed the next ergonomics layer with a read-only local HTML review shell above the authenticated operator API.
- `v1.20` completed the next operator workflow seam with durable review sessions, reviewed export snapshots, and bounded evidence re-verification handoffs above the authenticated operator API.
- `v1.21` completed the next operator seam with lane-aware review sessions, cross-lane comparison exports, and advisory promotion-readiness reviews across governance-prep, canary, and production evidence.
- Cross-lane review still reuses the existing bearer-auth boundary, stable IDs, and authenticated JSON plus HTML surfaces instead of creating a second control plane.
- `v1.22` is the active cycle: export portable review capsules, verify imported capsules locally, and preserve delegation continuity.
- `v1.23` is queued to define approval sets and signed approval ledgers.
- `v1.24` is queued to turn those ledgers into receipt-ready verdict packs and human-gate review artifacts.
- Quorum governance, multi-user control, and internet-exposed operator workflows remain deferred until independent trust boundaries exist.

## Next Command

`$gsd-plan-phase 68`
