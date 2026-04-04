---
gsd_state_version: 1.0
milestone: v1.22
milestone_name: Portable Review Capsules And External Handoff
status: milestone-complete
last_updated: "2026-04-04T23:59:00Z"
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 3
  completed_plans: 3
---

# State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-04)

**Core value:** Detect real threats quickly enough to take safe action before the window to respond closes.
**Current focus:** `v1.22 Portable Review Capsules And External Handoff` is complete. The repo is ready to start the next milestone cycle.

## Memory

- `v1.16` added durable packet-set artifacts, portfolio-history snapshots, and CLI review surfaces above governance-ready packets.
- `v1.17` extended that operator lane into an authenticated local HTTP surface and durable maintenance audit trails.
- `v1.18` added signed evidence bundle export, local verification records, authenticated evidence reads, and advisory promotion evidence packets.
- `v1.19` completed the next ergonomics layer with a read-only local HTML review shell above the authenticated operator API.
- `v1.20` completed the next operator workflow seam with durable review sessions, reviewed export snapshots, and bounded evidence re-verification handoffs above the authenticated operator API.
- `v1.21` completed the next operator seam with lane-aware review sessions, cross-lane comparison exports, and advisory promotion-readiness reviews across governance-prep, canary, and production evidence.
- `v1.22` now adds signed portable review capsules, imported capsule verification with local trust state, and advisory-only delegation continuity packets above that same workbench lane.
- Cross-lane review and portable capsule handoff still reuse the existing bearer-auth boundary, stable IDs, and authenticated JSON plus HTML surfaces instead of creating a second control plane.
- `v1.23 Approval Ledger And Quorum Readiness` remains the next queued cycle, followed by `v1.24 Approval Receipt Packs And Human Gate Prep`.
- Quorum governance, multi-user control, and internet-exposed operator workflows remain deferred until independent trust boundaries exist.

## Next Command

`$gsd-new-milestone`
