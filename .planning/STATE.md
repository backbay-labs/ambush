---
gsd_state_version: 1.0
milestone: v1.21
milestone_name: Cross-Lane Promotion Review
status: defining-requirements
last_updated: "2026-04-04T23:30:00Z"
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
**Current focus:** `v1.21 Cross-Lane Promotion Review` is active. The next planned work is to unify governance-prep, canary, and production evidence into one advisory cross-lane review flow.

## Memory

- `v1.16` added durable packet-set artifacts, portfolio-history snapshots, and CLI review surfaces above governance-ready packets.
- `v1.17` extended that operator lane into an authenticated local HTTP surface and durable maintenance audit trails.
- `v1.18` added signed evidence bundle export, local verification records, authenticated evidence reads, and advisory promotion evidence packets.
- `v1.19` completed the next ergonomics layer with a read-only local HTML review shell above the authenticated operator API.
- Operators can now browse evidence bundles by subject kind and verification status, inspect verification checks and signer metadata, and review promotion evidence packets without raw JSON-first workflows.
- The review surface still reuses the existing bearer-auth boundary, stable IDs, and underlying authenticated JSON routes instead of creating a second control plane.
- `v1.20` completed the next operator workflow seam with durable review sessions, reviewed export snapshots, and bounded evidence re-verification handoffs above the authenticated operator API.
- `v1.21` is planned as the next operator step: cross-lane sessions and promotion-readiness review above governance-prep, canary, and production evidence.
- `v1.22` is queued to make those reviewed sessions portable and externally verifiable without opening multi-user live control.
- `v1.23` is queued to introduce approval ledgers and quorum-readiness artifacts before any real distributed governance work starts.
- Quorum governance, multi-user control, and internet-exposed operator workflows remain deferred until independent trust boundaries exist.

## Next Command

`$gsd-plan-phase 65`
