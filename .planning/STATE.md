---
gsd_state_version: 1.0
milestone: v1.19
milestone_name: local-evidence-review-surface
status: milestone-complete
last_updated: "2026-04-04T21:56:41Z"
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
**Current focus:** `v1.19 Local Evidence Review Surface` is shipped and archived. The next cycle has not been started yet.

## Memory

- `v1.16` added durable packet-set artifacts, portfolio-history snapshots, and CLI review surfaces above governance-ready packets.
- `v1.17` extended that operator lane into an authenticated local HTTP surface and durable maintenance audit trails.
- `v1.18` added signed evidence bundle export, local verification records, authenticated evidence reads, and advisory promotion evidence packets.
- `v1.19` completed the next ergonomics layer with a read-only local HTML review shell above the authenticated operator API.
- Operators can now browse evidence bundles by subject kind and verification status, inspect verification checks and signer metadata, and review promotion evidence packets without raw JSON-first workflows.
- The review surface still reuses the existing bearer-auth boundary, stable IDs, and underlying authenticated JSON routes instead of creating a second control plane.
- Quorum governance, multi-user control, and internet-exposed operator workflows remain deferred until independent trust boundaries exist.

## Next Command

`$gsd-new-milestone`
