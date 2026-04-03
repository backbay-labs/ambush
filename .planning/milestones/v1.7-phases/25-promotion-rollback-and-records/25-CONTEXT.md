# Phase 25 Context

## Goal

Make production promotion reversible and operator-readable through durable promotion records, manual rollback controls, and stable-ID reload.

## Current Reality

- Canary artifacts already prove the pattern for persisted rollback history and CLI-based reload.
- Production promotion needs the same operator ergonomics, but with restored-baseline semantics and one durable promotion record.
- `swarmctl` has no production-promotion commands or promotion-results directory today.

## Constraints

- Keep the operator surface CLI-first.
- Promotion records should be self-contained enough to inspect without chasing multiple hidden stores.
- Manual actions must remain explicit and auditable.

## Likely Implementation Shape

- Add manual halt and rollback commands for active promotions.
- Preserve canary evidence, promotion lineage, rollback target, and final recommendation in one report.
- Document the canary-to-production workflow and default config.

## Success Checks

- Operators can halt or roll back active promotions with explicit reasons.
- Promotion artifacts can be reloaded by stable ID after completion or rollback.
- Docs explain the end-to-end production-promotion flow.
