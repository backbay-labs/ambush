---
phase: 118-operational-hardening
plan: 01
subsystem: runtime
tags: [secrets, hot-reload, config, arc-swap, file-watch]

requires:
  - phase: 116-agent-safety-hardening
    provides: signed deposit baseline and agent tick timeout

provides:
  - reload_secrets_only() method on IngestState for secret-only hot rotation
  - config_template stored in IngestState for template-based re-resolution
  - load_config_unresolved() for loading configs without secret resolution
  - SecretChange trigger routed to lightweight reload path in swarm_detect

affects: [118-02-dead-letter-rotation, 119-pheromone-test-suite]

tech-stack:
  added: []
  patterns:
    - "Config template storage: unresolved config stored alongside resolved stack for secret re-resolution"
    - "Selective reload: SecretChange vs FileChange/Signal determines reload depth"

key-files:
  created: []
  modified:
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/ingest.rs
    - crates/swarm-runtime/src/bin/swarm_detect.rs
    - crates/swarm-response/src/siem.rs

key-decisions:
  - "Stored unresolved config template in IngestState via ArcSwap rather than re-reading YAML on each secret rotation"
  - "from_config now resolves secrets internally so callers pass unresolved configs and templates are always captured"
  - "reload_from_disk updated to also store unresolved template for consistency"

patterns-established:
  - "Config template pattern: store pre-resolution config alongside resolved runtime for selective field re-resolution"

requirements-completed: [HARDEN-08]

duration: 12min
completed: 2026-04-07
---

# Phase 118 Plan 01: Secret-Dir Hot Rotation Summary

**Independent secret-dir hot rotation via stored config templates and selective reload_secrets_only path**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-07T23:07:14Z
- **Completed:** 2026-04-07T23:19:15Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 4

## Accomplishments
- Implemented `reload_secrets_only()` on `IngestState` that re-resolves `@secret:` references without YAML re-parsing
- Stored unresolved config template in `IngestState` via `ArcSwap` so secret re-resolution never needs disk YAML reads
- Routed `SecretChange` trigger in `swarm_detect` binary to the lightweight `reload_secrets_only` path
- Added `load_config_unresolved()` and `resolve_outbound_secrets` (now public) for split load/resolve workflow
- Three tests prove: auth_token updates after rotation, detector strategy preserved, no YAML file read required

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Add failing tests** - `289d470` (test)
2. **Task 1 (GREEN): Implement reload_secrets_only** - `da5b433` (feat)

_TDD task: RED committed failing tests, GREEN committed passing implementation._

## Files Created/Modified
- `crates/swarm-runtime/src/config.rs` - Made `resolve_outbound_secrets` public, added `load_config_unresolved()`
- `crates/swarm-runtime/src/ingest.rs` - Added `config_template` field, `reload_secrets_only()`, updated `from_config`/`from_path`/`reload_from_disk`
- `crates/swarm-runtime/src/bin/swarm_detect.rs` - Routed `SecretChange` to `reload_secrets_only()` with `continue` to skip full reload
- `crates/swarm-response/src/siem.rs` - Fixed pre-existing `DeadLetterJournal::from_path` missing argument (Rule 3)

## Decisions Made
- Stored unresolved config template in `IngestState` rather than re-reading YAML on each secret rotation. This ensures `reload_secrets_only` never touches the filesystem for config (only for secret files), making it strictly lighter than `reload_from_disk`.
- Changed `from_config` to resolve secrets internally so the template is always captured regardless of the caller's setup.
- Updated `reload_from_disk` to also refresh the stored template, so a full config reload followed by a secret rotation uses the latest config structure.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed DeadLetterJournal::from_path call in siem.rs**
- **Found during:** Task 1 (compilation)
- **Issue:** Pre-existing breaking change in `dead_letter.rs` added `max_bytes` parameter but `siem.rs` caller was not updated
- **Fix:** Added `None` as second argument to `DeadLetterJournal::from_path` call
- **Files modified:** `crates/swarm-response/src/siem.rs`
- **Verification:** Compilation succeeds
- **Committed in:** `289d470` (part of RED commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to unblock compilation. No scope creep.

## Issues Encountered
- Pre-existing uncommitted changes from parallel phase execution (117, 118-02) caused compilation errors. The `max_dead_letter_bytes` field and `DeadLetterJournal` API changes were from another plan's partial work. Only the siem.rs fix was needed for this plan's scope.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Secret hot-rotation path complete and tested
- Phase 118-02 (dead-letter rotation) can proceed independently
- Phase 119 (pheromone test suite) unblocked

---
*Phase: 118-operational-hardening*
*Completed: 2026-04-07*
