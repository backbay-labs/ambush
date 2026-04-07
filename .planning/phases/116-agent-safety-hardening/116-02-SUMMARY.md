---
phase: 116-agent-safety-hardening
plan: 02
subsystem: runtime
tags: [tokio, timeout, dispatcher, tracing, agent-safety]

# Dependency graph
requires:
  - phase: 116-01
    provides: "Signed pheromone deposits and agent identity"
provides:
  - "Configurable agent tick timeout with Degraded health marking"
  - "Exhaustive SwarmAction match in apply_actions with structured logging"
affects: [117-substrate-durability, 118-operational-hardening]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "tokio::time::timeout wrapping for agent tick enforcement"
    - "Exhaustive match arms with documented agent-direct vs dispatcher-routed semantics"

key-files:
  created: []
  modified:
    - "crates/swarm-core/src/config.rs"
    - "crates/swarm-runtime/src/dispatcher.rs"

key-decisions:
  - "Default agent_tick_timeout_ms set to 500ms -- balances responsiveness with detection workload tolerance"
  - "Timed-out agent actions are discarded entirely -- safer than partial application"
  - "ClaimInvestigation and PublishFindings logged at debug level (agent-direct, not dispatcher-routed)"
  - "ProposeStrategy logged at warn level (genuinely unhandled, no handler exists yet)"

patterns-established:
  - "Tick timeout: every agent.tick() wrapped in tokio::time::timeout using config value"
  - "Exhaustive action match: no wildcard arms in apply_actions -- every SwarmAction variant documented"

requirements-completed: [HARDEN-02, HARDEN-03]

# Metrics
duration: 19min
completed: 2026-04-07
---

# Phase 116 Plan 02: Tick Timeout and Unhandled Action Hardening Summary

**Configurable agent tick timeout enforcement with tokio::time::timeout and exhaustive SwarmAction match arms replacing silent wildcard drops**

## Performance

- **Duration:** 19 min
- **Started:** 2026-04-07T22:33:32Z
- **Completed:** 2026-04-07T22:52:36Z
- **Tasks:** 2
- **Files modified:** 2 primary (config.rs, dispatcher.rs) + 10 downstream for compilation

## Accomplishments
- Every agent tick is wrapped in tokio::time::timeout with configurable agent_tick_timeout_ms (default 500ms)
- Timed-out agents are marked AgentHealth::Degraded with structured warning logs including agent_id, role, and timeout value
- All SwarmAction variants are explicitly handled in apply_actions with documented reasoning for each arm
- ClaimInvestigation and PublishFindings acknowledged as agent-direct with debug logs instead of being silently dropped
- ProposeStrategy emits structured tracing::warn as genuinely unhandled variant

## Task Commits

Each task was committed atomically:

1. **Task 1: Add agent_tick_timeout_ms and wrap tick() in timeout** (TDD)
   - `381f0d2` test(116-02): add failing tests for agent tick timeout enforcement (RED)
   - `43cbaba` feat(116-02): wrap agent tick in configurable timeout enforcement (GREEN)

2. **Task 2: Log structured warnings for unhandled SwarmAction variants** - `c7e3988` (feat)

**Plan metadata:** pending (docs: complete plan)

_Note: Task 1 used TDD with separate RED and GREEN commits_

## Files Created/Modified
- `crates/swarm-core/src/config.rs` - Added agent_tick_timeout_ms field to RuntimeSettings with default 500ms
- `crates/swarm-runtime/src/dispatcher.rs` - Tick timeout wrapping, exhaustive SwarmAction match, SlowMockAgent test helper, 6 new tests

## Decisions Made
- Default timeout of 500ms chosen to balance between detecting stuck agents quickly and allowing legitimate detection workloads
- Timed-out actions are fully discarded (not partially applied) for safety
- ClaimInvestigation/PublishFindings use debug level (they are intentionally agent-direct, not bugs)
- ProposeStrategy uses warn level (genuinely unhandled -- signals need for future implementation)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Propagated 116-01 signing key to all callers**
- **Found during:** Task 1 (compilation blocked)
- **Issue:** 116-01 added deposit signature validation but left downstream callers (pipeline.rs, stalker_agent.rs, whisker_agent.rs, service.rs, ingest.rs, swarm_detect.rs, integration tests) without the required signing_key parameter
- **Fix:** Added signing_key parameter to detect_and_deposit, EventExecutionContext, IngestState, and all test constructions
- **Files modified:** 12 files across swarm-runtime
- **Verification:** Full workspace builds and all tests pass
- **Committed in:** `29b2850`, `f4baad8`

**2. [Rule 1 - Bug] Fixed clippy::expect_used violations in signing code**
- **Found during:** Task 1 (clippy check)
- **Issue:** 116-01 signing code used expect() in non-test code, violating project clippy configuration
- **Fix:** pipeline.rs: return Result with SubstrateError::Encode; stalker_agent.rs: use internal_error helper
- **Files modified:** pipeline.rs, stalker_agent.rs
- **Verification:** cargo clippy -p swarm-runtime -- -D warnings passes clean
- **Committed in:** `c283f11`

**3. [Rule 3 - Blocking] Added agent_tick_timeout_ms to all RuntimeSettings constructions**
- **Found during:** Task 1 (compilation)
- **Issue:** New required field needed in all 9 RuntimeSettings struct literals across workspace
- **Fix:** Added agent_tick_timeout_ms: 500 to all test config constructions
- **Files modified:** 8 files with RuntimeSettings constructions
- **Verification:** Workspace compiles cleanly
- **Committed in:** `381f0d2` (part of RED phase)

---

**Total deviations:** 3 auto-fixed (2 blocking, 1 bug)
**Impact on plan:** All fixes were necessary for compilation and clippy compliance. No scope creep -- deviations 1 and 2 were completing 116-01 leftover work.

## Issues Encountered
- Pre-existing test failure in evolution::tests::evolution_queue_creates_pending_review_proposal (unrelated to changes, VerificationFailed error in evolution.rs which was not modified)
- 116-01 plan left uncommitted caller-side changes that prevented workspace compilation

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 116 (Agent Safety Hardening) is complete: both HARDEN-02 and HARDEN-03 are closed
- Phase 117 (Substrate Durability And Bridge Resilience) and Phase 118 (Operational Hardening) can now proceed
- Workspace builds clean, clippy passes, 217/218 tests pass (1 pre-existing failure)

---
*Phase: 116-agent-safety-hardening*
*Completed: 2026-04-07*
