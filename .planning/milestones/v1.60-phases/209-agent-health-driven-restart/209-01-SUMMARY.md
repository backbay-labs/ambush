# Phase 209 Plan 01 Summary

## Delivered

- Added dispatcher-owned restart factories and in-place registry replacement in
  `crates/swarm-runtime/src/dispatcher.rs`, so explicit `failed` health now
  triggers a bounded restart of only the affected agent instead of forcing a
  full dispatcher or process restart.
- Kept restart health honest: a successfully rebuilt agent is held in
  `degraded` state until it completes a clean post-restart tick, while restart
  build failures leave the agent visibly `failed` and emit runtime-owned restart
  action telemetry.
- Refactored `crates/swarm-runtime/src/bin/swarm_detect.rs` so serve-mode agent
  registration goes through reusable restartable factories for Whisker, Tom,
  Pounce, Kitten, Stalker, Weaver, and the optional Sphinx and Calico agents.
- Updated `crates/swarm-runtime/src/whisker_agent.rs` to support a shared
  telemetry receiver handle, which lets a restarted Whisker instance reuse the
  live ingest queue instead of requiring a process-wide telemetry bridge reset.
- Added focused proof in `crates/swarm-runtime/src/dispatcher.rs` for both the
  Tom-driven failed-health restart path and the fail-closed case where restart
  reconstruction itself errors, plus `swarm_detect` tests that confirm optional
  startup agents still register through the new reusable factory path.

## Notes

- Phase 209 intentionally keys restart off the existing `AgentHealth::Failed`
  boundary rather than introducing a second lifecycle threshold; Tom's existing
  degraded-tick escalation remains the trigger source for repeated agent
  failures.
- Runtime-wide degradation levels and automated mode transitions remain Phase
  210 work.
