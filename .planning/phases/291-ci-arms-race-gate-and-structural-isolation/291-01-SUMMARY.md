# Phase 291 Plan 01 Summary

CI Arms Race Gate And Structural Isolation (v1.80). The LAST red-swarm phase — it completes the
v1.80 "Red Swarm" milestone (288–291). Executed 2026-09-07 with subagent-driven-development: Tasks
1–3 ran in parallel worktrees, each task-reviewed, before a whole-branch review and merge. (An
over-parallelism load spike to average 180 was diagnosed and cleared mid-flight; see the SDD ledger.)

## Delivered

- **Structural-isolation gate + Rust companion (ARMSCI-02, ARMSCI-03; 236812e28, fix 206571055):**
  `tools/check-red-swarm-no-execution-authority.sh` scans the red lane
  (`crates/swarm-runtime/src/red_swarm/**`, `crates/swarm-cli/src/red_swarm_cmd.rs`) for the four
  forbidden response-authority symbols (`execute_response`, `ResponseAdapter`,
  `PolicyDecision::Authorize`, `live_response`) and fails if any appears. It is proven NOT vacuous:
  it plants each symbol in a temp tree and asserts the same scan catches it before scanning for real
  (exit 2 if the needle is broken). A `#[cfg(test)]` Rust companion (`isolation_gate.rs`) performs the
  identical scan at `cargo test` time with a documented counterexample. Both exclude ONLY the
  counterexample fixture, by its FULL PATH (fix round 1 — the Rust side had excluded by bare filename,
  which would have silently skipped a same-named file elsewhere; a test now pins that a same-named
  file at a different path is still caught). Wired into `.github/workflows/ci.yml`.
- **Executed CI arms-race gate + wall-clock guard (ARMSCI-01, ARMSCI-05; a290a0425):**
  `tools/check-red-swarm-arms-race.sh` runs ONE bounded `swarmctl red-swarm campaign`, reads
  `final_blue_catch_rate` from the JSON report FILE the executor writes (removing any stale report
  first), and fails (numeric compare, naming observed vs required) if it is below the checked-in
  threshold `rulesets/red-swarm/arms-race-threshold.txt` (0.75; the real campaign scores 0.7778). A
  missing field or a campaign that exits 0 but writes no report is a LOUD failure, never a false pass.
  The campaign run is wrapped in `timeout --kill-after` (portable `timeout`/`gtimeout`), so a runaway
  campaign fails the CI step loudly rather than inflating build time. Wired into `ci.yml`.
- **`red_swarm_campaign` in `evolution status --json` (ARMSCI-04; a2966d905, fix b9cc8e2c9):**
  `swarmctl evolution status --json` now carries a fixed-shape `red_swarm_campaign` object
  (`campaign`, `seed`, `generation_count`, `stop_reason`, `final_blue_catch_rate`,
  `corpus_sequence_id`), sourced FRESH from the on-disk report on every call — `null` when the report
  is absent OR malformed, never a stale value (`load_red_swarm_campaign_summary` is fail-soft and
  uncached; a write/delete/assert-`None` test proves it). Fix round 1 collapsed the campaigns-dir path,
  which had been duplicated as private constants in the writer (`red_swarm_cmd.rs`, from 290) and the
  reader, into one canonical `CAMPAIGNS_DIR` in `red_swarm/campaign.rs` used by both — so the two can
  never drift into a silent `null`.

## Success criteria

1. **CI fails on a catch-rate regression, reading the executor's file** — ARMSCI-01, a290a0425: the
   gate reads `final_blue_catch_rate` from `data/red-swarm/campaigns/…`, numeric-compares to the
   checked-in 0.75; raising the threshold above the real 0.7778 makes it fail (verified).
2. **Isolation script: 0 on the real tree, 1 on an injected call** — ARMSCI-02, 236812e28: verified
   exit 0 clean, exit 1 on an injected `execute_response(`.
3. **Rust companion with a documented counterexample** — ARMSCI-03, 236812e28/206571055:
   `isolation_gate.rs`, scan shared with the shell gate's ban list, same-named-file test added.
4. **`evolution status --json` campaign object, null when absent; loud wall-clock guard** — ARMSCI-04
   (a2966d905/b9cc8e2c9) + ARMSCI-05 (a290a0425): the object populates/nulls per the on-disk report;
   the `timeout` guard fails loudly.

## Notes

- The red lane already carried ZERO response-authority symbols before this phase (290's whole-branch
  review confirmed), so both isolation gates pass the real tree from day one — their value is
  keeping it that way, enforced by CI and `cargo test`, not by a comment.
- Controller ruling: the isolation gate lives in `tools/` (repo convention + `check-gates-wired.sh`
  scans `tools/check-*.sh`), NOT `scripts/` as ARMSCI-02's text names it — a path slip. Both new
  gates are wired into `ci.yml` in the same phase, so `check-gates-wired.sh` stays green.
- **v1.80 "Red Swarm" milestone COMPLETE** with this phase: 288 (genome + target graph), 289
  (scoring + budget + memory), 290 (bidirectional co-evolution), 291 (CI gates + isolation).
