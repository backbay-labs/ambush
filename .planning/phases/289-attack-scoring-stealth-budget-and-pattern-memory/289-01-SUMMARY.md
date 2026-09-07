# Phase 289 Plan 01 Summary

Attack Scoring, Stealth Budget And Pattern Memory (v1.80). Executed 2026-09-07 with the
subagent-driven-development skill: one implementer per task, a task review after each, a
whole-branch review before merge. Tasks 2 and 3 ran in parallel worktrees; Task 4 ran in
parallel with Task 3's review. Branch `feat/red-swarm-289` off `main` `6c07ab402`.

## Delivered

- **`AttackScorer` + `AttackFitness` (ATKSCORE-01, a08c010bb):** a pure function
  `AttackScorer::score(&RedPlan, &EvasionCoverageSnapshot, stealth) -> AttackFitness
  { evasion_rate, stealth, red_fitness }`, with `score_unbudgeted` fixing `stealth = 1.0`.
  `evasion_rate = 1.0 -` the plan's mean per-technique catch rate, where a technique's catch is
  the **max** `catch_rate` over every `detectors[*].scenarios[*]` pairing naming it (caught if any
  detector catches it), and a technique absent from the snapshot catches `0.0` (uncovered — the
  case red hunts for, never an error). `red_fitness = evasion_rate * stealth`.
- **`StealthBudget` (ATKSCORE-02, ad6e48416):** `StealthBudget { max_events_per_generation,
  max_distinct_hosts, max_technique_repeats }` with a `DEFAULT` that leaves the 24-step campaign
  untruncated. `apply(Vec<GeneStep>) -> BudgetOutcome { steps, events_emitted, stealth, truncated }`
  walks steps in final order and tail-truncates at the first cap breach. It binds the 288
  placeholder `host_slot` to a real slot by first-seen assignment (each distinct technique → the
  next slot), so `max_distinct_hosts` genuinely bites (truncates at the (max+1)th distinct
  technique). `stealth = emitted/proposed` clamped to `(0.0, 1.0]`. `BTreeMap` throughout — pure
  and deterministic; the 288 planner is untouched.
- **`AttackPatternDb` (ATKSCORE-03, c1a170539):** an append-only JSON-lines store of
  `AttackPatternRecord { generation, technique, detector, detected }` behind a reader/writer seam
  (`from_reader`/`write` for tests, `load`/`append_line` file wrappers for a future CLI).
  `technique_success_rate = undetected/total`, with an **unrecorded technique → `1.0`** (the
  `total == 0` guard, which also rules out `0/0`) and an always-detected technique → `0.0`. A
  malformed line returns the new `RedSwarmError::MalformedPatternRecord { line, reason }`, never a
  panic. Byte-identical output for an identical record sequence (no clock, no map ordering). The
  bias-into-operators wiring is Phase 290; this delivers the store and the rate.
- **`swarmctl red-swarm score --json` (ATKSCORE-04, fb719d259):** mirrors the `plan` subcommand
  (`RedSwarmScoreArgs`, testable `build_score`, exit shell `run_score`, `ScoreView`). It plans,
  applies the budget, and scores the **budgeted** plan (`outcome.steps` with `outcome.stealth`, so
  red cannot win by volume), then prints top-level `red_fitness`, `evasion_rate`, `stealth`,
  `events_emitted` plus a `determinism` object. Refuses without `--virtual-clock-start-ms` (exit 1)
  and is byte-identical across runs; no `core.inc` change (the `RedSwarm` arm already delegates
  every subcommand).

## Success criteria

1. **`red_fitness == 0.0` for a fully caught plan; `> 0.5` for a declared-uncovered plan** —
   ATKSCORE-01, a08c010bb: `a_fully_detected_plan_scores_zero_red_fitness` (exact `0.0`) and
   `a_fully_uncovered_plan_scores_red_fitness_above_one_half` (exact `1.0`), and end-to-end through
   the CLI in fb719d259.
2. **An event cap bounds emitted events with identical truncation order at a seed** — ATKSCORE-02,
   ad6e48416: the budget tests bound `events_emitted` and assert identical `BudgetOutcome.steps`
   across two `apply` calls on a truncating fixture.
3. **Pattern store round-trips; unrecorded → 1.0, always-detected → 0.0** — ATKSCORE-03,
   c1a170539: `technique_success_rate_*` tests plus a separate byte-identical round-trip test.
4. **`score --json` prints the four fields as top-level** — ATKSCORE-04, fb719d259: the score CLI
   tests parse the JSON and assert the four finite top-level fields; the binary was verified
   byte-identical across two runs (sha256 match).

## Notes

- The red lane never reaches response authority: nothing under `red_swarm/` (scoring, budget,
  pattern_db) or the score CLI names `execute_response`, `ResponseAdapter`, `live_response`,
  imports `swarm_response`, or takes a broadcaster. It reads plans and snapshots and returns
  numbers; the pattern db reads and appends a file. The entropy-path guard is extended to the new
  score code.
- Scoping: 289 scores against a static `EvasionCoverageSnapshot` (a self-play estimate). Replacing
  the snapshot with real detector runs — materialization + the co-evolution loop — is Phase 290
  (COEVOLVE), which also binds `technique_success_rate` into the operators.
- One controller ruling recorded in the SDD ledger: the brief named
  `AdversaryTechniqueCoverageReport` as ATKSCORE-01's source, but that type is unreachable from a
  pure `&EvasionCoverageSnapshot` (it requires disk I/O); the scorer correctly consumes the
  reachable `detectors[*].scenarios[*]` data instead.
- All commit SHAs above are the branch's; a few small test-coverage and hygiene Minors from the
  task reviews were folded into the whole-branch fix wave (see the plan's `progress.md`).
