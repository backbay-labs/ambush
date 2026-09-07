# Phase 290 Plan 01 Summary

Bidirectional Co-Evolution And Convergence (v1.80). Executed 2026-09-07 with the
subagent-driven-development skill: one implementer per task, a task review after each, a
whole-branch review before merge. Task 2 was split into 2a (weighted planning) and 2b
(`run_generation`) because they were distinct-risk concerns. Branch `feat/red-swarm-290` off
`main` `4d1f476cf`.

## Delivered

- **`GenomeRedSwarm` (COEVOLVE-03, 31afa036d):** materializes a budgeted red plan into telemetry
  events (re-stamping each scenario event with a new id, a `host_slot`-derived host, and a
  `virtual_clock_start_ms + offset_ms` timestamp — deterministic, no wall clock) and implements the
  existing async `RedSwarmAdapter` trait alongside `SuiteRedSwarmAdapter`. Task 2b added
  `materialize_by_step`, which groups events by their step's technique for catch attribution.
- **Technique-weighted planning (part of COEVOLVE-01, 1988f5899):** `RedGenome::plan_weighted(..,
  Option<&TechniqueWeights>)` biases operator technique selection toward higher-success (evaded)
  techniques. `plan` IS `plan_weighted(.., None)` and `choose_distinct(None)` IS the unchanged 288
  `choose_distinct_uniform`, so no weights reproduces 288 character-for-character (the four 288
  guardrails still pass). This is the "red moves" mechanism.
- **`run_generation` (COEVOLVE-01, ef278cc8e + 29734daae):** the one measured generation — plan
  (weighted) → materialize → run the enabled `DetectionConfig.strategies`' real detectors over the
  events → per-technique catch (a technique is caught iff any enabled detector flags any of its
  ATTACK events; `Cover` steps' benign events are excluded from attribution, 29734daae) → assemble a
  minimal `EvasionCoverageSnapshot` and reuse 289's `AttackScorer` verbatim for `red_fitness`, plus
  `blue_catch_rate`, `AttackPatternRecord`s, and `evaded_techniques`.
- **`RedSwarmCampaign::run` (COEVOLVE-01 + COEVOLVE-02, c59d8f44e + 0c8ceeff1):** the bidirectional
  loop. Each generation: build weights from the pattern db accumulated so far, `run_generation`,
  record outcomes, then **blue moves** — probe every not-yet-enabled strategy against the evaded
  techniques' events and enable the ones that catch (real detector runs; the enabled set only grows,
  so `blue_catch_rate` is non-decreasing). The bounded stopping rule records `stop_reason` as
  `MaxGenerations` | `Plateau` (red_fitness flat within `min_delta` for `patience` gens) |
  `FullCoverage` (no evaded technique is coverable by any remaining strategy); every path terminates.
- **`swarmctl red-swarm campaign` + persistence (COEVOLVE-04, fa4455429):** the CLI mirrors `score`;
  the report view adds the single `generated_at_ms` clock read at the CLI layer (the engine `run`
  stays clock-free) plus a per-generation `corpus_sequence_id` (`"generation-<n>"`); reports persist
  under `data/red-swarm/campaigns/<campaign>-<seed>.json` (gitignored; tests write to a temp dir).
  `EvolutionAdversarialSummary.corpus_sequence_id` (already `Option<String>`) may reference a campaign
  generation with its public shape unchanged (proven by a test; zero production lines changed there).

## Success criteria

1. **6 generations, never a 7th** — COEVOLVE-02, c59d8f44e: `campaign` tests pin `generations.len()
   == 6` / `stop_reason == MaxGenerations` at a fixed seed, plus direct `plateaued()` boundary tests
   and a `max_generations == 1` case (0c8ceeff1).
2. **Plateau stops early** — COEVOLVE-02, c59d8f44e: a flat-fitness fixture stops with
   `stop_reason == Plateau` before `max_generations`, with a full-window guard.
3. **Blue non-decreasing, red shifts** — COEVOLVE-01, c59d8f44e: over ≥4 generations
   `blue_catch_rate` is non-decreasing (monotonic gap-closing) and a gen-0 favourite caught early has
   a strictly lower selection weight by the last generation.
4. **Byte-identical reports** — COEVOLVE-04, fa4455429: two `campaign … --json` runs at the same
   seed are byte-identical after stripping `generated_at_ms` (unit test + verified on the real binary).

## Notes

- **Measured against real detector runs, not self-play.** 289 scored against a static coverage
  snapshot; 290 runs the plan through the actual `detector_factory` detectors each generation. Both
  sides move: red biases by pattern memory, blue closes the gaps red exposes. The heavy file-based
  `mutation/` harness is deliberately NOT used — its `now_ms` would break SC4, and no requirement
  names it; blue's move is a real, deterministic, bounded best-response over the detector set.
- The red lane still never reaches response authority (verified by `check-workspace-layering`), draws
  no entropy (`no_entropy_path_*` extended), and the 288 pure planner is untouched (the weight
  injection is additive; `None` is 288).
- Recorded controller ruling: generation 0 plans against an all-neutral (1.0) weight snapshot through
  the weighted arm — deterministic, but NOT byte-identical to the unweighted `plan()` (the doc was
  corrected to say so, 0c8ceeff1). A few Minors (a forward-looking `scaled_weight` NaN guard, a
  report doc slip) are tracked for the whole-branch fix wave.
