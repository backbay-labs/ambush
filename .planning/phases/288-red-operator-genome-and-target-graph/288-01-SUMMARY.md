# Phase 288 Plan 01 Summary

## Delivered

- Turned `crates/swarm-runtime/src/red_swarm.rs` into a module directory
  (`red_swarm/mod.rs`) as a pure rename with history preserved, so the target
  graph and PRNG could land beside the existing suite-replay adapters without
  crowding one file (5815df17b).
- Added `TargetGraph` (OPFOR-02): built through the same loaders
  `evasion_coverage` uses, with nodes for the 11 catalogued detectors, every
  technique the catalog declares intentionally uncovered, every technique a
  tracked adversarial scenario declares, and the threat classes on either.
  Proven by `the_graph_technique_set_is_the_union_of_catalog_and_suite_techniques`
  (a86e7a533).
- Added `RedGenomeRng` (OPFOR-03): an in-tree xoshiro256** PRNG seeded through
  SplitMix64, implementing `rand_core::RngCore` + `SeedableRng` with no
  `Default` and no seedless constructor, so the red lane has no path to OS
  entropy or the wall clock. `fork` derives an independent per-operator stream.
  Proven by `no_entropy_path_exists_in_the_red_lane`, which reads every `.rs`
  under `red_swarm/` and fails the build on `getrandom`, `OsRng`,
  `thread_rng`, `SystemTime`, `Instant::now`, `Utc::now`, or `Local::now`
  outside `#[cfg(test)]` (eab31fa9d).
- Added the red genome, the six operator roles, and the pure planner
  (OPFOR-01, OPFOR-04): `GeneStep`, `RedGenome`, `RedPlan`, `CampaignParams`,
  `Determinism`, `OperatorRole`, `StepIntent`, the `RedOperator` trait, and
  `ReconOperator` / `InjectionOperator` / `AuthOperator` / `EvasionOperator` /
  `ChainOperator` / `OpsecOperator`. `RedGenome::plan(seed, generation,
  campaign)` forks one PRNG stream per operator, round-robin interleaves their
  proposals, assigns a monotone jittered schedule, validates every step
  against the graph, and stamps the determinism block and graph fingerprint.
  Proven byte-identical by `plan_is_byte_identical_for_identical_arguments`,
  proven to vary across seeds by `a_twenty_seed_sweep_differs_in_at_least_one_step_per_seed`,
  proven to reject an invented technique by
  `the_planner_rejects_an_operator_that_invents_a_technique` and
  `every_generated_step_names_a_graph_technique`, and proven to cover all six
  roles by `each_operator_role_appears_and_the_scheduler_string_is_pinned`
  (096cd6136).
- Fixed round 1 of the Task 2 review (069cfe573): `OpsecOperator` now draws
  cover from a benign-control scenario rather than the quietest adversarial
  one, via an additive `TargetGraph::benign_scenarios()` accessor that leaves
  the technique/detector/threat-class node sets unchanged; and three doc
  comments that overclaimed stream position-independence for `RedGenomeRng`
  fork were corrected to state that operator order is a versioned contract.
- Added `swarmctl red-swarm plan` (OPFOR-04, SC 4): builds the target graph
  from the evasion catalog and scenario suites, plans one generation of one
  campaign, and prints the `RedPlan` as JSON with the `determinism` record
  (`rng_seed`, `virtual_clock_start_ms`, `scheduler`) at the top level and the
  graph fingerprint as hex; a human-readable step table without `--json`.
  `--virtual-clock-start-ms` is required and its omission is refused with exit
  code 1 rather than defaulted to now. Proven by
  `the_plan_json_carries_determinism_at_top_level_and_a_hex_fingerprint`,
  `the_plan_json_is_byte_identical_across_two_runs_with_the_same_arguments`,
  `a_plan_omitting_the_virtual_clock_is_refused_rather_than_defaulting_to_now`,
  and `no_entropy_path_exists_in_the_red_swarm_cli` (67ce8b23f).

## Notes

- ONE RECORDED DEVIATION from OPFOR-01's literal text, sanctioned by the plan:
  `RedOperator::propose_steps` takes an extra `so_far: &[GeneStep]` argument,
  because the `EvasionOperator`, `ChainOperator`, and `OpsecOperator` roles
  amend the plan proposed before them and cannot do so from `(graph, rng)`
  alone. Documented on the trait itself.
- The red lane never reaches response authority: nothing under `red_swarm/`
  names `execute_response`, `ResponseAdapter`, `PolicyDecision::Authorize`, or
  `live_response`, imports `swarm_response`, or takes a
  `RuntimeEventBroadcaster`. It produces `TelemetryEvent`s and plans, and acts
  on nothing — this stays a later phase's structural gate (ARMSCI-02, Phase
  291) to enforce mechanically, but the code shipped here does not violate it.
- All four ROADMAP.md success criteria are met; commit SHAs and proving test
  names are recorded against each criterion in
  `.planning/ROADMAP.md` (Phase 288) and against each requirement in
  `.planning/REQUIREMENTS.md` (OPFOR-01..04).
- Six implementation commits landed across three dispatches, not three: Task
  1 is 5815df17b (module directory) + a86e7a533 (target graph) + eab31fa9d
  (PRNG); Task 2 is 096cd6136 (genome, operators, planner) + 069cfe573 (fix
  round); Task 3 is 67ce8b23f (CLI). The controller's task brief referred to
  the three tasks by their closing SHA only (eab31fa9d, 069cfe573,
  67ce8b23f); this summary and the ROADMAP/REQUIREMENTS citations instead
  name the commit that actually introduced each piece of functionality or
  test, which for OPFOR-02, OPFOR-01, and part of OPFOR-04 is an earlier
  commit in the same task.
