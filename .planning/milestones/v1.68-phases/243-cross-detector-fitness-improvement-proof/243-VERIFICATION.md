# Phase 243 Verification

status: passed

## Result

Phase 243 verification passed.

## Commands

- `CARGO_TARGET_DIR=target-v168-phase242 cargo test -p swarm-runtime --lib measured_fileless_evolution_benchmark_improves_over_conservative_seed`
- `CARGO_TARGET_DIR=target-v168-phase242 cargo test -p swarm-runtime --lib measured_evolution_benchmark_supports_non_process_tree_detectors`

## Verified Behaviors

- The fileless-execution detector improves above its conservative seed baseline on measured autonomous fitness.
- The generation leader also improves catch rate above the conservative fileless baseline, so the gain is not just a bookkeeping artifact.
- The improvement proof uses the same shared multi-detector benchmark harness and report surface introduced in Phase 242.
