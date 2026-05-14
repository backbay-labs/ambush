# Phase 246 Verification

status: passed

## Result

Phase 246 verification passed.

## Commands

- `cargo test -p swarm-runtime evasion_coverage::tests::command_line_normalization_benchmark_improves_execution_and_defense_evasion --lib`

## Verified Behaviors

- The runtime can evaluate baseline-vs-normalized command-line detector behavior from the same repo config by toggling only the shared normalization profile seam.
- The repo-owned adversarial command-line suite names the execution and defense-evasion scenarios used in the benchmark proof.
- The targeted benchmark lanes exceed the 15% catch-rate improvement requirement.
