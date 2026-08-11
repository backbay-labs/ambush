# Phase 247 Verification

status: passed

## Result

Phase 247 verification passed.

## Commands

- `cargo test -p swarm-runtime evasion_coverage::tests::command_line_normalization_regression_stays_zero_on_benign_controls --lib`

## Verified Behaviors

- The shared command-line normalization suite now includes benign controls that exercise caret, env-var, and Unicode input forms.
- The command-line detector family can be compared with normalization disabled and enabled from the same runtime config.
- Baseline and normalized benign false positives both remain zero across the affected detector family.
