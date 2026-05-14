# Phase 270 Verification

status: passed

## Result

Phase 270 verification passed.

## Commands

- `CARGO_TARGET_DIR=target-v175-emulation bash tools/check-adversary-emulation-coverage.sh`

## Verified Behaviors

- The shipped adversarial corpus replays through the configured runtime and
  satisfies the documented detector mapping.
- The repo-owned coverage report produces per-technique `detected`, `partial`,
  and `not_covered` status.
- The mapped corpus clears the required floor with 7 adversarial scenarios, 23
  mapped techniques, and 100% mapped coverage.
