# Phase 261 Verification

status: passed

## Result

Phase 261 verification passed.

## Commands

- `cargo test -p swarm-runtime --test recruitment_integration`

## Verified Behaviors

- Escalation cooldown writes one durable inhibitory `Normal` record for the resolved threat class.
- Recruitment pressure is cleared on the bounded detector path after resolution.
- Post-resolution restart reopens into the baseline threshold instead of leaving a stale recruited state behind.
