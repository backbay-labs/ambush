---
phase: 91-adapter-resilience-and-operational-probes
plan: 01
subsystem: response
tags: [resilience, retry, circuit-breaker, dead-letter]
requirements-completed: [OBS-03, OBS-04]
one-liner: "HTTP EDR and webhook execution now run through a resilient wrapper that retries transient failures, opens a circuit breaker on repeated failure, and appends exhausted actions to a dead-letter journal."
completed: 2026-04-05
---

# Phase 91 Plan 01 Summary

**HTTP EDR and webhook execution now run through a resilient wrapper that retries transient failures, opens a circuit breaker on repeated failure, and appends exhausted actions to a dead-letter journal.**

## Accomplishments

- Added `RetryConfig`, `CircuitBreakerConfig`, and `dead_letter_path` to runtime adapter config so resilience policy is repo-owned and validated at load time.
- Implemented `DeadLetterJournal` as an append-only JSONL sink that creates parent directories automatically and captures exhausted response attempts.
- Implemented `ResilientExecutor` with transient-failure retry, exponential backoff, per-adapter circuit-breaker state, cooldown reopening, and dead-letter writes after final failure.
- Updated `DispatchingExecutor` to wrap both HTTP EDR and webhook adapters in `ResilientExecutor` while leaving sandbox execution unchanged.
- Added response-side tests for retry success, exhausted failure journaling, dispatch wiring, and config round-trips.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-response/src/dead_letter.rs`
- `crates/swarm-response/src/resilience.rs`
- `crates/swarm-response/src/dispatch.rs`
- `crates/swarm-response/src/config.rs`
- `crates/swarm-response/src/lib.rs`

## Verification

- `cargo test -p swarm-response --lib`
- `cargo test --workspace`
- `cargo clippy -p swarm-core -p swarm-whisker -p swarm-response -p swarm-runtime -- -D warnings`

## Notes

- Circuit-breaker state is intentionally process-local for now; v1.30 hardens adapter behavior without introducing distributed breaker coordination.
- Dead-letter persistence happens after retry exhaustion, so failed actions are no longer silently lost even when an adapter stays unavailable.
