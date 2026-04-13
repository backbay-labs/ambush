# Phase 191 Verification

status: passed

## Result

Phase 191 verification passed.

## Commands

- `cargo fmt --all`
- `cargo check -p swarm-runtime --example end_to_end_ingest_bench`
- `cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`
- `STS_E2E_BENCH_MODE=ramp_until_shed STS_E2E_BENCH_MAX_HEAP_PRESSURE=0.00335 STS_E2E_BENCH_MAX_CONCURRENCY=16 cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`

## Verified Behaviors

- The shipped end-to-end ingest benchmark still reports the steady-state HTTP
  ingest envelope and post-run health surfaces in `fixed` mode.
- The same example can now ramp concurrency and stop at the first `/readyz`
  shed transition while recording per-stage throughput, latency, and peak
  heap-pressure data.
- The checked-in docs explicitly capture the measured host profile, the
  configured shed threshold used for the reference run, and the rerun contract
  operators must use for JetStream or deployment-specific memory budgets.
