# End-To-End Ingest Benchmark

**Generated:** 2026-04-12  
**Reference host:** Apple M1 Max, 10 CPU cores, 32 GiB RAM, Darwin 26.4 (kernel 25.4.0)

## Benchmark Scope

This benchmark measures the shipped detect HTTP surface instead of only the
detector hot path. The example now ships two repo-owned modes that cover the
same HTTP ingest path:

1. `fixed` keeps the original steady-state workload and records p50/p95/p99
   request latency plus accepted-event throughput.
2. `ramp_until_shed` doubles concurrency until `/readyz` returns `503 Service
   Unavailable`, so the repo can capture the first readiness-shedding stage on
   the same runtime path.

Both modes cover:

1. loopback HTTP `POST /v1/ingest/events`
2. JSON parsing and per-event validation
3. `SuspiciousProcessTreeDetector` evaluation
4. policy evaluation and replay persistence
5. `local_journal` pheromone deposit
6. `/readyz`, `/healthz`, and `/metrics`

Common runtime profile:

- 25 warmup requests
- 25 events per request
- `detect_only` mode
- `suspicious_process_tree` strategy
- `audit.bundle_store=local_files`
- `pheromone.backend=local_journal`
- async investigation, correlation, external notification, and SIEM delivery disabled

## Fixed Profile

**Measured command:** `cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`

Fixed-profile workload:

- 200 measured requests
- 5,000 measured events total

| Profile | p50 request latency | p95 request latency | p99 request latency | Throughput |
| --- | --- | --- | --- | --- |
| `local_journal` steady-state run | 6.64 ms | 8.14 ms | 9.75 ms | 3,645.23 events/sec |

Post-run health on the reference host for `fixed` mode:

- `/readyz`: `200 OK`
- `/healthz`: `200 OK`
- `/metrics`: `200 OK`
- `readyz.components.heap.pressure_ratio`: `0.001186370849609375`
- metrics confirmed: `swarm_ingest_request_latency_microseconds`,
  `swarm_ingest_events_total`, `swarm_detect_latency_microseconds`,
  `swarm_policy_latency_microseconds`, and `swarm_heap_pressure_ratio`

## Ramp-To-Shed Profile

**Measured command:**

```bash
STS_E2E_BENCH_MODE=ramp_until_shed \
STS_E2E_BENCH_MAX_HEAP_PRESSURE=0.00335 \
STS_E2E_BENCH_MAX_CONCURRENCY=16 \
cargo run -p swarm-runtime --release --example end_to_end_ingest_bench
```

Ramp profile contract on the reference host:

- same 25 warmup requests and 25 events per request as the fixed run
- 3 second stages
- concurrency doubles `1 -> 2 -> 4` until `/readyz` returns `503`
- `/readyz` is polled every 100 ms during the run
- `runtime.max_heap_pressure` is forced to `0.00335` so heap-pressure shedding
  is observable in the single-process loopback harness on a 32 GiB developer
  host

Measured ramp stages:

| Stage | Concurrency | p95 request latency | Peak heap pressure | Status | Throughput |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 | 10.87 ms | 0.0016546249389648438 | ready | 3,191.67 events/sec |
| 2 | 2 | 16.79 ms | 0.0024547576904296875 | ready | 4,394.19 events/sec |
| 3 | 4 | 20.33 ms | 0.003383636474609375 | `/readyz` shed | 6,631.87 events/sec |

Interpret the ramp run as:

- Highest stable sustained ceiling before readiness shedding:
  `4,394.19 events/sec` at concurrency `2`
- First readiness-shedding stage: concurrency `4`, peak heap pressure
  `0.003383636474609375`, `/readyz=503`
- The harness stops immediately after the first threshold crossing, so the
  post-run `/readyz` and `/healthz` responses remain `503 Service Unavailable`
  on this measured run

This run is meant to size and compare the runtime against an explicit heap
budget, not to claim that `0.00335` is a universal production threshold. On the
reference host, that low threshold is what makes the heap-pressure gate
observable in a loopback benchmark.

## Durable Production Variant

The supported production profile uses JetStream instead of `local_journal`.
Rerun both the steady-state and ramp profiles on the target host before
treating the local-journal measurements as a durable production limit:

```bash
STS_E2E_BENCH_BACKEND=jet_stream \
NATS_URL=nats://127.0.0.1:4222 \
cargo run -p swarm-runtime --release --example end_to_end_ingest_bench
```

```bash
STS_E2E_BENCH_MODE=ramp_until_shed \
STS_E2E_BENCH_MAX_HEAP_PRESSURE=<deployment threshold> \
STS_E2E_BENCH_BACKEND=jet_stream \
NATS_URL=nats://127.0.0.1:4222 \
cargo run -p swarm-runtime --release --example end_to_end_ingest_bench
```

The ramp profile is only meaningful when `STS_E2E_BENCH_MAX_HEAP_PRESSURE`
matches the deployment memory budget or the benchmark is running inside the same
cgroup limit as production. Expect the durable JetStream topology ceiling to be
lower because the hot path includes networked durable writes.
