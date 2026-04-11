# End-To-End Ingest Benchmark

**Generated:** 2026-04-11  
**Reference host:** Apple M1 Max, 10 CPU cores, 32 GiB RAM, macOS 25.4.0  
**Measured command:** `cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`

## Benchmark Scope

This benchmark measures the shipped detect HTTP surface instead of only the
detector hot path. One run covers:

1. loopback HTTP `POST /v1/ingest/events`
2. JSON parsing and per-event validation
3. `SuspiciousProcessTreeDetector` evaluation
4. policy evaluation and replay persistence
5. `local_journal` pheromone deposit
6. `/readyz`, `/healthz`, and `/metrics` after the run

Reference workload:

- 25 warmup requests
- 200 measured requests
- 25 events per request
- 5,000 measured events total
- `detect_only` mode
- `suspicious_process_tree` strategy
- `audit.bundle_store=local_files`
- `pheromone.backend=local_journal`
- async investigation, correlation, external notification, and SIEM delivery disabled

## Results

| Profile | p50 request latency | p95 request latency | p99 request latency | Throughput |
| --- | --- | --- | --- | --- |
| `local_journal` reference run | 6.45 ms | 8.18 ms | 9.95 ms | 3,728.80 events/sec |

Post-run health on the reference host:

- `/readyz`: `200 OK`
- `/healthz`: `200 OK`
- `/metrics`: `200 OK`
- `readyz.components.heap.pressure_ratio`: `0.00108`
- metrics confirmed: `swarm_ingest_request_latency_microseconds`,
  `swarm_ingest_events_total`, `swarm_detect_latency_microseconds`,
  `swarm_policy_latency_microseconds`, and `swarm_heap_pressure_ratio`

## Durable Production Variant

The supported production profile uses JetStream instead of `local_journal`.
Measure that ceiling on the target host before treating the local-journal number
as a durable production limit:

```bash
STS_E2E_BENCH_BACKEND=jet_stream \
NATS_URL=nats://127.0.0.1:4222 \
cargo run -p swarm-runtime --release --example end_to_end_ingest_bench
```

That keeps the workload fixed while swapping the pheromone substrate to
JetStream. Expect the durable topology ceiling to be lower because the hot path
now includes networked durable writes.
