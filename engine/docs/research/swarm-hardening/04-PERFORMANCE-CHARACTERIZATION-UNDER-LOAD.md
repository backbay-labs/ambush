---
title: "04 -- Performance Characterization Under Load"
series: Swarm Hardening (4 of 8)
version: "0.3"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# 04 -- Performance Characterization Under Load

## Document Metadata

| Field          | Value                                                                     |
|----------------|---------------------------------------------------------------------------|
| Document       | `04-PERFORMANCE-CHARACTERIZATION-UNDER-LOAD.md`                          |
| Series         | Swarm Hardening (4 of 8)                                                 |
| Version        | 0.3                                                                       |
| Date           | 2026-04-08                                                                |
| Status         | Draft (reviewed)                                                                     |
| Authors        | Swarm Team Six Research                                                   |

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Current Architecture Performance Profile](#2-current-architecture-performance-profile)
3. [Throughput Analysis](#3-throughput-analysis)
4. [Latency Budget Breakdown](#4-latency-budget-breakdown)
5. [Memory Pressure Analysis](#5-memory-pressure-analysis)
6. [Tokio Runtime Contention](#6-tokio-runtime-contention)
7. [Backpressure and Flow Control](#7-backpressure-and-flow-control)
8. [JetStream Backend Performance](#8-jetstream-backend-performance)
9. [Multi-Bridge Concurrent Ingestion](#9-multi-bridge-concurrent-ingestion)
10. [Benchmarking Framework Design](#10-benchmarking-framework-design)
11. [Target Performance Envelope](#11-target-performance-envelope)
12. [Optimization Opportunities](#12-optimization-opportunities)
13. [Allocation Pattern Analysis](#13-allocation-pattern-analysis)
14. [Deployment Scenario Profiles](#14-deployment-scenario-profiles)
15. [Open Questions and Future Work](#15-open-questions-and-future-work)
16. [Cross-References](#16-cross-references)
17. [References](#17-references)

---

## 1. Abstract

ClawdStrike Ambush is a ~71K-line Rust-first autonomous detection and
live-response engine built on a tokio async runtime. Its critical path --
telemetry ingestion through detection, pheromone deposit, policy authorization,
and response execution -- must sustain high event throughput with bounded tail
latency to serve as a credible replacement for traditional EDR/XDR sensors.

This document characterizes the performance profile of the current codebase by
analyzing the async topology, channel layouts, lock contention patterns, and
memory growth behavior. We derive theoretical throughput bounds for each pipeline
stage, establish a latency budget that identifies the critical path, analyze
memory pressure from pheromone substrate growth, and examine contention patterns
under concurrent multi-bridge ingestion.

The findings inform a benchmarking framework design and propose target SLOs for
the v1.40 killer demo: 10,000 events/second sustained ingestion, sub-10ms p99
critical-path latency for detect-only mode, and a 512MB memory ceiling for 100K
active pheromone deposits.

---

## 2. Current Architecture Performance Profile

### 2.1 Async Topology

The runtime is composed in `crates/swarm-runtime/src/bin/swarm_detect.rs` using
the `#[tokio::main]` attribute, which spawns a multi-threaded tokio runtime with
the default worker count (one per logical CPU core). The primary concurrent
subsystems are:

1. **Axum HTTP Server** -- accepts ingest requests on the configured bind
   address (default `127.0.0.1:9090`). Each request is handled by an Axum
   handler that drives the critical path synchronously within the request
   context.

2. **Bridge Workers** -- one `tokio::spawn`ed task per configured telemetry
   bridge (CloudTrail, Tetragon gRPC, or GenericJSON). Each bridge polls for
   events and sends them through a shared `mpsc::Sender<TelemetryEvent>`.

3. **Agent Dispatcher** -- a single `tokio::spawn`ed task running a tick loop
   at 100ms intervals (`AgentDispatcherConfig::tick_interval_ms = 100`). It
   iterates registered agents (WhiskerAgent, TomAgent, PounceAgent,
   StalkerAgent, WeaverAgent) sequentially within each tick, with a 500ms
   per-agent timeout (`agent_tick_timeout_ms = 500`).

4. **Concentration Monitor** -- a separate `tokio::spawn`ed task running at
   100ms intervals (`CONCENTRATION_MONITOR_INTERVAL_MS = 100`) that queries
   pheromone concentrations and manages escalation/de-escalation mode
   transitions.

5. **Config Reload Tasks** -- file watchers and signal handlers for hot
   reloading configuration and secrets.

```
                         Axum Server (HTTP ingest)
                              |
                              v
                      [ process_event ]
                      detect -> deposit -> policy -> response -> replay
                              |
                              |  (also: try_send to telemetry_tx)
                              v
     +---- Bridge Workers ----> mpsc(10_000) ----> WhiskerAgent (via dispatcher)
     |     (CloudTrail)                                  |
     |     (Tetragon)                                    v
     |     (GenericJSON)                          detect_and_deposit
     |                                                   |
     +---- Agent Dispatcher (100ms tick) ----+           v
     |     WhiskerAgent                      |    PheromoneSubstrate
     |     TomAgent                          |
     |     PounceAgent                       +--- ConcentrationMonitor (100ms)
     |     StalkerAgent                      |
     |     WeaverAgent                       |
     +---------------------------------------+
```

### 2.2 Channel Layout

The codebase uses a single primary channel for event distribution:

| Channel | Type | Capacity | Source | Sink |
|---------|------|----------|--------|------|
| `telemetry_tx/rx` | `tokio::sync::mpsc` | 10,000 | Bridge workers + HTTP ingest (`try_send`) | `WhiskerAgent::tick()` (`try_recv` drain) |
| `investigation_tx/rx` | `tokio::sync::mpsc` | `max_pending_jobs` (default 16) | `StalkerAgent` | Investigation worker pool |
| `reload_tx/rx` | `tokio::sync::mpsc::unbounded` | unbounded | File watcher, signal handlers | Main loop |
| `shutdown_tx/rx` | `tokio::sync::watch` | 1 (latest value) | Signal handler | All subsystems |

The telemetry channel at capacity 10,000 is the primary flow-control boundary.
When it fills, the HTTP ingest handler logs a warning and drops the agent
dispatch copy (the HTTP path still processes the event synchronously). Bridge
workers, by contrast, use `send().await` which applies backpressure by blocking
the bridge poll loop.

### 2.3 Lock Inventory

Performance-sensitive locks in the critical path:

| Lock | Type | Scope | Hot Path? |
|------|------|-------|-----------|
| `InMemoryPheromoneSubstrate::deposits` | `std::sync::RwLock` | All deposit/query/GC operations | Yes |
| `InMemoryPheromoneSubstrate::threat_intel_entries` | `std::sync::RwLock` | Threat intel enrichment queries, GC, feed ingestion | Yes |
| `InMemoryPheromoneSubstrate::threat_class_configs` | `std::sync::RwLock` | Concentration queries, deposit resolution | Yes |
| `RuntimeMetrics::inner` | `std::sync::Mutex` | Per-stage latency recording | Yes |
| `ConfigurableApprovalGate::agent_windows` | `std::sync::Mutex` | Rate-limiting window tracking | Yes |
| `WhiskerAgent::event_rx` | `tokio::sync::Mutex` | Channel drain during agent tick | No (tick only) |
| `SharedBridgeHealth` | `std::sync::Mutex` | Bridge health snapshot publication | No |

The `std::sync::RwLock` on the deposits vector is the most critical lock. Write
operations (deposit, GC) block read operations (concentration query, deposit
query). **Note:** `gc_evaporated()` is not currently invoked by any runtime code
(see section 5.3), so GC write contention does not occur today. The primary
write contention is between concurrent `deposit()` calls. Once GC is wired up,
the full `retain()` sweep will block all reads for O(n) time where n is the
number of active deposits.

**Lock ordering discipline.** The codebase currently acquires locks in the
following order within `gc_evaporated()`: `deposits` (write) then
`threat_class_configs` (read). If any future code path acquires these in
reverse order, deadlock results. The current code does not exhibit the reverse
ordering, but with 7+ locks in the critical path (see table above) and GC
increasing the lock interaction surface, the risk of accidental inversion grows.

The canonical lock acquisition order MUST be documented in the substrate module
and enforced by convention:

```
// LOCK ORDER (acquire in this sequence, never reverse):
//   1. deposits            (RwLock - write for deposit/GC, read for query)
//   2. threat_class_configs (RwLock - read for policy resolution)
//   3. threat_intel_entries (RwLock - read for enrichment, write for GC/store)
//   4. escalations         (RwLock - write for record, read for query)
//   5. RuntimeMetrics       (Mutex - per-stage recording)
//   6. agent_windows        (Mutex - rate-limit window tracking)
//   7. beacon_tracker       (Mutex - beacon state, independent of substrate)
```

A stronger enforcement mechanism: wrap each lock in a numbered-tier newtype
that makes out-of-order acquisition a compile-time or `debug_assert!` error:

```rust
struct TieredLock<T, const TIER: u8> {
    inner: RwLock<T>,
}

impl<T, const TIER: u8> TieredLock<T, TIER> {
    fn read(&self, _proof: LockOrderProof<TIER>) -> RwLockReadGuard<T> {
        self.inner.read().unwrap()
    }
}
```

At minimum, add a `// LOCK ORDER:` comment block to the top of `substrate.rs`
documenting the required acquisition sequence.

### 2.4 Expected Bottlenecks

Based on architectural analysis, the expected bottleneck hierarchy is:

1. **Pheromone substrate write lock contention** -- the deposits `RwLock` is
   acquired for write on every `deposit()` call. Once GC is enabled, it will
   also be held for the full duration of `gc_evaporated()`. Under high
   throughput, concurrent deposit writes contend; with GC, deposit writes and
   GC compaction will also contend.

2. **Ed25519 signature computation** -- every deposit is signed during
   `detect_and_deposit()` and verified on `substrate.deposit()`. When the
   concrete substrate is `ConfiguredPheromoneSubstrate`, the dispatch layer
   calls `validate_deposit_signature()` and then the inner backend (InMemory,
   LocalJournal) calls it again -- resulting in **two verifications per
   deposit**. Each Ed25519 sign+verify cycle costs ~80-130us on modern
   hardware, but the double verify raises the effective cost to ~130-210us
   per finding.

3. **Response adapter I/O latency** -- HTTP EDR and webhook adapters make
   outbound HTTP requests with a default 5-second timeout
   (`default_response_adapter_timeout_ms = 5000`). This dominates when
   live-response actions are authorized.

4. **Threat intel enrichment queries** -- for DNS and network events, the
   detection pipeline queries the threat intel index sequentially for each
   candidate indicator. Each query acquires the `threat_intel_entries` read
   lock.

---

## 3. Throughput Analysis

### 3.1 Detection Stage

The `CompositeDetector` evaluates all registered strategies sequentially via
`flat_map`:

```rust
fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
    self.strategies
        .iter()
        .flat_map(|strategy| strategy.evaluate(event))
        .collect()
}
```

With 8 detectors (SuspiciousProcessTree, DnsExfiltration, NetworkConnect,
LateralMovement, CredentialAccess, Persistence, SuspiciousScripting,
SupplyChain), each event passes through all 8 evaluators. Individual detectors
perform string matching and threshold comparisons -- CPU-bound work estimated at
1-5us per detector per event.

**Estimated single-event detection latency:** 10-50us (8 detectors, no I/O).

**Estimated detection throughput (single-threaded):** 20K-100K events/second.

However, detection is not the bottleneck because it is followed by pheromone
deposit operations that involve cryptographic signing and lock acquisition.

### 3.2 Pheromone Deposit Stage

For each finding produced by detection, `detect_and_deposit()` performs:

1. Threat intel enrichment -- 0-N async substrate queries (read lock per query)
2. Deposit resolution -- 1 async substrate query for threat class config
3. Ed25519 signing -- `serde_json::to_vec` + `signing_key.sign()` per deposit
4. Signature verification -- `validate_deposit_signature()` called **twice**
   inside `substrate.deposit()`: once in `ConfiguredPheromoneSubstrate` dispatch,
   once in the inner backend (see note below)
5. Write-lock acquisition and `Vec::push`

**Per-finding cost estimate:**

| Operation | Estimated Cost |
|-----------|---------------|
| Threat intel lookup (read lock) | 1-5us |
| Threat class config lookup (read lock) | 1-2us |
| JSON serialization for signing payload | 5-15us |
| Ed25519 sign | 30-50us |
| Ed25519 verify (`ConfiguredPheromoneSubstrate` dispatch) | 50-80us |
| Ed25519 verify (inner backend, e.g. `InMemoryPheromoneSubstrate`) | 50-80us |
| Write lock + Vec::push | 1-5us |
| **Total per finding** | **~140-240us** |

**Note on double verification:** `ConfiguredPheromoneSubstrate::deposit()`
calls `validate_deposit_signature()` before dispatching to the inner backend.
Each inner backend (`InMemoryPheromoneSubstrate`, `LocalJournalPheromoneSubstrate`)
also calls `validate_deposit_signature()` in its own `deposit()` implementation.
This means every deposit is verified twice. Removing the redundant verification
at either layer would save ~50-80us per finding (see section 15.1, question 6).

Most events produce 0-1 findings. For a typical workload where ~30% of events
produce a finding, the amortized deposit cost per event is ~42-72us.

**Estimated deposit throughput (single-threaded):** 4K-7K findings/second,
or 14K-24K events/second assuming a 30% finding rate.

### 3.3 Policy Evaluation Stage

`ConfigurableApprovalGate` evaluates an ordered list of YAML-defined rules plus
a static fallback. Each rule evaluation involves enum matching on severity,
threat class, and agent scope. Rate limiting requires a mutex lock on
`agent_windows` to check sliding window counts.

**Estimated single-evaluation cost:** 5-20us (rule matching + rate-limit check).

**Estimated policy throughput:** 50K-200K evaluations/second.

### 3.4 Response Execution Stage

Response latency depends entirely on the adapter:

| Adapter | Estimated Latency | Notes |
|---------|------------------|-------|
| Sandbox (dry-run) | <10us | No I/O, immediate return |
| HTTP EDR | 50-5000ms | Outbound HTTP, timeout at 5s |
| Webhook | 50-5000ms | Outbound HTTP, timeout at 5s |
| SIEM Forward | 50-5000ms | Outbound HTTP to Splunk/ELK |
| Notification | 50-5000ms | Outbound HTTP to Slack/PagerDuty |

In detect-only mode, response execution is either skipped or uses the sandbox
adapter. In live-response mode, the outbound HTTP call dominates total latency.

The `ResilientExecutor` wraps real adapters with retry logic
(`default_max_retries = 3`, `default_initial_backoff_ms = 200`,
`default_backoff_multiplier = 2.0`) and a circuit breaker
(`threshold = 5 failures`, `cooldown = 30s`). A worst-case retry sequence is
`200ms + 400ms + 800ms = 1.4s` additional latency before circuit-breaking.

### 3.5 End-to-End Throughput Estimate

For detect-only mode (sandbox executor, no outbound I/O):

| Stage | Per-Event Cost | Cumulative |
|-------|---------------|------------|
| Detection (8 detectors) | 10-50us | 10-50us |
| Deposit (amortized, 30% finding rate, incl. double verify) | 42-72us | 52-122us |
| Policy evaluation | 5-20us | 57-142us |
| Sandbox response | <10us | 62-152us |
| Metrics recording (4x mutex) | 4-8us | 66-160us |
| **Total** | | **~66-160us per event** |

**Theoretical single-threaded throughput: 6K-15K events/second.**

The HTTP path processes events sequentially within each request, but Axum
spawns handlers concurrently across the tokio thread pool. With N CPU cores,
the theoretical parallel throughput scales to `N * 6K-15K` events/second,
limited by lock contention on the shared substrate.

---

## 4. Latency Budget Breakdown

### 4.1 Critical Path: Ingest to Replay Bundle

The critical path runs synchronously within `RuntimeService::process_event()`:

```
                    Event arrives via HTTP POST /ingest/events
                                    |
                   [1] ensure_substrate_ready    ~5-20us (read lock; no GC contention today)
                                    |
                   [2] detect_and_deposit        ~90-240us
                       |-- evaluate_event        ~10-50us
                       |-- threat_intel_enrich   ~2-10us
                       |-- resolve_deposits      ~2-5us
                       |-- sign_deposit (x N)    ~30-50us each
                       +-- substrate.deposit     ~100-165us each (double verify)
                                    |
                   [3] finding_enrichment        ~5-15us
                                    |
                   [4] siem_forward (optional)   ~0 or 50-5000ms
                                    |
                   [5] notification_route        ~0 or 50-5000ms
                                    |
                   [6] policy_evaluate           ~5-20us
                                    |
                   [7] response_execute          ~<10us (sandbox) or 50-5000ms
                                    |
                   [8] build_replay_bundle       ~5-15us
                                    |
                    HTTP 200 returned to caller
```

### 4.2 Latency Allocation for Detect-Only Mode

| Stage | p50 Estimate | p99 Estimate | Notes |
|-------|-------------|-------------|-------|
| Substrate readiness | 5us | 20us | Read lock only; GC not currently active |
| Detection (8 strategies) | 20us | 50us | CPU-bound, predictable |
| Threat intel enrichment | 3us | 10us | 0-3 read-lock acquisitions |
| Deposit resolution | 3us | 10us | Read-lock + policy resolution |
| Ed25519 sign | 40us | 60us | Per finding, CPU-bound |
| Signature verify (double) + write | 105us | 180us | Two verifications per deposit; write-lock |
| Finding enrichment | 8us | 15us | JSON object manipulation |
| Policy evaluation | 8us | 20us | Rule matching + rate-limit lock |
| Sandbox response | 2us | 5us | Immediate return |
| Replay bundle assembly | 8us | 15us | Struct construction + format |
| Metrics recording | 4us | 8us | 4 mutex acquisitions |
| **Total** | **~206us** | **~393us** | |

The p99 estimate of ~393us is dominated by cryptographic operations (sign +
2x verify = ~240us at p99) and lock contention under concurrent access.
Removing the redundant second verification would reduce this by ~50-80us.
Even with the current double-verify overhead, there is substantial headroom
below the 10ms p99 SLO target. Note: these p99 estimates assume independent
per-stage tail latencies. Under contention, correlated delays across lock-
dependent stages could push the composite p99 higher.

### 4.3 Latency Allocation for Live-Response Mode

Live-response mode adds the response adapter latency to the critical path.
Assuming an HTTP EDR adapter with 50ms typical latency and 5s timeout:

| Stage | p50 | p99 | p99.9 |
|-------|-----|-----|-------|
| Detection through policy | 206us | 393us | 600us |
| HTTP EDR execution | 50ms | 200ms | 5000ms |
| **Total** | **~50ms** | **~200ms** | **~5000ms** |

The response adapter dominates. The 5-second timeout is the hard upper bound.
For the v1.40 demo, the detection-through-policy latency is the meaningful
internal SLO; response execution latency is externally bounded.

### 4.4 Instrumentation Status

The codebase already instruments the critical path via:

- `RuntimeMetrics` with per-stage histogram buckets at `[100, 500, 1000, 5000,
  10000, 50000, MAX]` microseconds
- `CriticalPathMetrics` (Prometheus) with histograms at `[100, 500, 1000, 5000,
  10000, 50000]` microseconds
- Per-event `Instant::now()` / `elapsed()` timing around detect, policy, and
  response stages

The finding enrichment stage (`time_to_detect_ms` in evidence) captures
detection latency relative to event timestamp, providing an end-to-end
observability signal.

**Gap:** No instrumentation exists for substrate lock wait time, GC pause
duration, or channel send/receive latency. These are critical for understanding
tail latency under load.

---

## 5. Memory Pressure Analysis

### 5.1 PheromoneDeposit Memory Layout

Each `PheromoneDeposit` contains:

```rust
pub struct PheromoneDeposit {
    pub indicator: serde_json::Value,  // heap-allocated JSON tree
    pub threat_class: ThreatClass,     // enum, 1-2 words + String for Custom
    pub severity: Severity,            // enum, 1 byte
    pub confidence: f64,               // 8 bytes
    pub timestamp: i64,                // 8 bytes
    pub decay_half_life: f64,          // 8 bytes
    pub agent_id: AgentId,             // String wrapper (~32-64 bytes typical)
    pub signature: Vec<u8>,            // 64 bytes (Ed25519 signature)
    pub agent_key: Vec<u8>,            // 32 bytes (Ed25519 public key)
}
```

**Estimated per-deposit heap size:**

| Field | Estimated Bytes |
|-------|----------------|
| `indicator` (JSON object with event_id, source, evidence) | 200-800 bytes |
| `threat_class` | 8-40 bytes |
| `severity` | 1 byte |
| `confidence` | 8 bytes |
| `timestamp` | 8 bytes |
| `decay_half_life` | 8 bytes |
| `agent_id` (strategy-scoped, e.g. "whisker-primary:dns_exfiltration") | 40-64 bytes |
| `signature` (Vec overhead + 64 bytes) | 88 bytes |
| `agent_key` (Vec overhead + 32 bytes) | 56 bytes |
| Struct overhead + alignment | 16-32 bytes |
| **Total per deposit** | **~450-1100 bytes** |

Using a conservative midpoint of **750 bytes per deposit**:

| Active Deposits | Estimated Heap (deposits only) |
|----------------|-------------------------------|
| 1,000 | ~750 KB |
| 10,000 | ~7.5 MB |
| 100,000 | ~75 MB |
| 1,000,000 | ~750 MB |

### 5.2 Substrate Growth Under Sustained Load

At 10,000 events/second with a 30% finding rate producing 1 deposit per
finding, the deposit ingest rate is 3,000 deposits/second. With the default
`decay_half_life` of 3,600 seconds and `evaporation_threshold` of 0.01:

The effective evaporation time (time until a deposit's decayed strength drops
below the threshold) depends on the initial confidence value. The evaporation
condition is:

```
strength(t) = confidence * 0.5^(elapsed / half_life) < threshold
elapsed     > half_life * log2(confidence / threshold)
```

For a high-confidence deposit (`confidence = 0.9`):

```
t_evaporate = 3600 * log2(0.9 / 0.01)
            = 3600 * log2(90)
            = 3600 * 6.49
            = ~23,370 seconds (~6.5 hours)
```

For a moderate-confidence deposit (`confidence = 0.5`):

```
t_evaporate = 3600 * log2(0.5 / 0.01)
            = 3600 * log2(50)
            = 3600 * 5.64
            = ~20,320 seconds (~5.6 hours)
```

Using the high-confidence upper bound (~23,400s) for steady-state estimation at
3,000 deposits/second:

```
N_steady = 3,000 * 23,400 = ~70.2 million deposits
```

This would consume ~52 GB of heap -- clearly unsustainable. As noted in section
5.3, the `gc_evaporated()` function is the critical mitigation, but **it is
currently never invoked by the runtime**. Without a GC call site, deposits
accumulate without bound.

### 5.3 GC Effectiveness

**Critical finding:** The `PheromoneSubstrate` trait defines `gc_evaporated()`
and `gc_expired_threat_intel()` methods, but **no runtime code currently calls
them**. The `ConcentrationMonitor::evaluate_all()` only calls
`query_concentration()` -- it does not trigger GC. This means that in the
current codebase, evaporated deposits are never removed from memory. The
deposit vector grows monotonically until process restart.

This is a correctness gap, not just a performance concern: without GC, the
memory growth model in section 5.2 describes the actual runtime behavior, not
a theoretical worst case. The 70.2M steady-state deposit calculation represents
what will actually happen under sustained load.

Adding a GC invocation path (e.g., within the `ConcentrationMonitor` tick loop
or as a dedicated background task) is a prerequisite for the memory ceiling SLOs
in section 11. The remainder of this subsection characterizes the expected GC
behavior once it is enabled.

Each GC invocation would:

1. Acquires the write lock on `deposits`
2. Acquires the read lock on `threat_class_configs`
3. Calls `Vec::retain()` which iterates all deposits, computing decay for each

The `retain()` callback evaluates `PheromoneDeposit::is_evaporated(now, threshold)`
for each deposit, which computes:

```
concentration = 2^(-elapsed_seconds / half_life)
evaporated = concentration < threshold
```

This is O(n) per GC invocation. At 100,000 active deposits, each GC sweep
touches 100K deposits every 100ms. This is ~1M deposits/second of GC work,
consuming significant CPU and holding the write lock for the full sweep.

**Critical observation:** GC would hold the write lock for the entire `retain()`
call. During this period, all `deposit()` calls and all concentration queries
would block. At high deposit counts, GC pause time would become the dominant
source of tail latency. Note also that `gc_evaporated()` acquires a read lock
on `threat_class_configs` while holding the write lock on `deposits` -- if
these locks were ever acquired in the reverse order elsewhere, deadlock would
result. The current code does not exhibit this reverse ordering, but the pattern
is fragile.

### 5.3a Enrichment Read-Lock vs. GC Write-Lock Contention

The threat-intel enrichment pipeline acquires the `threat_intel_entries`
read-lock on every detection pipeline invocation (`pipeline.rs` line 92, via
`threat_intel_matches_for_event`). Under sustained load at 10K events/sec,
this read-lock is acquired approximately 10K times/second (potentially more
with multiple queries per event -- see Doc 03 Section 6.5).

When `gc_expired_threat_intel` is eventually wired up, it will need the
write-lock on the same `threat_intel_entries` BTreeMap. The interaction:

| Load Level | Read-lock rate | GC interval | Contention window |
|------------|---------------|-------------|-------------------|
| 1K events/sec | ~1K reads/sec | 10s | 10K reads between GC ticks |
| 10K events/sec | ~10K reads/sec | 10s | 100K reads between GC ticks |
| 10K events/sec | 1s | 1s | 10K reads between GC ticks |

The write-lock for threat-intel GC blocks all enrichment reads for its
duration. With the current O(n) `retain()` implementation, GC pause
estimates by entry count:

| Entries | Estimated GC pause | Blocked reads at 10K/sec |
|---------|-------------------|-------------------------|
| 10,000 | ~200us | ~2 reads |
| 100,000 | ~2ms | ~20 reads |
| 1,000,000 | ~20ms | ~200 reads |

At 1M entries, a 20ms GC pause blocks 200 enrichment queries, pushing
those events' p99 latency well above the 10ms SLO.

**Mitigation:** The incremental GC design (Section 12.1) applies to threat-
intel GC as well. Using a `BinaryHeap` ordered by `expires_at`, each GC
tick pops only the expired entries, bounding write-lock hold time to O(k)
where k is the expired-entry batch size. With k=100 and ~1us per removal,
write-lock hold time is ~100us -- negligible relative to the 100ms tick
interval. Threat-intel GC should run at a slower cadence than deposit GC
(every 10 seconds vs. every 100ms) because IOC TTLs are measured in hours
to days, not seconds.

### 5.4 Memory Pressure Monitoring

The runtime includes heap pressure monitoring via `sysinfo::System`:

- `max_heap_pressure` defaults to 0.90 (90% of available memory)
- `HeapPressureSnapshot` tracks `bytes`, `limit_bytes`, and `pressure_ratio`
- The ingest handler checks heap pressure and rejects requests when above
  threshold

This is a coarse safety valve, not a fine-grained memory management strategy.
It does not account for substrate-specific growth patterns.

**Alerting thresholds.** The current binary reject-at-90% model provides no
warning before the system starts dropping traffic. Operators should receive
graduated alerts:

| Threshold | Level | Action |
|-----------|-------|--------|
| Heap pressure > 70% | Warning | Operator alert; consider reducing feed polling frequency or lowering deposit retention |
| Heap pressure > 85% | Critical | Operator page; trigger aggressive GC (increase `gc_max_evictions_per_tick` temporarily) |
| Heap pressure > 90% | Emergency | Reject new ingest requests (current behavior) |
| Deposit count > 80% of `max_active_deposits` | Warning | Indicates GC is not keeping up with deposit rate |
| GC pause duration > 5ms | Warning | Incremental GC batch size may be too large |
| GC pause duration > 50ms | Critical | GC is operating in full-sweep mode or the incremental design has regressed |

These thresholds should be exposed as Prometheus metrics and configurable via
the runtime configuration. The existing `CriticalPathMetrics` infrastructure
can be extended with `gc_pause_duration_us` (histogram) and
`deposit_count_ratio` (gauge) metrics.

### 5.5 LocalJournal Backend Memory

The `LocalJournalPheromoneSubstrate` maintains the same in-memory
`Vec<PheromoneDeposit>` as the `InMemory` backend, plus JSONL journal files.
Memory pressure is identical; the journal provides crash recovery but not memory
relief.

The journal files grow monotonically. There is no compaction or truncation
mechanism -- `gc_evaporated()` removes entries from the in-memory vector but
does not rewrite the journal. Over time, the journal file will contain a mix of
live and evaporated deposits.

**Journal compaction analysis.** At 3,000 deposits/second, the journal
grows at approximately 2.25 MB/second (750 bytes/deposit as JSON line). After
one hour: ~8.1 GB. After 24 hours: ~194 GB. Even with aggressive GC keeping
the in-memory deposit count at 100K, the journal file contains the full history
of all deposits ever written.

Replay-on-startup re-reads all entries via `load_jsonl`, including long-
evaporated deposits that will be discarded during the first GC pass. At 194 GB,
startup takes minutes of blocking I/O.

**Compaction options:**

1. **Periodic journal rewrite** (simplest). After each GC pass, rewrite the
   journal with only live entries. The existing `LocalJournalPheromoneSubstrate::
   gc_evaporated()` already does this via `rewrite_jsonl()`. The issue is that
   this is blocking I/O holding the write lock. Move to `spawn_blocking` and
   write to a temporary file, then atomic rename.

2. **Segmented journal.** Write to time-stamped segment files (one per hour).
   Delete segments older than `2 * max_evaporation_time`. Startup only reads
   segments within the evaporation window.

3. **Embedded database.** Replace JSONL with `redb` or `sled`, which handle
   compaction natively. This adds a dependency but eliminates the compaction
   problem entirely.

**Recommendation:** Option 1 is already partially implemented (the
`rewrite_jsonl` calls in GC). The fix is to make it non-blocking and run it
at a lower cadence than GC itself (e.g., every 5 minutes). Option 2 is
preferred for long-running production deployments. Estimate: at 3K deposits/sec
and 6.5-hour evaporation window, each segment contains ~70M entries and
compaction should trigger when cumulative journal size exceeds 2x the live
entry count.

### 5.6 Beacon Tracker Unbounded Growth

The `NetworkConnectDetector::beacon_tracker` (`crates/swarm-whisker/src/
network_connect.rs`, line 58) is a `HashMap<BeaconKey, VecDeque<i64>>` behind
an `Arc<Mutex<...>>` with **no eviction of stale keys**. Each `BeaconKey`
is a 5-field struct:

```rust
struct BeaconKey {
    host_id: String,        // ~16-32 bytes
    process_name: String,   // ~8-32 bytes
    destination_ip: String, // ~7-39 bytes
    destination_port: u16,  // 2 bytes
    protocol: String,       // ~3-8 bytes
}
```

The `record_connection` method (line 211) evicts old timestamps from each
key's `VecDeque` when they fall outside `beacon_window_ms`, but **never
removes keys whose VecDeque is empty or whose last timestamp is outside the
beacon window**. The code:

```rust
fn record_connection(&self, key: BeaconKey, timestamp_ms: i64) -> Vec<i64> {
    let window_start = timestamp_ms.saturating_sub(self.beacon_window_ms);
    let mut guard = self.beacon_tracker.lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let entries = guard.entry(key).or_default();
    while entries.front().is_some_and(|recorded_at| *recorded_at < window_start) {
        entries.pop_front();
    }
    entries.push_back(timestamp_ms);
    entries.iter().copied().collect()
}
```

Note that even when all timestamps are evicted from a `VecDeque`, the key
remains in the `HashMap` with an empty deque. The key itself consumes ~100-200
bytes (five heap-allocated `String` fields plus `HashMap` entry overhead).

**Growth projection.** In a deployment seeing connections to many distinct
(host, process, IP, port, protocol) tuples:

| Events/sec | Unique tuple rate | Keys/hour | Memory/hour |
|------------|------------------|-----------|-------------|
| 1,000 | 5% (50 new keys/s) | 180,000 | ~27 MB |
| 10,000 | 10% (1,000 new keys/s) | 3,600,000 | ~540 MB |
| 10,000 | 1% (100 new keys/s) | 360,000 | ~54 MB |

Even conservative estimates produce significant memory growth over hours of
operation. After 24 hours at the moderate scenario (100 new keys/sec), the
tracker holds ~8.6M keys consuming ~1.3GB.

**Proposed eviction strategies:**

1. **Eager empty-key removal.** After evicting stale timestamps, check if the
   `VecDeque` is empty and remove the key. Zero implementation cost, addresses
   the common case where connections are bursty:

   ```rust
   // After the while loop in record_connection:
   if entries.is_empty() {
       // Don't insert a new timestamp for a stale key we just found
       // Actually, we always push_back, so check after the full method
   }
   ```

   More precisely, add a periodic sweep that removes empty deques.

2. **Periodic stale-key sweep.** Run a background task every 60 seconds that
   iterates the `HashMap` and removes keys whose most recent timestamp is
   older than `beacon_window_ms`:

   ```rust
   fn gc_stale_beacon_keys(&self, now_ms: i64) {
       let window_start = now_ms.saturating_sub(self.beacon_window_ms);
       let mut guard = self.beacon_tracker.lock()
           .unwrap_or_else(|poison| poison.into_inner());
       guard.retain(|_key, deque| {
           deque.back().is_some_and(|ts| *ts >= window_start)
       });
   }
   ```

   Cost: O(n) per sweep, but the `retain` callback is cheap (one pointer
   comparison per key). At 1M keys, this takes ~1-2ms.

3. **LRU-bounded capacity.** Replace `HashMap` with an LRU cache capped at
   a configurable maximum (e.g., 100K keys). When the cache is full, the
   least-recently-accessed key is evicted. This provides a hard memory
   ceiling at the cost of potentially evicting active beacon tracking for
   low-frequency connections.

**Recommendation:** Implement option 2 (periodic stale-key sweep) as the
initial fix. It is simple, correct, and bounds memory growth to the number
of *active* connection tuples within the beacon window. Add option 3 as a
secondary safeguard for edge deployments with strict memory budgets.

### 5.7 Threat Intel Entry Memory Pressure

Doc 03 proposes scaling the threat-intel cache to 1M entries (Section 6.3, L2
target). The `gc_expired_threat_intel()` function suffers the same "never
called" bug as deposit GC (Section 5.3), and `store_threat_intel_entry`
(`substrate.rs` line 472) simply inserts into the `BTreeMap` without checking
any capacity limit. Feed ingestion thus grows the map without bound.

**Per-entry memory estimate:**

```rust
pub struct ThreatIntelEntry {
    pub indicator_type: ThreatIntelIndicatorType, // enum, 1-2 words
    pub value: String,                            // 24 + content (~20-80 bytes)
    pub confidence: f64,                          // 8 bytes
    pub expires_at: i64,                          // 8 bytes
}
// Plus BTreeMap node overhead: ~48-64 bytes per node
```

| Entry Count | Estimated Heap | Notes |
|-------------|---------------|-------|
| 1,000 | ~200 KB | Minimal deployment |
| 10,000 | ~2 MB | Edge profile (Doc 03 Section 15.1) |
| 100,000 | ~20 MB | Standard deployment |
| 1,000,000 | ~200 MB | Enterprise with expanded entry format |

With Doc 03's proposed expanded `ThreatIntelEntry` (adding `sources:
Vec<ThreatIntelSource>`, `ingested_at`, `decay_half_life_secs`, tags), per-
entry size increases to ~300-600 bytes, pushing the 1M entry scenario to
~300-600MB -- which exceeds the 256MB edge budget and consumes a significant
fraction of the 512MB developer-laptop budget.

**Mitigations:**

- Wire up `gc_expired_threat_intel()` alongside deposit GC (same priority).
- Add a hard cap: `threat_intel_max_entries` configuration parameter with LRU
  eviction when the cap is reached. Evict the lowest-confidence expired entry
  first, then the oldest entry.
- Deployment profiles (Doc 03 Section 15) should set per-profile caps.

---

## 6. Tokio Runtime Contention

### 6.1 Task Spawning Patterns

The binary spawns a fixed set of long-lived tasks at startup:

| Task | Lifetime | CPU Profile |
|------|----------|-------------|
| Axum server | Process lifetime | I/O-bound (HTTP accept + handler dispatch) |
| Bridge worker (per bridge) | Process lifetime | I/O-bound (poll + channel send) |
| Agent dispatcher | Process lifetime | Mixed (sequential agent ticks) |
| Concentration monitor | Process lifetime | CPU-bound (concentration computation) |
| Config reload watcher | Process lifetime | I/O-bound (filesystem events) |

No tasks are dynamically spawned per-event. The Axum handler executes the full
critical path within the request task, which is managed by tokio's task pool.
This is a significant advantage: no per-event spawn overhead, no unbounded task
growth.

### 6.2 Blocking Operations in Async Context

Several operations in the critical path perform blocking work within async
functions:

1. **`std::sync::RwLock` acquisitions** -- `InMemoryPheromoneSubstrate` uses
   `std::sync::RwLock`, not `tokio::sync::RwLock`. When these locks are
   contended, the calling tokio worker thread is blocked, reducing effective
   parallelism.

2. **`std::sync::Mutex` on `RuntimeMetrics`** -- four mutex acquisitions per
   event for stage latency recording. Short hold times mitigate impact.

3. **Ed25519 cryptographic operations** -- `sign()` and `verify()` are CPU-bound
   operations (~80-130us combined) that do not yield to the tokio scheduler.

4. **`serde_json::to_vec`** -- JSON serialization for signing payloads is
   CPU-bound.

5. **File I/O in `LocalJournalPheromoneSubstrate`** -- `append_jsonl_line()`
   performs synchronous `OpenOptions::append().open()` + `write_all()` +
   `flush()` inside an async context. This blocks the tokio worker thread on
   filesystem I/O. The scope of blocking I/O is broader than the deposit path
   alone:

   - `deposit()` (line 653): `append_jsonl_line(&self.journal_path, &deposit)`
   - `record_escalation()` (line 663): `append_jsonl_line(&self.escalation_journal_path, &record)`
   - `store_threat_class_config()` (line 676): `append_jsonl_line(&self.threat_class_config_journal_path, &config)`
   - `store_threat_intel_entry()` (line 690): `append_jsonl_line(&self.threat_intel_journal_path, &entry)`
   - `gc_evaporated()` (line 789): `rewrite_jsonl(&self.journal_path, &guard)` -- full file rewrite
   - `gc_expired_threat_intel()` (line 800): `rewrite_jsonl(&self.threat_intel_journal_path, ...)` -- full file rewrite
   - `open()` (line 624): `load_jsonl()` x4 for deposits, escalations, configs, threat intel -- blocking reads at startup

   With Doc 03's automated feed ingestion producing bulk inserts via
   `store_threat_intel_entry`, the threat-intel journal write path becomes a
   sustained blocking I/O source. Ingesting a feed batch of 10,000 IOCs
   produces 10,000 sequential `append_jsonl_line` calls, each performing an
   `open()` + `write_all()` + `flush()` syscall sequence. At ~50us per
   append on SSD, this is ~500ms of blocking I/O during a single feed poll.

   The `rewrite_jsonl` calls during GC are even more expensive: they serialize
   the entire live dataset and rewrite the file. At 100K deposits (~75MB of
   JSON), this is a multi-second blocking operation.

   **Recommendation:** Wrap all `LocalJournalPheromoneSubstrate` I/O operations
   in `tokio::task::spawn_blocking()`. For bulk feed ingestion, batch journal
   writes: accumulate N entries in memory and write them in a single
   `write_all` call rather than one `append_jsonl_line` per entry. Target:
   one fsync per batch (1,000 entries) rather than one fsync per entry.

**Risk assessment:** Under high concurrency, the `std::sync::RwLock` on
deposits is a contention source for concurrent deposit writes and concentration
queries. However, since `gc_evaporated()` is never called by the runtime (see
section 5.3), the GC write-lock pause described elsewhere in this document does
not currently occur. Once GC is wired up, a 1ms GC pause on 8 threads would
block 8ms of aggregate worker time. The double Ed25519 verification is the
more immediate concern: it holds no locks but consumes ~100-160us of CPU per
deposit across two redundant verify calls.

### 6.3 Runtime Configuration

The binary uses `#[tokio::main]` with default settings:

- **Worker threads:** One per logical CPU core (platform default)
- **Scheduling:** Work-stealing, multi-thread
- **Stack size:** Default (8MB on Linux)

No custom runtime configuration is applied. The default is reasonable for the
current workload, but explicit configuration would allow:

- Pinning worker count for predictable performance
- Dedicated blocking thread pool for file I/O
- Custom stack sizes for deep call chains

---

## 7. Backpressure and Flow Control

### 7.1 HTTP Ingest Path

The HTTP ingest handler in `crates/swarm-runtime/src/ingest.rs` processes events
synchronously within the request handler. Backpressure is applied implicitly
through HTTP connection concurrency -- Axum's default does not limit concurrent
requests, so the system relies on TCP backpressure and client-side timeouts.

After processing an event through the critical path, the handler attempts to
copy the event to the telemetry channel for agent dispatch:

```rust
match tx.try_send(event.clone()) {
    Ok(()) => {}
    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
        tracing::warn!(
            "telemetry buffer full; skipping agent dispatch copy"
        );
    }
    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
        tracing::warn!(
            "telemetry buffer closed; skipping agent dispatch copy"
        );
    }
}
```

This is a non-blocking `try_send`. When the 10,000-element channel is full,
the agent dispatch copy is silently dropped with a warning log. The HTTP
response is still returned successfully -- the critical path (detect + policy +
response) has already completed. This means:

- **HTTP callers see no backpressure from agent dispatch saturation.**
- **WhiskerAgent may miss events that were successfully processed by the HTTP
  critical path.** This is acceptable because the HTTP path already deposited
  pheromones; the WhiskerAgent path is redundant enrichment.

### 7.2 Bridge Ingest Path

Bridge workers use `telemetry_tx.send(event).await`, which blocks the bridge
poll loop when the channel is full. This applies proper backpressure -- if the
WhiskerAgent cannot consume events fast enough, bridges stop polling for new
events.

However, the bridge send is interruptible by shutdown:

```rust
tokio::select! {
    _ = shutdown.changed() => return,
    send = telemetry_tx.send(event) => {
        if send.is_err() { ... }
    }
}
```

Bridge-side backpressure can cascade to the upstream source. For Tetragon gRPC
streams, this means gRPC flow control kicks in. For CloudTrail and GenericJSON
file-based bridges, the bridge simply stalls on the next event and resumes when
the channel drains.

### 7.3 Agent Dispatch Consumption Rate

The WhiskerAgent drains the telemetry channel during each dispatcher tick using
`try_recv()` in a loop:

```rust
let mut events = Vec::new();
{
    let mut rx = self.event_rx.lock().await;
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
}
```

This means the WhiskerAgent processes all buffered events in a single tick.
At 100ms tick intervals with 10,000 channel capacity, the maximum burst that
can accumulate between ticks is bounded by channel capacity.

**Critical concern:** If 10,000 events accumulate between ticks, the
WhiskerAgent processes all of them sequentially in a single tick. Each event
passes through `detect_and_deposit()` which involves cryptographic operations.
At ~160us per event (including double signature verification), processing
10,000 events takes ~1.6 seconds, exceeding the 500ms agent tick timeout
(`agent_tick_timeout_ms = 500`). The dispatcher would mark WhiskerAgent as
Degraded.

### 7.4 Dead-Letter Behavior

Failed response executions and notification deliveries are written to dead-letter
JSONL files:

- `./dead-letter.jsonl` for response adapter failures
- `./siem-dead-letter.jsonl` for SIEM forward failures
- `./notification-dead-letter.jsonl` for notification delivery failures

Optional rotation is available via `max_dead_letter_bytes`. Dead-letter writes
are synchronous file I/O within the async context -- another blocking operation
under failure conditions.

### 7.5 Graceful Shutdown

The runtime implements drain-aware shutdown with a 30-second default timeout
(`drain_timeout_ms = 30_000`). During shutdown:

1. `begin_drain()` sets the `draining` flag
2. New ingest requests are rejected
3. `wait_for_drain()` waits for active requests to complete
4. Shutdown signal is sent to all subsystems
5. Background tasks are awaited with a 30-second timeout

This ensures in-flight events complete processing before shutdown, preventing
data loss in the critical path.

---

## 8. JetStream Backend Performance

### 8.1 Connection Management

The `JetStreamPheromoneSubstrate` uses lazy connection initialization via
`tokio::sync::OnceCell`. The first operation triggers a NATS connection with a
configurable timeout (default 5,000ms):

```rust
timeout(
    Duration::from_millis(connect_timeout_ms),
    async_nats::connect(url.as_str()),
).await
```

Once connected, the client is reused for all subsequent operations. Connection
failure is not retried automatically -- the substrate returns an error and the
caller must handle reconnection.

### 8.2 Key-Value Store Operations

The JetStream backend maps pheromone deposits to a NATS KV bucket
(`swarm-pheromone-deposits` by default). Each deposit is stored as a JSON-
encoded value under a key that encodes threat class and timestamp:

**Deposit write path:**
1. `ensure_connected()` -- OnceCell check (~0 cost after first call)
2. `validate_deposit_signature()` -- Ed25519 verify (~50-80us)
3. `serde_json::to_vec(&deposit)` -- JSON encode (~10-30us)
4. `store.put(key, bytes).await` -- NATS publish + JetStream ack (~1-5ms)

The NATS publish + JetStream ack latency dominates at 1-5ms per operation.
This is 10-50x slower than the in-memory backend's microsecond-level write lock.

**Deposit query path:**
1. `store.keys().await` -- retrieve all keys from bucket
2. Filter keys by threat class / timestamp
3. `store.get(key).await` per matching key -- individual KV reads

Querying is O(K) where K is the total number of keys in the bucket, because
the implementation iterates all keys to filter. This is a significant scalability
concern for large deposit counts.

### 8.3 GC on JetStream

The JetStream GC uses a paginated approach:

- `GC_PAGE_SPAN_SECS = 300` -- processes deposits in 5-minute time windows
- `DEFAULT_JETSTREAM_GC_PAGE_SIZE = 512` -- up to 512 keys per GC invocation
- Pages through deposits chronologically via a cursor

Each GC invocation:
1. Lists keys matching the current page cursor window
2. Fetches and deserializes each deposit
3. Evaluates evaporation for each
4. Deletes evaporated keys via `store.delete(key).await`

Each delete is a separate NATS operation. Deleting 512 evaporated deposits
requires 512 sequential NATS round-trips. At 1ms per operation, this is ~500ms
of GC time per page.

### 8.4 Batch Operation Opportunities

The current JetStream implementation does not use NATS batch publish or
multi-get operations. Each deposit write, each query read, and each GC delete
is an individual round-trip. Batching would reduce:

- Deposit writes: group multiple deposits into a single JetStream publish
- GC deletes: batch delete operations
- Query reads: use server-side filtering instead of client-side key iteration

---

## 9. Multi-Bridge Concurrent Ingestion

### 9.1 Bridge Architecture

Multiple bridges can run simultaneously, each as a separate tokio task. The
current bridge types are:

| Bridge | Source | Event Generation Pattern |
|--------|--------|------------------------|
| CloudTrail | JSON file / S3 | Batch: reads all events from file, emits sequentially |
| Tetragon | gRPC stream | Streaming: continuous event flow from kernel |
| GenericJSON | JSON file with field mapping | Batch: reads and transforms file contents |

All bridges share the same `mpsc::Sender<TelemetryEvent>` channel. The channel
is cloned per-bridge via `telemetry_tx.clone()`.

### 9.2 Contention Patterns

When multiple bridges produce events simultaneously:

1. **Channel send contention** -- `mpsc::Sender` is designed for concurrent
   sends. Tokio's mpsc uses a linked-list approach with per-sender semaphore
   permits, so multiple senders do not lock-contend. Send is O(1).

2. **Substrate write contention** -- if both the HTTP critical path and the
   WhiskerAgent (via bridge events) deposit pheromones concurrently, they
   contend on the substrate's write lock. The HTTP path deposits directly; the
   WhiskerAgent deposits during its tick. Since the dispatcher serializes agent
   ticks, WhiskerAgent deposits are temporally batched within a tick window.

3. **CPU contention** -- multiple bridges generating events simultaneously
   increases the channel fill rate. If the combined ingest rate exceeds the
   WhiskerAgent's consumption rate, the channel fills and bridge sends block.

### 9.3 Tetragon gRPC Specifics

The Tetragon bridge connects to a gRPC streaming endpoint with configurable
reconnect backoff:

- `reconnect_backoff_ms`: 1,000ms (initial)
- `max_reconnect_backoff_ms`: 30,000ms (ceiling)
- `event_timeout_secs`: 30 (per-event receive timeout)

Under sustained kernel telemetry load (e.g., high-frequency exec events),
the Tetragon bridge can produce thousands of events per second. Combined with
CloudTrail batch ingestion, the system may need to handle burst rates of
10K+ events/second across bridges.

### 9.4 Cross-Bridge Event Ordering

Events from different bridges arrive at the telemetry channel in arbitrary
order. The WhiskerAgent processes them in channel order (FIFO), but the
`TelemetryEvent::timestamp` field reflects the original event time, not arrival
time. Pheromone concentration queries use the event timestamp for decay
computation, so out-of-order arrival does not affect correctness.

However, correlation and investigation logic may produce confusing results when
events from different time windows arrive interleaved. This is a correctness
concern for incident reconstruction, not a performance concern.

---

## 10. Benchmarking Framework Design

### 10.1 Microbenchmarks (Criterion)

Individual hot-path functions should be benchmarked in isolation:

```
benches/
  detection_bench.rs      -- CompositeDetector::evaluate() with 8 strategies
  deposit_bench.rs        -- detect_and_deposit() against InMemorySubstrate
  signing_bench.rs        -- Ed25519 sign + verify cycle
  policy_bench.rs         -- ConfigurableApprovalGate::evaluate()
  substrate_bench.rs      -- deposit() + query_concentration() under contention
  gc_bench.rs             -- gc_evaporated() at various deposit counts
  serialization_bench.rs  -- serde_json for TelemetryEvent, PheromoneDeposit
```

**Key benchmark parameters:**

| Benchmark | Varied Parameter | Range |
|-----------|-----------------|-------|
| detection | Strategy count | 1, 4, 8 |
| detection | Event payload type | ProcessStart, DnsQuery, NetworkConnect |
| deposit | Finding count per event | 0, 1, 3 |
| substrate contention | Concurrent readers | 1, 4, 8, 16 |
| GC | Deposit count | 1K, 10K, 100K, 1M |
| GC | Evaporation ratio | 10%, 50%, 90% |

### 10.2 End-to-End Load Testing

A synthetic telemetry generator should produce configurable event streams:

```rust
struct SyntheticLoadConfig {
    /// Events per second target.
    events_per_second: u64,
    /// Distribution of event payload types.
    payload_distribution: PayloadDistribution,
    /// Fraction of events that trigger at least one finding.
    finding_rate: f64,
    /// Duration of the load test.
    duration: Duration,
    /// Number of concurrent HTTP clients.
    client_count: usize,
}
```

**Load test prerequisite: concurrency limits.** The current Axum server has
no concurrency limits (Section 7.1). A load test with 100 concurrent HTTP
clients could overwhelm the tokio thread pool before the substrate or
detection stages become the bottleneck, producing misleading results. Either
add `tower::limit::ConcurrencyLimitLayer` to the Axum server before load
testing, or design the load test to bypass HTTP and drive events directly
through `RuntimeService::process_event()` for a focused critical-path
measurement. The bypass approach is recommended for the initial benchmark
suite (Section 10.5) because it isolates the detection pipeline from HTTP
and network variability.

**Metrics to collect during load tests:**

| Category | Metrics |
|----------|---------|
| Throughput | Events ingested/sec, findings produced/sec, deposits/sec |
| Latency | p50/p95/p99/p99.9 for detect, policy, response, end-to-end |
| Memory | RSS, heap bytes, deposit count, threat intel entry count |
| Substrate | Write-lock hold time, GC pause duration, GC eviction count |
| Channel | Telemetry channel occupancy, dropped events (try_send failures) |
| CPU | Tokio worker utilization, context switches, time in crypto |
| Backpressure | Bridge send block duration, HTTP reject rate |

### 10.3 Stress Test Scenarios

1. **Sustained load:** 10K events/sec for 30 minutes, measure memory growth
   and latency stability
2. **Burst load:** 100K events in 1 second, measure recovery time
3. **GC stress:** Pre-fill 500K deposits, then measure GC pause impact on p99
4. **Multi-bridge saturation:** 3 bridges at 5K events/sec each, measure
   channel contention
5. **Response timeout cascade:** EDR adapter at 100% timeout rate, measure
   circuit breaker behavior and dead-letter write overhead
6. **Memory ceiling:** Increase load until heap pressure threshold triggers
   rejection, measure recovery behavior

### 10.4 Benchmark Infrastructure

```toml
# Cargo.toml additions
[dev-dependencies]
criterion = { version = "0.5", features = ["async_tokio"] }

[[bench]]
name = "critical_path"
harness = false
```

Benchmarks should run in CI with:
- Fixed CPU affinity for reproducibility
- Memory-limited cgroups to catch allocation regressions
- Baseline comparisons using `criterion`'s statistical regression detection

### 10.5 Benchmark Runability Status

**Current state: zero Criterion benchmarks exist in the production crates.**
The only `criterion` usage is in `vendor/reference/clawdstrike/`, which is
reference-only material. No `[[bench]]` sections exist in any production
`Cargo.toml`. The benchmarking framework designed above is aspirational --
none of it is runnable today.

**Bootstrap steps to create the first runnable benchmarks:**

1. **Add `criterion` to dev-dependencies** of `swarm-pheromone` and
   `swarm-runtime`:

   ```toml
   # crates/swarm-pheromone/Cargo.toml
   [dev-dependencies]
   criterion = { version = "0.5", features = ["async_tokio"] }

   [[bench]]
   name = "substrate_bench"
   harness = false

   # crates/swarm-runtime/Cargo.toml
   [dev-dependencies]
   criterion = { version = "0.5", features = ["async_tokio"] }

   [[bench]]
   name = "pipeline_bench"
   harness = false
   ```

2. **Write the three highest-value benchmarks** that directly validate
   the cost estimates in Sections 3-5:

   a. **`substrate_bench::deposit_and_query`** -- construct an
      `InMemoryPheromoneSubstrate` pre-populated with N deposits, then
      benchmark `deposit()` and `query_concentration()` under varying N
      (1K, 10K, 100K). This validates the write-lock contention estimates
      and provides the first empirical GC pause measurements.

   b. **`substrate_bench::gc_evaporated`** -- pre-fill the substrate with
      N deposits where P% are past their evaporation threshold. Benchmark
      `gc_evaporated()` at (10K, 10%), (100K, 50%), and (100K, 90%).
      This provides the GC pause duration numbers needed to validate the
      incremental GC design (Section 12.1).

   c. **`pipeline_bench::detect_and_deposit`** -- construct a
      `CompositeDetector` with all 8 strategies, an `InMemoryPheromoneSubstrate`
      with 1K threat-intel entries, and benchmark `detect_and_deposit()` with
      realistic `TelemetryEvent` payloads (DnsQuery, NetworkConnect,
      ProcessStart). This validates the end-to-end latency budget (Section 4).

3. **Run with**: `cargo bench --workspace` and verify results are
   reproducible within 5% variance across runs.

4. **CI integration** can follow once the benchmarks are stable. Start
   with local-only execution and manual comparison; add CI gates later.

**Estimated effort:** 2-4 hours for the three bootstrap benchmarks.
These should be treated as a prerequisite task for any optimization work,
not as future work.

---

## 11. Target Performance Envelope

### 11.1 Proposed SLOs for v1.40 Killer Demo

The following targets are derived from the architectural analysis and represent
achievable goals with targeted optimizations:

| Metric | Target | Rationale |
|--------|--------|-----------|
| Sustained ingestion rate | 10,000 events/sec | Current theoretical single-thread capacity is 6-15K; multi-thread should exceed 10K after removing double verify |
| p50 critical-path latency (detect-only) | < 500us | Current estimate is ~206us with headroom |
| p99 critical-path latency (detect-only) | < 10ms | Current estimate is ~393us; allows for future GC pauses and lock contention |
| p99.9 critical-path latency (detect-only) | < 50ms | Accommodates worst-case GC pause once GC is enabled |
| p50 critical-path latency (live-response) | < 100ms | Dominated by adapter I/O |
| p99 critical-path latency (live-response) | < 1s | Includes one retry attempt |
| Memory ceiling (100K active deposits) | < 512MB | ~75MB for deposits + overhead for runtime structures |
| Memory ceiling (1M active deposits) | < 2GB | Linear scaling with deposit count |
| GC pause duration at 100K deposits | < 5ms | Must not dominate p99 latency (requires GC to be wired up first) |
| Channel drop rate (agent dispatch) | < 0.1% | At sustained 10K events/sec |
| Time to first detection | < 1ms | From event receipt to finding emission |

### 11.2 Scaling Envelope

| Deployment | CPU Cores | Expected Throughput | Memory Budget |
|------------|-----------|--------------------| --------------|
| Developer laptop | 4 | 12-25K events/sec | 512MB |
| Small production | 8 | 30-60K events/sec | 2GB |
| Medium production | 16 | 60-120K events/sec | 4GB |
| Edge node (Raspberry Pi 4) | 4 | 4-8K events/sec | 256MB |

These projections assume resolution of the lock-contention and GC-pause
bottlenecks identified in this document. Without optimization, contention will
limit practical throughput to lower values than the theoretical per-core
capacity suggests.

### 11.3 Comparison with Industry Benchmarks

For context, published EDR/XDR performance claims:

| Product | Claimed Throughput | Agent Memory |
|---------|-------------------|-------------|
| CrowdStrike Falcon | Not published; kernel driver model | 200-400MB RSS |
| Microsoft Defender for Endpoint | Not published | 300-500MB RSS |
| Elastic Agent | 10K events/sec (documented) | 500MB-1GB RSS |
| OSSEC/Wazuh | 1K-5K events/sec (community benchmarks) | 100-300MB RSS |

Swarm Team Six's Rust-native implementation with no kernel driver and no
managed runtime should achieve competitive throughput at significantly lower
memory footprint.

---

## 12. Optimization Opportunities

### 12.1 Low-Hanging Fruit

**0a. Wire up GC invocation in the runtime (with incremental design)**

The `gc_evaporated()` and `gc_expired_threat_intel()` methods exist on the
`PheromoneSubstrate` trait and are implemented by all backends, but **no runtime
code calls them**. Without GC, deposits accumulate without bound.

**Impact:** Without this change, the memory ceiling SLOs in section 11 are
unachievable. This is a blocking prerequisite for production deployment.

**Critical design constraint:** Wiring the existing O(n) `retain()` into the
`ConcentrationMonitor` 100ms tick creates a new bottleneck. At 100K deposits,
the `retain()` call iterates all deposits with a decay computation per entry,
holding the write-lock for the entire sweep. At 10 ticks/second, this is ~1M
decay computations/second of pure GC overhead, plus write-lock contention that
blocks all concurrent deposit and query operations.

**Recommendation: skip the full-sweep wire-up and go directly to incremental
GC.** The existing `gc_evaporated()` implementation should be replaced, not
merely called. Three viable incremental designs:

**Option A: Time-bucketed eviction (recommended).** Maintain an auxiliary
`BTreeMap<i64, Vec<usize>>` mapping estimated evaporation timestamps to deposit
indices. On each GC tick, pop the front of the tree (entries with the earliest
evaporation times) and verify they are actually evaporated (the estimate may be
stale if confidence was boosted). Remove confirmed-evaporated deposits. Bound
the number of removals per tick to `gc_max_evictions_per_tick` (default: 500).

```rust
struct IncrementalGcState {
    /// Estimated evaporation time -> deposit indices.
    eviction_schedule: BTreeMap<i64, Vec<usize>>,
    /// Maximum deposits to evaluate per GC tick.
    max_per_tick: usize,
}

impl IncrementalGcState {
    fn gc_tick(
        &mut self,
        deposits: &mut Vec<PheromoneDeposit>,
        configs: &BTreeMap<ThreatClass, ThreatClassConfig>,
        pheromone_config: &PheromoneConfig,
        now: i64,
    ) -> usize {
        let mut evicted = 0;
        let mut checked = 0;
        // Collect keys up to `now` to avoid borrowing conflicts.
        let expired_keys: Vec<i64> = self.eviction_schedule
            .range(..=now)
            .map(|(k, _)| *k)
            .collect();
        for key in expired_keys {
            if checked >= self.max_per_tick {
                break;
            }
            if let Some(indices) = self.eviction_schedule.remove(&key) {
                for idx in indices {
                    if idx < deposits.len() {
                        let deposit = &deposits[idx];
                        let policy = resolved_policy(
                            pheromone_config, configs, &deposit.threat_class,
                        );
                        if deposit.is_evaporated(now, policy.evaporation_threshold) {
                            // Mark for removal (swap-remove or deferred compaction)
                            evicted += 1;
                        }
                    }
                    checked += 1;
                }
            }
        }
        evicted
    }
}
```

Write-lock hold time is bounded to O(k) where k = `max_per_tick`, not O(n).
At k=500 with ~1us per evaporation check, the hold time is ~500us -- well
within the 5ms GC pause SLO.

**Option B: Generational GC.** Partition deposits into "young" and "old"
generations. New deposits enter the young generation. After surviving N GC
cycles, they are promoted to old. The young generation (which changes rapidly)
is swept every tick; the old generation is swept every 10th tick. This reduces
per-tick work because most evaporations occur in the young generation (recently
deposited, low-confidence findings evaporate fast).

**Option C: Epoch-based reclamation.** Assign each deposit a monotonically
increasing epoch number. Track the "safe epoch" below which all deposits are
confirmed evaporated. GC only examines deposits between the safe epoch and the
current epoch. This is similar to epoch-based memory reclamation in lock-free
data structures.

**For the threat-intel GC (`gc_expired_threat_intel`):** The same incremental
approach applies. Since `ThreatIntelEntry` has an explicit `expires_at`
timestamp, maintain a `BinaryHeap<(i64, ThreatIntelKey)>` ordered by
expiration time. Each GC tick pops entries whose `expires_at <= now` and
removes them from the `BTreeMap`. This is O(k log n) per tick where k is the
number of expired entries.

**0b. Remove redundant double signature verification**

`ConfiguredPheromoneSubstrate::deposit()` calls `validate_deposit_signature()`
and then delegates to the inner backend which calls it again. Removing the
redundant call from either the dispatch layer or the inner backends saves
~50-80us per deposit.

**Impact:** ~50-80us per finding. Reduces end-to-end per-event latency by
~15-25us at a 30% finding rate. Zero risk -- the remaining verification
provides identical protection.

**1. Replace `std::sync::RwLock` with `tokio::sync::RwLock` on substrate**

The in-memory substrate uses `std::sync::RwLock` in an async context. When the
write lock is held (during deposit or GC), all tokio worker threads attempting
to acquire the read lock are blocked -- they do not yield to the scheduler.
Switching to `tokio::sync::RwLock` would allow blocked tasks to yield, improving
overall throughput even if individual lock acquisition latency increases slightly.

**Impact:** Reduces tail latency under GC contention. Estimated p99 improvement
of 2-5x during GC pauses.

**Risk:** Migrating to `tokio::sync::RwLock` changes the lock acquisition
methods from synchronous (`lock().unwrap()`) to asynchronous
(`.read().await` / `.write().await`). The current substrate methods acquire
`std::sync::RwLock`, perform synchronous work (no `.await` while holding the
guard), and drop the guard before returning. With `tokio::sync::RwLock`, the
guard lifetimes must still not span `.await` points to avoid holding the lock
longer than necessary. Since the substrate already follows a
lock-then-drop-before-await pattern, the migration is straightforward: replace
`RwLock::read().unwrap()` with `RwLock::read().await` and handle the `Result`
from lock poisoning differently (tokio's locks do not poison). Migration risk
is low.

**2. Batch deposit signing and verification**

Currently, each deposit is signed individually and verified on insert. For
events that produce multiple findings, signing could be batched (serialize all
payloads, sign once with a batch envelope). Verification could be deferred to
a background task rather than blocking the deposit write path.

**Impact:** Reduces per-event cryptographic cost by ~50% for multi-finding events.

**3. Incremental GC instead of full sweep**

Replace the full `retain()` sweep with an incremental eviction strategy:

- Maintain a sorted index by expiration time
- Each GC tick evicts only the next N expired deposits
- Bound GC hold time to a fixed duration (e.g., 1ms)

**Impact:** Eliminates GC pauses as a tail-latency contributor. Converts O(n)
per-tick GC to O(k) where k is the eviction batch size.

**4. Move all LocalJournal file I/O to `spawn_blocking`**

The `append_jsonl_line()` and `rewrite_jsonl()` functions perform synchronous
file I/O in async context. The scope is broader than deposit appends alone --
it includes threat-intel entry storage, escalation recording, threat-class
config persistence, and GC compaction (see Section 6.2 for full inventory).
Wrapping all `LocalJournalPheromoneSubstrate` I/O operations in
`tokio::task::spawn_blocking()` would prevent filesystem latency from blocking
tokio worker threads. For bulk feed ingestion, batch journal writes (N entries
per fsync) rather than one `append_jsonl_line` per entry.

**Impact:** Eliminates file I/O as a source of worker thread stalls. Critical
for feed ingestion paths where 10,000+ sequential appends would otherwise
block a tokio worker for ~500ms.

### 12.2 Architectural Changes

**5. Sharded substrate**

Partition the deposit vector by threat class (12 variants + Custom). Each shard
has its own `RwLock`. GC sweeps one shard at a time. Deposits and queries target
only the relevant shard.

**Impact:** Reduces lock contention by ~12x for deposits. GC pause applies to
only 1/12th of deposits per sweep.

**6. Lock-free deposit ring buffer**

Replace the `Vec<PheromoneDeposit>` with a fixed-size ring buffer using atomic
operations. New deposits overwrite the oldest when the buffer is full. This
eliminates GC entirely for the in-memory backend at the cost of a deposit count
ceiling.

**Impact:** Eliminates GC pauses entirely. Provides O(1) deposit and bounded
memory. Requires careful sizing to ensure sufficient retention window.

**7. Channel-per-bridge architecture**

Instead of a shared mpsc channel, give each bridge its own channel and
WhiskerAgent instance. This eliminates cross-bridge contention and allows
per-bridge backpressure tuning.

**Impact:** Better isolation and independent scaling. Increases agent count but
the dispatcher already supports up to 16 agents.

**8. Pipelined async processing**

Replace the sequential detect -> deposit -> policy -> response pipeline with
a staged pipeline using internal channels:

```
ingest -> [detection_queue] -> detect -> [deposit_queue] -> deposit
       -> [policy_queue] -> evaluate -> [response_queue] -> execute
```

This decouples stages and allows each to process at its natural rate, with
backpressure propagated via bounded channels between stages.

**Impact:** Higher throughput through stage parallelism. Adds complexity and
potential latency from cross-stage channel buffering.

**9. Pre-computed evaporation index**

Maintain a `BTreeMap<i64, Vec<usize>>` mapping evaporation timestamps to
deposit indices. GC queries the map for expired timestamps and removes only
those deposits, avoiding a full scan.

**Impact:** Converts GC from O(n) to O(k log n) where k is the number of
evaporated deposits per tick.

### 12.3 Optimization Priority Matrix

| Optimization | Effort | Impact | Risk | Priority |
|-------------|--------|--------|------|----------|
| **Wire up GC invocation** (currently never called) | Low | Critical | Low | **P0** |
| Remove redundant double signature verification | Low | Medium | Low | P0 |
| Incremental GC | Medium | High | Low | P0 |
| `spawn_blocking` for file I/O | Low | Medium | Low | P0 |
| Sharded substrate | Medium | High | Medium | P1 |
| tokio::sync::RwLock migration | Low | Medium | Low | P1 |
| Batch deposit signing | Medium | Medium | Low | P1 |
| Lock-free ring buffer | High | High | High | P2 |
| Channel-per-bridge | Medium | Medium | Low | P2 |
| Pipelined async stages | High | High | High | P3 |
| Pre-computed evaporation index | Medium | Medium | Medium | P2 |

---

## 13. Allocation Pattern Analysis

The detection hot path performs significant heap allocation that does not
appear in the lock-contention or cryptographic-cost analyses above. Under
high throughput, allocator pressure (fragmentation, system call overhead for
large allocations, contention on the global allocator) can become a
meaningful latency contributor.

### 13.1 Hot-Path Clone Inventory

The following clones occur in the critical path for every event that produces
at least one finding:

| Clone Site | File:Line | Estimated Cost | Notes |
|-----------|-----------|---------------|-------|
| `event.clone()` | `pipeline.rs:52` | 200-500 bytes | Clones the entire `TelemetryEvent` including all payload strings (source, host_identifier, event_id, plus payload-specific strings). A `ProcessStart` event with a long `command_line` can exceed 1KB. |
| `deposit.clone()` | `pipeline.rs:48` | 450-1100 bytes | Clones the full `PheromoneDeposit` before passing to `substrate.deposit()`. Includes the `indicator` JSON blob, signature `Vec<u8>`, and agent key `Vec<u8>`. |
| `finding.evidence.clone()` | `pipeline.rs:257` | 200-800 bytes | Clones the JSON evidence blob into the deposit's `indicator` field. |
| `entry.cloned()` | `substrate.rs:558` | 50-150 bytes | Clones a `ThreatIntelEntry` out of the read-locked `BTreeMap`. One clone per matching IOC. |

**Per-event allocation estimate (1 finding, 1 threat-intel match):**

- Minimum: ~900 bytes across 4 allocations
- Typical: ~2,000 bytes across 4-6 allocations
- Maximum (ProcessStart with long command line, multiple matches): ~5,000+ bytes

At 10K events/sec with 30% finding rate, this is ~6M bytes/sec of hot-path
allocations (3K finding-producing events x ~2KB each). The allocator must
handle ~12K-18K allocations/second from the hot path alone, plus background
allocations from logging, metrics, and channel operations.

### 13.2 Allocation Reduction Strategies

1. **`Arc<TelemetryEvent>` for zero-copy sharing.** The event is cloned into
   `DetectionPipelineOutcome` for the caller's use. If the caller accepts an
   `Arc<TelemetryEvent>` instead of an owned `TelemetryEvent`, the clone is
   replaced with an `Arc::clone` (pointer increment, ~1ns). This saves
   200-500 bytes of allocation per finding-producing event.

2. **Return `&ThreatIntelEntry` from substrate queries.** Currently
   `query_threat_intel_entry` returns `Option<ThreatIntelEntry>` (cloned from
   the `BTreeMap`). Returning a reference would eliminate the clone, but
   requires holding the read-lock for the duration of enrichment -- which
   conflicts with the goal of minimizing lock hold time. A middle ground:
   return `Arc<ThreatIntelEntry>` stored in the `BTreeMap`, paying the `Arc`
   overhead at insert time but eliminating clone-on-read.

3. **Pre-allocated finding buffer.** Instead of constructing a new
   `Vec<DetectionFinding>` per event, maintain a thread-local buffer that is
   cleared between events. This eliminates the `Vec` allocation overhead and
   reduces allocator contention under concurrent access.

4. **Evidence blob size cap.** The `annotate_threat_intel_evidence` function
   (pipeline.rs line 192) appends the full `threat_intel_matches` array to
   the evidence JSON. If an event matches 10+ IOCs (plausible with CIDR range
   expansion), each serialized as a full `ThreatIntelEntry`, the evidence
   blob can exceed 5KB. Cap the serialized matches at top-5 by confidence,
   summarize the remainder as `"additional_matches": N`.

### 13.3 Profiling Methodology

Allocation patterns should be measured before optimizing:

1. **`dhat` profiling:** Add `#[global_allocator] static ALLOC:
   dhat::Alloc = dhat::Alloc;` behind a `profiling` feature flag. Run the
   benchmark suite (Section 10.5) with `--features profiling` to collect
   per-allocation-site counts, bytes, and lifetimes.

2. **`jemalloc` statistics:** Switch to `tikv-jemallocator` and enable stats
   collection. Compare fragmentation ratios between `jemalloc` and the system
   allocator under the deposit growth/eviction pattern. `jemalloc` typically
   provides better fragmentation characteristics for the allocate-then-free-
   in-bulk pattern that GC produces.

3. **`perf` flame graphs:** Profile allocator time contribution to p99
   latency using `perf record` + `inferno`. Identify whether `malloc`/`free`
   appear in the hot path's flame graph.

---

## 14. Deployment Scenario Profiles

The performance characteristics and tuning parameters must adapt to
fundamentally different deployment targets. This section defines concrete
memory and CPU profiles for three scenarios.

### 14.1 Cloud Deployment (Generous Resources)

**Hardware:** 8-16 cores, 4-16GB RAM, SSD storage, low-latency network.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Substrate backend | JetStream (NATS) | Durability and multi-node sharing. Accepts the 1-5ms per-operation latency (Section 8.2) in exchange for crash recovery. |
| `max_active_deposits` | 1,000,000 | ~750MB deposit heap, well within 4GB+ budget |
| `threat_intel_max_entries` | 1,000,000 | ~200MB with current entry format (Section 5.7) |
| GC strategy | Incremental, 500 evictions/tick | GC CPU overhead is negligible relative to available cores |
| `telemetry_channel_capacity` | 50,000 | Larger buffer to absorb CloudTrail batch spikes |
| Worker threads | Pin to N-2 cores | Reserve 2 cores for GC, feed polling, and OS |
| Feed polling | Full portfolio (Tier 1-3) | Bandwidth and API rate limits are not a concern |

**Expected steady-state memory profile:**

| Component | Estimated Memory |
|-----------|-----------------|
| Deposit heap (500K active) | ~375 MB |
| Threat-intel cache (500K entries) | ~100 MB |
| Tokio runtime + task state | ~50 MB |
| Beacon tracker (100K keys) | ~20 MB |
| Journal files (if LocalJournal) | N/A (JetStream) |
| Channel buffers | ~50 MB |
| **Total** | **~600 MB** |

**Key concern:** JetStream KV latency (1-5ms per operation) means the
enrichment latency budget is consumed entirely by substrate I/O if threat-
intel queries go through JetStream. The L1 hot cache (Doc 03 Section 6.3)
is essential in cloud deployments to keep enrichment fast despite the slower
substrate backend.

### 14.2 Edge Deployment (Constrained Resources)

**Hardware:** Raspberry Pi 4, 4 ARM64 cores, 256MB available memory, SD card
or eMMC storage, potentially intermittent network.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Substrate backend | InMemory | No disk I/O overhead; crash recovery is acceptable to lose |
| `max_active_deposits` | 10,000 | ~7.5MB deposit heap |
| `threat_intel_max_entries` | 10,000 | ~2MB; IOC snapshots pushed from coordinator |
| GC strategy | Incremental, 100 evictions/tick | Minimize CPU overhead on 4 ARM cores |
| `telemetry_channel_capacity` | 1,000 | Smaller buffer to control memory |
| Worker threads | 2 | Reserve 2 cores for kernel and other processes |
| Feed polling | Disabled | IOCs pushed by central coordinator |
| Beacon tracker cap | 10,000 keys (LRU) | Hard memory ceiling |
| External enrichment | Disabled | No reliable network |

**Expected steady-state memory profile:**

| Component | Estimated Memory |
|-----------|-----------------|
| Deposit heap (5K active) | ~3.75 MB |
| Threat-intel cache (10K entries) | ~2 MB |
| Tokio runtime + task state | ~20 MB |
| Beacon tracker (10K keys) | ~2 MB |
| Channel buffers | ~5 MB |
| Binary + static data | ~30 MB |
| **Total** | **~65 MB** |

This leaves ~190MB headroom for spikes, OS overhead, and other processes.
The 256MB budget is achievable only with strict caps on all growable data
structures.

**Key concerns:**
- ARM64 Ed25519 performance is ~2-3x slower than x86_64. The per-deposit
  crypto cost rises from ~130-210us to ~260-630us. At 4K events/sec with
  30% finding rate, crypto alone consumes ~0.3-0.75 CPU seconds per second
  on one core. The double-verify fix (Section 12.1, item 0b) is critical
  for edge viability.
- SD card write latency (1-10ms per fsync) makes `LocalJournal` unsuitable.
  Use `InMemory` backend and accept data loss on crash.

### 14.3 Development Environment

**Hardware:** Developer laptop, 4-8 cores, 8-16GB RAM, SSD.

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Substrate backend | LocalJournal | Persistence across restarts for iterative development |
| `max_active_deposits` | 100,000 | Sufficient for realistic test scenarios |
| `threat_intel_max_entries` | 100,000 | Supports local feed testing |
| GC strategy | Incremental, 200 evictions/tick | Balance between responsiveness and background CPU |
| Feed polling | Tier 1 only (open-source feeds) | Developer network, avoid commercial API keys |

**Memory budget:** 512MB ceiling (Section 11.1). This is achievable with the
100K deposit and 100K threat-intel caps. Developers should be alerted if the
process exceeds 400MB, indicating a leak or misconfiguration.

---

## 15. Open Questions and Future Work

### 15.1 Open Questions

1. **What is the actual memory footprint of a `PheromoneDeposit` with realistic
   `indicator` JSON payloads?** The estimates in section 5 use conservative
   ranges. Profiling with `std::mem::size_of` and heap allocation tracking
   (via `dhat` or `jemalloc` stats) would provide precise numbers.

2. **Does the 10,000-element telemetry channel provide adequate buffering for
   realistic burst patterns?** CloudTrail batch ingestion may produce thousands
   of events in a single file read. The channel may need dynamic sizing or
   per-bridge queuing.

3. **What is the GC pause duration at 100K deposits on target hardware?** The
   theoretical O(n) analysis predicts problematic pauses, but actual timings
   depend on cache effects and branch prediction for the evaporation check.

4. **Should the JetStream backend use NATS KV or NATS Object Store for large
   deposit volumes?** The current key-per-deposit model may not scale beyond
   100K deposits due to key enumeration overhead.

5. **How does the ConfigurableApprovalGate's rate-limiting window interact with
   burst detection patterns?** The `agent_windows` mutex is acquired per-event;
   under high throughput, this may become a contention point that the current
   metrics do not capture.

6. **The double Ed25519 signature verification is confirmed redundant.**
   `ConfiguredPheromoneSubstrate::deposit()` verifies, then `InMemoryPheromoneSubstrate::deposit()`
   and `LocalJournalPheromoneSubstrate::deposit()` both verify again. This
   costs an extra ~50-80us per deposit. The fix is straightforward: remove
   `validate_deposit_signature()` from the inner backends (keeping it in
   the `ConfiguredPheromoneSubstrate` dispatch layer) or vice versa.

7. **How does the `arc_swap::ArcSwap` hot-reload mechanism affect cache
   coherency under load?** Config reloads replace the entire runtime stack
   atomically via `ArcSwap::store()`. During reload, concurrent reads may see
   either the old or new configuration. The performance impact of cache
   invalidation across cores during reload is unknown.

### 15.2 Future Work

1. **Wire up GC invocation** -- add `gc_evaporated()` and
   `gc_expired_threat_intel()` calls to the runtime (see section 12.1, item 0a).
   Without this, memory grows without bound under sustained load.

2. **Implement the benchmarking framework** described in section 10 and run
   baseline measurements against the current codebase.

3. **Add substrate lock instrumentation** -- wrap `RwLock` acquisitions with
   timing to capture lock wait time in the metrics pipeline.

4. **Prototype incremental GC** (optimization 3) and measure GC pause
   improvement at 100K+ deposits.

5. **Profile memory allocator behavior** -- evaluate whether `jemalloc` or
   `mimalloc` provides better fragmentation characteristics than the system
   allocator for the deposit growth/eviction pattern.

6. **Evaluate `dashmap`** as a concurrent hash map alternative to
   `RwLock<BTreeMap>` for threat intel entries and threat class configs.

7. **Design and implement a load testing harness** that can be run as part of
   CI to detect performance regressions. This should include threshold-based
   gates that fail the build if p99 latency exceeds configured limits.

8. **Investigate SIMD-accelerated JSON parsing** (`simd-json`) for telemetry
   deserialization in high-throughput bridge paths.

9. **Evaluate `io_uring` for journal writes** on Linux targets to reduce the
   syscall overhead of the LocalJournal backend.

---

## 16. Cross-References

| Document | Relevance |
|----------|-----------|
| [03 -- Threat Intelligence Lifecycle and Enrichment](../swarm-hardening/03-THREAT-INTELLIGENCE-LIFECYCLE-AND-ENRICHMENT.md) | Threat intel enrichment adds per-event substrate queries; enrichment latency directly impacts the detection pipeline timing in section 4. Feed refresh frequency affects the threat intel entry count and memory pressure in section 5. |
| [06 -- Behavioral Baseline and Anomaly Detection](../swarm-hardening/06-BEHAVIORAL-BASELINE-AND-ANOMALY-DETECTION.md) | Baseline computation requires periodic full-substrate scans. The overhead of these scans is analogous to GC pauses analyzed in section 5.3. Baseline models add per-event comparison cost to the detection stage in section 3.1. |
| [06 -- Stigmergic Coordination (Sentinel Convergence)](../sentinel-convergence/06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | The pheromone evaporation model analyzed in section 5.2 is formalized in this document. Decay rate and evaporation threshold parameters directly determine steady-state deposit counts. |
| [03 -- Edge-Native Security Detection (Sentinel Convergence)](../sentinel-convergence/03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge deployment targets (section 11.2) inherit the resource constraints analyzed in this document: 256MB memory ceiling, 4-core ARM64 CPU. Performance characterization here informs the tiered architecture proposed there. |
| [05 -- Telemetry Bridge Architecture (Sentinel Convergence)](../sentinel-convergence/05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Multi-bridge concurrent ingestion (section 9) directly extends the bridge architecture. Channel contention under multi-bridge load is a primary concern for bridge scaling. |
| [08 -- Resilience Patterns (Sentinel Convergence)](../sentinel-convergence/08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Circuit breaker and retry behavior in the response adapter (section 3.4) follows resilience patterns documented here. Backpressure under adapter failure cascades through the critical path. |

---

## 17. References

1. Tokio project. "Tokio: An Asynchronous Rust Runtime." 2024.
   https://tokio.rs/

2. The Rust async working group. "Asynchronous Programming in Rust." The Rust
   Foundation, 2024. https://rust-lang.github.io/async-book/

3. Josefsson, S., and I. Liusvaara. "Edwards-Curve Digital Signature Algorithm
   (EdDSA)." RFC 8032, IETF, January 2017.
   https://datatracker.ietf.org/doc/html/rfc8032

4. NATS Authors. "NATS JetStream." Synadia Communications, 2024.
   https://docs.nats.io/nats-concepts/jetstream

5. Bayer, D. "Criterion.rs: Statistics-Driven Benchmarking Library for Rust."
   2024. https://github.com/bheisler/criterion.rs

6. Bryan, M. "dhat-rs: DHAT-like Heap Profiling for Rust." 2024.
   https://github.com/nnethercote/dhat-rs

7. CrowdStrike. "Falcon Sensor for Linux Resource Usage." CrowdStrike
   Documentation, 2024.

8. Elastic. "Elastic Agent System Requirements." Elastic Documentation, 2024.
   https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html

9. Klabnik, S., and C. Nichols. "The Rust Programming Language: Fearless
   Concurrency." No Starch Press, 2023.

10. Stjepang. "Crossbeam: Tools for Concurrent Programming." 2024.
    https://github.com/crossbeam-rs/crossbeam

11. Dorigo, M. "Ant Colony Optimization." Scholarpedia 2, no. 3 (2007): 1461.
    Referenced for evaporation model analysis.

12. Prometheus authors. "prometheus-client: Prometheus Client Library for Rust."
    2024. https://github.com/prometheus/client_rust

13. Sean McArthur. "reqwest: An Easy and Powerful Rust HTTP Client." 2024.
    https://github.com/seanmonstar/reqwest

14. Levy, A. "arc-swap: Atomically Swappable Arc." 2024.
    https://github.com/vorner/arc-swap

15. Evans, J. "jemalloc: A General-Purpose Scalable Concurrent Allocator."
    2024. https://jemalloc.net/
