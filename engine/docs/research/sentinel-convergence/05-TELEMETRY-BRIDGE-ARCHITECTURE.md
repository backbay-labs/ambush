---
title: "05 -- Telemetry Bridge Architecture: Sentinel Convergence"
series: Sentinel Convergence (5 of 8)
version: "0.2"
date: 2026-04-07
status: Draft
authors: Swarm Team Six / AQ Stack
---

# 05 -- Telemetry Bridge Architecture: Sentinel Convergence

> Designing `swarm-ingest-sentinel` -- the bridge crate that fuses Sentinel
> infrastructure health telemetry into the Swarm Team Six detection pipeline.

> **Series Note**
> - This is the canonical proposed schema document for Sentinel-derived
>   infrastructure telemetry in the series.
> - The current repo does **not** yet expose these infrastructure payloads in
>   `swarm-core`; the additions here are proposed interfaces.
> - Any rollout of these variants requires coordinated consumer updates. See
>   [00-OVERVIEW.md](00-OVERVIEW.md) for current series posture.

---

## Table of Contents

1. [Survey of Telemetry Collection Approaches](#1-survey-of-telemetry-collection-approaches)
2. [Deep Analysis: Sentinel Collector](#2-deep-analysis-sentinel-collector)
3. [Deep Analysis: Swarm Team Six Ingest Bridges](#3-deep-analysis-swarm-team-six-ingest-bridges)
4. [Designing `swarm-ingest-sentinel`](#4-designing-swarm-ingest-sentinel)
5. [Multi-Source Telemetry Correlation](#5-multi-source-telemetry-correlation)
6. [Backpressure and Flow Control](#6-backpressure-and-flow-control)
7. [Schema Evolution and Versioning](#7-schema-evolution-and-versioning)
8. [Performance Benchmarks](#8-performance-benchmarks)
9. [Reference Implementation](#9-reference-implementation)
10. [Appendix: Data Flow Diagrams](#10-appendix-data-flow-diagrams)
11. [Cross-References](#cross-references)

---

## 1. Survey of Telemetry Collection Approaches

Infrastructure telemetry ranges from kernel-level tracing to cloud API audit logs. This section surveys the dominant paradigms and positions Sentinel relative to each.

### 1.1 eBPF-Based Collection (Tetragon, Falco)

eBPF programs attach to kernel hooks (kprobes, tracepoints, LSM hooks) and stream events to userspace with near-zero overhead per event.

| Property | Tetragon (Cilium) | Falco (Sysdig) |
|---|---|---|
| **Kernel attachment** | BTF-aware kprobes, tracepoints, LSM hooks | Syscall enter/exit via libsinsp driver or eBPF |
| **Event granularity** | Process lifecycle, file access, network connect, kprobe args | Syscall-level with rule filtering |
| **Output format** | gRPC streaming (protobuf `GetEventsResponse`) | gRPC streaming or stdout JSON |
| **Filtering** | Server-side `allow_list`/`deny_list` by `EventType` | Falco rules (YAML-based DSL with condition expressions) |
| **Overhead** | < 1% CPU per 100k events/sec | 2-5% CPU depending on rule complexity |
| **Deployment** | DaemonSet (Kubernetes) or standalone daemon | DaemonSet or sidecar |

**Strengths**: Sub-millisecond visibility into kernel operations. No polling -- events are push-based. Captures causality chains (parent-child process trees, socket-to-process binding).

**Weaknesses**: Requires privileged access (CAP_BPF, CAP_SYS_ADMIN). Kernel version sensitivity (BTF requirements). Cannot observe hardware-level degradation (thermal throttling, DIMM errors, disk latency trends).

### 1.2 /proc + /sys Polling (Sentinel)

Direct filesystem reads from the Linux virtual filesystems `/proc` and `/sys` to gather point-in-time snapshots of system state.

| Property | Value |
|---|---|
| **Collection method** | `open()` + `read()` on pseudo-files |
| **Typical interval** | 1-15 seconds |
| **Privilege required** | Read access to `/proc`, `/sys` (often root for thermal zones) |
| **Event model** | Pull/poll -- snapshot deltas computed in userspace |
| **CPU overhead** | < 0.1% at 1Hz on modern hardware |
| **Metrics breadth** | CPU, memory, disk I/O, network I/O, thermal zones, OOM counters |

**Strengths**: Universally available on Linux. No kernel module or eBPF bytecode loading. Extremely lightweight -- file reads are serviced by the kernel's procfs/sysfs handlers directly from kernel data structures. Captures hardware health signals (thermal zones, CPU throttle counts, frequency scaling) that eBPF typically does not surface.

**Weaknesses**: Polling introduces latency proportional to the collection interval. Cannot observe individual syscalls or process lifecycle events. Delta computations require stateful tracking across collection cycles.

### 1.3 Agent-Based Collection (osquery, node-exporter)

SQL-queryable agent that exposes OS state through a virtual table abstraction.

| Property | osquery | node-exporter |
|---|---|---|
| **Query model** | SQL over virtual tables (`processes`, `file`, `interface_details`) | Prometheus scrape endpoint |
| **Transport** | JSON over TLS to fleet manager, or local socket | HTTP `/metrics` (Prometheus exposition format) |
| **Configuration** | Scheduled queries + differential logging | Command-line flags + collector toggles |
| **Overhead** | 50-200 MB RSS, 1-5% CPU with aggressive query schedules | 10-30 MB RSS, < 0.5% CPU |

**Strengths**: Declarative query interface enables ad-hoc investigation. Rich schema covering processes, users, packages, file integrity. node-exporter is the de facto standard for Prometheus-based monitoring.

**Weaknesses**: osquery's differential logger is optimized for compliance/audit, not real-time detection. node-exporter lacks process-level attribution -- it reports system-wide counters only.

### 1.4 Sidecar Proxies (Envoy, Linkerd)

Service mesh sidecars intercept all network traffic to/from a pod and emit structured telemetry.

| Property | Value |
|---|---|
| **Visibility** | L4/L7 network flows, request latency, error rates, mTLS metadata |
| **Event model** | Request-scoped spans and access logs |
| **Overhead** | 2-10ms p99 latency added per hop; 50-100 MB RSS per sidecar |
| **Blind spots** | No host-level metrics, no process execution, no disk/thermal data |

**Strengths**: Deep application-layer visibility with distributed tracing context. Automatic mTLS gives cryptographic identity to every request.

**Weaknesses**: Significant resource overhead when deployed fleet-wide. Invisible to non-network threats (malware execution, thermal runaway, memory exhaustion).

### 1.5 Positioning Summary

Sentinel occupies a distinct niche: lightweight `/proc`+`/sys` polling (like node-exporter) combined with predictive failure analysis (Welford's algorithm, trend regression) and Raft-lite consensus for partition-tolerant edge clusters. eBPF tools see kernel events but miss hardware degradation; cloud audit logs see API calls but miss host health. Sentinel fills the infrastructure health gap that neither addresses. This gap is precisely what the proposed `swarm-ingest-sentinel` bridge exploits -- see [Doc 02](./02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) and [Doc 03](./03-EDGE-NATIVE-SECURITY-DETECTION.md) for the threat-signal and edge-native angles.

---

## 2. Deep Analysis: Sentinel Collector

### 2.1 Architecture Overview

The Sentinel collector (`pkg/collector/collector.go`) is a concurrent metrics gatherer that reads Linux virtual filesystems to produce a `NodeMetrics` snapshot on each collection cycle. The design prioritizes:

1. **Minimal allocation** -- single `NodeMetrics` struct per cycle, short-lived goroutines
2. **Concurrent subsystem collection** -- five goroutines fan out simultaneously
3. **Delta computation** -- CPU, disk I/O, and network counters are differenced against the previous sample
4. **Graceful degradation** -- partial failures are collected as `Errors` without aborting the snapshot

### 2.2 The `NodeMetrics` Contract

The `NodeMetrics` struct (`collector.go` lines 18-57) is the canonical data transfer object with 26 metric fields across five subsystems:

| Subsystem | Fields | Key Metrics |
|---|---|---|
| **CPU** (7) | Temperature, UsagePercent, Throttled, FrequencyMHz, LoadAvg 1/5/15m | Thermal + utilization |
| **Memory** (6) | TotalBytes, AvailableBytes, UsagePercent, SwapTotal, SwapUsed, OOMKillCount | Pressure + OOM |
| **Disk** (6) | TotalBytes, UsedBytes, UsagePercent, IOReadBytes, IOWriteBytes, IOLatencyMs | Capacity + I/O perf |
| **Network** (5) | RxBytes, TxBytes, RxErrors, TxErrors, LatencyMs | Throughput + errors |
| **Metadata** (2) | CollectionDurationMs, Errors | Self-monitoring |

### 2.3 Concurrent Collection Design

The `Collect()` method spawns five goroutines behind a `sync.WaitGroup`:

```
Collect(ctx) ──┬── go collectCPUMetrics()      reads /proc/stat, /proc/loadavg,
               │                                /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq,
               │                                /sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count
               │
               ├── go collectMemoryMetrics()    reads /proc/meminfo, /proc/vmstat
               │
               ├── go collectDiskMetrics()      reads /proc/diskstats
               │
               ├── go collectNetworkMetrics()   reads /proc/net/dev
               │
               └── go collectThermalMetrics()   reads /sys/class/thermal/thermal_zone*/temp
```

Error aggregation uses a mutex-protected append to `m.Errors`. This design means a thermal zone read failure does not prevent CPU or memory metrics from being collected -- the snapshot is always as complete as possible.

### 2.4 Delta Computation Strategy

Three subsystems require delta computation: CPU usage, disk I/O, and network throughput. The collector maintains previous-sample state under a `sync.Mutex`:

```go
type Collector struct {
    mu            sync.Mutex
    prevCPUStats  cpuStats   // user, nice, system, idle, iowait, irq, softirq
    prevDiskStats diskStats  // readBytes, writeBytes, readTime, writeTime, ioTime
    prevNetStats  netStats   // rxBytes, txBytes, rxErrors, txErrors
    lastCollect   time.Time
}
```

**CPU usage** is computed as: `100 * (1 - idle_delta / total_delta)` across all CPU jiffies. The first sample after startup yields 0% because there is no previous state.

**Disk I/O latency** is computed as: `(ioTime_delta / elapsed_ms) * 100`, where `ioTime` is the cumulative time the device spent doing I/O (field 12 of `/proc/diskstats`). Despite the field name `DiskIOLatencyMs`, this formula yields a utilization percentage (0-100), not per-request latency. The Sentinel bridge mapper should treat this value as I/O utilization, not milliseconds.

**Network throughput** reports raw byte deltas. Error deltas are also computed for detecting link-level problems.

### 2.5 Auto-Detection

The collector auto-detects:

- **Primary disk**: Reads `/proc/mounts`, finds the device mounted at `/`, strips partition numbers (handles both `sdaX` and `nvme0n1pX` formats)
- **Primary network interface**: Reads `/proc/net/route`, finds the interface carrying the default route (`destination == 00000000`)
- **Thermal zones**: Enumerates `/sys/class/thermal/thermal_zone*` and filters to those with a readable `temp` file

### 2.6 Performance Characteristics

| Metric | Value |
|---|---|
| **Collection cycle** | 5 concurrent goroutines, 1 `WaitGroup.Wait()` |
| **File operations per cycle** | 6-10 `open()`+`read()` calls (depends on thermal zones) |
| **Memory per cycle** | ~2 KB (one `NodeMetrics` + scanner buffers) |
| **Typical duration** | < 1ms on modern hardware (reported via `CollectionDurationMs`) |
| **Steady-state goroutines** | 5 per collection cycle, all short-lived |
| **Lock contention** | One `sync.Mutex` for delta state; held briefly per subsystem |

### 2.7 Prometheus Exposition

The `metrics.Exporter` (`pkg/metrics/exporter.go`) maps `NodeMetrics` fields to 35+ Prometheus metric families under the `sentinel_` namespace. The exporter also surfaces novel metrics not present in `NodeMetrics`:

- **Partition/consensus metrics** (see [Doc 01](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md)): `sentinel_partition_detected`, `sentinel_partition_duration_seconds`, `sentinel_consensus_is_leader`, `sentinel_consensus_term`
- **Prediction metrics**: `sentinel_prediction_failure_probability`, `sentinel_prediction_confidence`, `sentinel_prediction_time_to_failure_seconds`
- **Rate limiting metrics**: `sentinel_consensus_rate_limit_dropped_total`, `sentinel_consensus_rate_limit_enabled`

The exporter exposes a standard Prometheus HTTP endpoint at `:9100/metrics` (configurable). This becomes the primary scrape target for the Sentinel bridge.

### 2.8 Health Score Predictor

The `healthscore.Predictor` (`pkg/healthscore/predictor.go`) is a lightweight statistical model for edge deployment. Key design decisions:

- **Welford's online algorithm** for incremental mean/std computation -- O(1) per sample, no batch recomputation
- **Configurable risk weights**: Thermal (0.30), Memory (0.20), CPU (0.15), Disk (0.10), Network (0.10), Trend (0.15)
- **Graceful degradation**: If some metrics are unavailable, remaining weights are renormalized and confidence is reduced proportionally
- **Trend detection**: Linear regression over the last 30 samples to detect thermal drift and memory leak patterns
- **Time-to-failure estimation**: Extrapolates thermal trend slope to predict when 85C critical threshold will be reached
- **100ms prediction timeout**: Context-deadline enforced to prevent prediction from blocking collection

The predictor outputs a `Prediction` struct:

```go
type Prediction struct {
    Timestamp          time.Time `json:"timestamp"`
    NodeName           string    `json:"node_name"`
    FailureProbability float64   `json:"failure_probability"` // 0.0 to 1.0
    Confidence         float64   `json:"confidence"`          // 0.0 to 1.0
    TimeToFailure      float64   `json:"time_to_failure_seconds"` // -1 if no failure
    Reasons            []string  `json:"reasons"`
    Recommendation     string    `json:"recommendation"`
}
```

This prediction data is critical for the swarm -- it provides forward-looking threat intelligence about infrastructure reliability that no eBPF sensor or cloud audit log can deliver. [Doc 02](./02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) explores how these predictions translate into actionable threat signals within the swarm pipeline.

---

## 3. Deep Analysis: Swarm Team Six Ingest Bridges

### 3.1 The TelemetryBridge Trait

The canonical bridge contract lives in `swarm-core/src/telemetry.rs`:

```rust
// From swarm-core/src/telemetry.rs
/// Common contract for bridge adapters that normalize external telemetry into shared events.
#[async_trait]
pub trait TelemetryBridge: Send {
    fn source_id(&self) -> &str;
    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>>;
    fn validate_schema(&self, event: &TelemetryEvent) -> bool;
    fn health(&self) -> BridgeHealth;
}
```

The trait is deliberately minimal: `source_id` returns a stable identifier (e.g. `"tetragon"`); `poll` blocks or sleeps until the next batch is ready and returns `Vec<TelemetryEvent>`; `validate_schema` checks bridge-specific invariants on each event before it enters the pipeline; `health` returns a snapshot of the bridge's operational state.

Four design principles govern the trait:

1. **Single trait, multiple backends**: Every bridge implements the same four methods regardless of underlying transport.
2. **Pull-based polling**: The runtime calls `poll()` in a loop. Streaming bridges (Tetragon) block until the next event; finite-source bridges (JSON files) return empty `Vec` when exhausted.
3. **Bridge-owned validation**: Each bridge validates its own output via `validate_schema()` before events enter the pipeline -- defense in depth against mapper bugs.
4. **Mandatory health tracking**: Every bridge maintains a `BridgeHealth` struct tracking `events_processed`, `error_count`, `lag_seconds`, and `last_error`.

### 3.2 The TelemetryEvent and TelemetryPayload Contract

```rust
// From swarm-core/src/telemetry.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEvent {
    pub source: String,       // e.g., "tetragon", "cloudtrail", "sentinel"
    pub event_id: String,     // globally unique event identifier
    pub timestamp: i64,       // unix seconds
    pub host_id: Option<String>,
    pub payload: TelemetryPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPayload {
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistryAccess(RegistryAccessEvent),
    RegistryPersistence(RegistryPersistenceEvent),
    FilePersistence(FilePersistenceEvent),
    AuthenticationEvent(AuthenticationEventData),
}
```

The `TelemetryPayload` enum uses serde's internally tagged representation (`#[serde(tag = "kind")]`), so serialized events include a `"kind": "process_start"` discriminator. This matters for forward compatibility, but the current enum does **not** yet have an `Unknown` fallback: today an unrecognized `kind` fails deserialization. [Doc 10](./10-ADR-TELEMETRY-SCHEMA-ROLLOUT.md) proposes adding a serde-backed `Unknown` variant so older consumers can log-and-skip new payload kinds instead of erroring.

**Critical observation**: All seven current payload variants are security-event oriented (process execution, network connections, authentication, registry access). There are no variants for infrastructure health, thermal anomalies, or resource exhaustion. The Sentinel bridge requires new variants -- see [Section 4.2](#42-new-telemetrypayload-variants).

### 3.3 BridgeHealth Contract

```rust
// From swarm-core/src/telemetry.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeHealth {
    pub source_id: String,
    pub ready: bool,
    pub events_processed: u64,
    pub error_count: u64,
    pub lag_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}
```

The `lag_seconds` field is computed inside `BridgeHealth::record_event()` as `current_unix_seconds() - event_timestamp`, clamped to non-negative. This measures how far behind the bridge is from real-time. For a Sentinel bridge scraping at 5-second intervals (the proposed default), this should hover near 5.0s under normal conditions and increase if scrapes are delayed by backpressure.

### 3.4 Tetragon Bridge Deep-Dive

The Tetragon bridge (`swarm-ingest-tetragon/src/bridge.rs`) is the reference streaming bridge implementation:

**Connection management**: The bridge maintains an optional `tonic::Streaming<GetEventsResponse>` handle. On connection failure, it implements exponential backoff with a configurable cap:

```rust
// From swarm-ingest-tetragon/src/bridge.rs
fn reconnect_backoff(&self, attempts: u32) -> Duration {
    let shift = attempts.min(20);
    let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    let max_backoff = self.config.max_reconnect_backoff_ms
        .max(self.config.reconnect_backoff_ms);
    let delay_ms = self.config.reconnect_backoff_ms
        .saturating_mul(multiplier)
        .min(max_backoff);
    Duration::from_millis(delay_ms)
}
```

Default configuration: 1s initial backoff, 30s max backoff, 30s event timeout.

**Event mapping**: The `mapper.rs` module converts protobuf `ProcessExec` messages into normalized `TelemetryEvent` structs. Event IDs are constructed as `tetragon:{node_name}:{exec_id}` for global uniqueness.

**Schema validation**: For `ProcessStart`, validates non-empty `process_name` and `command_line` but does not require `parent_process` (kernel-spawned processes may lack a parent). This differs from the JSON bridges' shared `validate_event_schema()`, which requires non-empty `parent_process`. The Tetragon bridge also validates all other payload variants even though it currently only produces `ProcessStart` -- forward-proofing for future Tetragon event types.

**Error handling**: All errors flow through `TelemetryBridgeError` variants:
- `Connection` -- gRPC connectivity failures
- `Mapping` -- protobuf-to-TelemetryEvent conversion failures
- `Schema` -- post-mapping schema validation failures
- `Unavailable` -- bridge not ready

### 3.5 CloudTrail Bridge Deep-Dive

The CloudTrail bridge (`cloudtrail.rs`) normalizes AWS CloudTrail JSON records into two payload types: authentication events (ConsoleLogin, AssumeRole) map to `AuthenticationEvent`; API calls (S3 GetObject, etc.) map to `NetworkConnect` with `protocol: "aws_api"`. Records come from a `JsonRecordSource` supporting JSON objects, arrays, and JSON Lines. The mapper extracts `eventID`, `eventName`, `eventSource`, `eventTime` (RFC 3339), and resolves user identity from nested `userIdentity` with multiple fallback paths.

### 3.6 Generic JSON Bridge Deep-Dive

The Generic JSON bridge (`generic_json.rs`) accepts config-driven JSON Pointer mappings (`FieldMappingConfig`) to normalize arbitrary JSON. The `GenericJsonPayloadMappingConfig` enum supports all seven `TelemetryPayload` variants with configurable pointer paths for every field. Validation at construction time rejects invalid pointers (must start with `/`).

### 3.7 Bridge Runtime

The `BridgeRuntimeRegistry` (`swarm-runtime/src/bridge_runtime.rs`) is the orchestration layer that:

1. Reads `TelemetrySourceConfig` entries from the config file
2. Constructs the appropriate `Box<dyn TelemetryBridge>` for each
3. Spawns one Tokio task per bridge, each running a poll loop
4. Routes all events through a shared `mpsc::Sender<TelemetryEvent>` channel
5. Publishes `BridgeStatusSnapshot` updates to a `SharedBridgeHealth` (Arc-Mutex-Vec)
6. Supports graceful shutdown via `watch::Receiver<bool>`

The build function dispatches on `TelemetryBridgeConfig`. Each arm constructs the appropriate `Box<dyn TelemetryBridge>`:

```rust
// From swarm-runtime/src/bridge_runtime.rs
fn build_bridge(
    name: &str,
    config: &TelemetryBridgeConfig,
) -> Result<BoxedTelemetryBridge, BridgeRuntimeError> {
    match config {
        TelemetryBridgeConfig::Tetragon { config } => Ok(Box::new(TetragonBridge::new(...))),
        TelemetryBridgeConfig::CloudTrail { config } => Ok(Box::new(CloudTrailBridge::from_config(config)?)),
        TelemetryBridgeConfig::GenericJson { config } => Ok(Box::new(GenericJsonBridge::from_config(config)?)),
    }
}
```

The Sentinel bridge will add a fourth arm to this match (see [Section 9.4](#94-integration-with-bridgeruntimeregistry)).

---

## 4. Designing `swarm-ingest-sentinel`

### 4.1 Protocol Options

Sentinel exposes metrics via a Prometheus HTTP endpoint. We have four protocol options for the bridge:

#### Option A: Prometheus Scraping (HTTP Pull)

```
Sentinel (:9100/metrics) ──HTTP GET──> swarm-ingest-sentinel ──TelemetryEvent──> mpsc channel
```

| Property | Value |
|---|---|
| **Complexity** | Low -- HTTP client + Prometheus text parser |
| **Latency** | Scrape interval (1-15s) |
| **Dependencies** | `reqwest` + custom parser or `prometheus-parse` crate |
| **Failure mode** | Scrape timeout, HTTP errors |
| **Backpressure** | Natural -- scrape interval acts as rate limiter |
| **Deployment** | Sentinel runs independently; bridge connects over network |

**Assessment**: This is the recommended approach. It aligns with Sentinel's existing architecture, requires no changes to Sentinel itself, and provides natural backpressure through the scrape interval.

#### Option B: gRPC Streaming (Push)

```
Sentinel ──gRPC stream──> swarm-ingest-sentinel ──TelemetryEvent──> mpsc channel
```

| Property | Value |
|---|---|
| **Complexity** | Medium -- requires protobuf schema, gRPC server in Sentinel |
| **Latency** | Sub-second (push on collection) |
| **Dependencies** | `tonic`, protobuf definitions, Sentinel code changes |
| **Failure mode** | Stream disconnect, reconnection logic |
| **Backpressure** | gRPC flow control (HTTP/2 window) |
| **Deployment** | Requires modifying Sentinel to add gRPC server |

**Assessment**: Lower latency but requires invasive changes to Sentinel. Worth considering for a future iteration if sub-second infrastructure alerting becomes critical.

#### Option C: Unix Domain Socket -- Medium complexity, < 1ms latency, same-host only, requires Sentinel modification.

#### Option D: Shared Memory Ring Buffer -- High complexity, nanosecond latency, same-host only. Only justified at 10+ kHz sample rates. Overkill for 1Hz node-level polling.

#### Protocol Decision

**Recommendation**: Option A (Prometheus Scraping) for v1. Zero changes to Sentinel, aligns with pull-based `TelemetryBridge::poll()` contract, natural backpressure via scrape interval. Option B (gRPC) can be added later as a second transport behind the same bridge trait for sub-second alerting.

### 4.2 New TelemetryPayload Variants

The current `TelemetryPayload` enum lacks infrastructure health concepts. We propose three new variants.

**Series decision:** these are the canonical proposed wire-level variants for
Sentinel-derived infrastructure telemetry across this research set. Other
documents in the series should be read as depending on this shape rather than
defining competing payloads.

```rust
/// Proposed additions to swarm-core/src/telemetry.rs

/// Infrastructure health snapshot from a node monitoring agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureHealthEvent {
    /// Node identifier (hostname or Kubernetes node name).
    pub node_name: String,
    /// CPU usage percentage (0-100).
    pub cpu_usage_percent: f64,
    /// CPU frequency in MHz (0 if unavailable).
    pub cpu_frequency_mhz: f64,
    /// System load average (1-minute).
    pub load_average_1m: f64,
    /// System load average (5-minute).
    pub load_average_5m: f64,
    /// System load average (15-minute).
    pub load_average_15m: f64,
    /// Memory usage percentage (0-100).
    pub memory_usage_percent: f64,
    /// Available memory in bytes.
    pub memory_available_bytes: u64,
    /// Disk usage percentage (0-100).
    pub disk_usage_percent: f64,
    /// Disk I/O latency in milliseconds.
    pub disk_io_latency_ms: f64,
    /// Network receive bytes (delta since last sample).
    pub network_rx_bytes: u64,
    /// Network transmit bytes (delta since last sample).
    pub network_tx_bytes: u64,
    /// Network receive errors (delta since last sample).
    pub network_rx_errors: u64,
    /// Network transmit errors (delta since last sample).
    pub network_tx_errors: u64,
    /// Overall health score (0.0 = healthy, 1.0 = critical).
    pub failure_probability: f64,
    /// Confidence in the failure prediction (0.0 to 1.0).
    pub prediction_confidence: f64,
    /// Predicted seconds until failure (-1 if no failure predicted).
    pub time_to_failure_secs: f64,
    /// Collection duration in milliseconds (self-monitoring).
    pub collection_duration_ms: f64,
}

/// Thermal anomaly detected on a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalAnomalyEvent {
    /// Node identifier.
    pub node_name: String,
    /// Current CPU temperature in Celsius.
    pub temperature_celsius: f64,
    /// Whether the CPU is currently throttled.
    pub cpu_throttled: bool,
    /// Temperature trend slope (degrees per sample period).
    pub trend_slope: f64,
    /// Severity classification.
    pub severity: ThermalSeverity,
    /// Estimated seconds until critical threshold (85C).
    pub estimated_time_to_critical_secs: f64,
}

/// Thermal severity levels aligned with Sentinel's predictor thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalSeverity {
    /// < 60C: Normal operating range.
    Normal,
    /// 60-75C: Elevated, monitor closely.
    Elevated,
    /// 75-85C: High risk, throttling likely.
    High,
    /// > 85C: Critical, throttling active, failure imminent.
    Critical,
}

/// Resource exhaustion event from a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceExhaustionEvent {
    /// Node identifier.
    pub node_name: String,
    /// Which resource is exhausted.
    pub resource_kind: ExhaustedResource,
    /// Current utilization percentage.
    pub utilization_percent: f64,
    /// Absolute value of the exhausted resource.
    pub current_value: u64,
    /// Maximum/total capacity of the resource.
    pub capacity_value: u64,
    /// OOM kill count (only relevant for memory exhaustion).
    pub oom_kill_count: Option<u64>,
    /// Swap usage bytes (only relevant for memory exhaustion).
    pub swap_used_bytes: Option<u64>,
    /// Whether this is a new condition or ongoing.
    pub is_new: bool,
}

/// Classification of exhausted resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustedResource {
    Memory,
    Disk,
    Cpu,
    Swap,
    NetworkBandwidth,
}
```

The extended `TelemetryPayload` enum becomes:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPayload {
    // Existing variants (unchanged)
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistryAccess(RegistryAccessEvent),
    RegistryPersistence(RegistryPersistenceEvent),
    FilePersistence(FilePersistenceEvent),
    AuthenticationEvent(AuthenticationEventData),

    // New infrastructure variants
    InfrastructureHealth(InfrastructureHealthEvent),
    ThermalAnomaly(ThermalAnomalyEvent),
    ResourceExhaustion(ResourceExhaustionEvent),
}
```

### 4.3 Event Mapping: Sentinel Metrics to TelemetryPayload

Each Sentinel scrape cycle produces one to four `TelemetryEvent` instances:

| Condition | Payload Variant | Frequency |
|---|---|---|
| Every scrape | `InfrastructureHealth` | Every cycle |
| CPU temp > threshold OR throttled | `ThermalAnomaly` | Conditional |
| Memory usage > threshold | `ResourceExhaustion` (memory) | Conditional |
| Disk usage > threshold | `ResourceExhaustion` (disk) | Conditional |

The mapping logic:

```
Sentinel Prometheus Metrics
         │
         ├── sentinel_cpu_usage_percent ─────────────┐
         ├── sentinel_cpu_temperature_celsius ────────┤
         ├── sentinel_cpu_throttled ──────────────────┤
         ├── sentinel_cpu_frequency_mhz ─────────────┤
         ├── sentinel_cpu_load_average{period="1m"} ──┤
         ├── sentinel_memory_usage_percent ───────────┤   ┌──────────────────────┐
         ├── sentinel_memory_available_bytes ─────────┼──>│ InfrastructureHealth │ (every cycle)
         ├── sentinel_disk_usage_percent ─────────────┤   └──────────────────────┘
         ├── sentinel_disk_io_latency_ms ────────────┤
         ├── sentinel_network_rx_bytes_total ─────────┤
         ├── sentinel_network_tx_bytes_total ─────────┤
         ├── sentinel_prediction_failure_probability ──┤
         ├── sentinel_prediction_confidence ──────────┤
         └── sentinel_prediction_time_to_failure_seconds ┘
                                                      │
         ├── sentinel_cpu_temperature_celsius ────────┤
         ├── sentinel_cpu_throttled ──────────────────┤   ┌──────────────────┐
         │   (if temp > 60 || throttled)              ├──>│ ThermalAnomaly   │ (conditional)
         │                                            │   └──────────────────┘
         │                                            │
         ├── sentinel_memory_usage_percent ───────────┤
         ├── sentinel_disk_usage_percent ─────────────┤   ┌────────────────────────┐
         ├── sentinel_memory_oom_kill_total ───────────┼──>│ ResourceExhaustion     │ (conditional)
         └── sentinel_memory_swap_used_bytes ─────────┘   └────────────────────────┘
```

### 4.4 Event ID Construction

Following the Tetragon convention of `{source}:{host}:{unique_id}`:

```
sentinel:{node_name}:health:{unix_timestamp}
sentinel:{node_name}:thermal:{unix_timestamp}
sentinel:{node_name}:exhaustion:{resource_kind}:{unix_timestamp}
```

### 4.5 Scraper Configuration

```rust
/// Configuration for the Sentinel Prometheus scrape bridge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelBridgeConfig {
    /// Sentinel Prometheus endpoint URL (e.g., "http://sentinel:9100/metrics").
    pub endpoint: String,
    /// Scrape interval in milliseconds (default: 5000).
    #[serde(default = "default_sentinel_scrape_interval_ms")]
    pub scrape_interval_ms: u64,
    /// HTTP request timeout in milliseconds (default: 3000).
    #[serde(default = "default_sentinel_scrape_timeout_ms")]
    pub scrape_timeout_ms: u64,
    /// Temperature threshold (Celsius) above which ThermalAnomaly events are emitted.
    #[serde(default = "default_thermal_anomaly_threshold")]
    pub thermal_anomaly_threshold_celsius: f64,
    /// Memory usage threshold (percent) above which ResourceExhaustion events are emitted.
    #[serde(default = "default_memory_exhaustion_threshold")]
    pub memory_exhaustion_threshold_percent: f64,
    /// Disk usage threshold (percent) above which ResourceExhaustion events are emitted.
    #[serde(default = "default_disk_exhaustion_threshold")]
    pub disk_exhaustion_threshold_percent: f64,
    /// Maximum consecutive scrape failures before marking bridge unhealthy.
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,
}

fn default_sentinel_scrape_interval_ms() -> u64 { 5_000 }
fn default_sentinel_scrape_timeout_ms() -> u64 { 3_000 }
fn default_thermal_anomaly_threshold() -> f64 { 60.0 }
fn default_memory_exhaustion_threshold() -> f64 { 85.0 }
fn default_disk_exhaustion_threshold() -> f64 { 90.0 }
fn default_max_consecutive_failures() -> u32 { 5 }
```

### 4.6 Crate Structure

```
crates/swarm-ingest-sentinel/
    Cargo.toml
    src/
        lib.rs          -- pub mod declarations, re-exports
        bridge.rs       -- SentinelBridge: impl TelemetryBridge
        scraper.rs      -- Prometheus metrics scraper and parser
        mapper.rs       -- Prometheus metric families -> TelemetryEvent
        thresholds.rs   -- Threshold evaluation for conditional events
        error.rs        -- Bridge-specific error types
```

---

## 5. Multi-Source Telemetry Correlation

### 5.1 The Correlation Problem

With the addition of the Sentinel bridge, three distinct event categories flow into the swarm. The correlation engine must fuse them to detect compound threats:

```
   Tetragon Bridge                Sentinel Bridge              CloudTrail Bridge
   ───────────────                ───────────────              ─────────────────
   ProcessStart                   InfrastructureHealth         AuthenticationEvent
   (who ran what)                 (node health snapshot)       (who authenticated)
                                  ThermalAnomaly               NetworkConnect
                                  (hardware degradation)       (API calls)
                                  ResourceExhaustion
                                  (capacity limits)
```

### 5.2 Correlation Scenarios

#### Scenario 1: Cryptominer Detection

1. **Sentinel** reports: CPU usage jumps to 99%, thermal anomaly (temp rising from 45C to 78C in 60 seconds), load average spikes
2. **Tetragon** reports: Unknown binary `/tmp/.x11-unix/miner` started by `bash`, parent chain `sshd -> bash -> miner`
3. **CloudTrail** reports: IAM role `ec2-instance-role` used to call `s3:GetObject` on `config-bucket/mining-pool.json`

The swarm correlates these by `host_id`:
- Whisker agent detects CPU anomaly via Sentinel `InfrastructureHealth`
- Whisker agent detects suspicious process via Tetragon `ProcessStart`
- Weaver agent correlates: same host, temporal overlap, both pointing to unauthorized compute

#### Scenario 2: Disk-Filling Attack

**Sentinel** disk usage 60% -> 95% in 5 minutes + **Tetragon** `dd if=/dev/urandom of=/var/lib/data/fill` + **Sentinel** I/O latency 2ms -> 200ms. Correlation elevates from "disk filling up" to "active data destruction attempt."

#### Scenario 3: Lateral Movement with Infrastructure Stress

**CloudTrail** `AssumeRole` from unusual IP + **Tetragon** `ssh` on target host + **Sentinel** network TX spike on same host. Infrastructure health provides context: authorized deployment (gradual CPU increase) vs. attacker persistence (sudden network spike, anomalous process tree).

### 5.3 Correlation Key Design

Events across bridges are correlated on:

| Key | Source | Example |
|---|---|---|
| `host_id` | All bridges | `"node-worker-03"` |
| `timestamp` | All bridges | Temporal windowing (events within 60s) |
| `source_ip` | CloudTrail, Sentinel | Network origin attribution |
| `process_name` | Tetragon | Links process to resource consumption |

The `host_id` field on `TelemetryEvent` is the primary correlation axis. For the Sentinel bridge, this maps directly to `NodeMetrics.NodeName`. For Tetragon, it comes from the gRPC response's `node_name` field. For CloudTrail, it is `recipientAccountId` (account-level, not host-level -- a known gap that limits host-level correlation for cloud audit events).

### 5.4 Correlation Window Architecture

The correlation engine maintains per-host sliding windows keyed by `host_id`. When a new event arrives, it is placed in the window for its host. Whisker agents periodically scan windows looking for multi-signal patterns that individually fall below detection thresholds but collectively indicate a threat. For example, a `ProcessStart` + `ThermalAnomaly` + `NetworkConnect` in the same 60-second window on the same host produce a compound pheromone deposit that none of the individual signals would trigger alone.

---

## 6. Backpressure and Flow Control

### 6.1 The Backpressure Challenge

Each bridge operates at a different event rate:

| Bridge | Event Rate | Event Size | Throughput |
|---|---|---|---|
| Tetragon | 100-10,000 events/sec | ~500 bytes/event | 50 KB - 5 MB/sec |
| Sentinel | 1-4 events/scrape (every 1-15s) | ~2 KB/event | 0.2 - 8 KB/sec |
| CloudTrail | 10-1,000 events/batch (every 5-15min) | ~1 KB/event | 0.01 - 1 KB/sec |

Sentinel is the lowest-throughput bridge by two orders of magnitude. The danger is not Sentinel overwhelming the pipeline, but the pipeline overwhelming Sentinel (unnecessary scrape frequency) or Tetragon events starving Sentinel events in the channel.

### 6.2 Current Backpressure Mechanism

The runtime uses a bounded `mpsc::channel` as the backpressure boundary:

```rust
// From swarm-runtime/src/bridge_runtime.rs (conceptual)
let (tx, rx) = mpsc::channel(capacity);

// Bridge worker sends events
for event in events {
    tx.send(event).await  // Blocks if channel full
}
```

When the channel is full, `tx.send()` awaits, which naturally slows the bridge's poll loop. For the Tetragon bridge (streaming), this means the gRPC stream buffer fills, applying HTTP/2 flow control back to the Tetragon server. For the Sentinel bridge (polling), this means the scrape loop pauses, which is acceptable since scraped data is point-in-time anyway.

### 6.3 Per-Bridge Priority

Infrastructure events should not be starved by Tetragon process floods. The current runtime uses a single shared `mpsc::Sender<TelemetryEvent>` for all bridges, so high-volume bridges can fill the channel and block low-volume ones. **Recommendation**: Introduce separate `mpsc` channels per bridge category (security vs. infrastructure) with `tokio::select! { biased; }` giving infrastructure priority in the ingest router. Infrastructure events are low-volume (1-4/sec at most) and should never queue behind thousands of process events. This avoids modifying the `TelemetryEvent` contract with a priority field but does require changes to `BridgeRuntimeRegistry::spawn()`.

### 6.4 Sentinel-Specific Flow Control

The Sentinel bridge has a natural flow control mechanism: the scrape interval. If the pipeline is overwhelmed:

1. Channel send blocks
2. Scrape loop pauses
3. Next scrape happens later than configured interval
4. `lag_seconds` in `BridgeHealth` increases, visible in metrics
5. Operator can increase scrape interval or add capacity

This is inherently safe because Sentinel's data is sampled, not event-sourced -- missing a scrape cycle means slightly stale data, not lost events. [Doc 04](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) covers how the bridge behaves during network partitions, and [Doc 08](./08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) covers broader resilience patterns including backpressure under degraded conditions.

---

## 7. Schema Evolution and Versioning

### 7.1 Current Versioning State

The swarm config includes `schema_version: u32` at the top level:

```rust
// From swarm-core/src/config.rs
pub struct SwarmConfig {
    pub schema_version: u32,
    // ...
}
```

However, the `TelemetryPayload` enum itself has no explicit version. Evolution
is managed through serde's tagged enum, but that does **not** mean old
consumers automatically skip unknown `kind` values. With the current enum-based
deserialization model, a consumer that has not been updated for
`InfrastructureHealth` / `ThermalAnomaly` / `ResourceExhaustion` will usually
fail deserialization unless it explicitly models an unknown variant or is
fronted by a compatibility layer.

### 7.2 Adding Infrastructure Variants Safely

The `#[serde(tag = "kind")]` attribute makes the wire representation extensible,
but it is not a free compatibility guarantee. Existing consumers can still fail
at deserialization time if they have not been updated for the new variant set.

However, the `#[serde(deny_unknown_fields)]` on `TelemetryEvent` means the top-level envelope cannot gain new fields without a version bump. The payload variants also use `deny_unknown_fields`, so fields within a variant are fixed once published.

### 7.3 Recommended Evolution Strategy

**Wire compatibility rules**: (1) New payload variants are schema-extending,
but they are not operationally free; consumers must be upgraded together or
fronted by a compatibility layer. (2) New fields within a variant require a new
variant or explicit optional-field planning (`deny_unknown_fields`). (3)
Removing or renaming a variant is a breaking change. (4) Bump `schema_version`
in config or advertise a bridge capability flag when infrastructure variants
are expected. See [Doc 07](./07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md)
for how schema versioning interacts with the cryptographic audit trail.

### 7.4 Feature Gating

Do **not** feature-gate the `TelemetryPayload` enum variants. Feature-gated enum variants break serde deserialization -- a `"kind": "infrastructure_health"` message arriving at a node compiled without the feature causes hard failure rather than graceful skip. Add all three infrastructure variants unconditionally to `swarm-core`. Feature-gate only the `swarm-ingest-sentinel` crate dependency in `swarm-runtime/Cargo.toml`.

---

## 8. Performance Benchmarks

Unless otherwise marked, the values in this section are **estimates** for design
budgeting and should be validated once a real `swarm-ingest-sentinel`
implementation exists.

### 8.1 Expected Throughput Per Bridge

| Bridge | Scrape/Poll Model | Events/sec (p50) | Events/sec (p99) | Latency per event |
|---|---|---|---|---|
| Tetragon | gRPC stream, blocking poll | 500 | 8,000 | < 1ms (network + protobuf decode) |
| CloudTrail | File read, batch | 10 | 200 (large batch) | < 0.5ms (JSON parse per record) |
| Generic JSON | File read, sequential | 50 | 500 | < 0.5ms (JSON parse + pointer lookup) |
| Sentinel (proposed) | HTTP scrape, interval | 0.2 - 1.0 | 4.0 | 5-50ms (HTTP round-trip + parse) |

### 8.2 Sentinel Bridge Latency Budget

```
Scrape cycle breakdown (estimated):

  HTTP GET /metrics           2 - 20 ms    (network round-trip)
  Prometheus text parsing     0.5 - 2 ms   (line-by-line parsing, ~35 metric families)
  Metric extraction           0.1 - 0.5 ms (hashmap lookups)
  Event construction          < 0.1 ms     (struct allocation)
  Schema validation           < 0.1 ms     (field checks)
  Channel send                < 0.1 ms     (mpsc send, unless blocked)
  ────────────────────────────────────────
  Total per scrape:           3 - 23 ms

  At 5s scrape interval:
    Duty cycle = 23ms / 5000ms = 0.46% CPU
```

### 8.3 Memory Budget

| Component | Memory |
|---|---|
| `SentinelBridge` struct | ~256 bytes (config, health, state) |
| HTTP response buffer | 4 - 16 KB (Prometheus text for ~35 metrics) |
| Parsed metric map | ~2 KB (35 entries, String keys, f64 values) |
| Generated `TelemetryEvent`s | ~600 bytes per event (1-4 per cycle) |
| Previous scrape state (for deltas) | ~128 bytes (counter values) |
| **Total steady-state** | **~20 KB** |

### 8.4 Benchmark Comparison: Bridge Overhead

```
Bridge resource consumption at steady state:

Tetragon:
  CPU: 0.5 - 2% (gRPC + protobuf decode + stream management)
  Memory: 2 - 8 MB (gRPC buffers, connection state, event batching)
  File descriptors: 1 (gRPC TCP socket)

CloudTrail:
  CPU: < 0.1% (file read + JSON parse, burst on batch arrival)
  Memory: 0.5 - 2 MB (JSON parsing buffer, VecDeque of records)
  File descriptors: 1 (input file)

Sentinel (proposed):
  CPU: < 0.1% (HTTP scrape at 5s interval)
  Memory: ~20 KB (scrape buffer + metric state)
  File descriptors: 0 (HTTP connection is ephemeral per scrape)

Generic JSON:
  CPU: < 0.1% (file read + JSON parse)
  Memory: 0.5 - 2 MB (JSON parsing buffer, VecDeque of records)
  File descriptors: 1 (input file)
```

The Sentinel bridge is the most lightweight bridge in the fleet due to its low-frequency polling model.

### 8.5 End-to-End Detection Latency

```
                           Sentinel             Bridge              Dispatcher
Event occurs ──> /proc update ──> scrape ──> parse ──> channel ──> agent tick
                     ~0ms           5s        ~5ms      <1ms        ~10ms

Total: ~5.015 seconds (dominated by scrape interval)
```

For comparison:
- Tetragon end-to-end: ~50ms (kernel event to agent tick)
- CloudTrail end-to-end: ~5-15 minutes (AWS delivery delay to agent tick)

Sentinel sits between Tetragon (near-real-time) and CloudTrail (minutes-delayed), which is appropriate for infrastructure health signals that change on seconds-to-minutes timescales.

---

## 9. Reference Implementation

### 9.1 SentinelBridge Trait Implementation

```rust
// crates/swarm-ingest-sentinel/src/bridge.rs

const SOURCE_ID: &str = "sentinel";

pub struct SentinelBridge {
    config: SentinelBridgeConfig,
    scraper: SentinelScraper,
    health: Mutex<BridgeHealth>,
    consecutive_failures: u32,
    previous_counters: Option<CounterSnapshot>,
}

/// Monotonic counter values retained between scrapes for delta computation.
#[derive(Debug, Clone, Default)]
struct CounterSnapshot {
    network_rx_bytes: f64,
    network_tx_bytes: f64,
    network_rx_errors: f64,
    network_tx_errors: f64,
    disk_io_read_bytes: f64,
    disk_io_write_bytes: f64,
    oom_kill_total: f64,
}

#[async_trait]
impl TelemetryBridge for SentinelBridge {
    fn source_id(&self) -> &str { SOURCE_ID }

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>> {
        // 1. Sleep for scrape interval (natural rate limiting)
        tokio::time::sleep(Duration::from_millis(self.config.scrape_interval_ms)).await;

        // 2. HTTP GET Sentinel's /metrics endpoint
        let scraped = match self.scraper.scrape().await {
            Ok(metrics) => { self.consecutive_failures = 0; metrics }
            Err(error) => {
                self.consecutive_failures += 1;
                // Return Unavailable after max_consecutive_failures
                return Err(if self.consecutive_failures >= self.config.max_consecutive_failures {
                    TelemetryBridgeError::Unavailable(error.to_string())
                } else {
                    TelemetryBridgeError::Connection(error.to_string())
                });
            }
        };

        // 3. Map scraped metrics to 1-4 TelemetryEvents
        let events = map_scraped_metrics(&scraped, self.previous_counters.as_ref(), &self.config);

        // 4. Store counter snapshot for next delta
        self.previous_counters = Some(CounterSnapshot { /* current counter values */ });

        // 5. Validate and record health for each event
        for event in &events {
            if self.validate_schema(event) { self.record_event(event); }
            else { self.record_error(&format!("invalid event `{}`", event.event_id)); }
        }
        Ok(events)
    }

    fn validate_schema(&self, event: &TelemetryEvent) -> bool {
        // Source must be "sentinel", event_id non-empty, timestamp > 0
        // InfrastructureHealth: non-empty node_name, non-negative percentages
        // ThermalAnomaly: non-empty node_name, positive temperature
        // ResourceExhaustion: non-empty node_name, non-negative utilization, capacity > 0
        // All other payload kinds rejected (Sentinel should not produce them)
    }

    fn health(&self) -> BridgeHealth {
        self.health.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}
```

### 9.2 Prometheus Scraper

```rust
// crates/swarm-ingest-sentinel/src/scraper.rs

/// Parsed Prometheus metric families from a scrape.
#[derive(Debug, Clone, Default)]
pub struct ScrapedMetrics {
    /// Flat map of metric_name{label=value} -> f64 value.
    metrics: HashMap<String, f64>,
    /// Node name extracted from the "node" label.
    pub node_name: Option<String>,
    /// Scrape timestamp (unix seconds).
    pub scrape_timestamp: i64,
}

impl ScrapedMetrics {
    /// Get a metric value by its full name (first match without label filtering).
    pub fn get(&self, name: &str) -> f64 { /* prefix match on HashMap keys */ }

    /// Get a labeled metric value (e.g., load_average with period="1m").
    pub fn get_labeled(&self, name: &str, labels: &[(&str, &str)]) -> f64 { /* label match */ }
}

pub struct SentinelScraper {
    endpoint: String,
    timeout: Duration,
    client: reqwest::Client,
}

impl SentinelScraper {
    /// HTTP GET -> parse Prometheus exposition format -> ScrapedMetrics.
    pub async fn scrape(&self) -> Result<ScrapedMetrics, ScrapeError> {
        let body = self.client.get(&self.endpoint).send().await?.text().await?;
        parse_prometheus_text(&body)
    }
}

/// Line-by-line parser for Prometheus text format.
/// Skips `# HELP` and `# TYPE` comments, extracts metric_name{labels} value pairs,
/// and auto-detects the `node` label for host identification.
fn parse_prometheus_text(body: &str) -> Result<ScrapedMetrics, ScrapeError> { /* ... */ }

#[derive(Debug, thiserror::Error)]
pub enum ScrapeError {
    #[error("HTTP scrape failed: {0}")]
    Http(String),
    #[error("failed to parse Prometheus metrics: {0}")]
    Parse(String),
}
```

### 9.3 Mapper: Scraped Metrics to TelemetryEvents

```rust
// crates/swarm-ingest-sentinel/src/mapper.rs

pub fn map_scraped_metrics(
    scraped: &ScrapedMetrics,
    previous: Option<&CounterSnapshot>,
    config: &SentinelBridgeConfig,
) -> Vec<TelemetryEvent> {
    let node_name = scraped.node_name.clone().unwrap_or_else(|| "unknown".into());
    let timestamp = scraped.scrape_timestamp;
    let mut events = Vec::with_capacity(3);

    // 1. Always emit InfrastructureHealth
    events.push(build_infrastructure_health(scraped, &node_name, timestamp, previous));

    // 2. Conditionally emit ThermalAnomaly
    let temp = scraped.get("sentinel_cpu_temperature_celsius");
    let throttled = scraped.get("sentinel_cpu_throttled") > 0.5;
    if temp > config.thermal_anomaly_threshold_celsius || throttled {
        events.push(build_thermal_anomaly(scraped, &node_name, timestamp, temp, throttled));
    }

    // 3. Conditionally emit ResourceExhaustion (memory and/or disk)
    let mem_usage = scraped.get("sentinel_memory_usage_percent");
    if mem_usage > config.memory_exhaustion_threshold_percent {
        events.push(build_resource_exhaustion_memory(scraped, &node_name, timestamp, mem_usage, previous));
    }
    let disk_usage = scraped.get("sentinel_disk_usage_percent");
    if disk_usage > config.disk_exhaustion_threshold_percent {
        events.push(build_resource_exhaustion_disk(scraped, &node_name, timestamp, disk_usage));
    }

    events
}
```

**`build_infrastructure_health`** maps all `sentinel_*` gauge and counter metrics into a single `InfrastructureHealthEvent`. Counter metrics (`network_rx_bytes_total`, `oom_kill_total`, etc.) are delta-computed against `previous: Option<&CounterSnapshot>`. Load average uses labeled lookup: `scraped.get_labeled("sentinel_cpu_load_average", &[("period", "1m")])`.

**`build_thermal_anomaly`** classifies severity based on Sentinel's predictor thresholds (Normal < 60C, Elevated < 75C, High < 85C, Critical >= 85C) and pulls `time_to_failure_seconds` from the prediction metrics.

**`build_resource_exhaustion_memory`** and **`build_resource_exhaustion_disk`** emit events when utilization exceeds configured thresholds, including OOM kill deltas for memory and capacity values for both.

### 9.4 Integration with BridgeRuntimeRegistry

The `build_bridge` function in `swarm-runtime/src/bridge_runtime.rs` gains a new arm:

```rust
// Proposed addition to bridge_runtime.rs

fn build_bridge(
    name: &str,
    config: &TelemetryBridgeConfig,
) -> Result<BoxedTelemetryBridge, BridgeRuntimeError> {
    match config {
        TelemetryBridgeConfig::Tetragon { config } => { /* existing */ }
        TelemetryBridgeConfig::CloudTrail { config } => { /* existing */ }
        TelemetryBridgeConfig::GenericJson { config } => { /* existing */ }
        TelemetryBridgeConfig::Sentinel { config } => {
            Ok(Box::new(swarm_ingest_sentinel::SentinelBridge::new(
                sentinel_runtime_config(config),
            )))
        }
    }
}
```

And the config enum gains a new variant:

```rust
// Proposed addition to swarm-core/src/config.rs

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryBridgeConfig {
    Tetragon { /* existing */ },
    CloudTrail { /* existing */ },
    GenericJson { /* existing */ },
    Sentinel {
        #[serde(flatten)]
        config: Box<SentinelBridgeConfig>,
    },
}
```

### 9.5 YAML Configuration Example

```yaml
# In rulesets/default.yaml or deployment config
runtime:
  mode: detect_only
  telemetry_sources:
    - name: tetragon-primary
      bridge:
        kind: tetragon
        endpoint: "http://tetragon:54321"

    - name: sentinel-infra
      bridge:
        kind: sentinel
        endpoint: "http://sentinel:9100/metrics"
        scrape_interval_ms: 5000
        scrape_timeout_ms: 3000
        thermal_anomaly_threshold_celsius: 60.0
        memory_exhaustion_threshold_percent: 85.0
        disk_exhaustion_threshold_percent: 90.0

    - name: cloudtrail-audit
      bridge:
        kind: cloud_trail
        path: "/var/log/cloudtrail/events.jsonl"
```

### 9.6 Detector Integration: Infrastructure Whisker

A new Whisker agent specialization processes the three infrastructure payload variants. The core pattern:

```rust
/// Detects infrastructure anomalies and deposits pheromones
/// that other agents can correlate with security events.
pub struct InfrastructureWhisker {
    failure_probability_threshold: f64,
    health_history: VecDeque<InfrastructureHealthEvent>,
    max_history: usize,
}

impl InfrastructureWhisker {
    pub fn evaluate(&mut self, event: &TelemetryEvent) -> Option<PheromoneDeposit> {
        match &event.payload {
            TelemetryPayload::InfrastructureHealth(health) => {
                self.health_history.push_back(health.clone());
                // Deposit Impact pheromone when failure_probability exceeds threshold
                // Severity: Critical if > 0.7, High otherwise
                // Confidence: directly from Sentinel's prediction_confidence
            }
            TelemetryPayload::ThermalAnomaly(thermal) => {
                // Deposit Impact pheromone for High/Critical severity
                // Confidence: 0.9 (hardware data is high-fidelity)
            }
            TelemetryPayload::ResourceExhaustion(exhaustion) => {
                // Deposit Impact pheromone: Critical if > 95% utilization
                // Confidence: 0.95 (direct measurement)
            }
            _ => None,
        }
    }
}
```

The key insight is that infrastructure pheromones use `ThreatClass::Impact` -- they represent threats to availability rather than confidentiality or integrity. The Weaver agent can then correlate an `Impact` pheromone on `node-03` with a `ThreatClass::Execution` pheromone from the Tetragon bridge on the same host, producing a compound signal that neither source could generate alone. See [Doc 06](./06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) for the full pheromone coordination model.

---

## 10. Appendix: Data Flow Diagrams

### 10.1 Complete Bridge Data Flow

```
                          ┌──────────────────────────────────────────────────┐
                          │              Swarm Runtime                       │
                          │                                                  │
┌───────────┐  gRPC       │  ┌──────────────────┐   mpsc    ┌────────────┐ │
│ Tetragon  │────stream──>│  │ TetragonBridge    │──channel─>│            │ │
│ (eBPF)    │             │  │ poll() -> Vec<E>  │           │            │ │
└───────────┘             │  └──────────────────┘           │  Ingest    │ │
                          │                                  │  Router    │ │
┌───────────┐  HTTP GET   │  ┌──────────────────┐   mpsc    │            │ │
│ Sentinel  │────scrape──>│  │ SentinelBridge    │──channel─>│  ┌──────┐ │ │
│ (/proc    │             │  │ poll() -> Vec<E>  │           │  │Whisker│ │ │
│  +/sys)   │             │  └──────────────────┘           │  │agents │ │ │
└───────────┘             │                                  │  └──┬───┘ │ │
                          │                                  │     │     │ │
┌───────────┐  file read  │  ┌──────────────────┐   mpsc    │     v     │ │
│ CloudTrail│────parse───>│  │ CloudTrailBridge  │──channel─>│ Pheromone │ │
│ (JSON)    │             │  │ poll() -> Vec<E>  │           │ Substrate │ │
└───────────┘             │  └──────────────────┘           └────────────┘ │
                          │                                                  │
                          └──────────────────────────────────────────────────┘
```

### 10.2 Sentinel Bridge Internal Flow

```
poll() -> sleep(interval) -> HTTP GET /metrics -> parse_prometheus_text()
       -> map_scraped_metrics() -> validate_schema() -> update_health()
       -> return Ok(Vec<TelemetryEvent>)

Output per cycle: 1 InfrastructureHealth  (always)
                + 0-1 ThermalAnomaly     (if temp > threshold or throttled)
                + 0-1 ResourceExhaustion (if memory > threshold)
                + 0-1 ResourceExhaustion (if disk > threshold)
```

### 10.3 Multi-Source Correlation Timeline (Cryptominer Example)

```
T=0s    Tetragon: ProcessStart(/tmp/miner, parent=bash)
T=0s    Sentinel: InfrastructureHealth(cpu=15%, temp=42C)
T=5s    Sentinel: InfrastructureHealth(cpu=98%, temp=55C)
T=10s   Sentinel: InfrastructureHealth(cpu=99%, temp=68C) + ThermalAnomaly
T=10s   CloudTrail: NetworkConnect(s3:GetObject, mining-pool.json)
                                              │
                 Correlation Engine: Window[host=node-3] matches
                 ProcessStart + ThermalAnomaly + NetworkConnect
                              ──> ALERT: Cryptominer on node-3
```

### 10.4 Bridge Comparison Table

| Property | Tetragon | Sentinel | CloudTrail | Generic JSON |
|---|---|---|---|---|
| **Source ID** | `tetragon` | `sentinel` | `cloudtrail` | `generic_json` |
| **Transport** | gRPC stream | HTTP scrape | File read | File read |
| **Event model** | Push (blocking poll) | Pull (interval sleep) | Pull (exhaustible) | Pull (exhaustible) |
| **Payload types** | `ProcessStart` | `InfrastructureHealth`, `ThermalAnomaly`, `ResourceExhaustion` | `AuthenticationEvent`, `NetworkConnect` | All 7+ variants |
| **Reconnection** | Exponential backoff | Retry on next interval | N/A (file) | N/A (file) |
| **Backpressure** | gRPC flow control | Scrape interval | Source exhaustion | Source exhaustion |
| **Typical latency** | < 50ms | ~5s | Minutes (AWS delay) | < 1ms |
| **Memory footprint** | 2-8 MB | ~20 KB | 0.5-2 MB | 0.5-2 MB |
| **New to codebase** | Existing | **Proposed** | Existing | Existing |

---

## References

1. Sentinel source: `playground/sentinel/pkg/collector/collector.go` -- NodeMetrics struct and concurrent collection
2. Sentinel Prometheus exporter: `playground/sentinel/pkg/metrics/exporter.go` -- 35+ metric families under `sentinel_` namespace
3. Sentinel health predictor: `playground/sentinel/pkg/healthscore/predictor.go` -- Welford's algorithm, risk weights, trend analysis
4. Sentinel configuration: `playground/sentinel/pkg/config/config.go` -- Server at `:9100`, 1s collection interval
5. Sentinel consensus: `playground/sentinel/pkg/consensus/raft_lite.go` -- Partition-tolerant autonomous decisions
6. TelemetryBridge trait: `swarm-team-six/crates/swarm-core/src/telemetry.rs` -- `poll()`, `validate_schema()`, `health()`
7. TelemetryPayload enum: `swarm-team-six/crates/swarm-core/src/telemetry.rs` -- 7 current variants
8. Tetragon bridge: `swarm-team-six/crates/swarm-ingest-tetragon/src/bridge.rs` -- gRPC streaming reference
9. CloudTrail bridge: `swarm-team-six/crates/swarm-ingest-json/src/cloudtrail.rs` -- JSON normalization reference
10. Generic JSON bridge: `swarm-team-six/crates/swarm-ingest-json/src/generic_json.rs` -- Config-driven mapping
11. Bridge runtime: `swarm-team-six/crates/swarm-runtime/src/bridge_runtime.rs` -- Worker spawn, health tracking
12. Bridge config: `swarm-team-six/crates/swarm-core/src/config.rs` -- `TelemetryBridgeConfig` enum, `TelemetrySourceConfig`

---

## Cross-References

This document is part 5 of the 8-document Sentinel Convergence research series.

| Doc | Title | Relevance to This Document |
|-----|-------|---------------------------|
| [01](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Distributed Consensus for Agent Swarms | Sentinel's Raft-lite consensus underpins the partition metrics (`sentinel_consensus_*`) this bridge scrapes. |
| [02](./02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Predictive Failure as Threat Signal | Explains how Sentinel's `failure_probability` and `time_to_failure` predictions become actionable threat signals in the swarm pipeline. |
| [03](./03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge-Native Security Detection | Covers deployment constraints (ARM, limited RAM, intermittent connectivity) that inform the bridge's ~20 KB memory budget and polling model. |
| [04](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | Autonomous Response Under Partition | Defines bridge behavior when the Sentinel endpoint becomes unreachable and the swarm must operate on stale infrastructure telemetry. |
| **05** | **Telemetry Bridge Architecture** | **This document.** |
| [06](./06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Stigmergic Coordination and Swarm Intelligence | Describes how `ThreatClass::Impact` pheromones deposited by the infrastructure Whisker agent interact with security pheromones from other bridges. |
| [07](./07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Audit Trails and Decision Reconciliation | Schema versioning and `deny_unknown_fields` constraints affect how new `TelemetryPayload` variants are recorded in the cryptographic audit chain. |
| [08](./08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Resilience Patterns for Distributed Agents | Backpressure, circuit-breaking, and graceful degradation patterns that the bridge runtime applies to all bridges including Sentinel. |
