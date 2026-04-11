# Edge-Native Security Detection: Converging Sentinel's Edge Patterns with Swarm Team Six

## Document Metadata

| Field          | Value                                                              |
|----------------|--------------------------------------------------------------------|
| Document       | `03-EDGE-NATIVE-SECURITY-DETECTION.md`                            |
| Series         | Sentinel Convergence Research (3 of 8)                            |
| Version        | 0.2                                                                |
| Date           | 2026-04-07                                                         |
| Status         | Draft                                                              |
| Prerequisites  | [01 -- Consensus](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md), [02 -- Predictive Failure](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) |

> **Series Note**
> - `swarm-edge` is exploratory in the current repo state and is not part of the
>   near-term roadmap.
> - Treat this document as future-track research for an edge initiative, not as
>   an accepted execution plan.
> - See [00-OVERVIEW.md](00-OVERVIEW.md) for current series posture.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Edge Computing Security Gap](#2-the-edge-computing-security-gap)
3. [Sentinel's Edge-Native Design Patterns](#3-sentinels-edge-native-design-patterns)
4. [Swarm Team Six Architecture Recap](#4-swarm-team-six-architecture-recap)
5. [Resource Profiling: Detection Pipeline on Edge Hardware](#5-resource-profiling-detection-pipeline-on-edge-hardware)
6. [Tiered Detection Architecture](#6-tiered-detection-architecture)
7. [Compilation Strategies for Edge Targets](#7-compilation-strategies-for-edge-targets)
8. [Feature Gating: Compile-Time Binary Profiles](#8-feature-gating-compile-time-binary-profiles)
9. [Deployment Patterns for Heterogeneous Clusters](#9-deployment-patterns-for-heterogeneous-clusters)
10. [Network-Aware Detection](#10-network-aware-detection)
11. [Real-World Edge Security Scenarios](#11-real-world-edge-security-scenarios)
12. [Reference Deployment Architecture](#12-reference-deployment-architecture)
13. [Implementation Roadmap](#13-implementation-roadmap)
14. [Appendix: Cross-Project Code Reference](#14-appendix-cross-project-code-reference)
15. [Cross-References](#15-cross-references)

---

## 1. Executive Summary

Edge computing fundamentally breaks the assumptions that traditional endpoint
detection and response (EDR/XDR) platforms rely on: abundant memory, stable
network connectivity, and homogeneous x86 hardware. Devices at the edge --
Raspberry Pi clusters running retail point-of-sale systems, Jetson Nano units
processing industrial camera feeds, Intel NUC gateways in branch offices --
operate under constraints where a 200MB CrowdStrike sensor is a non-starter.

This document analyzes two Backbay projects that approach the edge from
different angles:

- **Sentinel** (`playground/sentinel`): A Go-based predictive failure engine
  designed from the ground up for Kubernetes edge nodes. It runs as a static
  binary within a 64Mi request / 128Mi limit envelope, collects metrics
  directly from `/proc` and `/sys`, and includes a lightweight Raft consensus
  protocol for autonomous operation during network partitions. (Sentinel's
  prediction model is analyzed in
  [02 -- Predictive Failure as Threat Signal](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md).)

- **Swarm Team Six** (`standalone/swarm-team-six`): A Rust-based security
  detection engine built around stigmergic coordination (pheromone substrate),
  Ed25519-signed audit trails, and a multi-agent detection architecture. It
  currently targets server-class deployments with a tokio async runtime, NATS
  JetStream durability, and a rich operator surface.

The research question is: **How should Swarm Team Six extend its detection
pipeline to edge environments, and what design patterns from Sentinel are
directly transferable?**

The answer is a tiered architecture -- a full `swarm-runtime` on servers, a
lightweight `swarm-edge` binary on constrained nodes -- connected by the same
pheromone substrate protocol. This document provides the technical blueprint
for that convergence.

---

## 2. The Edge Computing Security Gap

### 2.1 Why Traditional EDR/XDR Fails at the Edge

Traditional endpoint detection platforms assume a deployment target that looks
like a corporate laptop or cloud VM:

| Assumption | Typical EDR | Edge Reality |
|---|---|---|
| Available RAM | 512MB - 2GB for agent | 32MB - 128MB total system |
| CPU architecture | x86_64 | ARM64, RISC-V, mixed |
| Network | Always-on, low-latency to cloud | Intermittent, satellite, LTE |
| Kernel version | Recent, uniform fleet | Yocto/Buildroot, custom, frozen |
| Disk I/O | SSD, fast random access | eMMC, SD card, NOR flash |
| OS | Full Linux/Windows/macOS | Minimal Linux, no glibc |
| Update cadence | Quarterly agent updates | Annual or never |

These constraints create three categories of failure:

**Resource exhaustion.** A traditional EDR agent consuming 300MB RSS on a
Raspberry Pi 4 (1GB total RAM) leaves insufficient headroom for the actual
workload. The OOM killer terminates either the agent or the business process,
both of which are unacceptable.

**Connectivity dependence.** Cloud-first architectures that stream all
telemetry to a central SIEM and wait for cloud-side detection create a blind
window during connectivity loss. An attacker who compromises the uplink
(trivial in many edge topologies) simultaneously disables detection.

**Architecture incompatibility.** Agents compiled for x86_64 with glibc
dynamic linking cannot run on ARM64 musl-based edge distributions. The
cross-compilation matrix for a heterogeneous fleet (ARMv7, ARM64, x86_64,
RISC-V) is rarely tested in EDR vendor CI pipelines.

### 2.2 The Attack Surface at the Edge

Edge nodes present a uniquely attractive target:

```
                     ATTACK SURFACE COMPARISON
    +------------------------------------------------------------+
    |                                                            |
    |   Cloud/Data Center          Edge/IoT                     |
    |   +------------------+       +------------------+          |
    |   | Hardened OS      |       | Minimal OS       |          |
    |   | SELinux/AppArmor |       | No MAC policy    |          |
    |   | Network segmented|       | Flat network     |          |
    |   | IDS/IPS inline   |       | No inline filter |          |
    |   | SIEM connected   |       | Intermittent SIEM|          |
    |   | Patched monthly  |       | Patched annually |          |
    |   | Full EDR agent   |       | No EDR           |   <---  |
    |   +------------------+       +------------------+          |
    |                                                            |
    +------------------------------------------------------------+
```

Edge devices are often:

- Physically accessible (retail stores, warehouses, field installations)
- Running outdated firmware with known CVEs
- Connected to sensitive operational technology (OT) networks
- Trusted implicitly by upstream systems as "inside the perimeter"
- Unmonitored because no detection agent fits their constraints

This creates a detection gap that adversaries actively exploit. The 2023 Volt
Typhoon campaign specifically targeted edge network appliances (routers,
firewalls, VPN concentrators) because they lacked endpoint detection. The 2024
retail POS campaigns leveraged IoT gateways as pivot points into payment
networks precisely because those gateways had no security monitoring.

### 2.3 What Edge Detection Requires

An edge-native detection system must satisfy constraints that traditional
platforms do not:

| Requirement | Constraint | Implication |
|---|---|---|
| Memory budget | < 32MB RSS | No JVM, no Python, no V8; statically linked native binary |
| CPU budget | < 100m (0.1 cores) | Microsecond-budget detection; no ML inference per event |
| Binary size | < 10MB on disk | LTO, symbol stripping, no debug info in release |
| Startup time | < 2 seconds | No JIT warmup, no dependency download |
| Architecture | ARM64 + x86_64 minimum | Cross-compilation from CI, single source tree |
| Connectivity | Intermittent or absent | Local detection, local state, batch upload |
| Durability | Survive power loss | WAL or append-only log on local storage |
| Observability | Prometheus + health probes | Kubernetes-native liveness/readiness |
| Privilege | Minimal | Read-only `/proc`/`/sys` access, no kernel module |

---

## 3. Sentinel's Edge-Native Design Patterns

Sentinel provides a production-validated reference for building software that
runs on Kubernetes edge nodes under severe resource constraints. Every design
decision in Sentinel was made with the <64MB RAM budget in mind.

### 3.1 Static Binary, Zero CGO

From `Makefile`:

```makefile
CGO_ENABLED=0 go build $(GOFLAGS) $(LDFLAGS) -o $(BINDIR)/$@ ./cmd/$@
```

Sentinel compiles with `CGO_ENABLED=0`, producing a fully static binary with
no dynamic library dependencies. This is critical for edge deployments where
the target filesystem may not have glibc, libssl, or any other shared library.

The `-trimpath` flag (set via `GOFLAGS`) strips build machine paths from
the binary. The Makefile's `-ldflags` inject only a version string
(`-X main.version=$(VERSION)`); the Dockerfile adds `-s -w` to strip symbol
tables and DWARF debug information for smaller production images. The result
is a fully static binary that runs on any Linux kernel regardless of
userspace distribution.

**Lesson for STS:** Rust's default static linking with musl already achieves
this. The `swarm-edge` binary should target `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl` to produce equivalent zero-dependency binaries.

### 3.2 Direct /proc and /sys Access

Sentinel's collector reads hardware metrics directly from the Linux virtual
filesystems rather than using higher-level abstractions:

```go
// From pkg/collector/collector.go
type Collector struct {
    nodeName     string
    procPath     string    // default: "/proc"
    sysPath      string    // default: "/sys"
    thermalZones []string
    primaryDisk  string
    networkIface string
    // ...
}
```

The collector reads:
- `/proc/stat` for CPU usage (delta calculations between samples)
- `/proc/meminfo` for memory pressure (MemTotal, MemAvailable, Swap)
- `/proc/vmstat` for OOM kill counts
- `/proc/diskstats` for I/O latency and throughput
- `/proc/net/dev` for network traffic and errors
- `/proc/net/route` for primary interface detection
- `/proc/mounts` for root filesystem disk detection
- `/sys/class/thermal/thermal_zone*/temp` for CPU temperature
- `/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq` for frequency
- `/sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count`

This approach has three advantages over using a metrics library like
`node_exporter` or `sysinfo`:

1. **Zero allocation overhead.** Reading a file and parsing integers allocates
   only a small scanner buffer. No struct reflection, no maps of maps.
2. **Selective collection.** Only the specific metrics needed for prediction
   are read. A full `node_exporter` collects hundreds of metrics, most
   irrelevant to failure prediction.
3. **Testability.** The `WithProcPath` and `WithSysPath` options allow
   injecting fake filesystems in tests without requiring root or containers.

**Lesson for STS:** The `swarm-runtime` crate currently depends on the
`sysinfo` crate (see workspace `Cargo.toml`), which is convenient for
server deployments but pulls in a large dependency tree and allocates
extensively. The `swarm-edge` binary should instead read security-relevant
data from `/proc` directly:
- `/proc/[pid]/exe` -- process binary path (detecting renamed executables)
- `/proc/[pid]/cmdline` -- command line arguments
- `/proc/[pid]/status` -- UID/GID, capabilities, seccomp status
- `/proc/[pid]/fd/` -- open file descriptor targets
- `/proc/net/tcp` and `/proc/net/tcp6` -- active connections (C2 detection)
- `/proc/[pid]/maps` -- memory mappings (detecting injected code)

### 3.3 DaemonSet Deployment with Host Access

Sentinel deploys as a Kubernetes DaemonSet with read-only host filesystem
mounts:

```yaml
# From deploy/helm/aeop/templates/daemonset.yaml
volumes:
  - name: proc
    hostPath:
      path: /proc
  - name: sys
    hostPath:
      path: /sys
```

```yaml
# From deploy/helm/aeop/values.yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

Key patterns:
- **DaemonSet ensures one pod per node.** No scheduling games, no affinity
  rules. Every node in the cluster gets exactly one Sentinel instance.
- **Read-only mounts.** `/proc` and `/sys` are mounted read-only. The agent
  observes but never modifies the host.
- **Principle of least privilege.** All capabilities are dropped. The pod
  runs as non-root (UID 1000). No privilege escalation is allowed.
- **Tolerations for edge nodes.** The taint
  `node-role.kubernetes.io/edge:NoSchedule` is tolerated, ensuring deployment
  to edge-labeled nodes that reject normal workloads.
- **Kubernetes-native probes.** Liveness and readiness probes hit `/health`
  on the API port (9101). Sentinel's health package (`pkg/health/health.go`)
  provides separate `LivenessHandler`, `ReadinessHandler`, and
  `HealthHandler` endpoints returning JSON status objects.

### 3.4 Memory-Bounded Prediction

Sentinel's predictor maintains a fixed-size sliding window:

```go
// From pkg/healthscore/predictor.go
return &Predictor{
    nodeName:   nodeName,
    thresholds: thresholds,
    maxHistory: 1000, // ~16 minutes at 1 sample/sec
}
```

The history buffer is capped at 1000 samples. When full, old samples are
evicted:

```go
if len(p.history) > p.maxHistory {
    p.history = p.history[len(p.history)-p.maxHistory:]
}
```

This guarantees a fixed memory ceiling regardless of how long the process
runs. `NodeMetrics` contains 22 numeric fields (8 bytes each = 176 bytes)
plus a `Timestamp` (24 bytes), a `NodeName` string header (~16 bytes), and
an errors slice header (~24 bytes), totaling roughly 240 bytes per sample:

```
1000 samples * ~240 bytes/sample = ~240KB
```

This is a critical pattern for edge: **every buffer must have a compile-time
or configuration-time size bound.** Unbounded growth is a deployment-ending
bug on devices with 512MB total RAM.

### 3.5 Lightweight Consensus for Partition Resilience

Sentinel includes a Raft-lite consensus protocol (`pkg/consensus/raft_lite.go`)
designed for 3-10 node edge clusters. Key characteristics:

- **150ms election timeout** (randomized to 150-300ms)
- **50ms heartbeat interval**
- **Token bucket rate limiting** (100 msg/sec default, burst of 20)
- **Exponential backoff** for peer reconnection (100ms initial, 30s max)
- **Autonomous decision types:** pod reschedule, node cordon, service
  failover, resource scale

The consensus protocol enables edge nodes to make coordinated decisions
(e.g., cordon a failing node and evict its pods) even when the Kubernetes
control plane is unreachable. This is directly analogous to STS's
`swarm-consensus` crate, but optimized for the tighter latency and memory
budget of edge environments. For a detailed comparison of the two consensus
models, see
[01 -- Distributed Consensus for Agent Swarms](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md).

### 3.6 Circuit Breaker for API Server Communication

The Kubernetes client (`pkg/k8s/client.go`) wraps every API server call with
a circuit breaker:

```go
// From pkg/k8s/circuit_breaker.go
type CircuitBreakerConfig struct {
    FailureThreshold int           // 5 failures to open
    SuccessThreshold int           // 2 successes to close
    Timeout          time.Duration // 30s before half-open
}
```

When the control plane is unreachable (common at the edge), the circuit
breaker prevents the agent from spending CPU and network bandwidth on
futile API calls. After the timeout elapses, a single probe request tests
whether connectivity has been restored.

**Lesson for STS:** The `swarm-edge` binary must include a circuit breaker
for all upstream communication -- NATS, SIEM forwarding, operator surface.
When the circuit is open, the edge binary operates in fully autonomous mode
with local-only detection and buffered findings. This pattern is explored
further in
[08 -- Resilience Patterns for Distributed Agents](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md).

---

## 4. Swarm Team Six Architecture Recap

Before designing the edge variant, we must understand what STS looks like
today and which components are load-bearing versus optional. (See
[05 -- Telemetry Bridge Architecture](05-TELEMETRY-BRIDGE-ARCHITECTURE.md)
for the complementary question of how Sentinel telemetry flows *into* STS.)

### 4.1 Current Crate Structure

```
swarm-team-six/
  crates/
    swarm-core/          Core types, pheromone primitives, agent trait
    swarm-whisker/       Streaming detection agents (Rust-native)
    swarm-ingest-tetragon/  Tetragon gRPC telemetry bridge
    swarm-ingest-json/   CloudTrail and generic JSON ingestion
    swarm-pheromone/     In-memory + NATS substrate (feature-gated)
    swarm-policy/        Deterministic live-response policy gate
    swarm-response/      Response adapters (HTTP EDR, webhooks, SIEM)
    swarm-runtime/       Full runtime wiring (axum, dispatcher, agents)
    swarm-consensus/     BFT consensus (deferred)
    swarm-spine/         Signed envelopes, Merkle audit trail
    swarm-guard/         Guard pipeline (egress allowlist, etc.)
    swarm-crypto/        Ed25519 key management
```

### 4.2 Critical Detection Path

The fast-path benchmark (`docs/benchmarks/fast-detection.md`, run on a
development machine in release mode) demonstrates the current hot path:

```
Telemetry Event  -->  Detector  -->  Finding  -->  Pheromone Deposit
                                                       |
                                            p50: 2.04 us
                                            p99: 6.29 us
                                            ~300K events/sec
```

This pipeline is already microsecond-budget and allocation-conscious. The
`DetectionStrategy` trait evaluates synchronously (no async in the hot path),
but the current implementation still materializes small `Vec` and JSON
structures while producing findings and deposits. The benchmark therefore
captures a typed, low-allocation path rather than a strictly allocation-free
one; findings are then converted to pheromone deposits that are signed and
stored in the in-memory substrate.

### 4.3 Components by Resource Cost

| Component | RAM (est.) | CPU | I/O | Edge-viable? |
|---|---|---|---|---|
| `swarm-core` | ~1MB | Negligible | None | Yes |
| `swarm-whisker` | ~2-5MB | Low (per event) | None | Yes |
| `swarm-pheromone` (default-features off) | ~5-20MB | Low | None | Yes |
| `swarm-pheromone` (with `nats` feature) | ~50MB+ | Moderate | Network | No |
| `swarm-guard` | ~2MB | Low | None | Yes |
| `swarm-policy` | ~1MB | Negligible | None | Yes |
| `swarm-crypto` | ~1MB | Low (signing) | None | Yes |
| `swarm-spine` | ~10-30MB | Moderate | Disk | Partial |
| `swarm-ingest-tetragon` | ~10MB | Moderate | gRPC | Partial |
| `swarm-ingest-json` | ~5MB | Low | File/stdin | Yes |
| `swarm-runtime` (full) | ~80-150MB | High | Network | No |
| `swarm-response` | ~10MB | Low | Network | Conditional |
| `swarm-consensus` | ~5MB | Low | Network | Conditional |

---

## 5. Resource Profiling: Detection Pipeline on Edge Hardware

### 5.1 Target Hardware Profiles

| Device | CPU | RAM | Storage | Network | Use Case |
|---|---|---|---|---|---|
| Raspberry Pi 4B | Cortex-A72 (4x 1.8GHz) | 1-8GB | microSD | 1GbE + WiFi | Retail gateway, lab |
| Raspberry Pi CM4 | Cortex-A72 (4x 1.8GHz) | 1-8GB | eMMC | 1GbE | Industrial embedded |
| NVIDIA Jetson Nano | Cortex-A57 (4x 1.43GHz) | 4GB | microSD | 1GbE | Camera/ML edge |
| Intel NUC (N100) | Alder Lake-N (4x 3.4GHz) | 8-16GB | NVMe | 2.5GbE | Branch office |
| Qualcomm RB3 Gen2 | Kryo 585 (8x 2.84GHz) | 8GB | UFS | WiFi 6E | 5G edge |
| Rock Pi 4C+ | RK3399 (2x A72 + 4x A53) | 4GB | eMMC | 1GbE | Budget edge |

### 5.2 Projected Memory Budget for swarm-edge

Based on the crate-level analysis, a minimal edge binary would include:

```
MEMORY BUDGET: swarm-edge on 1GB Raspberry Pi 4

+--------------------------------------------------+
| Component                          | RSS (est.)  |
|------------------------------------+-------------|
| Rust runtime + static allocations  |     2 MB    |
| swarm-core types                   |     1 MB    |
| swarm-whisker (3 detectors loaded) |     3 MB    |
| swarm-pheromone (in-memory, 1hr)   |     5 MB    |
| swarm-guard (policy rules)         |     2 MB    |
| swarm-crypto (Ed25519 keys)        |     1 MB    |
| /proc scanner buffers              |     1 MB    |
| Event ring buffer (4096 events)    |     4 MB    |
| Finding backlog (offline buffer)   |     3 MB    |
| Prometheus metrics (minimal)       |     2 MB    |
| Stack + overhead                   |     2 MB    |
|------------------------------------+-------------|
| TOTAL                              |    26 MB    |
+--------------------------------------------------+

Available to workloads: 1024 - 26 = 998 MB
K8s request/limit: 32Mi / 48Mi
```

Sentinel's Helm chart sets a 64Mi *request* and 128Mi *limit*
(`deploy/helm/aeop/values.yaml`). A 26MB RSS projection fits within a 48Mi
limit for swarm-edge, well below Sentinel's envelope, and leaves abundant
headroom for the actual business workload.

### 5.3 CPU Budget Estimation

Using the benchmark data (p99 = 6.29us on server hardware) and adjusting
for ARM64 Cortex-A72 performance (roughly 40-60% of modern x86 single-thread):

```
THROUGHPUT ESTIMATES BY HARDWARE

+---------------------+------------------+------------------+
| Device              | Est. p99 latency | Est. throughput  |
|---------------------+------------------+------------------+
| Server (x86, 3GHz) |         6.29 us  | 303,000 evt/sec  |
| Intel NUC (N100)    |        ~9.0 us   | ~180,000 evt/sec |
| Raspberry Pi 4      |       ~12.0 us   | ~100,000 evt/sec |
| Jetson Nano         |       ~15.0 us   |  ~80,000 evt/sec |
| Rock Pi 4C+         |       ~14.0 us   |  ~85,000 evt/sec |
+---------------------+------------------+------------------+
```

Even on a Raspberry Pi, 100K events/sec is orders of magnitude more than
the typical edge telemetry rate (a retail POS gateway generates ~100-1000
process/network events per second). The detection pipeline is CPU-viable
on all target hardware.

### 5.4 Binary Size Estimation

Current full `swarm-runtime` release build (estimated):

```
Full runtime (estimated):  ~15-25 MB (with tokio, axum, tonic, etc.)
```

Edge binary with selective dependencies:

```
BINARY SIZE BUDGET

Component                         | Contribution
----------------------------------|-------------
Core types + detection            |    ~1.5 MB
In-memory pheromone substrate     |    ~0.5 MB
Guard pipeline (regex, glob)      |    ~1.0 MB
Ed25519 crypto                    |    ~0.3 MB
/proc scanner                     |    ~0.2 MB
Minimal HTTP (health probes)      |    ~0.8 MB
Prometheus metrics (minimal)      |    ~0.4 MB
serde_json                        |    ~0.3 MB
tokio (minimal features)          |    ~1.0 MB
                                  |
TOTAL (before LTO/strip)          |    ~6.0 MB
After LTO + strip                 |    ~3.5 MB
After UPX compression             |    ~1.5 MB
```

---

## 6. Tiered Detection Architecture

### 6.1 Architectural Overview

The core insight is that detection fidelity should scale with available
resources. A server with 32GB RAM can run the full STS runtime with
JetStream substrate, investigation agents, and the operator surface. A
Raspberry Pi with 1GB RAM needs only the fast-path Whisker detectors
with local buffering.

```
TIERED DETECTION ARCHITECTURE

+================================================================+
|                        CLOUD / DATA CENTER                      |
|                                                                 |
|   +----------------------------------------------------------+ |
|   |              swarm-runtime (FULL ENGINE)                  | |
|   |                                                           | |
|   |   Whisker agents    Stalker agents    Weaver agents      | |
|   |   Full pheromone substrate (NATS/JetStream-backed)       | |
|   |   Policy gate + response adapters                        | |
|   |   Spine audit trail (Merkle tree)                        | |
|   |   Operator surface (axum HTTP)                           | |
|   |   Investigation pipeline                                 | |
|   |   Correlation engine                                     | |
|   |   Evolution / canary framework                           | |
|   |                                                           | |
|   |   Memory: 128-512 MB    CPU: 1-4 cores                  | |
|   +----------------------------------------------------------+ |
|                          |                                      |
|                  pheromone protocol                              |
|                  (NATS or HTTP batch)                            |
|                          |                                      |
+================================================================+
                           |
              +============|============+
              |       EDGE GATEWAY      |
              |                         |
              |   +-------------------+ |
              |   | swarm-edge (LITE) | |
              |   |                   | |
              |   | Whisker subset    | |
              |   | In-memory sub.    | |
              |   | /proc scanner     | |
              |   | Local buffer      | |
              |   | Health probes     | |
              |   | Circuit breaker   | |
              |   |                   | |
              |   | Mem: 24-48 MB     | |
              |   | CPU: 50-200m      | |
              |   +-------------------+ |
              |                         |
              +=========================+
```

### 6.2 Detection Tiers

| Tier | Binary | Where | Detectors | Substrate | Response |
|---|---|---|---|---|---|
| **Full** | `swarm-runtime` | Server / cloud | All whiskers + stalkers + weavers | NATS-backed (JetStream durability) | Full policy gate + adapters |
| **Standard** | `swarm-runtime --profile=standard` | Beefy edge (NUC) | All whiskers, no stalkers | NATS or in-memory | Policy gate, webhook only |
| **Lite** | `swarm-edge` | Constrained edge (Pi) | Core whiskers only | In-memory, bounded | Escalate-only (no local response) |
| **Micro** | `swarm-edge --profile=micro` | Extreme edge (MCU) | Single pattern-match detector | Ring buffer | Forward-only |

### 6.3 Detector Selection by Tier

Not all detectors are appropriate for edge. The selection criteria:

| Detector Type | Memory | CPU/event | Edge Tier |
|---|---|---|---|
| Pattern matching (Sigma-like rules) | ~100KB per ruleset | ~1us | Micro+ |
| Process tree anomaly | ~500KB sliding window | ~3us | Lite+ |
| Network connection tracking | ~2MB connection table | ~2us | Lite+ |
| Threat intel IOC matching | ~5MB hash table | ~1us | Standard+ |
| Statistical anomaly (z-score) | ~1MB per metric | ~2us | Lite+ |
| Embedding cosine similarity | ~50MB model | ~100us | Full only |
| Temporal correlation | ~10MB event graph | ~50us | Standard+ |

### 6.4 Edge Detector: Process Tree Scanner

A concrete example of an edge-viable detector that reads from `/proc`:

```rust
// Proposed: crates/swarm-whisker/src/detectors/proc_scanner.rs

use std::fs;
use std::path::Path;

/// Lightweight process scanner reading directly from /proc.
/// No sysinfo dependency, no allocation per scan cycle.
pub struct ProcScanner {
    proc_path: String,
    /// Known-suspicious process names (compiled at build time or loaded from config).
    suspicious_names: Vec<&'static str>,
    /// Known-suspicious parent->child relationships.
    suspicious_lineages: Vec<(&'static str, &'static str)>,
}

impl ProcScanner {
    pub fn scan_once(&self) -> Vec<ProcAnomaly> {
        let mut anomalies = Vec::new();
        let proc_dir = Path::new(&self.proc_path);

        // Read /proc/[pid]/stat for each numeric directory
        if let Ok(entries) = fs::read_dir(proc_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Only process numeric directories (PIDs)
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                let pid_path = entry.path();

                // Read comm (process name, max 16 chars, no allocation needed)
                if let Ok(comm) = fs::read_to_string(pid_path.join("comm")) {
                    let comm = comm.trim();

                    // Check against suspicious names
                    if self.suspicious_names.iter().any(|s| comm.contains(s)) {
                        anomalies.push(ProcAnomaly {
                            pid: name_str.parse().unwrap_or(0),
                            comm: comm.to_string(),
                            anomaly_type: AnomalyType::SuspiciousName,
                        });
                    }
                }

                // Check for deleted exe (common in fileless malware)
                if let Ok(exe_link) = fs::read_link(pid_path.join("exe")) {
                    let exe_str = exe_link.to_string_lossy();
                    if exe_str.contains("(deleted)") {
                        anomalies.push(ProcAnomaly {
                            pid: name_str.parse().unwrap_or(0),
                            comm: String::new(),
                            anomaly_type: AnomalyType::DeletedExe,
                        });
                    }
                }
            }
        }
        anomalies
    }
}
```

This detector:
- Reads only `/proc/[pid]/comm` and `/proc/[pid]/exe` (two small reads per process)
- Allocates only for findings, not for scanning
- Runs in <1ms even with hundreds of processes
- Requires no kernel module, no eBPF, no ptrace

---

## 7. Compilation Strategies for Edge Targets

### 7.1 Rust's Advantages for Edge Deployment

Rust provides four structural advantages over Go (Sentinel's language) for
edge security binaries:

**Zero-cost abstractions.** The `DetectionStrategy` trait compiles to static
dispatch when the concrete type is known at compile time. There is no vtable
overhead in the hot path. Go's interfaces use dynamic dispatch; the Go
compiler can sometimes devirtualize calls, but this is not guaranteed and
the optimization is less aggressive than Rust's monomorphization.

**No garbage collector.** Sentinel's Go runtime includes a concurrent GC
whose stop-the-world phases typically take tens of microseconds on server
hardware but can reach hundreds of microseconds to low milliseconds on an
ARM Cortex-A72 with a larger heap. This is acceptable for Sentinel's
1-second collection interval but introduces latency variance in a
microsecond-budget detection path. Rust has no GC pauses.

**Cross-compilation.** Rust's `cross` tool and musl targets produce static
ARM64 binaries from x86 CI machines trivially:

```bash
# Build for ARM64 edge targets from x86 CI
cargo build --release --target aarch64-unknown-linux-musl -p swarm-edge
```

Go achieves this with `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`, but Rust's
musl integration is more mature for complex dependency trees (no C library
linkage issues with OpenSSL, zlib, etc.).

**Binary size optimization.** Rust's LTO (Link-Time Optimization) and
aggressive dead code elimination produce smaller binaries than Go for
equivalent functionality. Go binaries include the full runtime and GC even
when unused.

### 7.2 Build Configuration for Edge

```toml
# Proposed: Cargo.toml [profile.edge]

[profile.edge]
inherits = "release"
opt-level = "z"          # Optimize for size (smallest binary)
lto = true               # Full link-time optimization
codegen-units = 1        # Maximum optimization (slower compile)
strip = true             # Strip symbols and debug info
panic = "abort"          # No unwind tables (saves ~100KB)
```

Comparison of build profiles:

```
BUILD PROFILE COMPARISON (estimated for swarm-edge)

+------------------+-----------+----------+----------+
| Profile          | Binary    | Compile  | Runtime  |
|                  | Size      | Time     | Perf     |
|------------------+-----------+----------+----------|
| debug            | ~30 MB    | 30s      | Slowest  |
| release          | ~8 MB     | 2min     | Fast     |
| edge (opt-z+LTO) | ~3.5 MB  | 5min     | Fast*    |
| edge + UPX       | ~1.5 MB  | 5min+10s | Fast*    |
+------------------+-----------+----------+----------+

* opt-level="z" trades ~5-10% throughput for smaller binary.
  Acceptable at edge where events/sec is low.
```

### 7.3 Cross-Compilation Matrix

```
TARGET MATRIX FOR CI

+-------------------------+---------------------+-------------------+
| Target Triple           | Hardware            | Linker            |
|-------------------------+---------------------+-------------------|
| x86_64-unknown-linux-musl | Intel NUC, VMs   | musl-gcc          |
| aarch64-unknown-linux-musl | Pi 4, Jetson, CM4 | aarch64-musl-gcc |
| armv7-unknown-linux-musleabihf | Pi 3, older ARM | arm-musl-gcc  |
+-------------------------+---------------------+-------------------+

CI Pipeline:

  cargo build --target aarch64-unknown-linux-musl \
    --profile edge -p swarm-edge

  cargo build --target x86_64-unknown-linux-musl \
    --profile edge -p swarm-edge
```

### 7.4 Docker Multi-Architecture Build

Following Sentinel's pattern but using a scratch base:

```dockerfile
# Proposed: deploy/docker/Dockerfile.swarm-edge

# Build stage (edition = "2024" requires Rust >= 1.85)
FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --profile edge --target x86_64-unknown-linux-musl \
    -p swarm-edge

# Runtime stage - scratch (zero OS, zero CVEs)
FROM scratch
COPY --from=builder /src/target/x86_64-unknown-linux-musl/edge/swarm-edge \
    /swarm-edge
USER 65534:65534
EXPOSE 9100 9101
ENTRYPOINT ["/swarm-edge"]
```

Sentinel uses `alpine:3.18` as its runtime base (adding `ca-certificates`
and `tzdata`). Note: Sentinel's Dockerfile currently references
`golang:1.19-alpine` as its build image despite `go.mod` specifying Go 1.21
-- a discrepancy worth flagging. The `swarm-edge` binary can use `scratch`
since Rust's `rustls` eliminates the need for system CA certificates, and
`chrono` with the `clock` feature handles time without `tzdata`.

---

## 8. Feature Gating: Compile-Time Binary Profiles

### 8.1 Feature Flag Design

Cargo features allow producing different binary profiles from the same
source tree:

```toml
# Proposed: crates/swarm-edge/Cargo.toml

[package]
name = "swarm-edge"
version.workspace = true

[features]
default = ["core-detectors", "proc-scanner", "health-probes"]

# Detection tiers
# NOTE: swarm-whisker has no feature gates today; these require adding
# them upstream before swarm-edge can consume them selectively.
core-detectors = ["swarm-whisker/core"]        # proposed
full-detectors = ["swarm-whisker/full", "swarm-whisker/embedding"]  # proposed

# Data sources
proc-scanner = []                     # /proc-based process monitoring
tetragon = ["swarm-ingest-tetragon"]  # Tetragon gRPC bridge
json-ingest = ["swarm-ingest-json"]   # Generic JSON/CloudTrail

# Substrate backends
# NOTE: swarm-pheromone currently exposes a single "nats" feature
# (default on). These features require splitting the crate first.
substrate-memory = ["swarm-pheromone/memory-only"]  # proposed
substrate-nats = ["swarm-pheromone/nats", "async-nats"]

# Connectivity
nats-upstream = ["async-nats"]        # NATS-based pheromone sync
http-upstream = ["reqwest"]           # HTTP batch upload
offline-only = []                     # No upstream connectivity

# Operator surface
health-probes = ["axum"]              # /healthz, /readyz only
full-http = ["axum", "tower"]         # Full operator API

# Audit (see 07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md)
spine-audit = ["swarm-spine"]         # Full Merkle audit trail
local-journal = []                    # Append-only local file

# Response
response-adapters = ["swarm-response"]
escalate-only = []                    # Can only escalate, no local response

[dependencies]
swarm-core.workspace = true
swarm-whisker.workspace = true
swarm-guard.workspace = true
swarm-crypto.workspace = true
swarm-pheromone = { workspace = true, default-features = false }

# Optional dependencies gated by features
swarm-ingest-tetragon = { workspace = true, optional = true }
swarm-ingest-json = { workspace = true, optional = true }
swarm-spine = { workspace = true, optional = true }
swarm-response = { workspace = true, optional = true }
async-nats = { workspace = true, optional = true }
reqwest = { workspace = true, optional = true }
axum = { workspace = true, optional = true }
tower = { workspace = true, optional = true }
```

### 8.2 Binary Profiles via Feature Combinations

```
FEATURE COMBINATIONS BY DEPLOYMENT TIER

+----------+----------------------------------------------------+
| Profile  | cargo build command                                 |
|----------+----------------------------------------------------|
| micro    | --no-default-features                              |
|          | --features core-detectors,offline-only,local-journal|
|          |                                                     |
| lite     | --features core-detectors,proc-scanner,             |
|          |   substrate-memory,health-probes,                   |
|          |   http-upstream,escalate-only                       |
|          |                                                     |
| standard | --features core-detectors,proc-scanner,             |
|          |   tetragon,substrate-memory,health-probes,          |
|          |   nats-upstream,response-adapters                   |
|          |                                                     |
| full     | --all-features                                     |
+----------+----------------------------------------------------+

ESTIMATED BINARY SIZES (after LTO + strip):

  micro:     ~1.5 MB
  lite:      ~3.5 MB
  standard:  ~6.0 MB
  full:      ~12.0 MB
```

### 8.3 Conditional Compilation in Detection Code

The feature flags propagate into detection logic:

```rust
// Proposed: crates/swarm-whisker/src/lib.rs

/// Core detectors always available.
pub mod process_tree;
pub mod pattern_match;
pub mod network_anomaly;

/// Extended detectors behind feature gates.
#[cfg(feature = "embedding")]
pub mod embedding_similarity;

#[cfg(feature = "temporal")]
pub mod temporal_correlation;

/// Build the detector set for the current feature profile.
pub fn build_detector_set(config: &DetectionConfig) -> CompositeDetector {
    let mut detectors: Vec<Box<dyn DetectionStrategy>> = Vec::new();

    // Always included
    detectors.push(Box::new(process_tree::SuspiciousProcessTreeDetector::new(
        &config.process_tree,
    )));
    detectors.push(Box::new(pattern_match::PatternMatchDetector::new(
        &config.pattern_rules,
    )));

    #[cfg(feature = "full")]
    {
        detectors.push(Box::new(
            network_anomaly::NetworkAnomalyDetector::new(&config.network),
        ));
    }

    #[cfg(feature = "embedding")]
    {
        detectors.push(Box::new(
            embedding_similarity::EmbeddingDetector::load(&config.embedding_model),
        ));
    }

    CompositeDetector::new(detectors)
}
```

---

## 9. Deployment Patterns for Heterogeneous Clusters

### 9.1 Pattern Comparison

Edge security agents can be deployed in three patterns, each with distinct
trade-offs:

```
DEPLOYMENT PATTERN COMPARISON

Pattern 1: DaemonSet (Sentinel's approach)
+---------+  +---------+  +---------+
| Node A  |  | Node B  |  | Node C  |
| +-----+ |  | +-----+ |  | +-----+ |
| |edge | |  | |edge | |  | |edge | |
| |agent| |  | |agent| |  | |agent| |
| +-----+ |  | +-----+ |  | +-----+ |
| |work | |  | |work | |  | |work | |
| |load | |  | |load | |  | |load | |
| +-----+ |  | +-----+ |  | +-----+ |
+---------+  +---------+  +---------+

Pattern 2: Sidecar
+---------+  +---------+  +---------+
| Node A  |  | Node B  |  | Node C  |
| +-----+ |  | +-----+ |  | +-----+ |
| |pod  | |  | |pod  | |  | |pod  | |
| |+---+| |  | |+---+| |  | |+---+| |
| ||wkl|| |  | ||wkl|| |  | ||wkl|| |
| ||+--+| |  | ||+--+| |  | ||+--+| |
| ||sts|| |  | ||sts|| |  | ||sts|| |
| |+---+| |  | |+---+| |  | |+---+| |
| +-----+ |  | +-----+ |  | +-----+ |
+---------+  +---------+  +---------+

Pattern 3: Embedded Library
+---------+  +---------+  +---------+
| Node A  |  | Node B  |  | Node C  |
| +-----+ |  | +-----+ |  | +-----+ |
| |app  | |  | |app  | |  | |app  | |
| |with | |  | |with | |  | |with | |
| |sts  | |  | |sts  | |  | |sts  | |
| |lib  | |  | |lib  | |  | |lib  | |
| +-----+ |  | +-----+ |  | +-----+ |
+---------+  +---------+  +---------+
```

| Pattern | Pros | Cons | Best For |
|---|---|---|---|
| **DaemonSet** | Host-level visibility, one per node, simple lifecycle | Requires K8s, needs hostPath mounts | K8s edge clusters (K3s, MicroK8s) |
| **Sidecar** | Per-pod isolation, no host access needed | Per-pod overhead, no host visibility | Service mesh, multi-tenant |
| **Embedded** | Minimal overhead, in-process detection | Tight coupling, language-specific | Rust workloads, single-purpose devices |

### 9.2 Recommended: DaemonSet with NodeAffinity

For Kubernetes-managed edge fleets, the DaemonSet pattern (Sentinel's
approach) is the correct default. The Helm chart should select the binary
profile based on node labels:

```yaml
# Proposed: deploy/helm/swarm-edge/templates/daemonset.yaml

apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {{ .Release.Name }}-edge
  labels:
    app.kubernetes.io/name: swarm-edge
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: swarm-edge
  template:
    metadata:
      labels:
        app.kubernetes.io/name: swarm-edge
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9100"
    spec:
      serviceAccountName: {{ .Release.Name }}-edge
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
      containers:
        - name: detector
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          args:
            - --config=/etc/swarm/config.yaml
            - --node=$(NODE_NAME)
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          ports:
            - name: metrics
              containerPort: 9100
            - name: health
              containerPort: 9101
          livenessProbe:
            httpGet:
              path: /healthz
              port: health
            initialDelaySeconds: 3
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
              port: health
            initialDelaySeconds: 2
            periodSeconds: 5
          resources:
            requests:
              cpu: {{ .Values.resources.requests.cpu }}
              memory: {{ .Values.resources.requests.memory }}
            limits:
              cpu: {{ .Values.resources.limits.cpu }}
              memory: {{ .Values.resources.limits.memory }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: proc
              mountPath: /host/proc
              readOnly: true
            - name: sys
              mountPath: /host/sys
              readOnly: true
            - name: config
              mountPath: /etc/swarm
              readOnly: true
            - name: buffer
              mountPath: /var/lib/swarm
      volumes:
        - name: proc
          hostPath:
            path: /proc
        - name: sys
          hostPath:
            path: /sys
        - name: config
          configMap:
            name: {{ .Release.Name }}-config
        - name: buffer
          emptyDir:
            sizeLimit: 50Mi
      tolerations:
        - key: "node-role.kubernetes.io/edge"
          operator: "Exists"
          effect: "NoSchedule"
        - key: "node.kubernetes.io/not-ready"
          operator: "Exists"
          effect: "NoSchedule"
```

### 9.3 Helm Values: Hardware-Aware Defaults

```yaml
# Proposed: deploy/helm/swarm-edge/values.yaml

# Profiles: micro, lite, standard
profile: lite

image:
  repository: ghcr.io/backbay-labs/swarm-edge
  tag: "latest"
  pullPolicy: IfNotPresent

# Resource limits by profile
resources:
  # lite profile (Raspberry Pi class)
  requests:
    cpu: 50m
    memory: 32Mi
  limits:
    cpu: 200m
    memory: 48Mi

# Override for standard profile (Intel NUC class)
# resources:
#   requests:
#     cpu: 100m
#     memory: 64Mi
#   limits:
#     cpu: 500m
#     memory: 128Mi

detection:
  # Scan interval for /proc-based detectors
  scanIntervalMs: 1000
  # Maximum events buffered when offline
  offlineBufferSize: 10000

upstream:
  # How findings reach the full STS runtime
  mode: http   # "http", "nats", or "none"
  endpoint: "https://swarm-runtime.internal:8443/api/v1/findings"
  # Batch size for HTTP uploads
  batchSize: 100
  # Flush interval when batch is not full
  flushIntervalMs: 5000

pheromone:
  # Local substrate settings (smaller than server defaults)
  defaultHalfLifeSecs: 1800
  evaporationThreshold: 0.05
  maxDeposits: 5000   # Bounded for memory

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
```

### 9.4 Heterogeneous Cluster: Mixed Architecture Deployment

A realistic edge cluster contains mixed architectures:

```
HETEROGENEOUS EDGE CLUSTER

+----------------------------------------------------+
|  K3s Control Plane (Intel NUC x3)                  |
|  Image: swarm-edge:latest-amd64                    |
|  Profile: standard                                  |
|  Resources: 128Mi limit                            |
+----------------------------------------------------+
        |
+-------+--------+----------+----------+
|                 |          |          |
| Warehouse       | Retail   | Loading  |
| Camera Gateway  | POS GW   | Dock IoT |
| Jetson Nano     | Pi 4     | Pi CM4   |
| arm64           | arm64    | arm64    |
| swarm-edge:lite | lite     | micro    |
| 48Mi limit      | 48Mi     | 32Mi     |
+----------------+----------+----------+
```

The Helm chart handles this with node selectors and architecture-specific
image tags. Multi-arch Docker manifests allow a single tag to resolve to the
correct architecture:

```bash
# CI builds both architectures, pushes a manifest list
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/backbay-labs/swarm-edge:latest \
  --push .
```

---

## 10. Network-Aware Detection

### 10.1 Connectivity States

Edge nodes cycle through three connectivity states. The detection engine
must behave correctly in all three:

```
CONNECTIVITY STATE MACHINE

    +-----------+      link up       +------------+
    |           | -----------------> |            |
    |  OFFLINE  |                    |  CONNECTED |
    |           | <----------------- |            |
    +-----------+    link down /     +------------+
         ^  |        timeout              |  ^
         |  |                             |  |
         |  |  partial connectivity       |  | recovered
         |  |  (packet loss > 30%)        |  | (loss < 5%)
         |  +------>  +-----------+ <-----+  |
         |            |           |-----------+
         +----------- |  DEGRADED |
          link down   |           |
                      +-----------+
```

### 10.2 Behavior by Connectivity State

| Component | Connected | Degraded | Offline |
|---|---|---|---|
| Detection | Full pipeline | Full pipeline | Full pipeline |
| Pheromone substrate | Sync to upstream | Batch sync (reduced freq) | Local-only |
| Finding upload | Streaming | Batched (5s flush) | Buffer to disk |
| Config updates | Live reload | Cached | Last-known config |
| Health probes | Full reporting | Full reporting | Local-only |
| Response actions | Full (if authorized) | Escalate-only | Log-only |
| Time sync | NTP verified | Drift-tolerant (100ms) | Monotonic only |

### 10.3 Offline Buffer Design

When upstream connectivity is lost, findings must be buffered locally
without unbounded memory growth:

```rust
// Proposed: crates/swarm-edge/src/offline_buffer.rs

/// Bounded ring buffer for findings produced while offline.
///
/// When the buffer is full, the oldest finding is evicted (with a metric
/// increment for dropped findings). This guarantees a fixed memory ceiling
/// regardless of how long the node is offline.
pub struct OfflineBuffer {
    findings: VecDeque<BufferedFinding>,
    max_size: usize,
    dropped_count: u64,
}

pub struct BufferedFinding {
    /// Serialized finding (pre-serialized to avoid re-serialization on flush).
    pub payload: Vec<u8>,
    /// Monotonic timestamp for ordering.
    pub timestamp: std::time::Instant,
    /// Estimated upstream time (may drift while offline).
    pub wall_clock: i64,
}

impl OfflineBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            findings: VecDeque::with_capacity(max_size),
            max_size,
            dropped_count: 0,
        }
    }

    pub fn push(&mut self, finding: BufferedFinding) {
        if self.findings.len() >= self.max_size {
            self.findings.pop_front(); // Evict oldest
            self.dropped_count += 1;
        }
        self.findings.push_back(finding);
    }

    /// Drain all buffered findings for batch upload.
    pub fn drain(&mut self) -> Vec<BufferedFinding> {
        self.findings.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }
}
```

Memory calculation for the buffer:

```
10,000 findings * ~1KB average payload = ~10 MB
```

This is within budget for all target hardware.

### 10.4 Partition-Aware Pheromone Merging

When an edge node reconnects after an offline period, its local pheromone
deposits must be merged with the upstream substrate (see
[06 -- Stigmergic Coordination](06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md)
for the full pheromone coordination model). The merge is conflict-free by
design:

1. **Pheromone deposits are append-only.** No two agents produce the same
   deposit ID (agent_id + timestamp + content hash).
2. **Decay is deterministic.** Given a deposit's timestamp and half-life,
   any node can compute its effective strength at any time.
3. **Concentration is aggregatable.** The upstream substrate simply adds the
   edge deposits to its existing set and recomputes concentration.

The merge protocol:

```
EDGE RECONNECTION PROTOCOL

Edge Node                              Upstream Runtime
    |                                        |
    |  1. POST /api/v1/findings/batch        |
    |  (all buffered findings + deposits)    |
    | -------------------------------------> |
    |                                        |
    |  2. 200 OK { accepted: N, seq: M }    |
    | <------------------------------------- |
    |                                        |
    |  3. GET /api/v1/pheromones?since=T     |
    |  (catch up on deposits from other      |
    |   nodes during our offline period)     |
    | -------------------------------------> |
    |                                        |
    |  4. 200 OK { deposits: [...] }        |
    | <------------------------------------- |
    |                                        |
    |  5. Merge upstream deposits into       |
    |     local substrate                    |
    |                                        |
```

This is directly analogous to Sentinel's `PartitionReconciler`
(`pkg/k8s/migrator.go`), which reconciles autonomous decisions made during a
partition with the Kubernetes control plane state after connectivity is
restored. See
[04 -- Autonomous Response Under Partition](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md)
for a deeper treatment of partition recovery semantics.

---

## 11. Real-World Edge Security Scenarios

### 11.1 Scenario: IoT Fleet Compromise via Firmware Update

**Environment:** 500 Raspberry Pi CM4 devices running warehouse inventory
scanners. K3s cluster with three NUC control-plane nodes. LTE backhaul
with 50ms latency, intermittent during shift changes.

**Attack:** Adversary compromises the firmware update server and pushes a
modified image containing a reverse shell. The update rolls out to 200
devices overnight.

**Detection with swarm-edge:**

```
T+0h    Firmware update applied. Reverse shell binary written to
        /tmp/.update_helper (common for supply chain attacks).

T+0h01  swarm-edge /proc scanner detects:
        - New process /tmp/.update_helper (suspicious path)
        - Process has network socket to external IP (C2)
        - Binary not in known-good hash set

        Finding deposited to local pheromone substrate:
        {
          threat_class: "execution",
          severity: "HIGH",
          confidence: 0.85,
          indicator: {
            "pid": 4721,
            "exe": "/tmp/.update_helper",
            "remote_addr": "185.220.101.42:443"
          }
        }

T+0h02  swarm-edge on 200 nodes batch-upload findings to upstream
        swarm-runtime.

T+0h03  Upstream Whisker agents detect concentration spike:
        - threat_class: execution
        - total_strength: 170.0 (200 nodes * 0.85)
        - distinct_sources: 200
        - Immediate transition: Normal -> Incident

T+0h04  Upstream Stalker investigates, correlates with firmware
        update timeline. Weaver links to supply chain TTP.
        Pouncer proposes BlockEgress for C2 IP range.
```

**Key insight:** The edge nodes did not need investigation capability or
the full runtime. They needed only the `/proc` scanner and the ability to
forward findings to the upstream runtime where the full detection pipeline
could correlate across the fleet.

### 11.2 Scenario: Retail POS RAM Scraping

**Environment:** 50 retail locations, each with 3-5 Raspberry Pi 4 devices
running POS terminals. K3s cluster per store, managed by a central fleet
operator. Satellite backhaul with 200ms latency and 1-hour daily outages.

**Attack:** Adversary gains access to a POS terminal via a phishing email
to the store manager's workstation, then pivots to the POS network. A
memory-scraping tool is loaded to extract credit card track data.

**Detection with swarm-edge:**

```
T+0h    Memory scraper loaded via PowerShell-equivalent on Linux.
        Process: /dev/shm/pos_helper (tmpfs, never touches disk)

T+0h01  swarm-edge proc scanner detects:
        - Process running from /dev/shm (suspicious memory-only exec)
        - Process opens /proc/[POS_pid]/mem (reading other process memory)
        - Network connection to exfiltration endpoint

        Multiple findings deposited:
        1. execution:HIGH  - suspicious tmpfs execution
        2. credential_access:CRITICAL - /proc/*/mem access
        3. data_exfiltration:HIGH - unusual outbound connection

T+0h02  Local pheromone concentration exceeds alert threshold
        (3 findings from same node, but needs source diversity).
        swarm-edge escalates via HTTP batch to upstream.

T+0h03  Satellite uplink is DOWN. Findings buffered locally.
        swarm-edge continues monitoring autonomously.
        Detection continues producing findings.

T+1h15  Satellite uplink restored. Buffer flush:
        - 73 findings batched and uploaded
        - Upstream processes retroactively
        - Incident timeline reconstructed with correct timestamps
```

### 11.3 Scenario: Industrial Control System (ICS) Lateral Movement

**Environment:** Water treatment facility. NVIDIA Jetson Nano devices
monitoring SCADA equipment via Modbus TCP. Air-gapped from corporate
network but connected to a local K3s cluster for data collection.

**Attack:** An insider with physical access connects a rogue device to the
OT network. The device scans the Modbus network and sends unauthorized
commands to PLCs (programmable logic controllers).

**Detection with swarm-edge** (requires the `/proc/net/tcp` network
connection tracker from Phase 5 of the roadmap):

```
T+0h    Rogue device connects to OT VLAN.

T+0h01  swarm-edge network connection tracker detects:
        - New MAC address on monitored interface
        - TCP SYN flood to port 502 (Modbus) across /24 subnet
        - Connection from unknown source to PLC addresses

        Findings:
        1. discovery:HIGH - network scan on Modbus port range
        2. lateral_movement:CRITICAL - unauthorized Modbus connection
        3. impact:CRITICAL - Modbus write command to PLC

T+0h02  Air-gapped network: NO upstream connectivity.
        swarm-edge operates in full offline mode.
        Local pheromone substrate tracks concentration.
        Findings written to append-only journal on eMMC.

T+0h03  Local alert threshold exceeded. swarm-edge activates
        response-escalation: writes alert to local syslog and
        triggers GPIO pin connected to facility alarm system.

        No network-based response possible (air-gapped).
        Physical response initiated by operator.
```

**Key insight:** In air-gapped environments, the edge binary must be
entirely self-contained. It cannot rely on upstream processing. The
detection, alerting, and local response must all function with zero
network connectivity.

---

## 12. Reference Deployment Architecture

### 12.1 Full Architecture Diagram

```
REFERENCE DEPLOYMENT: MIXED EDGE + CLOUD

+================================================================+
|                    CENTRAL SOC / CLOUD                          |
|                                                                 |
|   +----------------------------------------------------------+ |
|   |              swarm-runtime (FULL)                         | |
|   |                                                           | |
|   |   +----------+  +----------+  +----------+               | |
|   |   | Whisker  |  | Stalker  |  | Weaver   |               | |
|   |   | agents   |  | agents   |  | agents   |               | |
|   |   +----------+  +----------+  +----------+               | |
|   |                                                           | |
|   |   +---------------------------------------------------+  | |
|   |   |  Pheromone Substrate (NATS/JetStream-backed)      |  | |
|   |   |  All deposits from all tiers aggregated here      |  | |
|   |   +---------------------------------------------------+  | |
|   |                                                           | |
|   |   +------------+  +----------+  +-----------+            | |
|   |   | Policy     |  | Spine    |  | Operator  |            | |
|   |   | Gate       |  | Audit    |  | Surface   |            | |
|   |   +------------+  +----------+  +-----------+            | |
|   |                                                           | |
|   |   Memory: 256-512 MB    CPU: 2-4 cores                  | |
|   +----------------------------------------------------------+ |
|              |                   |                   |          |
|         NATS cluster        HTTP API          Prometheus        |
|              |                   |                   |          |
+==============|===================|===================|==========+
               |                   |                   |
    +----------+---+    +----------+---+    +----------+---+
    |  SITE A      |    |  SITE B      |    |  SITE C      |
    |  (K3s + NUC) |    |  (K3s + Pi)  |    |  (Air-gapped)|
    |              |    |              |    |              |
    | swarm-edge   |    | swarm-edge   |    | swarm-edge   |
    | standard     |    | lite         |    | micro        |
    |              |    |              |    |              |
    | +----------+ |    | +----------+ |    | +----------+ |
    | |NUC: 128Mi| |    | |Pi4: 48Mi | |    | |CM4: 32Mi | |
    | |std profile| |    | |lite prof.| |    | |micro prof| |
    | |NATS sync | |    | |HTTP batch| |    | |journal   | |
    | +----------+ |    | +----------+ |    | +----------+ |
    | +----------+ |    | +----------+ |    | +----------+ |
    | |Pi4: 48Mi | |    | |Pi4: 48Mi | |    | |Pi4: 32Mi | |
    | |lite prof.| |    | |lite prof.| |    | |micro prof| |
    | |HTTP batch| |    | |HTTP batch| |    | |journal   | |
    | +----------+ |    | +----------+ |    | +----------+ |
    +--------------+    +--------------+    +--------------+
```

### 12.2 Resource Budget Summary

```
RESOURCE BUDGET BY DEPLOYMENT TIER

+----------+---------+---------+--------+---------+-------------+
| Tier     | Binary  | RAM     | CPU    | Disk    | Upstream    |
|          | Size    | Limit   | Limit  | Buffer  | Mode        |
|----------+---------+---------+--------+---------+-------------|
| Full     | 12 MB   | 512 Mi  | 4 core | SSD     | NATS stream |
| Standard | 6 MB    | 128 Mi  | 500m   | 100 Mi  | NATS or HTTP|
| Lite     | 3.5 MB  | 48 Mi   | 200m   | 50 Mi   | HTTP batch  |
| Micro    | 1.5 MB  | 32 Mi   | 100m   | 20 Mi   | Journal only|
+----------+---------+---------+--------+---------+-------------+

COST PER NODE (annualized, hardware only):

  Raspberry Pi 4 (4GB) + case + PSU: ~$80
  swarm-edge overhead: ~32MB RAM, ~5% CPU
  Effective cost of edge security: $0 marginal hardware cost
```

### 12.3 Prometheus Metrics from Edge Nodes

Following Sentinel's metrics pattern (`sentinel_*` namespace), the edge
binary exposes a minimal set of Prometheus metrics:

```
# HELP swarm_edge_detection_events_total Total telemetry events processed
# TYPE swarm_edge_detection_events_total counter
swarm_edge_detection_events_total{node="warehouse-pi-042"} 142857

# HELP swarm_edge_detection_findings_total Total findings produced
# TYPE swarm_edge_detection_findings_total counter
swarm_edge_detection_findings_total{node="warehouse-pi-042",severity="HIGH"} 3

# HELP swarm_edge_pheromone_deposits_total Total pheromone deposits
# TYPE swarm_edge_pheromone_deposits_total counter
swarm_edge_pheromone_deposits_total{node="warehouse-pi-042"} 3

# HELP swarm_edge_buffer_depth Current offline buffer depth
# TYPE swarm_edge_buffer_depth gauge
swarm_edge_buffer_depth{node="warehouse-pi-042"} 0

# HELP swarm_edge_buffer_dropped_total Findings dropped due to buffer overflow
# TYPE swarm_edge_buffer_dropped_total counter
swarm_edge_buffer_dropped_total{node="warehouse-pi-042"} 0

# HELP swarm_edge_upstream_connected Upstream connectivity status
# TYPE swarm_edge_upstream_connected gauge
swarm_edge_upstream_connected{node="warehouse-pi-042"} 1

# HELP swarm_edge_scan_duration_seconds Time to complete one /proc scan
# TYPE swarm_edge_scan_duration_seconds histogram
swarm_edge_scan_duration_seconds_bucket{le="0.001"} 142800
swarm_edge_scan_duration_seconds_bucket{le="0.01"} 142857

# HELP swarm_edge_memory_rss_bytes Current RSS in bytes
# TYPE swarm_edge_memory_rss_bytes gauge
swarm_edge_memory_rss_bytes{node="warehouse-pi-042"} 26738688
```

### 12.4 Health and Readiness Probes

Directly modeled on Sentinel's health check pattern:

```
GET /healthz  -> 200 {"status": "alive"}           (liveness)
GET /readyz   -> 200 {"status": "ready", ...}      (readiness)
GET /health   -> 200 {"status": "healthy",          (detailed)
                      "checks": {
                        "detector": {"status": "healthy"},
                        "substrate": {"status": "healthy"},
                        "upstream": {"status": "degraded",
                                     "message": "last sync 47s ago"}
                      }}
```

---

## 13. Implementation Roadmap

This roadmap is intentionally exploratory. It describes a plausible future edge
track, not the current `docs/ROADMAP.md` execution plan.

### Phase 1: Edge-Viable Whisker Extraction (2-3 weeks)

**Goal:** Prove that `swarm-whisker` detectors compile and run on ARM64
within the 48MB memory budget.

Tasks:
1. Create `crates/swarm-edge` crate with feature-gated dependencies
2. Implement `/proc` scanner detector (process tree, deleted exe, /dev/shm exec)
3. Add `profile.edge` to workspace `Cargo.toml`
4. Cross-compile for `aarch64-unknown-linux-musl`
5. Benchmark on Raspberry Pi 4: measure RSS, p99 latency, events/sec
6. Write Dockerfile.swarm-edge (scratch-based, multi-arch)

**Exit criteria:** Binary runs on Pi 4, RSS < 32MB, detects test scenarios.

### Phase 2: Offline Buffer and Upstream Sync (2 weeks)

**Goal:** Edge binary operates correctly during network partitions.

Tasks:
1. Implement `OfflineBuffer` ring buffer with bounded memory
2. Implement circuit breaker for upstream HTTP connection
3. Implement batch upload protocol (`POST /api/v1/findings/batch`)
4. Add connectivity state machine (Connected / Degraded / Offline)
5. Integration test: simulate 1-hour outage, verify buffer flush

**Exit criteria:** Edge binary survives 24-hour offline period without OOM,
findings recovered on reconnect.

### Phase 3: Helm Chart and Fleet Deployment (2 weeks)

**Goal:** Deploy swarm-edge across a heterogeneous K3s cluster via Helm.

Tasks:
1. Write `deploy/helm/swarm-edge/` chart (DaemonSet, RBAC, ConfigMap)
2. Implement values-based profile selection (micro/lite/standard)
3. Add node-affinity rules for architecture-specific images
4. Add Prometheus ServiceMonitor for edge metrics
5. Test on mixed ARM64 + x86_64 cluster

**Exit criteria:** `helm install swarm-edge ./deploy/helm/swarm-edge`
deploys to all nodes in a heterogeneous cluster.

### Phase 4: Pheromone Protocol Integration (2 weeks)

**Goal:** Edge findings flow into the upstream pheromone substrate.

Tasks:
1. Define `/api/v1/findings/batch` endpoint in `swarm-runtime`
2. Implement edge deposit -> upstream pheromone conversion
3. Implement upstream deposit -> edge catch-up protocol
4. Verify that edge findings contribute to upstream concentration
5. Test fleet-wide incident detection across edge + server tiers

**Exit criteria:** 10 edge nodes producing findings trigger a mode
transition in the upstream runtime.

### Phase 5: Production Hardening (ongoing)

Tasks:
1. Add Sigma rule loading for pattern-match detector
2. Implement network connection tracker (parse `/proc/net/tcp`)
3. Add threat-intel IOC hash matching (optional feature)
4. Benchmark on Jetson Nano and Intel NUC
5. Add e2e chaos tests (network partition, OOM simulation)
6. Write operator documentation for edge deployment

---

## 14. Appendix: Cross-Project Code Reference

### Sentinel Files Referenced

| File | Purpose | Relevance |
|---|---|---|
| `cmd/predictor/main.go` | Main entry point, server lifecycle | Signal handling, graceful shutdown pattern |
| `pkg/collector/collector.go` | `/proc` and `/sys` metric collection | Direct filesystem access pattern for edge |
| `pkg/healthscore/predictor.go` | Bounded sliding window prediction | Memory-bounded buffer pattern |
| `pkg/consensus/raft_lite.go` | Lightweight Raft for edge clusters | Partition-resilient consensus model |
| `pkg/k8s/circuit_breaker.go` | Circuit breaker for API calls | Network failure resilience pattern |
| `pkg/k8s/client.go` | K8s client with circuit breaker | Control plane communication pattern |
| `pkg/k8s/migrator.go` | Partition reconciliation | Post-partition state merging |
| `pkg/health/health.go` | Health check framework | Liveness/readiness probe pattern |
| `pkg/metrics/exporter.go` | Prometheus metrics export | Edge observability pattern |
| `pkg/logging/logger.go` | Structured logging (slog) | Lightweight logging pattern |
| `deploy/helm/aeop/values.yaml` | Helm chart values | Resource limits, tolerations |
| `deploy/helm/aeop/templates/daemonset.yaml` | DaemonSet template | hostPath mounts, security context |
| `deploy/docker/Dockerfile.predictor` | Multi-stage Docker build | Static binary, non-root user |
| `Makefile` | Cross-compilation targets | `CGO_ENABLED=0`, multi-arch build |

### Swarm Team Six Files Referenced

| File | Purpose | Relevance |
|---|---|---|
| `Cargo.toml` (workspace) | Workspace configuration | Crate dependency structure |
| `crates/swarm-core/src/pheromone.rs` | Pheromone types and decay | Edge substrate must implement same protocol |
| `crates/swarm-core/src/types.rs` | Agent ID, severity, response actions | Shared types between edge and server |
| `crates/swarm-core/src/config.rs` | Runtime configuration | Feature-gated config for edge profile |
| `crates/swarm-whisker/Cargo.toml` | Whisker detection crate | Core detection dependency for edge |
| `crates/swarm-runtime/src/whisker_agent.rs` | Whisker agent implementation | Detection agent pattern to extract |
| `crates/swarm-runtime/src/detection/pipeline.rs` | Fast detection path | Hot path to preserve on edge |
| `crates/swarm-runtime/src/dispatcher.rs` | Agent dispatcher | Tick-based agent lifecycle model |
| `crates/swarm-guard/src/lib.rs` | Guard pipeline | Lightweight policy for edge |
| `crates/swarm-pheromone/src/substrate.rs` | In-memory substrate | Edge substrate implementation |
| `docs/benchmarks/fast-detection.md` | Detection benchmark | p50=2us, p99=6us baseline |
| `docs/AGENTS.md` | Agent archetype reference | Whisker tier-1 autonomy for edge |
| `docs/PHEROMONES.md` | Pheromone substrate design | Decay model, source diversity |
| `docs/CONSENSUS.md` | BFT consensus design | Deferred for edge, but partition model relevant |
| `docs/RUST_FIRST_MIGRATION.md` | Migration strategy | "Smaller Rust vertical slice" principle |

---

## 15. Cross-References

This document is part of the **Sentinel Convergence** research series (8
documents). Each explores a different axis of convergence between Sentinel
(`playground/sentinel`) and Swarm Team Six (`standalone/swarm-team-six`).

| # | Document | Relevance to This Document |
|---|----------|---------------------------|
| 01 | [Distributed Consensus for Agent Swarms](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Compares Sentinel's Raft-lite with STS BFT consensus -- directly informs the edge consensus trade-offs in Section 3.5. |
| 02 | [Predictive Failure as Threat Signal](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Maps Sentinel's statistical predictor to STS threat detection; the predictor's memory-bounded design (Section 3.4) is central to that analysis. |
| 03 | **Edge-Native Security Detection** (this document) | -- |
| 04 | [Autonomous Response Under Partition](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | Extends the offline-mode and circuit-breaker patterns from Sections 3.6 and 10 into a full partition-tolerant response framework. |
| 05 | [Telemetry Bridge Architecture](05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Designs the `swarm-ingest-sentinel` bridge; the `/proc` collection patterns from Section 3.2 feed into the bridge's input contract. |
| 06 | [Stigmergic Coordination and Swarm Intelligence](06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Formalizes the pheromone merging protocol sketched in Section 10.4 and analyzes edge-to-cloud concentration propagation. |
| 07 | [Audit Trails and Decision Reconciliation](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Covers the cryptographic audit trail for offline decisions; the `spine-audit` vs `local-journal` trade-off from Section 8.1 is expanded here. |
| 08 | [Resilience Patterns for Distributed Agents](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Catalogs the circuit breaker, backoff, and bounded-buffer patterns referenced throughout this document as general resilience primitives. |
