---
title: "02 -- Predictive Infrastructure Failure as a Threat Signal"
series: Sentinel Convergence (2 of 8)
version: "0.2"
date: 2026-04-07
status: Draft
authors: Swarm Team Six Research
---

# 02 -- Predictive Infrastructure Failure as a Threat Signal

> **Scope**: Mapping Sentinel's statistical failure-prediction model to swarm-team-six's threat-detection substrate, designing the `InfrastructureAnomalyDetector` family, and establishing formal convergence between infrastructure health telemetry and security threat intelligence.

> **Series Note**
> - The canonical proposed wire schema for infrastructure telemetry now lives in
>   [05-TELEMETRY-BRIDGE-ARCHITECTURE.md](05-TELEMETRY-BRIDGE-ARCHITECTURE.md).
> - This document should be read as detector logic and threat-signal design over
>   that schema, not as a competing transport contract.
> - Quantitative values in Section 12 are design targets and validation
>   hypotheses unless explicitly measured.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Motivation: The Security-Infrastructure Boundary Is a Fiction](#2-motivation-the-security-infrastructure-boundary-is-a-fiction)
3. [Attack-Infrastructure Correlation Matrix](#3-attack-infrastructure-correlation-matrix)
4. [Deep Analysis: Sentinel's Statistical Prediction Model](#4-deep-analysis-sentinels-statistical-prediction-model)
5. [Mapping Sentinel Predictions to ThreatClass Taxonomy](#5-mapping-sentinel-predictions-to-threatclass-taxonomy)
6. [Designing the InfrastructureAnomalyDetector Family](#6-designing-the-infrastructureanomalydetector-family)
7. [False Positive Mitigation](#7-false-positive-mitigation)
8. [Time-Series Analysis Techniques for Dual-Domain Detection](#8-time-series-analysis-techniques-for-dual-domain-detection)
9. [Case Studies: Real-World Attacks Detectable Through Infrastructure Anomalies](#9-case-studies-real-world-attacks-detectable-through-infrastructure-anomalies)
10. [Integration with the Pheromone Substrate](#10-integration-with-the-pheromone-substrate)
11. [Prototype Implementation Sketches](#11-prototype-implementation-sketches)
12. [Evaluation Framework and Benchmarks](#12-evaluation-framework-and-benchmarks)
13. [Open Questions and Future Work](#13-open-questions-and-future-work)
14. [References](#14-references)
15. [Cross-References](#cross-references)

---

## 1. Abstract

Traditional EDR/XDR platforms and infrastructure monitoring operate in parallel silos that rarely share signal. This document argues that the boundary is artificial and exploitable: adversaries routinely produce infrastructure anomalies as side effects of their operations, and those anomalies constitute high-signal, low-evasion threat indicators when fused with behavioral detection.

We present a formal analysis of **Sentinel** -- a Go-based predictive failure detection system for Kubernetes edge nodes using Welford's online algorithm, configurable risk weights, and linear regression trend analysis. We then design a convergence layer that feeds Sentinel-style infrastructure metrics into **swarm-team-six**'s pheromone substrate as a new detector family: `InfrastructureAnomalyDetector`. The key insight is that infrastructure anomalies, when deposited as pheromones alongside process/network/credential signals, create compound concentration patterns that reduce false positives while catching attacks that evade purely behavioral detection.

---

## 2. Motivation: The Security-Infrastructure Boundary Is a Fiction

### 2.1 The Adversary Doesn't Respect Your Org Chart

SOCs and SRE teams use different tools and alerting pipelines. A Monero miner on a compromised K8s node may trigger nothing in the security plane -- custom-built binary with no signature match, innocuous process name, no suspicious parent-child relationship -- yet it produces unmistakable infrastructure signals: CPU > 95%, thermal throttling, load z-score > 3, memory pressure from connection caching. Neither plane alone has sufficient signal; together, the pattern is definitive.

### 2.2 Evasion Cost Asymmetry

Behavioral evasion is relatively cheap. An adversary can:

- Rename binaries to match legitimate process names.
- Use LOLBins (living-off-the-land binaries) to avoid suspicious process trees.
- Encrypt C2 traffic to blend with HTTPS flows.
- Throttle data exfiltration to stay below bandwidth thresholds.

But **physical resource consumption cannot be hidden**. A cryptominer must consume CPU cycles. A fork bomb must allocate processes (and therefore memory). Data exfiltration must generate network I/O. Disk wipers must issue write syscalls.

This asymmetry makes infrastructure signals uniquely valuable: they represent a detection channel where the adversary's evasion budget is constrained by physical resource requirements, not software configuration.

### 2.3 Edge Environments Amplify the Signal

Sentinel targets resource-constrained edge nodes where a 4-core ARM node running three pods has a far tighter resource envelope than a 128-core cloud instance. A cryptominer producing 200% of expected CPU on an edge node creates a dramatic z-score deviation that would be lost in noise on an over-provisioned cloud VM. This makes the Sentinel-swarm convergence particularly powerful for edge K8s deployments.

---

## 3. Attack-Infrastructure Correlation Matrix

The following table maps common attack classes to the infrastructure telemetry signals they produce. Each row represents an attack category, and each column indicates which of Sentinel's five metric domains (thermal, memory, disk I/O, network, CPU) carries signal.

### 3.1 Primary Correlation Table

| Attack Class | Thermal | Memory | CPU | Disk I/O | Network | Sentinel Risk Factors | MITRE ATT&CK |
|---|---|---|---|---|---|---|---|
| Cryptocurrency Mining | **Critical** | Medium | **Critical** | Low | Medium | `cpu_temp_critical`, `cpu_saturated`, `load_anomaly`, `thermal_trend_rising` | T1496 |
| Fork Bomb / Process Explosion | High | **Critical** | **Critical** | Medium | Low | `memory_critical`, `oom_events`, `cpu_saturated`, `load_anomaly` | T1499.001 |
| Data Exfiltration (bulk) | Low | Medium | Low | Medium | **Critical** | `network_latency_critical`, `network_errors_high` | T1048 |
| Data Exfiltration (DNS tunneling) | Low | Low | Low | Low | **High** | `network_latency_elevated`, `network_errors_elevated` | T1048.003 |
| Disk Wiper / Ransomware Encryption | Medium | Low | Medium | **Critical** | Low | `disk_io_critical`, `disk_full`, `disk_critical` | T1485, T1486 |
| Memory-Resident Malware (fileless) | Low | **High** | Medium | Low | Low | `memory_pressure`, `swap_pressure`, `memory_trend_rising` | T1055 |
| Privilege Escalation via Kernel Exploit | Medium | Medium | High | Low | Low | `cpu_temp_elevated`, `load_anomaly`, `cpu_high` | T1068 |
| Container Escape | Medium | Medium | High | Medium | Low | `cpu_temp_rising`, `load_anomaly`, `memory_pressure` | T1611 |
| Reverse Shell / C2 Beaconing | Low | Low | Low | Low | **High** | `network_latency_elevated` | T1071 |
| Log Tampering / Evidence Destruction | Low | Low | Low | **High** | Low | `disk_io_high`, `disk_io_critical` | T1070 |

### 3.2 Signal Strength by Domain

Aggregating across attack types: CPU provides the broadest signal (relevant to most attack types), thermal is the strongest single indicator (hardest for adversaries to suppress), and network is essential for exfiltration/C2 detection. This validates Sentinel's default risk weight allocation, which assigns the highest weight (0.30) to thermal.

---

## 4. Deep Analysis: Sentinel's Statistical Prediction Model

### 4.1 Architecture Overview

Sentinel's prediction engine (`pkg/healthscore/predictor.go`) implements a lightweight statistical model designed for edge deployment. The Collector (`pkg/collector/collector.go`) reads from Linux procfs and sysfs, gathering 20+ metrics per sample across five domains (CPU, thermal, memory, disk, network). The Predictor maintains a rolling window of up to 1000 samples (~16.7 minutes at 1 Hz) and feeds each sample through Welford's online statistics and OLS trend analysis to produce a composite risk score with time-to-failure estimation.

### 4.2 Welford's Online Algorithm

The core statistical primitive is Welford's online algorithm for computing running mean and variance in a single pass with O(1) memory. From `predictor.go`:

```go
func updateMeanStd(oldMean, oldStd, newValue, n float64) (float64, float64) {
    if n == 1 {
        return newValue, 0
    }
    delta := newValue - oldMean
    newMean := oldMean + delta/n
    delta2 := newValue - newMean
    newVar := (oldStd*oldStd*(n-1) + delta*delta2) / n
    return newMean, math.Sqrt(newVar)
}
```

The mathematical formulation is:

Given a stream of values x_1, x_2, ..., x_n, Welford's algorithm maintains:

```
M_n = M_{n-1} + (x_n - M_{n-1}) / n           (running mean)
S_n = S_{n-1} + (x_n - M_{n-1})(x_n - M_n)    (running sum of squared deviations)
sigma_n = sqrt(S_n / n)                          (population standard deviation)
```

**Properties relevant to threat detection**:

1. **Numerically stable**: Unlike the naive two-pass formula `Var = E[X^2] - (E[X])^2`, Welford's avoids catastrophic cancellation when the mean is large relative to the variance. This matters for metrics like `NetworkRxBytes` which can be in the billions.

2. **O(1) memory**: No need to store the full history for statistics. The Predictor stores history for trend analysis, but the statistics themselves need only `(mean, std, n)` per feature.

3. **Monotonic convergence**: As n grows, the estimate converges. For security purposes, this means the model becomes more sensitive to anomalies over time, not less -- exactly the property we want.

**Limitation for security applications**: Welford's computes a global mean/variance, so it adapts to sustained attacks. A miner running for hours will eventually be absorbed into the baseline. [Section 8](#8-time-series-analysis-techniques-for-dual-domain-detection) addresses this with EWMA and CUSUM, which provide recency-weighted alternatives.

### 4.3 Risk Weight Architecture

Sentinel uses configurable weights that sum to 1.0:

```go
type RiskWeights struct {
    Thermal float64  // Default: 0.30
    Memory  float64  // Default: 0.20
    CPU     float64  // Default: 0.15
    Disk    float64  // Default: 0.10
    Network float64  // Default: 0.10
    Trend   float64  // Default: 0.15
}
```

The composite risk score is:

```
R = w_thermal * r_thermal + w_memory * r_memory + w_cpu * r_cpu 
    + w_disk * r_disk + w_network * r_network + w_trend * r_trend
```

Where each `r_i` is in [0.0, 1.0] and each `w_i` sums to 1.0.

**Graceful degradation**: When metrics are unavailable (common on edge devices with missing sensors), Sentinel normalizes by available weight:

```go
if availableWeight > 0 && availableWeight < 1.0 {
    riskScore = riskScore / availableWeight
    confidence *= availableWeight
}
```

This is critical for security applications because an adversary who disables thermal monitoring (e.g., by unloading the `coretemp` kernel module) will not suppress detection -- the remaining metrics will be upweighted and the confidence will be reduced, which itself is a signal.

### 4.4 Per-Domain Risk Calculation

Each domain uses a piecewise linear risk function with empirically-derived thresholds:

**Thermal Risk (r_thermal)**:

```
r_thermal = 0.0                              if T <= 55°C
          = (T - 55) / 10 * 0.3              if 55 < T <= 65
          = 0.3 + (T - 65) / 10 * 0.4        if 65 < T <= 75
          = 0.7 + (T - 75) / 10 * 0.3        if 75 < T <= 85
          = 1.0                              if T > 85
          + 0.2 if (T - avg(T_recent_10)) > 5   (rapid rise bonus)
          + 0.3 if CPU_throttled                (throttle bonus)
```

**Memory Risk (r_memory)**:

```
r_memory = 0.0                              if usage <= 70%
         = (usage - 70) / 10 * 0.3           if 70 < usage <= 80
         = 0.3 + (usage - 80) / 10 * 0.4     if 80 < usage <= 90
         = 0.7 + (usage - 90) / 5 * 0.3      if 90 < usage <= 95
         = 1.0                              if usage > 95
         + 0.5 if OOM_kill_count increased   (OOM events)
         + 0.2 if swap_usage > 50%           (swap pressure)
```

**CPU Risk (r_cpu)**:

```
r_cpu = 0.0                              if usage <= 70%
      = (usage - 70) / 15 * 0.4           if 70 < usage <= 85
      = 0.4 + (usage - 85) / 10 * 0.4     if 85 < usage <= 95
      = 0.8                              if usage > 95 (note: not 1.0)
      + 0.30 if z_score(load_1min) > 3    (load anomaly)
      + 0.15 if 2 < z_score(load_1min) <= 3  (elevated load)
      clamped to [0.0, 1.0]
```

Note that CPU usage alone caps at 0.8, requiring a concurrent load z-score anomaly to reach 1.0. This design choice is security-relevant: sustained 100% CPU without a load anomaly (i.e., consistent with baseline) is less suspicious than a sudden spike.

The z-score calculation for load anomaly is particularly relevant for security:

```go
if p.stats.loadMean > 0 && p.stats.loadStd > 0 {
    zScore := (m.LoadAverage1Min - p.stats.loadMean) / p.stats.loadStd
    if zScore > 3 {
        risk += 0.3
    }
}
```

A z-score above 3 indicates the current load is more than 3 standard deviations from the running mean -- a statistically significant anomaly that occurs in only ~0.27% of samples under a normal distribution (two-tailed), or ~0.13% for the one-tailed case relevant here (we only care about upward deviations). For security purposes, this is a strong signal that something has changed the workload profile of the node.

### 4.5 Trend Analysis via Linear Regression

Sentinel computes simple linear regression over the most recent 30 samples to detect trends:

```go
slope := (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX)
```

This is ordinary least squares (OLS) regression with the independent variable being sample index. For thermal trending:

```
T(i) = a + b*i + epsilon

where b (slope) represents degrees Celsius per sample interval
```

A slope > 0.1 degrees/sample (6 degrees/minute at 1 Hz) triggers a trend risk contribution. For memory:

```
M(i) = a + b*i + epsilon

where b > 0.5 (%/sample) indicates memory is growing at >30%/minute
```

**Time-to-failure estimation** uses the thermal slope to project when the 85 degree critical threshold will be reached:

```
TTF = (T_critical - T_current) / slope * sample_interval
```

### 4.6 Confidence Model

Sentinel's confidence model combines a hard history guard with a multiplicative metric-coverage penalty:

```
if samples < 10:
    confidence = 0.1 (insufficient history; early return)
else:
    confidence = 0.8 (base) * availableWeight (metric coverage penalty)
```

The history guard prevents action on noisy early samples. The `availableWeight` term degrades confidence proportionally when sensors are missing. For security applications, we extend this with a temporal confidence decay and corroborating-signal boost (see [Section 10](#10-integration-with-the-pheromone-substrate)).

### 4.7 Prediction Output Structure

```go
type Prediction struct {
    Timestamp          time.Time
    NodeName           string
    FailureProbability float64   // [0.0, 1.0]
    Confidence         float64   // [0.0, 1.0]
    TimeToFailure      float64   // seconds, -1 if none
    Reasons            []string  // machine-parseable tags
    Recommendation     string    // human-readable action
}
```

The `Reasons` field is the critical bridge to threat classification. Tags like `cpu_temp_critical`, `load_anomaly`, `memory_pressure`, `oom_events`, `network_errors_high`, and `disk_io_critical` can be directly mapped to threat class indicators.

---

## 5. Mapping Sentinel Predictions to ThreatClass Taxonomy

With Sentinel's statistical model now established, the next step is mapping its outputs into the swarm's threat-classification vocabulary so they can participate in pheromone-based correlation.

### 5.1 swarm-team-six ThreatClass Enumeration

From `crates/swarm-core/src/pheromone.rs`:

```rust
pub enum ThreatClass {
    LateralMovement,
    DataExfiltration,
    PrivilegeEscalation,
    CommandAndControl,
    InitialAccess,
    Persistence,
    SupplyChain,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    Execution,
    Impact,
    Custom(String),
}
```

### 5.2 Reason-to-ThreatClass Mapping

The following table defines the mapping from Sentinel's machine-readable reason tags to swarm-team-six ThreatClass variants:

| Sentinel Reason Tag | Primary ThreatClass | Secondary ThreatClass | Rationale |
|---|---|---|---|
| `cpu_temp_critical` | `Execution` | `Impact` | Sustained high CPU suggests unauthorized computation |
| `cpu_temp_high` | `Execution` | -- | Elevated but not critical; lower confidence |
| `cpu_temp_rising` | `Execution` | `Custom("resource_hijack")` | Rapid thermal rise suggests new compute-heavy process |
| `cpu_throttled` | `Execution` | `Impact` | Throttling implies sustained maximal consumption |
| `cpu_saturated` | `Execution` | -- | Near-total CPU consumption |
| `load_anomaly` | `Execution` | `PrivilegeEscalation` | z-score > 3 deviation from baseline |
| `memory_critical` | `Impact` | `Execution` | Memory exhaustion can indicate fork bomb or malware |
| `memory_pressure` | `Execution` | -- | Moderate memory anomaly |
| `memory_pressure_high` | `Impact` | `Execution` | Severe memory consumption |
| `oom_events` | `Impact` | `Execution` | OOM kills are a strong signal of resource abuse |
| `swap_pressure` | `Execution` | -- | Swap usage indicates memory-resident payload growth |
| `memory_trend_rising` | `Execution` | `Persistence` | Steadily growing memory suggests leak or payload accumulation |
| `disk_full` | `Impact` | -- | Disk exhaustion, possibly ransomware or wiper |
| `disk_critical` | `Impact` | -- | Near-full disk |
| `disk_io_critical` | `Impact` | `DataExfiltration` | Extreme I/O suggests encryption or mass copy |
| `disk_io_high` | `DataExfiltration` | `Impact` | Elevated I/O suggests data staging |
| `network_latency_critical` | `CommandAndControl` | `DataExfiltration` | Extreme latency may indicate tunneling |
| `network_latency_high` | `CommandAndControl` | -- | Elevated latency |
| `network_latency_elevated` | `CommandAndControl` | -- | Marginal latency increase |
| `network_errors_high` | `DataExfiltration` | `CommandAndControl` | Error storms suggest covert channel or DDoS |
| `network_errors_elevated` | `CommandAndControl` | -- | Moderate error rate |
| `thermal_trend_rising` | `Execution` | `Custom("resource_hijack")` | Monotonic thermal rise |
| `partial_metrics_available` | `DefenseEvasion` | -- | Missing sensors may indicate tampering |
| `no_metrics_available` | `DefenseEvasion` | -- | Complete metric loss is highly suspicious |

### 5.3 Compound Signal Rules

Single infrastructure signals have low specificity. The power comes from compound rules that combine multiple signals:

```
Rule: CRYPTOMINER_SIGNATURE
  Conditions:
    - cpu_temp_critical OR cpu_temp_high
    - cpu_saturated OR load_anomaly
    - thermal_trend_rising
    - NOT (disk_io_critical)  // miners don't write much
  Maps to: ThreatClass::Execution
  MITRE: T1496 (Resource Hijacking)
  Confidence boost: +0.3 over individual signal confidence

Rule: RANSOMWARE_SIGNATURE
  Conditions:
    - disk_io_critical
    - cpu_temp_elevated OR cpu_high
    - memory_pressure (encryption buffers)
    - disk_usage_trend_rising
  Maps to: ThreatClass::Impact
  MITRE: T1486 (Data Encrypted for Impact)
  Confidence boost: +0.4

Rule: EXFILTRATION_SIGNATURE
  Conditions:
    - network_errors_elevated OR network_latency_high
    - disk_io_high (staging reads)
    - NOT (cpu_temp_critical)  // exfil is not compute-heavy
  Maps to: ThreatClass::DataExfiltration
  MITRE: T1048 (Exfiltration Over Alternative Protocol)
  Confidence boost: +0.25

Rule: FORK_BOMB_SIGNATURE
  Conditions:
    - memory_critical OR oom_events
    - load_anomaly (z-score > 3)
    - cpu_saturated
    - memory_trend_rising (rapid slope)
  Maps to: ThreatClass::Impact
  MITRE: T1499.001 (Endpoint Denial of Service)
  Confidence boost: +0.35

Rule: SENSOR_TAMPERING
  Conditions:
    - partial_metrics_available OR no_metrics_available
    - previous_tick had full metrics
  Maps to: ThreatClass::DefenseEvasion
  MITRE: T1562 (Impair Defenses)
  Confidence: 0.6 (high inherent suspicion)
```

---

## 6. Designing the InfrastructureAnomalyDetector Family

### 6.1 Architectural Position

The `InfrastructureAnomalyDetector` is a new Whisker-family detector that sits alongside the existing eight detector families:

```
swarm-whisker/src/
├── composite.rs                 # CompositeDetector (fan-out orchestrator)
├── credential_access.rs         # CredentialAccessDetector
├── detector.rs                  # DetectionStrategy trait + SuspiciousProcessTreeDetector
├── dns_exfiltration.rs          # DnsExfiltrationDetector
├── lateral_movement.rs          # LateralMovementDetector
├── network_connect.rs           # NetworkConnectDetector
├── persistence.rs               # PersistenceDetector
├── stream.rs                    # Stream processing runtime
├── supply_chain.rs              # SupplyChainDetector
├── suspicious_scripting.rs      # SuspiciousScriptingDetector
└── infrastructure_anomaly.rs    # NEW: InfrastructureAnomalyDetector
```

### 6.2 Detector Input Model

Earlier drafts of this series proposed a single wire-level telemetry payload for
all infrastructure metrics. The series now standardizes on the three proposed
payloads in [Doc 05](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md):
`InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion`.

The structure below is still useful as an **internal aggregated detector view**
after those canonical payloads have been normalized for analysis:

```rust
/// Proposed internal detector view derived from the canonical
/// infrastructure telemetry payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureMetricsView {
    pub node_name: String,

    // Thermal
    pub cpu_temperature_celsius: Option<f64>,
    pub cpu_throttled: Option<bool>,

    // CPU
    pub cpu_usage_percent: Option<f64>,
    pub load_average_1min: Option<f64>,
    pub load_average_5min: Option<f64>,

    // Memory
    pub memory_usage_percent: Option<f64>,
    pub memory_total_bytes: Option<u64>,
    pub oom_kill_count: Option<u64>,
    pub swap_usage_percent: Option<f64>,

    // Disk
    pub disk_usage_percent: Option<f64>,
    pub disk_io_read_bytes: Option<u64>,
    pub disk_io_write_bytes: Option<u64>,
    pub disk_io_latency_ms: Option<f64>,

    // Network
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
    pub network_rx_errors: Option<u64>,
    pub network_tx_errors: Option<u64>,
    pub network_latency_ms: Option<f64>,

    // Sentinel prediction (if available)
    pub sentinel_failure_probability: Option<f64>,
    pub sentinel_confidence: Option<f64>,
    pub sentinel_reasons: Option<Vec<String>>,
    pub sentinel_time_to_failure_secs: Option<f64>,
}
```

All fields are `Option` to support graceful degradation, matching Sentinel's approach of detecting metric availability and adjusting confidence accordingly.

### 6.3 Detector Profile

Following the established pattern (e.g., `DnsExfiltrationProfile`, `LateralMovementProfile`):

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureAnomalyProfile {
    // Welford's configuration
    #[serde(default = "default_min_samples")]
    pub min_samples: usize,                    // 30
    #[serde(default = "default_max_history")]
    pub max_history: usize,                    // 1000

    // Z-score thresholds for anomaly detection
    #[serde(default = "default_zscore_warning")]
    pub zscore_warning: f64,                   // 2.0
    #[serde(default = "default_zscore_critical")]
    pub zscore_critical: f64,                  // 3.0

    // Domain-specific thresholds (aligned with Sentinel defaults)
    #[serde(default = "default_thermal_critical_celsius")]
    pub thermal_critical_celsius: f64,         // 85.0
    #[serde(default = "default_thermal_elevated_celsius")]
    pub thermal_elevated_celsius: f64,         // 65.0
    #[serde(default = "default_memory_critical_percent")]
    pub memory_critical_percent: f64,          // 95.0
    #[serde(default = "default_memory_elevated_percent")]
    pub memory_elevated_percent: f64,          // 80.0
    #[serde(default = "default_cpu_critical_percent")]
    pub cpu_critical_percent: f64,             // 95.0
    #[serde(default = "default_disk_io_critical_ms")]
    pub disk_io_critical_ms: f64,              // 100.0
    #[serde(default = "default_network_latency_critical_ms")]
    pub network_latency_critical_ms: f64,      // 500.0

    // Trend analysis
    #[serde(default = "default_trend_window")]
    pub trend_window: usize,                   // 30
    #[serde(default = "default_thermal_slope_critical")]
    pub thermal_slope_critical: f64,           // 0.1 deg/sample
    #[serde(default = "default_memory_slope_critical")]
    pub memory_slope_critical: f64,            // 0.5 %/sample

    // Compound rule toggles
    #[serde(default = "default_enable_compound_rules")]
    pub enable_compound_rules: bool,           // true

    // Risk weights (Sentinel-compatible)
    #[serde(default = "default_risk_weight_thermal")]
    pub risk_weight_thermal: f64,              // 0.30
    #[serde(default = "default_risk_weight_memory")]
    pub risk_weight_memory: f64,               // 0.20
    #[serde(default = "default_risk_weight_cpu")]
    pub risk_weight_cpu: f64,                  // 0.15
    #[serde(default = "default_risk_weight_disk")]
    pub risk_weight_disk: f64,                 // 0.10
    #[serde(default = "default_risk_weight_network")]
    pub risk_weight_network: f64,              // 0.10
    #[serde(default = "default_risk_weight_trend")]
    pub risk_weight_trend: f64,                // 0.15

    // Confidence thresholds
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,        // 0.85
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,      // 0.60
}
```

### 6.4 Stateful Detector with Welford's Algorithm (Rust Port)

The detector maintains per-node state with running statistics, matching Sentinel's approach:

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Per-node running statistics using Welford's online algorithm.
#[derive(Debug, Clone, Default)]
struct NodeStats {
    samples: usize,
    cpu_temp: WelfordAccumulator,
    cpu_usage: WelfordAccumulator,
    mem_usage: WelfordAccumulator,
    load_avg: WelfordAccumulator,
    disk_io_latency: WelfordAccumulator,
    net_latency: WelfordAccumulator,
    history: Vec<InfrastructureMetricsView>,  // bounded ring buffer
}

/// Welford's online mean/variance accumulator.
#[derive(Debug, Clone, Default)]
struct WelfordAccumulator {
    n: u64,
    mean: f64,
    m2: f64,   // sum of squared deviations
}

impl WelfordAccumulator {
    fn update(&mut self, value: f64) {
        self.n += 1;
        let delta = value - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(&self) -> f64 {
        if self.n < 2 { return 0.0; }
        self.m2 / self.n as f64
    }

    fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    fn z_score(&self, value: f64) -> f64 {
        let sd = self.std_dev();
        if sd < f64::EPSILON { return 0.0; }
        (value - self.mean) / sd
    }
}
```

**Key difference from Sentinel's implementation**: Sentinel stores `std` directly, whereas our Rust port stores `m2` (the sum of squared deviations) and derives std on demand. This is more numerically precise for the variance computation and avoids a sqrt on every update. The sqrt is only computed when a z-score is actually needed.

### 6.5 Detection Logic

The `evaluate` implementation follows a four-phase pipeline:

1. **Update statistics**: Feed the new metric sample into all per-node Welford accumulators.
2. **Individual domain evaluation**: Compute thermal, memory, CPU, disk, network, and trend risk scores using Sentinel-equivalent piecewise linear functions and z-score anomaly tests.
3. **Compound rule matching**: Apply the compound rules from Section 5.3 over the individual domain results, boosting confidence when multiple domains align with a known attack pattern.
4. **Sensor tampering detection**: If previously-available metrics disappear, emit a `ThreatClass::DefenseEvasion` finding.

The detector skips evaluation when `node_stats.samples < min_samples` (default 30), returning an empty findings vec. This mirrors Sentinel's `len(p.history) < 10` guard, adjusted upward because the security application requires a more stable baseline.

### 6.6 Sentinel Bridge: Direct Prediction Passthrough

When Sentinel is co-deployed, its pre-computed predictions can be consumed directly. If `sentinel_failure_probability` is present and exceeds 0.3, the detector creates a finding with confidence scaled to `sentinel_confidence * 0.8` (infrastructure confidence does not map 1:1 to security confidence). The `sentinel_reasons` vector is classified against the mapping table in Section 5.2 to determine the primary `ThreatClass`.

---

## 7. False Positive Mitigation

The detector design above is complete, but infrastructure anomalies are noisy by nature. This section addresses the central engineering challenge: keeping false positives below the 5% target (Section 12) while maintaining detection sensitivity.

### 7.1 The Core Challenge

Infrastructure anomalies are not inherently malicious. Legitimate scenarios that produce Sentinel-flagged anomalies include:

| Legitimate Scenario | Infrastructure Signal | Security Misclassification Risk |
|---|---|---|
| CI/CD build spike | CPU saturation, thermal rise | Cryptominer false positive |
| Memory-intensive batch job | Memory pressure, swap usage | Fork bomb false positive |
| Large backup operation | Disk I/O critical, network high | Ransomware / exfil false positive |
| Pod autoscaling event | CPU/memory spikes, load anomaly | Multiple false positives |
| Node drain / cordon | Memory pressure, OOM events | Impact false positive |
| Garbage collection pause | CPU spike, memory churn | Execution false positive |

### 7.2 Contextual Gating

The primary mitigation is contextual gating: infrastructure signals should only be promoted to security findings when corroborated by additional context.

**Kubernetes context enrichment**: A `K8sContext` struct tracks recent scale events, draining nodes, active CronJobs, and CI runner node labels. This context can be populated from Sentinel's existing K8s client (`pkg/k8s/client.go`), which already watches the API server for node and pod events. The detector suppresses findings during intentional scaling and node drains, and reduces confidence (but does not suppress) for CI runner nodes, which are legitimate high-resource consumers but also attractive supply-chain attack targets.

### 7.3 Temporal Correlation Windows

Legitimate workload changes are typically correlated with observable cluster events. We define a temporal gating window:

```
LEGITIMATE_WINDOW = 120 seconds

If (infrastructure_anomaly.timestamp - last_scale_event.timestamp) < LEGITIMATE_WINDOW:
    confidence *= 0.3  // Heavy suppression
    add_reason("correlated_with_scale_event")
```

This exploits the fact that legitimate workload changes are preceded by orchestration events (kubectl scale, HPA decisions, CronJob triggers), whereas malicious resource consumption appears without warning.

### 7.4 Workload Profiling and Baseline Classes

Different node types have fundamentally different baselines. A `NodeProfile` enum (GeneralPurpose, ComputeIntensive, StorageIntensive, EdgeConstrained) defines expected ranges per metric domain. While Welford's algorithm naturally adapts to each node's baseline, explicit profiles allow the detector to set appropriate z-score thresholds: a compute-intensive node at 90% CPU is normal, but an edge node at 90% CPU is alarming.

### 7.5 Pheromone Concentration as FP Filter

The swarm's stigmergic architecture provides an elegant false positive filter. An infrastructure anomaly deposited as a lone pheromone will evaporate (decay) without triggering escalation, because the pheromone substrate requires both concentration strength and source diversity:

```rust
// From crates/swarm-core/src/pheromone.rs
impl PheromoneConcentration {
    pub fn exceeds_threshold(&self, strength_threshold: f64, min_sources: usize) -> bool {
        self.total_strength >= strength_threshold && self.distinct_sources >= min_sources
    }
}
```

The `min_sources_for_escalation` (default: 2) means a single infrastructure detector cannot trigger escalation alone. It requires at least one corroborating signal from a different agent (e.g., a `SuspiciousProcessTreeDetector` seeing an anomalous process tree, or a `DnsExfiltrationDetector` seeing tunneling). This is the key architectural advantage of the swarm approach: **false positives are structurally suppressed by requiring independent corroboration**.

### 7.6 Confidence Scaling Formula

The final confidence for an infrastructure-derived security finding is:

```
C_final = C_base * C_infra * C_context * C_compound

where:
  C_base     = base confidence from Sentinel risk score mapping
  C_infra    = 1.0 - (missing_metrics / total_metrics) * 0.5
  C_context  = 0.3 if correlated with K8s scaling event, else 1.0
  C_compound = min(1.5, 1.0 + 0.3 * matched_compound_rules)
```

Note that `C_compound` can push the product above `C_base` when multiple compound rules match, reflecting increased certainty from pattern convergence. The 1.5 cap prevents overconfidence from stacking.

---

## 8. Time-Series Analysis Techniques for Dual-Domain Detection

### 8.1 Limitations of Welford's for Security Applications

While Welford's online algorithm is excellent for infrastructure failure prediction (where you want a global baseline), security applications need to detect recent deviations without the new behavior being absorbed into the baseline. Three techniques address this.

### 8.2 Exponentially Weighted Moving Average (EWMA)

EWMA gives exponentially decaying weight to older observations:

```
EWMA_t = alpha * x_t + (1 - alpha) * EWMA_{t-1}
```

where `alpha` is the smoothing factor (higher alpha = more responsive to recent changes).

For security applications, we use a dual-EWMA approach:

```rust
struct DualEwma {
    /// Slow EWMA (alpha=0.01): represents the long-term baseline.
    slow: f64,
    /// Fast EWMA (alpha=0.1): represents recent behavior.
    fast: f64,
}

impl DualEwma {
    fn update(&mut self, value: f64) {
        self.slow = 0.01 * value + 0.99 * self.slow;
        self.fast = 0.10 * value + 0.90 * self.fast;
    }

    /// Divergence between fast and slow: positive means recent values
    /// are higher than the long-term baseline.
    fn divergence(&self) -> f64 {
        self.fast - self.slow
    }

    /// Normalized divergence as a fraction of the slow baseline.
    fn relative_divergence(&self) -> f64 {
        if self.slow.abs() < f64::EPSILON {
            return 0.0;
        }
        (self.fast - self.slow) / self.slow
    }
}
```

**Security application**: A cryptominer will cause `fast` CPU EWMA to diverge sharply from `slow` within minutes, while Welford's global mean would take much longer to register the anomaly. A relative divergence > 0.5 (50% above long-term baseline) with sustained duration > 60 seconds is a strong signal.

### 8.3 CUSUM (Cumulative Sum) Change-Point Detection

CUSUM detects shifts in the mean of a process:

```
S_t^+ = max(0, S_{t-1}^+ + (x_t - mu_0 - k))   (upper CUSUM: detects upward shifts)
S_t^- = max(0, S_{t-1}^- + (mu_0 - k - x_t))   (lower CUSUM: detects downward shifts)
```

where `mu_0` is the target mean, `k` is the allowance parameter (typically `0.5 * delta` where `delta` is the minimum shift worth detecting), and an alarm is raised when either `S_t^+` or `S_t^-` exceeds the decision threshold `h`.

```rust
struct CusumDetector {
    /// Target mean (estimated from Welford's running mean).
    mu_0: f64,
    /// Allowance parameter: minimum shift worth detecting.
    k: f64,
    /// Decision threshold: alarm when exceeded.
    h: f64,
    /// Upper cumulative sum.
    s_upper: f64,
    /// Lower cumulative sum.
    s_lower: f64,
}

impl CusumDetector {
    fn update(&mut self, value: f64) -> Option<CusumAlarm> {
        self.s_upper = (self.s_upper + (value - self.mu_0 - self.k)).max(0.0);
        self.s_lower = (self.s_lower - (value - self.mu_0 + self.k)).max(0.0);

        if self.s_upper > self.h {
            Some(CusumAlarm::PositiveShift { magnitude: self.s_upper })
        } else if self.s_lower > self.h {
            Some(CusumAlarm::NegativeShift { magnitude: self.s_lower })
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.s_upper = 0.0;
        self.s_lower = 0.0;
    }
}
```

**Security application**: CUSUM is optimal for detecting persistent shifts -- exactly the pattern produced by a cryptominer or memory-resident malware that establishes a new, sustained resource consumption level. Unlike z-scores (which detect instantaneous deviation) or EWMA (which adapts to the new level), CUSUM accumulates evidence of sustained deviation and alarms when sufficient evidence has accumulated.

**Tuning guidance**:

| Metric | k (allowance) | h (threshold) | Detects |
|---|---|---|---|
| CPU temp | 2.0 degrees | 15.0 | Sustained thermal rise of 4+ degrees |
| Memory % | 3.0% | 20.0 | Sustained memory increase of 6+% |
| Load avg | 0.5 * std | 10.0 * std | Sustained load anomaly |
| Disk I/O latency | 5.0 ms | 30.0 | Sustained I/O degradation |
| Network latency | 10.0 ms | 50.0 | Sustained network anomaly |

### 8.4 Bayesian Online Changepoint Detection (BOCPD)

For high-security environments, BOCPD provides probabilistic changepoint estimation using `P(r_t | x_{1:t})` where `r_t` is the run length since last changepoint. It offers probability-of-changepoint (vs. binary alarm), automatic reset after changepoints, and multi-scale detection of both gradual and abrupt changes. A simplified variant with a normal-inverse-gamma conjugate prior runs in O(R) where R is the maximum run length.

### 8.5 Recommended Technique Selection

| Scenario | Recommended Technique | Rationale |
|---|---|---|
| Edge nodes (resource-constrained) | Welford's + EWMA | Low compute overhead, good detection |
| General K8s nodes | EWMA + CUSUM | Best balance of sensitivity and specificity |
| High-security environments | EWMA + CUSUM + BOCPD | Maximum detection capability |
| Sentinel passthrough mode | Sentinel predictions only | Zero additional compute overhead |

### 8.6 Integration with Welford's Baseline

All three techniques benefit from Welford's running statistics as a baseline:

```rust
struct IntegratedAnomalyState {
    /// Welford's: provides global mean and std for z-scores.
    welford: WelfordAccumulator,
    /// EWMA: provides recency-weighted baseline for divergence detection.
    ewma: DualEwma,
    /// CUSUM: accumulates evidence of sustained shifts.
    cusum: CusumDetector,
}

impl IntegratedAnomalyState {
    fn update(&mut self, value: f64) -> AnomalySignals {
        self.welford.update(value);
        self.ewma.update(value);

        // Update CUSUM target mean from Welford's (slowly adapting)
        if self.welford.n > 100 {
            self.cusum.mu_0 = self.welford.mean;
        }

        AnomalySignals {
            z_score: self.welford.z_score(value),
            ewma_divergence: self.ewma.relative_divergence(),
            cusum_alarm: self.cusum.update(value),
        }
    }
}
```

---

## 9. Case Studies: Real-World Attacks Detectable Through Infrastructure Anomalies

### 9.1 Case Study: Monero Cryptominer on Edge Kubernetes Cluster

**Scenario**: Attacker compromises a container image registry and injects a Monero miner (XMRig variant) into a sidecar container. The miner runs as a legitimate-looking process (`kube-proxy-helper`) to evade process name detection.

**Behavioral detection evasion**:
- Process name mimics a Kubernetes component.
- Binary is not signature-matched (custom build).
- No suspicious parent-child relationship.
- Network traffic is encrypted (TLS to mining pool on port 443).

**Infrastructure signal timeline**:

```
T+0s:    Miner starts. No immediate anomaly.
T+5s:    CPU usage jumps from 25% to 97%.
T+10s:   Load average z-score exceeds 3.0.
T+30s:   CPU temperature rises from 52C to 68C.
T+60s:   Thermal trend slope = 0.27 deg/sample (CRITICAL).
T+90s:   CPU throttling engaged.
T+120s:  EWMA divergence on CPU = +0.72 (72% above baseline).
T+180s:  CUSUM upper sum exceeds threshold on CPU, temperature, and load.
```

**Sentinel prediction at T+60s**:
```json
{
    "failure_probability": 0.62,
    "confidence": 0.80,
    "reasons": [
        "cpu_temp_elevated",
        "cpu_saturated",
        "load_anomaly",
        "thermal_trend_rising"
    ]
}
```

**InfrastructureAnomalyDetector findings**:

1. Individual: `ThreatClass::Execution`, confidence 0.55 (CPU saturation alone).
2. Individual: `ThreatClass::Execution`, confidence 0.50 (thermal anomaly alone).
3. **Compound rule CRYPTOMINER_SIGNATURE matched**: confidence boosted to 0.78.

**Pheromone interaction**: The infrastructure pheromone deposit (confidence 0.78) combines with a concurrent `NetworkConnectEvent` deposit from a network detector noticing a new outbound TLS connection to an IP in a known mining pool range. Two distinct sources now contribute to the `ThreatClass::Execution` concentration, potentially triggering escalation from Normal to Alert mode.

### 9.2 Case Study: Memory-Resident Fileless Malware

**Scenario**: Adversary exploits a deserialization vulnerability in a Java application pod. The payload runs entirely in memory, injecting shellcode into the JVM heap. No file is written to disk.

**Behavioral detection evasion**:
- No new process created (runs within existing JVM).
- No file system artifacts.
- Network C2 uses DNS over HTTPS (DoH), blending with legitimate DNS traffic.

**Infrastructure signal timeline**:

```
T+0s:    Exploit fires. JVM heap grows by 200MB.
T+5s:    Memory usage jumps from 62% to 71%.
T+30s:   Memory trend slope = 0.3 %/sample.
T+60s:   Swap usage increases (JVM old-gen GC pressure).
T+120s:  Memory stabilizes at 73% (payload loaded).
T+300s:  Memory usage slowly climbs to 78% (payload data accumulation).
T+600s:  Memory z-score = 2.4 (elevated but not critical).
```

**Key insight**: The initial memory jump is the strongest signal. EWMA captures this as a divergence event, while Welford's z-score only reaches 2.4 because the global mean adapts. CUSUM is the ideal detector here because it accumulates evidence of the sustained shift.

**InfrastructureAnomalyDetector findings**:
- `ThreatClass::Execution` at T+5s (memory spike).
- `ThreatClass::Persistence` at T+300s (sustained memory trend).

**Cross-detector correlation**: When the `DnsExfiltrationDetector` simultaneously flags high-entropy DNS queries (DoH tunneling), the compound pheromone concentration for `Execution` + `DataExfiltration` triggers Alert mode.

### 9.3 Case Study: Slow Data Exfiltration via Disk Staging

**Scenario**: Insider threat or APT stages sensitive data to a local directory, compresses it, and exfiltrates via slow HTTPS uploads (100KB/min to avoid bandwidth-based detection).

**Behavioral detection evasion**:
- Data staging uses standard `tar` and `gzip` (LOLBins).
- Exfiltration rate is below typical bandwidth anomaly thresholds.
- Destination is a legitimate cloud storage endpoint (S3 bucket).

**Infrastructure signal timeline**:

```
T+0:     Staging begins. Disk I/O read spikes (reading source files).
T+60s:   Disk I/O write spikes (writing tar archive).
T+120s:  Disk usage increases by 2GB (staged archive).
T+180s:  Exfiltration begins. Network TX increases by ~1.7KB/s.
T+300s:  Disk I/O read latency increases (compression reads + normal workload).
```

**Detection challenge**: Each individual metric is within normal ranges. Disk I/O latency of 25ms is "elevated" but not "critical." Network TX of 1.7KB/s is negligible.

**Compound detection opportunity**: The temporal pattern -- disk read spike followed by disk write spike followed by sustained network TX increase -- is distinctive. A `SequentialPattern` matcher tracks ordered stage transitions (disk-read EWMA divergence, then disk-write EWMA divergence, then network-TX CUSUM alarm) within a bounded window (600s). If all three stages fire in order, a high-confidence `DataExfiltration` finding is emitted.

### 9.4 Case Study: Disk Wiper / Ransomware

**Scenario**: Ransomware payload activates on multiple nodes simultaneously after a dormancy period. It encrypts files using AES-256 in CBC mode, generating heavy CPU and disk I/O.

**Infrastructure signal timeline** (all nodes simultaneously):

```
T+0s:    Encryption begins.
T+2s:    Disk I/O write throughput: 500MB/s (saturating NVMe).
T+5s:    CPU usage: 85% (AES encryption).
T+10s:   Disk I/O latency: 150ms (queue depth saturation).
T+15s:   CPU temperature: 72C (climbing from 50C baseline).
T+30s:   Disk usage climbing rapidly (encrypted copies alongside originals).
T+60s:   Multiple nodes report identical patterns (CUSUM alarm on all).
```

**The multi-node signal**: Multiple nodes exhibiting the same anomaly pattern simultaneously is vanishingly unlikely for legitimate workloads (which scale gradually, not atomically). Sentinel's Raft-lite consensus layer (`pkg/consensus/raft_lite.go`) currently handles autonomous decision-making during partitions (pod rescheduling, node cordoning). We propose extending it with threat-correlation semantics: when > N/2 nodes report `FailureProbability > 0.7` with overlapping reason tags within a 30-second window, a fleet-wide `ThreatClass::Impact` signal would be emitted with confidence 0.95. See [Doc 01](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) for the consensus primitives this builds on.

### 9.5 Case Study: Container Escape via Kernel Exploit

**Scenario**: Attacker exploits a container runtime vulnerability to escape the container sandbox and gain host-level access. The exploit involves triggering a kernel code path that corrupts memory and provides arbitrary read/write.

**Infrastructure signals**:
- Brief CPU spike during exploit execution (kernel time).
- Memory anomaly from kernel heap manipulation.
- Potential kernel panic avoidance behavior (unusual syscall patterns).
- Post-escape: new processes visible at the host level that don't belong to any pod.

**Sentinel reasons**: `cpu_temp_rising`, `load_anomaly` (brief), `memory_pressure` (brief).

**Challenge**: The infrastructure signals are transient (seconds, not minutes). This requires the detector to capture and report brief anomaly spikes before they are smoothed away by running averages.

**Solution**: Maintain a `PeakDetector` alongside the running statistics that tracks the maximum z-score within a sliding window (e.g., 30 seconds). The peak detector uses a `VecDeque<(timestamp, z_score)>`, evicting entries older than the window on each update and returning the maximum. This captures brief exploit-phase anomalies that would be smoothed away by running averages.

---

## 10. Integration with the Pheromone Substrate

### 10.1 Pheromone Decay Model Alignment

The swarm's pheromone decay model uses exponential half-life decay:

```rust
// From crates/swarm-core/src/pheromone.rs
pub fn strength_at(&self, now: i64) -> f64 {
    if now <= self.timestamp {
        return self.confidence;
    }
    let elapsed = (now - self.timestamp) as f64;
    self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life)
}
```

This produces:

```
strength(t) = confidence * 2^(-(t - t_0) / t_half)
```

For infrastructure signals, we need to tune the half-life based on the attack class:

| Attack Temporal Profile | Recommended Half-Life | Rationale |
|---|---|---|
| Cryptomining (persistent) | 3600s (1 hour) | Long-running; signal should persist |
| Fork bomb (acute) | 300s (5 min) | Resolved quickly; signal fades fast |
| Data exfiltration (slow) | 7200s (2 hours) | Low confidence per sample; accumulates slowly |
| Ransomware (acute, critical) | 1800s (30 min) | Critical but time-bounded event |
| Fileless malware (persistent) | 3600s (1 hour) | Long-running; may go dormant |
| Sensor tampering | 600s (10 min) | May be transient; should not linger |

These can be configured via the `ThreatClassConfig` mechanism in the pheromone substrate:

```rust
// Per-threat-class pheromone configuration
pub struct ThreatClassConfig {
    pub threat_class: ThreatClass,
    pub half_life_secs: f64,
    pub evaporation_threshold: f64,
    pub alert_threshold: f64,
    pub incident_threshold: f64,
}
```

### 10.2 Source Diversity and Anti-Flooding

The pheromone substrate enforces source diversity via `min_sources_for_escalation`. The existing `strategy_scoped_agent_id()` in `stream.rs` produces IDs of the form `{base}:{strategy_id}` (e.g., `whisker-01:infrastructure_anomaly`). For the infrastructure detector, we propose extending this with domain-level sub-scoping (e.g., `whisker-01:infrastructure_anomaly:thermal`) to support per-domain correlation queries. However, to prevent a single infrastructure agent from flooding the substrate, **all `infrastructure_anomaly:*` sub-IDs from the same base agent must count as ONE logical source** for concentration thresholds. This ensures infrastructure signals require corroboration from a non-infrastructure detector (process tree, DNS, lateral movement, etc.) to trigger escalation.

### 10.3 Concentration Compounding

The real power of the convergence is concentration compounding. Consider a scenario where:

1. `InfrastructureAnomalyDetector` deposits a pheromone for `ThreatClass::Execution` with confidence 0.6 (thermal + CPU anomaly suggesting cryptomining).

2. `SuspiciousProcessTreeDetector` deposits a pheromone for `ThreatClass::Execution` with confidence 0.7 (unexpected child process of a container entrypoint).

The pheromone concentration for `ThreatClass::Execution` is now:

```
total_strength = 0.6 * decay(t1) + 0.7 * decay(t2)
distinct_sources = 2 (infra + process detector)
```

With default thresholds (`alert_threshold = 2.0`, `incident_threshold = 5.0`, `min_sources_for_escalation = 2`), the source diversity requirement is met (two distinct detector families), but the combined strength (~1.3 before decay) remains below the alert threshold. A third corroborating signal -- say, a `CredentialAccessDetector` finding related to the same host -- would push total strength above 2.0 and trigger Alert mode. The key insight is that **no single signal alone triggers escalation**, and even a two-source compound requires sustained or replicated evidence to reach the threshold.

### 10.4 Escalation Flow

The flow is: **Sentinel Collector/Predictor** -> **InfrastructureAnomalyDetector** -> **Pheromone Substrate**. In parallel, **eBPF/Tetragon** -> **Process/Network/DNS Detectors** -> **Pheromone Substrate**. The substrate aggregates concentration per `ThreatClass`, and when `total_strength >= alert_threshold AND distinct_sources >= 2`, triggers a `SwarmMode` transition (Normal -> Alert -> Incident).

### 10.5 Pheromone Deposit Construction

Infrastructure findings are converted to `PheromoneDeposit` via `findings_to_deposits()` from `swarm-whisker/src/stream.rs`. Currently, that function unconditionally uses `pheromone.default_half_life_secs` for every deposit. For infrastructure signals, we propose a modification: the `decay_half_life` should be set to the attack-specific half-life from the table in [Section 10.1](#101-pheromone-decay-model-alignment), resolved through the existing `ThreatClassConfig` override mechanism, rather than the global default. The deposit's `indicator` JSON should also include a `"sentinel_integration": true` flag and the originating `node_name` to support fleet-wide correlation queries.

---

## 11. Prototype Implementation Sketches

### 11.1 Sentinel Metrics Ingestion Bridge

A `SentinelBridge` struct implements the `TelemetryBridge` trait, polling
Sentinel's prediction API (`:9101`) and metrics endpoint (`:9100`). In the
canonical series design from [Doc 05](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md),
it converts Sentinel output into `TelemetryEvent` instances carrying
`InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion` payloads.
The bridge reports health via `BridgeHealth::record_event()` on each successful
poll.

For detector logic that benefits from a single aggregate view, a normalization
step can map those payloads into the `InfrastructureMetricsView` struct shown in
Section 6.2. For environments exposing only Prometheus metrics, a scrape
adapter maps the `sentinel_*` metric family (defined in
`pkg/metrics/exporter.go`) -- including
`sentinel_cpu_temperature_celsius`, `sentinel_prediction_failure_probability`,
and `sentinel_prediction_confidence` -- into that internal view.

### 11.2 Configuration Integration

The `InfrastructureAnomalyDetector` integrates with swarm-team-six's `DetectionConfig`. The existing `DetectorProfilesConfig` struct (`crates/swarm-core/src/config.rs`) has one `Option<serde_json::Value>` field per detector family. Adding `infrastructure_anomaly` follows the same pattern:

```yaml
# swarm-config.yaml (excerpt)
detection:
  strategy: suspicious_process_tree
  strategies:
    - suspicious_process_tree
    - dns_exfiltration
    - lateral_movement
    - credential_access
    - persistence
    - supply_chain
    - suspicious_scripting
    - network_connect
    - infrastructure_anomaly          # NEW
  high_confidence_threshold: 0.9
  medium_confidence_threshold: 0.7
  profiles:
    # NEW: Infrastructure anomaly detection profile
    infrastructure_anomaly:
      min_samples: 30
      max_history: 1000
      zscore_warning: 2.0
      zscore_critical: 3.0
      thermal_critical_celsius: 85.0
      memory_critical_percent: 95.0
      enable_compound_rules: true
      risk_weight_thermal: 0.30
      risk_weight_memory: 0.20
      risk_weight_cpu: 0.15
      risk_weight_disk: 0.10
      risk_weight_network: 0.10
      risk_weight_trend: 0.15
```

---

## 12. Evaluation Framework and Benchmarks

The metrics and outcome tables in this section are **targets for validation**,
not measured baselines from the current repo state.

### 12.1 Detection Efficacy Metrics

| Metric | Definition | Target |
|---|---|---|
| True Positive Rate (TPR) | Attacks correctly detected via infra signals | > 0.80 |
| False Positive Rate (FPR) | Benign events flagged as threats | < 0.05 |
| Mean Time to Detect (MTTD) | Time from attack start to first finding | < 120s |
| Compound Lift | TPR improvement when infra signals are combined with behavioral | > 1.3x |
| Evasion Resistance | Fraction of evasion-optimized attacks still detected | > 0.60 |

### 12.2 Synthetic Attack Benchmark Suite

The benchmark suite defines eight scenarios: Cryptominer (CPU 98%, thermal slope 0.3deg/s), ForkBomb (memory 60->99% in 10s), BulkExfiltration (500MB disk read + 5MB/s TX), SlowExfiltration (2KB/s TX for 1h), Ransomware (500MB/s disk write, 85% CPU), FilelessMalware (15% memory increase, no I/O), plus two legitimate baselines (CI build spike, backup operation) to measure false positive rates.

### 12.3 Performance Budget

For edge deployment, the `InfrastructureAnomalyDetector` must fit within Sentinel's existing performance constraints:

| Operation | Budget | Notes |
|---|---|---|
| Per-event evaluation | < 50 microseconds | Must not exceed agent tick timeout |
| Memory per node | < 200 KB | Welford state + history buffer |
| Peak allocation | < 1 MB | During trend analysis window |
| CUSUM update | < 1 microsecond | Trivial arithmetic |
| EWMA update | < 1 microsecond | Trivial arithmetic |

The Sentinel collector already operates at ~1ms per collection cycle. The detector must not double this budget.

### 12.4 Expected Detection Matrix

The matrix below is an **expected validation hypothesis** for benchmark design.

| Attack Type | Infra-Only Detection | Behavioral-Only Detection | Combined Detection |
|---|---|---|---|
| Cryptominer (known binary) | 0.75 | 0.90 | 0.98 |
| Cryptominer (unknown binary) | 0.75 | 0.20 | 0.85 |
| Fork bomb | 0.90 | 0.40 | 0.95 |
| Bulk exfiltration | 0.60 | 0.70 | 0.90 |
| Slow exfiltration | 0.15 | 0.50 | 0.55 |
| Ransomware | 0.85 | 0.75 | 0.98 |
| Fileless malware | 0.40 | 0.30 | 0.60 |
| Container escape | 0.30 | 0.65 | 0.80 |
| Sensor tampering | 0.95 | 0.00 | 0.95 |

The critical row is "Cryptominer (unknown binary)": behavioral detection alone achieves only 0.20 (no signature match, clean process tree), but infrastructure signals push combined detection to 0.85. This is the primary value proposition of the convergence.

---

## 13. Open Questions and Future Work

### 13.1 Adaptive Weight Learning

Sentinel's risk weights are static. A natural extension is to learn optimal weights from labeled data:

```
w* = argmin_w sum_i L(y_i, f(x_i; w)) + lambda * ||w||_2
```

where `y_i` is the true label (attack/benign) and `f(x_i; w)` is the weighted risk score. This could be implemented as online gradient descent on the weight vector, with the constraint that weights sum to 1.0.

### 13.2 Cross-Node Correlation in the Pheromone Substrate

The current design treats each node independently. Fleet-wide attacks (like the ransomware case study) require cross-node correlation. One approach is a "fleet pheromone" that aggregates signals from multiple `InfrastructureAnomalyDetectors` deployed on different nodes:

```
fleet_concentration(threat_class) = sum over nodes of node_concentration(threat_class)
```

This requires extending the pheromone substrate's query model with a spatial dimension (node identity).

### 13.3 Additional Research Directions

- **GPU and accelerator metrics**: Extending Sentinel's collector with GPU temperature/utilization would improve detection of GPU-targeted cryptomining.
- **eBPF integration**: The `swarm-ingest-tetragon` crate already bridges Tetragon eBPF events; extending this to capture infrastructure metrics at kernel level would unify the collection path and reduce polling latency. See [Doc 05](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md) for the bridge abstraction this would plug into.
- **Formal compound rule verification**: Decision tree induction over labeled attack datasets could automatically discover optimal compound rules and verify them against false positive corpora.
- **Privacy and multi-tenancy**: Namespace-scoped metric collection and pheromone deposit tagging are needed for multi-tenant Kubernetes clusters.
- **Circuit breaker integration**: Sentinel's `CircuitBreaker` state transitions (open = control plane unreachable) are themselves security-relevant signals (`ThreatClass::CommandAndControl`). See [Doc 08](./08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) for the resilience patterns this connects to.
- **Consensus-level threat signaling**: Sentinel's Raft-lite consensus could propagate threat signals between nodes, extending the pheromone substrate across the physical cluster during network partitions. See [Doc 01](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) and [Doc 04](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) for the consensus and partition-response foundations.

---

## 14. References

### 14.1 Sentinel Source References

- `playground/sentinel/pkg/healthscore/predictor.go` -- Core prediction engine
- `playground/sentinel/pkg/collector/collector.go` -- Linux procfs/sysfs metric collection
- `playground/sentinel/pkg/config/config.go` -- Configuration schema and validation
- `playground/sentinel/pkg/metrics/exporter.go` -- Prometheus metric definitions
- `playground/sentinel/pkg/k8s/circuit_breaker.go` -- Circuit breaker for API resilience
- `playground/sentinel/pkg/consensus/raft_lite.go` -- Raft-inspired consensus

### 14.2 swarm-team-six Source References

- `crates/swarm-core/src/pheromone.rs` -- ThreatClass, PheromoneDeposit, decay model
- `crates/swarm-core/src/agent.rs` -- SwarmAgent trait, AgentRole, SwarmMode
- `crates/swarm-core/src/types.rs` -- SwarmAction, Severity, ResponseAction
- `crates/swarm-core/src/verdict.rs` -- ThreatVerdict, ConsensusResult
- `crates/swarm-core/src/config.rs` -- SwarmConfig, PheromoneConfig
- `crates/swarm-core/src/telemetry.rs` -- TelemetryEvent, TelemetryPayload
- `crates/swarm-whisker/src/detector.rs` -- DetectionStrategy trait, DetectionFinding
- `crates/swarm-whisker/src/stream.rs` -- Stream processing, deposit construction
- `crates/swarm-pheromone/src/substrate.rs` -- PheromoneSubstrate trait

### 14.3 Academic and Industry References

1. Welford, B.P. (1962). "Note on a method for calculating corrected sums of squares and products." *Technometrics* 4(3).
2. Page, E.S. (1954). "Continuous inspection schemes." *Biometrika* 41(1/2). [CUSUM]
3. Roberts, S.W. (1959). "Control chart tests based on geometric moving averages." *Technometrics* 1(3). [EWMA]
4. Adams, R.P. and MacKay, D.J. (2007). "Bayesian online changepoint detection." *arXiv:0710.3742*.
5. MITRE ATT&CK: T1496, T1048, T1486, T1499, T1055, T1611, T1562, T1071, T1068, T1070.
6. Dorigo, M. and Stutzle, T. (2004). *Ant Colony Optimization*. MIT Press.

---

## Cross-References

This document is part 2 of 8 in the **Sentinel Convergence** research series.

| Doc | Title | Relevance to This Document |
|-----|-------|---------------------------|
| [01](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Distributed Consensus for Agent Swarms | Consensus primitives underpinning the fleet-wide threat signaling proposed in Section 9.4 and Section 13.3 |
| [03](./03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge-Native Security Detection | Extends the edge-constrained detection model; shares the performance budget constraints from Section 12.3 |
| [04](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | Autonomous Response Under Partition | Defines what happens after this document's detector triggers an escalation during a network partition |
| [05](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Telemetry Bridge Architecture | Details the `SentinelBridge` implementation sketched in Section 11.1 |
| [06](./06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Stigmergic Coordination and Swarm Intelligence | Formalizes the pheromone concentration compounding model used in Section 10 |
| [07](./07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Audit Trails and Decision Reconciliation | Covers how infrastructure-derived findings are recorded for post-incident review |
| [08](./08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Resilience Patterns for Distributed Agents | Addresses circuit-breaker and graceful-degradation patterns referenced in Sections 4.3 and 13.3 |
