---
title: "06 -- Behavioral Baseline and Anomaly Detection Approaches"
series: Swarm Hardening (6 of 8)
version: "0.1"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# 06 -- Behavioral Baseline and Anomaly Detection Approaches

> **Scope**: Designing a behavioral baseline layer for swarm-team-six that
> complements the existing rule/pattern-based detection pipeline. This document
> surveys statistical approaches suitable for streaming detection in Rust,
> proposes concrete detector designs that integrate with the `CompositeDetector`
> framework and pheromone substrate, and addresses the practical challenges of
> cold start, drift, memory efficiency, and anomaly scoring.

> **Series Note**
> - Behavioral baselines are a v1.42+ roadmap capability. This document is
>   forward-looking research, not an accepted execution plan.
> - The sentinel-convergence series (Doc 02) already covers Welford's algorithm
>   for infrastructure signal baselines. This document extends that work to
>   process, network, and authentication telemetry domains.
> - Quantitative values in Sections 11 and 13 are design targets and validation
>   hypotheses unless explicitly measured.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Motivation: The Unknown-Unknown Problem](#2-motivation-the-unknown-unknown-problem)
3. [Statistical Approaches Comparison](#3-statistical-approaches-comparison)
4. [Process Behavior Profiling](#4-process-behavior-profiling)
5. [Network Traffic Baselines](#5-network-traffic-baselines)
6. [User Entity Behavior Analytics (UEBA)](#6-user-entity-behavior-analytics-ueba)
7. [Cold-Start Problem](#7-cold-start-problem)
8. [Drift Detection](#8-drift-detection)
9. [Memory-Efficient Implementations](#9-memory-efficient-implementations)
10. [Integration with Current Architecture](#10-integration-with-current-architecture)
11. [Anomaly Scoring](#11-anomaly-scoring)
12. [Proposed Detector Designs](#12-proposed-detector-designs)
13. [Evaluation Methodology](#13-evaluation-methodology)
14. [Open Questions and Future Work](#14-open-questions-and-future-work)
15. [Cross-References](#15-cross-references)
16. [References](#16-references)

---

## 1. Abstract

Swarm Team Six currently deploys eight pattern-based detectors in the
`swarm-whisker` crate: `SuspiciousProcessTreeDetector`, `DnsExfiltrationDetector`,
`LateralMovementDetector`, `NetworkConnectDetector`, `PersistenceDetector`,
`SupplyChainDetector`, `SuspiciousScriptingDetector`, and
`CredentialAccessDetector`. Each encodes expert knowledge about specific attack
patterns -- suspicious parent-child process relationships, high-entropy DNS
subdomains, known remote-execution indicators, beacon interval regularity,
registry run-key writes, unsigned trusted-path execution, encoded PowerShell
arguments, and LSASS memory access.

These detectors are effective against **known** attack patterns. They are fast,
deterministic, and produce low false-positive rates when well-tuned. But they
share a fundamental limitation: they cannot detect what they were not designed
to detect. An adversary who uses a novel execution technique, a previously
unseen exfiltration channel, or a new credential-harvesting tool will evade
every rule in the current pipeline.

This document proposes a complementary **behavioral baseline** detection layer
that learns what "normal" looks like for each observed entity (process, host,
user, service) and flags statistically significant deviations. The approach
trades the precision of rule-based detection for the breadth of anomaly-based
detection, creating a defense-in-depth architecture where rule detectors catch
known attacks with high confidence and baseline detectors surface unknown
anomalies for investigation.

We survey streaming statistical algorithms suitable for Rust implementation
with bounded memory, propose three concrete baseline detectors
(`ProcessBaselineDetector`, `NetworkBaselineDetector`, `AuthBaselineDetector`),
and describe how baseline-derived signals integrate with the pheromone
substrate's concentration dynamics to produce compound detection patterns.

---

## 2. Motivation: The Unknown-Unknown Problem

### 2.1 Rule-Based Detection Coverage Gaps

The eight detectors enumerated in Section 1 cover seven MITRE ATT&CK tactic
categories (Execution, Exfiltration, C2, Lateral Movement, Persistence,
Defense Evasion, Credential Access). Each encodes a finite set of heuristics. The
`SuspiciousProcessTreeDetector`, for example, maintains two lists --
`suspicious_parents` (winword, excel, outlook, acrord32, teams) and
`suspicious_children` (powershell, pwsh, cmd, sh, bash, curl, wget). A novel
Office macro that spawns `certutil` instead of `powershell` to download a
payload would evade this detector entirely, despite following the same
parent-spawns-suspicious-child pattern.

Similarly, the `DnsExfiltrationDetector` uses Shannon entropy thresholds
(default 3.5), known tunneling patterns (dnscat, iodine), and burst volume
detection (8 queries per 60 seconds). An adversary who uses a custom DNS
tunneling tool with lower-entropy encoding (base32 with dictionary padding)
and rate-limited queries (1 per 10 seconds) could exfiltrate data below every
configured threshold.

### 2.2 The Asymmetry of Evasion vs. Detection

For every rule added to the pipeline, the adversary has a deterministic recipe
to evade it: read the rule, do the opposite. This creates an arms race where
detection engineering is always reactive. Behavioral baselines invert the
asymmetry: instead of defining what is bad (enumerable), they define what is
normal (observed) and flag deviations. An adversary who wants to evade a
baseline detector must make their attack look exactly like normal behavior for
the specific host, user, and time window being monitored -- a much harder
constraint than avoiding a static pattern list.

### 2.3 Compound Detection Through Pheromone Concentration

The pheromone substrate's concentration dynamics (see `PheromoneConcentration`
in `crates/swarm-core/src/pheromone.rs`) aggregate signals from multiple
independent detectors. A baseline detector that deposits a low-confidence
`DataExfiltration` pheromone for anomalous outbound data volume, combined with
the `DnsExfiltrationDetector`'s medium-confidence deposit for slightly elevated
query frequency, could cross the `alert_threshold` that neither detector would
reach alone. This compound detection model is the primary value proposition of
adding baseline detectors to the existing pipeline: they amplify weak signals
from rule-based detectors and surface signals that rule-based detectors miss
entirely.

### 2.4 Prior Art Within the Project

The sentinel-convergence series (Doc 02, Section 4.2) already analyzed
Welford's online algorithm for computing running mean and variance over
infrastructure health metrics. That analysis established the algorithm's
properties -- O(1) memory, numerical stability, monotonic convergence -- in
the context of CPU temperature, memory pressure, and disk I/O baselines.
This document extends the same algorithmic family to behavioral telemetry
(process execution, network connections, authentication events) and introduces
additional streaming algorithms (EWMA, reservoir sampling, Count-Min Sketch,
HyperLogLog) that address limitations Welford's alone cannot solve.

---

## 3. Statistical Approaches Comparison

### 3.1 Welford's Online Algorithm

**Already researched** in sentinel-convergence Doc 02, Section 4.2. Summary
of properties relevant to behavioral baselines:

```
M_n = M_{n-1} + (x_n - M_{n-1}) / n           (running mean)
S_n = S_{n-1} + (x_n - M_{n-1})(x_n - M_n)    (running sum of squared deviations)
sigma_n = sqrt(S_n / n)                          (population standard deviation)
z_n = (x_n - M_n) / sigma_n                     (z-score for anomaly detection)
```

**State per feature**: 3 values (`mean`, `M2`, `count`) = 24 bytes.

**Strengths**: Numerically stable, minimal memory, single-pass, well-understood
convergence properties.

**Weaknesses for behavioral detection**:
- Computes a **global** mean/variance. A sustained attack will gradually be
  absorbed into the baseline. If an attacker runs a low-and-slow exfiltration
  for hours, Welford's running mean will drift toward the attack traffic
  volume, reducing the z-score over time.
- No recency weighting. A behavior that was normal six months ago contributes
  equally to the baseline as behavior from the last hour.
- No support for categorical features (process names, IP addresses). Only
  works on numeric scalars.

**Best use**: Long-term stable numeric features where the baseline should
represent the full observation history (e.g., "average command-line argument
count for svchost.exe over the lifetime of the agent").

### 3.2 EWMA (Exponentially Weighted Moving Average)

EWMA addresses Welford's recency problem by weighting recent observations
more heavily:

```
EWMA_n = alpha * x_n + (1 - alpha) * EWMA_{n-1}
```

where `alpha` in (0, 1] is the smoothing factor. Higher alpha gives more
weight to recent observations; lower alpha produces a smoother, more
historical average.

For anomaly detection, the EWMA control chart computes control limits:

```
UCL = EWMA_target + L * sigma * sqrt(alpha / (2 - alpha))
LCL = EWMA_target - L * sigma * sqrt(alpha / (2 - alpha))
```

where `L` is the control limit width (typically 2.5-3.0 for security
applications) and `sigma` is the estimated process standard deviation.

**State per feature**: 3 values (`ewma`, `ewma_variance`, `count`) = 24
bytes (matching the `EwmaState` struct in Section 9.3.1 before the `alpha`
configuration field).

**Strengths**:
- Natural recency bias prevents baseline poisoning from sustained attacks.
- The `alpha` parameter is directly interpretable: `alpha = 0.1` means each
  new observation contributes 10% to the average, making the effective memory
  approximately `1/alpha = 10` observations.
- Comparable computational cost to Welford's per update (both are a handful
  of multiplications and additions).

**Weaknesses**:
- Requires careful `alpha` tuning per feature. Network byte counts at 1-second
  granularity need a different `alpha` than daily login counts.
- No explicit handling of time gaps. If an agent restarts after 24 hours of
  downtime, the next observation is weighted as if it immediately follows the
  previous one.

**Best use**: Numeric features where recency matters and the baseline should
adapt to legitimate behavioral changes over time (e.g., "typical outbound
data volume per hour for this host").

**Proposed default parameters for swarm-team-six**:

| Feature Domain | alpha | L (sigma multiplier) | Rationale |
|---|---|---|---|
| Process execution count | 0.05 | 3.0 | Stable feature, low alpha for smoothing |
| Network bytes per interval | 0.10 | 2.7 | More variable, moderate alpha |
| DNS query rate | 0.08 | 3.0 | Semi-stable, standard control limits |
| Auth failure rate | 0.15 | 2.5 | Bursty by nature, higher alpha, tighter limits |

### 3.3 Reservoir Sampling

Reservoir sampling maintains a uniform random sample of `k` items from a
stream of unknown length, where each item in the stream has an equal
probability of being in the final sample:

```
For item i (1-indexed):
  if i <= k: add to reservoir
  else:
    j = random(1, i)
    if j <= k: replace reservoir[j] with item i
```

**State**: `k` stored items + 1 counter = `k * item_size + 8` bytes.

**Strengths**:
- Works on categorical data (process names, IP addresses, command-line
  patterns) without numeric reduction.
- Provides a representative sample for offline analysis or histogram
  construction.
- No tuning parameters beyond `k`.

**Weaknesses**:
- Not directly an anomaly detector. Requires a second pass over the reservoir
  to compute distributional statistics.
- Equal probability across the stream means no recency weighting.
- For high-cardinality categorical data (e.g., command-line strings), even
  `k = 1000` may not capture rare but normal patterns.

**Best use**: Building empirical distributions of categorical features for
periodic baseline recalculation (e.g., "what processes normally run on this
host?" answered by maintaining a reservoir of observed process names).

### 3.4 Count-Min Sketch

A Count-Min Sketch is a probabilistic data structure for frequency estimation
on streaming data. It uses `d` hash functions and a `w x d` counter matrix:

```
For each item x:
  for i in 0..d:
    counters[i][hash_i(x) % w] += 1

Estimated count of x:
  min over i of counters[i][hash_i(x) % w]
```

**State**: `w * d * sizeof(counter)` bytes. With `w = 2048, d = 4`,
4-byte counters: 32 KiB.

**Strengths**:
- Bounded memory regardless of cardinality. A sketch with `w = 2048, d = 4`
  handles millions of distinct items in 32 KiB.
- Point query gives an upper bound on the true count with known error
  guarantees: `P(estimate > true_count + epsilon * N) < delta`, where
  `epsilon = e/w` and `delta = (1/e)^d`.
- Incremental updates are O(d) -- extremely fast.

**Weaknesses**:
- Only provides frequency estimates, not distributional statistics.
- One-directional error: estimates are always >= true count (overcounting
  from hash collisions).
- Cannot enumerate items (no inverse lookup). If the sketch says "something
  unusual is happening," it cannot identify what without side information.

**Best use**: Tracking per-entity event frequencies with bounded memory for
high-cardinality keying dimensions (e.g., "how many times has each unique
(process_name, destination_port) pair been seen in the last hour?"). Used to
answer "is this combination rare?" without storing all observed combinations.

### 3.5 HyperLogLog

HyperLogLog estimates the cardinality (number of distinct elements) of a
multiset using a fixed-size register array:

```
For each item x:
  h = hash(x)
  bucket = h[0..p]  (first p bits select the register)
  rank = leading_zeros(h[p..]) + 1
  registers[bucket] = max(registers[bucket], rank)

Cardinality estimate:
  alpha_m * m^2 / sum(2^(-registers[i]))
```

**State**: `2^p` registers of `log2(log2(N))` bits each. With `p = 14` (16384
registers, 6 bits each): ~12 KiB for estimates up to 10^18 with ~0.8%
standard error.

**Strengths**:
- Fixed memory for cardinality estimation regardless of actual cardinality.
- Mergeable: two HyperLogLog sketches covering different time windows can be
  combined by taking the register-wise maximum.
- Extremely fast updates (one hash, one register write).

**Weaknesses**:
- Only answers "how many distinct X?" -- no frequency information, no
  distribution shape.
- Inaccurate at low cardinalities without bias correction. The threshold
  depends on register count: roughly below `2.5 * 2^p` (e.g., ~40K for
  p=14, ~640 for p=8). The HLL++ variant adds linear counting for the
  small-range regime and empirical bias correction.

**Best use**: Tracking the number of distinct destinations, distinct users,
distinct processes, or distinct DNS domains per host/interval. Sudden increases
in cardinality ("this host normally contacts 15 distinct IPs per hour, but in
the last hour it contacted 347") are strong anomaly signals for scanning,
lateral movement, and data exfiltration reconnaissance.

### 3.6 Comparison Matrix

| Algorithm | Memory | Numeric | Categorical | Recency | Streaming | Anomaly Signal |
|---|---|---|---|---|---|---|
| Welford | O(1) | Yes | No | No | Yes | z-score |
| EWMA | O(1) | Yes | No | Yes | Yes | Control limits |
| Reservoir Sampling | O(k) | Yes | Yes | No | Yes | Distribution comparison |
| Count-Min Sketch | O(w*d) | Frequency | Yes | Decay-able | Yes | Rarity score |
| HyperLogLog | O(2^p) | No | Cardinality | Windowed | Yes | Cardinality spike |

For the swarm-team-six baseline detector family, we propose a **layered
approach**:

1. **EWMA** as the primary numeric baseline engine (process counts, byte
   volumes, query rates).
2. **Count-Min Sketch** for categorical frequency tracking with bounded
   memory (process-port pairs, domain frequencies).
3. **HyperLogLog** for cardinality monitoring (distinct destinations,
   distinct users).
4. **Welford** retained for long-horizon stable features where the full
   history is the correct baseline (per Doc 02 infrastructure metrics).

---

## 4. Process Behavior Profiling

### 4.1 Available Telemetry

The `ProcessStartEvent` struct (`crates/swarm-core/src/telemetry.rs`)
provides seven fields: `parent_process`, `process_name`, `command_line`,
`user`, `executable_path`, `signer`, and `signature_valid`. Each event also
carries `host_id`, `timestamp`, and `source` from the enclosing
`TelemetryEvent`.

### 4.2 Baseline Dimensions

#### 4.2.1 Command-Line Argument Patterns

For each `(host_id, process_name)` pair, maintain:

- **Argument count distribution**: EWMA of the number of space-delimited
  tokens in `command_line`. A process that normally runs with 2-3 arguments
  suddenly appearing with 15 arguments (typical of encoded payloads or
  multi-stage downloaders) is anomalous.
- **Argument length distribution**: EWMA of the total `command_line` length.
  Encoded PowerShell commands (`-enc <base64>`) produce abnormally long
  command lines. While the `SuspiciousScriptingDetector` already catches
  explicit `-enc` flags, a baseline detector would catch any unusually long
  command line regardless of content.
- **Argument entropy**: EWMA of Shannon entropy over the `command_line` string.
  High-entropy arguments suggest encoded or obfuscated payloads even when the
  encoding method is unknown to the rule-based detectors.

#### 4.2.2 Parent-Child Relationship Baselines

Instead of a static list of suspicious parents and children, maintain a
**frequency model** of observed parent-child pairs per host:

- **Count-Min Sketch** keyed on `(host_id, parent_process, process_name)`.
- When a new `ProcessStart` event arrives, query the sketch for the frequency
  of this triple. If the estimated count is below a threshold (e.g., bottom
  5th percentile of all observed pairs), the event is anomalous.
- This approach catches novel suspicious parent-child relationships without
  requiring them to be pre-enumerated. If `acrord32` has never spawned
  `certutil` on this host before, the baseline detector flags it regardless
  of whether `certutil` appears in any static list.

#### 4.2.3 Execution Frequency Baselines

For each `(host_id, process_name)` pair, maintain:

- **Hourly execution count**: EWMA of process starts per hour. A service that
  normally starts once per day suddenly starting 50 times per hour suggests
  either a crash loop (infrastructure signal) or adversary activity (repeated
  tool execution during lateral movement).
- **Time-of-day distribution**: Partition the day into 24 bins. A process
  that normally runs during business hours (bins 8-17) executing at 3 AM
  (bin 3) is anomalous. This can be implemented as 24 EWMA counters, one
  per hour-of-day, normalized to a distribution.

#### 4.2.4 Signer Baselines

Track the set of observed `(executable_path, signer)` pairs. A binary that
was always signed by "Microsoft Corporation" suddenly appearing unsigned or
signed by an unknown entity is a strong supply-chain indicator. This
supplements the `SupplyChainDetector`'s static trusted-signer list with
per-binary learned expectations.

### 4.3 Key Design Constraint: Process Name Cardinality

On a typical Windows endpoint, the set of distinct process names observed
over a week is in the range of 200-500. On a Linux server running containers,
it may be 50-150 per host, but 1000+ across a fleet. The `(host_id,
process_name)` keying dimension is therefore bounded and manageable: a
Count-Min Sketch with `w = 2048, d = 4` provides ample capacity.

The `(host_id, parent_process, process_name)` triple has higher cardinality
but is still bounded by the product of unique parents and children, which
in practice is 500-2000 per host. A single Count-Min Sketch per host or a
shared sketch with `w = 4096` handles this comfortably.

---

## 5. Network Traffic Baselines

### 5.1 Available Telemetry

`NetworkConnectEvent` provides `process_name`, `destination_ip`,
`destination_port`, and `protocol`. `DnsQueryEvent` provides `query_name`,
`query_type`, and optional `source_ip`, `process_name`, `response_code`.
See `crates/swarm-core/src/telemetry.rs` for full definitions.

### 5.2 Connection Pattern Baselines

#### 5.2.1 Destination Cardinality

For each `(host_id, process_name)`, maintain a **HyperLogLog** sketch of
distinct `destination_ip` values observed. Normal web browsers contact many
distinct IPs; a database server contacts a small, stable set. Deviations in
either direction are informative:

- A process that normally contacts 5 IPs suddenly contacting 200+ suggests
  **network scanning** or **lateral movement reconnaissance**.
- A process that normally contacts 100+ IPs suddenly contacting only 1-2
  suggests **C2 channel establishment** (the adversary has narrowed
  communication to their infrastructure).

#### 5.2.2 Port Usage Profiles

The `NetworkConnectDetector` already implements a `process_port_allowlist`
for static port expectations. A baseline detector extends this with a
**learned** port distribution:

- **Count-Min Sketch** keyed on `(host_id, process_name, destination_port)`.
- For each new connection, check whether this (process, port) combination is
  rare. If the sketch reports a count in the bottom percentile, flag the
  connection as anomalous.
- This catches port pivoting attacks where an adversary uses an unusual port
  for a legitimate-looking process (e.g., `svchost.exe` connecting to port
  8443 when it normally only uses ports 80, 443, and 135).

#### 5.2.3 Data Volume Baselines

The current `NetworkConnectEvent` does not include a byte-count field, which
is a telemetry gap for volume-based exfiltration detection. If byte counts
are added in a future telemetry schema revision, the baseline approach would
be:

- **EWMA** of outbound bytes per `(host_id, process_name)` per time interval.
- Sustained deviation above the upper control limit suggests bulk data
  exfiltration.
- Sustained deviation below (near-zero) for a normally active connection
  suggests the connection has been hijacked or is being used as a covert
  channel with minimal cover traffic.

### 5.3 DNS Query Baselines

#### 5.3.1 Query Frequency Per Domain

The `DnsExfiltrationDetector` already implements burst detection (8 queries
per 60 seconds). A baseline detector provides a per-domain, per-host frequency
model:

- **EWMA** of query count per `(host_id, query_domain)` per hour, where
  `query_domain` is the effective second-level domain extracted from
  `query_name`.
- This catches slow-drip DNS exfiltration that stays below the burst
  threshold. If a host normally queries `example.com` 5 times per hour and
  suddenly queries it 40 times per hour, the per-domain baseline flags the
  anomaly even though 40 queries/hour is below the global burst threshold.

#### 5.3.2 Domain Cardinality

**HyperLogLog** of distinct `query_name` values per `(host_id)` per time
interval. A host that normally resolves 50 distinct domains per hour suddenly
resolving 500+ may indicate DNS reconnaissance, domain generation algorithm
(DGA) activity, or DNS-based C2 with high domain rotation.

#### 5.3.3 Query Type Distribution

Normal DNS traffic is overwhelmingly A/AAAA records. The
`DnsExfiltrationDetector` already flags TXT, NULL, and CNAME as suspicious
query types, but a baseline approach tracks the **ratio** of non-standard
query types:

- **EWMA** of (non-A/AAAA queries) / (total queries) per host.
- Deviation above the upper control limit suggests DNS tunneling even if the
  specific query type is not in the detector's static `suspicious_query_types`
  list (e.g., MX or SRV record abuse).

---

## 6. User Entity Behavior Analytics (UEBA)

### 6.1 Available Telemetry

`AuthenticationEventData` provides `auth_type`, `source_host`,
`target_host`, `target_service`, `process_name`, `success`, and `user`.
See `crates/swarm-core/src/telemetry.rs`.

### 6.2 Session-Level Behavioral Models

#### 6.2.1 Login Time Distribution

For each `user`, maintain a **time-of-day histogram** (24 hourly bins, EWMA
per bin). An analyst who normally logs in between 8 AM and 6 PM authenticating
at 2 AM is a strong anomaly signal, especially when combined with other
indicators.

#### 6.2.2 Source Host Baselines

For each `user`, maintain a **HyperLogLog** of distinct `source_host` values.
Users typically authenticate from 1-3 hosts (workstation, laptop, mobile).
A sudden increase in source host cardinality suggests credential theft with
the compromised credentials being used from unfamiliar machines.

Additionally, a **Count-Min Sketch** keyed on `(user, source_host)` provides
frequency-based anomaly detection: the user has authenticated from this host
before, but how often? A host that appears in the sketch with count 1 (first
time ever) is more suspicious than one with count 500.

#### 6.2.3 Target Service Baselines

For each `user`, track the set of `target_service` values with a Count-Min
Sketch. A developer who normally accesses Git and CI services suddenly
requesting access to the domain controller's LDAP service or a SQL database
they have never touched is anomalous. This directly addresses the
Kerberoasting detection gap: even if the adversary uses a process name not in
the `CredentialAccessDetector`'s `suspicious_kerberoast_processes` list, the
baseline detector flags the unusual service access pattern.

### 6.3 Authentication Pattern Baselines

#### 6.3.1 Failure Rate

The `LateralMovementDetector` already tracks failed RDP attempts with a
threshold (default: 3 failures in 300 seconds). A baseline detector
generalizes this:

- **EWMA** of authentication failure rate per `(user, auth_type)`.
- Any auth_type (not just RDP) that shows a sustained failure rate above the
  upper control limit is flagged.
- This catches password spraying attacks that distribute attempts across many
  auth types to stay below per-type thresholds.

#### 6.3.2 Auth Type Distribution

For each `user`, maintain an **EWMA per auth_type** normalized to a
probability distribution. A user who normally authenticates via Kerberos
(95% of events) and occasionally via NTLM (5%) suddenly showing 80% NTLM
authentication may indicate a downgrade attack or lateral movement using
pass-the-hash.

### 6.4 Privilege Usage Baselines

The current telemetry schema lacks explicit privilege or group membership
fields. The `auth_type` and `target_service` fields serve as proxies --
the baseline mechanisms in Sections 6.2.3 and 6.3.2 already capture
privilege-adjacent anomalies (unusual service access, auth type shifts).

---

## 7. Cold-Start Problem

### 7.1 The Bootstrap Dilemma

Behavioral baselines require observation history before they can distinguish
normal from abnormal. A newly deployed agent has no baseline and therefore
cannot produce meaningful anomaly scores. This creates a detection gap during
the most vulnerable period -- initial deployment -- when the environment may
already be compromised.

### 7.2 Time-to-Stable-Baseline Estimates

The time required depends on the feature and the statistical algorithm:

| Feature | Algorithm | Minimum Observations | Estimated Time to Stable |
|---|---|---|---|
| Process execution count/hour | EWMA (alpha=0.05) | ~20 intervals | ~20 hours |
| Command-line argument count | EWMA (alpha=0.05) | ~100 events per process | 1-7 days depending on frequency |
| Parent-child pair frequency | Count-Min Sketch | ~1000 events | 1-3 days |
| DNS query rate/host/hour | EWMA (alpha=0.08) | ~12 intervals | ~12 hours |
| Destination IP cardinality | HyperLogLog | ~24 intervals (hourly) | ~24 hours |
| User login time distribution | EWMA histogram (24 bins) | ~5 logins per bin | 1-4 weeks |
| Auth failure rate | EWMA (alpha=0.15) | ~7 intervals | ~7 hours |

These estimates assume the feature is observed at a reasonable rate. For
sparse features (e.g., a service account that authenticates once per day),
the bootstrap period is much longer.

### 7.3 Bootstrapping Strategies

#### 7.3.1 Population Baselines

Instead of starting with an empty model, initialize each entity's baseline
from a **population aggregate**. If 100 hosts are already monitored and a
new host joins the fleet:

1. Compute the aggregate EWMA parameters across all hosts of the same role
   (e.g., "web server", "developer workstation").
2. Initialize the new host's baseline with the population mean and a widened
   variance (2x the population variance) to reduce false positives during
   the adaptation period.
3. As the new host generates observations, the EWMA naturally converges from
   the population baseline toward the host-specific baseline.

This requires the substrate or a sidecar data store to maintain population
statistics, which maps naturally to the pheromone substrate's ability to
aggregate across agents.

#### 7.3.2 Prior Knowledge Seeding

For environments with known baseline properties (e.g., a hardened server
image where the expected process set is defined by the golden image):

1. Seed the Count-Min Sketch with the expected process names and their
   approximate frequencies.
2. Seed the HyperLogLog sketches with the expected cardinalities.
3. Set the EWMA initial values to the expected means from the configuration
   baseline.

This is effectively a **supervised** cold-start strategy where the operator
provides ground truth about what normal looks like.

#### 7.3.3 Graduated Confidence

During the cold-start period, baseline detectors should emit findings with
**reduced confidence** proportional to the observation count:

```
effective_confidence = base_confidence * min(1.0, n / n_stable)
```

where `n` is the current observation count and `n_stable` is the minimum
observations for a stable baseline (from Section 7.2). This ensures baseline
detectors contribute less pheromone strength during the bootstrap period,
avoiding false escalations while still providing weak signal for compound
detection.

---

## 8. Drift Detection

### 8.1 Legitimate Behavioral Change

Environments evolve. Software updates change process execution patterns.
Infrastructure migrations change network connection profiles. Organizational
changes alter user authentication patterns. A baseline detector must
distinguish between:

1. **Legitimate drift**: gradual, correlated changes that affect many entities
   simultaneously (e.g., a fleet-wide update changes the command-line arguments
   for a service process).
2. **Adversary-induced change**: sudden, localized changes that affect one
   entity (e.g., a compromised host begins contacting a new C2 server).
3. **Adversary baseline poisoning**: deliberate slow introduction of malicious
   behavior to shift the baseline before executing the attack at higher
   intensity.

### 8.2 Adaptive vs. Fixed Baselines

**Adaptive baselines** (EWMA with moderate alpha) continuously incorporate
new observations, which handles legitimate drift but is vulnerable to baseline
poisoning. **Fixed baselines** (Welford's with frozen parameters after a
training period, or operator-seeded values) resist poisoning but generate
false positives when the environment legitimately changes.

The proposed approach uses a **dual-baseline** architecture:

1. **Short-term adaptive baseline**: EWMA with `alpha = 0.10-0.15`, adapts
   within hours. Detects sudden deviations from recent behavior.
2. **Long-term reference baseline**: EWMA with `alpha = 0.01-0.02`, adapts
   over weeks. Detects sustained deviations from historical behavior.

A finding is generated when the short-term baseline shows a deviation that
the long-term baseline also flags as unusual. This rejects transient noise
(short-term deviation only, long-term unaffected) and provides partial
resistance to baseline poisoning: when an adversary gradually shifts the
short-term baseline over days, the long-term baseline (alpha = 0.01-0.02,
effective memory of 50-100 observations spanning weeks) has not yet absorbed
the poisoned values, so the attack still registers as a long-term anomaly.
The defense degrades against multi-week poisoning campaigns; see Section
14.2 for adversarial analysis.

### 8.3 Seasonal Patterns

Many behavioral features exhibit daily, weekly, or monthly periodicity.
Business-hours login patterns, backup-job network traffic, and scheduled-task
process executions all follow predictable cycles. A naive EWMA baseline will
flag every Monday morning as anomalous if the training period was primarily
weekends.

Two approaches:

1. **Time-bucketed baselines**: Maintain separate EWMA states for each
   (hour-of-day, day-of-week) combination. 24 * 7 = 168 baseline states
   per feature per entity. At 24 bytes per EWMA state, this is ~4 KiB per
   feature per entity -- manageable for process-level profiling but expensive
   for high-cardinality dimensions.

2. **Fourier decomposition**: Subtract known periodic components (estimated
   via DFT on the reservoir sample) from the observation before feeding it
   to the EWMA. This is more memory-efficient but computationally heavier
   and requires a stable enough baseline to estimate the periodic components.

For the initial implementation, we recommend time-bucketed baselines with
coarse granularity (4 time-of-day bins x 2 weekday/weekend bins = 8 states
per feature per entity) as a pragmatic starting point.

### 8.4 Change-Point Detection

For detecting abrupt shifts in baseline behavior (as opposed to gradual
drift), CUSUM (Cumulative Sum) control charts complement EWMA:

```
S_high_n = max(0, S_high_{n-1} + (x_n - mu_0 - k))
S_low_n  = max(0, S_low_{n-1}  + (mu_0 - k - x_n))
```

Signal alarm when `S_high_n > h` or `S_low_n > h`, where `mu_0` is the
target mean, `k` is the allowance (slack) parameter, and `h` is the decision
interval. CUSUM is more sensitive to small sustained shifts than EWMA and
is well-suited for detecting the onset of low-and-slow attacks.

**State per feature**: 2 values (`S_high`, `S_low`) + 2 parameters
(`mu_0`, `k`) = 32 bytes.

---

## 9. Memory-Efficient Implementations

### 9.1 Memory Budget

The swarm-team-six runtime targets deployment on both server-class hardware
and (per sentinel-convergence Doc 03) potentially constrained edge nodes. The
baseline detection layer must operate within a bounded memory envelope.

**Proposed per-host memory budget**: 1 MiB for baseline state. This is
conservative relative to the overall runtime memory footprint but ensures
the baseline layer does not dominate the process heap.

### 9.2 Per-Entity State Breakdown

For a typical host with 200 distinct process names observed over the
baseline period:

| Component | Per-Entity State | Entities | Total |
|---|---|---|---|
| Process EWMA (arg count, arg length, entropy) | 3 features x 2 baselines x 24 bytes = 144 bytes | 200 processes | 28.1 KiB |
| Process frequency EWMA (8 time bins) | 8 bins x 24 bytes = 192 bytes | 200 processes | 37.5 KiB |
| Parent-child Count-Min Sketch | 4096 x 4 x 4 bytes | 1 per host | 64 KiB |
| Network destination HyperLogLog | 16384 registers x 6 bits | 200 processes | 240 KiB |
| Network port Count-Min Sketch | 2048 x 4 x 4 bytes | 1 per host | 32 KiB |
| DNS domain frequency EWMA | 24 bytes x 2 baselines | 500 domains | 23.4 KiB |
| DNS domain cardinality HyperLogLog | 12 KiB | 1 per host | 12 KiB |
| User auth EWMA (8 time bins + failure rate) | 9 x 24 bytes = 216 bytes | 50 users | 10.5 KiB |
| User source host HyperLogLog | 192 bytes (p=8) | 50 users | 9.4 KiB |
| **Total** | | | **~456 KiB** |

This is well within the 1 MiB target. Note: per-user source host HLL uses
`p = 8` (256 registers, ~192 bytes) rather than the `p = 14` used for
high-cardinality network destinations. Most users authenticate from 1-5
hosts, so the ~3% standard error at p=8 (accurate above ~30 distinct values)
is more than sufficient, and the memory saving vs. p=14 is 60x per user.
The previous draft's p=14 per-user allocation (12 KiB x 50 = 600 KiB) was
the dominant cost and grossly oversized for typical source-host cardinalities.

For the network destination HLL entries (200 processes x 12 KiB = 240 KiB),
p=14 is justified because browser and service processes routinely contact
hundreds of distinct IPs. On edge deployments with fewer processes, `p = 10`
(1.5 KiB each, ~3.25% error) is a viable fallback.

### 9.3 Rust Data Structure Choices

#### 9.3.1 EWMA State

```rust
/// Exponentially weighted moving average with variance tracking.
pub struct EwmaState {
    mean: f64,
    variance: f64,
    count: u64,
    alpha: f64,
}
```

32 bytes per instance (mean: 8, variance: 8, count: 8, alpha: 8). The
memory table in Section 9.2 uses 24 bytes per EWMA to reflect that `alpha`
is a configuration constant shared across instances with the same
time-horizon and could be stored once per profile rather than per state.
The `count` field drives cold-start confidence scaling (Section 7.3.3).

#### 9.3.2 Count-Min Sketch

Use `u32` counters to support counts up to ~4 billion per cell. With
aggressive time-window expiration (decay all counters by 50% every window
rotation), overflow is not a practical concern.

```rust
pub struct CountMinSketch {
    counters: Vec<Vec<u32>>,  // d rows x w columns
    seeds: Vec<u64>,          // d hash seeds
}
```

The `ahash` crate provides fast, high-quality hashing suitable for sketch
applications in Rust.

#### 9.3.3 HyperLogLog

Use 6-bit packed registers stored in a `Vec<u8>` with bit-packing:

```rust
pub struct HyperLogLog {
    registers: Vec<u8>,  // Packed 6-bit registers
    precision: u8,       // p parameter (number of register-index bits)
}
```

For `p = 14`: 16384 registers x 6 bits = 12288 bytes = 12 KiB.

### 9.4 Time-Window Management

All baseline structures need periodic aging to prevent unbounded state
growth and to implement recency semantics:

1. **EWMA**: Inherently recency-weighted; no explicit aging needed. Optionally
   reset to population baseline if the entity has not been observed for
   `dormancy_threshold` seconds (e.g., 7 days).
2. **Count-Min Sketch**: Apply a decay factor (multiply all counters by 0.5)
   at each window boundary. This halves all counts, effectively implementing
   an exponential decay on frequencies.
3. **HyperLogLog**: Cannot be decayed (registers represent maximums, not
   counts). Instead, maintain two sketches per entity: "current window" and
   "previous window." At each window boundary, swap current to previous and
   reset current. Anomaly detection compares the current window's cardinality
   against the previous window's.

---

## 10. Integration with Current Architecture

### 10.1 CompositeDetector Framework

Baseline detectors implement the existing `DetectionStrategy` trait
(`crates/swarm-whisker/src/detector.rs`), which requires `Send + Sync`,
an `id() -> &str` identifier, and an `evaluate(&self, &TelemetryEvent) ->
Vec<DetectionFinding>` method.

This means baseline detectors plug directly into the `CompositeDetector`
alongside rule-based detectors with zero framework changes. The
`CompositeDetector::evaluate` method calls each strategy's `evaluate` and
merges findings via `flat_map` -- baseline findings join rule-based findings
in the same output stream.

**Important caveat**: Baseline detectors are inherently **non-deterministic**
because their output depends on accumulated internal state. Given the same
event, a baseline detector may produce different findings depending on
prior observation history. This is a fundamental property of learned
baselines, not a bug, but it means replay-based testing (Section 13.2.3)
must replay the full event sequence, not individual events in isolation.

### 10.2 Statefulness Considerations

The `DetectionStrategy` trait requires `Send + Sync`. Its doc comment
states strategies should be "deterministic and side-effect free," but in
practice three existing detectors already maintain internal mutable state
behind `Arc<Mutex<>>`:

- `DnsExfiltrationDetector` -- `query_tracker: Arc<Mutex<HashMap<String, VecDeque<i64>>>>`.
- `LateralMovementDetector` -- `failed_rdp_tracker: Arc<Mutex<HashMap<String, VecDeque<i64>>>>`.
- `NetworkConnectDetector` -- `beacon_tracker: Arc<Mutex<HashMap<BeaconKey, VecDeque<i64>>>>`.

Baseline detectors follow the same pattern. The trait doc comment should be
updated to reflect the reality that windowed stateful detectors are a
first-class pattern, not an exception.

For baseline detectors, `Arc<RwLock<>>` is preferred over `Mutex` because
the evaluate hot-path is read-heavy (check baseline) with infrequent
writes (update baseline with new observation). Since updates are O(1) for
EWMA and O(d) for Count-Min Sketch, lock hold times are short and
contention is minimal.

**Architectural difference from existing stateful detectors**: The existing
`DnsExfiltrationDetector` and `NetworkConnectDetector` only append timestamps
for windowed counting -- their state tracks recent event timing but does not
alter the detector's decision logic over time. Baseline detectors, by
contrast, mutate their statistical model on every evaluation. This means
the evaluate call has **learning side effects**: processing the same event
stream in a different order may produce different findings. This is
acceptable for behavioral baselines but should be documented clearly in the
trait-level contract if baseline detectors become a standard pattern.

### 10.3 Baseline as Pheromone Deposit

When a baseline detector produces a `DetectionFinding`, the existing
`findings_to_deposits` function in `crates/swarm-whisker/src/stream.rs`
converts it to a `PheromoneDeposit`. The conversion maps each finding's
`threat_class`, `severity`, and `confidence` directly onto the deposit,
uses `strategy_scoped_agent_id` to scope the depositing identity, and
currently applies `pheromone.default_half_life_secs` as the decay rate
for all findings regardless of source.

Baseline findings should use **longer decay half-lives** than rule-based
findings. A rule-based finding says "I saw a known-bad pattern" -- high
confidence, fast decay. A baseline finding says "something unusual happened"
-- lower confidence, slower decay. The slower decay allows baseline
pheromones to accumulate over time, crossing thresholds only when anomalies
persist or compound with other signals.

**Proposed half-life mapping**:

| Finding Source | Default Half-Life | Rationale |
|---|---|---|
| Rule-based detector | `default_half_life_secs` (config) | Standard decay for known patterns |
| Baseline detector (high z-score) | `2 * default_half_life_secs` | Anomalies should linger for correlation |
| Baseline detector (moderate z-score) | `3 * default_half_life_secs` | Weak signals need more time to compound |

**Implementation note**: The current `findings_to_deposits` function in
`crates/swarm-whisker/src/stream.rs` unconditionally uses
`pheromone.default_half_life_secs` for all findings. Implementing the
half-life mapping above requires extending this function to inspect
`finding.strategy_id` (e.g., prefix-match on `baseline_*`) and select the
appropriate multiplier. This is a targeted change to one function, not a
framework-level modification.

### 10.4 Concentration Dynamics for Baseline Signals

The pheromone substrate's `PheromoneConcentration` struct (in
`crates/swarm-core/src/pheromone.rs`) aggregates signals by `threat_class`,
tracking `total_strength`, `distinct_sources`, and `peak_confidence`.
Escalation requires both `total_strength >= strength_threshold` AND
`distinct_sources >= min_sources` (via `exceeds_threshold`).
This multi-source requirement is critical for baseline detectors: a single
baseline detector finding an anomaly should not, by itself, trigger
escalation. But a baseline anomaly from one detector combined with a
rule-based finding from another detector satisfies the multi-source
requirement and can trigger escalation.

**Example compound detection scenario**:

1. `ProcessBaselineDetector` flags an unusual parent-child pair
   (`outlook.exe` -> `certutil.exe`) with confidence 0.6, depositing a
   `ThreatClass::Execution` pheromone.
2. `SuspiciousProcessTreeDetector` does **not** fire (certutil is not in
   the default `suspicious_children` list).
3. `NetworkConnectDetector` flags `certutil.exe` connecting to port 443
   with confidence 0.7 (process-port mismatch), depositing a
   `ThreatClass::CommandAndControl` pheromone.
4. `NetworkBaselineDetector` flags the same connection as a novel
   (process, port) pair with confidence 0.5.
5. Neither individual finding crosses `alert_threshold` (default 2.0).
   But the compound `total_strength` across the Execution class reaches
   0.6, and across CommandAndControl reaches 1.2 (0.7 + 0.5) from two
   distinct sources. With extended half-lives for baseline deposits,
   continued anomalous connections accumulate additional strength. After
   3-4 more baseline deposits within the decay window, the C2 class
   crosses the 2.0 threshold and triggers an alert.

This illustrates the key value: rule-based detectors provide the initial
signal, baseline detectors amplify it, and the pheromone concentration
model gates escalation on sustained, multi-source evidence.

---

## 11. Anomaly Scoring

### 11.1 Statistical Deviation Scores

Each baseline algorithm produces a raw deviation metric:

| Algorithm | Raw Metric | Interpretation |
|---|---|---|
| EWMA | `z = (x - ewma_mean) / sqrt(ewma_variance)` | Number of standard deviations from the moving average |
| Count-Min Sketch | `rarity = 1 - (count / max_count)` | How rare this item is relative to the most common |
| HyperLogLog | `ratio = current_cardinality / baseline_cardinality` | How much cardinality has changed |
| CUSUM | `max(S_high, S_low)` | Cumulative evidence for a shift |

### 11.2 Mapping Deviation to Confidence

Raw deviation scores must be mapped to the `confidence: f64` field (0.0-1.0)
expected by `DetectionFinding`. The mapping should be:

1. **Non-linear**: Small deviations should map to low confidence (near 0.0),
   while large deviations should saturate near the detector's configured
   `high_confidence_threshold`.
2. **Calibrated**: A confidence of 0.7 should mean roughly the same thing
   whether it comes from a rule-based detector or a baseline detector.

**Proposed sigmoid mapping**:

```
confidence = high_threshold / (1 + exp(-k * (z - z_threshold)))
```

where:
- `z` is the z-score or equivalent deviation metric
- `z_threshold` is the minimum deviation for non-zero confidence (default: 2.0)
- `k` is the steepness parameter (default: 1.5)
- `high_threshold` is the detector's configured `high_confidence_threshold`

With `high_threshold = 0.85` and the defaults above, exact values are:

- z = 2.0 -> confidence = 0.85 / (1 + e^0) = **0.425** (borderline anomaly, low pheromone contribution)
- z = 3.0 -> confidence = 0.85 / (1 + e^-1.5) = **0.695** (clear anomaly, medium pheromone contribution)
- z = 4.0 -> confidence = 0.85 / (1 + e^-3.0) = **0.810** (strong anomaly, significant pheromone contribution)
- z = 5.0+ -> confidence = 0.85 / (1 + e^-4.5) = **0.841** (extreme anomaly, near-maximum contribution)

Note the asymptotic ceiling is `high_threshold` (0.85), not 1.0. The curve
saturates quickly above z = 4, providing limited additional discrimination
for extreme outliers. If finer granularity is needed at high z-scores,
increase `k` or replace the logistic with a stretched-sigmoid variant such
as `high_threshold * tanh(k * (z - z_threshold))` for a wider dynamic range.

### 11.3 Contextual Confidence Adjustments

Raw statistical deviation is necessary but not sufficient for high-quality
anomaly scoring. Contextual signals should adjust confidence:

1. **Cold-start penalty**: As described in Section 7.3.3, multiply confidence
   by `min(1.0, n / n_stable)` when the baseline has fewer than `n_stable`
   observations.
2. **Correlation bonus**: If multiple baseline features for the same entity
   are simultaneously anomalous (e.g., both command-line length AND execution
   frequency for the same process), increase confidence by a correlation
   factor (e.g., 1.2x per additional correlated anomaly, capped at 1.5x).
3. **Time-of-day adjustment**: Anomalies during known quiet periods (late
   night, weekends) receive a confidence boost (1.1-1.2x) because the
   baseline is more stable and deviations are more significant.
4. **Population deviation**: If the anomaly is also unusual relative to the
   population baseline (Section 7.3.1), increase confidence. An entity that
   is anomalous relative to its own history AND the population is more
   suspicious than one that is only anomalous relative to a recently-shifted
   personal baseline.

### 11.4 Severity Mapping

Baseline detectors should map severity more conservatively than rule-based
detectors:

| Confidence Range | Rule-Based Severity | Baseline Severity |
|---|---|---|
| >= 0.9 | Critical | High |
| 0.7 - 0.9 | High | Medium |
| 0.5 - 0.7 | Medium | Low |
| < 0.5 | (no finding) | (no finding) |

This one-tier reduction reflects the inherent uncertainty of anomaly-based
detection. Baseline findings are hypotheses, not verdicts. They should
amplify rule-based findings through pheromone concentration but not
independently trigger high-severity escalations.

---

## 12. Proposed Detector Designs

### 12.1 ProcessBaselineDetector

```rust
/// Behavioral baseline detector for process execution patterns.
///
/// Learns per-(host, process) baselines for:
/// - Command-line argument count and length
/// - Command-line entropy
/// - Parent-child pair frequency
/// - Execution frequency per time bin
///
/// Anomalies are scored using EWMA z-scores and Count-Min rarity.
pub struct ProcessBaselineDetector {
    /// Dual-timescale EWMA states keyed by (host_id, process_name).
    process_baselines: Arc<RwLock<HashMap<ProcessKey, ProcessBaseline>>>,
    /// Shared Count-Min Sketch for parent-child pair frequency.
    parent_child_sketch: Arc<RwLock<CountMinSketch>>,
    /// Configuration profile.
    profile: ProcessBaselineProfile,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ProcessKey {
    host_id: String,
    process_name: String,
}

struct ProcessBaseline {
    arg_count: DualEwma,
    arg_length: DualEwma,
    cmd_entropy: DualEwma,
    hourly_frequency: [DualEwma; 8],  // 4 time-of-day x 2 weekday/weekend
    first_seen: i64,
    observation_count: u64,
}

/// Paired short-term and long-term EWMA for dual-baseline detection.
struct DualEwma {
    short_term: EwmaState,  // alpha = 0.10
    long_term: EwmaState,   // alpha = 0.02
}
```

**Trait implementation sketch**:

```rust
impl DetectionStrategy for ProcessBaselineDetector {
    fn id(&self) -> &str {
        "process_baseline"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        let TelemetryPayload::ProcessStart(process) = &event.payload else {
            return Vec::new();
        };

        let host_id = event.host_id.as_deref().unwrap_or(&event.source);
        let key = ProcessKey {
            host_id: host_id.to_lowercase(),
            process_name: process.process_name.to_lowercase(),
        };

        // Compute current observation features
        let arg_count = count_arguments(&process.command_line) as f64;
        let arg_length = process.command_line.len() as f64;
        let cmd_entropy = shannon_entropy(&process.command_line);
        let time_bin = time_bin_index(event.timestamp);

        // Update baseline and compute z-scores
        let mut findings = Vec::new();
        {
            let mut guard = self.process_baselines.write().unwrap();
            let baseline = guard.entry(key).or_insert_with(|| {
                ProcessBaseline::new(event.timestamp, &self.profile)
            });

            let z_arg_count = baseline.arg_count.update_and_score(arg_count);
            let z_arg_length = baseline.arg_length.update_and_score(arg_length);
            let z_entropy = baseline.cmd_entropy.update_and_score(cmd_entropy);
            baseline.observation_count += 1;

            let max_z = z_arg_count.abs()
                .max(z_arg_length.abs())
                .max(z_entropy.abs());

            if max_z > self.profile.z_threshold {
                let confidence = sigmoid_confidence(
                    max_z,
                    self.profile.z_threshold,
                    self.profile.high_confidence_threshold,
                );
                let cold_start_factor = cold_start_scale(
                    baseline.observation_count,
                    self.profile.stable_observation_count,
                );

                findings.push(DetectionFinding {
                    finding_id: format!("{}:{}", self.id(), event.event_id),
                    event_id: event.event_id.clone(),
                    threat_class: infer_threat_class_from_process(process),
                    severity: baseline_severity(confidence),
                    confidence: confidence * cold_start_factor,
                    evidence: json!({
                        "mode": "process_baseline_deviation",
                        "z_arg_count": z_arg_count,
                        "z_arg_length": z_arg_length,
                        "z_entropy": z_entropy,
                        "observation_count": baseline.observation_count,
                        "cold_start_factor": cold_start_factor,
                    }),
                    strategy_id: self.id().to_string(),
                });
            }
        }

        // Check parent-child pair rarity
        let pair_rarity = {
            let mut sketch = self.parent_child_sketch.write().unwrap();
            let pair_key = format!(
                "{}:{}:{}",
                host_id.to_lowercase(),
                process.parent_process.to_lowercase(),
                process.process_name.to_lowercase(),
            );
            sketch.increment(&pair_key);
            sketch.rarity(&pair_key)
        };

        if pair_rarity > self.profile.rarity_threshold {
            findings.push(DetectionFinding {
                finding_id: format!("{}:pair:{}", self.id(), event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::Execution,
                severity: Severity::Low,
                confidence: pair_rarity * self.profile.medium_confidence_threshold,
                evidence: json!({
                    "mode": "novel_parent_child_pair",
                    "parent_process": process.parent_process,
                    "process_name": process.process_name,
                    "pair_rarity": pair_rarity,
                }),
                strategy_id: self.id().to_string(),
            });
        }

        findings
    }
}
```

### 12.2 NetworkBaselineDetector

```rust
/// Behavioral baseline detector for network connection patterns.
///
/// Learns per-(host, process) baselines for:
/// - Destination IP cardinality (HyperLogLog)
/// - Port usage frequency (Count-Min Sketch)
/// - Connection rate per time bin (EWMA)
///
/// Anomalies flag unusual connection patterns that rule-based
/// detectors may not cover.
pub struct NetworkBaselineDetector {
    /// Per-(host, process) destination cardinality tracking.
    cardinality_trackers: Arc<RwLock<HashMap<NetworkKey, CardinalityTracker>>>,
    /// Shared Count-Min Sketch for (host, process, port) frequency.
    port_sketch: Arc<RwLock<CountMinSketch>>,
    /// Per-(host, process) connection rate EWMA.
    rate_baselines: Arc<RwLock<HashMap<NetworkKey, DualEwma>>>,
    /// Configuration profile.
    profile: NetworkBaselineProfile,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NetworkKey {
    host_id: String,
    process_name: String,
}

struct CardinalityTracker {
    current_window: HyperLogLog,
    previous_window: HyperLogLog,
    window_start: i64,
}
```

**Detection logic**:

```rust
impl DetectionStrategy for NetworkBaselineDetector {
    fn id(&self) -> &str {
        "network_baseline"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        let TelemetryPayload::NetworkConnect(connect) = &event.payload else {
            return Vec::new();
        };

        let host_id = event.host_id.as_deref().unwrap_or(&event.source);
        let key = NetworkKey {
            host_id: host_id.to_lowercase(),
            process_name: connect.process_name.to_lowercase(),
        };

        let mut findings = Vec::new();

        // Cardinality anomaly detection
        {
            let mut guard = self.cardinality_trackers.write().unwrap();
            let tracker = guard.entry(key.clone()).or_insert_with(|| {
                CardinalityTracker::new(event.timestamp, self.profile.window_secs)
            });
            tracker.maybe_rotate(event.timestamp, self.profile.window_secs);
            tracker.current_window.insert(&connect.destination_ip);

            let current_card = tracker.current_window.estimate();
            let previous_card = tracker.previous_window.estimate();
            if previous_card > 5.0 {
                let ratio = current_card / previous_card;
                if ratio > self.profile.cardinality_spike_threshold {
                    findings.push(DetectionFinding {
                        finding_id: format!("{}:card:{}", self.id(), event.event_id),
                        event_id: event.event_id.clone(),
                        threat_class: ThreatClass::Discovery,
                        severity: Severity::Medium,
                        confidence: sigmoid_confidence(
                            ratio,
                            self.profile.cardinality_spike_threshold,
                            self.profile.high_confidence_threshold,
                        ),
                        evidence: json!({
                            "mode": "destination_cardinality_spike",
                            "current_cardinality": current_card,
                            "previous_cardinality": previous_card,
                            "ratio": ratio,
                        }),
                        strategy_id: self.id().to_string(),
                    });
                }
            }
        }

        // Port rarity detection
        {
            let mut sketch = self.port_sketch.write().unwrap();
            let port_key = format!(
                "{}:{}:{}",
                key.host_id, key.process_name, connect.destination_port,
            );
            sketch.increment(&port_key);
            let rarity = sketch.rarity(&port_key);
            if rarity > self.profile.port_rarity_threshold {
                findings.push(DetectionFinding {
                    finding_id: format!("{}:port:{}", self.id(), event.event_id),
                    event_id: event.event_id.clone(),
                    threat_class: ThreatClass::CommandAndControl,
                    severity: Severity::Low,
                    confidence: rarity * self.profile.medium_confidence_threshold,
                    evidence: json!({
                        "mode": "unusual_port_for_process",
                        "process_name": connect.process_name,
                        "destination_port": connect.destination_port,
                        "port_rarity": rarity,
                    }),
                    strategy_id: self.id().to_string(),
                });
            }
        }

        findings
    }
}
```

### 12.3 AuthBaselineDetector

```rust
/// Behavioral baseline detector for authentication patterns.
///
/// Learns per-user baselines for:
/// - Login time-of-day distribution (EWMA histogram)
/// - Source host cardinality (HyperLogLog)
/// - Target service frequency (Count-Min Sketch)
/// - Authentication failure rate (EWMA)
///
/// Designed to catch credential theft, privilege escalation,
/// and lateral movement that evade rule-based detectors.
pub struct AuthBaselineDetector {
    /// Per-user authentication baselines.
    user_baselines: Arc<RwLock<HashMap<String, AuthBaseline>>>,
    /// Shared Count-Min Sketch for (user, target_service) frequency.
    service_sketch: Arc<RwLock<CountMinSketch>>,
    /// Configuration profile.
    profile: AuthBaselineProfile,
}

struct AuthBaseline {
    /// EWMA histogram of login times (8 bins: 4 time-of-day x 2 weekday/weekend).
    time_histogram: [EwmaState; 8],
    /// HyperLogLog of distinct source hosts.
    source_hosts: HyperLogLog,
    /// Previous window source host cardinality for comparison.
    prev_source_host_count: f64,
    /// EWMA of authentication failure rate.
    failure_rate: DualEwma,
    /// Total observations for cold-start scaling.
    observation_count: u64,
}
```

**Detection logic**:

```rust
impl DetectionStrategy for AuthBaselineDetector {
    fn id(&self) -> &str {
        "auth_baseline"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        let TelemetryPayload::AuthenticationEvent(auth) = &event.payload else {
            return Vec::new();
        };

        let user = match &auth.user {
            Some(u) if !u.is_empty() => u.to_lowercase(),
            _ => return Vec::new(),
        };

        let mut findings = Vec::new();

        {
            let mut guard = self.user_baselines.write().unwrap();
            let baseline = guard.entry(user.clone()).or_insert_with(|| {
                AuthBaseline::new(&self.profile)
            });
            baseline.observation_count += 1;

            // Time-of-day anomaly
            let time_bin = time_bin_index(event.timestamp);
            let time_z = baseline.time_histogram[time_bin]
                .update_and_score(1.0);
            if time_z.abs() > self.profile.z_threshold {
                findings.push(DetectionFinding {
                    finding_id: format!("{}:time:{}", self.id(), event.event_id),
                    event_id: event.event_id.clone(),
                    threat_class: ThreatClass::InitialAccess,
                    severity: Severity::Low,
                    confidence: sigmoid_confidence(
                        time_z.abs(),
                        self.profile.z_threshold,
                        self.profile.medium_confidence_threshold,
                    ) * cold_start_scale(
                        baseline.observation_count,
                        self.profile.stable_observation_count,
                    ),
                    evidence: json!({
                        "mode": "unusual_auth_time",
                        "user": user,
                        "time_bin": time_bin,
                        "z_score": time_z,
                    }),
                    strategy_id: self.id().to_string(),
                });
            }

            // Source host cardinality anomaly
            if let Some(source) = &auth.source_host {
                baseline.source_hosts.insert(source);
                let current_card = baseline.source_hosts.estimate();
                if baseline.prev_source_host_count > 2.0 {
                    let ratio = current_card / baseline.prev_source_host_count;
                    if ratio > self.profile.source_host_spike_threshold {
                        findings.push(DetectionFinding {
                            finding_id: format!("{}:src:{}", self.id(), event.event_id),
                            event_id: event.event_id.clone(),
                            threat_class: ThreatClass::CredentialAccess,
                            severity: Severity::Medium,
                            confidence: sigmoid_confidence(
                                ratio,
                                self.profile.source_host_spike_threshold,
                                self.profile.high_confidence_threshold,
                            ),
                            evidence: json!({
                                "mode": "source_host_cardinality_spike",
                                "user": user,
                                "current_cardinality": current_card,
                                "previous_cardinality": baseline.prev_source_host_count,
                                "source_host": source,
                            }),
                            strategy_id: self.id().to_string(),
                        });
                    }
                }
            }

            // Failure rate anomaly
            let failure_value = if auth.success { 0.0 } else { 1.0 };
            let failure_z = baseline.failure_rate.update_and_score(failure_value);
            if failure_z > self.profile.z_threshold && !auth.success {
                let fail_confidence = sigmoid_confidence(
                    failure_z,
                    self.profile.z_threshold,
                    self.profile.high_confidence_threshold,
                );
                findings.push(DetectionFinding {
                    finding_id: format!("{}:fail:{}", self.id(), event.event_id),
                    event_id: event.event_id.clone(),
                    threat_class: ThreatClass::CredentialAccess,
                    severity: baseline_severity(fail_confidence),
                    confidence: fail_confidence,
                    evidence: json!({
                        "mode": "elevated_auth_failure_rate",
                        "user": user,
                        "auth_type": auth.auth_type,
                        "failure_z_score": failure_z,
                        "success": auth.success,
                    }),
                    strategy_id: self.id().to_string(),
                });
            }
        }

        // Target service rarity
        if let Some(service) = &auth.target_service {
            let mut sketch = self.service_sketch.write().unwrap();
            let service_key = format!("{}:{}", user, service.to_lowercase());
            sketch.increment(&service_key);
            let rarity = sketch.rarity(&service_key);
            if rarity > self.profile.service_rarity_threshold {
                findings.push(DetectionFinding {
                    finding_id: format!("{}:svc:{}", self.id(), event.event_id),
                    event_id: event.event_id.clone(),
                    threat_class: ThreatClass::LateralMovement,
                    severity: Severity::Medium,
                    confidence: rarity * self.profile.medium_confidence_threshold,
                    evidence: json!({
                        "mode": "unusual_target_service",
                        "user": user,
                        "target_service": service,
                        "service_rarity": rarity,
                    }),
                    strategy_id: self.id().to_string(),
                });
            }
        }

        findings
    }
}
```

### 12.4 Profile Structures

Following the established pattern in the codebase (every detector has a
serializable `*Profile` struct with `#[serde(deny_unknown_fields)]`):

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessBaselineProfile {
    #[serde(default = "default_short_term_alpha")]
    pub short_term_alpha: f64,
    #[serde(default = "default_long_term_alpha")]
    pub long_term_alpha: f64,
    #[serde(default = "default_z_threshold")]
    pub z_threshold: f64,
    #[serde(default = "default_rarity_threshold")]
    pub rarity_threshold: f64,
    #[serde(default = "default_stable_observation_count")]
    pub stable_observation_count: u64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
    #[serde(default = "default_sketch_width")]
    pub sketch_width: usize,
    #[serde(default = "default_sketch_depth")]
    pub sketch_depth: usize,
}
```

Default values:

| Parameter | Default | Rationale |
|---|---|---|
| `short_term_alpha` | 0.10 | Adapts over ~10 observations |
| `long_term_alpha` | 0.02 | Adapts over ~50 observations |
| `z_threshold` | 2.5 | Slightly tighter than the 3-sigma rule for security sensitivity |
| `rarity_threshold` | 0.95 | Flag items rarer than the 95th percentile |
| `stable_observation_count` | 100 | ~1-3 days of typical process telemetry |
| `high_confidence_threshold` | 0.85 | Capped below rule-based detectors' 0.9 |
| `medium_confidence_threshold` | 0.60 | Capped below rule-based detectors' 0.7 |
| `sketch_width` | 4096 | Count-Min Sketch columns |
| `sketch_depth` | 4 | Count-Min Sketch rows (hash functions) |

---

## 13. Evaluation Methodology

### 13.1 Metrics

#### 13.1.1 ROC Curves

For each baseline detector, produce ROC curves at various z-score thresholds
using a labeled dataset containing both attack and benign activity. The area
under the ROC curve (AUC-ROC) quantifies the detector's ability to
discriminate between normal and anomalous behavior regardless of the chosen
threshold.

**Target AUC-ROC**: >= 0.80 for individual baseline detectors. Combined with
rule-based detectors through pheromone concentration, the effective system
AUC-ROC should exceed 0.92.

#### 13.1.2 Precision/Recall at Operating Thresholds

At the proposed default thresholds (z >= 2.5, rarity >= 0.95):

| Detector | Target Precision | Target Recall | Notes |
|---|---|---|---|
| `ProcessBaselineDetector` | >= 0.30 | >= 0.60 | Low precision acceptable -- findings are weak signals |
| `NetworkBaselineDetector` | >= 0.25 | >= 0.65 | Network baselines are noisier |
| `AuthBaselineDetector` | >= 0.40 | >= 0.55 | Auth patterns are more stable, higher precision |

These precision targets are deliberately low for individual baseline
detectors. The value comes from compound detection through pheromone
concentration, where multiple low-precision signals produce high-precision
escalations.

#### 13.1.3 Time-to-Stable-Baseline

Measure the time from first observation to the point where the detector
achieves 90% of its steady-state AUC-ROC. This quantifies the cold-start
penalty and validates the bootstrapping strategies from Section 7.

### 13.2 Test Datasets

#### 13.2.1 Synthetic Baseline Corpus

Generate synthetic telemetry streams with known statistical properties:
- Normal process executions with Gaussian-distributed argument counts.
- Normal network connections with Poisson-distributed rates.
- Normal authentication events with time-of-day modulated rates.

Inject known anomalies at random points:
- Process execution with 5-sigma argument count deviation.
- Network connection to a destination never seen before.
- Authentication from a novel source host at an unusual time.

This corpus validates the mathematical correctness of the baseline
algorithms independent of real-world noise.

#### 13.2.2 MITRE ATT&CK Evaluation Corpus

Map techniques from Doc 02's coverage analysis to expected baseline
deviations. Focus on techniques with **no** existing rule-based coverage:
T1071.001 (destination cardinality), T1083 (execution frequency spike),
T1046 (destination cardinality spike), T1078 (unusual login time + source),
T1550 (auth type distribution shift). Also validate that partially covered
techniques (T1059 via entropy, T1110 via generalized failure rate) receive
stronger compound signals when baseline and rule-based detectors fire
together.

#### 13.2.3 Replay Tests

Use the existing substrate replay infrastructure (local journal backend with
`LocalJournalPheromoneSubstrate`) to replay recorded telemetry through the
baseline detectors and verify that:
1. Findings are deterministic given the same input sequence.
2. Pheromone deposits produce expected concentration dynamics.
3. Cold-start behavior matches the graduated-confidence model.

### 13.3 Performance Benchmarks

Baseline detectors must not degrade the hot-path detection latency
established by the rule-based pipeline:

| Metric | Target | Measurement Method |
|---|---|---|
| Per-event evaluation latency (p50) | < 5 microseconds | `criterion` microbenchmark |
| Per-event evaluation latency (p99) | < 50 microseconds | `criterion` microbenchmark |
| Memory per host (steady state) | < 1 MiB | `jemalloc` heap profiling |
| Memory per host (cold start) | < 100 KiB | `jemalloc` heap profiling |
| Lock contention (p99) | < 1 microsecond | `parking_lot` instrumentation |

The p99 latency target of 50 microseconds allows for occasional lock
contention and sketch decay operations. The steady-state memory target of
1 MiB per host is validated by the analysis in Section 9.2.

---

## 14. Open Questions and Future Work

### 14.1 Baseline Persistence Across Restarts

The current design stores baseline state in memory. Agent restarts lose all
learned baselines, triggering a full cold-start period. Two mitigation paths:

1. **Periodic snapshots**: Serialize baseline state to the local journal
   backend at configurable intervals (e.g., every 5 minutes). On restart,
   load the most recent snapshot. This requires `Serialize`/`Deserialize`
   implementations for all baseline data structures.
2. **Substrate-backed baselines**: Store baseline state as special pheromone
   deposits in the substrate. This leverages existing durability
   infrastructure but conflates two different data models (threat signals
   vs. statistical state).

Recommendation: periodic snapshots to a sidecar file, separate from the
pheromone substrate. Baseline state is not a threat signal and should not
participate in concentration dynamics.

### 14.2 Adversarial Baseline Manipulation

An adversary who is aware of the baseline detection system can attempt to:

1. **Slow poisoning**: Gradually introduce malicious behavior over weeks to
   shift the baseline before executing the attack. The dual-baseline
   architecture (Section 8.2) partially mitigates this, but a sufficiently
   patient adversary can shift even the long-term baseline.
2. **Noise injection**: Generate high volumes of benign-looking anomalies
   to inflate the false positive rate, desensitizing operators. The
   graduated confidence model and pheromone concentration requirements
   provide some resistance.
3. **Baseline reset attacks**: Crash the agent to force a cold-start period
   during which detection confidence is reduced.

See Swarm Hardening Doc 01 (Evasion Techniques) for a fuller treatment of
adversarial resistance. Formal analysis of baseline robustness under
adversarial manipulation is deferred to future work.

### 14.3 Multi-Host Correlation

The proposed detectors operate per-host. Fleet-wide attacks that produce
small per-host anomalies may only be detectable through cross-host
correlation. The pheromone substrate's concentration aggregation provides
a partial solution (multiple hosts depositing weak pheromones for the same
`ThreatClass` can cross the `alert_threshold`), but explicit multi-host
baseline detectors -- "is this pattern unusual for the fleet, not just this
host?" -- are a natural extension.

### 14.4 Feedback Loop from Investigations

When a Stalker agent (async investigation) confirms or rejects a baseline
anomaly, that feedback could be used to adjust the baseline parameters:
confirmed true positives tighten the thresholds (lower z_threshold);
confirmed false positives widen them. This creates a closed-loop learning
system that improves over time. The mechanism is not yet designed and
requires careful thought about adversary-induced feedback corruption.

### 14.5 Telemetry Schema Extensions

The effectiveness of network baselines is limited by the current
`NetworkConnectEvent` schema, which lacks:
- **Byte counts**: Essential for data volume baselining and exfiltration
  detection.
- **Duration**: Connection duration enables session profiling and C2 dwell
  time detection.
- **Direction**: Inbound vs. outbound distinction enables server-profile
  baselines.

A telemetry schema revision adding these fields would significantly increase
the value of the `NetworkBaselineDetector`.

---

## 15. Cross-References

This document is part 6 of 8 in the **Swarm Hardening** research series.

| Doc | Title | Relevance to This Document |
|-----|-------|---------------------------|
| 01 | Evasion Techniques and Countermeasures | Adversarial baseline manipulation (Section 14.2); evasion cost asymmetry motivating baselines (Section 2.2) |
| 02 | ATT&CK Coverage Analysis | Coverage gaps addressable by baseline detectors (Section 13.2.2); technique-to-signal mapping |
| 04 | Performance Budget and Hot-Path Constraints | Computation overhead targets for baseline evaluation (Section 13.3); memory budget constraints (Section 9.1) |
| 05 | Kill Chain Reconstruction and Graph-Based Correlation | Compound detection via graph overlay complements pheromone-based correlation (Section 10.4) |

**Sentinel Convergence Series Cross-References**:

| Doc | Title | Relevance |
|-----|-------|-----------|
| [SC-02](../sentinel-convergence/02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Predictive Infrastructure Failure as Threat Signal | Welford's algorithm analysis (Section 3.1); infrastructure baseline foundation |
| [SC-03](../sentinel-convergence/03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge-Native Security Detection | Memory-constrained deployment targets informing the 1 MiB budget (Section 9.1) |
| [SC-05](../sentinel-convergence/05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Telemetry Bridge Architecture | Schema constraints for new telemetry fields proposed in Section 14.5 |
| [SC-06](../sentinel-convergence/06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Stigmergic Coordination and Swarm Intelligence | Pheromone concentration dynamics used for compound detection (Section 10.4) |
| [SC-10](../sentinel-convergence/10-ADR-TELEMETRY-SCHEMA-ROLLOUT.md) | ADR: Telemetry Schema Rollout | Schema extension process for byte count/duration fields (Section 14.5) |

---

## 16. References

### 16.1 swarm-team-six Source References

- `crates/swarm-core/src/telemetry.rs` -- TelemetryEvent, TelemetryPayload, ProcessStartEvent, NetworkConnectEvent, DnsQueryEvent, AuthenticationEventData
- `crates/swarm-core/src/pheromone.rs` -- ThreatClass, PheromoneDeposit, PheromoneConcentration, decay model
- `crates/swarm-core/src/types.rs` -- Severity, AgentId, SwarmAction
- `crates/swarm-core/src/config.rs` -- PheromoneConfig, DetectionConfig, DetectorProfilesConfig
- `crates/swarm-whisker/src/detector.rs` -- DetectionStrategy trait, DetectionFinding, SuspiciousProcessTreeDetector
- `crates/swarm-whisker/src/composite.rs` -- CompositeDetector (pluggable strategy composition)
- `crates/swarm-whisker/src/stream.rs` -- findings_to_deposits, strategy_scoped_agent_id
- `crates/swarm-whisker/src/dns_exfiltration.rs` -- DnsExfiltrationDetector (Shannon entropy, burst detection)
- `crates/swarm-whisker/src/network_connect.rs` -- NetworkConnectDetector (beacon analysis, port allowlist)
- `crates/swarm-whisker/src/lateral_movement.rs` -- LateralMovementDetector (RDP failure tracking)
- `crates/swarm-whisker/src/credential_access.rs` -- CredentialAccessDetector (Kerberoasting, LSASS access)
- `crates/swarm-whisker/src/persistence.rs` -- PersistenceDetector (registry run keys, cron, systemd)
- `crates/swarm-whisker/src/supply_chain.rs` -- SupplyChainDetector (unsigned binary, DLL sideload)
- `crates/swarm-whisker/src/suspicious_scripting.rs` -- SuspiciousScriptingDetector (encoded commands, LOLBins)
- `crates/swarm-pheromone/src/substrate.rs` -- PheromoneSubstrate trait, InMemoryPheromoneSubstrate, concentration_for

### 16.2 Academic and Industry References

1. Welford, B.P. (1962). "Note on a method for calculating corrected sums of squares and products." *Technometrics* 4(3).
2. Roberts, S.W. (1959). "Control chart tests based on geometric moving averages." *Technometrics* 1(3). [EWMA]
3. Page, E.S. (1954). "Continuous inspection schemes." *Biometrika* 41(1/2). [CUSUM]
4. Cormode, G. and Muthukrishnan, S. (2005). "An improved data stream summary: the count-min sketch and its applications." *Journal of Algorithms* 55(1).
5. Flajolet, P., Fusy, E., Gandouet, O., and Meunier, F. (2007). "HyperLogLog: the analysis of a near-optimal cardinality estimation algorithm." *Conference on Analysis of Algorithms*.
6. Vitter, J.S. (1985). "Random sampling with a reservoir." *ACM Transactions on Mathematical Software* 11(1).
7. Chandola, V., Banerjee, A., and Kumar, V. (2009). "Anomaly detection: a survey." *ACM Computing Surveys* 41(3).
8. MITRE ATT&CK Framework: T1059, T1071, T1083, T1046, T1110, T1078, T1550, T1496, T1048.
9. Gates, C. and Taylor, C. (2006). "Challenging the anomaly detection paradigm: a provocative discussion." *Proceedings of the 2006 workshop on New security paradigms*.
10. Axelsson, S. (2000). "The base-rate fallacy and the difficulty of intrusion detection." *ACM Transactions on Information and System Security* 3(3).
11. Dorigo, M. and Stutzle, T. (2004). *Ant Colony Optimization*. MIT Press. [Stigmergic coordination foundations]
12. Adams, R.P. and MacKay, D.J. (2007). "Bayesian online changepoint detection." *arXiv:0710.3742*.
