# Gap Report: Detection Robustness and ATT&CK Coverage

**Scope:** Gap analysis of Swarm Team Six detection capabilities in
`swarm-whisker` and `swarm-core`, evaluated against adversarial evasion
techniques and MITRE ATT&CK framework coverage.

**Date:** 2026-04-08

---

## Executive Summary

1. **No memory-only / fileless telemetry type exists.** The `TelemetryPayload`
   enum has no variant for in-memory operations (reflective DLL injection,
   process hollowing, .NET assembly loading). Entire ATT&CK technique families
   under Defense Evasion (T1055, T1620) are structurally undetectable.

2. **AMSI, ETW, and kernel callback telemetry are absent.** Modern adversaries
   routinely patch AMSI (`AmsiScanBuffer`) and blind ETW providers before
   executing payloads. Without telemetry for these tampering events, the engine
   cannot detect its own instrumentation being disabled.

3. **Process-tree detection is trivially evadable.** The
   `SuspiciousProcessTreeDetector` matches on exact parent-child process name
   pairs via string containment. Parent PID spoofing (T1134.004), process
   injection into benign parents, and renamed binaries defeat it completely.

4. **No image-load or module-load telemetry.** DLL sideloading detection in
   `SupplyChainDetector` only fires on `FilePersistence` events, not on actual
   DLL load operations. Adversaries who pre-stage libraries or use search-order
   hijacking at runtime are invisible.

5. **Command-line detection is string-match only.** All detectors that inspect
   `command_line` use `contains()` on lowercased strings. Obfuscation via
   string concatenation, environment variable expansion, caret insertion
   (`p^o^w^e^r^s^h^e^l^l`), and Unicode homoglyphs bypass every detector.

6. **No privilege escalation detector exists.** `ThreatClass::PrivilegeEscalation`
   is defined in `swarm-core` but no detector in `swarm-whisker` produces
   findings with that class. The entire Privilege Escalation tactic (TA0004) is
   uncovered.

7. **Beacon detection has a narrow jitter model.** The `NetworkConnectDetector`
   uses a fixed jitter-ratio threshold (default 0.20). Modern C2 frameworks
   (Cobalt Strike, Sliver, Brute Ratel) use adaptive jitter up to 50% and
   domain fronting, which evades the current statistical model.

8. **No Discovery or Impact tactic detectors.** The `ThreatClass` enum includes
   `Discovery` and `Impact` but no whisker strategy produces findings for
   either. Host enumeration, account discovery, data destruction, and
   ransomware pre-encryption behavior are unmonitored.

9. **Threat-intel enrichment is defined but unused.** `ThreatIntelEntry` and
   `ThreatIntelIndicatorType` are defined in `swarm-core/src/pheromone.rs` but
   no detector queries or correlates against threat-intel indicators during
   evaluation.

10. **No adversary-profile-driven evaluation methodology.** Testing uses
    synthetic single-event fixtures. There is no multi-stage attack simulation,
    no replay of real APT kill chains, and no false-positive rate benchmarking
    against production telemetry baselines.

---

## Detailed Findings

### 1. Missing Evasion Techniques

**Priority: Critical**

The following well-documented evasion families have no corresponding telemetry
type or detector logic:

| Evasion Technique | ATT&CK ID | Detection Gap |
|---|---|---|
| Process Hollowing | T1055.012 | No memory-operation telemetry payload |
| Reflective DLL Injection | T1620.001 | No in-memory module-load telemetry |
| Process Doppelganging | T1055.013 | No NTFS transaction telemetry |
| AMSI Bypass (patching) | T1562.001 | No AMSI health / tamper telemetry |
| ETW Patching | T1562.006 | No ETW provider integrity telemetry |
| Parent PID Spoofing | T1134.004 | Process tree uses reported parent name only |
| Syscall Unhooking (direct syscalls) | T1106 | No hook-integrity telemetry |
| Timestomping | T1070.006 | No file metadata change telemetry |
| Indicator Removal (log clearing) | T1070.001 | No log-integrity telemetry |
| Token Manipulation | T1134 | No token/privilege telemetry type |

**Recommended additions:**

- Add `MemoryOperation` payload variant covering injection, hollowing, and
  assembly-load events. This requires kernel-level or eBPF telemetry sources.
- Add `InstrumentationTamper` payload variant for AMSI, ETW, and callback
  integrity events.
- Add `process_id` and `parent_process_id` (numeric PID) fields to
  `ProcessStartEvent` so PID-spoofing correlation becomes possible.
- Add `TokenChange` payload variant for privilege and impersonation events.

### 2. Technique Coverage Blind Spots

**Priority: Critical**

ATT&CK tactics with declared `ThreatClass` enum variants but zero detector
coverage:

| Tactic | ThreatClass Variant | Detectors Producing It |
|---|---|---|
| Privilege Escalation (TA0004) | `PrivilegeEscalation` | None |
| Discovery (TA0007) | `Discovery` | None |
| Impact (TA0040) | `Impact` | None |
| Initial Access (TA0001) | `InitialAccess` | None |
| Defense Evasion (TA0005) | `DefenseEvasion` | None |

Partially covered tactics with significant technique gaps:

| Tactic | What Is Covered | Major Gaps |
|---|---|---|
| Execution (TA0002) | Process tree, LOLBin abuse, encoded PowerShell | No WMI event subscription (T1546.003), no scheduled task execution (T1053 exec side), no inter-process COM execution (T1559) |
| Persistence (TA0003) | Registry run keys, cron, systemd timers, scheduled tasks | No WMI event subscription persistence (T1546.003), no bootkit (T1542), no startup folder (T1547.001 folder variant), no image file execution options (T1546.012) |
| Credential Access (TA0006) | LSASS access, SAM read, Kerberoasting | No DCSync (T1003.006), no NTDS.dit extraction (T1003.003), no credential dumping via comsvcs.dll (T1003.001 variant), no AS-REP roasting (T1558.004) |
| Lateral Movement (TA0008) | WMI remote exec, PsExec, SSH, RDP brute force | No DCOM lateral movement (T1021.003), no remote service creation (T1569.002), no WinRM exploitation, no pass-the-hash/ticket (T1550) |
| Exfiltration (TA0010) | DNS tunneling | No HTTPS exfiltration (T1048.001), no exfil over alternative protocols (T1048), no exfil to cloud storage (T1567) |
| C2 (TA0011) | Beacon detection, suspicious ports | No domain fronting (T1090.004), no encrypted channel detection (T1573), no protocol tunneling (T1572), no multi-stage C2 (T1104) |

**Recommended additions:**

- Implement a `PrivilegeEscalationDetector` covering at minimum: named pipe
  impersonation, UAC bypass patterns, and service permission abuse.
- Implement a `DiscoveryDetector` for high-frequency enumeration patterns
  (rapid `net group`, `nltest`, `whoami /all`, `systeminfo` bursts).
- Implement an `ImpactDetector` for mass file modification patterns
  (ransomware pre-encryption), service stop/disable sequences, and volume
  shadow deletion.
- Extend `CredentialAccessDetector` with DCSync detection (replication
  traffic from non-DC sources) and AS-REP roasting patterns.

### 3. Cross-Document Consistency Issues

**Priority: High**

Items where the detection code and the threat model diverge:

- **Supply chain detector misclassifies LOLBin abuse.** The `SupplyChainDetector`
  classifies certutil/rundll32 abuse as `ThreatClass::SupplyChain`, but these
  are ATT&CK Defense Evasion (T1218) and Execution techniques, not supply
  chain compromise. The `SuspiciousScriptingDetector` also detects some of the
  same LOLBins (certutil, rundll32) and classifies them as
  `ThreatClass::Execution`. This creates duplicate, inconsistently-classified
  findings for the same event.

- **Persistence detector declares `dormancy_window_secs` but never uses it in
  detection logic.** The field exists in the profile and is emitted in evidence
  JSON but does not affect confidence scoring or finding generation. This
  suggests incomplete implementation of a time-based persistence heuristic.

- **Severity assignment is inconsistent across detectors.** The
  `NetworkConnectDetector` assigns `Severity::Medium` to suspicious ports but
  `Severity::High` to beaconing. The `LateralMovementDetector` assigns
  `Severity::Medium` to failed RDP brute force but `Severity::High` to unusual
  SSH. There is no documented severity model that explains these differences.

### 4. Depth Gaps

**Priority: High**

Sections requiring deeper analytical treatment:

- **No detection probability model.** No detector quantifies P(detection |
  technique variant). The confidence values (0.7, 0.9) are hardcoded defaults
  with no empirical basis or Bayesian updating from observed outcomes.

- **No false-positive rate analysis.** Shannon entropy threshold of 3.5 for
  DNS exfiltration was chosen without documented analysis of legitimate CDN
  subdomain entropy distributions. Legitimate services (e.g., AWS CloudFront
  distribution IDs, Azure CDN hashes) routinely produce subdomains with
  entropy above 3.5.

- **Beacon statistical model lacks rigor.** The beaconing detector uses
  mean-interval and CV-based jitter ratio, which fails against:
  - Adaptive jitter with non-Gaussian distributions
  - Sleep-based beacons with exponential backoff
  - Beacon intervals that overlap with legitimate polling (NTP, heartbeats)
  - A formal treatment of detection power vs. sample size is missing.

- **No evasion cost analysis.** The documents should quantify the operational
  cost to adversaries of evading each detector (e.g., "process renaming costs
  ~0 effort and defeats the process-tree detector" vs. "avoiding all DNS
  exfiltration patterns requires switching to HTTPS exfil, costing C2
  infrastructure changes").

### 5. Missing Adversary Profiles

**Priority: High**

The detection suite has not been evaluated against known threat group TTPs. The
following groups would expose specific detection gaps:

| Threat Group | Primary TTPs That Bypass Current Detection |
|---|---|
| **APT29 (Cozy Bear)** | WMI event subscriptions for persistence (no detector), EnvyScout HTML smuggling (no browser telemetry), SAML token forging (no cloud auth telemetry), Cobalt Strike with 40%+ jitter (exceeds beacon model) |
| **FIN7** | COM object abuse for execution (T1559.001, no detector), SQLRat memory-resident payloads (no memory telemetry), JSSLoader with dynamic C2 domain generation (DGA not detected) |
| **Lazarus Group** | Custom packed loaders evade signature-based detection, in-memory-only payload execution (no memory telemetry), watering hole via compromised supply chain sites (no URL reputation telemetry) |
| **APT41** | Rootkit deployment (T1014, no kernel telemetry), DLL search-order hijacking at load time (no image-load telemetry), bootkit persistence (T1542, no boot telemetry) |
| **Volt Typhoon** | Living-off-the-land exclusively via netsh, certutil, wmic without obvious indicators, LOLBin chains that individually appear benign but form malicious sequences (no behavioral chaining) |

**Recommended additions:**

- Build purple-team replay scenarios for each group's top-5 techniques.
- Implement behavioral sequence detection (kill-chain stage correlation) rather
  than single-event detection to catch multi-step campaigns.
- Add DGA (Domain Generation Algorithm) detection to the DNS exfiltration
  detector using character-level n-gram analysis.

### 6. Telemetry Gaps

**Priority: Critical**

The `TelemetryPayload` enum supports 7 payload types. The following additional
telemetry categories are necessary for meaningful coverage improvement:

| Telemetry Type | Required For | ATT&CK Coverage Gained |
|---|---|---|
| **ImageLoad / ModuleLoad** | DLL sideloading, reflective injection, search-order hijacking | T1574.*, T1055.*, T1620 |
| **MemoryOperation** | Process injection, hollowing, .NET assembly load | T1055.*, T1620.001 |
| **DriverLoad** | Rootkit detection, vulnerable driver exploitation | T1014, T1068 |
| **WmiEvent** | WMI persistence and execution | T1546.003, T1047 |
| **PipeEvent** | Named pipe impersonation, C2 over named pipes | T1134.*, T1570, T1572 |
| **ClipboardAccess** | Clipboard data theft | T1115 |
| **ScreenCapture** | Screen capture detection | T1113 |
| **ScriptBlockLog** | Deobfuscated PowerShell content | T1059.001 (deep inspection) |
| **CloudAuditLog** | Cloud identity and resource manipulation | T1078.004, T1537 |
| **UserAccountChange** | Account manipulation and creation | T1136.*, T1098 |
| **ServiceChange** | Service creation and modification | T1543.003, T1569.002 |

The most impactful additions for the current crate architecture would be
`ImageLoad`, `MemoryOperation`, and `ServiceChange`, as they enable detection
of the largest number of currently-blind technique families without requiring
cloud-specific integration work.

**Recommended additions:**

- Extend `TelemetryPayload` with `ImageLoad`, `MemoryOperation`, and
  `ServiceChange` as Phase 1 telemetry expansion.
- Add `ScriptBlockLog` as Phase 2 to enable deobfuscated script analysis
  (defeating encoded-command evasion).
- Add `DriverLoad` as Phase 3 for rootkit and BYOVD detection.

### 7. Evaluation Gaps

**Priority: High**

Current test coverage analysis:

- **All tests use single-event synthetic fixtures.** No test exercises
  multi-event temporal correlation (e.g., the beacon detector requires 4+
  events but tests only assert the threshold crossing, not detection quality
  across varying jitter distributions).

- **No adversarial test suite.** Tests verify that known-bad patterns trigger
  findings but never test that evasion variants avoid detection. A robust
  evaluation needs both true-positive and evasion-success tests.

- **No false-positive benchmark.** No test runs a representative corpus of
  benign telemetry through detectors to measure FP rate. Without this,
  threshold tuning (entropy, burst count, beacon jitter) is guesswork.

- **No performance benchmark.** The `DetectionStrategy::evaluate` trait
  requires strategies to be "fast" per documentation, but no benchmark measures
  latency per event or throughput under load. The `DnsExfiltrationDetector` and
  `NetworkConnectDetector` hold `Mutex`-guarded state that may contend under
  high event rates.

- **Missing evaluation frameworks:**
  - No MITRE ATT&CK Evaluations-style scoring (detection categories: N/A,
    None, Telemetry, General, Tactic, Technique)
  - No Atomic Red Team integration for automated technique validation
  - No PCAP/evtx replay capability for historical attack reconstruction
  - No ROC curve analysis for threshold-sensitive detectors (entropy, beacon
    jitter, burst count)

**Recommended additions:**

- Build a `swarm-whisker-bench` crate with criterion benchmarks for each
  detector under sustained load.
- Create an adversarial test harness that generates evasion variants
  (obfuscated command lines, jittered beacons, renamed processes) and measures
  detection rate degradation.
- Implement a benign-telemetry replay suite from sanitized production traces to
  measure false-positive rate per detector per threshold configuration.
- Add Atomic Red Team test mappings for each implemented technique.

---

## Priority Summary

| Priority | Finding | Section |
|---|---|---|
| Critical | No memory-operation or fileless telemetry type | 1, 6 |
| Critical | Five ATT&CK tactics have zero detector coverage | 2 |
| Critical | TelemetryPayload needs ImageLoad, MemoryOperation, ServiceChange | 6 |
| High | Process-tree detection trivially evadable via PID spoofing/renaming | 1 |
| High | Command-line detection defeated by basic obfuscation | 1 |
| High | No AMSI/ETW tamper detection | 1 |
| High | Duplicate/inconsistent LOLBin classification across detectors | 3 |
| High | No adversary-profile-driven evaluation | 5 |
| High | No adversarial evasion test suite or FP benchmarks | 7 |
| High | Beacon jitter model too narrow for modern C2 | 4 |
| High | No detection probability model or empirical threshold validation | 4 |
| Medium | Unused dormancy_window_secs field in persistence detector | 3 |
| Medium | DNS entropy threshold not validated against CDN distributions | 4 |
| Medium | Inconsistent severity assignment model | 3 |
| Medium | No DGA detection capability | 5 |
| Medium | Threat-intel types defined but never queried | 2 |
| Low | No performance benchmarks for stateful detectors | 7 |
| Low | No clipboard, screen capture, or cloud audit telemetry | 6 |
