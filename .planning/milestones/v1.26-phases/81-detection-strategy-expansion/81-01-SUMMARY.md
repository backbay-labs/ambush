---
phase: 81-detection-strategy-expansion
plan: 01
subsystem: whisker
tags: [detection, telemetry, dns, lateral-movement, credential-access, scripting]
requirements-completed: [DET-01, DET-02, DET-03, DET-04]
one-liner: "swarm-whisker now understands DNS, registry, and authentication telemetry and ships four configurable detectors for DNS exfiltration, lateral movement, credential access, and suspicious scripting."
completed: 2026-04-05
---

# Phase 81 Plan 01 Summary

**swarm-whisker now understands DNS, registry, and authentication telemetry and ships four configurable detectors for DNS exfiltration, lateral movement, credential access, and suspicious scripting.**

## Accomplishments

- Extended `TelemetryPayload` with `dns_query`, `registry_access`, and `authentication_event` variants plus strict serde-backed event structs.
- Added `DnsExfiltrationDetector` with entropy, tunneling-signature, and per-source burst-volume heuristics plus YAML-configurable thresholds.
- Added `LateralMovementDetector` with WMI, PsExec, unusual SSH, and thresholded failed-RDP heuristics.
- Added `CredentialAccessDetector` for LSASS access, sensitive registry reads, and Kerberoasting-style `kerberos_tgs` activity.
- Added `SuspiciousScriptingDetector` for encoded PowerShell, download-and-execute chains, and LOLBin abuse.
- Added focused unit coverage proving the new detectors emit findings for malicious inputs and remain quiet on benign traffic.

## Files Created Or Modified

- `crates/swarm-whisker/src/detector.rs`
- `crates/swarm-whisker/src/lib.rs`
- `crates/swarm-whisker/src/dns_exfiltration.rs`
- `crates/swarm-whisker/src/lateral_movement.rs`
- `crates/swarm-whisker/src/credential_access.rs`
- `crates/swarm-whisker/src/suspicious_scripting.rs`

## Verification

- `cargo test -p swarm-whisker`

## Notes

- DNS and RDP burst heuristics use bounded in-memory counters so the detector profiles stay serializable while still covering the written breadth requirements.
