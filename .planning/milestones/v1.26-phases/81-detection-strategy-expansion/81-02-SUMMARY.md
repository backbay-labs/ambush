---
phase: 81-detection-strategy-expansion
plan: 02
subsystem: runtime
tags: [detection, replay, scenarios, integration-tests, mitre-attack]
requirements-completed: [DET-05]
one-liner: "All five detector strategies are now selectable through control and replay surfaces, and MITRE ATT&CK-tagged scenarios plus integration tests prove end-to-end detection for each new threat family."
completed: 2026-04-05
---

# Phase 81 Plan 02 Summary

**All five detector strategies are now selectable through control and replay surfaces, and MITRE ATT&CK-tagged scenarios plus integration tests prove end-to-end detection for each new threat family.**

## Accomplishments

- Extended `SupportedDetector` handling in `control.rs`, `replay.rs`, `canary.rs`, and `promotion.rs` so the runtime no longer assumes `suspicious_process_tree` is the only selectable strategy.
- Expanded replay candidate manifests and validation so offline experiments can serialize and instantiate all new detector profile types.
- Hardened drafting and mutation materialization to fail closed when pressure-driven mutation is requested for detector families that do not yet support profile mutation workflows.
- Added ATT&CK-tagged scenario fixtures for DNS tunneling, WMI lateral movement, LSASS credential access, encoded PowerShell, and a benign DNS baseline.
- Extended `critical_path_integration.rs` so each new fixture is executed with the correct strategy and asserted on the resulting detector ID.
- Updated the default ruleset comments to document the broader detector strategy surface without changing the shipped default baseline.

## Files Created Or Modified

- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/drafting.rs`
- `crates/swarm-runtime/src/canary.rs`
- `crates/swarm-runtime/src/promotion.rs`
- `crates/swarm-runtime/src/mutation.rs`
- `crates/swarm-runtime/tests/critical_path_integration.rs`
- `rulesets/default.yaml`
- `scenarios/dns-tunneling-exfil.yaml`
- `scenarios/lateral-movement-wmi.yaml`
- `scenarios/credential-access-lsass.yaml`
- `scenarios/scripting-encoded-powershell.yaml`
- `scenarios/benign-dns-baseline.yaml`

## Verification

- `cargo test -p swarm-runtime --test critical_path_integration`
- `cargo test -p swarm-runtime --tests`

## Notes

- The legacy replay-suite smoke test was narrowed to default-strategy-compatible fixtures so detector-specific scenarios do not falsely fail under the process-tree baseline.
