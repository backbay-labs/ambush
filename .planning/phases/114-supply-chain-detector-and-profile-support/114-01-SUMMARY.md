---
phase: 114-supply-chain-detector-and-profile-support
plan: 01
subsystem: detection
tags: [detection, supply-chain, signer, mitre]
requirements-completed: [PERSIST-02, PERSIST-03, PERSIST-04]
one-liner: "A new `SupplyChainDetector` now catches unsigned trusted-path execution, DLL side-loading, and signed-binary abuse with ATT&CK-tagged evidence."
completed: 2026-04-07
---

# Phase 114 Plan 01 Summary

**A new `SupplyChainDetector` now catches unsigned trusted-path execution, DLL side-loading, and signed-binary abuse with ATT&CK-tagged evidence.**

## Accomplishments

- Added `SupplyChainProfile` defaults and validation for trusted paths, trusted signers, suspicious loader pairs, and confidence thresholds.
- Implemented unsigned trusted-path execution detection using optional process signer metadata and ATT&CK technique `T1553.002`.
- Implemented DLL side-loading detection across `FilePersistence` events using loader-directory expectations and ATT&CK technique `T1574.001`.
- Implemented signed-binary abuse coverage for `certutil -urlcache` and `rundll32` remote or `javascript:` execution with ATT&CK techniques `T1218` and `T1218.011`.
- Emitted `ThreatClass::SupplyChain` consistently across every heuristic branch and re-exported the detector through `swarm-whisker`.

## Files Created Or Modified

- `crates/swarm-whisker/src/supply_chain.rs`
- `crates/swarm-whisker/src/lib.rs`

## Verification

- `cargo test -p swarm-whisker --lib`
- `cargo test --workspace`

## Notes

- Trusted signer matching intentionally requires both signer data and a valid signature signal; a missing signer does not silently count as trusted.
- The heuristic set is focused on trusted-path abuse and loader anomalies for this milestone, not on full package or repository provenance.
