# Phase 249 Context

## Goal

Add a Sysmon-backed telemetry bridge that maps process, network, and file activity into the shared schema without inventing a separate runtime path.

## Repo State

- The bridge runtime already has one shared registry, worker lifecycle, and health/metrics surface.
- `swarm-ingest-json` already owns the file-backed host-log normalization path introduced by earlier bridge milestones.
- The shipped detector families already consume `ProcessStart`, `NetworkConnect`, and `FilePersistence` payloads.

## Phase Focus

- Add a `SysmonBridgeConfig` under the existing bridge config enum.
- Implement `SysmonBridge` for representative Sysmon event IDs:
  - `1` process create -> `ProcessStart`
  - `3` network connection -> `NetworkConnect`
  - `11` file create -> `FilePersistence`
- Preserve signer and signed-status context on process-create records where the source export carries it.

## Verification Target

- Focused `swarm-ingest-json` tests for Sysmon process, network, and file mappings.
- Runtime registration proof that Sysmon now constructs through the shared bridge registry.
