# Phase 248 Context

## Goal

Add a Windows Event Log-backed telemetry bridge that emits shared `TelemetryEvent` payloads for the shipped detector families through the existing bridge runtime.

## Repo State

- `swarm_core::config::TelemetryBridgeConfig` already owns repo-configured bridge selection.
- `swarm_runtime::bridge_runtime::BridgeRuntimeRegistry` already handles bridge construction, worker lifecycle, and shared health metrics.
- `swarm-ingest-json` already owns file-backed JSON normalization bridges and is the narrowest place to add repo-owned host-log adapters.

## Phase Focus

- Add a `WindowsEventLogBridgeConfig` variant under the existing runtime config surface.
- Implement `WindowsEventLogBridge` in `swarm-ingest-json` as a file-backed JSON bridge instead of introducing a second ingest path.
- Map representative Windows Security records into the shared schema:
  - `4624`/`4625` logon records -> `AuthenticationEvent`
  - `4688` process-create records -> `ProcessStart`
- Keep unsupported event IDs skippable so mixed Windows log exports do not fail closed on non-mapped records.

## Verification Target

- Focused `swarm-ingest-json` bridge tests for representative Windows auth and process-create records.
- Config validation proof that the new bridge kind deserializes and validates through `swarm-core`.
