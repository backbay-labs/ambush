# Phase 273 Context

## Goal

The runtime can ingest AWS CloudTrail and Kubernetes audit log telemetry through two new bridge variants that participate in the existing bridge health and metrics surface.

## Repo State

- `swarm-ingest-json` already ships repo-owned host-log adapters for Windows Event Log, Sysmon, and auditd on the shared bridge contract.
- `v1.76` Phase 272 is intended to establish external threat-intel enrichment before cloud telemetry sources join the same runtime lane.
- The operator and health surfaces already expose bridge status, which should stay the single visibility path for the new cloud sources.

## Phase Focus

- Extend the existing JSON bridge family with `cloudtrail` and `kubernetes_audit` variants instead of inventing a parallel ingestion stack.
- Preserve the shared `TelemetryPayload` and bridge-health contracts so cloud telemetry composes with the current runtime and operator surfaces.
- Keep the mapping bounded to stable CloudTrail and Kubernetes audit fields needed for later detector evidence.

## Verification Target

- Integration tests proving CloudTrail and Kubernetes audit JSON normalize into the correct `TelemetryPayload` variants with no mapped-field loss.
- Runtime proof that both bridge variants register through `SwarmConfig.runtime.telemetry_sources` and surface health metrics alongside existing bridges.
- Config validation proof that the new bridge variants fail closed on missing or malformed required mapping fields.
