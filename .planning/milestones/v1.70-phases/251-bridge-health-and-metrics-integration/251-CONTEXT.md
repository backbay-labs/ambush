# Phase 251 Context

## Goal

Close the milestone by proving Windows Event Log, Sysmon, and auditd all participate in the shared runtime health, metrics, and detector pipeline surfaces.

## Repo State

- `BridgeRuntimeRegistry` already owns bridge worker lifecycle, shared health snapshots, and metrics export.
- Operator readiness and runtime status surfaces already consume bridge status generically through `BridgeStatusReport`.
- The three new host-log bridges compile and pass focused bridge tests, but the milestone still needs one fleet-level integration proof.

## Phase Focus

- Ensure the runtime registry constructs all three new bridge kinds.
- Ensure operator readiness probing validates file-backed Windows Event Log, Sysmon, and auditd sources through the same generic path.
- Add one end-to-end registry + Whisker proof that:
  - all three bridges run together
  - health and event-count metrics surface correctly
  - their normalized events drive existing detectors without a bridge-specific detector path

## Verification Target

- `cargo test -p swarm-runtime --test bridge_registry_integration`
- `cargo check -p swarm-core -p swarm-ingest-json -p swarm-runtime`
