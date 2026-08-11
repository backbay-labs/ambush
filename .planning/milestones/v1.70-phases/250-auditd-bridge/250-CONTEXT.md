# Phase 250 Context

## Goal

Add a Linux auditd-backed bridge that maps representative syscall and authentication signals into the shared telemetry schema with enough context for the shipped detector families.

## Repo State

- The detector family already consumes shared `AuthenticationEvent`, `ProcessStart`, `NetworkConnect`, and `FilePersistence` payloads.
- The new host-log bridges already share one file-backed JSON normalization seam in `swarm-ingest-json`.
- The runtime bridge registry and operator readiness probe now already understand file-backed host-log bridge construction.

## Phase Focus

- Add `AuditdBridgeConfig` to the shared config surface.
- Implement `AuditdBridge` for representative auditd records:
  - `USER_AUTH` / `USER_LOGIN` -> `AuthenticationEvent`
  - `execve` -> `ProcessStart`
  - `connect` / `sendto` -> `NetworkConnect`
  - `open` / `openat` / `creat` / `rename*` -> `FilePersistence`
- Keep the normalized payloads close enough to existing detector expectations that no bridge-specific detector path is needed.

## Verification Target

- Focused `swarm-ingest-json` tests for auditd auth, execve, network-connect, and file-write records.
- End-to-end proof in Phase 251 that auditd events flow through the shared registry and detector pipeline unchanged.
