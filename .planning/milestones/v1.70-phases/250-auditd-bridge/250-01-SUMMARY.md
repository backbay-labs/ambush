# Phase 250 Plan 01 Summary

## Delivered

- Added `auditd` as a repo-owned bridge config kind under the shared runtime config surface.
- Implemented `AuditdBridge` in `swarm-ingest-json` on the same file-backed JSON bridge seam as the other host-log adapters.
- Mapped representative auditd records into the shared schema:
  - auth records -> `AuthenticationEvent`
  - `execve` -> `ProcessStart`
  - `connect` / `sendto` -> `NetworkConnect`
  - file-writing syscalls -> `FilePersistence`

## Notes

- The bridge deliberately emits the same shared payload types the detectors already understand, so the runtime and detector layers do not need a Linux-only special path.
- Auth typing is bounded to `ssh`, `sudo`, `login`, or a `pam` fallback based on the source record fields.
