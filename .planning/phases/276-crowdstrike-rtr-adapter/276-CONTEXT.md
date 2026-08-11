# Phase 276 Context

## Goal

The runtime can execute host-isolation, process-kill, and file-quarantine actions through a repo-owned CrowdStrike RTR adapter validated against a mock RTR API.

## Repo State

- `v1.76` completed bounded external threat-intel ingestion plus cloud telemetry and detector proof on the shared runtime path.
- The response lane already has `ResponseExecutor`, `ResilientExecutor`, circuit-breaker, dead-letter, and `@secret:` resolution seams that should be reused.
- The next milestone shifts from ingest breadth to proving one real response-adapter path end to end.

## Phase Focus

- Implement one bounded CrowdStrike RTR adapter on the existing response-executor seam instead of widening the runtime into a generic EDR abstraction rewrite.
- Reuse the shipped resilience and auth-resolution contracts so the adapter inherits retry, circuit-breaker, and audit behavior.
- Keep proof repo-owned by validating against a mock RTR API rather than live credentials.

## Verification Target

- Repo-owned integration tests covering OAuth2 auth, session creation, host isolation, process kill, file quarantine, timeout handling, and error propagation against the mock RTR surface.
- Runtime proof that failed RTR executions still surface through the existing audit and dead-letter contracts.
