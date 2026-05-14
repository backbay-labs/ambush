# Phase 277 Context

## Goal

The runtime can deliver detection findings to Splunk HEC with CIM-aligned field mapping, batching, and bounded resilience backed by a repo-owned mock endpoint.

## Repo State

- `v1.76` completed external signal ingestion, so the runtime now produces a broader set of signed findings to export.
- The response lane already has resilient executor, secret resolution, and audit-receipt seams that outbound delivery should reuse.
- Phase 276 is intended to prove one real response adapter before the SIEM lane closes the detect-to-deliver loop.

## Phase Focus

- Implement one Splunk HEC adapter on the existing executor seam, not a parallel delivery subsystem.
- Reuse `@secret:` token resolution, retry, circuit-breaker, and metrics contracts already shipped by the runtime.
- Keep batching bounded and explicit so delivery behavior stays observable and testable.

## Verification Target

- Repo-owned mock HEC integration tests covering authentication, batching, CIM field mapping, latency or byte metrics, and backpressure or error propagation.
- Proof that delivery receipts and failures remain visible on the existing audit surface.
