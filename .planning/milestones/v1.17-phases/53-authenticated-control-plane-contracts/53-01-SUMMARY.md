---
phase: 53-authenticated-control-plane-contracts
plan: 01
subsystem: operator-surface
tags:
  - operator
  - http
  - auth
  - runtime
one-liner: Added a local authenticated HTTP operator surface with repo-owned config, fail-closed bearer auth, and a protected status endpoint.
requires:
  - 52-packet-set-and-history-review-surfaces
provides:
  - local HTTP operator surface bootstrapped from repo config
  - loopback-only operator-surface config and validation
  - `swarmctl serve` for hosting the authenticated surface
affects: []
tech-stack:
  added:
    - axum
    - tower test helpers
  patterns:
    - HTTP stays a thin transport over existing control-plane types
key-files:
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/operator_http.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/lib.rs
    - rulesets/default.yaml
key-decisions:
  - "Keep the operator surface local-only and require a loopback bind address in canonical config."
  - "Use a bearer token from env and fail closed when the token is missing or empty."
  - "Expose status first and treat HTTP as a transport over the existing `DefaultControlPlane`."
patterns-established:
  - "The operator surface now starts from repo-owned config plus CLI results-dir wiring instead of introducing a second runtime model."
requirements-completed:
  - OPS-04
duration: 36min
completed: 2026-04-04
---

# Phase 53: Authenticated Control Plane Contracts Summary

**The runtime now has a local authenticated HTTP surface with one protected status endpoint and a repo-owned startup path through `swarmctl serve`.**

## Accomplishments

- Added canonical `operator_surface` config with loopback bind validation, bearer-token env settings, operator identity, and bounded list defaults.
- Added `crates/swarm-runtime/src/operator_http.rs` as the initial authenticated HTTP adapter over the existing control plane.
- Added bearer-token middleware and structured JSON API errors for the local operator surface.
- Added `swarmctl serve` to host the authenticated surface from the existing repo-owned config path.
- Added focused config and router tests that prove the surface fails closed without auth and returns JSON status when authorized.
