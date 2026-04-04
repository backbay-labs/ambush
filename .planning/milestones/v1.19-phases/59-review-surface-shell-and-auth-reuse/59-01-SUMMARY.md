---
phase: 59-review-surface-shell-and-auth-reuse
plan: 01
subsystem: operator-surface
tags:
  - operator
  - http
  - review
  - auth
one-liner: Added a read-only authenticated HTML review shell above the existing operator API.
requires:
  - 58-promotion-evidence-packets
provides:
  - authenticated local HTML review routes
  - shared review layout and navigation helpers
  - read-only review entry points wired through `swarmctl serve`
affects: []
tech-stack:
  added: []
  patterns:
    - The review client is a thin server-rendered layer above the existing authenticated Axum operator surface
key-files:
  modified:
    - crates/swarm-runtime/src/operator_http.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Reuse the same bearer-token middleware and shared operator state instead of inventing a second review auth model."
  - "Keep the local review shell read-only and single-node so it improves ergonomics without widening control-plane scope."
  - "Use server-rendered HTML because the repo has no existing UI framework and the current runtime already ships Axum."
patterns-established:
  - "Authenticated operator review now has a local HTML shell that composes directly over the existing JSON artifact surface."
requirements-completed:
  - OPS-08
  - OPS-11
completed: 2026-04-04
---

# Phase 59: Review Surface Shell And Auth Reuse Summary

**The runtime now serves a local authenticated HTML review shell that sits above the existing operator API and stays explicitly read-only.**

## Accomplishments

- Added `/v1/operator/review` and related HTML routes behind the same bearer-auth middleware already used by the JSON operator endpoints.
- Introduced shared HTML layout, escaping, navigation, and status-pill helpers so evidence and promotion review pages compose into one consistent local surface.
- Kept the review shell stable-ID-first: pages link back to existing authenticated API routes instead of reading raw store files or introducing a second artifact protocol.
- Documented the local review entry point and read-only scope in `docs/CONFIGURATION.md`.
