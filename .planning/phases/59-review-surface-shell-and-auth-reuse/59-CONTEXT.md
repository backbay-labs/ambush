# Phase 59 Context

## Goal

Introduce a local read-only evidence review surface that reuses the authenticated operator API and existing stable IDs instead of raw store inspection.

## Why This Phase Exists

`v1.18` made evidence export and verification real, but operators still have to work from JSON API responses and CLI renderers. The next seam is not quorum governance or a richer write-capable surface. It is a read-only local review shell that sits above the current authenticated Axum service and evidence stores.

## Inputs

- `.planning/PROJECT.md`
- `.planning/REQUIREMENTS.md`
- `.planning/ROADMAP.md`
- `.planning/STATE.md`
- `crates/swarm-runtime/src/operator_http.rs`
- `crates/swarm-runtime/src/evidence.rs`
- `docs/CONFIGURATION.md`

## Prior Decisions

- Keep the runtime single-node and local-first until independent trust boundaries exist.
- Reuse the existing authenticated HTTP surface instead of creating a second control-plane protocol.
- Keep the next review layer read-only; bounded writes stay on the existing maintenance and rollout APIs.
- Avoid adding a frontend stack when the current runtime already ships Axum and serializable report types.

## Assumptions

- A server-rendered HTML surface is the smallest credible “review client” for this repo because there is no existing UI framework in the workspace.
- The same bearer-auth middleware should protect the HTML review pages and the JSON endpoints.
- The first shell only needs navigation, layout, and stable-ID drill-down paths; richer filtering and promotion review can follow in Phases 60 and 61.

## Non-Goals

- No multi-user control, RBAC, or internet-exposed review surface.
- No direct mutation or maintenance actions from the new review pages.
- No new persistence model separate from the existing evidence and operator artifact stores.

## Phase Exit Signal

Operators can open a local authenticated HTML review shell that is clearly layered above the existing operator API, is read-only, and links into stable-ID evidence views without direct store inspection.
