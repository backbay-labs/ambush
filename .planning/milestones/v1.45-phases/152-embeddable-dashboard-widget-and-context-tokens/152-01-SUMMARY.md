# Phase 152 Plan 01 Summary

## Delivered

- Added repo-owned widget and token policy in `crates/swarm-core/src/config.rs`: `operator_surface.allowed_embed_origins` controls widget embedding, and `operator_surface.widget_token_ttl_secs` bounds short-lived read-only Providence context tokens.
- Implemented signed `ProvidenceContextScope` tokens plus scoped Providence link generation in `crates/swarm-runtime/src/providence.rs`, and updated the outbound Providence payload to emit widget, event-stream, findings, and incidents URLs carrying that shared scope.
- Added `/v1/demo/widget` in `crates/swarm-runtime/src/ingest.rs` as a self-contained HTML surface that reuses the existing dashboard snapshot and runtime SSE endpoints, applies `frame-ancestors` / `X-Frame-Options` headers from config, and renders only the scoped context supplied through URL parameters or a signed token.
- Extended the versioned platform API auth middleware so signed context tokens can authorize narrowly scoped read-only `GET /v2/api/findings` and `GET /v2/api/incidents` requests without requiring the Providence embedder to hold the full operator bearer token and API key pair.
- Updated `rulesets/default.yaml` and `docs/CONFIGURATION.md` to document the shipped widget/base-URL/token settings and the read-only token contract.

## Notes

- Phase 152 verification surfaced two implementation defects and both were fixed before closeout: fixed-timestamp test tokens were expiring immediately, and the nested `/v2/api` middleware path was matching only the fully prefixed URI instead of the router-local subpath.
- Context-token auth remains intentionally narrow. It is accepted only on scoped read-only platform routes and does not grant write access to the operator surface.
