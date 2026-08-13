//! The part of the operator HTTP surface that stayed in the composition root.
//!
//! # Placement (SPLIT-01 and SPLIT-05, phase 282)
//!
//! Everything else that lived here -- the authenticated operator surface, its
//! handlers, its HTML rendering and its tests -- moved to `swarm-runtime-http`
//! in SPLIT-01. Two items stayed behind, both because `ingest/` reads them from
//! non-test code and `ingest/` was still in this crate: `rate_limit`, and
//! `tls_identity`'s `TlsClientIdentity`.
//!
//! `rate_limit` is gone from here as of SPLIT-05. It could not go UP into
//! `swarm-runtime-http`, because the settled layering is
//! `swarm-runtime-http -> swarm-ingest-runtime -> swarm-runtime` and both the
//! top and the middle crate mount a rate-limited surface; promoting it would
//! have made the middle crate depend on the top one. It went DOWN instead, to
//! `swarm_core::http_rate_limit`, which is the only position both surfaces can
//! reach and is where its `HttpRateLimitConfig` already lived. The three status
//! types it produces -- `HttpRateLimitStatus`, `HttpRateLimitThreshold`,
//! `HttpRateLimitViolationRecord` -- went with it, because `service`'s operator
//! status report embeds the first as a field and so cannot follow ingest out.
//!
//! `TlsClientIdentity` still stays: it is produced by the TLS accept loop in
//! `swarm-runtime-http` and read back by `ingest/platform_api.rs`, so it is
//! below both and this is still the lowest crate that both can reach. It moves
//! when `ingest/` does, or down into `swarm-core` beside the rate limiter --
//! whichever SPLIT-05's remaining step finds cheaper.
//!
//! # The `axum` edge that outlived SPLIT-01
//!
//! SPLIT-01 undertook to take six transport dependencies out of
//! `swarm-runtime`'s manifest. Five left with the moved code; `axum` did not.
//! The attribution is reproducible rather than a judgement call: delete the
//! `axum` line from `crates/swarm-runtime/Cargo.toml` and run
//! `cargo check -p swarm-runtime --lib`. Before SPLIT-05 that yielded 52
//! errors, of which exactly one was in `rate_limit.rs` and the other 51 were in
//! `ingest/`. With the rate limiter moved, every remaining error is in
//! `ingest/`, so the whole of the surviving `axum` edge now belongs to the file
//! set SPLIT-05 extracts and nothing else in this crate holds it.
//!
//! `docs/decisions/0002-split-01-open-until-split-05.md` holds SPLIT-01 open
//! until that deletion lands. The phase owner may still prefer to amend the
//! requirement instead; recording that supersedes the ADR and this note with it.
pub mod tls_identity;
