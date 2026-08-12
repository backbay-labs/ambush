//! The part of the operator HTTP surface that stayed in the composition root.
//!
//! # Placement (SPLIT-01, phase 282)
//!
//! Everything else that lived here -- the authenticated operator surface, its
//! handlers, its HTML rendering and its tests -- moved to `swarm-runtime-http`.
//! `rate_limit` did NOT, because `ingest` uses it from non-test code:
//! `ingest/mod.rs` holds an `HttpRateLimiter` for the platform API surface and
//! `ingest/platform_api.rs` maps its `HttpRateLimitRejection` onto a 429.
//!
//! Promoting it into `swarm-runtime-http` would make `swarm-runtime` depend on
//! the transport crate, which is exactly the cycle the split exists to remove.
//! It therefore stays at its original path: `ingest` is untouched by the split,
//! and `swarm-runtime-http` reaches it as `swarm_runtime::http::rate_limit`.
//!
//! IF THIS CHANGES: once `ingest` no longer needs a rate limiter -- or once
//! `ingest` itself moves out of the composition root -- this module and the
//! `axum` dependency it forces can follow the rest of the surface upward.
//! Two items stayed for the same reason, and they are the only two:
//! `rate_limit`, and `tls_identity`'s `TlsClientIdentity` (produced by the TLS
//! accept loop above, read back here by `ingest/platform_api.rs`).
//!
//! # Why the `axum` edge outlived SPLIT-01, measured
//!
//! SPLIT-01 undertook to take six transport dependencies out of
//! `swarm-runtime`'s manifest. Five left with the moved code; `axum` did not.
//! The attribution is not a judgement call, it is reproducible: delete the
//! `axum` line from `crates/swarm-runtime/Cargo.toml` and run
//! `cargo check -p swarm-runtime --lib`. That yields 52 errors, 19 in
//! `ingest/platform_api.rs`, 8 in `ingest/providence_handlers.rs`, 7 each in
//! `ingest/mod.rs` and `ingest/demo.rs`, 6 in `ingest/soar_verdict_handlers.rs`,
//! 4 in `ingest/health.rs`, and 1 here in `rate_limit.rs`.
//!
//! All 52 land in SPLIT-05's file set: `ingest/`, plus the rate limiter that
//! SPLIT-05's own text names as an import it has to resolve. NONE land in
//! SPLIT-01's file set -- `http/` less `rate_limit`, `serve.rs`,
//! `operator_http.rs` -- because that set is fully extracted. The surviving
//! edge is not a SPLIT-01 remnant, and no further work inside SPLIT-01's
//! boundary can remove it.
//!
//! Nor can SPLIT-05 simply ride along inside SPLIT-01's diff. The coupling is
//! bidirectional: `ingest/` and `bridge_runtime.rs` import 28 distinct
//! `crate::` modules of the remainder, while four remainder files import back
//! into them from non-test code (`anti_tamper.rs:1`, `control.rs:8`,
//! `providence.rs:1`, `service/mod.rs:39`). Like SPLIT-03 before it, SPLIT-05
//! needs a trait inversion first; it is a separate extraction, not a rider.
//!
//! That scope question -- whether SPLIT-01's `axum` clause moves to SPLIT-05,
//! or SPLIT-01 stays open until SPLIT-05 lands -- is now answered on the record:
//! `docs/decisions/0002-split-01-open-until-split-05.md` holds SPLIT-01 open.
//! SPLIT-01 is NOT satisfied while `axum` is in `swarm-runtime`'s manifest,
//! whatever the state of the other five dependencies. The phase owner may still
//! prefer the amendment instead; recording it supersedes that ADR and this note
//! with it.
pub mod rate_limit;
pub mod tls_identity;
