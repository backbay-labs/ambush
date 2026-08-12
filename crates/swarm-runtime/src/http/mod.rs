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
pub mod rate_limit;
pub mod tls_identity;
