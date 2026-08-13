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
//! `TlsClientIdentity` still stays, and now for a settled reason rather than a
//! pending one. It is produced by the TLS accept loop in `swarm-runtime-http`
//! and read back by `swarm-ingest-runtime`'s `ingest/platform_api.rs`. Those are
//! the top and middle of `swarm-runtime-http -> swarm-ingest-runtime ->
//! swarm-runtime`, so this crate is the lowest position both can reach and it
//! did NOT follow `ingest/` out: putting it in the middle crate would leave the
//! type defined above one of its two consumers. It could still go down beside
//! the rate limiter in `swarm-core` if a third consumer ever appears below it;
//! nothing forces that today.
//!
//! # The `axum` edge that outlived SPLIT-01
//!
//! SPLIT-01 undertook to take six transport dependencies out of
//! `swarm-runtime`'s manifest. Five left with the moved code; `axum` did not.
//! The attribution has always been reproducible rather than a judgement call:
//! delete the `axum` line from `crates/swarm-runtime/Cargo.toml` and run
//! `cargo check -p swarm-runtime --lib`. Before SPLIT-05 that yielded 52 errors,
//! one in `rate_limit.rs` and 51 in `ingest/`. After the rate limiter moved,
//! all 51 remaining were in `ingest/`. With `ingest/` extracted it yields none:
//!
//! ```text
//! $ sed -i '' '/^axum.workspace = true$/d' crates/swarm-runtime/Cargo.toml
//! $ cargo check -p swarm-runtime --lib 2>&1 | grep -c '^error'
//! 0
//! $ cargo check -p swarm-runtime --all-targets 2>&1 | grep '^error' -A2
//! error[E0432]: unresolved import `axum`
//!  --> crates/swarm-runtime/tests/dispatch_integration.rs:5:5
//! ...
//! ```
//!
//! So every `axum` use left in this crate is a test, an example or a bench --
//! `providence.rs` and `threat_intel_runtime.rs` each spin one up inside a
//! `#[cfg(test)] mod tests` to stand in for a remote server -- and the edge is a
//! dev-dependency wearing a normal dependency's clothes.
//!
//! THE MANIFEST LINE IS DELIBERATELY LEFT IN PLACE HERE. SPLIT-05 was code
//! motion, and moving `axum` from `[dependencies]` to `[dev-dependencies]` is a
//! manifest change whose correctness is exactly the measurement above; it is
//! SPLIT-06's to make and to prove, on a tree where nothing else is moving.
//! `docs/decisions/0002-split-01-open-until-split-05.md` holds SPLIT-01 open
//! until it lands. What SPLIT-05 changed is that the blocker the ADR names is
//! gone: no non-test code in this crate holds the edge any more.
pub mod tls_identity;
