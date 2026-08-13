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
//! # The `axum` edge that outlived SPLIT-01, and no longer does
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
//! $ cargo check -p swarm-runtime --all-targets --keep-going 2>&1 | grep '^error' -A2
//! error[E0432]: unresolved import `axum`
//!  --> crates/swarm-runtime/tests/dispatch_integration.rs:5:5
//! ...
//! ```
//!
//! (`--keep-going` is load-bearing in that second command: without it cargo
//! stops scheduling units at the first failing target and the list comes back
//! short. See ADR 0008's "Counting the dev targets".)
//!
//! So every `axum` use left in this crate is a test, an example or a bench --
//! `providence.rs` and `threat_intel_runtime.rs` each spin one up inside a
//! `#[cfg(test)] mod tests` to stand in for a remote server -- and the edge was
//! a dev-dependency wearing a normal dependency's clothes.
//!
//! THE LINE HAS SINCE MOVED to `[dev-dependencies]`, on a tree where nothing
//! else was moving, which is the only condition under which the measurement
//! above proves anything. Five dev targets, across seven files, hold it there,
//! so it moved rather than being deleted. Note what that does and does not
//! buy: it stops this crate NAMING `axum` outside dev targets, but `axum` is
//! still compiled for the normal profile via `swarm-ingest-tetragon -> tonic
//! -> axum`, so the graph-level removal SPLIT-01's prose implies is not what
//! landed.
//! `docs/decisions/0008-split-01-axum-edge-is-now-dev-only.md` records that,
//! and supersedes `0002-split-01-open-until-split-05.md`.
pub mod tls_identity;
