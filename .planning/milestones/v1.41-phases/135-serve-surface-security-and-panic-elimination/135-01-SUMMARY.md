# Phase 135 Plan 01 Summary

## Delivered

- Replaced the panic-prone detector `Default` implementations across all eight `swarm-whisker` detectors with direct safe construction, and added a focused regression test that constructs every default detector without panicking.
- Removed the remaining demo proof-export `.expect()` calls in `crates/swarm-runtime/src/ingest.rs` and now return the existing conflict response when approval state is incomplete.
- Added bearer-token enforcement to `/v2/api/*` on top of the existing scoped platform API key gate, reusing `operator_surface.auth.token_env` and recording the authenticated operator identity plus optional TLS client identity in tracing.
- Added a shared TLS serve helper in `crates/swarm-runtime/src/serve.rs`, modeled by top-level `SwarmConfig.tls`, and wired both `swarm_detect --serve` and `swarmctl serve` through it with optional mTLS via `tls.client_ca_cert`.
- Updated `docs/CONFIGURATION.md` with the new platform API auth contract and the shared TLS/mTLS configuration shape.

## Notes

- Rustls now installs a process-level crypto provider once inside the shared serve helper so the TLS path stays deterministic even when multiple provider features are present in the dependency graph.
- Verification required clearing `target/debug/incremental` after the local disk filled during the first `cargo check`; only build artifacts were removed.
