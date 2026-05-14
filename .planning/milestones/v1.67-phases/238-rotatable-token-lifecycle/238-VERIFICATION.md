# Phase 238 Verification

status: passed

## Result

Phase 238 verification passed.

## Commands

- `CARGO_TARGET_DIR=target-v167-ratelimit cargo check -p swarm-core -p swarm-runtime -p swarm-cli`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-core --lib operator_surface_rejects_non_positive_token_expiry`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-runtime --lib status_route_reloads_rotated_bearer_token_without_rebuild`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-runtime --lib platform_api_routes_reload_rotated_bearer_token_without_restart`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-runtime --lib status_route_rejects_expired_bearer_token_with_context`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-runtime --lib platform_api_routes_reject_expired_bearer_token_with_context`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-runtime --lib status_route_requires_bearer_token`
- `CARGO_TARGET_DIR=target-v167-ratelimit cargo test -p swarm-runtime --lib platform_api_routes_require_bearer_and_api_key_but_health_and_ingest_do_not`

## Verified Behaviors

- Repo-owned config now accepts explicit bearer-token expiry metadata and rejects non-positive expiry timestamps.
- Operator-surface bearer auth observes rotated env-backed tokens without requiring a rebuild or process restart.
- Platform API bearer auth observes rotated env-backed tokens without restart and still requires both bearer and API key credentials.
- Expired bearer tokens fail closed with explicit expiry context on both the operator and platform protected routes.

## Notes

- The verification scope intentionally used focused auth tests rather than a broader integration sweep because this phase changes only the protected-request auth seam and status payloads.
- `cargo check -p swarm-cli` passed after adding the direct `ed25519-dalek` workspace dependency surfaced by the current CLI source.
