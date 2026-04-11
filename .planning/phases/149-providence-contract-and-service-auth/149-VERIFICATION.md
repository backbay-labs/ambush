# Phase 149 Verification

status: passed

## Result

Phase 149 verification passed.

## Commands

- `cargo fmt --all`
- `cargo check -p swarm-crypto -p swarm-core -p swarm-response -p swarm-runtime --tests -j 1 --message-format short`
- `cargo test -p swarm-crypto hashing::tests::test_hmac_sha256_matches_known_vector -- --exact`
- `cargo test -p swarm-core config::tests::notification_request_signature_requires_non_empty_secret -- --exact`
- `cargo test -p swarm-runtime config::tests::notification_request_signature_secret_reference_is_resolved -- --exact`
- `cargo test -p swarm-response notification::tests::router_signs_notifications_with_hmac_header -- --exact`
- `cargo test -p swarm-runtime ingest::tests::providence_webhook_payload_includes_runtime_context_and_links -- --exact`

## Verified Behaviors

- The shared Providence webhook contract now emits `schema_version` and a typed `create_incident` mapping instead of raw ad hoc JSON.
- Notification channels fail closed when request-signature secrets are empty and resolve the HMAC secret through the same `@secret:` path as bearer tokens.
- Canonical JSON outbound notification delivery preserves bearer auth and emits the expected `X-Swarm-Signature: sha256=<hex>` header.
- The live `providence_webhook` runtime path now sends the typed contract with runtime context, operator drilldown links, bearer auth, and the matching HMAC signature.
