# Phase 256 Verification

status: passed

## Commands

- `CARGO_TARGET_DIR=target-v172-openapi cargo run -p swarm-runtime --bin generate_platform_openapi -- --output docs/openapi/v2-platform-openapi.json`
- `bash tools/check-platform-openapi.sh`

## Verified Behaviors

- The repo emits one stable OpenAPI 3.1 document for the shipped `/v2/api/` surface from repo-owned code.
- The checked-in spec regenerates without drift.
- The emitted document passes OpenAPI validation.
