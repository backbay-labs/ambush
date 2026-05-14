# Phase 257 Plan 01 Summary

## Delivered

- Added `tools/generate-platform-python-client.sh` plus `clients/python/openapi-python-client-config.yml` to regenerate the checked-in Python package from the OpenAPI spec.
- Checked in the generated `clients/python/swarm-platform-client` package and removed generator cache noise from the output path.
- Added `clients/python/smoke_platform_client.py` and a live runtime smoke test in `crates/swarm-runtime/src/ingest/tests.rs` to prove the generated client against the shipped router.

## Notes

- The generated client currently models bearer auth directly and accepts the platform API key through shared headers, which matches the live runtime enforcement path.
- The smoke test runs `uv` in isolated no-project mode so unrelated Python workspace metadata outside this repo slice cannot interfere with contract proof.
