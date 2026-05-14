# Phase 238 Plan 01 Summary

## Delivered

- Extended [crates/swarm-core/src/config/operator.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config/operator.rs) with optional `token_expires_at_ms` metadata for both the legacy single-principal operator auth path and the multi-principal contract, then validated the new fields in [crates/swarm-core/src/config/validation.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config/validation.rs).
- Reworked operator bearer auth in [crates/swarm-runtime/src/http/core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) so the runtime still fails fast if configured token env vars are missing at startup, but re-reads the live env value on each protected request instead of caching long-lived bearer plaintext in auth state.
- Reworked platform bearer auth and Providence context-token reads in [crates/swarm-runtime/src/ingest/platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs) to follow the same per-request env-read pattern, allowing bearer rotation without restart while preserving fail-closed behavior.
- Added operator-visible lifecycle status to [crates/swarm-runtime/src/service/types.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service/types.rs) and [crates/swarm-runtime/src/service/runtime_service.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/service/runtime_service.rs) so expired bearer principals are surfaced through status payloads and warning text.
- Added focused lifecycle tests in [crates/swarm-runtime/src/http/core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc), [crates/swarm-runtime/src/ingest/tests.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/tests.rs), and a small direct-dependency fix in [crates/swarm-cli/Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-cli/Cargo.toml) that surfaced while verifying the updated workspace build.

## Notes

- Rotation in this phase is env-backed and immediate on the next protected request. There is no grace-period overlap between old and new bearer values.
- API key rotation and request-throttling behavior remain outside this slice; Phase 239 owns HTTP rate limiting.
