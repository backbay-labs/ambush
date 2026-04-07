---
phase: 85-container-and-deployment-infrastructure
plan: 02
subsystem: deploy
tags: [docker, compose, image, nats, packaging]
requirements-completed: [DEPLOY-01, DEPLOY-02]
one-liner: "the repo now ships a multi-stage container image, compose orchestration, and a small default runtime image for swarm-detect with an optional internal NATS sidecar."
completed: 2026-04-05
---

# Phase 85 Plan 02 Summary

**the repo now ships a multi-stage container image, compose orchestration, and a small default runtime image for swarm-detect with an optional internal NATS sidecar.**

## Accomplishments

- Added `.dockerignore` to keep the build context small by excluding `target/`, `.planning/`, `vendor/reference/`, data directories, and editor artifacts.
- Added a multi-stage `Dockerfile` that builds `swarm_detect` and `swarmctl` in a Rust Bookworm builder and copies only the stripped binaries plus rulesets into a Debian slim runtime image.
- Updated the builder stage to `rust:1.94-bookworm` after validating that the lockfile now requires Rust newer than 1.85.
- Added `docker-compose.yml` with the `swarm-detect` service, `/healthz` health checks, ruleset volume mounting for live reload, and an optional NATS sidecar profile.
- Kept the NATS profile internal to the compose network so it starts reliably even when the host already has a local NATS daemon on port `4222`.
- Verified the resulting `swarm-team-six-swarm-detect:latest` image is about 39.8 MB, well under the 150 MB target.

## Files Created Or Modified

- `.dockerignore`
- `Dockerfile`
- `docker-compose.yml`
- `rulesets/default.yaml`

## Verification

- `docker compose config --quiet`
- `docker compose build`
- `docker compose up -d`
- `docker compose --profile nats up -d`
- `docker compose stop`

## Notes

- The default repo-owned ruleset now declares `response_adapter.kind: sandbox` explicitly so the container health output matches the shipped default runtime behavior.
