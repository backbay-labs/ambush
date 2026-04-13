# Phase 188: Containerized NATS Test Harness - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 188 opens `v1.55` by turning JetStream testing from an ignored,
manually-booted workflow into a repo-owned harness. The workspace already ships
JetStream-backed pheromone code and ignored integration tests, but those tests
still depend on a developer manually starting NATS and exporting `NATS_URL`.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing repo-owned `docker-compose.yml` `nats` profile instead of
  introducing a second orchestration layer for local and CI JetStream tests.
- Add one shared harness entrypoint that starts JetStream, waits for health,
  exposes a stable `NATS_URL`, and tears the container down deterministically so
  later phases can invoke it from both pheromone and runtime test suites.
- Keep Phase 188 scoped to harness creation, CI bootstrapping, and at least one
  reusable smoke path; the full substrate-suite migration with identical
  assertions lands in Phase 189.

</decisions>

<code_context>
## Existing Code Insights

- [docker-compose.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/docker-compose.yml)
  already defines a JetStream-enabled `nats` service with health checks, but no
  test wrapper or CI path currently consumes it.
- [jetstream.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/tests/jetstream.rs)
  and [multi_instance.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/tests/multi_instance.rs)
  contain ignored JetStream tests that currently skip unless a developer
  separately provides a running NATS server.
- [.github/workflows/ci.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/.github/workflows/ci.yml)
  has no JetStream service container or compose-backed bootstrap step yet.
- [end_to_end_ingest_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/end_to_end_ingest_bench.rs)
  already accepts `NATS_URL`, so a shared harness can later serve both test and
  benchmark phases without inventing another backend contract.

</code_context>

<deferred>
## Deferred Ideas

- Migrating the full pheromone substrate assertion matrix onto JetStream is
  Phase 189 work, not a prerequisite to ship the reusable harness itself.
- Criterion latency baselines and sustained throughput measurement belong to
  Phases 190 and 191 once the real backend test harness is stable.

</deferred>
