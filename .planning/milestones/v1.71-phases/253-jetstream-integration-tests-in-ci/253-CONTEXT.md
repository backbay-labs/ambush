# Phase 253 Context

## Goal

Run the JetStream-backed substrate integration surface in CI against a containerized NATS instance instead of leaving it as local-only proof.

## Starting Point

- `swarm-pheromone` already shipped JetStream and multi-instance integration tests, but they were ignored by default and only runnable manually.
- The repo already had a `tools/with-nats-jetstream.sh` harness, but CI did not call it and failure output was too thin for quick diagnosis.

## Constraints

- The harness had to stay repo-owned and portable so CI did not depend on hidden platform setup.
- JetStream failures needed actionable logs because the likely breakpoints span Docker, NATS boot, harness wiring, and the tests themselves.
