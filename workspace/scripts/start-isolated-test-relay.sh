#!/usr/bin/env bash
# =============================================================================
# start-isolated-test-relay.sh — GUI read-model overhaul test harness (Dawn)
# =============================================================================
# Stands up a FULLY ISOLATED relay for seeding + parity/perf runs, from source
# on the current branch. Never touches the shared :3000 team relay or the
# default `ambush-*` dev stack. Backing services run under the dedicated
# `ambush-harness` Compose project (docker-compose.harness.yml); the relay runs
# in the foreground on override ports.
#
#   Topology (reuse this exact tuple for desktop parity runs):
#     compose project : ambush-harness
#     postgres        : localhost:5471  (db=ambush, user=ambush, pass=ambush_dev)
#     redis           : localhost:6471
#     minio           : localhost:9471 (console 9472)
#     relay main      : localhost:3030   ← AMBUSH_E2E_RELAY_URL=http://localhost:3030
#     relay health    : localhost:8088
#     relay metrics   : localhost:9202
#
# Usage:
#   ./scripts/start-isolated-test-relay.sh [--profile <cargo-profile>]
#
# Teardown (safe — scoped to our project only):
#   docker compose -p ambush-harness -f docker-compose.harness.yml down -v
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CARGO_PROFILE="${CARGO_PROFILE:-ci}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) CARGO_PROFILE="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Cargo names the development profile `dev`, but writes its binaries under
# target/debug. Accept `debug` as the user-facing spelling too.
case "${CARGO_PROFILE}" in
  dev|debug)
    CARGO_BUILD_PROFILE="dev"
    CARGO_TARGET_PROFILE="debug"
    ;;
  *)
    CARGO_BUILD_PROFILE="${CARGO_PROFILE}"
    CARGO_TARGET_PROFILE="${CARGO_PROFILE}"
    ;;
esac

PROJECT="ambush-harness"
COMPOSE_FILE="docker-compose.harness.yml"

# Isolated ports (distinct from :3000 team relay, default dev stack, and Eva's
# evaperf :5470/:6470/:9470/:3170 stack).
PG_PORT=5471
REDIS_PORT=6471
MINIO_PORT=9471
RELAY_MAIN=3030
RELAY_HEALTH=8088
RELAY_METRICS=9202
COMMUNITY_HOST="localhost:${RELAY_MAIN}"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
log() { echo -e "${BLUE}[isolated-relay]${NC} $*"; }
ok()  { echo -e "${GREEN}[isolated-relay]${NC} $*"; }
err() { echo -e "${RED}[isolated-relay]${NC} $*" >&2; }

# ── Backing services (scoped to ambush-harness only) ───────────────────────────
log "Bringing up backing services (project=${PROJECT})..."
docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" up -d

wait_pg() {
  for _ in $(seq 1 60); do
    if docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" exec -T postgres \
         pg_isready -U ambush >/dev/null 2>&1; then
      ok "Postgres ready"; return 0
    fi
    sleep 2
  done
  err "Postgres did not become ready"; return 1
}
wait_pg

# ── Schema + partitions ──────────────────────────────────────────────────────
export PGPASSWORD=ambush_dev
psql_h() { docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" exec -T postgres \
  psql -U ambush -d ambush -v ON_ERROR_STOP=1 "$@"; }

log "Resetting isolated database and applying schema..."
# This database belongs only to the ambush-harness Compose project. Reset it on
# every launch so stale partitions/events from an earlier proof cannot alter
# schema planning or test results.
psql_h -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
export PGSCHEMA_PLAN_HOST=localhost PGSCHEMA_PLAN_PORT=${PG_PORT}
export PGSCHEMA_PLAN_DB=ambush PGSCHEMA_PLAN_USER=ambush PGSCHEMA_PLAN_PASSWORD=ambush_dev
export PGHOST=localhost PGPORT=${PG_PORT} PGUSER=ambush PGDATABASE=ambush
./bin/pgschema apply --file schema/schema.sql --auto-approve
psql_h < scripts/reconcile-schema-after-pgschema.sql
ok "Schema applied"

# ── Deployment community + channels + members ────────────────────────────────
# setup-desktop-test-data.sh is the single writer of the dev community row and
# the channel/member seed. It keys everything off a fixed COMMUNITY_ID and an
# overridable host — point that host at OUR relay so the tenant binding matches,
# and point its DB env at OUR isolated postgres. (psql is on PATH, so it uses
# AMBUSH_DB_HOST/PORT rather than the shared `ambush-postgres` container.)
log "Seeding community (host=${COMMUNITY_HOST}), channels, and members..."
AMBUSH_COMMUNITY_HOST="${COMMUNITY_HOST}" \
  AMBUSH_DB_HOST=localhost AMBUSH_DB_PORT=${PG_PORT} AMBUSH_DB_USER=ambush \
  AMBUSH_DB_PASS=ambush_dev AMBUSH_DB_NAME=ambush \
  AMBUSH_DB_DOCKER_CONTAINER="${PROJECT}-postgres-1" \
  ./scripts/setup-desktop-test-data.sh
ok "Community + channels + members seeded"

# ── Build relay from source (current branch) ─────────────────────────────────
# The repo pins Rust via rust-toolchain.toml (1.95.0). Outside the hermit env a
# stray Homebrew `cargo` (1.89) shadows the pin and fails on sqlx's MSRV, so
# prefer the rustup shim, which honors the pin.
if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi
log "Building relay (profile=${CARGO_BUILD_PROFILE}, cargo=$(command -v cargo), $(cargo --version))..."
cargo build --profile "${CARGO_BUILD_PROFILE}" -p ambush-relay
ok "Relay built"

# ── Run relay (detached tmux session) ────────────────────────────────────────
# Run inside tmux, NOT the foreground: this script is invoked from ephemeral
# shells whose process group is reaped on return, which SIGTERMs a foreground
# relay ~seconds after startup. tmux fully daemonizes the session so the relay
# survives (same pattern the perf stack uses). Logs to ${RELAY_LOG}.
RELAY_LOG="${RELAY_LOG:-/tmp/dawn-relay-run.log}"
TMUX_SESSION="${TMUX_SESSION:-dawn-relay}"
RELAY_PRIVATE_KEY="$(openssl rand -hex 32)"
tmux kill-session -t "${TMUX_SESSION}" 2>/dev/null || true
if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"${RELAY_MAIN}" -sTCP:LISTEN >/dev/null 2>&1; then
  err "Port ${RELAY_MAIN} is already in use; refusing to report a stale relay as this harness."
  lsof -nP -iTCP:"${RELAY_MAIN}" -sTCP:LISTEN >&2 || true
  exit 1
fi
log "Starting relay in tmux session '${TMUX_SESSION}' on :${RELAY_MAIN} (health :${RELAY_HEALTH}, metrics :${RELAY_METRICS})..."
tmux new-session -d -s "${TMUX_SESSION}" "cd '${REPO_ROOT}' && env \
  DATABASE_URL=postgres://ambush:ambush_dev@localhost:${PG_PORT}/ambush \
  REDIS_URL=redis://localhost:${REDIS_PORT} \
  RELAY_URL=ws://localhost:${RELAY_MAIN} \
  AMBUSH_BIND_ADDR=0.0.0.0:${RELAY_MAIN} \
  AMBUSH_HEALTH_PORT=${RELAY_HEALTH} \
  AMBUSH_METRICS_PORT=${RELAY_METRICS} \
  AMBUSH_S3_ENDPOINT=http://localhost:${MINIO_PORT} \
  AMBUSH_S3_ACCESS_KEY=ambush_dev \
  AMBUSH_S3_SECRET_KEY=ambush_dev_secret \
  AMBUSH_S3_BUCKET=ambush-media \
  AMBUSH_RELAY_PRIVATE_KEY=${RELAY_PRIVATE_KEY} \
  AMBUSH_REQUIRE_AUTH_TOKEN=false \
  AMBUSH_RECONCILE_CHANNELS=true \
  './target/${CARGO_TARGET_PROFILE}/ambush-relay' > '${RELAY_LOG}' 2>&1"

# Wait for the main port to accept connections.
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "http://localhost:${RELAY_MAIN}/"; then
    ok "Relay live — AMBUSH_E2E_RELAY_URL=http://localhost:${RELAY_MAIN}"
    ok "Logs: ${RELAY_LOG}   Attach: tmux attach -t ${TMUX_SESSION}"
    ok "Stop relay: tmux kill-session -t ${TMUX_SESSION}"
    ok "Full teardown: docker compose -p ${PROJECT} -f ${COMPOSE_FILE} down -v"
    exit 0
  fi
  sleep 1
done
err "Relay did not come up on :${RELAY_MAIN} within 30s — check ${RELAY_LOG}"
exit 1
