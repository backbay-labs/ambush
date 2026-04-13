#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
PROJECT_NAME="${SWARM_NATS_COMPOSE_PROJECT:-swarm-nats-jetstream-$(date +%s)-$$}"
KEEP_STACK="${SWARM_NATS_KEEP_STACK:-0}"
START_TIMEOUT_SECS="${SWARM_NATS_START_TIMEOUT_SECS:-60}"

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 64
fi

compose() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile nats "$@"
}

cleanup() {
  local exit_code=$?
  if [[ "$KEEP_STACK" == "1" ]]; then
    echo "Keeping JetStream harness stack running for project $PROJECT_NAME" >&2
    exit "$exit_code"
  fi

  compose down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$exit_code"
}

trap cleanup EXIT INT TERM

require_port_mapping() {
  local private_port="$1"
  local deadline=$((SECONDS + START_TIMEOUT_SECS))
  local mapping

  while (( SECONDS < deadline )); do
    mapping="$(compose port nats "$private_port" 2>/dev/null || true)"
    if [[ -n "$mapping" ]]; then
      printf '%s\n' "${mapping##*:}"
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for nats port mapping on $private_port" >&2
  compose ps >&2 || true
  return 1
}

compose up -d nats >/dev/null

NATS_PORT="$(require_port_mapping 4222)"
NATS_HTTP_PORT="$(require_port_mapping 8222)"
NATS_URL="nats://127.0.0.1:${NATS_PORT}"
NATS_HTTP_URL="http://127.0.0.1:${NATS_HTTP_PORT}"

deadline=$((SECONDS + START_TIMEOUT_SECS))
until curl -fsS "$NATS_HTTP_URL/healthz" >/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "Timed out waiting for JetStream health at $NATS_HTTP_URL/healthz" >&2
    compose logs nats >&2 || true
    exit 1
  fi
  sleep 1
done

echo "JetStream harness ready: $NATS_URL" >&2

export NATS_URL
export NATS_HTTP_URL
export SWARM_NATS_COMPOSE_PROJECT="$PROJECT_NAME"

"$@"
