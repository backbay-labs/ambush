#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deploy/integration-proof/compose.yaml"
PROJECT_NAME="${PROOF_PROJECT_NAME:-swarm-integration-proof}"
RUNTIME_PORT="${PROOF_RUNTIME_PORT:-19090}"

if [[ -z "${PROOF_RUNTIME_DIR:-}" ]]; then
  PROOF_RUNTIME_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-integration-proof.XXXXXX")"
fi
export PROOF_RUNTIME_DIR PROOF_RUNTIME_PORT="$RUNTIME_PORT"

docker_compose() {
  docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" "$@"
}

print_failure_context() {
  docker_compose ps || true
  docker_compose logs --tail=200 || true
}

cleanup() {
  if [[ "${KEEP_PROOF_STACK:-0}" != "1" ]]; then
    docker_compose down --remove-orphans --volumes >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

rm -rf \
  "$PROOF_RUNTIME_DIR/input" \
  "$PROOF_RUNTIME_DIR/mocks" \
  "$PROOF_RUNTIME_DIR/replay" \
  "$PROOF_RUNTIME_DIR/dead-letter"
mkdir -p \
  "$PROOF_RUNTIME_DIR/input" \
  "$PROOF_RUNTIME_DIR/mocks" \
  "$PROOF_RUNTIME_DIR/replay" \
  "$PROOF_RUNTIME_DIR/dead-letter"
cp \
  "$ROOT_DIR/deploy/integration-proof/fixtures/attack-process.jsonl" \
  "$PROOF_RUNTIME_DIR/input/attack-process.jsonl"

docker_compose down --remove-orphans --volumes >/dev/null 2>&1 || true
docker_compose up --build -d

HEALTH_URL="http://127.0.0.1:${RUNTIME_PORT}/healthz"
METRICS_URL="http://127.0.0.1:${RUNTIME_PORT}/metrics"

wait_for_runtime() {
  local attempt
  for attempt in $(seq 1 60); do
    if curl -fsS "$HEALTH_URL" >"$PROOF_RUNTIME_DIR/healthz.json"; then
      if python3 - "$PROOF_RUNTIME_DIR/healthz.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
components = payload["components"]
assert components["response"]["adapter"] == "crowdstrike_rtr"
assert components["siem_forward"]["enabled"] is True
assert components["siem_forward"]["transport"] == "splunk_hec"
assert components["telemetry_sources"]["bridge_backed"] == 1
assert components["startup_attestation"]["effective_ready"] is True
PY
      then
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}

wait_for_artifacts() {
  local attempt
  for attempt in $(seq 1 60); do
    if [[ -s "$PROOF_RUNTIME_DIR/mocks/crowdstrike-rtr.jsonl" ]] \
      && [[ -s "$PROOF_RUNTIME_DIR/mocks/splunk-hec.jsonl" ]] \
      && find "$PROOF_RUNTIME_DIR/replay" -type f -name '*.json' ! -name 'index.json' | grep -q .
    then
      return 0
    fi
    sleep 2
  done
  return 1
}

if ! wait_for_runtime; then
  echo "integration proof failed: runtime did not become ready" >&2
  print_failure_context
  exit 1
fi

if ! wait_for_artifacts; then
  echo "integration proof failed: expected proof artifacts were not produced" >&2
  print_failure_context
  exit 1
fi

curl -fsS "$METRICS_URL" >"$PROOF_RUNTIME_DIR/metrics.prom"

REPLAY_BUNDLE_PATH="$(find "$PROOF_RUNTIME_DIR/replay" -type f -name '*.json' ! -name 'index.json' | head -n 1)"
if [[ -z "$REPLAY_BUNDLE_PATH" ]]; then
  echo "integration proof failed: replay bundle path was not found" >&2
  print_failure_context
  exit 1
fi

if ! python3 - \
  "$PROOF_RUNTIME_DIR/healthz.json" \
  "$PROOF_RUNTIME_DIR/metrics.prom" \
  "$PROOF_RUNTIME_DIR/mocks/crowdstrike-rtr.jsonl" \
  "$PROOF_RUNTIME_DIR/mocks/splunk-hec.jsonl" \
  "$REPLAY_BUNDLE_PATH" <<'PY'
import json
import sys
from pathlib import Path

health_path, metrics_path, crowdstrike_path, splunk_path, replay_path = sys.argv[1:]
health = json.load(open(health_path, encoding="utf-8"))
metrics = Path(metrics_path).read_text(encoding="utf-8")
crowdstrike = [
    json.loads(line)
    for line in Path(crowdstrike_path).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
splunk = [
    json.loads(line)
    for line in Path(splunk_path).read_text(encoding="utf-8").splitlines()
    if line.strip()
]
replay = json.load(open(replay_path, encoding="utf-8"))

assert health["components"]["response"]["adapter"] == "crowdstrike_rtr"
assert health["components"]["siem_forward"]["transport"] == "splunk_hec"
assert health["components"]["telemetry_sources"]["status"] in {"configured", "degraded"}

assert (
    "swarm_bridge_events_processed{bridge=\"proof-process-bridge\",source_id=\"generic_json\"} 1"
    in metrics
    or "swarm_bridge_events_processed{source_id=\"generic_json\",bridge=\"proof-process-bridge\"} 1"
    in metrics
)
assert (
    "swarm_delivery_batches_total{outcome=\"success\",transport=\"splunk_hec\"} 1" in metrics
    or "swarm_delivery_batches_total{transport=\"splunk_hec\",outcome=\"success\"} 1" in metrics
)
assert "swarm_delivery_events_total{transport=\"splunk_hec\"} 1" in metrics
assert "swarm_adapter_outcomes_total{outcome=\"success\"} 1" in metrics

assert any(entry["path"] == "/oauth2/token" for entry in crowdstrike)
assert any(
    entry["path"] == "/devices/entities/devices-actions/v2"
    and entry["query"].get("action_name") == ["isolate"]
    and entry["body"]["ids"] == ["host-1"]
    for entry in crowdstrike
)

assert len(splunk) == 1
assert splunk[0]["path"] == "/services/collector/event"
assert splunk[0]["authorization"] == "Splunk proof-splunk-token"
assert splunk[0]["event_count"] == 1
event = splunk[0]["events"][0]["event"]
assert event["signature"] == "suspicious_process_tree"
assert event["event_id"] == "evt-proof-attack-1"
assert event["dest"] == "host-1"
assert event["process"] == "powershell"
assert event["command"].startswith("powershell.exe -enc ")

assert replay["event"]["event_id"] == "evt-proof-attack-1"
assert replay["audit"]["response"]["kind"] == "success"
assert replay["audit"]["response"]["action"] == "isolate_host"
assert replay["audit"]["response"]["details"]["adapter"] == "crowdstrike_rtr"
assert replay["audit"]["response"]["details"]["operation"] == "host_isolation"
assert replay["audit"]["response"]["details"]["payload"]["ids"] == ["host-1"]
PY
then
  echo "integration proof failed: validation checks did not pass" >&2
  print_failure_context
  exit 1
fi

echo "integration proof passed"
echo "runtime_url=$HEALTH_URL"
echo "runtime_dir=$PROOF_RUNTIME_DIR"
echo "replay_bundle=$REPLAY_BUNDLE_PATH"
echo "crowdstrike_log=$PROOF_RUNTIME_DIR/mocks/crowdstrike-rtr.jsonl"
echo "splunk_log=$PROOF_RUNTIME_DIR/mocks/splunk-hec.jsonl"

if [[ "${KEEP_PROOF_STACK:-0}" == "1" ]]; then
  echo "compose stack left running because KEEP_PROOF_STACK=1"
fi
