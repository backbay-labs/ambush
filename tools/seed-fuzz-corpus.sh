#!/usr/bin/env bash
#
# Phase 287 FUZZ-02. Seeds each of the four cargo-fuzz targets'
# `fuzz/corpus/<target>/` directories from `scenarios/*.yaml` and
# `rulesets/*.yaml`, converting each fixture into that target's real wire
# format rather than copying it verbatim:
#
#   - ingest_json_decode:    each scenario event, re-encoded as JSON (it is
#                            already exactly a TelemetryEvent in YAML).
#   - ingest_sentinel_decode: a Prometheus text-exposition sample derived
#                            from each scenario event's own host_id/timestamp
#                            (no fixture carries this format natively).
#   - ingest_tetragon_decode: each `process_start` scenario event, encoded as
#                            a real `GetEventsResponse{ProcessExec}` protobuf
#                            message via the same `prost` derive the decoder
#                            decodes with.
#   - ruleset_yaml_parse:    every fixture, copied byte-for-byte -- raw YAML
#                            text IS this target's wire format.
#
# The conversion itself is a small Rust binary (fuzz/corpus-seed/), not bash:
# faithfully re-encoding to JSON and, especially, to protobuf is not a
# reasonable thing to hand-roll in shell, and this repo's own convention
# (tools/check-gates-wired.sh's header) is not to lean on non-stdlib Python
# packages like PyYAML in CI either. This script is the bash entry point
# FUZZ-02 names; it does no parsing itself, only invokes the real one and
# checks its result.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SEED_MANIFEST="fuzz/corpus-seed/Cargo.toml"
if [ ! -f "$SEED_MANIFEST" ]; then
  echo "missing $SEED_MANIFEST; refusing to pass silently" >&2
  exit 1
fi

echo "seeding fuzz corpora from scenarios/*.yaml and rulesets/*.yaml..."
cargo run --quiet --manifest-path "$SEED_MANIFEST" --

targets=(
  ingest_json_decode
  ingest_sentinel_decode
  ingest_tetragon_decode
  ruleset_yaml_parse
)

status=0
for target in "${targets[@]}"; do
  dir="fuzz/corpus/${target}"
  count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
  if [ "$count" -eq 0 ]; then
    echo "::error::${dir} has zero corpus entries after seeding; refusing to pass silently" >&2
    status=1
    continue
  fi
  echo "seeded ${count} entr$([ "$count" -eq 1 ] && echo y || echo ies) into ${dir}"
done

exit "$status"
