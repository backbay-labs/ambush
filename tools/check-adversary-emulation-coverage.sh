#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

report_path="$(mktemp "${TMPDIR:-/tmp}/swarm-adversary-emulation-XXXXXX.json")"
trap 'rm -f "$report_path"' EXIT

cargo test -p swarm-runtime --test adversary_emulation_integration -- --nocapture
cargo test -p swarm-runtime repo_adversary_emulation_coverage_report_meets_floor --lib -- --nocapture
cargo run -q -p swarm-runtime --bin generate_adversary_emulation_report -- --output "$report_path"

python3 - "$report_path" <<'PY'
import json
import sys

report_path = sys.argv[1]
with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)

scenario_count = report["scenario_count"]
technique_count = report["technique_count"]
coverage_percent = float(report["coverage_percent"])

if scenario_count < 7:
    raise SystemExit(f"expected at least 7 adversarial scenarios, got {scenario_count}")
if technique_count < 20:
    raise SystemExit(f"expected at least 20 mapped techniques, got {technique_count}")
if coverage_percent < 0.60:
    raise SystemExit(
        f"expected mapped coverage >= 0.60, got {coverage_percent:.2%}"
    )

print(
    "Adversary emulation coverage OK: "
    f"{scenario_count} scenarios, {technique_count} techniques, "
    f"{coverage_percent:.2%} mapped coverage"
)
PY
