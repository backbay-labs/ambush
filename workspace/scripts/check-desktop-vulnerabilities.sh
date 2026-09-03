#!/usr/bin/env bash
set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lockfile="$workspace_root/desktop/src-tauri/Cargo.lock"

# cargo-audit treats yanks as warnings unless every inherited warning is denied.
# Keep the reviewed chacha20 yank fail-closed without conflating it with the
# desktop graph's separately tracked unmaintained transitive dependencies.
python3 - "$lockfile" <<'PY'
import pathlib
import sys
import tomllib

lockfile = pathlib.Path(sys.argv[1])
packages = {
    (package["name"], package["version"])
    for package in tomllib.loads(lockfile.read_text())["package"]
}
blocked = {
    ("chacha20", "0.10.1"): "yanked release",
}
violations = [
    f"{name} {version}: {reason}"
    for (name, version), reason in blocked.items()
    if (name, version) in packages
]
if violations:
    raise SystemExit("desktop lockfile contains blocked packages:\n- " + "\n- ".join(violations))
PY

# These quick-xml advisories are already accepted in deny.toml: both locked
# copies parse trusted S3 or local-system XML and have no reachable patched
# upgrade. Every other active vulnerability in the independent desktop graph
# remains fatal; unmaintained/yanked warnings remain visible in the audit log.
cargo audit \
    --file "$lockfile" \
    --ignore RUSTSEC-2026-0194 \
    --ignore RUSTSEC-2026-0195
