#!/usr/bin/env bash
#
# The dev compose does not hand anyone a production foot-gun.
#
# WHY THIS EXISTS
#   A dev compose is the file people copy. Every property it demonstrates gets
#   demonstrated again on a machine that is reachable, so the defaults have to
#   be the safe ones even though this stack is meant for a laptop.
#
#   Three rules, each about a specific way this file could hurt someone:
#     C1  every published port binds 127.0.0.1. A bare "3000:3000" publishes on
#         every interface, which on a laptop on a conference network is an
#         unauthenticated relay on the internet.
#     C2  every service has a healthcheck. Without one `depends_on` waits for
#         the CONTAINER, not the service, and the relay starts against a
#         Postgres that is not accepting connections -- which fails in a way
#         that looks like a relay bug.
#     C3  no secret is inline. A key written into this file is a key in git
#         history forever; secrets reach the stack through env_file only.
#
# WHAT THIS CANNOT CHECK, AND WHY IT IS NOT CLAIMED
#   Image digest pinning. Two of the four services BUILD from source in this
#   file (`build:` not `image:`), so there is no reference to pin, and the two
#   that do carry images cannot have their digests verified here: this
#   repository's Docker daemon does not run (colima reports filesystem I/O
#   errors), so a digest written in would be transcribed rather than resolved.
#   A pinned digest nobody verified is worse than a tag, because it looks
#   verified. Recorded, not asserted.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="${1:-docker-compose.yml}"

# python3 standard library only: the CI image has no PyYAML.
scan() {
  python3 - "$1" <<'PY'
import re, sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().split("\n")

# Services are the two-space keys under a top-level `services:`.
service = None
in_services = False
services = {}
for i, raw in enumerate(lines):
    line = raw.split("#", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
    if re.match(r"^services:\s*$", line):
        in_services = True
        continue
    if line and not line.startswith(" ") and not line.startswith("-"):
        in_services = re.match(r"^services:", line) is not None
        continue
    if not in_services:
        continue
    m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
    if m:
        service = m.group(1)
        services[service] = {"start": i, "healthcheck": False, "ports": [], "inline": []}
        continue
    if service is None:
        continue
    if re.match(r"^    healthcheck:", line):
        services[service]["healthcheck"] = True
    # A published port is a "host:container" string under `ports:`.
    m = re.match(r'^      - "?([^"]+)"?\s*$', line)
    if m and re.search(r"^\s*ports:", lines[max(0, i - 1)].split("#")[0]) or (
        m and services[service].get("_in_ports")
    ):
        services[service]["ports"].append((i + 1, m.group(1)))
    if re.match(r"^    ports:", line):
        services[service]["_in_ports"] = True
    elif re.match(r"^    [A-Za-z]", line):
        services[service]["_in_ports"] = False
    # An inline secret: a KEY: value where the key names a secret and the value
    # is neither empty nor a ${...} interpolation.
    m = re.match(r"^      ([A-Z0-9_]*(KEY|SEED|TOKEN|PASSWORD|SECRET))\s*:\s*(.*)$", line)
    if m:
        value = m.group(3).strip().strip('"').strip("'")
        if value and not value.startswith("${"):
            services[service]["inline"].append((i + 1, m.group(1), value))

for name, info in services.items():
    for lineno, port in info["ports"]:
        if not port.startswith("127.0.0.1:"):
            print(f"C1 {path}:{lineno} service {name} publishes {port!r} on every interface")
    if not info["healthcheck"]:
        print(f"C2 {path}:{info['start'] + 1} service {name} has no healthcheck")
    for lineno, key, value in info["inline"]:
        print(f"C3 {path}:{lineno} service {name} sets {key} inline ({value!r})")

if not services:
    print(f"C0 {path} declares no services")
PY
}

# ---------------------------------------------------------------- fixture --
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

cat >"$FIXTURE_DIR/bad.yml" <<'BAD'
services:
  exposed:
    image: postgres:17-alpine
    ports:
      - "3000:3000"
    healthcheck:
      test: ["CMD", "true"]
  unhealthy:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
  leaky:
    image: x
    environment:
      AMBUSH_RELAY_PRIVATE_KEY: nsec1deadbeef
    healthcheck:
      test: ["CMD", "true"]
BAD

cat >"$FIXTURE_DIR/clean.yml" <<'CLEAN'
services:
  fine:
    image: postgres:17-alpine
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      # AMBUSH_RELAY_PRIVATE_KEY: never inline -- a comment is documentation
      PERCH_BRIDGE_NOSTR_SEED: ${PERCH_BRIDGE_NOSTR_SEED:-}
      SWARM_OPERATOR_TOKEN: ""
    healthcheck:
      test: ["CMD-SHELL", "pg_isready"]
CLEAN

for rule in C1 C2 C3; do
  if ! scan "$FIXTURE_DIR/bad.yml" | grep -q "^$rule "; then
    echo "check-perch-compose: SELF-TEST FAILED -- $rule caught nothing." >&2
    exit 2
  fi
done
CLEAN_HITS="$(scan "$FIXTURE_DIR/clean.yml")"
if [ -n "$CLEAN_HITS" ]; then
  echo "check-perch-compose: SELF-TEST FAILED -- clean control flagged:" >&2
  printf '%s\n' "$CLEAN_HITS" >&2
  exit 2
fi

# ------------------------------------------------------------------- scan --
HITS="$(scan "$TARGET")"
if [ -n "$HITS" ]; then
  echo "check-perch-compose: violations in $TARGET" >&2
  printf '%s\n' "$HITS" >&2
  echo >&2
  echo "C1 -> bind every published port to 127.0.0.1" >&2
  echo "C2 -> every service needs a healthcheck; depends_on waits for the container otherwise" >&2
  echo "C3 -> secrets reach the stack through env_file, never inline" >&2
  exit 1
fi

SERVICES="$(grep -cE '^  [A-Za-z0-9_.-]+:$' "$TARGET")"
echo "check-perch-compose: OK ($SERVICES services: every port on loopback, every service healthchecked, no inline secret; self-test 3 rules fired, 1 control clean)"
echo "check-perch-compose: NOT CHECKED -- image digests. Two services build from source and this repo's Docker daemon does not run, so a digest here would be transcribed rather than resolved."
