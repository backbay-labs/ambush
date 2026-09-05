#!/usr/bin/env bash
#
# The Perch console has exactly fourteen surfaces.
#
# WHY THIS EXISTS
#   Fourteen is a decision, not a count that happened. The cost of a surface is
#   not its code; it is the place a person has to remember to look during an
#   incident. A fifteenth surface is one an operator was never told about, and
#   surfaces arrive one reasonable addition at a time, each defensible on its
#   own. So the number is written down, and adding to it means editing this
#   manifest in the same commit -- which is exactly the review this deserves.
#
# WHAT IS COVERED
#   tools/perch-surfaces.tsv
#     P1  exactly fourteen data rows
#     P2  every routed row's path is declared in workspace/desktop/src/app/routes.ts
#     P3  every row's component file exists
#     P4  no duplicate id, route or component
#
# WHAT THIS CANNOT SEE
#   A screen that exists and is not in the manifest, unless it is routed --
#   an unrouted component reached from inside another surface is invisible to
#   any static count. P2 catches the routed case, which is the one that puts a
#   new place in the operator's head.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MANIFEST="${1:-tools/perch-surfaces.tsv}"
ROUTES="${2:-workspace/desktop/src/app/routes.ts}"

# One scan, shared by the fixture and the real manifest, so they cannot drift.
scan() {
  python3 - "$1" "$2" "$3" <<'PY'
import re, sys, os

manifest, routes_path, root = sys.argv[1], sys.argv[2], sys.argv[3]

rows = []
for line in open(manifest, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    fields = line.split("\t")
    if fields[0] == "id":
        continue
    if len(fields) != 4:
        print(f"P0 row has {len(fields)} columns, expected 4: {line!r}")
        continue
    rows.append(fields)

if len(rows) != 14:
    print(f"P1 manifest has {len(rows)} surfaces, expected exactly 14")

routes_src = open(routes_path, encoding="utf-8").read()
declared = set(re.findall(r'route\(\s*"([^"]+)"', routes_src))
# `index("index.tsx")` IS the "/" route; the virtual-file helper names it by
# position rather than by path, so a manifest row for "/" would otherwise read
# as undeclared while the route exists.
if re.search(r'\bindex\(\s*"', routes_src):
    declared.add("/")
for _id, _surface, route, _component in rows:
    if route != "-" and route not in declared:
        print(f"P2 {_id} claims route {route}, which {routes_path} does not declare")

for _id, _surface, _route, component in rows:
    if not os.path.isfile(os.path.join(root, component)):
        print(f"P3 {_id} names {component}, which does not exist")

for column, index in (("id", 0), ("route", 2), ("component", 3)):
    seen = {}
    for row in rows:
        value = row[index]
        if column == "route" and value == "-":
            continue
        if value in seen:
            print(f"P4 duplicate {column} {value!r} on {seen[value]} and {row[0]}")
        seen[value] = row[0]

routed = sum(1 for r in rows if r[2] != "-")
print(f"#counts {len(rows)} {routed} {len(rows) - routed}")
PY
}

# ---------------------------------------------------------------- fixture --
# A gate that has never been observed to fail is not a gate.
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
printf 'route("/real", "real.tsx"),\n' >"$FIXTURE_DIR/routes.ts"
mkdir -p "$FIXTURE_DIR/root"
for i in $(seq 1 15); do : >"$FIXTURE_DIR/root/present$i.tsx"; done

fixture_rows() {
  printf 'id\tsurface\troute\tcomponent\n'
  local n="$1"
  for i in $(seq 1 "$n"); do
    printf 'S%s\tSurface %s\t-\tpresent%s.tsx\n' "$i" "$i" "$i"
  done
}

fixture_rows 15 >"$FIXTURE_DIR/fifteen.tsv"
fixture_rows 13 >"$FIXTURE_DIR/thirteen.tsv"
fixture_rows 14 >"$FIXTURE_DIR/fourteen.tsv"
{ fixture_rows 13; printf 'S14\tMissing\t-\tabsent.tsx\n'; } >"$FIXTURE_DIR/missing.tsv"
{ fixture_rows 13; printf 'S14\tUnrouted\t/nowhere\tpresent14.tsx\n'; } >"$FIXTURE_DIR/unrouted.tsv"
{ fixture_rows 13; printf 'S14\tDuplicate\t-\tpresent1.tsx\n'; } >"$FIXTURE_DIR/duplicate.tsv"

check_fixture() {
  local name="$1" rule="$2"
  if ! scan "$FIXTURE_DIR/$name" "$FIXTURE_DIR/routes.ts" "$FIXTURE_DIR/root" | grep -q "^$rule"; then
    echo "check-perch-surface-count: SELF-TEST FAILED -- $rule caught nothing on $name" >&2
    exit 2
  fi
}
check_fixture fifteen.tsv P1
check_fixture thirteen.tsv P1
check_fixture missing.tsv P3
check_fixture unrouted.tsv P2
check_fixture duplicate.tsv P4

CLEAN="$(scan "$FIXTURE_DIR/fourteen.tsv" "$FIXTURE_DIR/routes.ts" "$FIXTURE_DIR/root" | grep -v '^#counts' || true)"
if [ -n "$CLEAN" ]; then
  echo "check-perch-surface-count: SELF-TEST FAILED -- clean control flagged:" >&2
  printf '%s\n' "$CLEAN" >&2
  exit 2
fi

# ------------------------------------------------------------------- scan --
OUT="$(scan "$MANIFEST" "$ROUTES" "$ROOT_DIR")"
HITS="$(printf '%s\n' "$OUT" | grep -v '^#counts' || true)"
COUNTS="$(printf '%s\n' "$OUT" | grep '^#counts' || true)"

if [ -n "$HITS" ]; then
  echo "check-perch-surface-count: violations" >&2
  printf '%s\n' "$HITS" >&2
  echo >&2
  echo "P1 -> fourteen is a decision; adding a surface means editing tools/perch-surfaces.tsv" >&2
  echo "P2 -> a routed surface must have its path declared in routes.ts" >&2
  echo "P3 -> the component named must exist" >&2
  echo "P4 -> two rows must not name one id, route or component" >&2
  exit 1
fi

set -- $COUNTS
echo "check-perch-surface-count: clean: $2 surfaces, $3 routed, $4 unrouted (self-test: 4 rules fired, 1 control clean)"
