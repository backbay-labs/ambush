#!/usr/bin/env bash
#
# Which cards may claim which attestation tier.
#
# WHY THIS EXISTS
#   A tier badge is the strongest claim this product makes on any surface: it
#   says an operator may rely on a chain of evidence. `maxTier` is the ceiling
#   on that claim, and a ceiling raised ahead of the evidence is exactly how a
#   console ends up displaying a badge for a chain nobody can fetch.
#
#   Raising one is therefore a decision with a precondition, and the
#   precondition is written down in the third column of the table. Editing the
#   registry alone fails this gate; editing the table alone fails it too. Both,
#   in one commit, is the review this deserves.
#
# WHAT IS COVERED
#   tools/perch-tier-allowlist.tsv against every `maxTier:` in
#   workspace/desktop/src/features/perch-evidence/ui/.
#     T1  every card in the table has a declaration
#     T2  every declaration has a table row
#     T3  the values are equal
#     T4  a zero-length extraction is a broken scanner, not a pass
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TABLE="${1:-tools/perch-tier-allowlist.tsv}"
UI_DIR="${2:-workspace/desktop/src/features/perch-evidence/ui}"

scan() {
  python3 - "$1" "$2" <<'PY'
import os, re, sys

table_path, ui_dir = sys.argv[1], sys.argv[2]

table = {}
for line in open(table_path, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    fields = line.split("\t")
    if fields[0] == "card":
        continue
    if len(fields) != 3:
        print(f"T0 row has {len(fields)} columns, expected 3: {line!r}")
        continue
    card, tier, _precondition = fields
    table[card] = tier

# Two declaration shapes: the registry's positional `notYetRendered(kind, …, N)`
# and a card module's `maxTier: N` beside its own `homeSurface`.
declared = {}
for root, _dirs, files in os.walk(ui_dir):
    for name in sorted(files):
        if not name.endswith((".tsx", ".ts")):
            continue
        src = open(os.path.join(root, name), encoding="utf-8").read()
        for m in re.finditer(
            r'notYetRendered\(\s*"([a-z]+)"\s*,\s*"[a-z]+"\s*,\s*\[[^\]]*\]\s*,\s*([012])\s*\)',
            src,
        ):
            declared[m.group(1)] = m.group(2)
        # `<kind>CardEntry = defineSwarmCard({ … maxTier: N … })`
        for m in re.finditer(
            r"export const ([a-z]+)CardEntry\s*=\s*defineSwarmCard(?:<[^>]*>)?\(\{(.*?)\n\}\)", src, re.S
        ):
            tier = re.search(r"maxTier:\s*([012])", m.group(2))
            if tier:
                declared[m.group(1)] = tier.group(1)

if not declared:
    print("T4 extracted zero declarations; refusing to pass silently")
    sys.exit(0)

for card, tier in sorted(table.items()):
    if card not in declared:
        print(f"T1 {card} is in the table and declares no maxTier")
    elif declared[card] != tier:
        print(f"T3 {card} declares maxTier {declared[card]}, table says {tier}")

for card in sorted(declared):
    if card not in table:
        print(f"T2 {card} declares maxTier {declared[card]} and is not in the table")

print(f"#counts {len(table)}")
PY
}

# ---------------------------------------------------------------- fixture --
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
mkdir -p "$FIXTURE_DIR/ui"

printf 'card\tmaxTier\tprecondition\nfinding\t0\tneeds B6\nrollback\t1\tholds\n' \
  >"$FIXTURE_DIR/table.tsv"

cat >"$FIXTURE_DIR/ui/clean.tsx" <<'CLEAN'
export const findingCardEntry = defineSwarmCard({
  pillar: "evidence",
  homeSurface: ["case"],
  maxTier: 0,
  decode,
  Presenter,
})
const registry = {
  rollback: notYetRendered("rollback", "evidence", ["case"], 1),
}
CLEAN

cat >"$FIXTURE_DIR/ui/bumped.tsx" <<'BAD'
export const findingCardEntry = defineSwarmCard({
  pillar: "evidence",
  homeSurface: ["case"],
  maxTier: 2,
  decode,
  Presenter,
})
const registry = {
  rollback: notYetRendered("rollback", "evidence", ["case"], 1),
  stowaway: notYetRendered("stowaway", "evidence", ["case"], 2),
}
BAD

mkdir -p "$FIXTURE_DIR/empty" "$FIXTURE_DIR/missing"
# A tree that declares `finding` and never mentions `rollback`, which the
# table requires: T1's case, and the one a deleted card presenter produces.
cat >"$FIXTURE_DIR/missing/only-finding.tsx" <<'MISSING'
export const findingCardEntry = defineSwarmCard({
  pillar: "evidence",
  homeSurface: ["case"],
  maxTier: 0,
  decode,
  Presenter,
})
MISSING

check_fixture() {
  local dir="$1" rule="$2"
  if ! scan "$FIXTURE_DIR/table.tsv" "$FIXTURE_DIR/$dir" | grep -q "^$rule "; then
    echo "check-perch-tier-allowlist: SELF-TEST FAILED -- $rule caught nothing on $dir" >&2
    exit 2
  fi
}
mkdir -p "$FIXTURE_DIR/bumped" && mv "$FIXTURE_DIR/ui/bumped.tsx" "$FIXTURE_DIR/bumped/"
check_fixture bumped T3
check_fixture bumped T2
check_fixture missing T1
check_fixture empty T4

CLEAN_HITS="$(scan "$FIXTURE_DIR/table.tsv" "$FIXTURE_DIR/ui" | grep -v '^#counts' || true)"
if [ -n "$CLEAN_HITS" ]; then
  echo "check-perch-tier-allowlist: SELF-TEST FAILED -- clean control flagged:" >&2
  printf '%s\n' "$CLEAN_HITS" >&2
  exit 2
fi

# ------------------------------------------------------------------- scan --
OUT="$(scan "$TABLE" "$UI_DIR")"
HITS="$(printf '%s\n' "$OUT" | grep -v '^#counts' || true)"
if [ -n "$HITS" ]; then
  echo "check-perch-tier-allowlist: violations" >&2
  printf '%s\n' "$HITS" >&2
  echo >&2
  echo "A tier badge says an operator may rely on a chain of evidence. Raising a" >&2
  echo "ceiling is a decision with a precondition: change tools/perch-tier-allowlist.tsv" >&2
  echo "and the registry in one commit, and say in the third column what now holds." >&2
  exit 1
fi

set -- $(printf '%s\n' "$OUT" | grep '^#counts')
echo "check-perch-tier-allowlist: clean over $2 card(s) (self-test: 4 rules fired, 1 control clean)"
