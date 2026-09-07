#!/usr/bin/env bash
#
# FALSIFY-03. The sync gate for Phase 285 Task 3's negative-falsifiability
# registry.
#
# `docs/assurance/MAPPING.md` (Phase 285 Tasks 1-2) names 15 fail-closed
# invariants and a positive test for each. A passing positive test proves the
# real function's behaviour matches one assertion; it does not prove that
# assertion would have caught a regression, because a check that always
# passes would pass the same positive test too. Task 3 closes that gap with
# one `negative_<name>.rs` test per invariant -- each one builds a
# DELIBERATELY BROKEN variant of the enforcing logic and shows it permits the
# exact input the real function denies -- and `docs/assurance/negative-registry.toml`
# is the index from `MAPPING.md` `Name` to that test's file and function.
#
# A registry is not a boundary. Nothing stops it from drifting the moment a
# `MAPPING.md` row is added without a matching entry, an entry is added for
# an invariant `MAPPING.md` no longer names, or an entry's `test_file`/
# `test_fn` stops resolving to a real, present test. This script makes that
# drift mechanical, the same way `tools/check-mapping.sh` (Task 2) does for
# the marker/`Path`/table three-way sync. Five checks, every invocation:
#
#   MISSING_REGISTRY_ENTRY -- a `MAPPING.md` row's `Name` has no
#     `[negative.<Name>]` table in the registry. This is the task's headline
#     requirement: every invariant must have a falsifiability entry.
#   ORPHAN_REGISTRY_ENTRY -- a registry `[negative.<Name>]` table names a
#     `Name` no `MAPPING.md` row has. A stale entry left behind by a rename
#     or a deleted invariant.
#   DANGLING_TEST_FILE -- an entry's `test_file` does not exist on disk.
#   DANGLING_TEST_FN -- an entry's `test_file` exists but no `fn <test_fn>`
#     is found in it (word-boundary aware, not a bare substring match).
#     DANGLING_TEST_FILE and DANGLING_TEST_FN together are the task's other
#     headline requirement: "the registry names an absent test file/fn".
#   CRATE_PATH_MISMATCH -- an entry's `test_file` does not live under
#     `crates/<its own crate field>/tests/`. Free to check once `crate` and
#     `test_file` are both read, and it catches a copy-paste error the other
#     four checks would not (e.g. `crate = "swarm-runtime"` pointing at a
#     `swarm-policy` test).
#
# WHY A HAND-ROLLED MAPPING.md READER BUT `tomllib` FOR THE REGISTRY
#   `MAPPING.md` is the same plain pipe-delimited GFM table
#   `check-mapping.sh` already reads structurally (split on `|`, strip
#   backticks) rather than by pattern-matching the raw line -- this script
#   reuses that exact approach so the two scripts can never disagree about
#   what a row's `Name` is. The registry is `docs/assurance/negative-registry.toml`,
#   real TOML (Task 3's own requirement), and `tomllib` is Python's standard
#   library since 3.11 -- not the external PyYAML this repo's gates avoid
#   (see check-gates-wired.sh's header). `ubuntu-latest` ships python3.12+,
#   and Task 1's own report already relied on `tomllib` to verify
#   `assumptions.toml` parses, so this is not a new portability assumption.
#
# NOT VACUOUS -- SIX PLANTED SCENARIOS, ONE SHARED RESOLVER, CHECKED BEFORE
# THE REAL TREE
#   Every invocation runs the identical resolver ($PY_HELPER, invoked the
#   same way every time) against a clean baseline plus five planted breaks --
#   one per finding type above -- before it is ever trusted against the real
#   `docs/assurance/MAPPING.md` and `docs/assurance/negative-registry.toml`.
#   Each planted scenario asserts BOTH that its own finding fires and that
#   the other four do not, so no finding type can be silently subsuming
#   another. If any scenario is not caught exactly as specified, this script
#   prints `FIXTURE FAILED` and exits 2 WITHOUT scanning the real files --
#   the same "a gate that cannot see its own planted subject is not a
#   passing gate" convention `check-mapping.sh` and
#   `check-no-unrouted-authorize.sh` already use.
#
# BASH 3.2
#   No `mapfile`, no associative arrays: macOS ships bash 3.2 and a gate a
#   developer cannot run locally is a gate that is only ever seen red in CI.
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MAPPING_FILE="docs/assurance/MAPPING.md"
REGISTRY_FILE="docs/assurance/negative-registry.toml"
CRATES_DIR="crates"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

py_helper="$workdir/negative_registry_check.py"

# --- the resolver, written once, invoked identically on every fixture and on
# the real tree. ------------------------------------------------------------
cat > "$py_helper" <<'PY'
import os
import re
import sys
import tomllib


def split_row(line):
    """Split one GFM table line into stripped, backtick-unwrapped cells.

    The same minimal delimited-row reader `check-mapping.sh` uses: split on
    '|' and only '|', so a cell containing '::' or ':' never confuses the
    column boundaries.
    """
    s = line.strip()
    if not s.startswith("|"):
        return []
    s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    cells = [c.strip() for c in s.split("|")]
    cleaned = []
    for c in cells:
        if len(c) >= 2 and c.startswith("`") and c.endswith("`"):
            c = c[1:-1]
        cleaned.append(c)
    return cleaned


def parse_mapping_names(path):
    """Return (list of Name values, None) or (None, error) for the first GFM
    table in path whose header row has a column literally named 'Name'."""
    if not os.path.isfile(path):
        return None, f"no such file: {path}"
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().split("\n")

    header_idx = None
    header = None
    for i, line in enumerate(lines):
        cells = split_row(line)
        if cells and cells[0] == "Name":
            header_idx = i
            header = cells
            break
    if header_idx is None:
        return None, "no header row found (expected a column literally named 'Name')"

    sep_idx = header_idx + 1
    if sep_idx >= len(lines):
        return None, "header row has no following separator row"
    sep_cells = split_row(lines[sep_idx])
    if not sep_cells or not all(re.match(r"^:?-+:?$", c) for c in sep_cells):
        return None, f"line {sep_idx + 1} is not a GFM separator row"

    names = []
    i = sep_idx + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip().startswith("|"):
            break
        cells = split_row(line)
        if len(cells) >= len(header):
            row = {header[j]: cells[j] for j in range(len(header))}
            name = row.get("Name", "")
            if name:
                names.append(name)
        i += 1

    if not names:
        return None, "zero data rows parsed; refusing to pass silently"
    return names, None


def load_registry(path):
    """Return (dict of Name -> entry table, None) or (None, error)."""
    if not os.path.isfile(path):
        return None, f"no such file: {path}"
    with open(path, "rb") as f:
        try:
            data = tomllib.load(f)
        except tomllib.TOMLDecodeError as error:
            return None, f"invalid TOML: {error}"
    negative = data.get("negative")
    if not isinstance(negative, dict) or not negative:
        return None, "no non-empty [negative.<Name>] table found; refusing to pass silently"
    return negative, None


FN_RE_TEMPLATE = r"(?<![A-Za-z0-9_])fn\s+{}\s*\("


def check(root, mapping_relpath, registry_relpath, crates_relpath):
    mapping_path = os.path.join(root, mapping_relpath)
    names, err = parse_mapping_names(mapping_path)
    if err:
        return [f"MAPPING_PARSE_ERROR\t{err}"]

    registry_path = os.path.join(root, registry_relpath)
    registry, err = load_registry(registry_path)
    if err:
        return [f"REGISTRY_PARSE_ERROR\t{err}"]

    mapping_names = set(names)
    registry_names = set(registry.keys())
    findings = []

    for name in sorted(mapping_names - registry_names):
        findings.append(f"MISSING_REGISTRY_ENTRY\t{name}")

    for name in sorted(registry_names - mapping_names):
        findings.append(f"ORPHAN_REGISTRY_ENTRY\t{name}")

    for name in sorted(registry_names & mapping_names):
        entry = registry[name]
        test_file = entry.get("test_file", "")
        test_fn = entry.get("test_fn", "")
        crate = entry.get("crate", "")
        if not test_file or not test_fn or not crate:
            findings.append(
                f"REGISTRY_ENTRY_MALFORMED\t{name}\tmissing one of crate/test_file/test_fn"
            )
            continue

        expected_prefix = f"{crates_relpath}/{crate}/tests/"
        if not test_file.startswith(expected_prefix):
            findings.append(
                f"CRATE_PATH_MISMATCH\t{name}\t{test_file}\tdoes not start with {expected_prefix}"
            )

        abs_test_file = os.path.join(root, test_file)
        if not os.path.isfile(abs_test_file):
            findings.append(f"DANGLING_TEST_FILE\t{name}\t{test_file}")
            continue

        with open(abs_test_file, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        fn_pattern = re.compile(FN_RE_TEMPLATE.format(re.escape(test_fn)))
        if not fn_pattern.search(text):
            findings.append(f"DANGLING_TEST_FN\t{name}\t{test_fn}\tnot found in {test_file}")

    return findings


def main():
    root, mapping_relpath, registry_relpath, crates_relpath = sys.argv[1:5]
    findings = check(root, mapping_relpath, registry_relpath, crates_relpath)
    if findings:
        for line in findings:
            print(line)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY

run_check() {
  # $1=root $2=mapping-relpath $3=registry-relpath $4=crates-relpath
  python3 "$py_helper" "$1" "$2" "$3" "$4"
}

fixture="$workdir/fixture"

# A clean baseline: one MAPPING.md row, one matching registry entry, one real
# test file with the fn the entry names.
reset_fixture() {
  rm -rf "$fixture"
  mkdir -p "$fixture/crates/x/tests"
  cat > "$fixture/MAPPING.md" <<'MD'
# Fixture mapping (self-test scaffolding only -- not the real docs/assurance/MAPPING.md)

| Name | Crate | Path | Source | Assumption | Denies |
|---|---|---|---|---|---|
| `FixtureAlpha` | x | `x::real_check` | `crates/x/src/lib.rs:2` | `ASSUME-FIXTURE` | A negative `x`. |
MD
  cat > "$fixture/negative-registry.toml" <<'TOML'
[negative.FixtureAlpha]
crate = "x"
test_file = "crates/x/tests/negative_fixture_alpha.rs"
test_fn = "negative_fixture_alpha"
target = "x::real_check"
TOML
  cat > "$fixture/crates/x/tests/negative_fixture_alpha.rs" <<'RS'
#[test]
fn negative_fixture_alpha() {
    assert!(true);
}
RS
}

assert_contains() {
  # $1=output $2=needle-regex $3=scenario-label
  if ! printf '%s\n' "$1" | grep -qE "$2"; then
    echo "check-negative-registry: FIXTURE FAILED -- scenario '$3' did not produce '$2'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$1" >&2
    exit 2
  fi
}

assert_absent() {
  # $1=output $2=needle-regex $3=scenario-label
  if printf '%s\n' "$1" | grep -qE "$2"; then
    echo "check-negative-registry: FIXTURE FAILED -- scenario '$3' wrongly produced '$2'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$1" >&2
    exit 2
  fi
}

assert_isolated() {
  # $1=output $2=expected-needle-regex $3=scenario-label $4..=other finding
  # types that must NOT also appear.
  local out="$1" needle="$2" label="$3"
  shift 3
  assert_contains "$out" "$needle" "$label"
  for other in "$@"; do
    assert_absent "$out" "$other" "$label"
  done
}

ALL_FINDING_TYPES=(
  '^MISSING_REGISTRY_ENTRY'
  '^ORPHAN_REGISTRY_ENTRY'
  '^DANGLING_TEST_FILE'
  '^DANGLING_TEST_FN'
  '^CRATE_PATH_MISMATCH'
)

others_except() {
  # Print every entry of ALL_FINDING_TYPES except $1.
  local skip="$1"
  for t in "${ALL_FINDING_TYPES[@]}"; do
    [ "$t" = "$skip" ] || echo "$t"
  done
}

# --- scenario 1: clean baseline must pass with zero findings ---------------
reset_fixture
rc=0; out="$(run_check "$fixture" "MAPPING.md" "negative-registry.toml" "crates")" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "check-negative-registry: FIXTURE FAILED -- clean baseline scenario did not exit 0" >&2
  printf '%s\n' "$out" >&2
  exit 2
fi
assert_contains "$out" '^OK\b' "clean baseline"

# --- scenario 2: a MAPPING.md row with no registry entry must be caught ---
reset_fixture
cat >> "$fixture/MAPPING.md" <<'MD'
| `FixtureOrphanMappingRow` | x | `x::another_check` | `crates/x/src/lib.rs:9` | `ASSUME-FIXTURE` | Another negative `x`. |
MD
rc=0; out="$(run_check "$fixture" "MAPPING.md" "negative-registry.toml" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-negative-registry: FIXTURE FAILED -- planted missing registry entry was not caught" >&2
  exit 2
fi
assert_isolated "$out" '^MISSING_REGISTRY_ENTRY\s.*FixtureOrphanMappingRow' "missing registry entry" \
  $(others_except '^MISSING_REGISTRY_ENTRY')

# --- scenario 3: a registry entry naming a Name absent from MAPPING.md must
# be caught, and ONLY as that (its own file/fn are real, so nothing else
# fires) ---------------------------------------------------------------
reset_fixture
cat > "$fixture/crates/x/tests/negative_fixture_ghost.rs" <<'RS'
#[test]
fn negative_fixture_ghost() {
    assert!(true);
}
RS
cat >> "$fixture/negative-registry.toml" <<'TOML'

[negative.FixtureGhostRegistryEntry]
crate = "x"
test_file = "crates/x/tests/negative_fixture_ghost.rs"
test_fn = "negative_fixture_ghost"
target = "x::ghost_check"
TOML
rc=0; out="$(run_check "$fixture" "MAPPING.md" "negative-registry.toml" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-negative-registry: FIXTURE FAILED -- planted orphan registry entry was not caught" >&2
  exit 2
fi
assert_isolated "$out" '^ORPHAN_REGISTRY_ENTRY\s.*FixtureGhostRegistryEntry' "orphan registry entry" \
  $(others_except '^ORPHAN_REGISTRY_ENTRY')

# --- scenario 4: a registry entry naming an absent test FILE must be
# caught, and ONLY as that ----------------------------------------------
reset_fixture
python3 - "$fixture/negative-registry.toml" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
text = text.replace(
    "crates/x/tests/negative_fixture_alpha.rs",
    "crates/x/tests/negative_fixture_alpha_does_not_exist.rs",
)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
rc=0; out="$(run_check "$fixture" "MAPPING.md" "negative-registry.toml" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-negative-registry: FIXTURE FAILED -- planted dangling test file was not caught" >&2
  exit 2
fi
assert_isolated "$out" '^DANGLING_TEST_FILE\s.*FixtureAlpha' "dangling test file" \
  $(others_except '^DANGLING_TEST_FILE')

# --- scenario 5: a registry entry naming an absent test FN (file exists,
# fn does not) must be caught, and ONLY as that --------------------------
reset_fixture
python3 - "$fixture/negative-registry.toml" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
text = text.replace(
    'test_fn = "negative_fixture_alpha"',
    'test_fn = "negative_fixture_alpha_does_not_exist"',
)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
rc=0; out="$(run_check "$fixture" "MAPPING.md" "negative-registry.toml" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-negative-registry: FIXTURE FAILED -- planted dangling test fn was not caught" >&2
  exit 2
fi
assert_isolated "$out" '^DANGLING_TEST_FN\s.*FixtureAlpha' "dangling test fn" \
  $(others_except '^DANGLING_TEST_FN')

# --- scenario 6: an entry whose test_file lives under a DIFFERENT crate's
# tests/ than its own `crate` field claims must be caught, and ONLY as that
# (the file and fn both still exist, so neither DANGLING check fires) ------
reset_fixture
python3 - "$fixture/negative-registry.toml" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
text = text.replace('crate = "x"', 'crate = "y"')
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
rc=0; out="$(run_check "$fixture" "MAPPING.md" "negative-registry.toml" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-negative-registry: FIXTURE FAILED -- planted crate/path mismatch was not caught" >&2
  exit 2
fi
assert_isolated "$out" '^CRATE_PATH_MISMATCH\s.*FixtureAlpha' "crate path mismatch" \
  $(others_except '^CRATE_PATH_MISMATCH')

rm -rf "$fixture"

# --- the real scan cannot be trusted to see nothing -------------------------
if [ ! -f "$MAPPING_FILE" ]; then
  echo "check-negative-registry: $MAPPING_FILE does not exist -- refusing to pass silently" >&2
  exit 1
fi
if [ ! -f "$REGISTRY_FILE" ]; then
  echo "check-negative-registry: $REGISTRY_FILE does not exist -- refusing to pass silently" >&2
  exit 1
fi
if [ ! -d "$CRATES_DIR" ]; then
  echo "check-negative-registry: $CRATES_DIR/ does not exist -- refusing to pass silently" >&2
  exit 1
fi

rc=0
real_out="$(run_check "$ROOT_DIR" "$MAPPING_FILE" "$REGISTRY_FILE" "$CRATES_DIR")" || rc=$?

if [ "$rc" -ne 0 ]; then
  echo "check-negative-registry: MAPPING.md / negative-registry.toml sync violation(s):" >&2
  printf '%s\n' "$real_out" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "  $line" >&2
  done
  echo "check-negative-registry: see docs/assurance/negative-registry.toml and FALSIFY-01/02/03" >&2
  exit 1
fi

echo "check-negative-registry: ${real_out}"
exit 0
