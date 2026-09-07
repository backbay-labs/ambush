#!/usr/bin/env bash
#
# MAPPING-04. The three-way sync gate for Phase 285's invariant map.
#
# Phase 285 Task 2 put a `// INVARIANT: <Name>` comment at each Rust call site
# `docs/assurance/MAPPING.md` names for one of the engine's fail-closed
# invariants. A comment is not a boundary -- nothing stops the table, the
# markers, and the real code from drifting apart the moment any one of the
# three changes without the other two. This script makes that drift
# mechanical to catch, the same way `tools/check-gates-wired.sh` did for
# "does this gate script actually run anywhere":
#
#   CHECK A -- UNMAPPED_MARKER: every `// INVARIANT: <Name>` marker under
#     `crates/` names a `Name` that appears in some `MAPPING.md` row. A marker
#     for a row that was renamed or deleted is a comment lying about an
#     invariant the table no longer claims to track.
#   CHECK B -- STALE_PATH: every `MAPPING.md` row's `Path` column (a
#     `crate::module::[Type::]function` string) still resolves to a real item
#     in the tree -- the file the path implies exists, the function is defined
#     in it, and, if the path names a type, the function is defined inside an
#     `impl ... <Type>` block in that same file. A path that used to resolve
#     and now doesn't means the enforcing code moved or was deleted out from
#     under the table's claim about it.
#   CHECK C -- UNMARKED_ROW (the "strongly preferred" third leg): every
#     `MAPPING.md` row's `Name` has at least one marker somewhere under
#     `crates/`. A row with no marker is a claim in the table that was never
#     actually annotated at its enforcement site, which is exactly the kind of
#     undetectable gap MAPPING-03 exists to close.
#
# WHY NOT A SINGLE REGEX OVER THE WHOLE `Path` STRING
#   `crate::module::Type::function` and the table's `Source` column
#   (`crates/x/src/y.rs:12,34-40`) both use `::` and `:` as meaningful
#   separators inside a value that itself sits between `|` column separators.
#   A regex written to pull "the path column" out of a raw table line by
#   counting colons breaks the instant a path gains or loses a module segment.
#   This script instead (a) splits each table row on GFM's actual column
#   separator (`|`), the same way a markdown renderer would, via a small
#   `python3` table reader -- not PyYAML, not a markdown library, just
#   `str.split("|")` plus backtick-stripping, because the table here is the
#   plain pipe-delimited GFM subset the repo's own tooling already assumes
#   (see check-gates-wired.sh's header) -- and then (b) resolves the `Path`
#   column structurally: split on `::`, map the crate segment to
#   `crates/<dashed-name>/src/`, map lowercase segments to a nested module
#   file, and require an uppercase trailing segment to name a real `impl`
#   block a brace-counter can find the requested `fn` inside of. That is a
#   real (if intentionally small) resolver, not a pattern match on the path
#   text.
#
# NOT VACUOUS -- THE FIXTURE IS THE POINT
#   Every invocation first runs the identical resolver (`$PY_HELPER`, invoked
#   the same way both times) against five planted miniature trees before it is
#   ever trusted against the real one:
#     1. a clean baseline (a plain function, one matching row+marker) must
#        pass with zero findings;
#     2. an UNMAPPED marker with no row must be caught, and caught ONLY as
#        that;
#     3. a STALE path (a table row renamed away from the function it once
#        named) must be caught, and caught ONLY as that;
#     4. an UNMARKED row (a resolvable path with no marker anywhere) must be
#        caught, and caught ONLY as that;
#     5. a type-scoping trap -- a `Path` naming `Thing::shared_name` where
#        `shared_name` is real but defined on a DIFFERENT type (`Other`) in
#        the same file -- must be caught as STALE, proving the resolver
#        actually checks impl-block membership rather than "does `fn
#        shared_name` appear anywhere in this file", which would silently
#        accept the wrong type forever.
#   If any planted scenario is not caught exactly as specified, this script
#   exits 2 WITHOUT scanning `docs/assurance/MAPPING.md` or `crates/` at all --
#   a gate that cannot see its own planted subject is not a passing gate.
#
# MARKER NAMES ARE REQUIRED TO LOOK LIKE THE TABLE'S NAMES
#   The marker regex requires the captured name to start with an uppercase
#   letter (`PolicyMalformedRequestRejected`-style), matching every real Name
#   in MAPPING.md today. This is not cosmetic: `workspace/` (a separate Cargo
#   workspace entirely -- see `workspace/CLAUDE.md`) already contains a real,
#   unrelated line, `// INVARIANT: apart from observer frames (parked above),
#   the WS publish ...`, a prose comment that happens to start with the same
#   six characters. A lowercase-tolerant capture would read that as a marker
#   named `apart` and fail this gate on a false positive. Scoping the scan to
#   `crates/` (below) already excludes that file; the uppercase requirement is
#   the second, independent reason it can never match.
#
# BASH 3.2
#   No `mapfile`, no associative arrays: macOS ships bash 3.2 and a gate a
#   developer cannot run locally is a gate that is only ever seen red in CI.
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MAPPING_FILE="docs/assurance/MAPPING.md"
CRATES_DIR="crates"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

py_helper="$workdir/mapping_check.py"

# --- the resolver, written once, invoked identically on every fixture and on
# the real tree (see check-red-swarm-no-execution-authority.sh's header for
# why "one function" matters: it is the only way a self-test and the real
# scan cannot silently diverge). -----------------------------------------
cat > "$py_helper" <<'PY'
import os
import re
import sys


def split_row(line):
    """Split one GFM table line into stripped, backtick-unwrapped cells.

    Not a regex over the whole line: a real (if minimal) delimited-row
    reader, so a cell containing '::' or ':' (a Path or Source value) never
    confuses the column boundaries, which are '|' and only '|'.
    """
    s = line.strip()
    if not s.startswith("|"):
        return []
    if s.startswith("|"):
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


def parse_table(path):
    """Return (header, rows) or (None, error) for the first GFM table in path
    whose header row has a column literally named 'Name'."""
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

    rows = []
    i = sep_idx + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip().startswith("|"):
            break
        cells = split_row(line)
        if len(cells) >= len(header):
            row = {header[j]: cells[j] for j in range(len(header))}
            row["_line"] = i + 1
            rows.append(row)
        i += 1
    return (header, rows), None


def find_impl_spans(text, type_name):
    """Byte-offset (start, end) spans of every `impl ... <type_name> ... { }`
    block in text, found by brace-counting from the impl header's opening
    brace -- not a line-based heuristic, so a multi-line `impl<P, E> Foo<P,
    E>\\nwhere\\n    ...\\n{` header is still recognized."""
    spans = []
    type_re = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(type_name) + r"(?![A-Za-z0-9_])")
    for m in re.finditer(r"\bimpl\b[^{]*\{", text):
        if not type_re.search(m.group(0)):
            continue
        depth = 1
        i = m.end()
        n = len(text)
        while i < n and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        spans.append((m.start(), i))
    return spans


def resolve_path(root, crates_dir, path_str):
    """Resolve a MAPPING.md `Path` cell (`crate::module::[Type::]function`)
    against real source under `root/crates_dir`. Returns (ok, detail)."""
    segs = [s for s in path_str.split("::") if s != ""]
    if len(segs) < 2:
        return False, f"'{path_str}' has fewer than 2 '::'-separated segments"

    crate_name = segs[0]
    func = segs[-1]
    rest = segs[1:-1]

    type_name = None
    module_segs = rest
    if rest and rest[-1][:1].isupper():
        type_name = rest[-1]
        module_segs = rest[:-1]

    crate_dir = crate_name.replace("_", "-")
    src_dir = os.path.join(root, crates_dir, crate_dir, "src")
    if not os.path.isdir(src_dir):
        return False, f"no such crate source dir: {os.path.relpath(src_dir, root)}"

    if module_segs:
        file_path = os.path.join(src_dir, *module_segs) + ".rs"
        if not os.path.isfile(file_path):
            alt = os.path.join(src_dir, *module_segs, "mod.rs")
            if os.path.isfile(alt):
                file_path = alt
    else:
        file_path = os.path.join(src_dir, "lib.rs")

    if not os.path.isfile(file_path):
        return False, f"no such source file: {os.path.relpath(file_path, root)}"

    with open(file_path, "r", encoding="utf-8") as f:
        text = f.read()

    fn_pattern = re.compile(r"(?<![A-Za-z0-9_])fn\s+" + re.escape(func) + r"\s*[(<]")
    fn_positions = [m.start() for m in fn_pattern.finditer(text)]
    if not fn_positions:
        return False, f"no `fn {func}` found in {os.path.relpath(file_path, root)}"

    if type_name is None:
        return True, f"fn {func} found in {os.path.relpath(file_path, root)}"

    impl_spans = find_impl_spans(text, type_name)
    if not impl_spans:
        return False, (
            f"no `impl ... {type_name}` block found in "
            f"{os.path.relpath(file_path, root)}"
        )
    for start, end in impl_spans:
        if any(start <= pos < end for pos in fn_positions):
            return True, (
                f"fn {func} found inside impl ... {type_name} in "
                f"{os.path.relpath(file_path, root)}"
            )
    return False, (
        f"fn {func} exists in {os.path.relpath(file_path, root)} but not inside "
        f"an impl block for {type_name}"
    )


MARKER_RE = re.compile(r"//\s*INVARIANT:\s*([A-Z][A-Za-z0-9_]*)")


def find_markers(scan_root):
    markers = []
    for dirpath, dirnames, filenames in os.walk(scan_root):
        dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, start=1):
                        m = MARKER_RE.search(line)
                        if m:
                            markers.append((path, lineno, m.group(1)))
            except OSError:
                continue
    return markers


def main():
    root, mapping_relpath, crates_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    mapping_path = os.path.join(root, mapping_relpath)

    parsed, err = parse_table(mapping_path)
    if err:
        print(f"MAPPING_PARSE_ERROR\t{err}")
        return 1
    header, rows = parsed
    if "Name" not in header or "Path" not in header:
        print("MAPPING_PARSE_ERROR\ttable has no Name/Path column")
        return 1
    if not rows:
        print("MAPPING_PARSE_ERROR\tzero data rows parsed; refusing to pass silently")
        return 1

    findings = []
    names_seen = set()
    marked = {}
    for row in rows:
        name = row.get("Name", "")
        path = row.get("Path", "")
        if not name or not path:
            findings.append(f"MAPPING_ROW_MALFORMED\tline {row['_line']}\tmissing Name or Path")
            continue
        if name in names_seen:
            findings.append(f"DUPLICATE_NAME\t{name}\tline {row['_line']}")
        names_seen.add(name)
        marked[name] = False
        ok, detail = resolve_path(root, crates_dir, path)
        if not ok:
            findings.append(f"STALE_PATH\t{name}\t{path}\t{detail}")

    scan_root = os.path.join(root, crates_dir)
    markers = find_markers(scan_root)
    if not markers:
        print(f"NO_MARKERS_FOUND\tzero '// INVARIANT: <Name>' markers under {crates_dir}/; refusing to pass silently")
        return 1

    for path, lineno, name in markers:
        relpath = os.path.relpath(path, root)
        if name not in names_seen:
            findings.append(f"UNMAPPED_MARKER\t{relpath}:{lineno}\t{name}")
        else:
            marked[name] = True

    for name, found in marked.items():
        if not found:
            findings.append(f"UNMARKED_ROW\t{name}")

    if findings:
        for line in findings:
            print(line)
        return 1

    print(f"OK\t{len(rows)} row(s)\t{len(markers)} marker(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY

run_check() {
  # $1=root $2=mapping-relpath $3=crates-relpath
  python3 "$py_helper" "$1" "$2" "$3"
}

fixture="$workdir/fixture"

reset_fixture() {
  rm -rf "$fixture"
  mkdir -p "$fixture/crates/x/src"
  cat > "$fixture/crates/x/src/lib.rs" <<'RS'
// INVARIANT: FixtureRealInvariant
pub fn real_check(x: i32) -> Result<(), String> {
    if x < 0 {
        return Err("negative".to_string());
    }
    Ok(())
}
RS
  cat > "$fixture/MAPPING.md" <<'MD'
# Fixture mapping (self-test scaffolding only -- not the real docs/assurance/MAPPING.md)

| Name | Crate | Path | Source | Assumption | Denies |
|---|---|---|---|---|---|
| `FixtureRealInvariant` | x | `x::real_check` | `crates/x/src/lib.rs:2` | `ASSUME-FIXTURE` | A negative `x`. |
MD
}

assert_contains() {
  # $1=output $2=needle-regex $3=scenario-label
  if ! printf '%s\n' "$1" | grep -qE "$2"; then
    echo "check-mapping: FIXTURE FAILED -- scenario '$3' did not produce '$2'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$1" >&2
    exit 2
  fi
}

assert_absent() {
  # $1=output $2=needle-regex $3=scenario-label
  if printf '%s\n' "$1" | grep -qE "$2"; then
    echo "check-mapping: FIXTURE FAILED -- scenario '$3' wrongly produced '$2'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$1" >&2
    exit 2
  fi
}

# --- scenario 1: clean baseline must pass with zero findings ---------------
reset_fixture
rc=0; out="$(run_check "$fixture" "MAPPING.md" "crates")" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "check-mapping: FIXTURE FAILED -- clean baseline scenario did not exit 0" >&2
  printf '%s\n' "$out" >&2
  exit 2
fi
assert_contains "$out" '^OK\b' "clean baseline"

# --- scenario 2: an unmapped marker must be caught, and ONLY as that -------
reset_fixture
cat >> "$fixture/crates/x/src/lib.rs" <<'RS'

// INVARIANT: FixtureGhostInvariant
fn ghost() {}
RS
rc=0; out="$(run_check "$fixture" "MAPPING.md" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-mapping: FIXTURE FAILED -- planted unmapped marker was not caught" >&2
  exit 2
fi
assert_contains "$out" '^UNMAPPED_MARKER\s.*FixtureGhostInvariant' "unmapped marker"
assert_absent   "$out" '^STALE_PATH'   "unmapped marker"
assert_absent   "$out" '^UNMARKED_ROW' "unmapped marker"

# --- scenario 3: a MAPPING row whose path was renamed away must be caught,
# and ONLY as that (source untouched -- only the table's Path cell moves) ---
reset_fixture
python3 - "$fixture/MAPPING.md" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
text = text.replace("x::real_check", "x::real_check_renamed_away")
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
rc=0; out="$(run_check "$fixture" "MAPPING.md" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-mapping: FIXTURE FAILED -- planted stale path was not caught" >&2
  exit 2
fi
assert_contains "$out" '^STALE_PATH\s.*FixtureRealInvariant' "stale path"
assert_absent   "$out" '^UNMAPPED_MARKER' "stale path"
assert_absent   "$out" '^UNMARKED_ROW'    "stale path"

# --- scenario 4: a resolvable row with no marker anywhere must be caught,
# and ONLY as that ------------------------------------------------------
reset_fixture
cat >> "$fixture/crates/x/src/lib.rs" <<'RS'

pub fn unmarked_check(x: i32) -> Result<(), String> {
    if x > 100 {
        return Err("too big".to_string());
    }
    Ok(())
}
RS
cat >> "$fixture/MAPPING.md" <<'MD'
| `FixtureOrphanRow` | x | `x::unmarked_check` | `crates/x/src/lib.rs:8` | `ASSUME-FIXTURE` | A too-large `x`. |
MD
rc=0; out="$(run_check "$fixture" "MAPPING.md" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-mapping: FIXTURE FAILED -- planted unmarked row was not caught" >&2
  exit 2
fi
assert_contains "$out" '^UNMARKED_ROW\s.*FixtureOrphanRow' "unmarked row"
assert_absent   "$out" '^STALE_PATH'      "unmarked row"
assert_absent   "$out" '^UNMAPPED_MARKER' "unmarked row"

# --- scenario 5: type-scoping trap -- `fn shared_name` is real but lives on
# the WRONG type; a resolver that ignores impl-block membership would wrongly
# accept this. Also carries one clean Type::method row+marker (FixtureTypeOk)
# so this scenario proves the positive Type::method case too, and so the
# "zero markers found" guard cannot short-circuit the scenario. ------------
reset_fixture
mkdir -p "$fixture/crates/y/src"
cat > "$fixture/crates/y/src/thing.rs" <<'RS'
pub struct Thing;
pub struct Other;

impl Thing {
    // INVARIANT: FixtureTypeOk
    pub fn check(x: i32) -> Result<(), String> {
        if x < 0 {
            return Err("negative".to_string());
        }
        Ok(())
    }
}

impl Other {
    pub fn shared_name(x: i32) -> Result<(), String> {
        let _ = x;
        Ok(())
    }
}
RS
cat >> "$fixture/MAPPING.md" <<'MD'
| `FixtureTypeOk` | y | `y::thing::Thing::check` | `crates/y/src/thing.rs:6` | `ASSUME-FIXTURE` | A negative `x`. |
| `FixtureTypeMismatch` | y | `y::thing::Thing::shared_name` | `crates/y/src/thing.rs:14` | `ASSUME-FIXTURE` | Wrong type entirely. |
MD
rc=0; out="$(run_check "$fixture" "MAPPING.md" "crates")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-mapping: FIXTURE FAILED -- type-scoping trap was not caught" >&2
  exit 2
fi
assert_contains "$out" '^STALE_PATH\s.*FixtureTypeMismatch' "type-scoping trap"
assert_absent   "$out" 'FixtureTypeOk' "type-scoping trap"

rm -rf "$fixture"

# --- the real scan cannot be trusted to see nothing -------------------------
if [ ! -f "$MAPPING_FILE" ]; then
  echo "check-mapping: $MAPPING_FILE does not exist -- refusing to pass silently" >&2
  exit 1
fi
if [ ! -d "$CRATES_DIR" ]; then
  echo "check-mapping: $CRATES_DIR/ does not exist -- refusing to pass silently" >&2
  exit 1
fi

rc=0
real_out="$(run_check "$ROOT_DIR" "$MAPPING_FILE" "$CRATES_DIR")" || rc=$?

if [ "$rc" -ne 0 ]; then
  echo "check-mapping: MAPPING.md / marker / source-tree sync violation(s):" >&2
  printf '%s\n' "$real_out" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "  $line" >&2
  done
  echo "check-mapping: see docs/assurance/MAPPING.md and MAPPING-03/04/05" >&2
  exit 1
fi

echo "check-mapping: ${real_out}"
exit 0
