#!/usr/bin/env bash
#
# Perch wire field-set parity gate.
#
# WHY THIS EXISTS
#   The Perch wire contract lives in three places and there is no codegen step
#   to keep them together:
#     1. docs/plans/ambush-ui/build/schemas/*.schema.json      (NORMATIVE)
#     2. crates/swarm-perch-wire/src/**/*.rs                   (the producer)
#     3. workspace/desktop/src/features/perch/wire/zod.ts      (the consumer)
#   Golden vectors, read by both language suites, already catch a field whose
#   TYPE or SHAPE differs between the two. What they cannot catch is a field
#   ADDED to one side and to no vector: every existing vector still parses, both
#   suites stay green, and the consumer silently ignores a fact the producer is
#   now publishing. That is the shape of defect this gate exists for, and it is
#   the same shape as every entry in .planning/STATE.md's catalogue -- a check
#   reporting success over a region it never inspected.
#
# WHAT IT COMPARES, AND WHAT IT DELIBERATELY DOES NOT
#   COMPARES: the set of property NAMES per object, per schema, against the
#   identifiers present in the Rust struct and in the zod schema.
#   DOES NOT COMPARE: types, optionality, nesting, or ordering. A shell script
#   that tries to type-check across three languages is a script that gets
#   switched off in a week -- the review lesson from 06 section 7.2's guard
#   scope. Types are the golden vectors' job and they already do it.
#
# WIRING, WHICH IS NOT OPTIONAL
#   tools/check-gates-wired.sh enumerates every tools/check-*.sh, TRACKED OR
#   UNTRACKED, and fails on any not named by a real `run:` command in some
#   .github/workflows/*.yml. This script therefore lands with its workflow edit
#   in the SAME COMMIT (.github/workflows/ci.yml, the gates job), or CI fails in
#   a way that looks like the gate is broken.
#
# WHY A FIXTURE
#   Same reason check-workspace-layering.sh:14-19 carries one: a gate that has
#   never been observed to fail is indistinguishable from a gate that cannot.
#   `--self-test` builds a two-field schema, a matching Rust struct and a
#   matching zod schema, proves they pass, then removes one field from each side
#   in turn and proves each removal is caught.
#
# EXIT CODES
#   0 parity holds   1 a field is missing on some side   2 vacuous (nothing found)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── --self-test ──────────────────────────────────────────────────────────────
#
# Same reason check-workspace-layering.sh:14-19 carries a fixture: a gate that
# has never been observed to FAIL is indistinguishable from a gate that cannot.
# The header promised this mode before it existed -- fixed here, and the third
# case below is the near-miss that promise was hiding: a field name inside a
# `.refine()` error string used to satisfy the gate, so renaming the real key left
# it green.
if [[ "${1:-}" == "--self-test" ]]; then
  fixture="$(mktemp -d)"
  trap 'rm -rf "$fixture"' EXIT
  mkdir -p "$fixture/schemas" "$fixture/src"
  cat >"$fixture/schemas/t.schema.json" <<'JSON'
{ "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": { "alpha": { "type": "string" }, "beta": { "type": "integer" } } }
JSON
  cat >"$fixture/src/t.rs" <<'RS'
pub struct T { pub alpha: String, pub beta: i64 }
RS
  cat >"$fixture/zod.ts" <<'TS'
export const t = z.strictObject({ alpha: z.string(), beta: z.number() });
TS
  run() { PERCH_WIRE_SCHEMAS="$fixture/schemas" PERCH_WIRE_RUST="$fixture/src" \
          PERCH_WIRE_TS="$fixture/zod.ts" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; }
  fails=0
  check() {  # check EXPECTED_EXIT LABEL
    local want="$1" label="$2" got=0
    run || got=$?
    if [[ "$got" == "$want" ]]; then printf '  ok   %s\n' "$label"
    else printf '  FAIL %s (exit %s, wanted %s)\n' "$label" "$got" "$want"; fails=1; fi
  }
  check 0 "a matching triple passes"
  cp "$fixture/src/t.rs" "$fixture/src/t.rs.bak"
  printf 'pub struct T { pub alpha: String }\n' >"$fixture/src/t.rs"
  check 1 "a field missing from Rust is caught"
  mv "$fixture/src/t.rs.bak" "$fixture/src/t.rs"
  cp "$fixture/zod.ts" "$fixture/zod.ts.bak"
  printf 'export const t = z.strictObject({ alpha: z.string() });\n' >"$fixture/zod.ts"
  check 1 "a field missing from zod is caught"
  # THE NEAR-MISS: the field is gone from the shape but still named in a message.
  printf 'export const t = z.strictObject({ alpha: z.string() })\n  .refine(v => v, { message: "beta: required" });\n' >"$fixture/zod.ts"
  check 1 "a field named only inside a string does NOT satisfy the gate"
  mv "$fixture/zod.ts.bak" "$fixture/zod.ts"
  rm -f "$fixture/schemas/t.schema.json"
  check 2 "an empty schema directory is VACUOUS, not green"
  [[ "$fails" == 0 ]] && printf 'parity gate self-test: all cases behave\n'
  exit "$fails"
fi

# ── LAYOUT RESOLUTION ────────────────────────────────────────────────────────
#
# The in-repo layout is the only candidate: the schemas under
# docs/plans/ambush-ui/build/schemas/, the Rust crate under crates/, and the
# desktop's zod module under workspace/ (one repository, two Cargo workspaces --
# 00-DECISIONS.md D2). The resolved paths are PRINTED before anything is
# reported: a gate should say what it looked at. Explicit overrides still win;
# they are how --self-test aims the same engine at a fixture.
resolve() {                       # resolve VAR_VALUE candidate...
  local override="$1"; shift
  if [[ -n "$override" ]]; then printf '%s\n' "$override"; return; fi
  local candidate
  for candidate in "$@"; do
    if [[ -e "$candidate" ]]; then printf '%s\n' "$candidate"; return; fi
  done
  printf '%s\n' "$1"            # report the FIRST candidate in the failure
}

ROOT="$(cd "$HERE/.." && pwd)"
SCHEMA_DIR="$(resolve "${PERCH_WIRE_SCHEMAS:-}" \
  "$ROOT/docs/plans/ambush-ui/build/schemas")"
RUST_DIR="$(resolve "${PERCH_WIRE_RUST:-}" \
  "$ROOT/crates/swarm-perch-wire/src")"
# When the desktop module is absent the gate reports which side it could not
# inspect and exits 2 -- VACUOUS, never 0. Reporting success over a region it
# never looked at is the exact failure mode this file's header names.
TS_FILE="$(resolve "${PERCH_WIRE_TS:-}" \
  "$ROOT/workspace/desktop/src/features/perch/wire/zod.ts")"

printf 'perch wire parity: schemas=%s\n                   rust=%s\n                   ts=%s\n' \
  "$SCHEMA_DIR" "$RUST_DIR" "$TS_FILE" >&2

python3 - "$SCHEMA_DIR" "$RUST_DIR" "$TS_FILE" <<'PY'
import json, pathlib, re, sys

schema_dir, rust_dir, ts_file = (pathlib.Path(a) for a in sys.argv[1:4])

if not schema_dir.is_dir():
    print(f"VACUOUS: no schema directory at {schema_dir}", file=sys.stderr)
    sys.exit(2)
if not rust_dir.is_dir():
    print(f"VACUOUS: no Rust source at {rust_dir}", file=sys.stderr)
    sys.exit(2)
if not ts_file.is_file():
    print(
        f"VACUOUS: no TypeScript wire module at {ts_file}.\n"
        "Exiting 2 rather than 0: a parity gate that inspected one side of two "
        "is not a parity gate.",
        file=sys.stderr,
    )
    sys.exit(2)

# ── every property name the schemas declare, with where it came from ─────────
#
# `x-carried-whole` marks an object (or a whole file) whose fields belong to a
# DOMAIN TYPE the Rust crate names rather than redeclares -- `SwarmFindingEnvelope`,
# `ActionRequest`, `AuditTrail`, `ContainmentLease`, `RollbackReceipt`, and the
# whole of `common.schema.json`. Carrying by type is the correct design: a field
# added upstream reaches the wire with no edit here, and a field removed upstream
# is a compile error rather than a silently absent key. So those subtrees are
# skipped on the RUST side and still checked on the TypeScript side, which has
# no such types and must mirror them by hand.
#
# Without this the gate reported 53 Rust "failures" on its first run over a
# correct tree. A gate that cries wolf on a correct tree is a gate somebody
# switches off, which is the failure mode 06 section 7.2 records for the copy
# guard and the reason that one's scope is written down.
declared: dict[str, dict[str, set[str]]] = {}


def walk(node, origin, carried):
    if isinstance(node, dict):
        carried = carried or "x-carried-whole" in node
        props = node.get("properties")
        if isinstance(props, dict):
            bucket = declared.setdefault(origin, {"both": set(), "ts_only": set()})
            bucket["ts_only" if carried else "both"].update(props.keys())
        for key, value in node.items():
            if key.startswith("x-"):
                continue
            walk(value, origin, carried)
    elif isinstance(node, list):
        for item in node:
            walk(item, origin, carried)


schemas = sorted(p for p in schema_dir.glob("*.schema.json"))
if not schemas:
    print(f"VACUOUS: no *.schema.json under {schema_dir}", file=sys.stderr)
    sys.exit(2)
for path in schemas:
    doc = json.loads(path.read_text())
    if doc.get("x-not-a-body"):
        # A NIP-01 event schema (`kind`, `content`, `tags`), not a body struct.
        # Its keys belong to nostr, not to either binding.
        continue
    walk(doc, path.name, "x-carried-whole" in doc)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


# `rglob`, not `glob`: cards.rs is 992 gate-lines and the obvious next move is
# a `cards/{mod,evidence,hold,verdict}.rs` split. With a flat glob that split
# would drop every field in it from the Rust side of the comparison and the
# gate would go green over a region it stopped inspecting -- the same failure
# shape the header names.
rust_files = sorted(rust_dir.rglob("*.rs"))
if not rust_files:
    print(f"VACUOUS: no *.rs under {rust_dir}", file=sys.stderr)
    sys.exit(2)
rust_text = strip_comments("\n".join(p.read_text() for p in rust_files))
ts_text = strip_comments(ts_file.read_text())

# A field counts as PRESENT in Rust if it appears as a struct field name or as a
# serde rename; in TypeScript if it appears as an object-literal key, INCLUDING
# ES shorthand (`severity,`), which zod object shapes use heavily. Both are
# name-level checks by design -- see the header on what this gate does not do.
rust_names = set(re.findall(r"\bpub ([a-z_][a-z0-9_]*)\s*:", rust_text))
rust_names |= set(re.findall(r'rename\s*=\s*"([^"]+)"', rust_text))
# A serde container attribute DECLARES a field too: `#[serde(tag = "cause")]`
# puts `cause` on the wire with no struct member anywhere.
rust_names |= set(re.findall(r'\b(?:tag|content)\s*=\s*"([^"]+)"', rust_text))

# STRING LITERALS ARE NOT DECLARATIONS, and this is the gate's own near-miss.
#
# The first revision ran the object-key regex over the raw text. Its lookahead is
# `[:,}]`, so a field name mentioned INSIDE A STRING -- e.g. a `.refine()` message
# reading "escalation.source_ids_absent_reason: exactly one must be null" --
# registered as a declaration. The self-test proved it: renaming the real
# `source_ids_absent_reason:` key in zod.ts left the gate GREEN, because the error
# message still contained the name. A parity gate that a doc comment can satisfy
# is not a parity gate.
#
# `z.literal("...")` values ARE declarations (a serde-tagged discriminator has no
# object key), so they are harvested BEFORE the strings are removed.
ts_literals = set(re.findall(r'z\.literal\("([^"]+)"\)', ts_text))
ts_code = re.sub(r'"(?:[^"\\\n]|\\.)*"', ' ', ts_text)
ts_code = re.sub(r"'(?:[^'\\\n]|\\.)*'", " ", ts_code)
ts_names = set(re.findall(r"\b([a-z_][a-zA-Z0-9_]*)\s*(?=[:,}])", ts_code))
ts_names |= ts_literals

missing_rust: list[str] = []
missing_ts: list[str] = []
total = 0
for origin, buckets in sorted(declared.items()):
    for scope, names in sorted(buckets.items()):
        for name in sorted(names):
            if not name or name.startswith("x-"):
                continue
            total += 1
            if scope == "both" and name not in rust_names:
                missing_rust.append(f"{origin}: {name}")
            if name not in ts_names:
                missing_ts.append(f"{origin}: {name}")

if total == 0:
    print("VACUOUS: the schemas declare no properties", file=sys.stderr)
    sys.exit(2)

status = 0
if missing_rust:
    status = 1
    print(f"{len(missing_rust)} schema field(s) absent from the Rust wire crate:")
    for row in missing_rust:
        print(f"  {row}")
if missing_ts:
    status = 1
    print(f"{len(missing_ts)} schema field(s) absent from the zod module:")
    for row in missing_ts:
        print(f"  {row}")

if status == 0:
    print(
        f"perch wire parity: {total} declared field(s) across {len(schemas)} schema(s), "
        f"all present on both sides "
        f"({len(rust_files)} Rust file(s), {ts_file.name})"
    )
sys.exit(status)
PY
