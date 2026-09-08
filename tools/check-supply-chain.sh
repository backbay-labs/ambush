#!/usr/bin/env bash
#
# SUPPLY-01 / SUPPLY-02. The dated, drift-proof supply-chain policy gate.
#
# WHY THIS EXISTS
#   `deny.toml` accepts two RUSTSEC advisories via `[advisories].ignore` and
#   pins twenty duplicate-dependency versions via `[[bans.skip]]`. An ignore
#   or a skip with no review date and no stated blast radius is a permanent,
#   silent exception -- nobody is ever prompted to re-look at it, and nothing
#   distinguishes "reviewed last week" from "reviewed three years ago and
#   forgotten". Separately, this script used to hand-maintain its own
#   `cargo audit --ignore RUSTSEC-...` argv as a second, manually-copied list
#   -- exactly the shape of drift this repository's `tools/check-*.sh` gates
#   exist to make mechanical (see `check-gates-wired.sh`'s and
#   `check-negative-registry.sh`'s headers for the same pattern applied
#   elsewhere).
#
# WHAT THIS SCRIPT ENFORCES, IN ORDER
#   1. `deny.toml`'s `[advisories].ignore` array and `[[bans.skip]]` array
#      each parse as valid TOML and contain no duplicate `id` / `crate` key.
#   2. Every ignore id and every skip crate@version has EXACTLY one matching
#      table in the companion ledger `tools/supply-chain-review.toml`
#      (`[advisories_ignore.<id>]` / `[bans_skip."<crate>@<version>"]`), and
#      no ledger table names an id/crate deny.toml does not have (an
#      ORPHAN_LEDGER_ENTRY -- ledger and deny.toml have drifted apart).
#   3. Every matched ledger table carries a `last_checked` NATIVE TOML DATE
#      (an unquoted `YYYY-MM-DD` literal -- a string given by mistake, or an
#      invalid calendar date, is a hard failure, not silently accepted), a
#      non-empty `blast_radius`, and a non-empty `clearing_condition`.
#   4. The `cargo audit --ignore` argv passed to `cargo audit` below is
#      DERIVED from step 1's validated ignore-id list every run -- there is
#      no second, hand-maintained copy of that list anywhere in this script,
#      so it cannot drift from `deny.toml` the way the old version could. An
#      id that is orphaned in the ledger (step 2) is excluded from the
#      derived argv even if some other bug tried to smuggle it in from the
#      ledger side, because the argv is built from deny.toml's ignore array,
#      never from the ledger.
#   5. Only once 1-4 pass: `cargo deny check advisories licenses bans sources`
#      and `cargo audit --deny warnings <the derived --ignore argv>`.
#
# WHY `tomllib`, NOT A LINE REGEX (precedent: check-negative-registry.sh)
#   `deny.toml` and the ledger are both real TOML; extracting `id = "..."` /
#   `crate = "..."` pairs with a regex over raw text is exactly the kind of
#   "looks structural, isn't" scan this repository's gates avoid (see
#   `check-gates-wired.sh`'s header on grep-as-behaviour-match). `tomllib` is
#   Python's standard library since 3.11 -- not the external PyYAML this
#   repo's gates avoid -- and `ubuntu-latest` ships python3.12+.
#
# WHY A COMPANION LEDGER AND NOT EXTRA KEYS INSIDE `deny.toml`
#   Measured at HEAD: cargo-deny 0.19.4 rejects any key beyond `{ id, reason
#   }` in an `[advisories].ignore` entry --
#     error[unexpected-keys]: found 1 unexpected keys, expected: ["id", "reason"]
#   -- and rejects any unrecognised TOP-LEVEL table too (confirmed the same
#   way with a throwaway `[metadata.x]` table). Adding `last_checked` /
#   `blast_radius` / `clearing_condition` directly to an ignore entry, or to
#   a new top-level table, breaks `cargo deny check` outright. The companion
#   ledger `tools/supply-chain-review.toml` is the schema-compatible answer
#   the plan calls for; see that file's own header for the exact keying
#   scheme (TOML tables, not arrays, so a duplicate ledger entry is a TOML
#   parse error before this script ever runs).
#
# NOT VACUOUS -- THREE PLANTED COUNTEREXAMPLES, ONE SHARED VALIDATOR, CHECKED
# BEFORE THE REAL TREE (precedent: check-negative-registry.sh,
# check-mapping.sh)
#   The identical python validator ($PY_HELPER, invoked the same way every
#   time) runs against a clean fixture baseline, then three DELIBERATELY
#   BROKEN fixture variants -- a ledger entry missing its `last_checked`
#   date, a duplicate advisory id inside deny.toml's `ignore` array, and an
#   orphaned ledger entry that must NOT leak into the derived audit argv --
#   before it is ever trusted against the real `deny.toml` and
#   `tools/supply-chain-review.toml`. If any planted scenario is not caught
#   exactly as specified, this script prints `FIXTURE FAILED` and exits 2
#   WITHOUT scanning the real files: a validator that cannot see its own
#   planted defect is not a passing validator.
#
# PINNED TOOL VERSIONS
#   `.github/workflows/ci.yml` installs `cargo-deny --version 0.19.4` and
#   `cargo-audit --version 0.22.0` for this gate (previously unpinned). Those
#   are the exact versions this file's cross-references to measured
#   cargo-deny behaviour (e.g. the unexpected-keys check above, and the
#   MEASURED LIMITATION comments in deny.toml) were taken against. A locally
#   installed different version still runs; only CI's pin is load-bearing.
#
# BASH 3.2
#   No `mapfile`, no associative arrays: macOS ships bash 3.2 and a gate a
#   developer cannot run locally is a gate only ever seen red in CI.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DENY_FILE="deny.toml"
LEDGER_FILE="tools/supply-chain-review.toml"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

py_helper="$workdir/validate_supply_chain.py"

# --- the validator, written once, invoked identically on every fixture and
# on the real tree. ----------------------------------------------------------
cat > "$py_helper" <<'PY'
import datetime
import re
import sys
import tomllib

RUSTSEC_ID_RE = re.compile(r"^RUSTSEC-\d{4}-\d{4,}$")


def load_toml(path, what):
    try:
        with open(path, "rb") as f:
            return tomllib.load(f), None
    except FileNotFoundError:
        return None, f"{what.upper()}_PARSE_ERROR\t{path}: no such file"
    except tomllib.TOMLDecodeError as error:
        return None, f"{what.upper()}_PARSE_ERROR\t{path}: invalid TOML: {error}"


def require_str(entry, field):
    value = entry.get(field)
    return isinstance(value, str) and value.strip() != ""


def validate_ledger_entry(kind, key, entry, findings):
    """Validate one matched ledger table; return True iff fully valid."""
    ok = True

    if "last_checked" not in entry:
        findings.append(f"MISSING_FIELD\t{kind}\t{key}\tlast_checked")
        ok = False
    elif not isinstance(entry["last_checked"], datetime.date):
        findings.append(
            f"BAD_FIELD_TYPE\t{kind}\t{key}\tlast_checked must be a native TOML "
            f"date (bare YYYY-MM-DD, not a string), got "
            f"{type(entry['last_checked']).__name__}"
        )
        ok = False

    for field in ("blast_radius", "clearing_condition"):
        if field not in entry:
            findings.append(f"MISSING_FIELD\t{kind}\t{key}\t{field}")
            ok = False
        elif not require_str(entry, field):
            findings.append(f"BAD_FIELD_TYPE\t{kind}\t{key}\t{field} must be a non-empty string")
            ok = False

    return ok


def collect_deny_keys(entries, kind, id_field, findings):
    """Return (ordered list of key values, ) after flagging malformed entries
    and duplicate keys within deny.toml's own array."""
    keys = []
    for entry in entries:
        if not isinstance(entry, dict) or id_field not in entry:
            findings.append(f"MALFORMED_DENY_ENTRY\t{kind}\t{entry!r}")
            continue
        keys.append(entry[id_field])

    seen = set()
    dups = set()
    for key in keys:
        if key in seen:
            dups.add(key)
        seen.add(key)
    for key in sorted(dups):
        tag = "DUPLICATE_ADVISORY_ID" if kind == "advisories.ignore" else "DUPLICATE_SKIP_ENTRY"
        findings.append(f"{tag}\t{key}")

    return keys


def check(deny_path, ledger_path):
    """Return (findings: list[str], derived_argv: list[str] | None)."""
    findings = []

    deny, err = load_toml(deny_path, "deny")
    if err:
        return [err], None
    ledger, err = load_toml(ledger_path, "ledger")
    if err:
        return [err], None

    ignore_entries = deny.get("advisories", {}).get("ignore", [])
    skip_entries = deny.get("bans", {}).get("skip", [])

    ignore_ids = collect_deny_keys(ignore_entries, "advisories.ignore", "id", findings)
    skip_keys = collect_deny_keys(skip_entries, "bans.skip", "crate", findings)

    for rid in ignore_ids:
        if isinstance(rid, str) and not RUSTSEC_ID_RE.match(rid):
            findings.append(f"BAD_ID_FORMAT\tadvisories.ignore\t{rid}")

    ledger_ignore = ledger.get("advisories_ignore", {})
    ledger_skip = ledger.get("bans_skip", {})
    if not isinstance(ledger_ignore, dict):
        findings.append("MALFORMED_LEDGER_TABLE\tadvisories_ignore")
        ledger_ignore = {}
    if not isinstance(ledger_skip, dict):
        findings.append("MALFORMED_LEDGER_TABLE\tbans_skip")
        ledger_skip = {}

    deny_ignore_set = set(ignore_ids)
    ledger_ignore_set = set(ledger_ignore.keys())
    deny_skip_set = set(skip_keys)
    ledger_skip_set = set(ledger_skip.keys())

    for rid in sorted(deny_ignore_set - ledger_ignore_set):
        findings.append(f"MISSING_LEDGER_ENTRY\tadvisories_ignore\t{rid}")
    for rid in sorted(ledger_ignore_set - deny_ignore_set):
        findings.append(f"ORPHAN_LEDGER_ENTRY\tadvisories_ignore\t{rid}")

    for key in sorted(deny_skip_set - ledger_skip_set):
        findings.append(f"MISSING_LEDGER_ENTRY\tbans_skip\t{key}")
    for key in sorted(ledger_skip_set - deny_skip_set):
        findings.append(f"ORPHAN_LEDGER_ENTRY\tbans_skip\t{key}")

    validated_ignore_ids = []
    for rid in sorted(deny_ignore_set & ledger_ignore_set):
        entry = ledger_ignore[rid]
        if not isinstance(entry, dict):
            findings.append(f"MALFORMED_LEDGER_ENTRY\tadvisories_ignore\t{rid}")
            continue
        if validate_ledger_entry("advisories_ignore", rid, entry, findings):
            validated_ignore_ids.append(rid)

    for key in sorted(deny_skip_set & ledger_skip_set):
        entry = ledger_skip[key]
        if not isinstance(entry, dict):
            findings.append(f"MALFORMED_LEDGER_ENTRY\tbans_skip\t{key}")
            continue
        validate_ledger_entry("bans_skip", key, entry, findings)

    # DERIVED FROM deny.toml's ignore array ONLY (never from the ledger), and
    # ONLY from ids that passed full validation -- an orphaned or malformed
    # ledger entry can never expand what `cargo audit` is told to ignore.
    derived_argv = []
    for rid in sorted(set(validated_ignore_ids)):
        derived_argv.extend(["--ignore", rid])

    return findings, derived_argv


def main():
    deny_path, ledger_path = sys.argv[1:3]
    findings, derived_argv = check(deny_path, ledger_path)
    for line in findings:
        print(line)
    if derived_argv is not None:
        print("DERIVED_ARGV\t" + "\t".join(derived_argv))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
PY

run_check() {
  # $1=deny.toml path  $2=ledger path
  python3 "$py_helper" "$1" "$2"
}

fixture="$workdir/fixture"

# A clean baseline: one advisory ignore, one bans skip, both fully annotated
# in a matching ledger.
reset_fixture() {
  rm -rf "$fixture"
  mkdir -p "$fixture"
  cat > "$fixture/deny.toml" <<'TOML'
[advisories]
ignore = [
  { id = "RUSTSEC-2024-0001", reason = "fixture" },
]

[bans]
skip = [
  { crate = "foo@1.0.0", reason = "fixture" },
]
TOML
  cat > "$fixture/ledger.toml" <<'TOML'
[advisories_ignore.RUSTSEC-2024-0001]
last_checked = 2026-09-07
blast_radius = "fixture blast radius"
clearing_condition = "fixture clearing condition"

[bans_skip."foo@1.0.0"]
last_checked = 2026-09-07
blast_radius = "fixture blast radius"
clearing_condition = "fixture clearing condition"
TOML
}

assert_contains() {
  # $1=output $2=needle-regex $3=scenario-label
  if ! printf '%s\n' "$1" | grep -qE "$2"; then
    echo "check-supply-chain: FIXTURE FAILED -- scenario '$3' did not produce '$2'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$1" >&2
    exit 2
  fi
}

assert_absent() {
  # $1=output $2=needle-regex $3=scenario-label
  if printf '%s\n' "$1" | grep -qE "$2"; then
    echo "check-supply-chain: FIXTURE FAILED -- scenario '$3' wrongly produced '$2'" >&2
    echo "--- captured output ---" >&2
    printf '%s\n' "$1" >&2
    exit 2
  fi
}

# --- scenario 1: clean baseline must pass with zero findings and derive the
# one ignore id into the argv -----------------------------------------------
reset_fixture
rc=0; out="$(run_check "$fixture/deny.toml" "$fixture/ledger.toml")" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "check-supply-chain: FIXTURE FAILED -- clean baseline scenario did not exit 0" >&2
  printf '%s\n' "$out" >&2
  exit 2
fi
assert_contains "$out" '^DERIVED_ARGV\s--ignore\sRUSTSEC-2024-0001$' "clean baseline"

# --- scenario (a): a ledger entry missing its last_checked date must be
# caught, and the argv must NOT be derived from an unvalidated entry --------
reset_fixture
python3 - "$fixture/ledger.toml" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
text = text.replace("last_checked = 2026-09-07\nblast_radius = \"fixture blast radius\"\nclearing_condition = \"fixture clearing condition\"\n\n[bans_skip", "[bans_skip", 1)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
rc=0; out="$(run_check "$fixture/deny.toml" "$fixture/ledger.toml")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-supply-chain: FIXTURE FAILED -- planted missing last_checked date was not caught" >&2
  exit 2
fi
assert_contains "$out" '^MISSING_FIELD\sadvisories_ignore\sRUSTSEC-2024-0001\slast_checked$' "missing date"
assert_absent "$out" '^DERIVED_ARGV\s--ignore\sRUSTSEC-2024-0001\b' "missing date leaking into argv"

# --- scenario (b): a duplicate advisory id inside deny.toml's own ignore
# array must be caught -------------------------------------------------------
reset_fixture
python3 - "$fixture/deny.toml" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()
text = text.replace(
    '{ id = "RUSTSEC-2024-0001", reason = "fixture" },\n',
    '{ id = "RUSTSEC-2024-0001", reason = "fixture" },\n'
    '  { id = "RUSTSEC-2024-0001", reason = "fixture duplicate" },\n',
)
with open(path, "w", encoding="utf-8") as f:
    f.write(text)
PY
rc=0; out="$(run_check "$fixture/deny.toml" "$fixture/ledger.toml")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-supply-chain: FIXTURE FAILED -- planted duplicate advisory id was not caught" >&2
  exit 2
fi
assert_contains "$out" '^DUPLICATE_ADVISORY_ID\sRUSTSEC-2024-0001$' "duplicate advisory id"

# --- scenario (c): argv/deny.toml drift -- a fully-annotated ledger entry
# for an id deny.toml does NOT ignore must be flagged as orphaned, and must
# NOT leak into the derived cargo-audit argv (which would otherwise silently
# widen what `cargo audit` ignores beyond what deny.toml actually declares) --
reset_fixture
cat >> "$fixture/ledger.toml" <<'TOML'

[advisories_ignore.RUSTSEC-2024-9999]
last_checked = 2026-09-07
blast_radius = "fixture orphan blast radius"
clearing_condition = "fixture orphan clearing condition"
TOML
rc=0; out="$(run_check "$fixture/deny.toml" "$fixture/ledger.toml")" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "check-supply-chain: FIXTURE FAILED -- planted orphan ledger entry (argv/deny.toml drift) was not caught" >&2
  exit 2
fi
assert_contains "$out" '^ORPHAN_LEDGER_ENTRY\sadvisories_ignore\sRUSTSEC-2024-9999$' "argv/deny.toml drift"
derived_only="$(printf '%s\n' "$out" | grep '^DERIVED_ARGV' || true)"
assert_absent "$derived_only" 'RUSTSEC-2024-9999' "orphan id leaking into derived argv"
assert_contains "$derived_only" '^DERIVED_ARGV\s--ignore\sRUSTSEC-2024-0001$' "argv/deny.toml drift (valid id still derived)"

rm -rf "$fixture"

echo "check-supply-chain: all three planted counterexamples caught; validator is not vacuous"

# --- the real scan cannot be trusted to see nothing -------------------------
if [ ! -f "$DENY_FILE" ]; then
  echo "check-supply-chain: $DENY_FILE does not exist -- refusing to pass silently" >&2
  exit 1
fi
if [ ! -f "$LEDGER_FILE" ]; then
  echo "check-supply-chain: $LEDGER_FILE does not exist -- refusing to pass silently" >&2
  exit 1
fi

rc=0
real_out="$(run_check "$DENY_FILE" "$LEDGER_FILE")" || rc=$?

derived_line="$(printf '%s\n' "$real_out" | grep '^DERIVED_ARGV' || true)"
findings="$(printf '%s\n' "$real_out" | grep -v '^DERIVED_ARGV' || true)"

if [ "$rc" -ne 0 ] || [ -z "$derived_line" ]; then
  echo "check-supply-chain: $DENY_FILE / $LEDGER_FILE metadata violation(s):" >&2
  printf '%s\n' "$findings" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "  $line" >&2
  done
  echo "check-supply-chain: see $LEDGER_FILE and SUPPLY-01/02" >&2
  exit 1
fi

# Rebuild the argv array from the tab-separated DERIVED_ARGV line (bash 3.2:
# no mapfile, no associative arrays -- a plain `read` loop over one field per
# line, fed by process substitution).
audit_ignore_args=()
while IFS= read -r field; do
  [ -n "$field" ] || continue
  [ "$field" = "DERIVED_ARGV" ] && continue
  audit_ignore_args+=("$field")
done < <(printf '%s\n' "$derived_line" | tr '\t' '\n')

echo "check-supply-chain: metadata validated -- $(( ${#audit_ignore_args[@]} / 2 )) ignore(s) in deny.toml, all dated + justified in $LEDGER_FILE"
echo "check-supply-chain: derived cargo-audit argv: ${audit_ignore_args[*]:-<none>}"

# `bans` runs with duplicates ENFORCED. Accepted duplicates are enumerated,
# dated and justified as version-pinned `[[bans.skip]]` entries in deny.toml
# (cross-validated against $LEDGER_FILE above), so a new duplicate -- or a
# skipped one moving version -- fails this gate.
cargo deny check advisories licenses bans sources

# `cargo deny` honours features and targets; `cargo audit` reads the whole
# lockfile, so the two see different graphs and BOTH must run -- but they
# must not disagree about which advisories are accepted. The --ignore argv
# above is derived from deny.toml (validated above), never hand-copied, so
# the two cannot drift apart the way a manually-maintained second list could.
if [ "${#audit_ignore_args[@]}" -gt 0 ]; then
  cargo audit --deny warnings "${audit_ignore_args[@]}"
else
  cargo audit --deny warnings
fi
