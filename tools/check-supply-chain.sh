#!/usr/bin/env bash
#
# Supply-chain gate (SUPPLY-01 / SUPPLY-02, phase 287).
#
# WHY THIS SCRIPT HAS A POLICY STEP IN FRONT OF THE TWO TOOLS
#   `deny.toml` may waive findings in two places: `[advisories] ignore` waives a
#   RustSec advisory, `[[bans.skip]]` waives a duplicate dependency. Before this
#   step existed, a waiver needed nothing but a free-text `reason`. "notify v7
#   still pulls instant transitively" is a sentence, not a policy: it carries no
#   date, so nobody can tell whether it was assessed last week or two years ago;
#   no blast radius, so a reviewer cannot tell what the exception exposes; and no
#   clearing condition, so there is no event at which it is supposed to end. A
#   comment convention that nothing checks decays into decoration, which is the
#   exact shape .planning/STATE.md catalogues twelve times over.
#
#   So the metadata is now a parsed contract, enforced here, and this gate fails
#   the build on a waiver that does not carry it.
#
# WHY THE METADATA LIVES INSIDE THE `reason` STRING
#   Because cargo-deny will not accept it anywhere else. Measured 2026-08-14 with
#   cargo-deny 0.19.4, adding `expires = "2026-11-12"` to an ignore entry:
#
#     error[unexpected-keys]: found 1 unexpected keys, expected: ["id", "reason"]
#     [ERROR] failed to deserialize config
#     EXIT=1
#
#   `id`/`reason` and `crate`/`reason` are the whole schema. The contract is
#   therefore a structured prefix inside `reason`, parsed here:
#
#     [advisories] ignore
#       last-checked <YYYY-MM-DD>; expires <YYYY-MM-DD>; blast-radius: <text>; clears-when: <text>
#     [[bans.skip]]
#       last-checked <YYYY-MM-DD>; pinned-by: <text>; clears-when: <text>
#
# WHY AN EXPIRED ADVISORY EXCEPTION FAILS RATHER THAN WARNS
#   An exception with a clearing condition nobody evaluates is a permanent
#   exception wearing a deadline. A warning on an expired waiver is read once and
#   scrolled past; the waiver keeps suppressing a real advisory either way. So
#   `expires` in the past is an error, and the maximum window is bounded
#   (MAX_EXCEPTION_WINDOW_DAYS below) so that "expires 2099-01-01" cannot be used
#   to write a permanent exception in deadline clothing. The cost is real and is
#   accepted deliberately: CI can go red on a calendar date with no code change.
#   That is what a deadline is. The failure message says what to do -- re-check
#   whether the advisory still fires, then either delete the entry or record a new
#   assessment with a new date.
#
# WHY `[[bans.skip]]` ENTRIES CARRY NO EXPIRY
#   Because an exact-version skip is self-invalidating, and that was measured
#   rather than assumed. This parser accepts `<crate>@<SemVer 2.0>` -- including
#   valid prerelease and build metadata -- and rejects wildcard, range, operator,
#   partial, and invalid SemVer specs. cargo-deny then supplies two distinct
#   stale-waiver checks, and all three failure modes were constructed and observed
#   on 2026-08-14:
#
#     fixture@1.2.3                         -> fixture = =1.2.3
#     fixture-prerelease@1.2.3-alpha.1      -> fixture-prerelease = =1.2.3-alpha.1
#     fixture-build@1.2.3+build.7            -> fixture-build = =1.2.3
#     fixture-both@1.2.3-alpha.1+build.7     -> fixture-both = =1.2.3-alpha.1
#     serde_yaml@0.9.34+deprecated           -> serde_yaml = =0.9.34
#
#   Those are cargo-deny 0.19.4's own `unmatched-skip` / `unnecessary-skip`
#   renderings. The leading `=` is the exact selector evidence. cargo-deny follows
#   SemVer precedence by normalizing build metadata out of matching, but accepts
#   it in a valid version string; changing the real serde_yaml fixture's core from
#   0.9.34 to 0.9.33 changes `unnecessary-skip` to `unmatched-skip`.
#
#     thiserror@1.0.69 -> thiserror@1.0.68 (the skip no longer matches the lock):
#       error[duplicate]: found 2 duplicate entries for crate 'thiserror'
#       warning[unmatched-skip]: skipped crate 'thiserror = =1.0.68' was not encountered
#       bans FAILED / EXIT=2
#
#     a skip for a version absent from the graph (serde@0.0.1), run with
#     `-D unmatched-skip`:
#       error[unmatched-skip]: skipped crate 'serde = =0.0.1' was not encountered
#       bans FAILED / EXIT=2
#
#     a skip for a version still present but no longer duplicated
#     (serde@1.0.228), run with `-D unnecessary-skip`:
#       error[unnecessary-skip]: skip 'serde = =1.0.228' applied to a crate
#         with only one version
#       bans FAILED / EXIT=2
#     Without `-D`, the same diagnostic is a warning, `bans ok`, EXIT=0.
#
#   So a stale exact skip fails through the duplicate it stopped covering,
#   `unmatched-skip`, or `unnecessary-skip`. A date-based expiry on top of that
#   would only add calendar churn to a check the lockfile already makes.
#
# WHY `-D advisory-not-detected`, `-D unmatched-skip`, AND `-D unnecessary-skip`
#   All three are warnings by default, and a warning does not change the exit code:
#   with an ignore entry added for a real advisory against a crate this workspace
#   does not carry, `cargo deny check advisories` printed
#   `warning[advisory-not-detected]` and still exited 0 (measured 2026-08-14; the
#   id is deliberately not repeated here, because the scan below forbids one). An
#   advisory exception that no longer matches anything is an exception nobody
#   needs, and it was invisible to the gate. With `-D` the same input is
#   `error[advisory-not-detected] ... advisories FAILED`, EXIT=1.
#   These three flags are what makes "the exception should go when it is no longer
#   needed" a mechanical outcome instead of a periodic human sweep. They also
#   close the obvious way around this gate: switching cargo-deny's own detection
#   off with `[advisories] unmaintained = "none"` while leaving the waivers in
#   place does not quietly pass, it turns both entries into
#   `error[advisory-not-detected]` (constructed and observed 2026-08-14, EXIT=1).
#
# WHY THE `cargo audit --ignore` LIST IS DERIVED, NOT COPIED
#   It used to be two hand-maintained lists that had to agree: `[advisories]
#   ignore` in deny.toml, and `--ignore RUSTSEC-...` flags written out in this
#   file, with a comment asking the next person to keep them identical. Two lists
#   that must agree and are maintained by hand WILL drift -- this repo's
#   most-repeated defect. deny.toml is now the single source of truth: the ids
#   below are read out of it and turned into `--ignore` flags, so the two cannot
#   disagree, and there is no second list to update.
#
#   The scan that follows closes the other half. deny.toml is the only place an
#   advisory id may appear on an enforcement surface; a literal id in a workflow,
#   in a tools script (including this one), or in a cargo-audit `audit.toml` is a
#   second list being born, and fails here. BOUNDARY, stated rather than implied:
#   this catches a literal id written on one of those surfaces. It does not catch
#   an ignore list assembled at runtime from somewhere else, and it says nothing
#   about prose in docs/ or .planning/, which are not enforcement surfaces.
#
# THE ONE PLACE THIS GATE READS THE WALL CLOCK
#   `expires` is compared against `date.today()`. A verdict that depends on the
#   machine clock is normally this project's bug, not its design -- but a deadline
#   is a statement about the calendar, and there is nothing else to compare it to.
#   It stays deterministic for a given date: same tree, same day, same answer, and
#   every other check here is clock-free.
#
# REFUSING TO PASS SILENTLY
#   Guards, in the same spirit as check-gates-wired.sh and
#   check-fixture-freshness.sh: deny.toml must parse and must contain a `[bans]
#   skip` array; the surface list must be non-empty and must contain at least one
#   workflow and at least one tools script (otherwise the id scan would be
#   inspecting nothing while reporting success); and deny.toml is cross-checked
#   against its own text twice -- outside comments, an advisory id may appear ONLY
#   on an `id = "..."` line, and the set of ids in that text must equal the set the
#   TOML parser saw as ignore entries. So an entry the parser silently missed, one
#   parked under the wrong table, and an id hidden in some other field are all
#   failures rather than waivers nobody checked. The weaker of those two checks
#   alone was not enough, and that was measured: an id written into a
#   `[[bans.skip]]` reason while the same id is a real ignore entry leaves the sets
#   equal, and the gate exited 0 until the line-position rule was added.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Enforcement surfaces: every place other than deny.toml where an advisory could
# be waived. Tracked or untracked, so a NEW workflow or gate script counts on the
# commit that adds it (same enumeration as check-gates-wired.sh:74).
surfaces=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  surfaces+=("$path")
done < <(
  git ls-files -c -o --exclude-standard -- \
    '.github/workflows/*.yml' '.github/workflows/*.yaml' \
    'tools/*.sh' 'audit.toml' '.cargo/audit.toml' '*/audit.toml' \
    | LC_ALL=C sort -u
)

if [ "${#surfaces[@]}" -eq 0 ]; then
  echo "no workflow or tools script found to scan; refusing to pass silently" >&2
  exit 1
fi

python3 - "$ROOT_DIR/deny.toml" "$WORK_DIR/advisory-ignores" "${surfaces[@]}" <<'PY'
import datetime
import pathlib
import re
import sys

if sys.version_info < (3, 11):
    print(
        "::error::this gate parses deny.toml with tomllib, which needs "
        f"python3 >= 3.11; found {sys.version.split()[0]}",
        file=sys.stderr,
    )
    sys.exit(1)

import tomllib  # noqa: E402  (guarded above so the failure is legible)

deny_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
surfaces = [pathlib.Path(p) for p in sys.argv[3:]]

TODAY = datetime.date.today()

# An advisory exception is a security decision with a deadline. Beyond this many
# days the "deadline" stops being one, so the window itself is bounded.
MAX_EXCEPTION_WINDOW_DAYS = 180

# A field that says "n/a" carries exactly as much as a field that is absent, and
# reads as compliance. Both are rejected. Every string here is shorter than
# MIN_FIELD_CHARS, so the length check below would catch these anyway -- what this
# set buys is the specific message, not extra coverage.
PLACEHOLDERS = {"n/a", "na", "tbd", "todo", "none", "unknown", "-", "?", "see above"}
MIN_FIELD_CHARS = 24

ADVISORY_ID = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
SEMVER_NUMBER = r"(?:0|[1-9][0-9]*)"
SEMVER_PRERELEASE_ID = (
    r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
)
SEMVER_BUILD_ID = r"[0-9A-Za-z-]+"
EXACT_SKIP_SPEC = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9_-]*@"
    rf"{SEMVER_NUMBER}\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}"
    rf"(?:-{SEMVER_PRERELEASE_ID}(?:\.{SEMVER_PRERELEASE_ID})*)?"
    rf"(?:\+{SEMVER_BUILD_ID}(?:\.{SEMVER_BUILD_ID})*)?\Z"
)

# Executable grammar fixtures. These run before deny.toml is inspected so a
# future regex edit cannot silently admit the broad forms this policy exists to
# reject. The exact control prevents a regex that rejects everything from
# masquerading as a stricter gate.
SKIP_SPEC_FIXTURES = (
    # Exact SemVer 2.0 versions, including the forms cargo-deny 0.19.4 was
    # observed accepting as exact selectors.
    ("fixture@1.2.3", True),
    ("fixture@1.2.3-alpha.1", True),
    ("fixture@1.2.3+build.7", True),
    ("fixture@1.2.3-alpha.1+build.7", True),
    ("serde_yaml@0.9.34+deprecated", True),
    # Wildcards, partials, and operators are not exact versions.
    ("fixture@*", False),
    ("fixture@1", False),
    ("fixture@^1", False),
    ("fixture@~1.3", False),
    ("fixture@=1.2.3", False),
    ("fixture@>=1.2.3", False),
    ("fixture@1.2.*", False),
    # SemVer 2.0 forbids leading zeroes in numeric identifiers and empty
    # prerelease/build identifiers.
    ("fixture@01.2.3", False),
    ("fixture@1.02.3", False),
    ("fixture@1.2.03", False),
    ("fixture@1.2.3-01", False),
    ("fixture@1.2.3-alpha..1", False),
    ("fixture@1.2.3+build..7", False),
    ("fixture@1.2.3-", False),
    ("fixture@1.2.3+", False),
)

for fixture, expected in SKIP_SPEC_FIXTURES:
    actual = EXACT_SKIP_SPEC.fullmatch(fixture) is not None
    if actual != expected:
        print(
            "::error::internal exact-skip grammar fixture failed: "
            f"{fixture!r} expected accepted={expected}, got accepted={actual}",
            file=sys.stderr,
        )
        sys.exit(1)

errors = []


def problem(where, message):
    errors.append(f"{where}: {message}")


def parse_date(where, field, text):
    if not DATE.match(text):
        problem(where, f"`{field}` is `{text}`, not a YYYY-MM-DD date")
        return None
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        problem(where, f"`{field}` is `{text}`, which is not a real calendar date")
        return None


def check_text(where, field, text):
    stripped = text.strip()
    if not stripped:
        problem(where, f"`{field}` is empty")
        return
    if stripped.lower().rstrip(".") in PLACEHOLDERS:
        problem(where, f"`{field}` is the placeholder `{stripped}`")
        return
    if len(stripped) < MIN_FIELD_CHARS:
        problem(
            where,
            f"`{field}` is {len(stripped)} characters "
            f"(minimum {MIN_FIELD_CHARS}); say what it actually means",
        )


def split_labelled(where, rest, head_label, tail_label):
    """Split `head-label: ... ; tail-label: ...` into its two texts."""
    head_prefix = f"{head_label}: "
    tail_sep = f"; {tail_label}: "
    if not rest.startswith(head_prefix):
        problem(where, f"expected `{head_prefix}` after the dates, found `{rest[:40]}`")
        return None, None
    body = rest[len(head_prefix) :]
    occurrences = body.count(tail_sep)
    if occurrences != 1:
        problem(
            where,
            f"expected exactly one `{tail_sep.strip()}` separator, found {occurrences}",
        )
        return None, None
    head, _, tail = body.partition(tail_sep)
    return head, tail


try:
    raw = deny_path.read_text(encoding="utf-8")
except OSError as exc:
    print(f"::error::cannot read {deny_path}: {exc}", file=sys.stderr)
    sys.exit(1)

try:
    config = tomllib.loads(raw)
except tomllib.TOMLDecodeError as exc:
    print(f"::error::{deny_path} does not parse as TOML: {exc}", file=sys.stderr)
    sys.exit(1)

ignores = config.get("advisories", {}).get("ignore", [])
skips = config.get("bans", {}).get("skip")

if skips is None:
    print(
        "::error::deny.toml has no `[bans] skip` array; either the file was "
        "restructured or this parser is reading the wrong shape, and in both "
        "cases duplicate waivers would go unchecked",
        file=sys.stderr,
    )
    sys.exit(1)

# --- advisory exceptions -----------------------------------------------------
ignore_ids = []
for index, entry in enumerate(ignores):
    where = f"deny.toml [advisories] ignore[{index}]"
    if not isinstance(entry, dict):
        problem(where, "must be a table with `id` and `reason`, not a bare string")
        continue
    advisory_id = entry.get("id", "")
    if not isinstance(advisory_id, str):
        advisory_id = ""
    where = f"deny.toml [advisories] ignore `{advisory_id or '<no id>'}`"
    if not ADVISORY_ID.fullmatch(advisory_id):
        problem(where, "`id` is not a RUSTSEC-YYYY-NNNN advisory id")
    else:
        ignore_ids.append(advisory_id)
    reason = entry.get("reason", "")
    if not isinstance(reason, str) or not reason.strip():
        problem(where, "has no `reason`")
        continue

    head = re.match(
        r"^last-checked (\S+); expires (\S+); (.*)$", reason.strip(), re.DOTALL
    )
    if head is None:
        problem(
            where,
            "reason must begin `last-checked <YYYY-MM-DD>; expires <YYYY-MM-DD>; `",
        )
        continue
    checked = parse_date(where, "last-checked", head.group(1))
    expires = parse_date(where, "expires", head.group(2))
    blast, clears = split_labelled(where, head.group(3), "blast-radius", "clears-when")
    if blast is not None:
        check_text(where, "blast-radius", blast)
        check_text(where, "clears-when", clears)
    if checked is not None and checked > TODAY:
        problem(where, f"`last-checked {checked}` is in the future")
    if checked is not None and expires is not None:
        if expires <= checked:
            problem(where, f"`expires {expires}` is not after `last-checked {checked}`")
        elif (expires - checked).days > MAX_EXCEPTION_WINDOW_DAYS:
            problem(
                where,
                f"the window last-checked..expires is {(expires - checked).days} days, "
                f"over the {MAX_EXCEPTION_WINDOW_DAYS}-day maximum",
            )
    if expires is not None and expires < TODAY:
        problem(
            where,
            f"EXPIRED: `expires {expires}` passed {(TODAY - expires).days} day(s) ago. "
            "Re-run this gate with the entry deleted: if the advisory no longer "
            "fires, delete it for good; if it does, record a new assessment with a "
            "new `last-checked`/`expires` pair",
        )

# --- duplicate-dependency waivers -------------------------------------------
for index, entry in enumerate(skips):
    where = f"deny.toml [bans] skip[{index}]"
    if not isinstance(entry, dict):
        problem(where, "must be a table with `crate` and `reason`, not a bare string")
        continue
    spec = entry.get("crate", "")
    if not isinstance(spec, str):
        spec = ""
    where = f"deny.toml [bans] skip `{spec or '<no crate>'}`"
    if EXACT_SKIP_SPEC.fullmatch(spec) is None:
        problem(
            where,
            "`crate` must be an exact `<crate>@<SemVer 2.0>` spec; valid "
            "prerelease and build metadata are accepted, but wildcard, range, "
            "operator, partial, and invalid SemVer requirements are forbidden "
            "because they can keep matching after the reviewed version moves "
            "or do not identify one valid version",
        )
    reason = entry.get("reason", "")
    if not isinstance(reason, str) or not reason.strip():
        problem(where, "has no `reason`")
        continue
    head = re.match(r"^last-checked (\S+); (.*)$", reason.strip(), re.DOTALL)
    if head is None:
        problem(where, "reason must begin `last-checked <YYYY-MM-DD>; `")
        continue
    checked = parse_date(where, "last-checked", head.group(1))
    pinned, clears = split_labelled(where, head.group(2), "pinned-by", "clears-when")
    if pinned is not None:
        check_text(where, "pinned-by", pinned)
        check_text(where, "clears-when", clears)
    if checked is not None and checked > TODAY:
        problem(where, f"`last-checked {checked}` is in the future")

# --- the parser must have seen every advisory id in the file ----------------
# Guards against an entry the TOML parse silently did not reach: parked under the
# wrong table, or in a shape this script does not walk. Comment lines are excluded
# because deny.toml explains its own policy in prose.
#
# TWO checks, because the set comparison alone is weaker than it looks and that
# was measured: an id written into a `[[bans.skip]]` reason, while the SAME id is
# also a real ignore entry, leaves the two sets equal and slipped through (built
# and observed 2026-08-14, EXIT=0). So each occurrence is also required to sit on
# an `id = "..."` line, which is the only position in this file that waives
# anything.
uncommented_lines = [
    line for line in raw.splitlines() if not line.lstrip().startswith("#")
]
for line in uncommented_lines:
    for found in ADVISORY_ID.findall(line):
        if f'id = "{found}"' not in line:
            problem(
                "deny.toml",
                f"advisory id {found} appears outside an `[advisories] ignore` "
                f"entry, on `{line.strip()[:60]}`; an id in this file names a "
                "waiver, and a waiver anywhere but the ignore array is one this "
                "gate does not check",
            )
text_ids = set(ADVISORY_ID.findall("\n".join(uncommented_lines)))
parsed_ids = set(ignore_ids)
if text_ids != parsed_ids:
    only_text = sorted(text_ids - parsed_ids)
    only_parsed = sorted(parsed_ids - text_ids)
    if only_text:
        problem(
            "deny.toml",
            f"advisory id(s) {', '.join(only_text)} appear in the file but are not "
            "`[advisories] ignore` entries this gate checked",
        )
    if only_parsed:
        problem(
            "deny.toml",
            f"advisory id(s) {', '.join(only_parsed)} were parsed as ignore entries "
            "but do not appear in the file text; the parse and the file disagree",
        )

# --- no second list anywhere else -------------------------------------------
has_workflow = any(str(p).startswith(".github/workflows/") for p in surfaces)
has_tool = any(str(p).startswith("tools/") for p in surfaces)
if not (has_workflow and has_tool):
    print(
        "::error::enforcement-surface scan covered "
        f"{len(surfaces)} file(s) but no workflow and/or no tools script; "
        "it would be reporting success over a region it never inspected",
        file=sys.stderr,
    )
    sys.exit(1)

for path in surfaces:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        problem(str(path), f"cannot be read for the advisory-id scan: {exc}")
        continue
    for number, line in enumerate(lines, start=1):
        for found in ADVISORY_ID.findall(line):
            problem(
                f"{path}:{number}",
                f"names advisory {found}. deny.toml `[advisories] ignore` is the "
                "single source of truth and this gate derives every "
                "`cargo audit --ignore` flag from it; a second list here would "
                "drift out of agreement with it",
            )

if errors:
    print(
        f"::error::supply-chain exception policy: {len(errors)} problem(s)",
        file=sys.stderr,
    )
    for error in errors:
        print(f"::error::  {error}", file=sys.stderr)
    sys.exit(1)

out_path.write_text("".join(f"{advisory_id}\n" for advisory_id in ignore_ids))

print(
    f"exception policy ok: {len(ignores)} advisory exception(s), "
    f"{len(skips)} duplicate waiver(s), "
    f"{len(surfaces)} enforcement surface(s) scanned for advisory ids"
)
for entry in ignores:
    reason = entry["reason"]
    expires = datetime.date.fromisoformat(
        re.search(r"expires ([0-9]{4}-[0-9]{2}-[0-9]{2})", reason).group(1)
    )
    print(f"  {entry['id']}: expires {expires} ({(expires - TODAY).days} day(s) left)")
PY

# `bans` runs with duplicates ENFORCED. Accepted duplicates are enumerated, dated
# and justified as exact-version `[[bans.skip]]` entries in deny.toml, so a new
# duplicate -- or a skipped one moving version or ceasing to be a duplicate --
# fails this gate. The three `-D` flags escalate cargo-deny's own stale-waiver
# warnings into errors; see the header for the measured cases.
cargo deny check -D advisory-not-detected -D unmatched-skip -D unnecessary-skip \
  advisories licenses bans sources

# `cargo deny` honours features and targets; `cargo audit` reads the whole
# lockfile, so the two see different graphs and BOTH must run. The ignore list
# below is READ OUT OF deny.toml by the step above -- there is no second list to
# keep in step with it.
audit_flags=()
audit_ignore_count=0
while IFS= read -r advisory_id; do
  [ -n "$advisory_id" ] || continue
  audit_flags+=(--ignore "$advisory_id")
  audit_ignore_count=$((audit_ignore_count + 1))
done < "$WORK_DIR/advisory-ignores"

if [ "$audit_ignore_count" -eq 0 ]; then
  echo "cargo audit: no advisory exceptions in deny.toml"
  cargo audit --deny warnings
else
  echo "cargo audit: $audit_ignore_count advisory exception(s) derived from deny.toml"
  cargo audit --deny warnings "${audit_flags[@]}"
fi
