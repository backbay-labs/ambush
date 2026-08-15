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
#   Because two independent checks make an exact-version skip self-invalidating.
#   Their ownership is deliberately separate:
#
#   1. This metadata stage owns FULL TEXTUAL IDENTITY. It splits at the final `@`,
#      requires a non-empty name and exact SemVer 2.0 version text, then makes
#      Cargo.lock's exact name authoritative. That accepts Cargo-valid names a
#      hand-written subset would miss, including leading underscore and Unicode
#      XID names. Every selector fails when multiple locked rows share its exact
#      name and build-stripped core+prerelease precedence identity: cargo-deny
#      cannot distinguish registry vs path identity or build variants there.
#      Ambiguity errors print each row's source string; a source-less lock row is
#      truthfully labeled path/local while noting Cargo.lock records no filesystem
#      path.
#
#      This is necessary because cargo-deny 0.19.4 normalizes build metadata out
#      of its comparator. Constructed on 2026-08-14 at 69b32d7: changing the real
#      duplicated skip `thiserror@1.0.69` to `thiserror@1.0.69+stale` still printed
#      `bans ok`, and the ENTIRE gate exited 0. The same cargo-deny behavior renders
#      `serde_yaml@0.9.34+deprecated` as `serde_yaml = =0.9.34`. Grammar validation
#      alone therefore cannot make build-bearing selectors stale safely.
#
#   2. cargo-deny owns DUPLICATE APPLICABILITY inside the graph it scans. With
#      `-D unmatched-skip`, a lock-present exact version absent from that graph
#      fails. With `-D unnecessary-skip`, a graph-present version that is no
#      longer duplicated fails. An uncovered new duplicate fails normally.
#
#      Constructed with serde@1.0.228, which is locked and graph-present but has
#      only one version:
#       error[unnecessary-skip]: skip 'serde = =1.0.228' applied to a crate
#         with only one version
#       bans FAILED / EXIT=2
#      Without `-D`, the same diagnostic is a warning, `bans ok`, EXIT=0.
#
#   So a moved or mistyped full version fails against Cargo.lock before cargo-deny
#   runs, and a version that stops being an applicable duplicate fails in
#   cargo-deny. A date-based expiry on top would only add calendar churn to checks
#   the resolved inventory and graph already make.
#
# WHY LOCKED RESOLUTION RUNS BEFORE THE LOCK INVENTORY IS READ
#   Cargo.lock is evidence only if it is current for the manifests. Measured on
#   2026-08-14 at 4ae5286: with a deliberately stale lock, the Python policy read
#   the old rows and passed; the unlocked `cargo deny check` then resolved the
#   manifests and rewrote Cargo.lock, so either same-precedence ambiguity bypass
#   failed only on the SECOND invocation. The first invocation had already made
#   its policy decision against stale evidence.
#
#   A quiet `cargo metadata --locked --format-version 1` now runs before Python
#   reads Cargo.lock. cargo-deny receives its own global `--locked` flag before
#   `check`, which is the position accepted by cargo-deny 0.19.4. cargo-audit
#   0.22.0 has no locked option; it reads Cargo.lock directly, so the gate keeps a
#   byte snapshot and compares it after metadata, cargo-deny, and cargo-audit.
#   Any attempted rewrite fails the gate. The disposable stale-lock fixture below
#   proves on every run that the FIRST locked metadata invocation refuses stale
#   resolution and leaves the lock bytes unchanged.
#
# WHY THE SCANNERS ARE EXACT-PINNED
#   Their CLI is part of this gate's policy contract. cargo-deny 0.20.0 moved
#   `--config` from the `check` subcommand to the root command; an unpinned hosted
#   install selected 0.20.2 while local validation used 0.19.4, so the helper scan
#   failed in CI before checking anything. This gate deliberately stays on the
#   measured 0.19.4 semantics until an explicit upgrade changes the invocation,
#   executable evidence, and documentation together. cargo-audit is likewise
#   pinned to the measured 0.22.0 contract whose lack of a locked mode requires
#   the byte-snapshot guard below. A missing or mismatched tool fails immediately.
#
# WHY THE CARGO CACHE EXCLUDES INSTALLED EXECUTABLES
#   A version string is not executable provenance. GitHub Actions cache entries
#   are reachable from other runs in the same repository scope, so restoring
#   ~/.cargo/bin could put an attacker-controlled cargo-deny or cargo-audit ahead
#   of the toolchain. A planted executable can print the pinned version and then
#   false-green the scan. Cargo's .crates.toml and .crates2.json install records
#   are excluded with the binaries; every cache retains only downloaded registry
#   and git sources. Every key and restore prefix uses the rotated
#   cargo-home-sources-v1 namespace, because changing only `path:` would not stop
#   a legacy cache archive from extracting the paths it recorded when created.
#   CI then rebuilds both exact scanner versions unconditionally with
#   `cargo install --locked --force`, and this gate checks that entire workflow
#   contract plus mutations that try to restore each bypass.
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
#   check-fixture-freshness.sh: deny.toml and Cargo.lock must parse; Cargo.lock must
#   expose a non-empty package inventory; deny.toml must contain a `[bans] skip`
#   array; the surface list must contain a workflow and a tools script; and
#   deny.toml is cross-checked against its own text twice. Outside comments, an
#   advisory id may appear ONLY on an `id = "..."` line, and the set of ids in that
#   text must equal the set the TOML parser saw as ignore entries. So an entry the
#   parser silently missed, one parked under the wrong table, and an id hidden in
#   some other field are all failures rather than waivers nobody checked. The
#   weaker of those two checks alone was not enough, and that was measured: an id
#   written into a `[[bans.skip]]` reason while the same id is a real ignore entry
#   leaves the sets equal, and the gate exited 0 until the line-position rule was
#   added.
set -euo pipefail

# The nominal gate never sets this. Version fixtures symlink this script under
# the scanner names so their subprocess output is deterministic and dependency-
# free; any other basename refuses to act as a fake.
if [ "${SUPPLY_CHAIN_TOOL_VERSION_FAKE:-0}" = "1" ]; then
  case "${0##*/}" in
    cargo-deny)
      printf 'cargo-deny %s\n' "${SUPPLY_CHAIN_FAKE_CARGO_DENY_VERSION:?}"
      ;;
    cargo-audit)
      printf 'cargo-audit %s\n' "${SUPPLY_CHAIN_FAKE_CARGO_AUDIT_VERSION:?}"
      ;;
    *)
      echo "::error::tool-version fake invoked under unexpected basename ${0##*/}" >&2
      exit 1
      ;;
  esac
  exit 0
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

REQUIRED_CARGO_DENY_VERSION="0.19.4"
REQUIRED_CARGO_AUDIT_VERSION="0.22.0"

require_exact_tool_version() {
  local executable="$1"
  local expected="$2"
  local actual

  if ! command -v "$executable" >/dev/null; then
    echo "::error::$executable $expected is required but is not installed" >&2
    return 1
  fi
  if ! actual="$("$executable" --version 2>&1)"; then
    echo "::error::failed to read $executable version: $actual" >&2
    return 1
  fi
  if [ "$actual" != "$executable $expected" ]; then
    echo "::error::$executable version mismatch: expected $expected, got '$actual'" >&2
    return 1
  fi
}

validate_tool_version_contract() {
  if [ -n "${CARGO_DENY_VERSION:-}" ] && \
    [ "$CARGO_DENY_VERSION" != "$REQUIRED_CARGO_DENY_VERSION" ]; then
    echo "::error::workflow cargo-deny pin $CARGO_DENY_VERSION disagrees with gate pin $REQUIRED_CARGO_DENY_VERSION" >&2
    return 1
  fi
  if [ -n "${CARGO_AUDIT_VERSION:-}" ] && \
    [ "$CARGO_AUDIT_VERSION" != "$REQUIRED_CARGO_AUDIT_VERSION" ]; then
    echo "::error::workflow cargo-audit pin $CARGO_AUDIT_VERSION disagrees with gate pin $REQUIRED_CARGO_AUDIT_VERSION" >&2
    return 1
  fi
  require_exact_tool_version cargo-deny "$REQUIRED_CARGO_DENY_VERSION" || return 1
  require_exact_tool_version cargo-audit "$REQUIRED_CARGO_AUDIT_VERSION" || return 1
}

# Non-vacuity fixtures for the contract above. Exact reported versions must pass;
# both workflow-pin drift and binary-reported drift must fail in isolated
# subprocesses before any dependency scan is allowed to begin.
VERSION_FIXTURE_BIN="$WORK_DIR/tool-version-fixture-bin"
mkdir -p "$VERSION_FIXTURE_BIN"
ln -s "$ROOT_DIR/tools/check-supply-chain.sh" "$VERSION_FIXTURE_BIN/cargo-deny"
ln -s "$ROOT_DIR/tools/check-supply-chain.sh" "$VERSION_FIXTURE_BIN/cargo-audit"

if ! (
  export PATH="$VERSION_FIXTURE_BIN:$PATH"
  export SUPPLY_CHAIN_TOOL_VERSION_FAKE=1
  export SUPPLY_CHAIN_FAKE_CARGO_DENY_VERSION="$REQUIRED_CARGO_DENY_VERSION"
  export SUPPLY_CHAIN_FAKE_CARGO_AUDIT_VERSION="$REQUIRED_CARGO_AUDIT_VERSION"
  export CARGO_DENY_VERSION="$REQUIRED_CARGO_DENY_VERSION"
  export CARGO_AUDIT_VERSION="$REQUIRED_CARGO_AUDIT_VERSION"
  validate_tool_version_contract
) >"$WORK_DIR/tool-version-exact.stdout" 2>"$WORK_DIR/tool-version-exact.stderr"; then
  sed -n '1,20p' "$WORK_DIR/tool-version-exact.stderr" >&2
  echo "::error::exact scanner-version control was rejected" >&2
  exit 1
fi

if (
  export PATH="$VERSION_FIXTURE_BIN:$PATH"
  export SUPPLY_CHAIN_TOOL_VERSION_FAKE=1
  export SUPPLY_CHAIN_FAKE_CARGO_DENY_VERSION="$REQUIRED_CARGO_DENY_VERSION"
  export SUPPLY_CHAIN_FAKE_CARGO_AUDIT_VERSION="$REQUIRED_CARGO_AUDIT_VERSION"
  export CARGO_DENY_VERSION="0.20.2"
  export CARGO_AUDIT_VERSION="$REQUIRED_CARGO_AUDIT_VERSION"
  validate_tool_version_contract
) >"$WORK_DIR/tool-version-env-drift.stdout" 2>"$WORK_DIR/tool-version-env-drift.stderr"; then
  echo "::error::workflow scanner-version drift fixture unexpectedly passed" >&2
  exit 1
fi
if ! grep -Fq 'workflow cargo-deny pin 0.20.2 disagrees with gate pin 0.19.4' \
  "$WORK_DIR/tool-version-env-drift.stderr"; then
  sed -n '1,20p' "$WORK_DIR/tool-version-env-drift.stderr" >&2
  echo "::error::workflow scanner-version drift failed for the wrong reason" >&2
  exit 1
fi

if (
  export PATH="$VERSION_FIXTURE_BIN:$PATH"
  export SUPPLY_CHAIN_TOOL_VERSION_FAKE=1
  export SUPPLY_CHAIN_FAKE_CARGO_DENY_VERSION="0.20.2"
  export SUPPLY_CHAIN_FAKE_CARGO_AUDIT_VERSION="$REQUIRED_CARGO_AUDIT_VERSION"
  export CARGO_DENY_VERSION="$REQUIRED_CARGO_DENY_VERSION"
  export CARGO_AUDIT_VERSION="$REQUIRED_CARGO_AUDIT_VERSION"
  validate_tool_version_contract
) >"$WORK_DIR/tool-version-binary-drift.stdout" 2>"$WORK_DIR/tool-version-binary-drift.stderr"; then
  echo "::error::binary-reported scanner-version drift fixture unexpectedly passed" >&2
  exit 1
fi
if ! grep -Fq "cargo-deny version mismatch: expected 0.19.4, got 'cargo-deny 0.20.2'" \
  "$WORK_DIR/tool-version-binary-drift.stderr"; then
  sed -n '1,20p' "$WORK_DIR/tool-version-binary-drift.stderr" >&2
  echo "::error::binary scanner-version drift failed for the wrong reason" >&2
  exit 1
fi
echo "tool version fixtures ok: exact pins accepted, env and binary drift refused"

if ! validate_tool_version_contract; then
  exit 1
fi
echo "supply-chain tools ok: cargo-deny $REQUIRED_CARGO_DENY_VERSION, cargo-audit $REQUIRED_CARGO_AUDIT_VERSION"

# Keep executable provenance separate from downloaded-source reuse. This parser
# intentionally validates every actions/cache block in the workflow, not merely
# the supply job: a poisoned cargo executable restored by any lane is still a
# poisoned executable. The mutations make the negative contract executable.
python3 - "$ROOT_DIR/.github/workflows/ci.yml" <<'PY'
import pathlib
import re
import sys

workflow_path = pathlib.Path(sys.argv[1])
workflow = workflow_path.read_text(encoding="utf-8")

allowed_paths = [
    "~/.cargo/registry/index/",
    "~/.cargo/registry/cache/",
    "~/.cargo/git/db/",
    "~/.cargo/git/checkouts/",
]
forbidden_paths = [
    "~/.cargo/bin/",
    "~/.cargo/.crates.toml",
    "~/.cargo/.crates2.json",
]
namespace = "cargo-home-sources-v1-"

deny_install = """      - name: Install cargo-deny
        run: |
          cargo install cargo-deny --version "${CARGO_DENY_VERSION}" --locked --force
          cargo-deny --version
"""
audit_install = """      - name: Install cargo-audit
        run: |
          cargo install cargo-audit --version "${CARGO_AUDIT_VERSION}" --locked --force
          cargo-audit --version
"""


def workflow_contract_problems(text: str) -> list[str]:
    problems: list[str] = []

    for forbidden in forbidden_paths:
        if forbidden in text:
            problems.append(f"forbidden Cargo cache path is present: {forbidden}")

    action_count = len(re.findall(r"uses: actions/cache@", text))
    blocks = re.findall(
        r"(?ms)^      - name: Cache cargo home\n.*?(?=^      - name:|\Z)",
        text,
    )
    if not blocks:
        problems.append("workflow contains no Cargo source cache blocks")
    if action_count != len(blocks):
        problems.append(
            "every actions/cache use must be a validated Cache cargo home block "
            f"(actions={action_count}, validated={len(blocks)})"
        )

    for index, block in enumerate(blocks, start=1):
        path_match = re.search(
            r"(?m)^          path: \|\n"
            r"(?P<paths>(?:            \S.*\n)+)"
            r"^          key: ",
            block,
        )
        if path_match is None:
            problems.append(f"Cargo cache block {index} has no parseable path list")
        else:
            paths = [line.strip() for line in path_match.group("paths").splitlines()]
            if paths != allowed_paths:
                problems.append(
                    f"Cargo cache block {index} paths are not the exact source-only set: {paths!r}"
                )

        key_match = re.search(r"(?m)^          key: (.+)$", block)
        if key_match is None or not key_match.group(1).startswith(namespace):
            actual = key_match.group(1) if key_match else "<missing>"
            problems.append(
                f"Cargo cache block {index} key is outside {namespace!r}: {actual}"
            )

        restore_match = re.search(
            r"(?m)^          restore-keys: \|\n(?P<keys>(?:            \S.*\n)+)",
            block,
        )
        if restore_match is None:
            problems.append(f"Cargo cache block {index} has no parseable restore prefix")
        else:
            restore_keys = [
                line.strip() for line in restore_match.group("keys").splitlines()
            ]
            if not restore_keys or any(
                not key.startswith(namespace) for key in restore_keys
            ):
                problems.append(
                    f"Cargo cache block {index} has legacy restore prefix: {restore_keys!r}"
                )

    supply_match = re.search(
        r"(?ms)^  supply-chain:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    if supply_match is None:
        problems.append("workflow has no parseable supply-chain job")
        supply_job = ""
    else:
        supply_job = supply_match.group("body")

    if supply_job.count(deny_install) != 1:
        problems.append(
            "cargo-deny must be installed exactly once, unconditionally, with --locked --force"
        )
    if supply_job.count(audit_install) != 1:
        problems.append(
            "cargo-audit must be installed exactly once, unconditionally, with --locked --force"
        )

    return problems


def require_valid(label: str, text: str) -> None:
    problems = workflow_contract_problems(text)
    if problems:
        raise SystemExit(f"{label} unexpectedly failed: {'; '.join(problems)}")


def require_invalid(label: str, text: str, expected: str) -> None:
    problems = workflow_contract_problems(text)
    matching = [problem for problem in problems if expected in problem]
    if not matching:
        rendered = "; ".join(problems) if problems else "no problems"
        raise SystemExit(f"{label} unexpectedly passed or failed vacuously: {rendered}")
    print(f"workflow mutation refused: {label}: {matching[0]}")


require_valid("checked-in workflow", workflow)

for forbidden in forbidden_paths:
    mutated = workflow.replace(
        "            ~/.cargo/registry/index/\n",
        f"            {forbidden}\n            ~/.cargo/registry/index/\n",
        1,
    )
    if mutated == workflow:
        raise SystemExit(f"could not construct forbidden-path mutation for {forbidden}")
    require_invalid(
        f"forbidden-path mutation {forbidden}",
        mutated,
        f"forbidden Cargo cache path is present: {forbidden}",
    )

legacy_key = workflow.replace(namespace, "cargo-home-", 1)
if legacy_key == workflow:
    raise SystemExit("could not construct legacy cache-key mutation")
require_invalid("legacy cache-key mutation", legacy_key, "key is outside")

restore_marker = f"            {namespace}"
legacy_restore = workflow.replace(restore_marker, "            cargo-home-", 1)
if legacy_restore == workflow:
    raise SystemExit("could not construct legacy restore-prefix mutation")
require_invalid("legacy restore-prefix mutation", legacy_restore, "legacy restore prefix")

conditional_install = workflow.replace(
    "      - name: Install cargo-deny\n        run: |\n",
    "      - name: Install cargo-deny\n        if: success()\n        run: |\n",
    1,
)
if conditional_install == workflow:
    raise SystemExit("could not construct conditional scanner-install mutation")
require_invalid(
    "conditional scanner-install mutation",
    conditional_install,
    "cargo-deny must be installed exactly once, unconditionally",
)

print(
    "workflow cache fixtures ok: source-only rotated caches and unconditional "
    "scanner installs enforced"
)
PY

ASSURANCE_HELPER_DIR="$ROOT_DIR/tools/negative-registry-ast"
ASSURANCE_HELPER_MANIFEST="$ASSURANCE_HELPER_DIR/Cargo.toml"
ASSURANCE_HELPER_LOCK="$ASSURANCE_HELPER_DIR/Cargo.lock"
ASSURANCE_HELPER_DENY="$ASSURANCE_HELPER_DIR/deny.toml"

locked_metadata() {
  cargo metadata --locked --format-version 1 --quiet "$@"
}

# Executable first-run regression for the stale-lock TOCTOU above. The checked-in
# fixture is copied so even a broken Cargo invocation cannot damage the evidence
# used by the next run. Its path dependency manifest says 0.2.0 while the locked
# dependency row says 0.1.0; the root package identity itself is unchanged.
STALE_LOCK_FIXTURE_SOURCE="$ROOT_DIR/tools/fixtures/supply-chain-stale-lock"
STALE_LOCK_FIXTURE="$WORK_DIR/supply-chain-stale-lock"
cp -R "$STALE_LOCK_FIXTURE_SOURCE" "$STALE_LOCK_FIXTURE"
cp "$STALE_LOCK_FIXTURE/Cargo.lock" "$WORK_DIR/stale-lock-before"

stale_metadata_status=0
if locked_metadata \
  --manifest-path "$STALE_LOCK_FIXTURE/Cargo.toml" \
  >"$WORK_DIR/stale-lock-metadata.json" \
  2>"$WORK_DIR/stale-lock-metadata.stderr"; then
  stale_metadata_status=0
else
  stale_metadata_status=$?
fi

if ! cmp -s "$WORK_DIR/stale-lock-before" "$STALE_LOCK_FIXTURE/Cargo.lock"; then
  echo "::error::locked metadata rewrote the disposable stale Cargo.lock" >&2
  exit 1
fi
if [ "$stale_metadata_status" -eq 0 ]; then
  echo "::error::locked metadata accepted the disposable stale Cargo.lock" >&2
  exit 1
fi
if ! grep -Fq 'Cargo.lock' "$WORK_DIR/stale-lock-metadata.stderr" || \
  ! grep -Fq -- '--locked' "$WORK_DIR/stale-lock-metadata.stderr"; then
  sed -n '1,20p' "$WORK_DIR/stale-lock-metadata.stderr" >&2
  echo "::error::stale-lock fixture failed for an unexpected reason" >&2
  exit 1
fi
echo "locked resolution fixture ok: first run refused stale Cargo.lock without mutation"

# Establish that the repository lock is current before it becomes policy input,
# and retain one immutable baseline through both downstream scanners.
cp "$ROOT_DIR/Cargo.lock" "$WORK_DIR/repository-lock-baseline"
metadata_status=0
if locked_metadata >"$WORK_DIR/repository-metadata.json"; then
  metadata_status=0
else
  metadata_status=$?
fi
if ! cmp -s "$WORK_DIR/repository-lock-baseline" "$ROOT_DIR/Cargo.lock"; then
  echo "::error::cargo metadata changed Cargo.lock despite --locked" >&2
  exit 1
fi
if [ "$metadata_status" -ne 0 ]; then
  echo "::error::Cargo.lock is stale for the manifests; refusing to parse stale inventory" >&2
  exit "$metadata_status"
fi
echo "locked resolution ok: Cargo.lock is current for the manifests"

# The negative-registry AST verifier is an executable Rust package with its own
# lockfile and intentionally separate workspace. Root-workspace scans cannot see
# that graph. Prove its resolution is locked before treating either its code or
# its dependency inventory as assurance evidence.
cp "$ASSURANCE_HELPER_LOCK" "$WORK_DIR/assurance-helper-lock-baseline"
helper_metadata_status=0
if locked_metadata \
  --manifest-path "$ASSURANCE_HELPER_MANIFEST" \
  >"$WORK_DIR/assurance-helper-metadata.json"; then
  helper_metadata_status=0
else
  helper_metadata_status=$?
fi
if ! cmp -s "$WORK_DIR/assurance-helper-lock-baseline" "$ASSURANCE_HELPER_LOCK"; then
  echo "::error::locked metadata changed the negative-registry helper Cargo.lock" >&2
  exit 1
fi
if [ "$helper_metadata_status" -ne 0 ]; then
  echo "::error::the negative-registry helper Cargo.lock is stale" >&2
  exit "$helper_metadata_status"
fi

# The helper gets no private waiver surface. It inherits the root license and
# source policy exactly, scans all of its features, and permits neither advisory
# ignores nor duplicate-version skips. A future policy change therefore updates
# one reviewed root decision and this strict projection together.
python3 - "$ROOT_DIR/deny.toml" "$ASSURANCE_HELPER_DENY" <<'PY'
import pathlib
import sys
import tomllib

root = tomllib.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
helper = tomllib.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
errors = []

root_licenses = root.get("licenses", {})
helper_licenses = helper.get("licenses", {})
helper_allow = set(helper_licenses.get("allow", []))
root_allow = set(root_licenses.get("allow", []))
if not helper_allow or not helper_allow.issubset(root_allow):
    errors.append("[licenses].allow must be a non-empty subset of the root policy")
if helper_licenses.get("confidence-threshold") != root_licenses.get(
    "confidence-threshold"
):
    errors.append("[licenses].confidence-threshold must match the root policy")
if helper_licenses.get("exceptions") != []:
    errors.append("[licenses].exceptions must stay empty")
if helper.get("sources") != root.get("sources"):
    errors.append("[sources] must exactly match the root policy")
if helper.get("graph") != {"targets": [], "all-features": True}:
    errors.append("[graph] must scan all helper features and all configured targets")

advisories = helper.get("advisories", {})
if advisories.get("ignore") != []:
    errors.append("[advisories].ignore must stay empty")
if advisories.get("db-path") != root.get("advisories", {}).get("db-path"):
    errors.append("[advisories].db-path must match the root policy")
if advisories.get("db-urls") != root.get("advisories", {}).get("db-urls"):
    errors.append("[advisories].db-urls must match the root policy")

root_bans = root.get("bans", {})
helper_bans = helper.get("bans", {})
for key in ("multiple-versions", "wildcards", "highlight"):
    if helper_bans.get(key) != root_bans.get(key):
        errors.append(f"[bans].{key} must match the root policy")
if helper_bans.get("skip") != []:
    errors.append("[bans].skip must stay empty")

if errors:
    for error in errors:
        print(f"::error::negative-registry helper policy: {error}", file=sys.stderr)
    raise SystemExit(1)
PY
echo "negative-registry helper locked resolution and zero-waiver policy ok"

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
    'tools/*.sh' 'tools/negative-registry-ast/deny.toml' \
    'audit.toml' '.cargo/audit.toml' '*/audit.toml' \
    | LC_ALL=C sort -u
)

if [ "${#surfaces[@]}" -eq 0 ]; then
  echo "no workflow or tools script found to scan; refusing to pass silently" >&2
  exit 1
fi

python3 - "$ROOT_DIR/deny.toml" "$ROOT_DIR/Cargo.lock" \
  "$WORK_DIR/advisory-ignores" "${surfaces[@]}" <<'PY'
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
lock_path = pathlib.Path(sys.argv[2])
out_path = pathlib.Path(sys.argv[3])
surfaces = [pathlib.Path(p) for p in sys.argv[4:]]

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
SEMVER_TEXT = (
    rf"{SEMVER_NUMBER}\.{SEMVER_NUMBER}\.{SEMVER_NUMBER}"
    rf"(?:-{SEMVER_PRERELEASE_ID}(?:\.{SEMVER_PRERELEASE_ID})*)?"
    rf"(?:\+{SEMVER_BUILD_ID}(?:\.{SEMVER_BUILD_ID})*)?"
)
EXACT_SEMVER = re.compile(rf"\A{SEMVER_TEXT}\Z")


def split_skip_spec(spec):
    """Split at the final @; Cargo.lock is authoritative for the package name."""
    name, separator, version = spec.rpartition("@")
    if not separator or not name or EXACT_SEMVER.fullmatch(version) is None:
        return None
    return name, version


def locked_skip_problem(spec, locked_packages):
    """Return why an exact skip does not identify one safe lockfile version."""
    parsed = split_skip_spec(spec)
    if parsed is None:
        raise ValueError(f"lock identity called with invalid skip spec {spec!r}")

    name, version = parsed
    locked_rows = [
        (locked_version, locked_identity)
        for locked_name, locked_version, locked_identity in locked_packages
        if locked_name == name
    ]

    precedence = version.partition("+")[0]
    same_precedence = [
        (locked_version, locked_identity)
        for locked_version, locked_identity in locked_rows
        if locked_version.partition("+")[0] == precedence
    ]
    if len(same_precedence) > 1:
        rendered = "; ".join(
            f"{locked_version} [{locked_identity}]"
            for locked_version, locked_identity in sorted(same_precedence)
        )
        return (
            f"selector `{spec}` is ambiguous: Cargo.lock has "
            f"{len(same_precedence)} `{name}` rows with build-stripped SemVer "
            f"precedence identity `{precedence}`: {rendered}. cargo-deny cannot "
            "distinguish these package identities"
        )

    if not any(locked_version == version for locked_version, _ in locked_rows):
        available = "; ".join(
            f"{locked_version} [{locked_identity}]"
            for locked_version, locked_identity in sorted(locked_rows)
        ) or "<none>"
        return (
            f"version `{version}` has no exact textual match in Cargo.lock for "
            f"crate `{name}` (locked row(s): {available}). This gate includes "
            "build metadata in waiver identity even though cargo-deny does not"
        )

    return None

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
    ("_probe@1.2.3", True),
    ("δprobe@1.2.3", True),
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
    ("@1.2.3", False),
)

for fixture, expected in SKIP_SPEC_FIXTURES:
    actual = split_skip_spec(fixture) is not None
    if actual != expected:
        print(
            "::error::internal exact-skip grammar fixture failed: "
            f"{fixture!r} expected accepted={expected}, got accepted={actual}",
            file=sys.stderr,
        )
        sys.exit(1)

# Executable lock-identity fixtures. The grammar and lockfile checks have
# different jobs: the first admits valid exact SemVer text; the second proves the
# full text names a locked package and closes cargo-deny's build-normalization
# gap. Both pass controls prevent a fail-everything implementation from looking
# strict.
FIXTURE_REGISTRY = "source=registry+https://example.invalid/index"
FIXTURE_PATH = "path/local (Cargo.lock records no source or filesystem path)"
LOCK_IDENTITY_FIXTURES = (
    (
        "exact locked build",
        "serde_yaml@0.9.34+deprecated",
        (("serde_yaml", "0.9.34+deprecated", FIXTURE_REGISTRY),),
        None,
    ),
    (
        "stale build",
        "serde_yaml@0.9.34+stale",
        (("serde_yaml", "0.9.34+deprecated", FIXTURE_REGISTRY),),
        ("has no exact textual match",),
    ),
    (
        "missing build text",
        "serde_yaml@0.9.34",
        (("serde_yaml", "0.9.34+deprecated", FIXTURE_REGISTRY),),
        ("has no exact textual match",),
    ),
    (
        "ambiguous build",
        "fixture@1.2.3+build.7",
        (
            ("fixture", "1.2.3+build.7", FIXTURE_REGISTRY),
            ("fixture", "1.2.3+build.8", FIXTURE_PATH),
        ),
        ("is ambiguous", FIXTURE_REGISTRY, FIXTURE_PATH),
    ),
    (
        "same version from registry and path",
        "fixture@1.2.3",
        (
            ("fixture", "1.2.3", FIXTURE_REGISTRY),
            ("fixture", "1.2.3", FIXTURE_PATH),
        ),
        ("is ambiguous", FIXTURE_REGISTRY, FIXTURE_PATH),
    ),
    (
        "stable selector beside build variant",
        "fixture@1.2.3",
        (
            ("fixture", "1.2.3", FIXTURE_REGISTRY),
            ("fixture", "1.2.3+local", FIXTURE_PATH),
        ),
        ("is ambiguous", "1.2.3+local", FIXTURE_REGISTRY, FIXTURE_PATH),
    ),
    (
        "stale combined prerelease and build",
        "fixture@1.2.3-alpha.1+build.8",
        (("fixture", "1.2.3-alpha.1+build.7", FIXTURE_REGISTRY),),
        ("has no exact textual match",),
    ),
    (
        "exact locked stable",
        "fixture@1.2.3",
        (("fixture", "1.2.3", FIXTURE_REGISTRY),),
        None,
    ),
    (
        "exact locked prerelease",
        "fixture@1.2.3-alpha.1",
        (("fixture", "1.2.3-alpha.1", FIXTURE_REGISTRY),),
        None,
    ),
    (
        "leading underscore Cargo name",
        "_probe@1.2.3",
        (("_probe", "1.2.3", FIXTURE_PATH),),
        None,
    ),
    (
        "Unicode XID Cargo name",
        "δprobe@1.2.3",
        (("δprobe", "1.2.3", FIXTURE_PATH),),
        None,
    ),
    (
        "name absent from lock",
        "missing@1.2.3",
        (("other", "1.2.3", FIXTURE_REGISTRY),),
        ("locked row(s): <none>",),
    ),
    (
        "at sign remains subject to authoritative lock name",
        "not@a@1.2.3",
        (("not-a", "1.2.3", FIXTURE_REGISTRY),),
        ("locked row(s): <none>",),
    ),
    (
        "empty name is rejected before lock matching",
        "@1.2.3",
        (("fixture", "1.2.3", FIXTURE_REGISTRY),),
        ("invalid skip spec",),
    ),
)

for label, spec, fixture_packages, expected_parts in LOCK_IDENTITY_FIXTURES:
    try:
        actual_problem = locked_skip_problem(spec, fixture_packages)
    except ValueError as exc:
        actual_problem = str(exc)
    if expected_parts is None:
        fixture_ok = actual_problem is None
    else:
        fixture_ok = actual_problem is not None and all(
            part in actual_problem for part in expected_parts
        )
    if not fixture_ok:
        print(
            "::error::internal skip lock-identity fixture failed: "
            f"{label!r} expected parts={expected_parts!r}, "
            f"got {actual_problem!r}",
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

try:
    lock_raw = lock_path.read_text(encoding="utf-8")
except OSError as exc:
    print(f"::error::cannot read {lock_path}: {exc}", file=sys.stderr)
    sys.exit(1)

try:
    lock_config = tomllib.loads(lock_raw)
except tomllib.TOMLDecodeError as exc:
    print(f"::error::{lock_path} does not parse as TOML: {exc}", file=sys.stderr)
    sys.exit(1)

lock_entries = lock_config.get("package")
if not isinstance(lock_entries, list) or not lock_entries:
    print(
        "::error::Cargo.lock has no non-empty `package` array; duplicate waiver "
        "versions cannot be checked against the resolved inventory",
        file=sys.stderr,
    )
    sys.exit(1)

locked_packages = []
lock_inventory_valid = True
for index, entry in enumerate(lock_entries):
    where = f"Cargo.lock package[{index}]"
    if not isinstance(entry, dict):
        problem(where, "must be a package table")
        lock_inventory_valid = False
        continue
    name = entry.get("name")
    version = entry.get("version")
    if not isinstance(name, str) or not name:
        problem(where, "has no string `name`")
        lock_inventory_valid = False
        continue
    if not isinstance(version, str) or not version:
        problem(where, "has no string `version`")
        lock_inventory_valid = False
        continue
    source = entry.get("source")
    if source is None:
        identity = "path/local (Cargo.lock records no source or filesystem path)"
    elif not isinstance(source, str) or not source:
        problem(where, "has a non-string or empty `source`")
        lock_inventory_valid = False
        continue
    else:
        identity = f"source={source}"
    locked_packages.append((name, version, identity))

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
    spec_parts = split_skip_spec(spec)
    if spec_parts is None:
        problem(
            where,
            "`crate` must end in `@<SemVer 2.0>` with a non-empty package name "
            "before the final `@`; valid prerelease and build metadata are "
            "accepted, while wildcard, range, operator, partial, and invalid "
            "SemVer requirements are forbidden. Cargo.lock exact-name matching "
            "is authoritative for which package names are valid",
        )
    elif lock_inventory_valid:
        lock_problem = locked_skip_problem(spec, locked_packages)
        if lock_problem is not None:
            problem(where, lock_problem)
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
    f"exception policy fixtures ok: {len(SKIP_SPEC_FIXTURES)} SemVer grammar, "
    f"{len(LOCK_IDENTITY_FIXTURES)} lock identity"
)
print(
    f"exception policy ok: {len(ignores)} advisory exception(s), "
    f"{len(skips)} duplicate waiver(s), "
    f"{len(locked_packages)} locked package(s) checked, "
    f"{len(surfaces)} enforcement surface(s) scanned for advisory ids"
)
for entry in ignores:
    reason = entry["reason"]
    expires = datetime.date.fromisoformat(
        re.search(r"expires ([0-9]{4}-[0-9]{2}-[0-9]{2})", reason).group(1)
    )
    print(f"  {entry['id']}: expires {expires} ({(expires - TODAY).days} day(s) left)")
PY

# The metadata stage above has already proved each skip's full version text exists
# in Cargo.lock. `bans` now owns applicability in its feature/target graph: a new
# duplicate fails normally, while the three `-D` flags make stale advisory ignores,
# lock-present skips unmatched in this graph, and no-longer-duplicate skips fail.
# See the header for the measured ownership boundary.
deny_status=0
if cargo deny --locked check \
  -D advisory-not-detected -D unmatched-skip -D unnecessary-skip \
  advisories licenses bans sources; then
  deny_status=0
else
  deny_status=$?
fi
if ! cmp -s "$WORK_DIR/repository-lock-baseline" "$ROOT_DIR/Cargo.lock"; then
  echo "::error::cargo-deny changed Cargo.lock despite --locked" >&2
  exit 1
fi
if [ "$deny_status" -ne 0 ]; then
  exit "$deny_status"
fi

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

audit_args=(--deny warnings "${audit_flags[@]}")
if [ "$audit_ignore_count" -eq 0 ]; then
  echo "cargo audit: no advisory exceptions in deny.toml"
else
  echo "cargo audit: $audit_ignore_count advisory exception(s) derived from deny.toml"
fi

audit_status=0
if cargo audit "${audit_args[@]}"; then
  audit_status=0
else
  audit_status=$?
fi
if ! cmp -s "$WORK_DIR/repository-lock-baseline" "$ROOT_DIR/Cargo.lock"; then
  echo "::error::cargo-audit changed Cargo.lock; it has no locked mode" >&2
  exit 1
fi
if [ "$audit_status" -ne 0 ]; then
  exit "$audit_status"
fi

# Scan the independently locked executable helper as its own dependency graph.
# Its config contains no exceptions, so an advisory or duplicate tolerated for
# the product graph cannot silently become part of the verifier's TCB.
helper_deny_status=0
if cargo deny \
  --manifest-path "$ASSURANCE_HELPER_MANIFEST" \
  --locked \
  check --config "$ASSURANCE_HELPER_DENY" \
  -D advisory-not-detected -D unmatched-skip -D unnecessary-skip \
  advisories licenses bans sources; then
  helper_deny_status=0
else
  helper_deny_status=$?
fi
if ! cmp -s "$WORK_DIR/assurance-helper-lock-baseline" "$ASSURANCE_HELPER_LOCK"; then
  echo "::error::cargo-deny changed the negative-registry helper Cargo.lock" >&2
  exit 1
fi
if [ "$helper_deny_status" -ne 0 ]; then
  exit "$helper_deny_status"
fi

helper_audit_status=0
if cargo audit --deny warnings --file "$ASSURANCE_HELPER_LOCK"; then
  helper_audit_status=0
else
  helper_audit_status=$?
fi
if ! cmp -s "$WORK_DIR/assurance-helper-lock-baseline" "$ASSURANCE_HELPER_LOCK"; then
  echo "::error::cargo-audit changed the negative-registry helper Cargo.lock" >&2
  exit 1
fi
if [ "$helper_audit_status" -ne 0 ]; then
  exit "$helper_audit_status"
fi
echo "negative-registry helper supply chain ok: locked, zero-waiver graph"
