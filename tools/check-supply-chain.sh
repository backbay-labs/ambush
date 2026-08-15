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
#   ~/.cargo/bin could put an attacker-controlled cargo-deny, cargo-audit, or
#   cargo-cyclonedx ahead of the toolchain. A planted executable can print the
#   pinned version and then false-green a scan or emit a false release SBOM.
#   Cargo's .crates.toml and .crates2.json install records are excluded with the
#   binaries; every cache in every tracked workflow retains only downloaded
#   registry and git sources. Every key and restore prefix uses the rotated
#   cargo-home-sources-v1 namespace, because changing only `path:` would not stop
#   a legacy cache archive from extracting the paths it recorded when created.
#   CI and release rebuild all three exact tools unconditionally with
#   `cargo install --locked --force`. The release's validation jobs also inherit
#   only `contents: read`; write permissions exist solely on the two jobs that
#   publish. This gate checks that whole contract plus mutations for every bypass.
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
REQUIRED_CARGO_CYCLONEDX_VERSION="0.5.9"

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
# asks git for every tracked workflow and local action manifest through its
# NUL-delimited interface rather than trusting quoted, line-delimited path output
# or maintaining another file list. Non-UTF-8 path bytes fail closed. Ruby/Psych
# parses the YAML with aliases disabled and rejects duplicate mapping keys from
# the syntax tree before safe_load can apply its last-key-wins behavior. Every
# cache-family use must be a source-only Cargo cache; split restore/save actions
# and composite-action caches are refused.
# Release jobs are held to their exact least-privilege token and tool-install
# contracts. The mutations make every negative branch executable.
python3 - "$ROOT_DIR" "$REQUIRED_CARGO_CYCLONEDX_VERSION" <<'PY'
import json
import pathlib
import re
import subprocess
import sys
import tempfile

root = pathlib.Path(sys.argv[1])
cyclonedx_version = sys.argv[2]


def escape_log_text(value: object) -> str:
    """Render untrusted text as one ASCII-only JSON string literal."""
    return json.dumps(str(value), ensure_ascii=True)


def escape_log_problems(problems: list[str]) -> str:
    return "[" + ", ".join(escape_log_text(problem) for problem in problems) + "]"


def git_tracked_utf8_paths(repository: pathlib.Path) -> list[str]:
    process = subprocess.run(
        ["git", "-C", str(repository), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        stderr = process.stderr.decode("utf-8", errors="backslashreplace").strip()
        raise SystemExit(
            "NUL-delimited git tracked-file inventory failed for "
            f"{escape_log_text(repository)}: exit={process.returncode}, "
            f"stderr={escape_log_text(stderr)}"
        )
    payload = process.stdout
    if payload and not payload.endswith(b"\0"):
        raise SystemExit(
            "NUL-delimited git tracked-file inventory was unterminated for "
            f"{escape_log_text(repository)}"
        )
    raw_paths = payload[:-1].split(b"\0") if payload else []
    paths: list[str] = []
    for raw_path in raw_paths:
        if not raw_path:
            raise SystemExit(
                "NUL-delimited git tracked-file inventory contained an empty path for "
                f"{escape_log_text(repository)}"
            )
        try:
            path = raw_path.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SystemExit(
                "tracked filename is not valid UTF-8; refusing a surrogate-escaped "
                f"workflow/action inventory entry {raw_path!r}: {exc}"
            ) from exc
        paths.append(path)
    return paths


def load_contract_inventory(
    repository: pathlib.Path,
) -> tuple[list[str], dict[str, str], list[str], dict[str, str]]:
    tracked_paths = git_tracked_utf8_paths(repository)
    discovered_workflows = sorted(
        name
        for name in tracked_paths
        if pathlib.PurePosixPath(name).parent
        == pathlib.PurePosixPath(".github/workflows")
        and pathlib.PurePosixPath(name).suffix in {".yml", ".yaml"}
    )
    discovered_actions = sorted(
        name
        for name in tracked_paths
        if pathlib.PurePosixPath(name).name in {"action.yml", "action.yaml"}
    )
    try:
        discovered_workflow_text = {
            name: (repository / name).read_text(encoding="utf-8")
            for name in discovered_workflows
        }
        discovered_action_text = {
            name: (repository / name).read_text(encoding="utf-8")
            for name in discovered_actions
        }
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit(
            "cannot read tracked workflow/action inventory as UTF-8 in "
            f"{escape_log_text(repository)}: {escape_log_text(exc)}"
        ) from exc
    return (
        discovered_workflows,
        discovered_workflow_text,
        discovered_actions,
        discovered_action_text,
    )


workflow_names, workflows, action_names, action_manifests = load_contract_inventory(root)
if not workflow_names:
    raise SystemExit("git reported no tracked .github/workflows/*.yml or *.yaml files")

ci_name = ".github/workflows/ci.yml"
release_name = ".github/workflows/release.yml"
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
cyclonedx_install = f"""      - name: Install cargo-cyclonedx
        run: |
          CYCLONEDX_INSTALL_ROOT="${{RUNNER_TEMP}}/cargo-cyclonedx-${{CARGO_CYCLONEDX_VERSION}}"
          cargo install cargo-cyclonedx --version "${{CARGO_CYCLONEDX_VERSION}}" --locked --force --root "${{CYCLONEDX_INSTALL_ROOT}}"
          CARGO_CYCLONEDX_BIN="${{CYCLONEDX_INSTALL_ROOT}}/bin/cargo-cyclonedx"
          test "$("${{CARGO_CYCLONEDX_BIN}}" cyclonedx --version)" = "cargo-cyclonedx-cyclonedx ${{CARGO_CYCLONEDX_VERSION}}"
          printf 'CARGO_CYCLONEDX_BIN=%s\\n' "${{CARGO_CYCLONEDX_BIN}}" >>"${{GITHUB_ENV}}"
"""
cyclonedx_pin = f'  CARGO_CYCLONEDX_VERSION: "{cyclonedx_version}"\n'
top_permissions = """permissions:
  contents: read
"""
publish_permissions = """    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
"""
github_release_permissions = """    permissions:
      contents: write
"""

RUBY_CACHE_VALIDATOR = r'''
require "json"
require "yaml"

unless YAML.respond_to?(:safe_load) && Psych.respond_to?(:parse_stream) && defined?(Psych::Nodes::Mapping)
  abort "ruby bootstrap lacks YAML.safe_load, Psych.parse_stream, or Psych node APIs"
end

payload = JSON.parse(STDIN.read)
documents = payload.fetch("workflows")
action_documents = payload.fetch("actions")
allowed_paths = [
  "~/.cargo/registry/index",
  "~/.cargo/registry/cache",
  "~/.cargo/git/db",
  "~/.cargo/git/checkouts",
]
namespace = "cargo-home-sources-v1-"
expected_counts = {
  ".github/workflows/ci.yml" => 12,
  ".github/workflows/release.yml" => 2,
}
recognized = [
  "actions/cache",
  "actions/cache/restore",
  "actions/cache/save",
]
problems = []
combined_total = 0
composite_cache_total = 0

parse_document = lambda do |source, name, kind|
  begin
    syntax_tree = Psych.parse_stream(source)
    duplicate_problems = []
    walk = nil
    walk = lambda do |node, path|
      if node.respond_to?(:tag) && !node.tag.nil? && !node.tag.empty?
        duplicate_problems << "#{name}: #{kind} YAML custom tag #{node.tag.inspect} is forbidden at #{path}"
      end
      if node.is_a?(Psych::Nodes::Mapping)
        seen = {}
        node.children.each_slice(2).with_index do |pair, index|
          key, value = pair
          if key.is_a?(Psych::Nodes::Scalar)
            identity = key.value
            if seen.key?(identity)
              duplicate_problems << "#{name}: #{kind} YAML duplicate mapping key #{identity.inspect} at #{path}"
            else
              seen[identity] = index
            end
            child_path = "#{path}.#{identity}"
          else
            duplicate_problems << "#{name}: #{kind} YAML mapping key at #{path}[#{index}] must be scalar"
            child_path = "#{path}[#{index}]"
          end
          walk.call(key, "#{path}.<key>")
          walk.call(value, child_path)
        end
      elsif node.respond_to?(:children) && node.children.is_a?(Array)
        node.children.each_with_index do |child, index|
          walk.call(child, "#{path}[#{index}]")
        end
      end
    end
    walk.call(syntax_tree, "$")
    unless duplicate_problems.empty?
      problems.concat(duplicate_problems)
      next nil
    end
    YAML.safe_load(source, aliases: false)
  rescue StandardError => error
    problems << "#{name}: #{kind} YAML parse failed with aliases disabled: #{error.class}: #{error.message}"
    nil
  end
end

validate_cache_steps = lambda do |name, context, steps|
  combined_count = 0
  steps.each_with_index do |step, index|
    next unless step.is_a?(Hash)
    raw_uses = step["uses"]
    next unless raw_uses.is_a?(String)
    normalized_uses = raw_uses.strip.downcase
    pieces = normalized_uses.split("@", -1)
    action_identity = pieces.first
    next unless recognized.include?(action_identity)
    label = "#{name}: #{context}.steps[#{index}] #{normalized_uses.inspect}"
    if pieces.length != 2 || pieces.last.empty?
      problems << "#{label}: cache action must contain exactly one non-empty @ reference"
      next
    end
    reference = pieces.last
    if reference != "v4"
      problems << "#{label}: cache action must use exact @v4"
    end
    if action_identity == "actions/cache"
      combined_count += 1
    else
      problems << "#{label}: split cache restore/save actions are forbidden; use actions/cache@v4"
    end

    inputs = step["with"]
    unless inputs.is_a?(Hash)
      problems << "#{label}: with must be an object"
      next
    end
    actual_keys = inputs.keys.map(&:to_s).sort
    expected_keys = if action_identity == "actions/cache/save"
      ["key", "path"]
    else
      ["key", "path", "restore-keys"]
    end
    if actual_keys != expected_keys
      problems << "#{label}: with keys must be exactly #{expected_keys.inspect}, got #{actual_keys.inspect}"
    end

    path_value = inputs["path"]
    if path_value.is_a?(String)
      paths = path_value.lines.map(&:strip).reject(&:empty?).map { |path| path.sub(%r{/+\z}, "") }
      if paths != allowed_paths
        problems << "#{label}: normalized paths must be exactly #{allowed_paths.inspect}, got #{paths.inspect}"
      end
    else
      problems << "#{label}: path must be a scalar string"
    end

    key = inputs["key"]
    unless key.is_a?(String) && key.start_with?(namespace)
      problems << "#{label}: key must be a scalar beginning #{namespace.inspect}"
    end
    unless action_identity == "actions/cache/save"
      restore_value = inputs["restore-keys"]
      if restore_value.is_a?(String)
        restore_keys = restore_value.lines.map(&:strip).reject(&:empty?)
        unless restore_keys.length == 1 && restore_keys.first.start_with?(namespace)
          problems << "#{label}: restore-keys must contain exactly one #{namespace.inspect} prefix"
        end
      else
        problems << "#{label}: restore-keys must be a scalar string"
      end
    end
  end
  combined_count
end

documents.keys.sort.each do |name|
  workflow = parse_document.call(documents.fetch(name), name, "workflow")
  next if workflow.nil?
  unless workflow.is_a?(Hash)
    problems << "#{name}: workflow YAML root must be an object"
    next
  end
  jobs = workflow["jobs"]
  unless jobs.is_a?(Hash)
    problems << "#{name}: workflow jobs must be an object"
    next
  end

  combined_count = 0
  jobs.each do |job_name, job|
    next unless job.is_a?(Hash)
    steps = job["steps"]
    next unless steps.is_a?(Array)
    combined_count += validate_cache_steps.call(name, "jobs.#{job_name}", steps)
  end
  combined_total += combined_count

  expected = expected_counts.fetch(name, 0)
  if combined_count != expected
    problems << "#{name}: expected #{expected} committed actions/cache@v4 step(s), found #{combined_count}"
  end
end

action_documents.keys.sort.each do |name|
  action = parse_document.call(action_documents.fetch(name), name, "action")
  next if action.nil?
  unless action.is_a?(Hash)
    problems << "#{name}: action YAML root must be an object"
    next
  end
  runs = action["runs"]
  next unless runs.is_a?(Hash) && runs["using"].to_s.strip.downcase == "composite"
  steps = runs["steps"]
  unless steps.is_a?(Array)
    problems << "#{name}: composite action runs.steps must be an array"
    next
  end
  count = validate_cache_steps.call(name, "runs", steps)
  composite_cache_total += count
  combined_total += count
end

if combined_total != 14
  problems << "tracked workflow inventory must contain exactly 14 actions/cache@v4 steps, found #{combined_total}"
end
if composite_cache_total != 0
  problems << "tracked composite actions must contain zero actions/cache@v4 steps, found #{composite_cache_total}"
end

STDOUT.write(JSON.generate({
  "problems" => problems,
  "ruby_version" => RUBY_VERSION,
  "psych_version" => Psych::VERSION,
}))
'''


def structural_cache_problems(
    documents: dict[str, str], actions: dict[str, str]
) -> tuple[list[str], str]:
    process = subprocess.run(
        ["ruby", "-e", RUBY_CACHE_VALIDATOR],
        input=json.dumps({"workflows": documents, "actions": actions}),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        raise SystemExit(
            "Ruby workflow cache validator failed closed: "
            f"exit={process.returncode}, stderr={escape_log_text(process.stderr.strip())}"
        )
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Ruby workflow cache validator returned invalid JSON: {exc}")
    if not isinstance(result, dict):
        raise SystemExit("Ruby workflow cache validator returned a non-object result")
    problems = result.get("problems")
    ruby_version = result.get("ruby_version")
    psych_version = result.get("psych_version")
    if not isinstance(problems, list) or not all(
        isinstance(problem, str) for problem in problems
    ):
        raise SystemExit("Ruby workflow cache validator returned a non-string problem list")
    if not isinstance(ruby_version, str) or not isinstance(psych_version, str):
        raise SystemExit("Ruby workflow cache validator omitted runtime bootstrap versions")
    return problems, f"ruby {ruby_version} / psych {psych_version}"


def job_body(text: str, job: str) -> str | None:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    return None if match is None else match.group("body")


def permission_blocks(body: str) -> list[str]:
    return re.findall(r"(?m)^    permissions:\n(?:      \S.*\n)+", body)


def workflow_contract_problems(
    documents: dict[str, str],
    actions: dict[str, str] = action_manifests,
    expected_workflow_names: list[str] = workflow_names,
    expected_action_names: list[str] = action_names,
) -> list[str]:
    problems: list[str] = []
    if sorted(documents) != expected_workflow_names:
        problems.append("validator input no longer equals git's tracked workflow inventory")
    if sorted(actions) != expected_action_names:
        problems.append("validator input no longer equals git's tracked action-manifest inventory")
    cache_problems, _ = structural_cache_problems(documents, actions)
    problems.extend(cache_problems)

    ci = documents.get(ci_name, "")
    supply_job = job_body(ci, "supply-chain")
    if supply_job is None:
        problems.append(f"{ci_name}: workflow has no parseable supply-chain job")
        supply_job = ""
    if supply_job.count(deny_install) != 1:
        problems.append(
            f"{ci_name}: cargo-deny must be installed exactly once, unconditionally, "
            "with --locked --force"
        )
    if supply_job.count(audit_install) != 1:
        problems.append(
            f"{ci_name}: cargo-audit must be installed exactly once, unconditionally, "
            "with --locked --force"
        )

    release = documents.get(release_name, "")
    sbom_job = job_body(release, "sbom")
    if sbom_job is None:
        problems.append(f"{release_name}: workflow has no parseable sbom job")
        sbom_job = ""
    if release.count(cyclonedx_pin) != 1:
        problems.append(
            f"{release_name}: cargo-cyclonedx pin must be exactly {cyclonedx_version}"
        )
    if sbom_job.count(cyclonedx_install) != 1:
        problems.append(
            f"{release_name}: cargo-cyclonedx must be installed exactly once, "
            "unconditionally, with --locked --force and exact version verification"
        )

    permission_count = len(re.findall(r"(?m)^ *permissions:$", release))
    if release.count(top_permissions) != 1 or permission_count != 3:
        problems.append(
            f"{release_name}: top-level permissions must be exactly contents: read "
            "with exactly two job overrides"
        )
    publish_job = job_body(release, "publish-container") or ""
    if permission_blocks(publish_job) != [publish_permissions]:
        problems.append(
            f"{release_name}: publish-container permissions must be exactly "
            "contents:read, packages:write, id-token:write, attestations:write"
        )
    github_release_job = job_body(release, "github-release") or ""
    if permission_blocks(github_release_job) != [github_release_permissions]:
        problems.append(
            f"{release_name}: github-release permissions must be exactly contents:write"
        )

    return problems


def replaced(
    documents: dict[str, str], name: str, old: str, new: str, label: str
) -> dict[str, str]:
    text = documents[name]
    mutated = text.replace(old, new, 1)
    if mutated == text:
        raise SystemExit(f"could not construct {label}")
    result = dict(documents)
    result[name] = mutated
    return result


def replaced_last(
    documents: dict[str, str], name: str, old: str, new: str, label: str
) -> dict[str, str]:
    text = documents[name]
    pieces = text.rsplit(old, 1)
    if len(pieces) != 2:
        raise SystemExit(f"could not construct {label}")
    result = dict(documents)
    result[name] = new.join(pieces)
    return result


def require_valid(
    label: str,
    documents: dict[str, str],
    actions: dict[str, str] = action_manifests,
) -> None:
    problems = workflow_contract_problems(documents, actions)
    if problems:
        raise SystemExit(
            f"{escape_log_text(label)} unexpectedly failed: "
            f"{escape_log_problems(problems)}"
        )


def require_invalid(
    label: str,
    documents: dict[str, str],
    expected: list[str],
    actions: dict[str, str] = action_manifests,
) -> None:
    problems = workflow_contract_problems(documents, actions)
    missing = [item for item in expected if not any(item in problem for problem in problems)]
    if missing:
        rendered = escape_log_problems(problems)
        raise SystemExit(
            f"{escape_log_text(label)} unexpectedly passed or failed vacuously; "
            f"missing {escape_log_problems(missing)}: {rendered}"
        )
    matched = [problem for problem in problems if any(item in problem for item in expected)]
    print(
        "workflow mutation refused: "
        f"{escape_log_text(label)}: {escape_log_problems(matched)}"
    )


require_valid("checked-in workflows and action manifests", workflows)
_, parser_bootstrap = structural_cache_problems(workflows, action_manifests)

for extension in ("yml", "yaml"):
    extension_mutation = dict(workflows)
    synthetic_name = f".github/workflows/ignored-cache.{extension}"
    extension_mutation[synthetic_name] = """name: ignored
jobs:
  ignored:
    steps:
      - name: Renamed cache step
        uses: "actions/cache@v4"
        with:
          path: |
            ~/.cargo/bin
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            ~/.cargo/git/checkouts/
          key: cargo-home-sources-v1-ignored
          restore-keys: |
            cargo-home-sources-v1-
"""
    require_invalid(
        f"tracked .{extension} quoted/renamed/no-slash cache mutation",
        extension_mutation,
        [f"{synthetic_name}: jobs.ignored.steps[0]", "normalized paths must be exactly"],
    )

    split_mutation = dict(workflows)
    split_name = f".github/workflows/split-cache.{extension}"
    split_mutation[split_name] = """name: split
jobs:
  split:
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: |
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            ~/.cargo/git/checkouts/
          key: cargo-home-sources-v1-split
          restore-keys: |
            cargo-home-sources-v1-
      - uses: "actions/cache/save@v4"
        with:
          path: |
            ~/.cargo/registry/index/
            ~/.cargo/registry/cache/
            ~/.cargo/git/db/
            ~/.cargo/git/checkouts/
          key: cargo-home-sources-v1-split
"""
    require_invalid(
        f"tracked .{extension} split restore/save cache mutation",
        split_mutation,
        [
            "actions/cache/restore@v4",
            "actions/cache/save@v4",
            "split cache restore/save actions are forbidden",
        ],
    )

newline_action_name = ".github/actions/hidden\n::error::forged\t\x1bcontrol/action.yml"
newline_action_invocation = """
      - name: Invoke newline-path composite mutation
        uses: "./.github/actions/hidden\\n::error::forged\\t\\u001bcontrol"
"""
newline_action_text = """name: newline cache probe
description: exercises byte-safe tracked-file discovery
runs:
  using: composite
  steps:
    - name: Renamed composite restore
      uses: "actions/cache/restore@v4"
      with:
        path: |
          ~/.cargo/bin
          ~/.cargo/registry/index/
          ~/.cargo/registry/cache/
          ~/.cargo/git/db/
          ~/.cargo/git/checkouts/
        key: cargo-home-sources-v1-newline
        restore-keys: |
          cargo-home-sources-v1-
"""
with tempfile.TemporaryDirectory(prefix="supply-newline-action-") as fixture_directory:
    fixture_root = pathlib.Path(fixture_directory)
    fixture_documents = dict(workflows)
    fixture_ci = fixture_documents[ci_name]
    mutated_ci = fixture_ci.replace(
        audit_install,
        audit_install + newline_action_invocation,
        1,
    )
    if mutated_ci == fixture_ci:
        raise SystemExit(
            "could not place newline-path composite invocation after forced tool installs"
        )
    fixture_documents[ci_name] = mutated_ci
    for name, text in {**fixture_documents, **action_manifests}.items():
        destination = fixture_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    newline_action_path = fixture_root / newline_action_name
    newline_action_path.parent.mkdir(parents=True, exist_ok=True)
    newline_action_path.write_text(newline_action_text, encoding="utf-8")
    for git_arguments in (("init", "-q"), ("add", "--all")):
        git_process = subprocess.run(
            ["git", "-C", str(fixture_root), *git_arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if git_process.returncode != 0:
            stderr = git_process.stderr.decode(
                "utf-8", errors="backslashreplace"
            ).strip()
            raise SystemExit(
                f"newline-path fixture git {' '.join(git_arguments)} failed: "
                f"exit={git_process.returncode}, stderr={escape_log_text(stderr)}"
            )
    (
        fixture_workflow_names,
        fixture_workflows,
        fixture_action_names,
        fixture_actions,
    ) = load_contract_inventory(fixture_root)
    if newline_action_name not in fixture_action_names:
        raise SystemExit(
            "NUL-delimited fixture inventory omitted the tracked newline-path action"
        )
    invocation_offset = fixture_workflows[ci_name].find(newline_action_invocation)
    forced_install_offset = fixture_workflows[ci_name].find(audit_install)
    if invocation_offset <= forced_install_offset:
        raise SystemExit(
            "newline-path action fixture is not invoked after both forced tool installs"
        )
    newline_problems = workflow_contract_problems(
        fixture_workflows,
        fixture_actions,
        fixture_workflow_names,
        fixture_action_names,
    )
    newline_expected = [
        f"{newline_action_name}: runs.steps[0]",
        "split cache restore/save actions are forbidden",
        "normalized paths must be exactly",
    ]
    newline_missing = [
        item
        for item in newline_expected
        if not any(item in problem for problem in newline_problems)
    ]
    if newline_missing:
        rendered = escape_log_problems(newline_problems)
        raise SystemExit(
            "real git newline-path composite fixture passed or failed vacuously; "
            f"missing {escape_log_problems(newline_missing)}: {rendered}"
        )
    newline_matched = [
        problem
        for problem in newline_problems
        if any(item in problem for item in newline_expected)
    ]
    escaped_newline_problems = escape_log_problems(newline_matched)
    expected_escapes = (r"\n::error::forged\t\u001bcontrol",)
    raw_controls = ("\n", "\r", "\t", "\x1b")
    if any(control in escaped_newline_problems for control in raw_controls):
        raise SystemExit(
            "hostile-path diagnostic escaping retained a raw newline, tab, or ESC byte"
        )
    if not all(expected in escaped_newline_problems for expected in expected_escapes):
        raise SystemExit(
            "hostile-path diagnostic escaping omitted the expected JSON escapes: "
            + escape_log_text(escaped_newline_problems)
        )
    print(
        "workflow mutation refused: real git hostile-path composite invoked after "
        f"forced installs: {escaped_newline_problems}"
    )

cache_workflows = [ci_name, release_name]
for name in cache_workflows:
    for forbidden in (*forbidden_paths, "~/.cargo/bin"):
        mutated = replaced(
            workflows,
            name,
            "            ~/.cargo/registry/index/\n",
            f"            {forbidden}\n            ~/.cargo/registry/index/\n",
            f"{name} forbidden-path mutation {forbidden}",
        )
        require_invalid(
            f"{name} forbidden-path mutation {forbidden}",
            mutated,
            [f"{name}: jobs.", "normalized paths must be exactly"],
        )

    legacy_key = replaced(
        workflows, name, namespace, "cargo-home-", f"{name} legacy cache-key mutation"
    )
    require_invalid(
        f"{name} legacy cache-key mutation",
        legacy_key,
        ["key must be a scalar beginning"],
    )

    legacy_restore = replaced(
        workflows,
        name,
        f"            {namespace}",
        "            cargo-home-",
        f"{name} legacy restore-prefix mutation",
    )
    require_invalid(
        f"{name} legacy restore-prefix mutation",
        legacy_restore,
        ["restore-keys must contain exactly one"],
    )

    target_cache = replaced(
        workflows,
        name,
        "            ~/.cargo/registry/index/\n",
        "            target/ci\n            ~/.cargo/registry/index/\n",
        f"{name} target-cache mutation",
    )
    require_invalid(
        f"{name} target-cache mutation",
        target_cache,
        ["normalized paths must be exactly"],
    )

    renamed_cache = replaced(
        workflows,
        name,
        "      - name: Cache cargo home\n",
        "      - name: Cache build tools\n",
        f"{name} renamed cache control",
    )
    require_valid(f"{name} renamed cache control", renamed_cache)

    quoted_cache = replaced(
        workflows,
        name,
        "        uses: actions/cache@v4\n",
        '        uses: "actions/cache@v4"\n',
        f"{name} quoted cache control",
    )
    require_valid(f"{name} quoted cache control", quoted_cache)

    capitalized_cache = replaced(
        workflows,
        name,
        "        uses: actions/cache@v4\n",
        "        uses: Actions/Cache@V4\n",
        f"{name} capitalized cache control",
    )
    require_valid(f"{name} capitalized cache control", capitalized_cache)

frozen_release_bypass = replaced_last(
    workflows,
    release_name,
    "      - name: Cache cargo home\n",
    "      - name: Restore release inputs\n",
    "frozen release cache-step rename",
)
frozen_release_bypass = replaced_last(
    frozen_release_bypass,
    release_name,
    "        uses: actions/cache@v4\n",
    '        uses: "actions/cache@v4"\n',
    "frozen release quoted cache action",
)
frozen_release_bypass = replaced_last(
    frozen_release_bypass,
    release_name,
    "            ~/.cargo/registry/index/\n",
    "            ~/.cargo/bin\n            ~/.cargo/registry/index/\n",
    "frozen release no-slash binary path",
)
require_invalid(
    "frozen renamed/quoted/no-slash release cache mutation",
    frozen_release_bypass,
    [
        ".github/workflows/release.yml: jobs.release-hardening.steps[1]",
        "normalized paths must be exactly",
    ],
)

missing_committed_cache = replaced(
    workflows,
    ci_name,
    "        uses: actions/cache@v4\n",
    "        uses: actions/checkout@v4\n",
    "missing committed cache inventory mutation",
)
require_invalid(
    "missing committed cache inventory mutation",
    missing_committed_cache,
    [
        ".github/workflows/ci.yml: expected 12 committed actions/cache@v4 step(s), found 11",
        "tracked workflow inventory must contain exactly 14 actions/cache@v4 steps, found 13",
    ],
)

yaml_alias_mutation = dict(workflows)
yaml_alias_mutation[".github/workflows/cache-alias.yaml"] = """name: aliases
cache_paths: &cache_paths |
  ~/.cargo/registry/index/
jobs:
  aliases:
    steps:
      - uses: actions/cache@v4
        with:
          path: *cache_paths
          key: cargo-home-sources-v1-alias
          restore-keys: cargo-home-sources-v1-
"""
require_invalid(
    "workflow YAML alias mutation",
    yaml_alias_mutation,
    ["workflow YAML parse failed with aliases disabled", "Psych::BadAlias"],
)

yaml_parse_mutation = dict(workflows)
yaml_parse_mutation[".github/workflows/broken.yaml"] = "jobs: [unterminated\n"
require_invalid(
    "workflow YAML parse-error mutation",
    yaml_parse_mutation,
    ["workflow YAML parse failed with aliases disabled", "Psych::SyntaxError"],
)

yaml_duplicate_key_mutation = replaced(
    workflows,
    ci_name,
    "        uses: actions/cache@v4\n",
    "        uses: actions/cache@v4\n        uses: actions/checkout@v4\n",
    "workflow YAML duplicate uses-key mutation",
)
require_invalid(
    "workflow YAML duplicate uses-key mutation",
    yaml_duplicate_key_mutation,
    ["workflow YAML duplicate mapping key \"uses\""],
)

yaml_custom_tag_mutation = dict(workflows)
yaml_custom_tag_mutation[".github/workflows/cache-tag.yaml"] = """name: tag
jobs:
  tagged:
    steps:
      - uses: actions/cache@v4
        with:
          path: !forged |
            ~/.cargo/registry/index/
          key: cargo-home-sources-v1-tag
          restore-keys: cargo-home-sources-v1-
"""
require_invalid(
    "workflow YAML custom-tag mutation",
    yaml_custom_tag_mutation,
    ["workflow YAML custom tag \"!forged\" is forbidden"],
)

for tool in ("cargo-deny", "cargo-audit"):
    conditional = replaced(
        workflows,
        ci_name,
        f"      - name: Install {tool}\n        run: |\n",
        f"      - name: Install {tool}\n        if: success()\n        run: |\n",
        f"conditional {tool} install mutation",
    )
    require_invalid(
        f"conditional {tool} install mutation",
        conditional,
        [f"{tool} must be installed exactly once, unconditionally"],
    )

conditional_cyclonedx = replaced(
    workflows,
    release_name,
    "      - name: Install cargo-cyclonedx\n        run: |\n",
    "      - name: Install cargo-cyclonedx\n        if: success()\n        run: |\n",
    "conditional cargo-cyclonedx install mutation",
)
require_invalid(
    "conditional cargo-cyclonedx install mutation",
    conditional_cyclonedx,
    ["cargo-cyclonedx must be installed exactly once, unconditionally"],
)

alias_shadowed_version = replaced(
    workflows,
    release_name,
    '          test "$("${CARGO_CYCLONEDX_BIN}" cyclonedx --version)" = ',
    '          test "$(cargo cyclonedx --version)" = ',
    "cargo alias-shadowed cyclonedx version mutation",
)
require_invalid(
    "cargo alias-shadowed cyclonedx version mutation",
    alias_shadowed_version,
    ["cargo-cyclonedx must be installed exactly once, unconditionally"],
)

cyclonedx_drift = replaced(
    workflows,
    release_name,
    cyclonedx_pin,
    '  CARGO_CYCLONEDX_VERSION: "0.5.8"\n',
    "cargo-cyclonedx pin drift mutation",
)
require_invalid(
    "cargo-cyclonedx pin drift mutation",
    cyclonedx_drift,
    [f"cargo-cyclonedx pin must be exactly {cyclonedx_version}"],
)

fake_cached_release = replaced(
    workflows,
    release_name,
    "            ~/.cargo/registry/index/\n",
    "            ~/.cargo/bin/\n            ~/.cargo/registry/index/\n",
    "fake cached cargo-cyclonedx path mutation",
)
fake_cached_release = replaced(
    fake_cached_release,
    release_name,
    cyclonedx_install,
    """      - name: Install cargo-cyclonedx
        run: command -v cargo-cyclonedx >/dev/null || cargo install cargo-cyclonedx --locked
""",
    "fake cached cargo-cyclonedx conditional-trust mutation",
)
require_invalid(
    "fake cached cargo-cyclonedx false-SBOM mutation",
    fake_cached_release,
    [
        "normalized paths must be exactly",
        "cargo-cyclonedx must be installed exactly once, unconditionally",
    ],
)

permission_mutations = [
    (
        "top-level write permission mutation",
        top_permissions,
        "permissions:\n  contents: write\n",
        "top-level permissions must be exactly contents: read",
    ),
    (
        "validation-job write permission mutation",
        "  sbom:\n    runs-on: ubuntu-latest\n",
        "  sbom:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n",
        "top-level permissions must be exactly contents: read",
    ),
    (
        "publish permission removal mutation",
        "      attestations: write\n",
        "      attestations: read\n",
        "publish-container permissions must be exactly",
    ),
    (
        "github-release ambient permission mutation",
        github_release_permissions,
        "    permissions:\n      contents: write\n      packages: write\n",
        "github-release permissions must be exactly contents:write",
    ),
]
for label, old, new, expected in permission_mutations:
    mutated = replaced(workflows, release_name, old, new, label)
    require_invalid(label, mutated, [expected])

print(
    f"workflow contract fixtures ok: {len(workflow_names)} tracked workflow(s), "
    f"{len(action_names)} tracked action manifest(s), 14 structurally parsed "
    "source-only caches, zero composite caches, exact tool installs, and "
    f"least-privilege release permissions ({parser_bootstrap}; stdlib json/yaml, "
    "YAML.safe_load + Psych.parse_stream required)"
)
PY

# A cached fake or Cargo alias can report the exact reviewed version while writing
# a false release SBOM. The workflow contract prevents the cached executable; the
# generator invokes an absolute external binary and rejects a repository alias.
# A two-package locked workspace makes completeness measurable: one valid forged
# document is still a failure when the second package is absent. Additional
# parser fixtures close duplicate-key and Python-json nonstandard-number
# acceptance rather than assuming json.loads is strict by default.
SBOM_FIXTURE_WORKSPACE="$WORK_DIR/sbom-fixture-workspace"
VALID_SBOM_DIR="$WORK_DIR/valid-sbom"
mkdir -p \
  "$SBOM_FIXTURE_WORKSPACE/fixture/src" \
  "$SBOM_FIXTURE_WORKSPACE/omitted/src" \
  "$VALID_SBOM_DIR"
cat >"$SBOM_FIXTURE_WORKSPACE/Cargo.toml" <<'TOML'
[workspace]
resolver = "2"
members = ["fixture", "omitted"]
TOML
cat >"$SBOM_FIXTURE_WORKSPACE/fixture/Cargo.toml" <<'TOML'
[package]
name = "fixture"
version = "1.0.0"
edition = "2021"
TOML
cat >"$SBOM_FIXTURE_WORKSPACE/omitted/Cargo.toml" <<'TOML'
[package]
name = "omitted"
version = "2.0.0"
edition = "2021"
TOML
printf '%s\n' '' >"$SBOM_FIXTURE_WORKSPACE/fixture/src/lib.rs"
printf '%s\n' '' >"$SBOM_FIXTURE_WORKSPACE/omitted/src/lib.rs"
cat >"$SBOM_FIXTURE_WORKSPACE/Cargo.lock" <<'TOML'
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "fixture"
version = "1.0.0"

[[package]]
name = "omitted"
version = "2.0.0"
TOML

cat >"$VALID_SBOM_DIR/fixture.cdx.json" <<'JSON'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "version": 1,
  "metadata": {
    "component": {
      "type": "library",
      "bom-ref": "fixture@1.0.0",
      "name": "fixture",
      "version": "1.0.0",
      "purl": "pkg:cargo/fixture@1.0.0?download_url=file://."
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "dependency@2.0.0",
      "name": "dependency",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {"ref": "fixture@1.0.0", "dependsOn": ["dependency@2.0.0"]},
    {"ref": "dependency@2.0.0", "dependsOn": []}
  ]
}
JSON
cat >"$VALID_SBOM_DIR/omitted.cdx.json" <<'JSON'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000002",
  "version": 1,
  "metadata": {
    "component": {
      "type": "library",
      "bom-ref": "omitted@2.0.0",
      "name": "omitted",
      "version": "2.0.0",
      "purl": "pkg:cargo/omitted@2.0.0?download_url=file://."
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "dependency@2.0.0",
      "name": "dependency",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {"ref": "omitted@2.0.0", "dependsOn": ["dependency@2.0.0"]},
    {"ref": "dependency@2.0.0", "dependsOn": []}
  ]
}
JSON
if ! bash "$ROOT_DIR/tools/generate-sbom.sh" --validate-dir "$VALID_SBOM_DIR" \
  "$SBOM_FIXTURE_WORKSPACE/Cargo.toml" \
  >"$WORK_DIR/valid-sbom.stdout" 2>"$WORK_DIR/valid-sbom.stderr"; then
  sed -n '1,20p' "$WORK_DIR/valid-sbom.stderr" >&2
  echo "::error::valid CycloneDX 1.5 control was rejected" >&2
  exit 1
fi

expect_sbom_rejection() {
  local label="$1"
  local directory="$2"
  local expected="$3"
  local manifest_path="${4:-$SBOM_FIXTURE_WORKSPACE/Cargo.toml}"

  if bash "$ROOT_DIR/tools/generate-sbom.sh" --validate-dir "$directory" "$manifest_path" \
    >"$WORK_DIR/$label.stdout" 2>"$WORK_DIR/$label.stderr"; then
    echo "::error::$label SBOM mutation unexpectedly passed" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$WORK_DIR/$label.stderr"; then
    sed -n '1,20p' "$WORK_DIR/$label.stderr" >&2
    echo "::error::$label SBOM mutation failed for the wrong reason" >&2
    exit 1
  fi
  printf 'SBOM mutation refused: %s: %s\n' "$label" "$expected"
}

FAKE_CYCLONEDX_BIN="$WORK_DIR/fake-cyclonedx-bin"
FAKE_SBOM_DIR="$WORK_DIR/fake-cyclonedx-sbom"
mkdir -p "$FAKE_CYCLONEDX_BIN" "$FAKE_SBOM_DIR"
cat >"$FAKE_CYCLONEDX_BIN/cargo-cyclonedx" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "cyclonedx" ]]; then
  echo "unexpected fake cargo-cyclonedx invocation: $*" >&2
  exit 2
fi
shift
if [[ -n "${SUPPLY_CHAIN_DIRECT_MARKER:-}" ]]; then
  printf 'direct external cargo-cyclonedx invoked\n' >"$SUPPLY_CHAIN_DIRECT_MARKER"
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'cargo-cyclonedx-cyclonedx %s\n' "${SUPPLY_CHAIN_FAKE_CYCLONEDX_VERSION:?}"
  exit 0
fi
printf '{}\n' >"${SUPPLY_CHAIN_FAKE_SBOM_PATH:?}"
SH
chmod +x "$FAKE_CYCLONEDX_BIN/cargo-cyclonedx"

fake_cyclonedx_version="$(
  SUPPLY_CHAIN_FAKE_CYCLONEDX_VERSION="$REQUIRED_CARGO_CYCLONEDX_VERSION" \
    "$FAKE_CYCLONEDX_BIN/cargo-cyclonedx" cyclonedx --version
)"
if [[ "$fake_cyclonedx_version" != \
  "cargo-cyclonedx-cyclonedx $REQUIRED_CARGO_CYCLONEDX_VERSION" ]]; then
  echo "::error::fake cargo-cyclonedx did not reproduce exact-version spoof" >&2
  exit 1
fi

ALIAS_SHADOW_ROOT="$WORK_DIR/cyclonedx-alias-shadow"
mkdir -p \
  "$ALIAS_SHADOW_ROOT/.cargo" \
  "$ALIAS_SHADOW_ROOT/tools" \
  "$ALIAS_SHADOW_ROOT/alias-helper/src"
cp -R "$SBOM_FIXTURE_WORKSPACE/fixture" "$ALIAS_SHADOW_ROOT/fixture"
cp -R "$SBOM_FIXTURE_WORKSPACE/omitted" "$ALIAS_SHADOW_ROOT/omitted"
cp "$SBOM_FIXTURE_WORKSPACE/Cargo.toml" "$ALIAS_SHADOW_ROOT/Cargo.toml"
cp "$SBOM_FIXTURE_WORKSPACE/Cargo.lock" "$ALIAS_SHADOW_ROOT/Cargo.lock"
cp "$ROOT_DIR/tools/generate-sbom.sh" "$ALIAS_SHADOW_ROOT/tools/generate-sbom.sh"
cat >"$ALIAS_SHADOW_ROOT/alias-helper/Cargo.toml" <<'TOML'
[package]
name = "cyclonedx-alias-helper"
version = "0.1.0"
edition = "2021"

[workspace]
TOML
cat >"$ALIAS_SHADOW_ROOT/alias-helper/src/main.rs" <<'RS'
use std::{env, fs};

fn main() {
    if let Ok(marker) = env::var("SUPPLY_CHAIN_ALIAS_MARKER") {
        fs::write(marker, "Cargo alias invoked\n").expect("write alias marker");
    }
    if env::args().any(|arg| arg == "--version") {
        println!("cargo-cyclonedx-cyclonedx 0.5.9");
        return;
    }
    let path = env::var("SUPPLY_CHAIN_ALIAS_SBOM_PATH")
        .expect("SUPPLY_CHAIN_ALIAS_SBOM_PATH");
    fs::write(
        path,
        r#"{
          "bomFormat":"CycloneDX","specVersion":"1.5",
          "serialNumber":"urn:uuid:00000000-0000-4000-8000-000000000003","version":1,
          "metadata":{"component":{"type":"library","bom-ref":"fixture@1.0.0","name":"fixture","version":"1.0.0","purl":"pkg:cargo/fixture@1.0.0"}},
          "components":[{"type":"library","bom-ref":"dependency@1.0.0","name":"dependency","version":"1.0.0"}],
          "dependencies":[{"ref":"fixture@1.0.0","dependsOn":[]}]}
        "#,
    )
    .expect("write alias-forged SBOM");
}
RS
cat >"$ALIAS_SHADOW_ROOT/.cargo/config.toml" <<TOML
[alias]
cyclonedx = ["run", "--quiet", "--manifest-path", "$ALIAS_SHADOW_ROOT/alias-helper/Cargo.toml", "--"]
TOML

ALIAS_MARKER="$WORK_DIR/cyclonedx-alias.marker"
DIRECT_MARKER="$WORK_DIR/cyclonedx-direct.marker"
alias_version="$(
  cd "$ALIAS_SHADOW_ROOT"
  SUPPLY_CHAIN_ALIAS_MARKER="$ALIAS_MARKER" cargo cyclonedx --version
)"
if [[ "$alias_version" != \
  "cargo-cyclonedx-cyclonedx $REQUIRED_CARGO_CYCLONEDX_VERSION" || \
  ! -f "$ALIAS_MARKER" || -e "$DIRECT_MARKER" ]]; then
  echo "::error::Cargo alias shadow fixture did not invoke the forged alias" >&2
  exit 1
fi
direct_version="$(
  SUPPLY_CHAIN_DIRECT_MARKER="$DIRECT_MARKER" \
    SUPPLY_CHAIN_FAKE_CYCLONEDX_VERSION="$REQUIRED_CARGO_CYCLONEDX_VERSION" \
    "$FAKE_CYCLONEDX_BIN/cargo-cyclonedx" cyclonedx --version
)"
if [[ "$direct_version" != \
  "cargo-cyclonedx-cyclonedx $REQUIRED_CARGO_CYCLONEDX_VERSION" || \
  ! -f "$DIRECT_MARKER" ]]; then
  echo "::error::direct external cargo-cyclonedx differential control failed" >&2
  exit 1
fi

ALIAS_FORGED_SBOM_DIR="$WORK_DIR/alias-forged-sbom"
mkdir -p "$ALIAS_FORGED_SBOM_DIR"
(
  cd "$ALIAS_SHADOW_ROOT"
  SUPPLY_CHAIN_ALIAS_MARKER="$ALIAS_MARKER" \
    SUPPLY_CHAIN_ALIAS_SBOM_PATH="$ALIAS_FORGED_SBOM_DIR/fixture.cdx.json" \
    cargo cyclonedx --manifest-path Cargo.toml --format json --spec-version 1.5 --quiet
)
expect_sbom_rejection \
  "alias-forged-incomplete-inventory" "$ALIAS_FORGED_SBOM_DIR" \
  "missing=[('omitted', '2.0.0')]" "$ALIAS_SHADOW_ROOT/Cargo.toml"

if CARGO_CYCLONEDX_BIN="$FAKE_CYCLONEDX_BIN/cargo-cyclonedx" \
  CARGO_CYCLONEDX_VERSION="$REQUIRED_CARGO_CYCLONEDX_VERSION" \
  bash "$ALIAS_SHADOW_ROOT/tools/generate-sbom.sh" "$WORK_DIR/alias-generator-output" \
  >"$WORK_DIR/alias-generator.stdout" 2>"$WORK_DIR/alias-generator.stderr"; then
  echo "::error::generator accepted a repository cyclonedx Cargo alias" >&2
  exit 1
fi
if ! grep -Fq "repository Cargo alias 'cyclonedx' is forbidden" \
  "$WORK_DIR/alias-generator.stderr"; then
  sed -n '1,20p' "$WORK_DIR/alias-generator.stderr" >&2
  echo "::error::generator alias fixture failed for the wrong reason" >&2
  exit 1
fi
echo "Cargo alias fixture ok: bare cargo was shadowed; direct external binary bypassed it; generator refused it"

if ! SUPPLY_CHAIN_FAKE_CYCLONEDX_VERSION="$REQUIRED_CARGO_CYCLONEDX_VERSION" \
  SUPPLY_CHAIN_FAKE_SBOM_PATH="$FAKE_SBOM_DIR/fake.cdx.json" \
  "$FAKE_CYCLONEDX_BIN/cargo-cyclonedx" cyclonedx \
    --manifest-path Cargo.toml --format json --spec-version 1.5 --quiet; then
  echo "::error::fake cargo-cyclonedx failed before constructing false SBOM evidence" >&2
  exit 1
fi
expect_sbom_rejection \
  "fake-cyclonedx-empty-object" "$FAKE_SBOM_DIR" "bomFormat must equal 'CycloneDX'"

MISSING_INVENTORY_DIR="$WORK_DIR/missing-inventory-sbom"
DUPLICATE_IDENTITY_DIR="$WORK_DIR/duplicate-identity-sbom"
WRONG_NAME_DIR="$WORK_DIR/wrong-name-sbom"
WRONG_VERSION_DIR="$WORK_DIR/wrong-version-sbom"
WRONG_PURL_DIR="$WORK_DIR/wrong-purl-sbom"
mkdir -p \
  "$MISSING_INVENTORY_DIR" \
  "$DUPLICATE_IDENTITY_DIR" \
  "$WRONG_NAME_DIR" \
  "$WRONG_VERSION_DIR" \
  "$WRONG_PURL_DIR"
cp "$VALID_SBOM_DIR/fixture.cdx.json" "$MISSING_INVENTORY_DIR/fixture.cdx.json"
cp "$VALID_SBOM_DIR/fixture.cdx.json" "$DUPLICATE_IDENTITY_DIR/fixture.cdx.json"
cp "$VALID_SBOM_DIR/fixture.cdx.json" "$DUPLICATE_IDENTITY_DIR/omitted.cdx.json"
cp "$VALID_SBOM_DIR/fixture.cdx.json" "$WRONG_NAME_DIR/fixture.cdx.json"
cp "$VALID_SBOM_DIR/omitted.cdx.json" "$WRONG_NAME_DIR/omitted.cdx.json"
perl -0pi -e 's/"name": "omitted"/"name": "forged"/' \
  "$WRONG_NAME_DIR/omitted.cdx.json"
cp "$VALID_SBOM_DIR/fixture.cdx.json" "$WRONG_VERSION_DIR/fixture.cdx.json"
cp "$VALID_SBOM_DIR/omitted.cdx.json" "$WRONG_VERSION_DIR/omitted.cdx.json"
perl -0pi -e 's/"version": "2\.0\.0"/"version": "9.0.0"/' \
  "$WRONG_VERSION_DIR/omitted.cdx.json"
perl -0pi -e 's#pkg:cargo/omitted\@2\.0\.0#pkg:cargo/omitted\@9.0.0#' \
  "$WRONG_VERSION_DIR/omitted.cdx.json"
cp "$VALID_SBOM_DIR/fixture.cdx.json" "$WRONG_PURL_DIR/fixture.cdx.json"
cp "$VALID_SBOM_DIR/omitted.cdx.json" "$WRONG_PURL_DIR/omitted.cdx.json"
perl -0pi -e 's#pkg:cargo/omitted\@2\.0\.0#pkg:cargo/forged\@2.0.0#' \
  "$WRONG_PURL_DIR/omitted.cdx.json"
expect_sbom_rejection \
  "missing-workspace-package" "$MISSING_INVENTORY_DIR" \
  "missing=[('omitted', '2.0.0')]"
expect_sbom_rejection \
  "duplicate-metadata-component" "$DUPLICATE_IDENTITY_DIR" \
  "metadata.component package identity is duplicated"
expect_sbom_rejection \
  "wrong-package-name" "$WRONG_NAME_DIR" \
  "filename must be 'forged.cdx.json'"
expect_sbom_rejection \
  "wrong-package-version" "$WRONG_VERSION_DIR" \
  "missing=[('omitted', '2.0.0')], unexpected=[('omitted', '9.0.0')]"
expect_sbom_rejection \
  "wrong-package-purl" "$WRONG_PURL_DIR" \
  "metadata.component.purl must identify omitted@2.0.0"

DUPLICATE_SBOM_DIR="$WORK_DIR/duplicate-key-sbom"
NAN_SBOM_DIR="$WORK_DIR/nan-sbom"
INFINITY_SBOM_DIR="$WORK_DIR/infinity-sbom"
JUNK_SBOM_DIR="$WORK_DIR/junk-sbom"
mkdir -p "$DUPLICATE_SBOM_DIR" "$NAN_SBOM_DIR" "$INFINITY_SBOM_DIR" "$JUNK_SBOM_DIR"
printf '%s\n' \
  '{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}' \
  >"$DUPLICATE_SBOM_DIR/duplicate.cdx.json"
printf '%s\n' '{"bomFormat":NaN}' >"$NAN_SBOM_DIR/nan.cdx.json"
printf '%s\n' '{"bomFormat":Infinity}' >"$INFINITY_SBOM_DIR/infinity.cdx.json"
printf '%s\n' 'not-json' >"$JUNK_SBOM_DIR/junk.cdx.json"
expect_sbom_rejection \
  "duplicate-key" "$DUPLICATE_SBOM_DIR" "duplicate object key 'bomFormat'"
expect_sbom_rejection \
  "nan-constant" "$NAN_SBOM_DIR" "non-standard JSON constant NaN"
expect_sbom_rejection \
  "infinity-constant" "$INFINITY_SBOM_DIR" "non-standard JSON constant Infinity"
expect_sbom_rejection \
  "non-json-junk" "$JUNK_SBOM_DIR" "not valid UTF-8 JSON"
echo "SBOM validation fixtures ok: real shape control accepted; spoofed and malformed JSON refused"

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
while IFS= read -r -d '' path; do
  [ -n "$path" ] || continue
  surfaces+=("$path")
done < <(
  git ls-files -z -c -o --exclude-standard -- \
    '.github/workflows/*.yml' '.github/workflows/*.yaml' \
    'tools/*.sh' 'tools/negative-registry-ast/deny.toml' \
    'audit.toml' '.cargo/audit.toml' '*/audit.toml' \
    | LC_ALL=C sort -zu
)

if [ "${#surfaces[@]}" -eq 0 ]; then
  echo "no workflow or tools script found to scan; refusing to pass silently" >&2
  exit 1
fi

python3 - "$ROOT_DIR/deny.toml" "$ROOT_DIR/Cargo.lock" \
  "$WORK_DIR/advisory-ignores" "${surfaces[@]}" <<'PY'
import datetime
import json
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


def escape_log_text(value):
    """Render untrusted policy/path text as one ASCII-only JSON string literal."""
    return json.dumps(str(value), ensure_ascii=True)

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
    print(
        f"::error::{escape_log_text(f'cannot read {deny_path}: {exc}')}",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    config = tomllib.loads(raw)
except tomllib.TOMLDecodeError as exc:
    print(
        f"::error::{escape_log_text(f'{deny_path} does not parse as TOML: {exc}')}",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    lock_raw = lock_path.read_text(encoding="utf-8")
except OSError as exc:
    print(
        f"::error::{escape_log_text(f'cannot read {lock_path}: {exc}')}",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    lock_config = tomllib.loads(lock_raw)
except tomllib.TOMLDecodeError as exc:
    print(
        f"::error::{escape_log_text(f'{lock_path} does not parse as TOML: {exc}')}",
        file=sys.stderr,
    )
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
        print(f"::error::  {escape_log_text(error)}", file=sys.stderr)
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
