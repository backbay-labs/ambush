#!/usr/bin/env bash
#
# Single-governor-key gate (BFT-03, phase 321 success criterion 3).
#
# WHY THIS EXISTS
#   ROADMAP criterion 3 reads "no production path holds more than one governor
#   signing key in memory" and names no method of checking it. As written it is
#   satisfiable by assertion, which is the exact failure pattern phase 321 is
#   supposed to be repairing. This script is the third and WEAKEST of three
#   mechanisms; the other two are stronger and are named here so nobody mistakes
#   this grep for the guarantee.
#
#   MECHANISM 1 -- THE TYPE (crates/swarm-governance/src/lib.rs).
#     `GovernanceState.local_governor: Option<LocalGovernorKey>` replaced
#     `governors: BTreeMap<AgentId, SigningKey>`. `LocalGovernorKey` exposes no
#     accessor returning a `SigningKey`, so nothing downstream can clone a key
#     back out into a collection.
#     CATCHES: a second key inside `GovernanceState`, at compile time.
#     MISSES: everything outside that one struct.
#
#   MECHANISM 2 -- THE TEST (crates/swarm-agents/tests/governance_single_key.rs,
#     `a_second_distinct_governor_signing_key_is_refused`).
#     `register_governor` returns `Err(GovernanceKeyError::SecondSigningKey)`
#     for a second, different key, and `TomAgent::new_with_signing_key`
#     propagates it to the composition root.
#     CATCHES: a runtime attempt to install a second key through the public API.
#     MISSES: a key acquired any other way.
#
#   MECHANISM 3 -- THIS SCRIPT.
#     A lexical scan for a COLLECTION of `SigningKey` in the three source paths that
#     make up the governance signing path, plus a production-source inventory
#     requiring one concrete opaque `GovernanceAuthority` handle, its private
#     policy field and authenticated mint, and no trait/backend/generic installer.
#
# WHAT THIS SCRIPT COVERS
#   `crates/swarm-governance/src/`, `crates/swarm-consensus/src/` and
#   `crates/swarm-policy/src/`, outside `#[cfg(test)]` regions: no
#   `BTreeMap<.., SigningKey>`, `HashMap<.., SigningKey>`, `Vec<SigningKey>`,
#   `[SigningKey; N]` or `&[SigningKey]`.
#
#   Scoped to those three deliberately. Every other agent legitimately holds its
#   OWN key, and `crates/swarm-crypto` is a key library whose job is to handle
#   keys, so scanning wider would produce a noisy allowlist that nobody reads --
#   the way an allowlist stops being a gate.
#
# WHAT THIS SCRIPT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
#   1. A fixed set of NAMED `SigningKey` struct fields
#      (`primary: SigningKey, secondary: SigningKey`). No collection syntax.
#   2. A type alias (`type Keyring = BTreeMap<AgentId, SigningKey>;` then
#      `keys: Keyring`). The alias declaration is caught; a use of it is not.
#   3. Keys reached through a `dyn` trait object or a closure capture.
#   4. TWO `GovernancePolicy` INSTANCES in one process, each holding one key.
#      This is the largest hole and no mechanism here closes it; mechanism 1
#      makes each instance single-key, not the process.
#   5. Anything outside the three scanned paths.
#   6. Semantic behavior inside an inherent authority method. Runtime negative
#      differentials and governance persistence tests cover those decisions.
#
#   1-3 are lexical blind spots. 4 is architectural and is recorded in
#   .planning/STATE.md as open.
#
# PROVING IT CAN FAIL
#   Three sweeps in this repository's history declared a search complete by
#   grepping identifier names and all three were wrong. So this script runs a
#   FIXTURE on every invocation, before it scans the real tree: it plants each
#   of the five forbidden shapes into a temporary file, runs the SAME scanner
#   over it, and fails if any of them is not caught. It also plants a clean
#   control that must pass, and a `#[cfg(test)]`-guarded keyring that must be
#   IGNORED -- without that control the scanner could be "catching" everything
#   by matching unconditionally.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCAN_PATHS=(
  "crates/swarm-governance/src"
  "crates/swarm-consensus/src"
  "crates/swarm-policy/src"
)

# The five collection-of-keys shapes. Kept as one alternation so the fixture and
# the real scan cannot drift apart.
KEY_COLLECTION_RE='(BTreeMap|HashMap|BTreeSet|HashSet)<[^>]*SigningKey|Vec<[^>]*SigningKey|\[[[:space:]]*SigningKey[[:space:]]*;|&\[[[:space:]]*SigningKey[[:space:]]*\]'

# Scan one file, printing `path:line:text` for every violation outside a
# `#[cfg(test)]` region.
#
# TEST-REGION DETECTION is deliberately conservative and deliberately simple: a
# `#[cfg(test)]` line opens a skipped region that runs to end of file. Every
# `#[cfg(test)] mod tests` in this repository is the last item in its file (92
# sites, all trailing), and a conservative rule that skips too much would hide
# violations -- so the fixture below plants a production keyring BELOW a
# `#[cfg(test)]` line to prove which way this errs. It errs toward skipping,
# which is why mechanisms 1 and 2 are the real guarantee and this is a backstop.
# COMMENT LINES are skipped: a line whose first non-whitespace is `//`, `*` or
# `/*` declares nothing, and this file's own prose names the very shape it
# forbids. Only WHOLE-LINE comments are skipped -- a declaration carrying a
# trailing `// ...` is still scanned, and the fixture proves both directions.
scan_file() {
  local path="$1"
  awk -v re="$KEY_COLLECTION_RE" '
    /^[[:space:]]*#\[cfg\(test\)\]/ { in_test = 1 }
    in_test { next }
    /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
    $0 ~ re { printf "%s:%d:%s\n", FILENAME, FNR, $0 }
  ' "$path"
}

scan_paths() {
  local path
  local files=()
  for path in "$@"; do
    if [ -d "$path" ]; then
      while IFS= read -r file; do
        [ -n "$file" ] || continue
        files+=("$file")
      done < <(find "$path" -name '*.rs' -type f | LC_ALL=C sort)
    elif [ -f "$path" ]; then
      files+=("$path")
    else
      echo "scan target does not exist: $path" >&2
      return 2
    fi
  done
  if [ "${#files[@]}" -eq 0 ]; then
    echo "no .rs files under the scan paths; refusing to pass silently" >&2
    return 2
  fi
  local file
  for file in "${files[@]}"; do
    scan_file "$file"
  done
}

# Inventory the shipped opaque governance capability. This is a structural
# backstop over production Rust source: external trybuild fixtures separately prove
# that a downstream Fake cannot implement, construct, or install the handle.
scan_governance_capability_inventory() {
  local source_root="$1"
  python3 - "$source_root" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
canonical = pathlib.Path("crates/swarm-governance/src/lib.rs")

def production_source(raw: str) -> str:
    out = []
    index = 0
    block_depth = 0
    in_string = False
    escaped = False
    while index < len(raw):
        char = raw[index]
        following = raw[index:index + 2]
        if block_depth:
            if following == "/*":
                block_depth += 1
                out.extend("  ")
                index += 2
            elif following == "*/":
                block_depth -= 1
                out.extend("  ")
                index += 2
            else:
                out.append("\n" if char == "\n" else " ")
                index += 1
            continue
        if in_string:
            out.append("\n" if char == "\n" else " ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if following == "//":
            newline = raw.find("\n", index + 2)
            if newline == -1:
                out.extend(" " * (len(raw) - index))
                break
            out.extend(" " * (newline - index))
            out.append("\n")
            index = newline + 1
            continue
        if following == "/*":
            block_depth = 1
            out.extend("  ")
            index += 2
            continue
        if char == '"':
            in_string = True
            out.append(" ")
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)

source_files = sorted((root / "crates").glob("*/src/**/*.rs"))
if not source_files:
    print("no shipped Rust source found for governance capability inventory", file=sys.stderr)
    raise SystemExit(2)
sources = {
    path.relative_to(root): production_source(path.read_text(encoding="utf-8"))
    for path in source_files
}
failed = False

def reject(label: str, pattern: str) -> None:
    global failed
    matches = [path for path, source in sources.items() if re.search(pattern, source, re.DOTALL)]
    if matches:
        rendered = ", ".join(str(path) for path in matches)
        print(f"governance capability inventory: {label}: {rendered}", file=sys.stderr)
        failed = True

declarations = [
    path
    for path, source in sources.items()
    for _ in re.finditer(r"\bpub\s+struct\s+GovernanceAuthority\b", source)
]
if declarations != [canonical]:
    rendered = ", ".join(str(path) for path in declarations) or "none"
    print(
        "governance capability inventory: expected exactly one public concrete "
        f"GovernanceAuthority in {canonical}; found {rendered}",
        file=sys.stderr,
    )
    failed = True

canonical_source = sources.get(canonical, "")
if not re.search(
    r"\bpub\s+struct\s+GovernanceAuthority\s*\{\s*"
    r"policy\s*:\s*Arc\s*<\s*GovernancePolicy\s*>\s*,?\s*\}",
    canonical_source,
    re.DOTALL,
):
    print(
        "governance capability inventory: canonical handle must contain only the "
        "private Arc<GovernancePolicy> field",
        file=sys.stderr,
    )
    failed = True

mint_pattern = (
    r"\bpub\s+fn\s+authority\s*\(\s*self\s*:\s*&\s*Arc\s*<\s*Self\s*>\s*\)"
    r"\s*->\s*Result\s*<\s*GovernanceAuthority\s*,\s*GovernanceAuthorityError\s*>"
)
if len(re.findall(mint_pattern, canonical_source, re.DOTALL)) != 1:
    print(
        "governance capability inventory: expected exactly one authenticated "
        "GovernancePolicy::authority mint",
        file=sys.stderr,
    )
    failed = True

reject("backend trait is forbidden", r"\btrait\s+GovernanceAuthority\b")
reject("legacy governance seal is forbidden", r"\bSealedGovernanceAuthority\b")
reject("trait-object governance backend is forbidden", r"\bdyn\s+GovernanceAuthority\b")
reject(
    "GovernanceAuthority trait implementation is forbidden",
    r"\bimpl\b(?:\s*<[^>{};]*>)?\s+(?:[A-Za-z_]\w*::)*GovernanceAuthority\s+for\b",
)
reject(
    "GovernanceAuthority Deref/AsRef exposure is forbidden",
    r"\bimpl\b(?:\s*<[^>{};]*>)?\s+(?:Deref|AsRef\s*<\s*GovernancePolicy\s*>)\s+for\s+GovernanceAuthority\b",
)
reject(
    "generic governance installer is forbidden",
    r"\bpub\s+fn\s+with_governance_authority\s*<|"
    r"\bwith_governance_authority\s*\([^)]*(?:impl\s+Into|T\s*:\s*Into)\s*<\s*GovernanceAuthority",
)
reject(
    "public raw-policy authority constructor is forbidden",
    r"\bimpl\s+GovernanceAuthority\s*\{(?:(?!\n\s*impl\b).)*"
    r"\bpub\s+fn\s+(?:new|from_policy|from_backend)\b",
)
raise SystemExit(1 if failed else 0)
PY
}
# ---------------------------------------------------------------------------
# THE FIXTURE. Runs on every invocation.
# ---------------------------------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-single-governor-key.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_failures=0

plant() {
  local name="$1"
  local body="$2"
  printf '%s\n' "$body" > "$FIXTURE_DIR/$name.rs"
}

expect_caught() {
  local name="$1"
  local description="$2"
  local hits
  hits="$(scan_file "$FIXTURE_DIR/$name.rs" | wc -l | tr -d ' ')"
  if [ "$hits" -eq 0 ]; then
    echo "FIXTURE FAILURE: the scanner did not catch $description ($name.rs)" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

expect_clean() {
  local name="$1"
  local description="$2"
  local hits
  hits="$(scan_file "$FIXTURE_DIR/$name.rs" || true)"
  if [ -n "$hits" ]; then
    echo "FIXTURE FAILURE: the scanner flagged $description ($name.rs):" >&2
    printf '%s\n' "$hits" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

plant btreemap 'struct GovernanceState {
    governors: BTreeMap<AgentId, SigningKey>,
}'
plant hashmap 'struct GovernanceState {
    governors: HashMap<AgentId, SigningKey>,
}'
plant vec 'struct GovernanceState {
    governors: Vec<SigningKey>,
}'
plant array 'struct GovernanceState {
    governors: [SigningKey; 4],
}'
plant slice 'fn simulate(governors: &[SigningKey]) -> usize {
    governors.len()
}'
plant control 'struct GovernanceState {
    local_governor: Option<LocalGovernorKey>,
    peer_governors: BTreeSet<AgentId>,
}

struct LocalGovernorKey {
    consensus_agent_id: AgentId,
    signing_key: SigningKey,
}'
plant test_region 'struct GovernanceState {
    local_governor: Option<LocalGovernorKey>,
}

#[cfg(test)]
mod tests {
    fn simulator(governors: &BTreeMap<AgentId, SigningKey>) {}
}'
plant prose '//! This module used to take `&BTreeMap<AgentId, SigningKey>`.
/// Replaced by a single-key type; see `Vec<SigningKey>` in the history.
// governors: HashMap<AgentId, SigningKey>,
struct LocalGovernorKey {
    signing_key: SigningKey,
}'
plant trailing_comment 'struct GovernanceState {
    governors: BTreeMap<AgentId, SigningKey>, // still here, just commented about
}'

expect_caught btreemap "a BTreeMap keyring"
expect_caught hashmap "a HashMap keyring"
expect_caught vec "a Vec of signing keys"
expect_caught array "a fixed-size array of signing keys"
expect_caught slice "a slice-of-keys parameter"
expect_caught trailing_comment "a keyring declared with a trailing comment"
expect_clean control "the single-key shape this phase ships"
expect_clean test_region "a keyring inside a #[cfg(test)] region"
expect_clean prose "a keyring named only in whole-line comments"

CANONICAL_CAPABILITY='pub struct GovernancePolicy;
pub struct GovernanceAuthority {
    policy: Arc<GovernancePolicy>,
}
pub struct GovernanceAuthorityError;
impl GovernancePolicy {
    pub fn authority(self: &Arc<Self>) -> Result<GovernanceAuthority, GovernanceAuthorityError> {
        todo!()
    }
}
impl GovernanceAuthority {
    pub fn same_policy(&self, other: &Self) -> bool { todo!() }
}'

plant_capability_fixture() {
  local name="$1"
  local canonical_body="$2"
  local extra_body="${3:-}"
  local root="$FIXTURE_DIR/capability-$name"
  mkdir -p "$root/crates/swarm-governance/src" "$root/crates/other/src"
  printf '%s\n' "$canonical_body" > "$root/crates/swarm-governance/src/lib.rs"
  printf '%s\n' "$extra_body" > "$root/crates/other/src/lib.rs"
}

expect_capability_clean() {
  local name="$1"
  local description="$2"
  if ! scan_governance_capability_inventory "$FIXTURE_DIR/capability-$name"; then
    echo "FIXTURE FAILURE: the capability inventory rejected $description" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

expect_capability_rejected() {
  local name="$1"
  local description="$2"
  if scan_governance_capability_inventory "$FIXTURE_DIR/capability-$name" >/dev/null 2>&1; then
    echo "FIXTURE FAILURE: the capability inventory accepted $description" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

plant_capability_fixture control "$CANONICAL_CAPABILITY"
plant_capability_fixture second_handle "$CANONICAL_CAPABILITY" \
  'pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }'
plant_capability_fixture backend_trait "$CANONICAL_CAPABILITY" \
  'pub trait GovernanceAuthority {}'
plant_capability_fixture legacy_seal "$CANONICAL_CAPABILITY" \
  'pub trait SealedGovernanceAuthority {}'
plant_capability_fixture trait_object "$CANONICAL_CAPABILITY" \
  'fn install(authority: Box<dyn GovernanceAuthority>) {}'
plant_capability_fixture trait_impl "$CANONICAL_CAPABILITY" \
  'impl GovernanceAuthority for Fake {}'
plant_capability_fixture generic_installer "$CANONICAL_CAPABILITY" \
  'pub fn with_governance_authority<T: Into<GovernanceAuthority>>(authority: T) {}'
plant_capability_fixture moved '' "$CANONICAL_CAPABILITY"
plant_capability_fixture removed '' ''
plant_capability_fixture public_field \
  "${CANONICAL_CAPABILITY/policy: Arc/pub policy: Arc}"
plant_capability_fixture public_constructor \
  "$CANONICAL_CAPABILITY" \
  'impl GovernanceAuthority {
       pub fn from_policy(policy: Arc<GovernancePolicy>) -> Self { todo!() }
   }'
plant_capability_fixture deref "$CANONICAL_CAPABILITY" \
  'impl Deref for GovernanceAuthority { type Target = GovernancePolicy; }'
plant_capability_fixture missing_mint \
  'pub struct GovernancePolicy;
pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }'

expect_capability_clean control "the canonical opaque authority and authenticated mint"
expect_capability_rejected second_handle "a second shipped concrete handle"
expect_capability_rejected backend_trait "a reintroduced public backend trait"
expect_capability_rejected legacy_seal "a reintroduced legacy governance seal"
expect_capability_rejected trait_object "a reintroduced trait-object backend"
expect_capability_rejected trait_impl "a reintroduced GovernanceAuthority trait impl"
expect_capability_rejected generic_installer "a generic authority installer"
expect_capability_rejected moved "the canonical handle moved out of swarm-governance"
expect_capability_rejected removed "the canonical handle was removed"
expect_capability_rejected public_field "the handle's inner policy field became public"
expect_capability_rejected public_constructor "a public raw-policy handle constructor"
expect_capability_rejected deref "a Deref exposure of the inner policy"
expect_capability_rejected missing_mint "the authenticated persisted-policy mint was removed"

if [ "$fixture_failures" -ne 0 ]; then
  echo "" >&2
  echo "The fixture proves this scanner can fail. $fixture_failures of its cases" >&2
  echo "did not behave as documented, so its verdict over the real tree means" >&2
  echo "nothing. Fix the scanner, not the fixture." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# THE REAL SCAN
# ---------------------------------------------------------------------------
violations="$(scan_paths "${SCAN_PATHS[@]}")"

if [ -n "$violations" ]; then
  echo "BFT-03: a collection of governor signing keys is declared on the" >&2
  echo "governance signing path. No production path may hold more than one" >&2
  echo "governor's signing key in memory." >&2
  echo "" >&2
  printf '%s\n' "$violations" >&2
  echo "" >&2
  echo "If this is genuinely correct -- a test-only multi-key simulator, say --" >&2
  echo "move it inside a #[cfg(test)] region, which this gate skips. There is" >&2
  echo "deliberately no allowlist: a one-line exemption file is how a gate stops" >&2
  echo "being one." >&2
  exit 1
fi

scan_governance_capability_inventory "$ROOT_DIR"

echo "single-governor-key gate: 22 fixture cases behaved as documented; no key" \
     "collection on the governance signing path; shipped governance authority" \
     "is one opaque concrete handle with an authenticated mint (${SCAN_PATHS[*]})"
