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
#     make up the governance signing path, plus a shipped-target inventory over
#     the exact normal reverse-dependency closure of `swarm-governance`. The
#     authority inventory requires one concrete opaque `GovernanceAuthority`,
#     its private policy field and authenticated mint; pins every closure
#     manifest, lib/bin root, inherent method/impl, and exact Rust privacy closure
#     rooted at every private-authority field owner; rejects custom build targets;
#     and requires the compiler to forbid unsafe code in every normal shipped target.
#     Full closure production source
#     is also scanned for raw-memory primitives regardless of inferred type.
#
# WHAT THIS SCRIPT COVERS
#   `crates/swarm-governance/src/`, `crates/swarm-consensus/src/` and
#   `crates/swarm-policy/src/`, outside `#[cfg(test)]` regions: no
#   `BTreeMap<.., SigningKey>`, `HashMap<.., SigningKey>`, `Vec<SigningKey>`,
#   `[SigningKey; N]` or `&[SigningKey]`.
#
#   The signing-key collection scan is scoped to those three deliberately.
#   Separately, locked Cargo metadata package IDs and dependency kinds derive and
#   pin all eight normal shipped reverse dependencies, every one of their lib/bin roots, and the complete
#   Rust source set in that closure. Raw source identity is reserved for the
#   five field-owning modules and every production descendant that Rust privacy
#   permits to read an ancestor-private handle field.
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
#   5. A signing-key collection outside the three governance-signing paths.
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
#   forbidden keyring shape and capability escape into a temporary source tree,
#   runs the SAME scanners over it, and fails if any mutation is not caught. It
#   also plants clean controls that must pass, including a `#[cfg(test)]`-guarded
#   keyring -- without those controls the scanners could be "catching" everything
#   by matching unconditionally.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

phase285_paths_overlap() {
  [[ "$1" == "$2" || "$1" == "$2/"* || "$2" == "$1/"* ]]
}

phase285_create_confined_scratch() {
  local prefix="$1" parent="${2:-${TMPDIR:-/tmp}}" scratch raw_scratch boundary
  parent="$(cd -- "$parent" && pwd -P)" || return 1
  local boundaries=(
    "$ROOT_DIR"
    "$(git rev-parse --path-format=absolute --git-dir)"
    "$(git rev-parse --path-format=absolute --git-common-dir)"
  )
  local canonical_boundaries=()
  for boundary in "${boundaries[@]}"; do
    canonical_boundaries+=("$(cd -- "$boundary" && pwd -P)") || return 1
  done
  scratch="$(mktemp -d "$parent/$prefix.XXXXXX")" || return 1
  raw_scratch="$scratch"
  scratch="$(cd -- "$scratch" && pwd -P)" || {
    rm -rf -- "$raw_scratch"
    [ ! -e "$raw_scratch" ]
    return 1
  }
  [ -z "$(find "$scratch" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    rm -rf -- "$scratch" || true
    [ ! -e "$scratch" ] || echo "PHASE285-SCRATCH[nonempty-cleanup-failed]" >&2
    echo "PHASE285-SCRATCH[nonempty-new-directory]" >&2
    return 1
  }
  for boundary in "${canonical_boundaries[@]}"; do
    if phase285_paths_overlap "$scratch" "$boundary"; then
      rmdir -- "$scratch" || {
        echo "PHASE285-SCRATCH[boundary-cleanup-failed]" >&2
        return 1
      }
      [ ! -e "$scratch" ] || {
        echo "PHASE285-SCRATCH[boundary-cleanup-failed]" >&2
        return 1
      }
      echo "PHASE285-SCRATCH[boundary-overlap]" >&2
      return 1
    fi
  done
  printf '%s\n' "$scratch"
}

phase285_cleanup_confined_scratch() {
  rm -rf -- "$1" || return 1
  [ ! -e "$1" ] || return 1
}

phase285_scratch_hostile_controls() {
  local boundary output exit_code rejected=0
  local boundaries=(
    "$ROOT_DIR"
    "$(git rev-parse --path-format=absolute --git-dir)"
    "$(git rev-parse --path-format=absolute --git-common-dir)"
  )
  for boundary in "${boundaries[@]}"; do
    exit_code=0
    output="$(TMPDIR="$boundary" phase285_create_confined_scratch phase285-signer-hostile 2>&1)" || exit_code=$?
    [ "$exit_code" -ne 0 ] && [ "$output" = "PHASE285-SCRATCH[boundary-overlap]" ] || return 1
    rejected=$((rejected + 1))
  done
  echo "phase285_scratch_self_test site=signer boundaries=$rejected passed=1"
}

PHASE285_SIGNER_PYTHON=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]] \
    && "$candidate" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    PHASE285_SIGNER_PYTHON="$candidate"
    break
  fi
done
if [[ -z "$PHASE285_SIGNER_PYTHON" ]]; then
  echo "Phase 285 signer check requires Python >= 3.11 at a pinned system path" >&2
  exit 1
fi

phase285_second_signer_check() {
  "$PHASE285_SIGNER_PYTHON" -I - "$1/crates/swarm-governance-witness/src" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
if not root.is_dir():
    raise SystemExit("PHASE285-SIGNER[missing-witness-source]")
pattern = re.compile(r"\bSigningKey\b|\bsigning_key\b|\bgovernor_signer\b")
for path in sorted(root.rglob("*.rs")):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if line.lstrip().startswith("//"):
            continue
        if pattern.search(line):
            raise SystemExit(f"PHASE285-SIGNER[second-governor-signer]:{path.name}:{number}")
print("phase285_second_signer positive=1")
PY
}

phase285_second_signer_self_test() (
  phase285_second_signer_check "$ROOT_DIR"
  phase285_scratch_hostile_controls
  local scratch
  scratch="$(phase285_create_confined_scratch phase285-signer)"
  trap 'phase285_cleanup_confined_scratch "$scratch" || exit 1' EXIT
  mkdir -p "$scratch/crates/swarm-governance-witness/src"
  cp "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" "$scratch/crates/swarm-governance-witness/src/lib.rs"
  printf '\npub struct Forbidden { signing_key: SigningKey }\n' >>"$scratch/crates/swarm-governance-witness/src/lib.rs"
  local output status=0
  output="$(phase285_second_signer_check "$scratch" 2>&1)" || status=$?
  [ "$status" -ne 0 ] && [[ "$output" == PHASE285-SIGNER\[second-governor-signer\]:* ]] || return 1
  echo "phase285_transport_self_test case=phase285-second-governor-signer positive=1 mutation_failure=1"
)

if [ "${1:-}" = --self-test ]; then
  [ "$#" -eq 2 ] && [ "$2" = phase285-second-governor-signer ] || {
    echo "usage: $0 [--self-test phase285-second-governor-signer]" >&2
    exit 2
  }
  phase285_second_signer_self_test
  exit 0
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--self-test phase285-second-governor-signer]" >&2
  exit 2
fi
phase285_second_signer_check "$ROOT_DIR" >/dev/null

SINGLE_GOVERNOR_PYTHON=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]] \
    && "$candidate" -I -c 'import sys, tomllib; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    SINGLE_GOVERNOR_PYTHON="$candidate"
    break
  fi
done
if [[ -z "$SINGLE_GOVERNOR_PYTHON" ]]; then
  echo "check-single-governor-key requires Python >= 3.11 at a pinned system path" >&2
  exit 1
fi
SINGLE_GOVERNOR_CARGO="$(command -v cargo || true)"
if [[ -z "$SINGLE_GOVERNOR_CARGO" || ! -x "$SINGLE_GOVERNOR_CARGO" ]]; then
  echo "check-single-governor-key requires Cargo on the trusted PATH" >&2
  exit 1
fi
SINGLE_GOVERNOR_MUTATION_PROBE="${SWARM_SINGLE_GOVERNOR_MUTATION_PROBE:-0}"
if [[ "$SINGLE_GOVERNOR_MUTATION_PROBE" != "0" \
  && "$SINGLE_GOVERNOR_MUTATION_PROBE" != "1" ]]; then
  echo "SWARM_SINGLE_GOVERNOR_MUTATION_PROBE must be 0 or 1" >&2
  exit 1
fi
SINGLE_GOVERNOR_CACHE_SOURCE="$HOME/.cargo"
if [[ "${SWARM_NEGATIVE_REGISTRY_PROTECTED:-0}" == "1" ]]; then
  SINGLE_GOVERNOR_CACHE_SOURCE="${SWARM_SINGLE_GOVERNOR_CACHE_SOURCE:-}"
  if [[ -z "$SINGLE_GOVERNOR_CACHE_SOURCE" \
    || ! -d "$SINGLE_GOVERNOR_CACHE_SOURCE" ]]; then
    echo "protected single-governor gate requires a gate-owned Cargo cache source" >&2
    exit 1
  fi
  SINGLE_GOVERNOR_CACHE_SOURCE="$(
    cd -- "$SINGLE_GOVERNOR_CACHE_SOURCE" && pwd -P
  )"
fi

SCAN_PATHS=(
  "crates/swarm-governance/src"
  "crates/swarm-consensus/src"
  "crates/swarm-policy/src"
)

# The five collection-of-keys shapes. Kept as one alternation so the fixture and
# the real scan cannot drift apart.
KEY_COLLECTION_RE='(BTreeMap|HashMap|BTreeSet|HashSet)<[^>]*SigningKey|Vec<[^>]*SigningKey|[[][[:space:]]*SigningKey[[:space:]]*;|&[[][[:space:]]*SigningKey[[:space:]]*[]]'

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
  local inventory_mode="${2:-fixture}"
  "$SINGLE_GOVERNOR_PYTHON" -I - \
    "$source_root" "$inventory_mode" "$SINGLE_GOVERNOR_CARGO" \
    "$ROOT_DIR/target/single-governor-source-inventory" \
    "$SINGLE_GOVERNOR_CACHE_SOURCE" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
inventory_mode = sys.argv[2]
strict_digest = inventory_mode in {"strict", "strict-force-depinfo"}
force_dep_info = inventory_mode == "strict-force-depinfo"
privacy_only = inventory_mode == "privacy"
cargo = pathlib.Path(sys.argv[3])
assurance_target = pathlib.Path(sys.argv[4])
cache_source = pathlib.Path(sys.argv[5])
canonical = pathlib.Path("crates/swarm-governance/src/lib.rs")
EXPECTED_ROOT_MANIFEST_DIGEST = "7ad7f702d39e1a74dd746f802889f85acdc6618309e292e718acb6e0f0769f72"
EXPECTED_ROOT_LOCK_DIGEST = "4a899e087f951de34c86b177c3c34658e15d75d55b3ce7ba307106770eb39903"
EXPECTED_WORKSPACE_PACKAGES = {
    "swarm-agents",
    "swarm-cli",
    "swarm-consensus",
    "swarm-core",
    "swarm-crypto",
    "swarm-evolution",
    "swarm-governance",
    "swarm-governance-witness",
    "swarm-guard",
    "swarm-ingest-json",
    "swarm-ingest-runtime",
    "swarm-ingest-sentinel",
    "swarm-ingest-taxii",
    "swarm-ingest-tetragon",
    "swarm-pheromone",
    "swarm-policy",
    "swarm-response",
    "swarm-runtime",
    "swarm-runtime-http",
    "swarm-runtime-workbench",
    "swarm-spine",
    "swarm-whisker",
}
EXPECTED_AUTHORITY_IMPL_DIGEST = "960ffd9693b8aa84064bd1abc40130ed38d52aaa5d0e5635b7353d7d2b84a2e7"
EXPECTED_GOVERNANCE_SOURCE_DIGEST = "1cf3f10dc555c9c8de2d3db1f02ef6dd2c79e461d9d213549c0273e8b06eef71"
EXPECTED_STRICT_AUTHORITY_IMPL_DIGESTS = {
    (canonical, "implstd::fmt::DebugforGovernanceAuthority"):
        "351c05a0947ce39862c748abd2f3a30e1fdd3fed287829554ac153b05e1ef515",
    (canonical, "implGovernancePolicy"):
        "5f0363aa2a888f7354ac60762225cc3d2fa9458539bee7fb87c0927c6937e6de",
    (canonical, "implGovernanceAuthority"):
        "960ffd9693b8aa84064bd1abc40130ed38d52aaa5d0e5635b7353d7d2b84a2e7",
    (pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"), "implIngestState"):
        "1d28d8a2bca185157c8e6ab76e09ba52302aef2b7f51644287ef60baafb6eddc",
    (pathlib.Path("crates/swarm-runtime/src/containment.rs"), "implContainmentSweep"):
        "154b2b98b5c74743b77a1afd1a974543cd743d32a4adc4654c35d4294cef03c4",
    (pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"), "implHumanApprovalResumeDispatcher"):
        "a6c06adff2661ce7eb96c8d47d9f60be3a34d6a38139917be8acc6cc1d080d7c",
    (pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"), "implAgentDispatcher"):
        "7d9e8c068da1a14d9d84a20fb15ec51333cd28d8cbf26980477292557cb00484",
    (pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"), "implShippedGovernanceWiring"):
        "4ba6347d6aa2ae80240472fd2ba3733b6bfca1bd3addcc6e2b991ab95a93a1fe",
}
EXPECTED_STRICT_AUTHORITY_PUBLIC_APIS = {
    (
        canonical,
        "pubfnauthority(self:&Arc<Self>)->Result<GovernanceAuthority,GovernanceAuthorityError>",
    ),
    (
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"),
        "pubfnwith_governance_authority(mutself,governance_authority:GovernanceAuthority)->Self",
    ),
    (
        pathlib.Path("crates/swarm-runtime/src/containment.rs"),
        "pubfnverify_release_attestation(receipt:&RollbackReceipt,governance:Option<&GovernanceAuthority>)->Result<ConsensusGovernanceReceipt,ReleaseAttestationError>",
    ),
    (
        pathlib.Path("crates/swarm-runtime/src/containment.rs"),
        "pubasyncfnrelease_lease(store:&dynContainmentLeaseStore,executor:&dynRollbackExecutor,mode:ExecutionMode,lease_id:&str,trigger:RollbackTrigger,now_ms:i64,governance:Option<&GovernanceAuthority>)->Result<RollbackReceipt,ContainmentReleaseError>",
    ),
    (
        pathlib.Path("crates/swarm-runtime/src/containment.rs"),
        "pubfnwith_governance_authority(mutself,governance:GovernanceAuthority)->Self",
    ),
    (
        pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"),
        "pubfnnew(governance:GovernanceAuthority,router:Arc<dynRequestResponseRouter>,expected_eligible_voters:Vec<String>,expected_threshold:ThresholdRule)->Self",
    ),
    (
        pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"),
        "pubfnwith_governance_authority(mutself,governance_authority:GovernanceAuthority)->Self",
    ),
}
EXPECTED_AUTHORITY_REVERSE_CLOSURE = {
    "swarm-governance",
    "swarm-governance-witness",
    "swarm-runtime",
    "swarm-ingest-runtime",
    "swarm-runtime-http",
    "swarm-agents",
    "swarm-evolution",
    "swarm-runtime-workbench",
    "swarm-cli",
}
EXPECTED_CLOSURE_MANIFEST_DIGESTS = {
    "swarm-governance": "4e1bf8dde6a967a3473401fa9abb65579e0d40d55c32b3dab67c5d355bf93aac",
    "swarm-governance-witness": "03c056a47f2e50807fed692c994fa2df3e976ef1b239878ee95face93796493d",
    "swarm-runtime": "d0d7570100a329751d1abbec9ef627d5c2b01f5bdfc62559b7cb22979ea1521e",
    "swarm-ingest-runtime": "9332eb415a092cbf5f1c4ae02b79d2a3e928464441c7d14ae1fcd39ecf406875",
    "swarm-runtime-http": "890644cbb2cd57bed43de30491b60d1fef5b8e64038520d5249af531a292b88f",
    "swarm-agents": "531cb9064f0d5e5143dac6cf56312ec88180e17a0feba3a4eeb2e7b2b169d67a",
    "swarm-evolution": "0fca9be1e6d92ad2acdd70fa1b06994bd6a28fd16381c3b42b0255f427f4887c",
    "swarm-runtime-workbench": "eab3a2b0578a2366e26604a69ca649ba03ce032d3fc45696876ae222573d24ce",
    "swarm-cli": "0593667747de0b4cd7792170f2c6bfa8fb0a5051767dca97ede20fad44a23dfe",
}
EXPECTED_CLOSURE_PACKAGE_FILE_INVENTORY = {
    "swarm-governance":
        (14, "fa359ba1da72ec1543ac52678c2cc7cae86870843656e8dec3a35506facdbe76"),
    "swarm-governance-witness":
        (16, "b9de5c5b50a502d71dfe435a36b28a9002843f6b7b6f3c49d44317f34a4c5614"),
    "swarm-runtime":
        (133, "8ac09aa65386fed38a0990dc6f7c97b95df178524a191e2cd5c026293564c1b6"),
    "swarm-ingest-runtime":
        (14, "e71df92a402c4dbc5f0e36319aeca0132d46d3c5d4f2d02f00415ecfb437d100"),
    "swarm-runtime-http":
        (22, "9dea36f32378484d96596ab95b198d6ebbc239a8e810172d9e1e2efb800de6d6"),
    "swarm-agents":
        (9, "965bdaa294602a9f13a04ebe110608f658021c0b3810eeb794c34cb4a92a8e96"),
    "swarm-evolution":
        (6, "6fe9028e2e5d2bc323926f99866ccbf3cf7490cf1f3f30894340d6ddb2ffdf56"),
    "swarm-runtime-workbench":
        (11, "b333bbfdc9f25b31982e33c30e49dc4663704b04ebc58531e93732300140f1f5"),
    "swarm-cli":
        (7, "ebe0ae8023e9d6bb141e173c7067b0c0fcb69fa1593aaae1e42fee1a3e96e45e"),
}
EXPECTED_PRIVACY_SOURCE_DIGESTS = {
    pathlib.Path("crates/swarm-governance/src/lib.rs"):
        "1cf3f10dc555c9c8de2d3db1f02ef6dd2c79e461d9d213549c0273e8b06eef71",
    pathlib.Path("crates/swarm-governance/src/persistence_protocol.rs"):
        "1fc3837ca0fdd6739352053266017162051925feb655a3b4f21fde77b5b8cfe0",
    pathlib.Path("crates/swarm-governance/src/witness_engine.rs"):
        "0ab35a8afcb3f080db48635008df18710e06a806d40d866d8a0f86eb35c56bbc",
    pathlib.Path("crates/swarm-governance/src/witness_engine/store.rs"):
        "9f639fbe2ef85da384527355632ffd3aa42e48189cfcb8a8c1ee3139d00249bf",
    pathlib.Path("crates/swarm-governance/src/witness_engine/store/in_memory.rs"):
        "426ac04999f7cd618e00c3c18d5e40e0e8e10ec663f201df30feddb966f26bda",
    pathlib.Path("crates/swarm-governance/src/witness_engine/store/proxy.rs"):
        "d627b503fe6c600f24ef1ac835a5e6d459073920faa3a357ec719fefb41f924e",
    pathlib.Path("crates/swarm-governance/src/witness_service.rs"):
        "a9891401a96c7b3dc20fa59830d31e3e3637d8c27a49ddcf5528124d37b6c2af",
    pathlib.Path("crates/swarm-governance/src/witness_service/witness_candidate_verifier.rs"):
        "6b861f64ed9c927ee671a22cebf3d1dc39947899a4b6a6b9115c685e5f55cebd",
    pathlib.Path("crates/swarm-runtime/src/containment.rs"):
        "813b259d69867ca71649f0f4a20fae30868a3405a5be1a217f467d8de53577ad",
    pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"):
        "1cdb52025a333d42a623ad0df08a34c05722a4a8aa3532af763415bc73e6f9e0",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"):
        "a17f2173304adc98c96182f199bd788346d638d5e96ed2fc0fb6e5f68d4dc3ce",
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"):
        "f909db3b9ded397cc87455c62350df8b10a68b6865eca524cb164ca3ba8baf7c",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/demo.rs"):
        "d0d3146879c0dce2ffbb4198305254c1cb544e8e17fbd9a9d1c36f29e1f33c64",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/governance_resume.rs"):
        "a9e902f8ca76aab03c2c4ea612ac0a834caeff012135d22029509e267ba2ae32",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/health.rs"):
        "3b875c6701baec37cf71692c9937d2e1a08bd477391c7529b05fb5a4c8325acd",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/platform_api.rs"):
        "6a47977b16fd895e5bea265ce18335f6f8b291db28b9ab758591cfd4d8e7bc14",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs"):
        "18851cb42818784fce99ad68b930eae1ca514d6b05486666f3055d862968df17",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/soar_verdict_handlers.rs"):
        "0ff48f14ce2eafb19f4600b7b49f8297222d45eac3af3ec2a67f934a12a06eba",
}
EXPECTED_PRIVACY_CLOSURES = {
    pathlib.Path("crates/swarm-governance/src/lib.rs"): {
        pathlib.Path("crates/swarm-governance/src/lib.rs"),
        pathlib.Path("crates/swarm-governance/src/persistence_protocol.rs"),
        pathlib.Path("crates/swarm-governance/src/witness_engine.rs"),
        pathlib.Path("crates/swarm-governance/src/witness_engine/store.rs"),
        pathlib.Path("crates/swarm-governance/src/witness_engine/store/in_memory.rs"),
        pathlib.Path("crates/swarm-governance/src/witness_engine/store/proxy.rs"),
        pathlib.Path("crates/swarm-governance/src/witness_service.rs"),
        pathlib.Path("crates/swarm-governance/src/witness_service/witness_candidate_verifier.rs"),
    },
    pathlib.Path("crates/swarm-runtime/src/containment.rs"): {
        pathlib.Path("crates/swarm-runtime/src/containment.rs"),
    },
    pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"): {
        pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"),
    },
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"): {
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"),
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/demo.rs"),
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/governance_resume.rs"),
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/health.rs"),
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/platform_api.rs"),
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs"),
        pathlib.Path("crates/swarm-ingest-runtime/src/ingest/soar_verdict_handlers.rs"),
    },
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"): {
        pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"),
    },
}
EXPECTED_CLOSURE_TARGET_ATTRIBUTES = {
    pathlib.Path("crates/swarm-governance/src/lib.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-governance-witness/src/lib.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-governance-witness/src/bin/swarm-governance-witness.rs"):
        "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-governance-witness/src/bin/swarm-governance-witness-store.rs"):
        "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-runtime/src/lib.rs"): "#![cfg_attr(not(test), forbid(unsafe_code))]",
    pathlib.Path("crates/swarm-runtime/src/bin/generate_adversary_emulation_report.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-runtime/src/bin/swarm_debug_attest.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-ingest-runtime/src/lib.rs"): "#![cfg_attr(not(test), forbid(unsafe_code))]",
    pathlib.Path("crates/swarm-ingest-runtime/src/bin/generate_platform_openapi.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-runtime-http/src/lib.rs"): "#![cfg_attr(not(test), forbid(unsafe_code))]",
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarmctl.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-agents/src/lib.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-evolution/src/lib.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-runtime-workbench/src/lib.rs"): "#![forbid(unsafe_code)]",
    pathlib.Path("crates/swarm-cli/src/lib.rs"): "#![cfg_attr(not(test), forbid(unsafe_code))]",
}
EXPECTED_CLOSURE_TARGET_DEP_INFO = {
    pathlib.Path("crates/swarm-governance/src/lib.rs"):
        (8, "f9ed6a705aad92bc1177359a874183d7c16fe26a24ce35d101320146cec12301"),
    pathlib.Path("crates/swarm-governance-witness/src/lib.rs"):
        (9, "8f3bdefe46ef31f3b48dfbc2aad1fca78853dcc70101f96eac7669831ec85243"),
    pathlib.Path("crates/swarm-governance-witness/src/bin/swarm-governance-witness.rs"):
        (1, "6556bcf8c511d576153dd6884819191b09b5da6ee7b638b3ca434376ce735c07"),
    pathlib.Path("crates/swarm-governance-witness/src/bin/swarm-governance-witness-store.rs"):
        (1, "f2942e31522c4ab748a8b448b19cac6e9f4878e8ff85b009b34a60a6569b7f78"),
    pathlib.Path("crates/swarm-runtime/src/lib.rs"):
        (66, "fafb667daf3e888aa38f9a7ef7911bec1670e197a1551412ca2cf3e958b380e3"),
    pathlib.Path("crates/swarm-runtime/src/bin/generate_adversary_emulation_report.rs"):
        (1, "2ac1fea5085cb1261d4a641a2d187f760a9695914438b5e79024cec0b7281ce9"),
    pathlib.Path("crates/swarm-runtime/src/bin/swarm_debug_attest.rs"):
        (1, "8eec9e48b0e573c9de8411260221ac958bb3f0c8da4a50f1bc56a038d53bc4be"),
    pathlib.Path("crates/swarm-ingest-runtime/src/lib.rs"):
        (11, "5bfb483f437753617f3b1eb53a37b410d291ca45328e1abd2b9ede17433f3277"),
    pathlib.Path("crates/swarm-ingest-runtime/src/bin/generate_platform_openapi.rs"):
        (1, "aedbc822aff15ffdd83b4c97c088a83b22cd358140802be85b0424b6e3cdc8dd"),
    pathlib.Path("crates/swarm-runtime-http/src/lib.rs"):
        (25, "760df5d6e1cd0ad46675b8b5d27984ddd07b9762841a6b4ec799a4ba858de871"),
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"):
        (1, "e9a5ca27250a7e81c6e0a0fb36a6a435e5655bac53c4cde4dce7635dcf52382b"),
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarmctl.rs"):
        (1, "6434697b0ee07f5447a26dcb0ee386746d795f9cd4e336e50789361002fa1329"),
    pathlib.Path("crates/swarm-agents/src/lib.rs"):
        (6, "3ed28be7109b735c5dfd3b67d3157896ebf2f1092b8ccc4c3e64ee16be6e96b3"),
    pathlib.Path("crates/swarm-evolution/src/lib.rs"):
        (5, "52daf51b99ca287272e6ca9c4653c6607eb87d8e9ff918f878c4248368a097da"),
    pathlib.Path("crates/swarm-runtime-workbench/src/lib.rs"):
        (10, "784281a62b833591581a15820dda82c0312f833ad9a5ba6ccdf0ee5e3f1ae3aa"),
    pathlib.Path("crates/swarm-cli/src/lib.rs"):
        (8, "2f85d4621421feabc955a4673f29eb5f83fe57a8727decaf75611db375f76f3a"),
}
EXPECTED_CLOSURE_PATH_DIRECTIVES = {
    (
        pathlib.Path("crates/swarm-cli/src/lib.rs"),
        "core.inc",
        pathlib.Path("crates/swarm-cli/src/core.inc"),
    ),
    *{
        (
            pathlib.Path("crates/swarm-runtime-http/src/cli/mod.rs"),
            f"../../../swarm-cli/src/{name}",
            pathlib.Path(f"crates/swarm-cli/src/{name}"),
        )
        for name in ("core.inc", "args.rs", "dispatch.rs", "format.rs", "tracing.rs")
    },
    *{
        (
            pathlib.Path("crates/swarm-runtime/src/mutation.rs"),
            f"mutation/{name}.rs",
            pathlib.Path(f"crates/swarm-runtime/src/mutation/{name}.rs"),
        )
        for name in ("autonomous", "fitness", "harness", "helpers", "render", "stores", "types")
    },
    *{
        (
            pathlib.Path("crates/swarm-runtime/src/evolution.rs"),
            f"evolution/{name}.rs",
            pathlib.Path(f"crates/swarm-runtime/src/evolution/{name}.rs"),
        )
        for name in ("assurance", "formal_safety", "harnesses", "helpers", "render", "stores", "types")
    },
}
EXPECTED_CLOSURE_NON_RS_RUST_DIGESTS = {
    pathlib.Path("crates/swarm-cli/src/core.inc"):
        "fcf7396863c83532664b0a00395b8a7862b0036c5f512e2771eeac8765129e76",
}
failed = False

ALLOWED_AUTHORITY_METHODS = {
    "same_policy": "pubfnsame_policy(&self,other:&Self)->bool",
    "identity": "pubfnidentity(&self)->GovernanceAuthorityIdentity",
    "authorize_partition_request": (
        "pubfnauthorize_partition_request(&self,request:&ActionRequest,now_ms:i64)"
        "->Result<Option<serde_json::Value>,String>"
    ),
    "verify_and_consume_action_authorization": (
        "pubfnverify_and_consume_action_authorization(&self,request:&ActionRequest,"
        "receipt:&serde_json::Value,now_ms:i64)->Result<serde_json::Value,String>"
    ),
    "verify_and_consume_veto": (
        "pubfnverify_and_consume_veto(&self,request:&ActionRequest,"
        "receipt:&serde_json::Value,now_ms:i64)->Result<serde_json::Value,String>"
    ),
    "begin_human_authorization_hold": (
        "pubfnbegin_human_authorization_hold(&self,request:&ActionRequest,"
        "receipt:&serde_json::Value,policy_decision:&PolicyDecision,now_ms:i64)"
        "->Result<GovernedHumanAuthorizationHold,String>"
    ),
    "bind_human_approval_set": (
        "pubfnbind_human_approval_set(&self,hold_id:&str,approval_set_id:&str,"
        "approval_set_digest:&str)->Result<GovernedHumanAuthorizationHold,String>"
    ),
    "reconcile_human_approval_set": (
        "pubfnreconcile_human_approval_set(&self,approval_set_id:&str,"
        "approval_set_digest:&str,approval_evidence_ref:&str)"
        "->Result<GovernedHumanAuthorizationHold,String>"
    ),
    "pending_human_authorization": (
        "pubfnpending_human_authorization(&self,approval_set_id:&str)"
        "->Result<GovernedHumanAuthorizationHold,String>"
    ),
    "verify_and_consume_human_authorization": (
        "pubfnverify_and_consume_human_authorization(&self,hold_id:&str,"
        "approval_set_id:&str,approval_set_digest:&str,now_ms:i64)"
        "->Result<ConsumedGovernedHumanAuthorization,String>"
    ),
    "is_partitioned": "pubfnis_partitioned(&self)->bool",
    "note_partition_veto": (
        "pubfnnote_partition_veto(&self,request:&ActionRequest,reason:&str,now_ms:i64)"
    ),
    "drain_runtime_events": (
        "pubfndrain_runtime_events(&self)->Vec<GovernanceRuntimeEventRecord>"
    ),
    "status_report": "pubfnstatus_report(&self)->GovernanceStatusReport",
    "attest_release": (
        "pubfnattest_release(&self,subject:&serde_json::Value,now_ms:i64)"
        "->Option<serde_json::Value>"
    ),
    "governor_public_keys": (
        "pubfngovernor_public_keys(&self)->BTreeSet<AgentId>"
    ),
}
EXPECTED_MINT_HEADER = (
    "pubfnauthority(self:&Arc<Self>)"
    "->Result<GovernanceAuthority,GovernanceAuthorityError>"
)

RUST_RAW_STRING = re.compile(r'(?:b|c)?r(?P<hashes>#{0,255})"')
RUST_CHARACTER_LITERAL = re.compile(
    r"'(?:\\(?:[nrt0\\'\"]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\})|"
    r"[^\\'\r\n])'"
)

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
        # Match against the original buffer at `index`. Slicing `raw[index:]`
        # for every byte makes this scanner quadratic on large Rust modules and
        # caused the clean-tree assurance subprocess to exceed its ten-minute
        # fail-closed timeout.
        raw_string = (
            RUST_RAW_STRING.match(raw, index) if char in {"b", "c", "r"} else None
        )
        if raw_string is not None:
            terminator = '"' + raw_string.group("hashes")
            end = raw.find(terminator, raw_string.end())
            if end < 0:
                raise ValueError("unclosed Rust raw string")
            end += len(terminator)
            out.extend("\n" if value == "\n" else " " for value in raw[index:end])
            index = end
            continue
        if char == '"':
            in_string = True
            out.append(" ")
            index += 1
            continue
        character = RUST_CHARACTER_LITERAL.match(raw, index) if char == "'" else None
        if character is not None:
            out.extend(" " * (character.end() - index))
            index = character.end()
            continue
        out.append(char)
        index += 1
    return "".join(out)

def without_cfg_test_modules(source: str) -> str:
    output = list(source)
    for match in reversed(list(re.finditer(
        r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]"
        r"(?:\s*#\s*\[[^\]]*\])*\s*mod\s+[A-Za-z_]\w*\s*\{",
        source,
        re.DOTALL,
    ))):
        opening = source.rfind("{", match.start(), match.end())
        end = matching_brace(source, opening) + 1
        for index in range(match.start(), end):
            if output[index] != "\n":
                output[index] = " "
    external = re.compile(
        r"(?m)^(?P<attrs>(?:[ \t]*#\s*\[[^\]\n]*\][ \t]*\n)+)"
        r"[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_]\w*\s*;",
    )
    for match in reversed(list(external.finditer(source))):
        if not re.search(
            r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]",
            match.group("attrs"),
        ):
            continue
        for index in range(match.start(), match.end()):
            if output[index] != "\n":
                output[index] = " "
    return "".join(output)

def canonical_tokens(value: str) -> str:
    value = re.sub(r",\s*\)", ")", value)
    return re.sub(r"\s+", "", value)

def matching_brace(source: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unclosed Rust item")

def braced_items(path: pathlib.Path, source: str, keyword: str):
    items = []
    leader = rf"(?:pub(?:\s*\([^)]*\))?\s+)?{keyword}" if keyword == "trait" else keyword
    pattern = re.compile(
        rf"(?m)^[ \t]*(?P<leader>{leader})\b(?P<header>[^{{}};]*)\{{",
        re.DOTALL | re.MULTILINE,
    )
    for match in pattern.finditer(source):
        opening = match.end() - 1
        try:
            closing = matching_brace(source, opening)
        except ValueError as error:
            print(
                "governance capability inventory: "
                f"{path}:{source.count(chr(10), 0, match.start()) + 1}: "
                f"{error} after `{canonical_tokens(match.group('leader') + match.group('header'))}`",
                file=sys.stderr,
            )
            raise SystemExit(2)
        items.append((
            canonical_tokens(match.group("leader") + match.group("header")),
            match.start(),
            closing + 1,
            source[match.start():closing + 1],
        ))
    return items

def inherent_method_headers(source: str):
    opening = source.find("{")
    if opening < 0:
        return []
    depth = 0
    depths = [0] * (len(source) + 1)
    for index, char in enumerate(source):
        depths[index] = depth
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    methods = []
    for match in re.finditer(r"\bfn\s+(?P<name>[A-Za-z_]\w*)", source):
        if depths[match.start()] != 1:
            continue
        line_start = source.rfind("\n", 0, match.start()) + 1
        body_open = source.find("{", match.end())
        if body_open < 0 or depths[body_open] != 1:
            raise ValueError(f"method `{match.group('name')}` has no top-level body")
        header = canonical_tokens(source[line_start:body_open])
        methods.append((match.group("name"), header))
    return methods

def public_function_headers(source: str):
    headers = []
    pattern = re.compile(
        r"\bpub\s+(?:(?:const|async|unsafe)\s+)*(?:extern\s*(?:\"[^\"]*\")?\s+)?"
        r"fn\s+[A-Za-z_]\w*",
        re.DOTALL,
    )
    for match in pattern.finditer(source):
        terminators = [position for position in (
            source.find("{", match.end()),
            source.find(";", match.end()),
        ) if position >= 0]
        if not terminators:
            continue
        end = min(terminators)
        headers.append(canonical_tokens(source[match.start():end]))
    return headers

def external_module_children(relative: pathlib.Path) -> set[pathlib.Path]:
    source_path = root / relative
    raw = source_path.read_text(encoding="utf-8")
    source = without_cfg_test_modules(production_source(raw))
    declaration = re.compile(
        r"(?m)^(?P<attrs>(?:[ \t]*#\s*\[[^\]\n]*\][ \t]*\n)*)"
        r"[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*;",
    )
    children = set()
    if relative.name in {"lib.rs", "main.rs", "mod.rs"}:
        default_base = relative.parent
    else:
        default_base = relative.parent / relative.stem
    for match in declaration.finditer(source):
        attrs = match.group("attrs")
        if re.search(r"cfg\s*\([^)]*\btest\b", attrs):
            continue
        path_attributes = re.findall(r"path\s*=\s*\"([^\"]+)\"", attrs)
        if len(path_attributes) > 1:
            raise ValueError(f"{relative}: duplicate #[path] on module {match.group('name')}")
        if path_attributes:
            candidates = [relative.parent / path_attributes[0]]
        else:
            name = match.group("name")
            candidates = [default_base / f"{name}.rs", default_base / name / "mod.rs"]
        existing = [candidate for candidate in candidates if (root / candidate).is_file()]
        if len(existing) != 1:
            raise ValueError(
                f"{relative}: module {match.group('name')} resolves to {existing}, expected one file"
            )
        children.add(existing[0])
    return children

def privacy_module_closure(owner: pathlib.Path) -> set[pathlib.Path]:
    closure = set()
    pending = [owner]
    while pending:
        relative = pending.pop()
        if relative in closure:
            continue
        if not (root / relative).is_file():
            raise ValueError(f"privacy-closure source is missing: {relative}")
        closure.add(relative)
        pending.extend(external_module_children(relative) - closure)
    return closure

def validate_privacy_inventory() -> None:
    global failed
    observed_privacy_sources = set()
    for owner, expected_closure in EXPECTED_PRIVACY_CLOSURES.items():
        try:
            actual_closure = privacy_module_closure(owner)
        except (OSError, ValueError) as error:
            print(f"governance capability inventory: {error}", file=sys.stderr)
            failed = True
            continue
        observed_privacy_sources.update(actual_closure)
        if actual_closure != expected_closure:
            print(
                "governance capability inventory: private-authority privacy closure "
                f"for {owner} drifted; found {sorted(map(str, actual_closure))}",
                file=sys.stderr,
            )
            failed = True
    if observed_privacy_sources != set(EXPECTED_PRIVACY_SOURCE_DIGESTS):
        print(
            "governance capability inventory: private-authority privacy source inventory "
            f"drifted; found {sorted(map(str, observed_privacy_sources))}",
            file=sys.stderr,
        )
        failed = True
    for path, expected in EXPECTED_PRIVACY_SOURCE_DIGESTS.items():
        source_path = root / path
        actual = hashlib.sha256(source_path.read_bytes()).hexdigest() if source_path.is_file() else None
        if actual != expected:
            print(
                f"governance capability inventory: private-authority privacy source {path} "
                f"digest {actual} != pinned {expected}",
                file=sys.stderr,
            )
            failed = True

if privacy_only:
    validate_privacy_inventory()
    raise SystemExit(1 if failed else 0)

authority_closure = set()
if strict_digest:
    for relative, expected in (
        (pathlib.Path("Cargo.toml"), EXPECTED_ROOT_MANIFEST_DIGEST),
        (pathlib.Path("Cargo.lock"), EXPECTED_ROOT_LOCK_DIGEST),
    ):
        path = root / relative
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        if actual != expected:
            print(
                f"governance capability inventory: root {relative} digest "
                f"{actual} != pinned {expected}",
                file=sys.stderr,
            )
            failed = True
    try:
        metadata_process = subprocess.run(
            [str(cargo), "metadata", "--locked", "--format-version", "1"],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"governance capability inventory: Cargo metadata failed: {error}", file=sys.stderr)
        raise SystemExit(2)
    if metadata_process.returncode:
        print(
            "governance capability inventory: Cargo metadata failed under --locked: "
            f"{metadata_process.stderr[-4000:]}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        metadata = json.loads(metadata_process.stdout)
    except json.JSONDecodeError as error:
        print(f"governance capability inventory: invalid Cargo metadata: {error}", file=sys.stderr)
        raise SystemExit(2)
    packages_by_id = {
        package["id"]: package
        for package in metadata.get("packages", [])
        if isinstance(package, dict) and isinstance(package.get("id"), str)
    }
    workspace_ids = set(metadata.get("workspace_members", []))
    workspace_packages = {
        packages_by_id[package_id]["name"]
        for package_id in workspace_ids
        if package_id in packages_by_id
    }
    if workspace_packages != EXPECTED_WORKSPACE_PACKAGES or len(workspace_ids) != len(workspace_packages):
        print(
            "governance capability inventory: resolved workspace package identity drifted; "
            f"found {sorted(workspace_packages)}",
            file=sys.stderr,
        )
        failed = True
    resolved_nodes = {
        node["id"]: node
        for node in (metadata.get("resolve") or {}).get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    governance_ids = {
        package_id
        for package_id in workspace_ids
        if packages_by_id.get(package_id, {}).get("name") == "swarm-governance"
    }
    if len(governance_ids) != 1:
        print(
            "governance capability inventory: expected one resolved workspace "
            f"swarm-governance package, found {sorted(governance_ids)}",
            file=sys.stderr,
        )
        failed = True
    resolved_closure_ids = set(governance_ids)
    changed = True
    while changed:
        changed = False
        for package_id in workspace_ids - resolved_closure_ids:
            node = resolved_nodes.get(package_id, {})
            normal_dependencies = {
                dependency.get("pkg")
                for dependency in node.get("deps", [])
                if any(
                    kind.get("kind") is None
                    for kind in dependency.get("dep_kinds", [])
                    if isinstance(kind, dict)
                )
            }
            if normal_dependencies & resolved_closure_ids:
                resolved_closure_ids.add(package_id)
                changed = True
    authority_closure = {
        packages_by_id[package_id]["name"]
        for package_id in resolved_closure_ids
        if package_id in packages_by_id
    }
    if authority_closure != EXPECTED_AUTHORITY_REVERSE_CLOSURE:
        print(
            "governance capability inventory: resolved normal reverse dependency closure drifted; "
            f"found {sorted(authority_closure)}",
            file=sys.stderr,
        )
        failed = True
    manifests = {}
    crate_roots = {}
    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            print(f"governance capability inventory: cannot parse {manifest}: {error}", file=sys.stderr)
            raise SystemExit(2)
        package = document.get("package", {}).get("name")
        if not isinstance(package, str) or package in manifests:
            print(f"governance capability inventory: invalid or duplicate package in {manifest}", file=sys.stderr)
            raise SystemExit(2)
        manifests[package] = (manifest, document)
        crate_roots[package] = manifest.parent
    observed_targets = set()
    for package in sorted(EXPECTED_AUTHORITY_REVERSE_CLOSURE):
        manifest_entry = manifests.get(package)
        if manifest_entry is None:
            print(f"governance capability inventory: closure package {package} is missing", file=sys.stderr)
            failed = True
            continue
        manifest, _document = manifest_entry
        actual_manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        if actual_manifest_digest != EXPECTED_CLOSURE_MANIFEST_DIGESTS[package]:
            print(
                f"governance capability inventory: {package} manifest digest "
                f"{actual_manifest_digest} != pinned {EXPECTED_CLOSURE_MANIFEST_DIGESTS[package]}",
                file=sys.stderr,
            )
            failed = True
        package_root = crate_roots[package]
        package_entries = sorted(package_root.rglob("*"))
        symlinks = [path for path in package_entries if path.is_symlink()]
        package_files = [
            path for path in package_entries if path.is_file() and not path.is_symlink()
        ]
        package_inventory = "".join(
            f"{path.relative_to(root)}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n"
            for path in package_files
        )
        actual_package_inventory = (
            len(package_files),
            hashlib.sha256(package_inventory.encode()).hexdigest(),
        )
        expected_package_inventory = EXPECTED_CLOSURE_PACKAGE_FILE_INVENTORY[package]
        if symlinks or actual_package_inventory != expected_package_inventory:
            print(
                "governance capability inventory: complete regular-file identity for "
                f"{package} is {actual_package_inventory}, expected "
                f"{expected_package_inventory}; symlinks="
                f"{sorted(str(path.relative_to(root)) for path in symlinks)}",
                file=sys.stderr,
            )
            failed = True
        build_script = crate_roots[package] / "build.rs"
        if build_script.exists():
            print(
                "governance capability inventory: authority-closure packages may not "
                f"have a custom build target: {build_script.relative_to(root)}",
                file=sys.stderr,
            )
            failed = True
        metadata_packages = [
            candidate
            for package_id, candidate in packages_by_id.items()
            if package_id in workspace_ids and candidate.get("name") == package
        ]
        if len(metadata_packages) != 1:
            print(
                f"governance capability inventory: resolved closure package {package} "
                f"has {len(metadata_packages)} workspace identities",
                file=sys.stderr,
            )
            failed = True
            continue
        for target in metadata_packages[0].get("targets", []):
            kinds = set(target.get("kind", []))
            if "custom-build" in kinds:
                print(
                    "governance capability inventory: authority-closure packages may not "
                    f"have a resolved custom-build target: {target.get('src_path')}",
                    file=sys.stderr,
                )
                failed = True
            if not ({"lib", "bin"} & kinds):
                continue
            try:
                resolved_source = pathlib.Path(target["src_path"]).resolve().relative_to(root.resolve())
            except (KeyError, ValueError):
                print(
                    f"governance capability inventory: resolved target escaped the workspace: {target}",
                    file=sys.stderr,
                )
                failed = True
                continue
            observed_targets.add(resolved_source)
    if observed_targets != set(EXPECTED_CLOSURE_TARGET_ATTRIBUTES):
        print(
            "governance capability inventory: shipped authority-closure target roots drifted; "
            f"found {sorted(map(str, observed_targets))}",
            file=sys.stderr,
        )
        failed = True
    for path, attribute in EXPECTED_CLOSURE_TARGET_ATTRIBUTES.items():
        target = root / path
        raw = target.read_text(encoding="utf-8") if target.is_file() else ""
        if not raw.startswith(attribute + "\n"):
            print(
                f"governance capability inventory: {path} must begin with {attribute}",
                file=sys.stderr,
            )
            failed = True
    validate_privacy_inventory()

def cfg_test_external_module_sources() -> set[pathlib.Path]:
    test_sources = set()
    declaration = re.compile(
        r"(?m)^(?P<attrs>(?:[ \t]*#\s*\[[^\]\n]*\][ \t]*\n)+)"
        r"[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*;",
    )
    for declaring in sorted((root / "crates").glob("*/src/**/*.rs")):
        raw = declaring.read_text(encoding="utf-8")
        sanitized = production_source(raw)
        for match in declaration.finditer(sanitized):
            if not re.search(
                r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]",
                match.group("attrs"),
            ):
                continue
            path_match = re.search(r"#\s*\[\s*path\s*=", match.group("attrs"))
            if path_match is not None:
                value_start = match.start("attrs") + path_match.end()
                value_end = sanitized.find("]", value_start, match.end("attrs"))
                literal_text = raw[value_start:value_end].strip()
                try:
                    literal = json.loads(literal_text)
                except json.JSONDecodeError:
                    literal = None
                candidates = [declaring.parent / literal] if isinstance(literal, str) else []
            else:
                module = match.group("name")
                if declaring.stem in {"lib", "main", "mod"}:
                    candidates = [
                        declaring.parent / f"{module}.rs",
                        declaring.parent / module / "mod.rs",
                    ]
                else:
                    candidates = [
                        declaring.parent / declaring.stem / f"{module}.rs",
                        declaring.parent / declaring.stem / module / "mod.rs",
                    ]
            resolved = [candidate.resolve() for candidate in candidates if candidate.is_file()]
            if len(resolved) != 1:
                print(
                    "governance capability inventory: cfg(test) external module did not "
                    f"resolve exactly once: {declaring.relative_to(root)}:{match.group('name')}",
                    file=sys.stderr,
                )
                raise SystemExit(2)
            test_sources.add(resolved[0])
    return test_sources

cfg_test_sources = cfg_test_external_module_sources()
source_files = sorted(
    path
    for path in (root / "crates").glob("*/src/**/*.rs")
    if path.name not in {"test.rs", "tests.rs"}
    and "tests" not in path.relative_to(root).parts
    and path.resolve() not in cfg_test_sources
)
if not source_files:
    print("no shipped Rust source found for governance capability inventory", file=sys.stderr)
    raise SystemExit(2)
raw_sources = {
    path.relative_to(root): path.read_text(encoding="utf-8")
    for path in source_files
}
if strict_digest:
    for relative, expected in EXPECTED_CLOSURE_NON_RS_RUST_DIGESTS.items():
        source_path = root / relative
        actual = hashlib.sha256(source_path.read_bytes()).hexdigest() if source_path.is_file() else None
        if source_path.is_symlink() or actual != expected:
            print(
                "governance capability inventory: sanctioned non-.rs Rust source "
                f"{relative} digest {actual} != pinned {expected}",
                file=sys.stderr,
            )
            failed = True
        if source_path.is_file() and not source_path.is_symlink():
            raw_sources[relative] = source_path.read_text(encoding="utf-8")
sources = {}
for path, raw in raw_sources.items():
    try:
        sources[path] = without_cfg_test_modules(production_source(raw))
    except ValueError as error:
        print(
            f"governance capability inventory: cannot sanitize production source "
            f"{path}: {error}",
            file=sys.stderr,
        )
        raise SystemExit(2)
def reject(label: str, pattern: str) -> None:
    global failed
    matches = [path for path, source in sources.items() if re.search(pattern, source, re.DOTALL)]
    if matches:
        rendered = ", ".join(str(path) for path in matches)
        print(f"governance capability inventory: {label}: {rendered}", file=sys.stderr)
        failed = True

if strict_digest:
    closure_sources = {
        path: source
        for path, source in sources.items()
        if len(path.parts) > 2
        and path.parts[0] == "crates"
        and path.parts[1] in authority_closure
    }
    include_tokens = [
        path
        for path, source in closure_sources.items()
        if path not in EXPECTED_CLOSURE_NON_RS_RUST_DIGESTS
        and re.search(r"\binclude(?:_bytes|_str)?\b", source)
    ]
    if include_tokens:
        print(
            "governance capability inventory: production include/include_str/include_bytes "
            "tokens are forbidden outside the exact sanctioned core.inc; "
            "compiler source inputs must be ordinary modules or the exact sanctioned "
            f"#[path] source: {', '.join(map(str, include_tokens))}",
            file=sys.stderr,
        )
        failed = True
    macro_definitions = [
        path
        for path, source in closure_sources.items()
        if re.search(r"\bmacro_rules\s*!", source)
    ]
    if macro_definitions:
        print(
            "governance capability inventory: production macro_rules! definitions are "
            "forbidden in the governance reverse closure because they can synthesize "
            f"source directives: {', '.join(map(str, macro_definitions))}",
            file=sys.stderr,
        )
        failed = True
    observed_path_directives = set()
    for relative, source in closure_sources.items():
        raw = raw_sources[relative]
        cfg_attr_paths = list(re.finditer(
            r"#\s*\[\s*cfg_attr\b[^\]]*\bpath\s*=",
            source,
            re.DOTALL,
        ))
        if cfg_attr_paths:
            print(
                "governance capability inventory: cfg_attr path redirection is forbidden: "
                f"{relative}",
                file=sys.stderr,
            )
            failed = True
        for match in re.finditer(r"#\s*\[\s*path\s*=", source):
            closing = source.find("]", match.end())
            if closing < 0:
                print(
                    f"governance capability inventory: unterminated #[path] in {relative}",
                    file=sys.stderr,
                )
                failed = True
                continue
            literal_text = raw[match.end():closing].strip()
            try:
                literal = json.loads(literal_text)
            except json.JSONDecodeError:
                literal = None
            if not isinstance(literal, str) or not literal:
                print(
                    "governance capability inventory: #[path] must use one exact ordinary "
                    f"string literal: {relative}:{literal_text!r}",
                    file=sys.stderr,
                )
                failed = True
                continue
            candidate = (root / relative).parent / literal
            try:
                resolved = candidate.resolve(strict=True)
                resolved_relative = resolved.relative_to(root.resolve())
            except (OSError, ValueError):
                print(
                    "governance capability inventory: #[path] source escaped or is missing: "
                    f"{relative}:{literal}",
                    file=sys.stderr,
                )
                failed = True
                continue
            cursor = root.resolve()
            symlinked = False
            for component in resolved_relative.parts:
                cursor /= component
                if cursor.is_symlink():
                    symlinked = True
                    break
            if symlinked or not resolved.is_file():
                print(
                    "governance capability inventory: #[path] source must resolve through "
                    f"regular files only: {relative}:{literal}",
                    file=sys.stderr,
                )
                failed = True
                continue
            observed_path_directives.add((relative, literal, resolved_relative))
    if observed_path_directives != EXPECTED_CLOSURE_PATH_DIRECTIVES:
        print(
            "governance capability inventory: production #[path] source graph drifted; "
            f"found {sorted((str(a), b, str(c)) for a, b, c in observed_path_directives)}",
            file=sys.stderr,
        )
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
canonical_raw_source = raw_sources.get(canonical, "")
if not canonical_raw_source.startswith("#![forbid(unsafe_code)]\n"):
    print(
        "governance capability inventory: swarm-governance must begin with "
        "#![forbid(unsafe_code)]",
        file=sys.stderr,
    )
    failed = True
if strict_digest:
    actual_source_digest = hashlib.sha256(canonical_raw_source.encode()).hexdigest()
    if actual_source_digest != EXPECTED_GOVERNANCE_SOURCE_DIGEST:
        print(
            "governance capability inventory: canonical swarm-governance source "
            f"digest {actual_source_digest} != pinned {EXPECTED_GOVERNANCE_SOURCE_DIGEST}",
            file=sys.stderr,
        )
        failed = True
if not re.search(
    r"#\s*\[\s*derive\s*\(\s*Clone\s*\)\s*\]\s*"
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

all_impl_items = [
    (path, header, start, end, item)
    for path, source in sources.items()
    for header, start, end, item in braced_items(path, source, "impl")
]
authority_impl_items = [
    (path, header, start, end, item)
    for path, header, start, end, item in all_impl_items
    if re.search(r"\bGovernanceAuthority\b", item)
]
fixture_allowed_impls = {
    (canonical, "implstd::fmt::DebugforGovernanceAuthority"),
    (canonical, "implGovernancePolicy"),
    (canonical, "implGovernanceAuthority"),
}
allowed_impls = (
    set(EXPECTED_STRICT_AUTHORITY_IMPL_DIGESTS)
    if strict_digest
    else fixture_allowed_impls
)
observed_impls = {
    (path, header)
    for path, header, _start, _end, _item in authority_impl_items
}
if observed_impls != allowed_impls or len(authority_impl_items) != len(allowed_impls):
    rendered = ", ".join(
        f"{path}:{header}"
        for path, header, _start, _end, _item in authority_impl_items
    ) or "none"
    print(
        "governance capability inventory: every impl whose source mentions the "
        "authority must match the exact inventory; "
        f"found {rendered}",
        file=sys.stderr,
    )
    failed = True
if strict_digest:
    for path, header, start, end, _item in authority_impl_items:
        expected = EXPECTED_STRICT_AUTHORITY_IMPL_DIGESTS.get((path, header))
        actual = hashlib.sha256(
            canonical_tokens(raw_sources[path][start:end]).encode()
        ).hexdigest()
        if expected != actual:
            print(
                "governance capability inventory: authority-referencing impl "
                f"{path}:{header} digest {actual} != pinned {expected}",
                file=sys.stderr,
            )
            failed = True

main_impls = [
    (start, end)
    for path, header, start, end, _item in authority_impl_items
    if path == canonical and header == "implGovernanceAuthority"
]
if len(main_impls) == 1:
    start, end = main_impls[0]
    main_impl = canonical_source[start:end]
    try:
        methods = inherent_method_headers(main_impl)
    except ValueError as error:
        print(f"governance capability inventory: {error}", file=sys.stderr)
        failed = True
        methods = []
    observed_methods = dict(methods)
    if len(observed_methods) != len(methods) or observed_methods != ALLOWED_AUTHORITY_METHODS:
        rendered = ", ".join(f"{name}={header}" for name, header in methods) or "none"
        print(
            "governance capability inventory: public inherent authority method "
            f"allowlist drifted; found {rendered}",
            file=sys.stderr,
        )
        failed = True
    if strict_digest:
        raw_item = raw_sources[canonical][start:end]
        actual_digest = hashlib.sha256(canonical_tokens(raw_item).encode()).hexdigest()
        if actual_digest != EXPECTED_AUTHORITY_IMPL_DIGEST:
            print(
                "governance capability inventory: canonical GovernanceAuthority impl "
                f"digest {actual_digest} != pinned {EXPECTED_AUTHORITY_IMPL_DIGEST}",
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

construction_sites = []
for path, source in sources.items():
    for match in re.finditer(r"\bGovernanceAuthority\s*\{", source):
        line_start = source.rfind("\n", 0, match.start()) + 1
        prefix = source[line_start:match.start()]
        if re.search(r"\b(?:pub\s+)?struct\s*$", prefix):
            continue
        if re.search(r"\bimpl\b[^{};]*$", prefix):
            continue
        construction_sites.append((path, match.start()))
if len(construction_sites) != 1 or any(path != canonical for path, _ in construction_sites):
    rendered = ", ".join(f"{path}:{source.count(chr(10), 0, offset) + 1}" for path, offset in construction_sites for source in [sources[path]]) or "none"
    print(
        "governance capability inventory: expected only the authenticated mint "
        f"construction; found {rendered}",
        file=sys.stderr,
    )
    failed = True

authority_public_apis = [
    (path, header)
    for path, source in sources.items()
    for header in public_function_headers(source)
    if re.search(r"\bGovernanceAuthority\b", header)
]
fixture_public_apis = {(canonical, EXPECTED_MINT_HEADER)}
expected_public_apis = (
    EXPECTED_STRICT_AUTHORITY_PUBLIC_APIS
    if strict_digest
    else fixture_public_apis
)
if set(authority_public_apis) != expected_public_apis or len(authority_public_apis) != len(expected_public_apis):
    rendered = ", ".join(f"{path}:{header}" for path, header in authority_public_apis) or "none"
    print(
        "governance capability inventory: public authority API inventory drifted; "
        f"found {rendered}",
        file=sys.stderr,
    )
    failed = True

for path, source in sources.items():
    for header in public_function_headers(source):
        return_type = header.split("->", 1)[1] if "->" in header else ""
        if re.search(r"\bGovernanceAuthority\b", return_type) and header != EXPECTED_MINT_HEADER:
            print(
                "governance capability inventory: public function can return or borrow a governance "
                f"authority outside the authenticated mint: {path}:{header}",
                file=sys.stderr,
            )
            failed = True

erased_return = re.compile(
    r"\bdyn\s+(?:(?:std::)?any::)?Any\b|"
    r"\bdyn\s+(?:(?:std::)?fmt::)?(?:Debug|Display)\b|"
    r"->[^;{]*\bimpl\s+(?:(?:std::)?any::)?Any\b|"
    r"->[^;{]*\bimpl\s+(?:(?:std::)?fmt::)?(?:Debug|Display)\b",
    re.DOTALL,
)
for path, source in sources.items():
    for header, _start, _end, item in braced_items(path, source, "trait"):
        if re.search(r"\bGovernanceAuthority\b", item):
            print(
                "governance capability inventory: trait methods and associated items "
                f"may not expose a governance authority: {path}:{header}",
                file=sys.stderr,
            )
            failed = True
        if (
            erased_return.search(item)
            and re.search(r"\b(?:authority|governance)\b", item)
        ):
            print(
                "governance capability inventory: trait-based type erasure may not "
                f"expose authority storage: {path}:{header}",
                file=sys.stderr,
            )
            failed = True
for path, header, _start, _end, item in all_impl_items:
    if erased_return.search(item) and re.search(r"\b(?:authority|governance)\b", item):
        print(
            "governance capability inventory: impl-based type erasure may not "
            f"expose authority storage: {path}:{header}",
            file=sys.stderr,
        )
        failed = True

dangerous_authority_primitive = re.compile(
    r"\bunsafe\b|\btransmute(?:_copy)?\b|\bfrom_raw(?:_bits)?\b|"
    r"\bMaybeUninit\b|\bzeroed\b|\bunion\s+[A-Za-z_]\w*|"
    r"\b(?:Box|Arc|Rc|Vec|CString)::from_raw\b|\bstd::ptr::",
    re.DOTALL,
)
for path, source in sources.items():
    crate_name = path.parts[1] if len(path.parts) > 2 and path.parts[0] == "crates" else None
    if strict_digest and crate_name not in authority_closure:
        continue
    if dangerous_authority_primitive.search(source):
        print(
            "governance capability inventory: authority-closure production source "
            f"contains a forbidden unsafe/raw-memory primitive irrespective of type spelling: {path}",
            file=sys.stderr,
        )
        failed = True
for path, header, _start, _end, item in authority_impl_items:
    if dangerous_authority_primitive.search(item):
        print(
            "governance capability inventory: authority-referencing impl uses a "
            f"forbidden unsafe/raw-memory primitive: {path}:{header}",
            file=sys.stderr,
        )
        failed = True

reject("backend trait is forbidden", r"\btrait\s+GovernanceAuthority\b")
reject("legacy governance seal is forbidden", r"\bSealedGovernanceAuthority\b")
reject("trait-object governance backend is forbidden", r"\bdyn\s+GovernanceAuthority\b")
reject(
    "GovernanceAuthority alias is forbidden",
    r"\btype\b[^;{}]*\bGovernanceAuthority\b[^;]*;",
)
reject(
    "GovernanceAuthority renamed re-export is forbidden",
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?use\s+[^;]*"
    r"\bGovernanceAuthority\s+as\s+[A-Za-z_]\w*",
)
reject(
    "generic governance installer is forbidden",
    r"\bpub\s+fn\s+with_governance_authority\s*<|"
    r"\bwith_governance_authority\s*\([^)]*(?:impl\s+Into|T\s*:\s*Into)\s*<\s*GovernanceAuthority",
)
reject(
    "macro-generated governance authority API is forbidden",
    r"\bmacro_rules\s*!\s*[A-Za-z_]\w*[^;]*\bGovernanceAuthority\b|"
    r"\b[A-Za-z_]\w*\s*!\s*[({][^;{}]*\bGovernanceAuthority\b",
)
reject(
    "public GovernanceAuthority static/constant is forbidden",
    r"\bpub\s+(?:static|const)\s+[A-Za-z_]\w*\s*:\s*(?:[A-Za-z_]\w*::)*GovernanceAuthority\b",
)
reject(
    "public GovernanceAuthority field is forbidden",
    r"\bpub(?:\s*\([^)]*\))?\s+[A-Za-z_]\w*\s*:\s*"
    r"[^,;}]*\bGovernanceAuthority\b",
)
reject(
    "Default/Deserialize raw construction derive is forbidden",
    r"#\s*\[\s*derive\s*\([^\]]*\b(?:Default|Deserialize)\b[^\]]*\)\s*\]\s*"
    r"pub\s+struct\s+GovernanceAuthority\b",
)

def dependency_file_for_artifact(message: dict) -> pathlib.Path | None:
    target = message.get("target", {})
    kinds = set(target.get("kind", []))
    for rendered in message.get("filenames", []):
        artifact = pathlib.Path(rendered)
        candidates = []
        if artifact.suffix in {".rmeta", ".rlib"}:
            stem = artifact.stem
            if stem.startswith("lib"):
                stem = stem[3:]
            candidates.append(artifact.with_name(stem + ".d"))
        if "bin" in kinds and not artifact.suffix:
            candidates.append(artifact.with_suffix(".d"))
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    return None

def repo_inputs_from_dep_info(path: pathlib.Path) -> set[pathlib.Path]:
    text = path.read_text(encoding="utf-8").replace("\\\n", " ")
    first_rule = text.splitlines()[0] if text.splitlines() else ""
    if ":" not in first_rule:
        raise ValueError(f"dep-info {path} has no primary dependency rule")
    inputs = set()
    for rendered in shlex.split(first_rule.split(":", 1)[1], posix=True):
        candidate = pathlib.Path(rendered)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        try:
            relative = resolved.relative_to(root.resolve())
        except ValueError as error:
            raise ValueError(f"dep-info input escaped the workspace: {resolved}") from error
        if relative.parts and relative.parts[0] == "target":
            continue
        if not resolved.is_file():
            raise ValueError(f"dep-info input is not a regular file: {relative}")
        inputs.add(relative)
    return inputs

def validate_compiler_source_inventory() -> None:
    global failed
    if failed and not force_dep_info:
        return
    target_dir = assurance_target.resolve()
    cargo_home = target_dir / "cargo-home"
    if cargo_home.is_symlink():
        cargo_home.unlink()
    elif cargo_home.exists():
        shutil.rmtree(cargo_home)
    cargo_home.mkdir(parents=True)
    for name in ("registry", "git"):
        source = cache_source / name
        destination = cargo_home / name
        if source.is_dir():
            destination.symlink_to(source, target_is_directory=True)
        else:
            destination.mkdir()
    environment = dict(os.environ)
    for name in list(environment):
        if (
            name.startswith("CARGO_")
            or name.startswith("RUSTUP_")
            or name in {"RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS"}
        ):
            environment.pop(name, None)
    environment.update({
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target_dir),
    })
    forced_fixture_compile = force_dep_info and failed
    expected_dep_info = (
        {
            pathlib.Path("crates/swarm-runtime-workbench/src/lib.rs"):
                EXPECTED_CLOSURE_TARGET_DEP_INFO[
                    pathlib.Path("crates/swarm-runtime-workbench/src/lib.rs")
                ],
        }
        if forced_fixture_compile
        else EXPECTED_CLOSURE_TARGET_DEP_INFO
    )
    command = [
        str(cargo),
        "check",
        "--locked",
        "--offline",
        "--lib",
        "--bins",
        "--message-format=json",
    ]
    selected_packages = (
        {"swarm-runtime-workbench"}
        if forced_fixture_compile
        else EXPECTED_AUTHORITY_REVERSE_CLOSURE
    )
    for package in sorted(selected_packages):
        command.extend(("-p", package))
    try:
        process = subprocess.run(
            command,
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(
            f"governance capability inventory: controlled primary-package compile failed: {error}",
            file=sys.stderr,
        )
        failed = True
        return
    if process.returncode:
        print(
            "governance capability inventory: controlled primary-package compile failed "
            "with closure packages selected directly (dependency cap-lints are not an "
            f"authority boundary): {(process.stdout + process.stderr)[-8000:]}",
            file=sys.stderr,
        )
        failed = True
        return
    artifacts = {}
    for line in process.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        package_id = message.get("package_id")
        if package_id not in resolved_closure_ids:
            continue
        target = message.get("target", {})
        kinds = set(target.get("kind", []))
        if not ({"lib", "bin"} & kinds):
            continue
        try:
            target_root = pathlib.Path(target["src_path"]).resolve().relative_to(root.resolve())
        except (KeyError, ValueError):
            print(
                f"governance capability inventory: compiled target escaped the workspace: {target}",
                file=sys.stderr,
            )
            failed = True
            continue
        if target_root not in expected_dep_info:
            continue
        dep_info = dependency_file_for_artifact(message)
        if dep_info is None:
            print(
                "governance capability inventory: no compiler dep-info accompanied "
                f"compiled target {target_root}",
                file=sys.stderr,
            )
            failed = True
            continue
        artifacts.setdefault(target_root, []).append(dep_info)
    if set(artifacts) != set(expected_dep_info) or any(
        len(values) != 1 for values in artifacts.values()
    ):
        print(
            "governance capability inventory: controlled compiler target/dep-info "
            "inventory drifted; found "
            f"{sorted((str(path), len(values)) for path, values in artifacts.items())}",
            file=sys.stderr,
        )
        failed = True
    for target_root, dep_infos in artifacts.items():
        if len(dep_infos) != 1:
            continue
        try:
            inputs = repo_inputs_from_dep_info(dep_infos[0])
        except (OSError, UnicodeError, ValueError) as error:
            print(
                f"governance capability inventory: cannot read {target_root} dep-info: {error}",
                file=sys.stderr,
            )
            failed = True
            continue
        rendered = "".join(f"{path}\n" for path in sorted(inputs))
        actual = (len(inputs), hashlib.sha256(rendered.encode()).hexdigest())
        expected = expected_dep_info[target_root]
        if actual != expected:
            print(
                "governance capability inventory: compiler-consumed source/input set "
                f"for {target_root} is count/digest {actual}, expected {expected}; "
                f"found {sorted(map(str, inputs))}",
                file=sys.stderr,
            )
            failed = True

if strict_digest and (force_dep_info or not failed):
    validate_compiler_source_inventory()
raise SystemExit(1 if failed else 0)
PY
}
# ---------------------------------------------------------------------------
# THE FIXTURE. Runs on every invocation.
# ---------------------------------------------------------------------------
if [[ "$SINGLE_GOVERNOR_MUTATION_PROBE" == "0" ]]; then
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-single-governor-key.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_failures=0
fixture_adversarial_cases=0
fixture_clean_controls=0

printf '%s\n' 'let keys: &[SigningKey];' > "$FIXTURE_DIR/portable-awk-ere.rs"
portable_awk_output="$(
  scan_file "$FIXTURE_DIR/portable-awk-ere.rs" \
    2>"$FIXTURE_DIR/portable-awk-ere.stderr"
)"
if [[ -s "$FIXTURE_DIR/portable-awk-ere.stderr" \
  || "$portable_awk_output" != *'let keys: &[SigningKey];' ]]; then
  echo "FIXTURE FAILURE: the signing-key ERE is not warning-free and equivalent on GNU/BSD awk" >&2
  sed -n '1,20p' "$FIXTURE_DIR/portable-awk-ere.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi

plant() {
  local name="$1"
  local body="$2"
  printf '%s\n' "$body" > "$FIXTURE_DIR/$name.rs"
}

expect_caught() {
  local name="$1"
  local description="$2"
  local hits
  fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
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
  fixture_clean_controls=$((fixture_clean_controls + 1))
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
# Fixture prose must retain literal Rust tokens.
# shellcheck disable=SC2016
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

CANONICAL_CAPABILITY='#![forbid(unsafe_code)]
pub struct GovernancePolicy;
#[derive(Clone)]
pub struct GovernanceAuthority {
    policy: Arc<GovernancePolicy>,
}
pub struct GovernanceAuthorityError;
impl std::fmt::Debug for GovernanceAuthority {
    fn fmt(&self, formatter: &mut Formatter) -> std::fmt::Result {
        todo!()
    }
}
impl GovernancePolicy {
    pub fn authority(self: &Arc<Self>) -> Result<GovernanceAuthority, GovernanceAuthorityError> {
        Ok(GovernanceAuthority { policy: Arc::clone(self) })
    }
}
impl GovernanceAuthority {
    pub fn same_policy(&self, other: &Self) -> bool { todo!() }
    pub fn identity(&self) -> GovernanceAuthorityIdentity { todo!() }
    pub fn authorize_partition_request(
        &self,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<Option<serde_json::Value>, String> { todo!() }
    pub fn verify_and_consume_action_authorization(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> { todo!() }
    pub fn verify_and_consume_veto(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        now_ms: i64,
    ) -> Result<serde_json::Value, String> { todo!() }
    pub fn begin_human_authorization_hold(
        &self,
        request: &ActionRequest,
        receipt: &serde_json::Value,
        policy_decision: &PolicyDecision,
        now_ms: i64,
    ) -> Result<GovernedHumanAuthorizationHold, String> { todo!() }
    pub fn bind_human_approval_set(
        &self,
        hold_id: &str,
        approval_set_id: &str,
        approval_set_digest: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> { todo!() }
    pub fn reconcile_human_approval_set(
        &self,
        approval_set_id: &str,
        approval_set_digest: &str,
        approval_evidence_ref: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> { todo!() }
    pub fn pending_human_authorization(
        &self,
        approval_set_id: &str,
    ) -> Result<GovernedHumanAuthorizationHold, String> { todo!() }
    pub fn verify_and_consume_human_authorization(
        &self,
        hold_id: &str,
        approval_set_id: &str,
        approval_set_digest: &str,
        now_ms: i64,
    ) -> Result<ConsumedGovernedHumanAuthorization, String> { todo!() }
    pub fn is_partitioned(&self) -> bool { todo!() }
    pub fn note_partition_veto(&self, request: &ActionRequest, reason: &str, now_ms: i64) {
        todo!()
    }
    pub fn drain_runtime_events(&self) -> Vec<GovernanceRuntimeEventRecord> { todo!() }
    pub fn status_report(&self) -> GovernanceStatusReport { todo!() }
    pub fn attest_release(
        &self,
        subject: &serde_json::Value,
        now_ms: i64,
    ) -> Option<serde_json::Value> { todo!() }
    pub fn governor_public_keys(&self) -> BTreeSet<AgentId> { todo!() }
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
  fixture_clean_controls=$((fixture_clean_controls + 1))
  if ! scan_governance_capability_inventory "$FIXTURE_DIR/capability-$name"; then
    echo "FIXTURE FAILURE: the capability inventory rejected $description" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

expect_capability_rejected() {
  local name="$1"
  local description="$2"
  fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
  if scan_governance_capability_inventory "$FIXTURE_DIR/capability-$name" >/dev/null 2>&1; then
    echo "FIXTURE FAILURE: the capability inventory accepted $description" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

plant_strict_privacy_fixture() {
  local name="$1"
  local fixture_root="$FIXTURE_DIR/privacy-$name"
  local crate_dir
  local crate_name
  mkdir -p "$fixture_root"
  cp "$ROOT_DIR/Cargo.toml" "$fixture_root/Cargo.toml"
  cp "$ROOT_DIR/Cargo.lock" "$fixture_root/Cargo.lock"
  cp -R "$ROOT_DIR/rulesets" "$fixture_root/rulesets"
  for crate_dir in "$ROOT_DIR"/crates/*; do
    [[ -d "$crate_dir" && -f "$crate_dir/Cargo.toml" ]] || continue
    crate_name="${crate_dir##*/}"
    mkdir -p "$fixture_root/crates/$crate_name"
    cp -R "$crate_dir/." "$fixture_root/crates/$crate_name/"
  done
  printf '%s\n' "$fixture_root"
}

expect_strict_privacy_clean() {
  local fixture_root="$1"
  local description="$2"
  fixture_clean_controls=$((fixture_clean_controls + 1))
  if ! scan_governance_capability_inventory "$fixture_root" privacy; then
    echo "FIXTURE FAILURE: the strict privacy inventory rejected $description" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

expect_strict_privacy_rejected() {
  local fixture_root="$1"
  local description="$2"
  fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
  if scan_governance_capability_inventory "$fixture_root" privacy >/dev/null 2>&1; then
    echo "FIXTURE FAILURE: the strict privacy inventory accepted $description" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

plant_compiler_input_fixture() {
  local fixture_root="$FIXTURE_DIR/compiler-input"
  if [[ ! -d "$fixture_root" ]]; then
    plant_strict_privacy_fixture compiler-input >/dev/null
    mv "$FIXTURE_DIR/privacy-compiler-input" "$fixture_root"
    cp \
      "$fixture_root/crates/swarm-runtime-workbench/src/lib.rs" \
      "$fixture_root/crates/swarm-runtime-workbench/src/lib.rs.canonical"
  fi
  cp \
    "$fixture_root/crates/swarm-runtime-workbench/src/lib.rs.canonical" \
    "$fixture_root/crates/swarm-runtime-workbench/src/lib.rs"
  rm -f \
    "$fixture_root/crates/swarm-runtime-workbench/assurance_escape.inc" \
    "$fixture_root/crates/swarm-runtime-workbench/capability_forge.txt" \
    "$fixture_root/assurance_escape.rs" \
    "$FIXTURE_DIR/authority_escape_external.rs"
  printf '%s\n' "$fixture_root"
}

prepare_source_cargo_home() {
  # The cache links are invocation-scoped. A protected negative-registry run
  # intentionally supplies a different cache source; reusing its empty
  # directory during a later standalone run produces a false offline failure.
  local source_cargo_home="$FIXTURE_DIR/source-cargo-home"
  mkdir -p "$source_cargo_home"
  local cache_name
  for cache_name in registry git; do
    if [[ -d "$SINGLE_GOVERNOR_CACHE_SOURCE/$cache_name" \
      && ! -e "$source_cargo_home/$cache_name" \
      && ! -L "$source_cargo_home/$cache_name" ]]; then
      ln -s \
        "$SINGLE_GOVERNOR_CACHE_SOURCE/$cache_name" \
        "$source_cargo_home/$cache_name"
    elif [[ ! -e "$source_cargo_home/$cache_name" \
      && ! -L "$source_cargo_home/$cache_name" ]]; then
      mkdir "$source_cargo_home/$cache_name"
    fi
  done
  printf '%s\n' "$source_cargo_home"
}

write_unsafe_compiler_input() {
  local path="$1"
  local cfg_attribute="${2:-}"
  {
    printf '%s\n' \
    'use std::sync::Arc;' \
    'use swarm_runtime::containment::ContainmentSweep;'
    if [[ -n "$cfg_attribute" ]]; then
      printf '%s\n' "$cfg_attribute"
    fi
    printf '%s\n' \
    'pub fn install_assurance_escape(' \
    '    raw: Arc<()>,' \
    '    sweep: ContainmentSweep,' \
    ') -> ContainmentSweep {' \
    '    let authority = unsafe { std::mem::transmute_copy(&raw) };' \
    '    std::mem::forget(raw);' \
    '    sweep.with_governance_authority(authority)' \
    '}'
  } > "$path"
}

expect_compiler_input_builds() {
  local fixture_root="$1"
  local name="$2"
  local mode="$3"
  local cargo_args=(
    check --manifest-path "$fixture_root/Cargo.toml"
    --locked --offline -p swarm-runtime-workbench --lib
  )
  if [[ "$mode" == "cap-lints" ]]; then
    cargo_args=(
      rustc --manifest-path "$fixture_root/Cargo.toml"
      --locked --offline -p swarm-runtime-workbench --lib -- --cap-lints allow
    )
  elif [[ "$mode" == "cap-lints-release-cfg" ]]; then
    cargo_args=(
      rustc --manifest-path "$fixture_root/Cargo.toml"
      --locked --offline -p swarm-runtime-workbench --lib --
      --cap-lints allow -C debug-assertions=no
    )
  fi
  fixture_clean_controls=$((fixture_clean_controls + 1))
  if [[ "$SINGLE_GOVERNOR_MUTATION_PROBE" == "1" ]]; then
    return
  fi
  local source_target="$ROOT_DIR/target/single-governor-source-inventory"
  local source_cargo_home
  source_cargo_home="$(prepare_source_cargo_home)"
  if ! CARGO_HOME="$source_cargo_home" CARGO_TARGET_DIR="$source_target" \
    "$SINGLE_GOVERNOR_CARGO" "${cargo_args[@]}" \
    >"$FIXTURE_DIR/${name}.stdout" \
    2>"$FIXTURE_DIR/${name}.stderr"; then
    echo "FIXTURE FAILURE: Cargo rejected valid compiler-input control $name" >&2
    sed -n '1,60p' "$FIXTURE_DIR/${name}.stderr" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

expect_compiler_input_rejected() {
  local fixture_root="$1"
  local name="$2"
  local mode="$3"
  local diagnostic="$4"
  if [[ "$SINGLE_GOVERNOR_MUTATION_PROBE" == "1" \
    && "$mode" == "strict-force-depinfo" ]]; then
    mode="strict"
    diagnostic="complete regular-file identity"
  fi
  fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
  if scan_governance_capability_inventory "$fixture_root" "$mode" \
    >"$FIXTURE_DIR/${name}-gate.stdout" \
    2>"$FIXTURE_DIR/${name}-gate.stderr"; then
    echo "FIXTURE FAILURE: compiler source-input inventory accepted $name" >&2
    fixture_failures=$((fixture_failures + 1))
  elif ! grep -Fq "$diagnostic" "$FIXTURE_DIR/${name}-gate.stderr"; then
    echo "FIXTURE FAILURE: $name failed without exercising $diagnostic" >&2
    sed -n '1,80p' "$FIXTURE_DIR/${name}-gate.stderr" >&2
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

CAPABILITY_UNCHECKED="${CANONICAL_CAPABILITY}"$'\n''impl GovernanceAuthority {
    pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }
}'
CAPABILITY_GENERIC_CONSTRUCTOR="${CANONICAL_CAPABILITY}"$'\n''impl GovernanceAuthority {
    pub fn unchecked<T: Into<Arc<GovernancePolicy>>>(policy: T) -> Self {
        Self { policy: policy.into() }
    }
}'
CAPABILITY_HELPER_CONSTRUCTOR="${CANONICAL_CAPABILITY}"$'\n''impl GovernanceAuthority {
    fn from_raw(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }
    pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self::from_raw(policy) }
}'
CAPABILITY_SWAP_POLICY="${CANONICAL_CAPABILITY}"$'\n''impl GovernanceAuthority {
    pub fn swap_policy(&mut self, policy: Arc<GovernancePolicy>) { self.policy = policy; }
}'
CAPABILITY_RAW_GETTER="${CANONICAL_CAPABILITY}"$'\n''impl GovernanceAuthority {
    pub fn policy(&self) -> &GovernancePolicy { &self.policy }
}'

if [[ "$CAPABILITY_GENERIC_CONSTRUCTOR" != *'Self { policy: policy.into() }'* ]]; then
  echo "FIXTURE FAILURE: multiline capability fixtures still use non-portable Bash pattern replacement" >&2
  fixture_failures=$((fixture_failures + 1))
fi

plant_capability_fixture unchecked_associated "$CAPABILITY_UNCHECKED"
plant_capability_fixture generic_associated "$CAPABILITY_GENERIC_CONSTRUCTOR"
plant_capability_fixture helper_constructor "$CAPABILITY_HELPER_CONSTRUCTOR"
plant_capability_fixture swap_policy "$CAPABILITY_SWAP_POLICY"
plant_capability_fixture raw_policy_getter "$CAPABILITY_RAW_GETTER"
plant_capability_fixture alias_constructor "$CANONICAL_CAPABILITY" \
  'pub type AuthorityAlias = GovernanceAuthority;
   pub fn unchecked(policy: Arc<GovernancePolicy>) -> AuthorityAlias {
       GovernanceAuthority { policy }
   }'
plant_capability_fixture private_alias_inherent "$CANONICAL_CAPABILITY" \
  'type AuthorityAlias = GovernanceAuthority;
   impl AuthorityAlias {
       pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }
   }'
plant_capability_fixture private_use_alias_inherent "$CANONICAL_CAPABILITY" \
  'use crate::GovernanceAuthority as AuthorityAlias;
   impl AuthorityAlias {
       pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }
   }'
plant_capability_fixture macro_constructor "$CANONICAL_CAPABILITY" \
  'macro_rules! mint_unchecked {
       () => {
           pub fn unchecked(policy: Arc<GovernancePolicy>) -> GovernanceAuthority {
               GovernanceAuthority { policy }
           }
       };
   }
   mint_unchecked!();'
plant_capability_fixture from_raw "$CANONICAL_CAPABILITY" \
  'impl From<Arc<GovernancePolicy>> for GovernanceAuthority {
       fn from(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }
   }'
plant_capability_fixture try_from_raw "$CANONICAL_CAPABILITY" \
  'impl TryFrom<Arc<GovernancePolicy>> for GovernanceAuthority {
       type Error = GovernanceAuthorityError;
       fn try_from(policy: Arc<GovernancePolicy>) -> Result<Self, Self::Error> {
           Ok(Self { policy })
       }
   }'
plant_capability_fixture default_impl "$CANONICAL_CAPABILITY" \
  'impl Default for GovernanceAuthority {
       fn default() -> Self { todo!() }
   }'
plant_capability_fixture as_ref "$CANONICAL_CAPABILITY" \
  'impl AsRef<GovernancePolicy> for GovernanceAuthority {
       fn as_ref(&self) -> &GovernancePolicy { &self.policy }
   }'
plant_capability_fixture as_mut "$CANONICAL_CAPABILITY" \
  'impl AsMut<GovernancePolicy> for GovernanceAuthority {
       fn as_mut(&mut self) -> &mut GovernancePolicy { Arc::make_mut(&mut self.policy) }
   }'
plant_capability_fixture borrow "$CANONICAL_CAPABILITY" \
  'impl std::borrow::Borrow<GovernancePolicy> for GovernanceAuthority {
       fn borrow(&self) -> &GovernancePolicy { &self.policy }
   }'
plant_capability_fixture manual_clone "$CANONICAL_CAPABILITY" \
  'impl Clone for GovernanceAuthority {
       fn clone(&self) -> Self { Self { policy: Arc::clone(&self.policy) } }
   }'
plant_capability_fixture deserialize_impl "$CANONICAL_CAPABILITY" \
  'impl Deserialize for GovernanceAuthority {
       fn deserialize<D: Deserializer>(deserializer: D) -> Result<Self, D::Error> { todo!() }
   }'
plant_capability_fixture derive_default \
  "${CANONICAL_CAPABILITY/\#\[derive\(Clone\)\]/#[derive(Clone, Default)]}"
plant_capability_fixture derive_deserialize \
  "${CANONICAL_CAPABILITY/\#\[derive\(Clone\)\]/#[derive(Clone, Deserialize)]}"
plant_capability_fixture type_alias "$CANONICAL_CAPABILITY" \
  'pub type AlternateAuthority = GovernanceAuthority;'
plant_capability_fixture renamed_reexport "$CANONICAL_CAPABILITY" \
  'pub use crate::{GovernanceAuthority as AlternateAuthority, GovernancePolicy};'
plant_capability_fixture free_constructor "$CANONICAL_CAPABILITY" \
  'pub fn unchecked(policy: Arc<GovernancePolicy>) -> GovernanceAuthority {
       GovernanceAuthority { policy }
   }'
plant_capability_fixture free_policy_accessor "$CANONICAL_CAPABILITY" \
  'pub fn raw_policy(authority: &GovernanceAuthority) -> &GovernancePolicy {
       &authority.policy
   }'
plant_capability_fixture public_static "$CANONICAL_CAPABILITY" \
  'pub static AUTHORITY: GovernanceAuthority = todo!();'
plant_capability_fixture trait_forge "$CANONICAL_CAPABILITY" \
  'pub trait ForgeAuthority {
       fn forge_authority(self) -> GovernanceAuthority;
   }
   impl ForgeAuthority for Arc<GovernancePolicy> {
       fn forge_authority(self) -> GovernanceAuthority {
           unsafe { std::mem::transmute(self) }
       }
   }'
plant_capability_fixture trait_associated_type "$CANONICAL_CAPABILITY" \
  'pub trait ForgeAuthority { type Authority; }
   impl ForgeAuthority for Arc<GovernancePolicy> {
       type Authority = GovernanceAuthority;
   }'
plant_capability_fixture generic_default_alias "$CANONICAL_CAPABILITY" \
  'pub type AlternateAuthority<T = GovernanceAuthority> = T;
   pub fn mint_alternate(policy: Arc<GovernancePolicy>) -> AlternateAuthority {
       GovernanceAuthority { policy }
   }'
plant_capability_fixture borrowed_authority "$CANONICAL_CAPABILITY" \
  'pub fn borrow_authority(value: &GovernanceAuthority) -> &GovernanceAuthority { value }'
plant_capability_fixture public_authority_field "$CANONICAL_CAPABILITY" \
  'pub struct AuthorityHolder { pub authority: GovernanceAuthority }'
plant_capability_fixture from_raw_bits "$CANONICAL_CAPABILITY" \
  'fn forge_from_raw_bits(policy: Arc<GovernancePolicy>) -> GovernanceAuthority {
       GovernanceAuthority::from_raw_bits(policy)
   }'
plant_capability_fixture authority_union "$CANONICAL_CAPABILITY" \
  'union AuthorityBits {
       policy: std::mem::ManuallyDrop<Arc<GovernancePolicy>>,
       authority: std::mem::ManuallyDrop<GovernanceAuthority>,
   }'
plant_capability_fixture maybe_uninit "$CANONICAL_CAPABILITY" \
  'fn forge_uninitialized() -> GovernanceAuthority {
       unsafe { std::mem::MaybeUninit::uninit().assume_init() }
   }'
plant_capability_fixture missing_unsafe_forbid \
  "${CANONICAL_CAPABILITY/\#\!\[forbid\(unsafe_code\)\]/}"
plant_capability_fixture inferred_transmute_copy "$CANONICAL_CAPABILITY" \
  'fn install(policy: Arc<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
       let value = unsafe { std::mem::transmute_copy(&policy) };
       std::mem::forget(policy);
       sweep.with_governance_authority(value)
   }'
plant_capability_fixture inferred_zeroed "$CANONICAL_CAPABILITY" \
  'fn install(sweep: ContainmentSweep) -> ContainmentSweep {
       let value = unsafe { std::mem::zeroed() };
       sweep.with_governance_authority(value)
   }'
plant_capability_fixture inferred_maybe_uninit "$CANONICAL_CAPABILITY" \
  'fn install(sweep: ContainmentSweep) -> ContainmentSweep {
       let value = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
       sweep.with_governance_authority(value)
   }'
plant_capability_fixture inferred_union "$CANONICAL_CAPABILITY" \
  'union ErasedCapability { raw: std::mem::ManuallyDrop<Arc<GovernancePolicy>>, bits: [usize; 2] }
   fn install(raw: Arc<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
       let erased = ErasedCapability { raw: std::mem::ManuallyDrop::new(raw) };
       let value = unsafe { erased.bits };
       sweep.with_governance_authority(value)
   }'
plant_capability_fixture inferred_from_raw_pointer "$CANONICAL_CAPABILITY" \
  'fn install(raw: *const (), sweep: ContainmentSweep) -> ContainmentSweep {
       let value = unsafe { std::ptr::read(raw.cast()) };
       sweep.with_governance_authority(value)
   }'
plant_capability_fixture renamed_inferred_transmute "$CANONICAL_CAPABILITY" \
  'use std::sync::Arc as Shared;
   fn install(policy: Shared<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
       let value = unsafe { std::mem::transmute_copy(&policy) };
       std::mem::forget(policy);
       sweep.with_governance_authority(value)
   }'
plant_capability_fixture erased_any_getter "$CANONICAL_CAPABILITY" \
  'pub trait ExposeErasedAuthority { fn authority_any(&self) -> Option<&dyn std::any::Any>; }
   impl ExposeErasedAuthority for ContainmentSweep {
       fn authority_any(&self) -> Option<&dyn std::any::Any> {
           self.governance.as_ref().map(|value| value as &dyn std::any::Any)
       }
   }'
plant_capability_fixture erased_debug_getter "$CANONICAL_CAPABILITY" \
  'pub trait ExposeReleaseCapability { fn erased(&self) -> Option<&dyn std::fmt::Debug>; }
   impl ExposeReleaseCapability for ContainmentSweep {
       fn erased(&self) -> Option<&dyn std::fmt::Debug> {
           self.governance.as_ref().map(|value| value as &dyn std::fmt::Debug)
       }
   }'
plant_capability_fixture erased_callback "$CANONICAL_CAPABILITY" \
  'pub trait VisitReleaseCapability {
       fn visit<R>(&self, callback: impl FnOnce(&dyn std::any::Any) -> R) -> Option<R>;
   }
   impl VisitReleaseCapability for ContainmentSweep {
       fn visit<R>(&self, callback: impl FnOnce(&dyn std::any::Any) -> R) -> Option<R> {
           self.governance.as_ref().map(|value| callback(value))
       }
   }'
plant_capability_fixture erased_impl_any "$CANONICAL_CAPABILITY" \
  'impl ContainmentSweep {
       pub fn erased(&self) -> Option<&impl std::any::Any> { self.governance.as_ref() }
   }'
plant_capability_fixture trait_default_clone "$CANONICAL_CAPABILITY" \
  'pub trait ReleaseAuthorityLeak {
       fn release_authority(sweep: &ContainmentSweep) -> Option<GovernanceAuthority> {
           sweep.governance.clone()
       }
   }
   impl ReleaseAuthorityLeak for () {}'
plant_capability_fixture extern_authority_clone "$CANONICAL_CAPABILITY" \
  'pub extern "Rust" fn release_authority_extern(
       sweep: &ContainmentSweep,
   ) -> Option<GovernanceAuthority> {
       sweep.governance.clone()
   }'

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
expect_capability_rejected unchecked_associated "an arbitrary-name raw-policy associated constructor"
expect_capability_rejected generic_associated "a generic raw-policy associated constructor"
expect_capability_rejected helper_constructor "a helper-mediated raw-policy associated constructor"
expect_capability_rejected swap_policy "a public raw-policy replacement method"
expect_capability_rejected raw_policy_getter "a public raw-policy getter"
expect_capability_rejected alias_constructor "an alias-returning free constructor"
expect_capability_rejected private_alias_inherent "a private type-alias inherent constructor"
expect_capability_rejected private_use_alias_inherent "a private use-alias inherent constructor"
expect_capability_rejected macro_constructor "a macro-generated free constructor"
expect_capability_rejected from_raw "a From<Arc<GovernancePolicy>> implementation"
expect_capability_rejected try_from_raw "a TryFrom<Arc<GovernancePolicy>> implementation"
expect_capability_rejected default_impl "a manual Default implementation"
expect_capability_rejected as_ref "an AsRef<GovernancePolicy> exposure"
expect_capability_rejected as_mut "an AsMut<GovernancePolicy> exposure"
expect_capability_rejected borrow "a Borrow<GovernancePolicy> exposure"
expect_capability_rejected manual_clone "a second manual Clone construction path"
expect_capability_rejected deserialize_impl "a manual Deserialize construction path"
expect_capability_rejected derive_default "a derived Default construction path"
expect_capability_rejected derive_deserialize "a derived Deserialize construction path"
expect_capability_rejected type_alias "a public authority type alias"
expect_capability_rejected renamed_reexport "a renamed authority re-export"
expect_capability_rejected free_constructor "a public free function returning an authority"
expect_capability_rejected free_policy_accessor "a public free raw-policy accessor"
expect_capability_rejected public_static "a public static authority value"
expect_capability_rejected trait_forge "a trait method and hidden-header impl that forge an authority"
expect_capability_rejected trait_associated_type "a trait associated type exposing an authority"
expect_capability_rejected generic_default_alias "a generic default alias hiding an authority return"
expect_capability_rejected borrowed_authority "a public borrowed authority return"
expect_capability_rejected public_authority_field "a public field exposing an authority"
expect_capability_rejected from_raw_bits "a raw-bits authority construction helper"
expect_capability_rejected authority_union "a union-based authority representation escape"
expect_capability_rejected maybe_uninit "a MaybeUninit authority construction helper"
expect_capability_rejected missing_unsafe_forbid "removal of the crate unsafe-code prohibition"
expect_capability_rejected inferred_transmute_copy "an inferred transmute_copy authority forgery"
expect_capability_rejected inferred_zeroed "an inferred zeroed authority forgery"
expect_capability_rejected inferred_maybe_uninit "an inferred MaybeUninit authority forgery"
expect_capability_rejected inferred_union "an inferred union authority forgery"
expect_capability_rejected inferred_from_raw_pointer "an inferred raw-pointer authority forgery"
expect_capability_rejected renamed_inferred_transmute "a renamed-import inferred authority forgery"
expect_capability_rejected erased_any_getter "a safe Any authority getter"
expect_capability_rejected erased_debug_getter "a safe Debug authority wrapper"
expect_capability_rejected erased_callback "a safe erased-authority callback"
expect_capability_rejected erased_impl_any "an opaque impl Any authority getter"
expect_capability_rejected trait_default_clone "a public trait default method cloning the authority"
expect_capability_rejected extern_authority_clone "an extern Rust function cloning the authority"

privacy_clean="$(plant_strict_privacy_fixture clean)"
expect_strict_privacy_clean "$privacy_clean" "the exact derived private-field module closures"

privacy_descendant="$(plant_strict_privacy_fixture descendant)"
printf '%s\n' '
fn x(state: &IngestState) -> Option<&dyn std::any::Any> {
    state
        .governance_authority
        .as_ref()
        .map(|value| value as &dyn std::any::Any)
}

impl IngestState {
    pub fn erased(&self) -> Option<&dyn std::any::Any> { x(self) }
}' >> "$privacy_descendant/crates/swarm-ingest-runtime/src/ingest/governance_resume.rs"
expect_strict_privacy_rejected \
  "$privacy_descendant" \
  "the exact split-helper descendant Any leak"

privacy_sibling="$(plant_strict_privacy_fixture sibling)"
printf '%s\n' '
fn y(state: &IngestState) -> Option<&dyn std::any::Any> {
    state
        .governance_authority
        .as_ref()
        .map(|value| value as &dyn std::any::Any)
}

impl IngestState {
    pub fn erased_health(&self) -> Option<&dyn std::any::Any> { y(self) }
}' >> "$privacy_sibling/crates/swarm-ingest-runtime/src/ingest/health.rs"
expect_strict_privacy_rejected \
  "$privacy_sibling" \
  "a sibling descendant module leaking the parent-private authority"

privacy_nested="$(plant_strict_privacy_fixture nested)"
printf '%s\n' 'mod privacy_escape_nested;' \
  >> "$privacy_nested/crates/swarm-ingest-runtime/src/ingest/governance_resume.rs"
mkdir -p "$privacy_nested/crates/swarm-ingest-runtime/src/ingest/governance_resume"
printf '%s\n' '
use crate::ingest::IngestState;

fn z(state: &IngestState) -> Option<&dyn std::any::Any> {
    state
        .governance_authority
        .as_ref()
        .map(|value| value as &dyn std::any::Any)
}

impl IngestState {
    pub fn erased_nested(&self) -> Option<&dyn std::any::Any> { z(self) }
}' > "$privacy_nested/crates/swarm-ingest-runtime/src/ingest/governance_resume/privacy_escape_nested.rs"
expect_strict_privacy_rejected \
  "$privacy_nested" \
  "a newly declared nested descendant authority leak"

privacy_inline="$(plant_strict_privacy_fixture inline)"
printf '%s\n' '
mod privacy_escape_inline {
    use super::IngestState;

    fn z(state: &IngestState) -> Option<&dyn std::any::Any> {
        state
            .governance_authority
            .as_ref()
            .map(|value| value as &dyn std::any::Any)
    }

    impl IngestState {
        pub fn erased_inline(&self) -> Option<&dyn std::any::Any> { z(self) }
    }
}' >> "$privacy_inline/crates/swarm-ingest-runtime/src/ingest/governance_resume.rs"
expect_strict_privacy_rejected \
  "$privacy_inline" \
  "a newly declared inline descendant authority leak"

privacy_redirect="$(plant_strict_privacy_fixture redirect)"
cp \
  "$privacy_redirect/crates/swarm-ingest-runtime/src/ingest/governance_resume.rs" \
  "$privacy_redirect/crates/swarm-ingest-runtime/src/ingest/governance_resume_redirected.rs"
awk '
  /^mod governance_resume;$/ {
    print "#[path = \"governance_resume_redirected.rs\"]"
  }
  { print }
' "$privacy_redirect/crates/swarm-ingest-runtime/src/ingest/mod.rs" \
  > "$privacy_redirect/crates/swarm-ingest-runtime/src/ingest/mod.rs.next"
mv \
  "$privacy_redirect/crates/swarm-ingest-runtime/src/ingest/mod.rs.next" \
  "$privacy_redirect/crates/swarm-ingest-runtime/src/ingest/mod.rs"
expect_strict_privacy_rejected \
  "$privacy_redirect" \
  "a redirected existing privacy descendant"

metadata_alias="$(plant_strict_privacy_fixture metadata-alias)"
"$SINGLE_GOVERNOR_PYTHON" -I - "$metadata_alias" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest = root / "Cargo.toml"
source = manifest.read_text()
member_marker = '    "crates/swarm-crypto",\n]'
dependency_marker = '# Internal crates\n'
crate_root = root / "crates/swarm-closure-escape"
already_installed = '    "crates/swarm-closure-escape",\n' in source
if already_installed:
    required = (
        'gov-cap = { package = "swarm-governance"',
        'rt-cap = { package = "swarm-runtime"',
        'gov-cap.workspace = true',
        'rt-cap.workspace = true',
    )
    crate_text = (crate_root / "Cargo.toml").read_text() if crate_root.is_dir() else ""
    if not all(marker in source for marker in required[:2]) or not all(
        marker in crate_text for marker in required[2:]
    ):
        raise SystemExit("metadata alias fixture found an incomplete preinstalled escape")
else:
    if source.count(member_marker) != 1 or source.count(dependency_marker) != 1:
        raise SystemExit("metadata alias fixture lost its exact workspace markers")
    manifest.write_text(
        source
        .replace(
            member_marker,
            '    "crates/swarm-crypto",\n    "crates/swarm-closure-escape",\n]',
            1,
        )
        .replace(
            dependency_marker,
            dependency_marker
            + 'gov-cap = { package = "swarm-governance", version = "0.1.0", '
              'path = "crates/swarm-governance" }\n'
            + 'rt-cap = { package = "swarm-runtime", version = "0.1.0", '
              'path = "crates/swarm-runtime" }\n',
            1,
        )
    )
    (crate_root / "src").mkdir(parents=True)
    (crate_root / "Cargo.toml").write_text('''
[package]
name = "swarm-closure-escape"
version.workspace = true
edition.workspace = true

[dependencies]
gov-cap.workspace = true
rt-cap.workspace = true
''')
    (crate_root / "src/lib.rs").write_text('''
use std::sync::Arc;

use gov_cap::GovernancePolicy;
use rt_cap::containment::ContainmentSweep;

pub fn install(policy: Arc<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
    let value = unsafe { std::mem::transmute_copy(&policy) };
    std::mem::forget(policy);
    sweep.with_governance_authority(value)
}
''')
    with (root / "Cargo.lock").open("a") as lock:
        lock.write('''

[[package]]
name = "swarm-closure-escape"
version = "0.1.0"
dependencies = [
 "swarm-governance",
 "swarm-runtime",
]
''')
PY
fixture_clean_controls=$((fixture_clean_controls + 1))
metadata_alias_validation=(check --locked --offline -p swarm-closure-escape)
if [[ "${SWARM_NEGATIVE_REGISTRY_PROTECTED:-}" == "1" ]]; then
  metadata_alias_validation=(metadata --locked --offline --format-version 1)
fi
source_cargo_home="$(prepare_source_cargo_home)"
if ! CARGO_HOME="$source_cargo_home" \
  CARGO_TARGET_DIR="$ROOT_DIR/target/single-governor-metadata-fixture" \
  "$SINGLE_GOVERNOR_CARGO" "${metadata_alias_validation[@]}" \
  --manifest-path "$metadata_alias/Cargo.toml" \
  >"$FIXTURE_DIR/metadata_alias.stdout" \
  2>"$FIXTURE_DIR/metadata_alias.stderr"; then
  echo "FIXTURE FAILURE: Cargo rejected the valid workspace-alias closure escape" >&2
  sed -n '1,40p' "$FIXTURE_DIR/metadata_alias.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi
fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
if scan_governance_capability_inventory "$metadata_alias" strict \
  >"$FIXTURE_DIR/metadata_alias_gate.stdout" \
  2>"$FIXTURE_DIR/metadata_alias_gate.stderr"; then
  echo "FIXTURE FAILURE: the resolved metadata inventory accepted a renamed workspace escape" >&2
  fixture_failures=$((fixture_failures + 1))
elif ! grep -q 'resolved normal reverse dependency closure drifted' \
  "$FIXTURE_DIR/metadata_alias_gate.stderr"; then
  echo "FIXTURE FAILURE: the alias escape failed without exercising the resolved closure" >&2
  sed -n '1,40p' "$FIXTURE_DIR/metadata_alias_gate.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi

compiler_input="$(plant_compiler_input_fixture)"
write_unsafe_compiler_input \
  "$compiler_input/crates/swarm-runtime-workbench/assurance_escape.inc"
printf '%s\n' 'include!("../assurance_escape.inc");' \
  >> "$compiler_input/crates/swarm-runtime-workbench/src/lib.rs"
expect_compiler_input_builds "$compiler_input" include_non_rs_cap_lints cap-lints
expect_compiler_input_rejected \
  "$compiler_input" \
  "an inferred transmute_copy in an include!-loaded non-.rs compiler input" \
  strict-force-depinfo \
  "controlled primary-package compile failed"

compiler_input="$(plant_compiler_input_fixture)"
write_unsafe_compiler_input \
  "$compiler_input/crates/swarm-runtime-workbench/assurance_escape.inc"
printf '%s\n' '#[path = "../assurance_escape.inc"] pub mod assurance_escape;' \
  >> "$compiler_input/crates/swarm-runtime-workbench/src/lib.rs"
expect_compiler_input_builds "$compiler_input" path_non_rs_cap_lints cap-lints
expect_compiler_input_rejected \
  "$compiler_input" \
  "an inferred transmute_copy in a #[path]-loaded non-.rs compiler input" \
  strict \
  "production #[path] source graph drifted"

compiler_input="$(plant_compiler_input_fixture)"
write_unsafe_compiler_input \
  "$compiler_input/crates/swarm-runtime-workbench/capability_forge.txt" \
  '#[cfg(not(debug_assertions))]'
# Fixture macro tokens are intentionally literal.
# shellcheck disable=SC2016
printf '%s\n' \
  'macro_rules! load_assurance_escape {' \
  '    ($loader:ident, $path:literal) => { $loader!($path); };' \
  '}' \
  'load_assurance_escape!(include, "../capability_forge.txt");' \
  >> "$compiler_input/crates/swarm-runtime-workbench/src/lib.rs"
expect_compiler_input_builds \
  "$compiler_input" macro_include_cap_lints_release_cfg cap-lints-release-cfg
expect_compiler_input_rejected \
  "$compiler_input" \
  "a macro-wrapped include! source escape" \
  strict \
  "production include/include_str/include_bytes tokens are forbidden"

compiler_input="$(plant_compiler_input_fixture)"
printf '%s\n' 'pub fn untracked_workspace_source_control() {}' \
  > "$compiler_input/assurance_escape.rs"
printf '%s\n' '#[path = "../../../assurance_escape.rs"] pub mod assurance_escape;' \
  >> "$compiler_input/crates/swarm-runtime-workbench/src/lib.rs"
expect_compiler_input_rejected \
  "$compiler_input" \
  "an untracked workspace-root #[path] source" \
  strict \
  "production #[path] source graph drifted"

compiler_input="$(plant_compiler_input_fixture)"
printf '%s\n' 'pub fn external_source_control() {}' \
  > "$FIXTURE_DIR/authority_escape_external.rs"
printf '%s\n' \
  '#[path = "../../../../authority_escape_external.rs"] pub mod assurance_escape;' \
  >> "$compiler_input/crates/swarm-runtime-workbench/src/lib.rs"
expect_compiler_input_builds "$compiler_input" external_path_builds check
expect_compiler_input_rejected \
  "$compiler_input" \
  "a #[path] compiler input outside the workspace" \
  strict-force-depinfo \
  "dep-info input escaped the workspace"

compiler_input="$(plant_compiler_input_fixture)"
printf '%s\n' 'pub fn safe_included_source_control() {}' \
  > "$compiler_input/crates/swarm-runtime-workbench/assurance_escape.inc"
printf '%s\n' 'include!("../assurance_escape.inc");' \
  >> "$compiler_input/crates/swarm-runtime-workbench/src/lib.rs"
expect_compiler_input_builds "$compiler_input" safe_include_builds check
expect_compiler_input_rejected \
  "$compiler_input" \
  "a safe new compiler-consumed include input" \
  strict-force-depinfo \
  "compiler-consumed source/input set"

plant compiler_forbid_control '#![forbid(unsafe_code)]
use std::sync::Arc;
pub struct GovernancePolicy;
pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }
pub trait ForgeAuthority { fn forge_authority(self) -> GovernanceAuthority; }
impl ForgeAuthority for Arc<GovernancePolicy> {
    fn forge_authority(self) -> GovernanceAuthority { GovernanceAuthority { policy: self } }
}'
plant compiler_generic_alias_control '#![forbid(unsafe_code)]
use std::sync::Arc;
pub struct GovernancePolicy;
pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }
pub type AlternateAuthority<T = GovernanceAuthority> = T;
pub fn mint_alternate(policy: Arc<GovernancePolicy>) -> AlternateAuthority {
    GovernanceAuthority { policy }
}'
plant compiler_forbid_unsafe '#![forbid(unsafe_code)]
use std::sync::Arc;
pub struct GovernancePolicy;
pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }
pub trait ForgeAuthority { fn forge_authority(self) -> GovernanceAuthority; }
impl ForgeAuthority for Arc<GovernancePolicy> {
    fn forge_authority(self) -> GovernanceAuthority {
        unsafe { std::mem::transmute(self) }
    }
}'
plant compiler_inferred_unsafe_control 'use std::sync::Arc;
pub struct GovernancePolicy;
pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }
pub struct ContainmentSweep;
impl ContainmentSweep {
    pub fn with_governance_authority(self, _value: GovernanceAuthority) -> Self { self }
}
pub fn install(policy: Arc<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
    let value = unsafe { std::mem::transmute_copy(&policy) };
    std::mem::forget(policy);
    sweep.with_governance_authority(value)
}'
plant compiler_inferred_unsafe_forbidden '#![forbid(unsafe_code)]
use std::sync::Arc;
pub struct GovernancePolicy;
pub struct GovernanceAuthority { policy: Arc<GovernancePolicy> }
pub struct ContainmentSweep;
impl ContainmentSweep {
    pub fn with_governance_authority(self, _value: GovernanceAuthority) -> Self { self }
}
pub fn install(policy: Arc<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
    let value = unsafe { std::mem::transmute_copy(&policy) };
    std::mem::forget(policy);
    sweep.with_governance_authority(value)
}'
plant compiler_safe_erasure_control '#![forbid(unsafe_code)]
use std::any::Any;
use std::sync::Arc;
#[derive(Clone)]
pub struct GovernanceAuthority { policy: Arc<()> }
pub struct ContainmentSweep { governance: Option<GovernanceAuthority> }
pub trait ExposeErasedAuthority {
    fn authority_any(&self) -> Option<&dyn Any>;
}
impl ExposeErasedAuthority for ContainmentSweep {
    fn authority_any(&self) -> Option<&dyn Any> {
        self.governance.as_ref().map(|value| value as &dyn Any)
    }
}
pub mod external {
    use super::{ContainmentSweep, ExposeErasedAuthority, GovernanceAuthority};
    pub fn recover(sweep: &ContainmentSweep) -> Option<GovernanceAuthority> {
        sweep.authority_any()?.downcast_ref::<GovernanceAuthority>().cloned()
    }
}'
plant compiler_trait_default_control '#![forbid(unsafe_code)]
use std::sync::Arc;
#[derive(Clone)]
pub struct GovernanceAuthority { policy: Arc<()> }
pub struct ContainmentSweep { governance: Option<GovernanceAuthority> }
pub trait ReleaseAuthorityLeak {
    fn release_authority(sweep: &ContainmentSweep) -> Option<GovernanceAuthority> {
        sweep.governance.clone()
    }
}
impl ReleaseAuthorityLeak for () {}
pub fn external_recover(sweep: &ContainmentSweep) -> Option<GovernanceAuthority> {
    <() as ReleaseAuthorityLeak>::release_authority(sweep)
}'
plant compiler_extern_control '#![forbid(unsafe_code)]
use std::sync::Arc;
#[derive(Clone)]
pub struct GovernanceAuthority { policy: Arc<()> }
pub struct ContainmentSweep { governance: Option<GovernanceAuthority> }
pub extern "Rust" fn release_authority_extern(
    sweep: &ContainmentSweep,
) -> Option<GovernanceAuthority> {
    sweep.governance.clone()
}'
plant compiler_privacy_descendant_control '#![forbid(unsafe_code)]
use std::any::Any;
use std::sync::Arc;

#[derive(Clone)]
pub struct GovernanceAuthority { policy: Arc<()> }

pub mod ingest {
    use super::GovernanceAuthority;

    pub struct IngestState {
        governance_authority: Option<GovernanceAuthority>,
    }

    mod governance_resume {
        use super::IngestState;

        fn x(state: &IngestState) -> Option<&dyn std::any::Any> {
            state
                .governance_authority
                .as_ref()
                .map(|value| value as &dyn std::any::Any)
        }

        impl IngestState {
            pub fn erased(&self) -> Option<&dyn std::any::Any> { x(self) }
        }
    }

    mod health {
        use super::IngestState;

        fn y(state: &IngestState) -> Option<&dyn std::any::Any> {
            state
                .governance_authority
                .as_ref()
                .map(|value| value as &dyn std::any::Any)
        }

        impl IngestState {
            pub fn erased_health(&self) -> Option<&dyn std::any::Any> { y(self) }
        }
    }

    mod branch {
        mod nested {
            use crate::ingest::IngestState;

            fn z(state: &IngestState) -> Option<&dyn std::any::Any> {
                state
                    .governance_authority
                    .as_ref()
                    .map(|value| value as &dyn std::any::Any)
            }

            impl IngestState {
                pub fn erased_nested(&self) -> Option<&dyn std::any::Any> { z(self) }
            }
        }
    }
}

pub mod external {
    use super::{Any, GovernanceAuthority};
    use super::ingest::IngestState;

    fn recover(value: Option<&dyn Any>) -> Option<GovernanceAuthority> {
        value?.downcast_ref::<GovernanceAuthority>().cloned()
    }

    pub fn recover_all(
        state: &IngestState,
    ) -> (
        Option<GovernanceAuthority>,
        Option<GovernanceAuthority>,
        Option<GovernanceAuthority>,
    ) {
        (
            recover(state.erased()),
            recover(state.erased_health()),
            recover(state.erased_nested()),
        )
    }
}'
fixture_clean_controls=$((fixture_clean_controls + 1))
if ! rustc --edition=2024 --crate-type=lib --emit=metadata \
  "$FIXTURE_DIR/compiler_forbid_control.rs" \
  -o "$FIXTURE_DIR/compiler_forbid_control.rmeta" \
  >"$FIXTURE_DIR/compiler_forbid_control.stdout" \
  2>"$FIXTURE_DIR/compiler_forbid_control.stderr"; then
  echo "FIXTURE FAILURE: rustc rejected the safe forbid(unsafe_code) control" >&2
  sed -n '1,20p' "$FIXTURE_DIR/compiler_forbid_control.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi
fixture_clean_controls=$((fixture_clean_controls + 1))
if ! rustc --edition=2024 --crate-type=lib --emit=metadata \
  "$FIXTURE_DIR/compiler_generic_alias_control.rs" \
  -o "$FIXTURE_DIR/compiler_generic_alias_control.rmeta" \
  >"$FIXTURE_DIR/compiler_generic_alias_control.stdout" \
  2>"$FIXTURE_DIR/compiler_generic_alias_control.stderr"; then
  echo "FIXTURE FAILURE: rustc rejected the exact safe generic-alias forge specimen" >&2
  sed -n '1,20p' "$FIXTURE_DIR/compiler_generic_alias_control.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi
fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
if rustc --edition=2024 --crate-type=lib --emit=metadata \
  "$FIXTURE_DIR/compiler_forbid_unsafe.rs" \
  -o "$FIXTURE_DIR/compiler_forbid_unsafe.rmeta" \
  >"$FIXTURE_DIR/compiler_forbid_unsafe.stdout" \
  2>"$FIXTURE_DIR/compiler_forbid_unsafe.stderr"; then
  echo "FIXTURE FAILURE: rustc accepted an unsafe transmute under forbid(unsafe_code)" >&2
  fixture_failures=$((fixture_failures + 1))
elif ! grep -q 'unsafe' "$FIXTURE_DIR/compiler_forbid_unsafe.stderr"; then
  echo "FIXTURE FAILURE: compiler red did not fail on the unsafe-code prohibition" >&2
  sed -n '1,20p' "$FIXTURE_DIR/compiler_forbid_unsafe.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi
fixture_clean_controls=$((fixture_clean_controls + 1))
if ! rustc --edition=2024 --crate-type=lib --emit=metadata \
  "$FIXTURE_DIR/compiler_inferred_unsafe_control.rs" \
  -o "$FIXTURE_DIR/compiler_inferred_unsafe_control.rmeta" \
  >"$FIXTURE_DIR/compiler_inferred_unsafe_control.stdout" \
  2>"$FIXTURE_DIR/compiler_inferred_unsafe_control.stderr"; then
  echo "FIXTURE FAILURE: rustc rejected the exact inferred transmute_copy exploit control" >&2
  sed -n '1,20p' "$FIXTURE_DIR/compiler_inferred_unsafe_control.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi
fixture_adversarial_cases=$((fixture_adversarial_cases + 1))
if rustc --edition=2024 --crate-type=lib --emit=metadata \
  "$FIXTURE_DIR/compiler_inferred_unsafe_forbidden.rs" \
  -o "$FIXTURE_DIR/compiler_inferred_unsafe_forbidden.rmeta" \
  >"$FIXTURE_DIR/compiler_inferred_unsafe_forbidden.stdout" \
  2>"$FIXTURE_DIR/compiler_inferred_unsafe_forbidden.stderr"; then
  echo "FIXTURE FAILURE: rustc accepted inferred transmute_copy under forbid(unsafe_code)" >&2
  fixture_failures=$((fixture_failures + 1))
elif ! grep -q 'unsafe' "$FIXTURE_DIR/compiler_inferred_unsafe_forbidden.stderr"; then
  echo "FIXTURE FAILURE: inferred compiler red did not fail on the unsafe-code prohibition" >&2
  sed -n '1,20p' "$FIXTURE_DIR/compiler_inferred_unsafe_forbidden.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi
for control in safe_erasure trait_default extern; do
  fixture_clean_controls=$((fixture_clean_controls + 1))
  if ! rustc --edition=2024 --crate-type=lib --emit=metadata \
    "$FIXTURE_DIR/compiler_${control}_control.rs" \
    -o "$FIXTURE_DIR/compiler_${control}_control.rmeta" \
    >"$FIXTURE_DIR/compiler_${control}_control.stdout" \
    2>"$FIXTURE_DIR/compiler_${control}_control.stderr"; then
    echo "FIXTURE FAILURE: rustc rejected the safe ${control} authority-leak control" >&2
    sed -n '1,20p' "$FIXTURE_DIR/compiler_${control}_control.stderr" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
done
fixture_clean_controls=$((fixture_clean_controls + 1))
if ! rustc --edition=2024 --crate-type=lib --emit=metadata \
  "$FIXTURE_DIR/compiler_privacy_descendant_control.rs" \
  -o "$FIXTURE_DIR/compiler_privacy_descendant_control.rmeta" \
  >"$FIXTURE_DIR/compiler_privacy_descendant_control.stdout" \
  2>"$FIXTURE_DIR/compiler_privacy_descendant_control.stderr"; then
  echo "FIXTURE FAILURE: rustc rejected descendant/sibling/nested private-field recovery" >&2
  sed -n '1,20p' "$FIXTURE_DIR/compiler_privacy_descendant_control.stderr" >&2
  fixture_failures=$((fixture_failures + 1))
fi

if [ "$fixture_failures" -ne 0 ]; then
  echo "" >&2
  echo "The fixture proves this scanner can fail. $fixture_failures of its cases" >&2
  echo "did not behave as documented, so its verdict over the real tree means" >&2
  echo "nothing. Fix the scanner, not the fixture." >&2
  exit 1
fi
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

scan_governance_capability_inventory "$ROOT_DIR" strict

if [[ "$SINGLE_GOVERNOR_MUTATION_PROBE" == "1" ]]; then
  echo "single-governor mutation-probe mode is not an authority verdict" >&2
  exit 1
fi

fixture_cases=$((fixture_adversarial_cases + fixture_clean_controls))
echo "single-governor-key gate: $fixture_cases fixture cases behaved as documented" \
     "($fixture_adversarial_cases adversarial, $fixture_clean_controls controls); no key" \
     "collection on the governance signing path; shipped governance authority" \
     "is one opaque concrete handle with an authenticated mint (${SCAN_PATHS[*]})"
