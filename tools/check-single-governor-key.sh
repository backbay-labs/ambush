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
#     manifest, lib/bin root, inherent method/impl, and private-field-owner
#     source; rejects custom build targets; and requires the compiler to forbid
#     unsafe code in every normal shipped target. Full closure production source
#     is also scanned for raw-memory primitives regardless of inferred type.
#
# WHAT THIS SCRIPT COVERS
#   `crates/swarm-governance/src/`, `crates/swarm-consensus/src/` and
#   `crates/swarm-policy/src/`, outside `#[cfg(test)]` regions: no
#   `BTreeMap<.., SigningKey>`, `HashMap<.., SigningKey>`, `Vec<SigningKey>`,
#   `[SigningKey; N]` or `&[SigningKey]`.
#
#   The signing-key collection scan is scoped to those three deliberately.
#   Separately, the authority scan derives and pins all eight normal shipped
#   reverse dependencies, every one of their lib/bin roots, and the complete
#   Rust source set in that closure. Raw source identity is reserved for the
#   five modules that can directly read the private handle field.
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
  local inventory_mode="${2:-fixture}"
  "$SINGLE_GOVERNOR_PYTHON" -I - "$source_root" "$inventory_mode" <<'PY'
import hashlib
import pathlib
import re
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
strict_digest = sys.argv[2] == "strict"
canonical = pathlib.Path("crates/swarm-governance/src/lib.rs")
EXPECTED_AUTHORITY_IMPL_DIGEST = "8da26c153a0436586d711477061eeeceee911e66752ac17952397b14631e57e5"
EXPECTED_GOVERNANCE_SOURCE_DIGEST = "2beaf67e5b1180752255484c6e8ad456354ac8c59f572fb4392d579005f92896"
EXPECTED_STRICT_AUTHORITY_IMPL_DIGESTS = {
    (canonical, "implstd::fmt::DebugforGovernanceAuthority"):
        "351c05a0947ce39862c748abd2f3a30e1fdd3fed287829554ac153b05e1ef515",
    (canonical, "implGovernancePolicy"):
        "a1c1ede69bb5cfb718970ddc2df051e3efd0768167be55d58df36fb54d58988e",
    (canonical, "implGovernanceAuthority"):
        "8da26c153a0436586d711477061eeeceee911e66752ac17952397b14631e57e5",
    (pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"), "implIngestState"):
        "eb3c0c4082592c6408a367d31ff42a9682329e1576b12e61ac9198804a16cc88",
    (pathlib.Path("crates/swarm-runtime/src/containment.rs"), "implContainmentSweep"):
        "154b2b98b5c74743b77a1afd1a974543cd743d32a4adc4654c35d4294cef03c4",
    (pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"), "implHumanApprovalResumeDispatcher"):
        "2e421c9337fb979bf020e049f1962081d190854263feeaff1ba09186d7279e0d",
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
        "pubfnnew(governance:GovernanceAuthority,router:Arc<dynRequestResponseRouter>)->Self",
    ),
    (
        pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"),
        "pubfnwith_governance_authority(mutself,governance_authority:GovernanceAuthority)->Self",
    ),
}
EXPECTED_AUTHORITY_REVERSE_CLOSURE = {
    "swarm-governance",
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
    "swarm-runtime": "d0d7570100a329751d1abbec9ef627d5c2b01f5bdfc62559b7cb22979ea1521e",
    "swarm-ingest-runtime": "9332eb415a092cbf5f1c4ae02b79d2a3e928464441c7d14ae1fcd39ecf406875",
    "swarm-runtime-http": "890644cbb2cd57bed43de30491b60d1fef5b8e64038520d5249af531a292b88f",
    "swarm-agents": "531cb9064f0d5e5143dac6cf56312ec88180e17a0feba3a4eeb2e7b2b169d67a",
    "swarm-evolution": "0fca9be1e6d92ad2acdd70fa1b06994bd6a28fd16381c3b42b0255f427f4887c",
    "swarm-runtime-workbench": "eab3a2b0578a2366e26604a69ca649ba03ce032d3fc45696876ae222573d24ce",
    "swarm-cli": "0593667747de0b4cd7792170f2c6bfa8fb0a5051767dca97ede20fad44a23dfe",
}
EXPECTED_FIELD_OWNER_SOURCE_DIGESTS = {
    pathlib.Path("crates/swarm-governance/src/lib.rs"):
        "2beaf67e5b1180752255484c6e8ad456354ac8c59f572fb4392d579005f92896",
    pathlib.Path("crates/swarm-runtime/src/containment.rs"):
        "813b259d69867ca71649f0f4a20fae30868a3405a5be1a217f467d8de53577ad",
    pathlib.Path("crates/swarm-runtime/src/dispatcher.rs"):
        "de7ad808ff477c7d1432b47360f4139e9ddaa5d5449a4fa5d21e28b5e86c8c8e",
    pathlib.Path("crates/swarm-ingest-runtime/src/ingest/mod.rs"):
        "33a272f43e892f47816eb6fe183f41d9afda86b3093b5258da0c7c6e8a3c7c47",
    pathlib.Path("crates/swarm-runtime-http/src/bin/swarm_detect.rs"):
        "51f81097ef4e5ba17f9a3757e8e413118f36572f9c844fef20729d4532da9a10",
}
EXPECTED_CLOSURE_TARGET_ATTRIBUTES = {
    pathlib.Path("crates/swarm-governance/src/lib.rs"): "#![forbid(unsafe_code)]",
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

def normal_dependency_names(document: dict) -> set[str]:
    tables = [document.get("dependencies", {})]
    for target in document.get("target", {}).values():
        if isinstance(target, dict):
            tables.append(target.get("dependencies", {}))
    dependencies = set()
    for table in tables:
        if not isinstance(table, dict):
            continue
        for name, specification in table.items():
            package = specification.get("package", name) if isinstance(specification, dict) else name
            dependencies.add(package)
    return dependencies

def shipped_target_roots(crate_root: pathlib.Path, document: dict) -> set[pathlib.Path]:
    targets = set()
    library = document.get("lib")
    implicit_library = crate_root / "src/lib.rs"
    if isinstance(library, dict):
        targets.add(crate_root / library.get("path", "src/lib.rs"))
    elif implicit_library.is_file():
        targets.add(implicit_library)
    for binary in document.get("bin", []):
        if isinstance(binary, dict) and "path" in binary:
            targets.add(crate_root / binary["path"])
    if document.get("package", {}).get("autobins", True):
        main = crate_root / "src/main.rs"
        if main.is_file():
            targets.add(main)
        binary_root = crate_root / "src/bin"
        if binary_root.is_dir():
            targets.update(binary_root.glob("*.rs"))
            targets.update(binary_root.glob("*/main.rs"))
    return {path.relative_to(root) for path in targets}

authority_closure = set()
if strict_digest:
    manifests = {}
    crate_roots = {}
    dependency_graph = {}
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
        dependency_graph[package] = normal_dependency_names(document)
    authority_closure = {"swarm-governance"}
    changed = True
    while changed:
        changed = False
        for package, dependencies in dependency_graph.items():
            if package not in authority_closure and dependencies & authority_closure:
                authority_closure.add(package)
                changed = True
    if authority_closure != EXPECTED_AUTHORITY_REVERSE_CLOSURE:
        print(
            "governance capability inventory: normal reverse dependency closure drifted; "
            f"found {sorted(authority_closure)}",
            file=sys.stderr,
        )
        failed = True
    observed_targets = set()
    for package in sorted(EXPECTED_AUTHORITY_REVERSE_CLOSURE):
        manifest_entry = manifests.get(package)
        if manifest_entry is None:
            print(f"governance capability inventory: closure package {package} is missing", file=sys.stderr)
            failed = True
            continue
        manifest, document = manifest_entry
        actual_manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        if actual_manifest_digest != EXPECTED_CLOSURE_MANIFEST_DIGESTS[package]:
            print(
                f"governance capability inventory: {package} manifest digest "
                f"{actual_manifest_digest} != pinned {EXPECTED_CLOSURE_MANIFEST_DIGESTS[package]}",
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
        observed_targets.update(shipped_target_roots(crate_roots[package], document))
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
    for path, expected in EXPECTED_FIELD_OWNER_SOURCE_DIGESTS.items():
        source_path = root / path
        actual = hashlib.sha256(source_path.read_bytes()).hexdigest() if source_path.is_file() else None
        if actual != expected:
            print(
                f"governance capability inventory: private-handle field-owner source {path} "
                f"digest {actual} != pinned {expected}",
                file=sys.stderr,
            )
            failed = True

source_files = sorted(
    path
    for path in (root / "crates").glob("*/src/**/*.rs")
    if path.name not in {"test.rs", "tests.rs"}
    and "tests" not in path.relative_to(root).parts
)
if not source_files:
    print("no shipped Rust source found for governance capability inventory", file=sys.stderr)
    raise SystemExit(2)
raw_sources = {
    path.relative_to(root): path.read_text(encoding="utf-8")
    for path in source_files
}
sources = {
    path: without_cfg_test_modules(production_source(raw))
    for path, raw in raw_sources.items()
}
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
raise SystemExit(1 if failed else 0)
PY
}
# ---------------------------------------------------------------------------
# THE FIXTURE. Runs on every invocation.
# ---------------------------------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-single-governor-key.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_failures=0
fixture_adversarial_cases=0
fixture_clean_controls=0

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

CAPABILITY_UNCHECKED="${CANONICAL_CAPABILITY/impl GovernanceAuthority \{/impl GovernanceAuthority \{
    pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }}"
CAPABILITY_GENERIC_CONSTRUCTOR="${CANONICAL_CAPABILITY/impl GovernanceAuthority \{/impl GovernanceAuthority \{
    pub fn unchecked<T: Into<Arc<GovernancePolicy>>>(policy: T) -> Self {
        Self { policy: policy.into() }
    }}"
CAPABILITY_HELPER_CONSTRUCTOR="${CANONICAL_CAPABILITY/impl GovernanceAuthority \{/impl GovernanceAuthority \{
    fn from_raw(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }
    pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self::from_raw(policy) }}"
CAPABILITY_SWAP_POLICY="${CANONICAL_CAPABILITY/impl GovernanceAuthority \{/impl GovernanceAuthority \{
    pub fn swap_policy(&mut self, policy: Arc<GovernancePolicy>) { self.policy = policy; }}"
CAPABILITY_RAW_GETTER="${CANONICAL_CAPABILITY/impl GovernanceAuthority \{/impl GovernanceAuthority \{
    pub fn policy(&self) -> &GovernancePolicy { &self.policy }}"

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

scan_governance_capability_inventory "$ROOT_DIR" strict

fixture_cases=$((fixture_adversarial_cases + fixture_clean_controls))
echo "single-governor-key gate: $fixture_cases fixture cases behaved as documented" \
     "($fixture_adversarial_cases adversarial, $fixture_clean_controls controls); no key" \
     "collection on the governance signing path; shipped governance authority" \
     "is one opaque concrete handle with an authenticated mint (${SCAN_PATHS[*]})"
