#!/usr/bin/env bash
# Phase-285 negative-registry gate. Each test must invoke the repository's
# shared typed protocol, which owns an exact production call plus
# mirror(None)/mirror(Broken) execution over one typed probe. Production calls
# are forced through checker-pinned, crate-root `extern crate` aliases so a
# local module cannot shadow an external crate. A focused syn checker binds the
# entire registered source files and shared protocol AST to local digests,
# including imports and helper/wrapper bodies. Registered cases use only the
# compiler's built-in #[test] attribute, and a wrapper sentinel surrounds the
# shared synchronous driver. The gate binds the relevant Cargo manifests and
# lock resolution and pinned rust-toolchain semantics. Every Cargo subprocess
# uses a fresh config-free CARGO_HOME plus an exact pinned cargo/rustc, while a
# gate-owned isolated-Python RUSTC_WRAPPER audits one forced test compilation's
# crate name, test mode, canonical source path, and source hash per target. The
# gate performs one controlled hydration phase, fetching each tracked,
# locked/checksummed dependency domain into that empty home. It then forces
# every later dependency-resolving Cargo command locked and offline, except for
# one self-test that resolves a freshly constructed file:// Git repository in a
# separate empty home, validates its exact local URL/revision-only lock, and
# returns to offline mode before compiling. Emitted test binaries run directly
# under a sanitized environment,
# so Cargo runner/config and process/module-injection settings cannot fabricate
# discovery/execution output. Active-host compiler, flags, target, and runner
# environment overrides are refused; inactive-target overrides are stripped
# from every child process.
# Registered integration targets must remain Cargo-auto-discovered from their
# canonical source files; production libraries and the complete local
# custom-build target inventory are also bound through Cargo metadata. The one
# reviewed local build script is source- and manifest-digested, while all other
# local custom-build targets are rejected. Each supported CI entry point has a
# dedicated fresh Ubuntu runner and only a pinned credential-free checkout
# before its gate. Its custom-shell template starts `/usr/bin/env -i` directly;
# there is no default Bash, cache, repository command, GITHUB_ENV, or GITHUB_PATH
# writer before it. The fresh runner is the bootstrap trust root: this script
# cannot sanitize code that
# executes before line one. Checker-owned semantic digests pin all five
# crate manifests plus root execution-affecting tables. Those co-located digests
# are tamper-evident against uncoordinated edits, not an external trust anchor.
# Mirror fidelity beyond the registered probe remains a reviewed limitation.
set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR="."
fi
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
cd "$ROOT_DIR"

PHASE285_PYTHON=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]] \
    && "$candidate" -I -c 'import sys, tomllib; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    PHASE285_PYTHON="$candidate"
    break
  fi
done
if [[ -z "$PHASE285_PYTHON" ]]; then
  echo "check-negative-registry requires Python >= 3.11 at a pinned system path" >&2
  exit 1
fi

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
    output="$(TMPDIR="$boundary" phase285_create_confined_scratch phase285-negative-hostile 2>&1)" || exit_code=$?
    [ "$exit_code" -ne 0 ] && [ "$output" = "PHASE285-SCRATCH[boundary-overlap]" ] || return 1
    rejected=$((rejected + 1))
  done
  echo "phase285_scratch_self_test site=negative boundaries=$rejected passed=1"
}

phase285_transport_negative_check() {
  "$PHASE285_PYTHON" -I - "$1" "$2" <<'PY'
import pathlib, re, sys, tomllib
root = pathlib.Path(sys.argv[1])
case = sys.argv[2]
if case == "phase285-raw-kv-subject":
    source = root / "crates/swarm-governance-witness/src"
    if not source.is_dir():
        raise SystemExit("PHASE285-NEGATIVE[missing-witness-source]")
    for path in sorted(source.rglob("*.rs")):
        if re.search(r"\$KV\.[A-Za-z0-9_.>*-]*", path.read_text()):
            raise SystemExit("PHASE285-NEGATIVE[raw-kv-subject]")
elif case == "phase285-unrelated-authority-crate":
    path = root / "crates/swarm-governance-witness/Cargo.toml"
    with path.open("rb") as handle:
        manifest = tomllib.load(handle)
    names = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for key, value in manifest.get(section, {}).items():
            names.add(value.get("package", key) if isinstance(value, dict) else key)
    if "swarm-consensus" in names:
        raise SystemExit("PHASE285-NEGATIVE[unrelated-authority-crate]")
else:
    raise SystemExit(f"unknown Phase 285 transport negative case: {case}")
print(f"phase285_transport_negative case={case} positive=1")
PY
}

phase285_transport_negative_self_test() (
  local case="$1" scratch output status=0
  phase285_transport_negative_check "$ROOT_DIR" "$case"
  phase285_scratch_hostile_controls
  scratch="$(phase285_create_confined_scratch phase285-negative)"
  trap 'phase285_cleanup_confined_scratch "$scratch" || exit 1' EXIT
  mkdir -p "$scratch/crates/swarm-governance-witness/src"
  cp "$ROOT_DIR/crates/swarm-governance-witness/Cargo.toml" "$scratch/crates/swarm-governance-witness/Cargo.toml"
  cp "$ROOT_DIR/crates/swarm-governance-witness/src/lib.rs" "$scratch/crates/swarm-governance-witness/src/lib.rs"
  if [ "$case" = phase285-raw-kv-subject ]; then
    # The mutant must contain a literal raw subject.
    # shellcheck disable=SC2016
    printf '\npub const FORBIDDEN_RAW: &str = "$KV.raw.>";\n' >>"$scratch/crates/swarm-governance-witness/src/lib.rs"
  else
    "$PHASE285_PYTHON" -I - "$scratch/crates/swarm-governance-witness/Cargo.toml" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1]); text = path.read_text()
text = text.replace("[dev-dependencies]", "swarm-consensus.workspace = true\n\n[dev-dependencies]", 1)
path.write_text(text)
PY
  fi
  output="$(phase285_transport_negative_check "$scratch" "$case" 2>&1)" || status=$?
  [ "$status" -ne 0 ] && [[ "$output" == PHASE285-NEGATIVE\[* ]] || return 1
  echo "phase285_transport_self_test case=$case positive=1 mutation_failure=1"
)

if [ "${1:-}" = --self-test ]; then
  [ "$#" -eq 2 ] || { echo "usage: $0 [--self-test case]" >&2; exit 2; }
  case "$2" in
    phase285-raw-kv-subject|phase285-unrelated-authority-crate)
      phase285_transport_negative_self_test "$2"
      exit 0
      ;;
    *) echo "unknown Phase 285 self-test: $2" >&2; exit 2 ;;
  esac
elif [ "$#" -ne 0 ]; then
  echo "usage: $0 [--self-test case]" >&2
  exit 2
fi
phase285_transport_negative_check "$ROOT_DIR" phase285-raw-kv-subject
phase285_transport_negative_check "$ROOT_DIR" phase285-unrelated-authority-crate

"$PHASE285_PYTHON" -I - "$ROOT_DIR" "$PHASE285_PYTHON" <<'PY'
from __future__ import annotations

import pathlib
import pwd
import re
import os
import hashlib
import importlib.util
import json
import secrets
import shutil
import subprocess
import sys
import tempfile
import tomllib

REPO_ROOT = pathlib.Path(sys.argv[1])
TRUSTED_PYTHON = pathlib.Path(sys.argv[2]).resolve()
if pathlib.Path(sys.executable).resolve() != TRUSTED_PYTHON:
    raise SystemExit(
        f"unexpected Python interpreter {pathlib.Path(sys.executable).resolve()}, "
        f"expected {TRUSTED_PYTHON}"
    )
sys.dont_write_bytecode = True
assurance_spec = importlib.util.spec_from_file_location(
    "assurance_source", REPO_ROOT / "tools/assurance_source.py",
)
if assurance_spec is None or assurance_spec.loader is None:
    raise SystemExit("cannot load the exact assurance_source.py")
assurance_source = importlib.util.module_from_spec(assurance_spec)
sys.modules["assurance_source"] = assurance_source
assurance_spec.loader.exec_module(assurance_source)
enum_variant_defined = assurance_source.enum_variant_defined
function_attributes = assurance_source.function_attributes
function_has_conditional_owner = assurance_source.function_has_conditional_owner
matching_brace = assurance_source.matching_brace
resolve_function = assurance_source.resolve_function
sanitize_rust = assurance_source.sanitize_rust
test_function = assurance_source.test_function

MAPPING_REL = "docs/assurance/MAPPING.md"
REGISTRY_REL = "docs/assurance/negative-registry.toml"
UNIVERSE_REL = "docs/assurance/universe.toml"
TEST_FILE = re.compile(r"^crates/[^/]+/tests/negative_[A-Za-z0-9_]+\.rs$")
PROTOCOL_REL = "tests/negative_protocol.rs"
CONTRACT_REL = "crates/swarm-policy/tests/negative_protocol_contract.rs"
CONTRACT_CRATE = "swarm-policy"
CONTRACT_TARGET = "negative_protocol_contract"
CONTRACT_TESTS = {
    "protocol_executes_each_typed_role_exactly_once",
    "protocol_rejects_denying_broken",
    "protocol_rejects_permitting_real",
    "protocol_rejects_real_control_mismatch",
    "protocol_rejects_swapped_none_and_broken_roles",
}
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
PINNED_RESOLUTION = {
    "async-trait": ("0.1.89", CRATES_IO_SOURCE, "9035ad2d096bed7955a320ee7e2230574d28fd3c3a0f186cbea1ff3c7eed5dbb"),
    "proc-macro2": ("1.0.106", CRATES_IO_SOURCE, "8fd00f0bb2e90d81d1044c2b32617f68fcb9fa3bb7640c23e9c748e53fb30934"),
    "quote": ("1.0.45", CRATES_IO_SOURCE, "41f2619966050689382d2b44f664f4bc593e129785a36d6ee376ddf37259b924"),
    "serde": ("1.0.228", CRATES_IO_SOURCE, "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e"),
    "serde_derive": ("1.0.228", CRATES_IO_SOURCE, "d540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79"),
    "serde_json": ("1.0.149", CRATES_IO_SOURCE, "83fc039473c5595ace860d8c4fafa220ff474b3fc6bfdb4293327f1a37e94d86"),
    "syn": ("2.0.117", CRATES_IO_SOURCE, "e665b8803e7b1d2a727f4023456bbbbe74da67099c585258af0ad9c5013b9b99"),
    "tokio": ("1.52.3", CRATES_IO_SOURCE, "8fc7f01b389ac15039e4dc9531aa973a135d7a4135281b12d7c1bc79fd57fffe"),
    "tokio-macros": ("2.7.0", CRATES_IO_SOURCE, "385a6cb71ab9ab790c5fe8d67f1645e6c450a7ce006a33de03daa956cf70a496"),
}
PRODUCTION_PACKAGES = {
    "swarm-governance": ("crates/swarm-governance/Cargo.toml", "swarm_governance"),
    "swarm-policy": ("crates/swarm-policy/Cargo.toml", "swarm_policy"),
    "swarm-response": ("crates/swarm-response/Cargo.toml", "swarm_response"),
    "swarm-runtime": ("crates/swarm-runtime/Cargo.toml", "swarm_runtime"),
    "swarm-spine": ("crates/swarm-spine/Cargo.toml", "swarm_spine"),
}
EXPECTED_CRATE_MANIFEST_DIGESTS = {
    "crates/swarm-governance/Cargo.toml": "d43ae97906033262f9bc8dc52d8534252b2b7c52e16edff803539020b5d3646d",
    "crates/swarm-policy/Cargo.toml": "29ef642b8ba57958db7b202ebedb237d8b5bab1cb17b88d9e0e7ce56f9604520",
    "crates/swarm-response/Cargo.toml": "55d970d2348d4366791f1cb2e46df04872e33892af451c3919f67c45dd736760",
    "crates/swarm-runtime/Cargo.toml": "9e71810643aef57970036390c66e2e973231cff2b0b3e10490b7fb810ca84b0a",
    "crates/swarm-spine/Cargo.toml": "fb26c630348a352a5d8655d44987ed6356fec65270f99919852b0c3fb3a93d04",
}
GOVERNANCE_ASSURANCE_INPUT_DIGESTS = {
    "Cargo.toml": "187e7bd6b36943484258043d03bd2c4ec1c43744300534fddd02dae5a4627b8b",
    "Cargo.lock": "36d0fc55404cc6bcc9b1555d3a4b84e99e9de6a6a49eb86cf7def6624f9bd5e7",
    ".github/workflows/ci.yml": "d2efb24c6c1c167c40483e6b1587c16dc9e8e6439a44ecd6b81d9d2557f55d4c",
    ".github/workflows/release.yml": "937af30a8bc982a73615ca49e1e48f4d64049e82a7a28113cd1c72c2110d8e51",
    "tools/check-supply-chain.sh": "212b37c57bcd372fc74ca29b8e537297196c28c399d98e7613fa24c6413c2fd0",
    "tools/generate-sbom.sh": "95764c8a4e0797bcf3876242912b158cd95f898b1856e4c68633ef866857175d",
    "tools/check-single-governor-key.sh": "f1e1a56887d57bcc37246beadb25d136fa7453c3da308610cbc2e82c1127054b",
    "crates/swarm-governance/Cargo.toml": "4e1bf8dde6a967a3473401fa9abb65579e0d40d55c32b3dab67c5d355bf93aac",
    "crates/swarm-runtime/Cargo.toml": "d0d7570100a329751d1abbec9ef627d5c2b01f5bdfc62559b7cb22979ea1521e",
    "crates/swarm-ingest-runtime/Cargo.toml": "9332eb415a092cbf5f1c4ae02b79d2a3e928464441c7d14ae1fcd39ecf406875",
    "crates/swarm-runtime-http/Cargo.toml": "890644cbb2cd57bed43de30491b60d1fef5b8e64038520d5249af531a292b88f",
    "crates/swarm-agents/Cargo.toml": "531cb9064f0d5e5143dac6cf56312ec88180e17a0feba3a4eeb2e7b2b169d67a",
    "crates/swarm-evolution/Cargo.toml": "0fca9be1e6d92ad2acdd70fa1b06994bd6a28fd16381c3b42b0255f427f4887c",
    "crates/swarm-runtime-workbench/Cargo.toml": "eab3a2b0578a2366e26604a69ca649ba03ce032d3fc45696876ae222573d24ce",
    "crates/swarm-cli/Cargo.toml": "0593667747de0b4cd7792170f2c6bfa8fb0a5051767dca97ede20fad44a23dfe",
    "crates/swarm-cli/src/core.inc": "a0def11bbf07f546082a72487d6260087822afc35e98f05b0817362a5c9692e2",
    "crates/swarm-governance/src/lib.rs": "2beaf67e5b1180752255484c6e8ad456354ac8c59f572fb4392d579005f92896",
    "crates/swarm-runtime/src/containment.rs": "813b259d69867ca71649f0f4a20fae30868a3405a5be1a217f467d8de53577ad",
    "crates/swarm-runtime/src/dispatcher.rs": "de7ad808ff477c7d1432b47360f4139e9ddaa5d5449a4fa5d21e28b5e86c8c8e",
    "crates/swarm-ingest-runtime/src/ingest/mod.rs": "33a272f43e892f47816eb6fe183f41d9afda86b3093b5258da0c7c6e8a3c7c47",
    "crates/swarm-runtime-http/src/bin/swarm_detect.rs": "51f81097ef4e5ba17f9a3757e8e413118f36572f9c844fef20729d4532da9a10",
    "crates/swarm-ingest-runtime/src/ingest/demo.rs": "18ed6e3ee9ea5d49a237de45067cf555f6e620264d9fd46c812180d10e110b0b",
    "crates/swarm-ingest-runtime/src/ingest/governance_resume.rs": "492614aa84da4f8da399408bf99a64009d1d686c8f79b70b06579a39e19a9645",
    "crates/swarm-ingest-runtime/src/ingest/health.rs": "3b875c6701baec37cf71692c9937d2e1a08bd477391c7529b05fb5a4c8325acd",
    "crates/swarm-ingest-runtime/src/ingest/platform_api.rs": "6a47977b16fd895e5bea265ce18335f6f8b291db28b9ab758591cfd4d8e7bc14",
    "crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs": "ec8fb17c3226fadbe6120a381714f88eccdf5225aa62a471923fc21df92d7adc",
    "crates/swarm-ingest-runtime/src/ingest/soar_verdict_handlers.rs": "c0a9d45eaf9302b1617295dfd7257e0158e35f1d16cd7bb429d45df9228f83fb",
}
GOVERNANCE_ASSURANCE_PACKAGE_FILE_INVENTORY = {
    "swarm-governance":
        (2, "f3345ca1525686353fb3dfccef2df4ae9b561b1b8c1dae065f285d01b3fe1b61"),
    "swarm-runtime":
        (127, "25f4c2939179f05df6545b3dfc89a5162e5ff0b5465056945667b24405af0df2"),
    "swarm-ingest-runtime":
        (14, "058ccc0dfa06a4d13d3edb22a534ee2fd142f8d764545d948fe0573e325d2a41"),
    "swarm-runtime-http":
        (22, "b6e62e6c68f65da711fd5362a7ddfde3e28663d18a7a8a225212c83902c01020"),
    "swarm-agents":
        (9, "3745e6436813b7f76b6cb5388db11064ddcab1bee77fd371cf5197a37e9789ec"),
    "swarm-evolution":
        (6, "de3afe080980d4901954dbddbef02f987a5eaef896b8af193efc05f0c4f028e9"),
    "swarm-runtime-workbench":
        (11, "b333bbfdc9f25b31982e33c30e49dc4663704b04ebc58531e93732300140f1f5"),
    "swarm-cli":
        (7, "31d1d554fba3635556d968f045861270859a24c7e1131607a8666467b09494db"),
}
GOVERNANCE_ASSURANCE_CLOSURE_CRATES = (
    "swarm-governance",
    "swarm-runtime",
    "swarm-ingest-runtime",
    "swarm-runtime-http",
    "swarm-agents",
    "swarm-evolution",
    "swarm-runtime-workbench",
    "swarm-cli",
)
GOVERNANCE_ASSURANCE_TARGET_ROOTS = {
    "crates/swarm-governance/src/lib.rs",
    "crates/swarm-runtime/src/lib.rs",
    "crates/swarm-runtime/src/bin/generate_adversary_emulation_report.rs",
    "crates/swarm-runtime/src/bin/swarm_debug_attest.rs",
    "crates/swarm-ingest-runtime/src/lib.rs",
    "crates/swarm-ingest-runtime/src/bin/generate_platform_openapi.rs",
    "crates/swarm-runtime-http/src/lib.rs",
    "crates/swarm-runtime-http/src/bin/swarm_detect.rs",
    "crates/swarm-runtime-http/src/bin/swarmctl.rs",
    "crates/swarm-agents/src/lib.rs",
    "crates/swarm-evolution/src/lib.rs",
    "crates/swarm-runtime-workbench/src/lib.rs",
    "crates/swarm-cli/src/lib.rs",
}
SINGLE_GOVERNOR_GATE_REL = "tools/check-single-governor-key.sh"
SINGLE_GOVERNOR_GATE_OUTPUT = (
    "single-governor-key gate: 94 fixture cases behaved as documented "
    "(76 adversarial, 18 controls); no key collection on the governance signing "
    "path; shipped governance authority is one opaque concrete handle with an "
    "authenticated mint (crates/swarm-governance/src crates/swarm-consensus/src "
    "crates/swarm-policy/src)"
)
EXPECTED_ROOT_EXECUTION_MANIFEST_DIGEST = "5d426b63b3f2a34e0aecd2157a3e5f68afb780bd62446b5f528ee747c3c86903"
ALLOWED_LOCAL_CUSTOM_BUILD = {
    "swarm-ingest-tetragon": {
        "manifest": "crates/swarm-ingest-tetragon/Cargo.toml",
        "manifest_digest": "6c5a7b0a586f2a2e82930b03fc05296faa8b0e7da4e6f41fa6612d8603023cb8",
        "script": "crates/swarm-ingest-tetragon/build.rs",
        "script_digest": "13dbbcdbe498167d853c7417d4271f2883b47893c8c501a21063e45c739b3fc3",
    },
}
PINNED_TOOLCHAIN = {
    "toolchain": {
        "channel": "1.97.1",
        "components": ["clippy", "rustfmt"],
    },
}
PINNED_RUST_VERSION = "1.97.1"
PINNED_RUSTC_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
PINNED_CARGO_COMMIT = "c980f4866141969fab6254a680546a277789d6f0"
SANITIZED_CARGO_HOME = None
PINNED_CARGO = None
PINNED_RUSTC = None
PINNED_HOST = None
DEPENDENCY_CACHE_HYDRATED = False
DEPENDENCY_FETCH_ACTIVE = False
RUSTC_AUDIT_WRAPPER = None
RUSTC_AUDIT_PROGRAM = None
RUSTC_AUDIT_LOG = None
RUSTC_AUDIT_ARTIFACT_DIGESTS = {}
REGISTERED_TARGETS = {
    ("swarm-policy", "negative_policy_gates"): "crates/swarm-policy/tests/negative_policy_gates.rs",
    ("swarm-response", "negative_containment_and_rollback"): "crates/swarm-response/tests/negative_containment_and_rollback.rs",
    ("swarm-runtime", "negative_runtime_fail_closed"): "crates/swarm-runtime/tests/negative_runtime_fail_closed.rs",
    ("swarm-spine", "negative_envelope_and_chain"): "crates/swarm-spine/tests/negative_envelope_and_chain.rs",
    (CONTRACT_CRATE, CONTRACT_TARGET): CONTRACT_REL,
}
ROW = re.compile(
    r"^\|\s*`(?P<invariant>[A-Z0-9][A-Z0-9-]*)`\s*"
    r"\|\s*`(?P<function>[A-Za-z0-9_:]+)`\s*\|",
    re.M,
)


class Report:
    def __init__(self): self.violations: list[tuple[str, str]] = []
    def violation(self, code, message): self.violations.append((code, message))
    def codes(self): return {code for code, _ in self.violations}


def rows(root, report):
    path = root / MAPPING_REL
    if not path.is_file(): report.violation("mapping-missing", f"{MAPPING_REL} missing"); return []
    return [{"invariant": m.group("invariant"), "function": m.group("function")} for m in ROW.finditer(path.read_text())]


def registry_document(root, report):
    path = root / REGISTRY_REL
    if not path.is_file(): report.violation("registry-missing", f"{REGISTRY_REL} missing"); return {}
    try: return tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as error:
        report.violation("registry-unparseable", str(error)); return {}


def entries(root, report):
    return registry_document(root, report).get("entry", [])


def listed_tests(output):
    tests = set()
    for line in output.splitlines():
        match = re.fullmatch(r"(?P<name>[A-Za-z0-9_:]+): test", line.strip())
        if match:
            tests.add(match.group("name"))
    return tests


def run_summary(output):
    matches = list(re.finditer(
        r"^test result: ok\. (?P<passed>\d+) passed; (?P<failed>\d+) failed; "
        r"(?P<ignored>\d+) ignored; (?P<measured>\d+) measured; "
        r"(?P<filtered>\d+) filtered out;",
        output,
        re.M,
    ))
    if len(matches) != 1:
        return None
    return {key: int(value) for key, value in matches[0].groupdict().items()}


def parse_toml(path, report, code):
    try:
        return tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        report.violation(code, f"{path}: {error}")
        return {}


def canonical_toml_digest(document):
    canonical = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def validate_toolchain_identity(root, report):
    document = parse_toml(root / "rust-toolchain.toml", report, "dependency-toolchain-read")
    if document != PINNED_TOOLCHAIN:
        report.violation(
            "dependency-toolchain-drift",
            f"rust-toolchain.toml semantics are {document!r}, expected {PINNED_TOOLCHAIN!r}",
        )


def cargo_config_sources(root):
    sources = []
    for directory in (root.resolve(), *root.resolve().parents):
        for name in ("config", "config.toml"):
            candidate = directory / ".cargo" / name
            if candidate.exists() or candidate.is_symlink():
                sources.append(candidate)
    return sources


BOOTSTRAP_ENVIRONMENT_NAMES = {
    "BASH_ENV",
    "BASHOPTS",
    "ENV",
    "SHELLOPTS",
}
WORKFLOW_LOADER_ENVIRONMENT_NAMES = {
    "LD_AUDIT",
    "LD_ASSUME_KERNEL",
    "LD_BIND_NOT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_ORIGIN_PATH",
    "LD_POINTER_GUARD",
    "LD_PREFER_MAP_32BIT_EXEC",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_TRACE_LOADED_OBJECTS",
    "LD_USE_LOAD_BIAS",
    "LD_VERBOSE",
    "LD_WARN",
    "GLIBC_TUNABLES",
    "DYLD_ABORT_MULTIPLE_INITS",
    "DYLD_DISABLE_DOFS",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_NO_FIX_PREBINDING",
    "DYLD_PRINT_APIS",
    "DYLD_PRINT_BINDINGS",
    "DYLD_PRINT_DOFS",
    "DYLD_PRINT_ENV",
    "DYLD_PRINT_INITIALIZERS",
    "DYLD_PRINT_LIBRARIES",
    "DYLD_PRINT_LIBRARIES_POST_LAUNCH",
    "DYLD_PRINT_OPTS",
    "DYLD_PRINT_REBASINGS",
    "DYLD_PRINT_RPATHS",
    "DYLD_PRINT_SEGMENTS",
    "DYLD_PRINT_STATISTICS",
    "DYLD_PRINT_STATISTICS_DETAILS",
    "DYLD_ROOT_PATH",
    "DYLD_SHARED_CACHE_DIR",
    "DYLD_SHARED_CACHE_DONT_VALIDATE",
    "DYLD_SHARED_REGION",
    "DYLD_IMAGE_SUFFIX",
    "DYLD_VERSIONED_FRAMEWORK_PATH",
    "DYLD_VERSIONED_LIBRARY_PATH",
}
WORKFLOW_BOOTSTRAP_SHELL = (
    "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
    "/bin/bash --noprofile --norc -e -o pipefail {0}"
)
PINNED_CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
WORKFLOW_GATE_JOBS = {
    "mapping-contract": (
        "tools/check-mapping.sh",
        "Check the invariant map against the source markers",
        "mapping-contract (${{ github.sha }})",
    ),
    "negative-registry-contract": (
        "tools/check-negative-registry.sh",
        "Check every mapped invariant has a falsifying negative test",
        "negative-registry-contract (${{ github.sha }})",
    ),
}
WORKFLOW_GLOBAL_ENVIRONMENT = (
    "env:\n"
    "  CARGO_TERM_COLOR: always\n"
    "  CARGO_TARGET_DIR: ${{ github.workspace }}/target/ci"
)


def bootstrap_override_names(environment):
    return sorted(
        name for name, value in environment.items()
        if value and (
            name in BOOTSTRAP_ENVIRONMENT_NAMES
            or name in WORKFLOW_LOADER_ENVIRONMENT_NAMES
            or name.startswith("BASH_FUNC_")
            or name.startswith("LD_")
            or name.startswith("DYLD_")
        )
    )


def validate_workflow_bootstrap(root, report):
    workflow = root / ".github/workflows/ci.yml"
    try:
        text = workflow.read_text()
    except OSError as error:
        report.violation("dependency-bootstrap-workflow-read", str(error))
        return
    invalid = []
    jobs_marker = "jobs:\n"
    prefix = text.split(jobs_marker, 1)[0] if jobs_marker in text else text
    workflow_environments = [
        match.group(0).rstrip()
        for match in re.finditer(r"(?ms)^env:\n(?:  [^\n]+\n?)+", prefix)
    ]
    if workflow_environments != [WORKFLOW_GLOBAL_ENVIRONMENT]:
        invalid.append(f"workflow-env={workflow_environments!r}")
    for job, (command, step_name, display_name) in WORKFLOW_GATE_JOBS.items():
        matches = list(re.finditer(
            rf"(?ms)^  {re.escape(job)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            text,
        ))
        expected = (
            f"  {job}:\n"
            f"    name: {display_name}\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - name: Checkout the candidate without persisted credentials\n"
            f"        uses: {PINNED_CHECKOUT}\n"
            "        with:\n"
            "          persist-credentials: false\n\n"
            f"      - name: {step_name}\n"
            f"        shell: {WORKFLOW_BOOTSTRAP_SHELL}\n"
            f"        run: {command}"
        )
        actual = matches[0].group(0).rstrip() if len(matches) == 1 else ""
        if actual != expected:
            invalid.append(f"{job}-job={actual!r}")
    if invalid:
        report.violation(
            "dependency-bootstrap-workflow-drift",
            f"mapping/negative-registry jobs are not the exact fresh-runner boundary: {invalid}",
        )


def cargo_target_environment_name(target):
    return re.sub(r"[^A-Za-z0-9]", "_", target).upper()


def cargo_override_names(environment, *, active_target_only=True):
    forbidden = {
        "RUSTC",
        "RUSTDOC",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_BOOTSTRAP",
        "RUSTUP_HOME",
        "CC",
        "CXX",
        "AR",
        "LD",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTDOC",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_TARGET",
    }
    configured = []
    for name, value in environment.items():
        if not value:
            continue
        if name == "RUSTUP_TOOLCHAIN":
            if value != PINNED_RUST_VERSION:
                configured.append(name)
            continue
        target_override = re.fullmatch(
            r"CARGO_TARGET_([A-Z0-9_]+)_(?:LINKER|RUNNER|RUSTFLAGS|RUSTDOCFLAGS)",
            name,
        )
        if target_override is not None:
            if (
                active_target_only
                and PINNED_HOST is not None
                and target_override.group(1) != cargo_target_environment_name(PINNED_HOST)
            ):
                continue
            configured.append(name)
            continue
        if (
            name in forbidden
            or re.fullmatch(r"CARGO_(?:REGISTRIES|CREDENTIAL)_[A-Z0-9_]+", name)
            or re.fullmatch(r"(?:CC|CXX|AR|RANLIB)_[A-Za-z0-9_-]+", name)
        ):
            configured.append(name)
    return sorted(configured)


def resolve_pinned_toolchain(report):
    global PINNED_HOST
    account_home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
    rustup = account_home / ".cargo/bin/rustup"
    if not rustup.is_file():
        report.violation(
            "dependency-toolchain-unavailable",
            f"account-owned rustup is absent at {rustup}",
        )
        return None, None
    environment = {
        "HOME": str(account_home),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }

    resolved = {}
    for tool in ("cargo", "rustc"):
        result = subprocess.run(
            [str(rustup), "which", "--toolchain", PINNED_RUST_VERSION, tool],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        path = pathlib.Path(result.stdout.strip()).resolve() if result.returncode == 0 else None
        if result.returncode or path is None or not path.is_file():
            report.violation(
                "dependency-toolchain-unavailable",
                f"could not resolve pinned {tool}: {result.stderr[-1000:]}",
            )
        else:
            resolved[tool] = path
    if len(resolved) != 2:
        return None, None

    rustc_version = subprocess.run(
        [str(resolved["rustc"]), "-vV"],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    cargo_version = subprocess.run(
        [str(resolved["cargo"]), "-vV"],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    rustc_expected = (
        rustc_version.returncode == 0
        and f"release: {PINNED_RUST_VERSION}" in rustc_version.stdout
        and f"commit-hash: {PINNED_RUSTC_COMMIT}" in rustc_version.stdout
    )
    cargo_expected = (
        cargo_version.returncode == 0
        and f"release: {PINNED_RUST_VERSION}" in cargo_version.stdout
        and f"commit-hash: {PINNED_CARGO_COMMIT}" in cargo_version.stdout
    )
    if not rustc_expected or not cargo_expected:
        report.violation(
            "dependency-toolchain-binary-drift",
            "resolved cargo/rustc do not match the pinned release and commit identities",
        )
        return None, None
    host = re.search(r"^host: (\S+)$", rustc_version.stdout, re.M)
    if host is None:
        report.violation(
            "dependency-toolchain-binary-drift",
            "resolved rustc did not report a host target",
        )
        return None, None
    PINNED_HOST = host.group(1)
    return resolved["cargo"], resolved["rustc"]


def configure_sanitized_cargo_boundary(report):
    global SANITIZED_CARGO_HOME, PINNED_CARGO, PINNED_RUSTC
    global DEPENDENCY_CACHE_HYDRATED, DEPENDENCY_FETCH_ACTIVE
    global RUSTC_AUDIT_WRAPPER, RUSTC_AUDIT_PROGRAM, RUSTC_AUDIT_LOG
    global RUSTC_AUDIT_ARTIFACT_DIGESTS
    PINNED_CARGO, PINNED_RUSTC = resolve_pinned_toolchain(report)
    DEPENDENCY_CACHE_HYDRATED = False
    DEPENDENCY_FETCH_ACTIVE = False
    if PINNED_CARGO is None or PINNED_RUSTC is None:
        return
    assurance_target = REPO_ROOT / "target/phase285-negative-registry"
    assurance_target.mkdir(parents=True, exist_ok=True)
    SANITIZED_CARGO_HOME = assurance_target / "cargo-home"
    if SANITIZED_CARGO_HOME.is_symlink():
        SANITIZED_CARGO_HOME.unlink()
    elif SANITIZED_CARGO_HOME.exists():
        shutil.rmtree(SANITIZED_CARGO_HOME)
    SANITIZED_CARGO_HOME.mkdir()
    for name in ("registry", "git"):
        destination = SANITIZED_CARGO_HOME / name
        destination.mkdir()
    RUSTC_AUDIT_LOG = SANITIZED_CARGO_HOME / "rustc-audit.jsonl"
    RUSTC_AUDIT_PROGRAM = assurance_target / "rustc-audit.py"
    RUSTC_AUDIT_WRAPPER = assurance_target / "rustc-audit.sh"
    RUSTC_AUDIT_PROGRAM.write_text(
        "import hashlib, json, os, pathlib, sys\n"
        f"pinned = pathlib.Path({str(PINNED_RUSTC)!r}).resolve()\n"
        "compiler = pathlib.Path(sys.argv[1]).resolve()\n"
        "if compiler != pinned:\n"
        "    raise SystemExit(f'unexpected rustc: {compiler}, expected {pinned}')\n"
        "arguments = sys.argv[2:]\n"
        "sources = []\n"
        "for argument in arguments:\n"
        "    candidate = pathlib.Path(argument)\n"
        "    if argument.endswith('.rs') and candidate.is_file():\n"
        "        source = candidate.resolve()\n"
        "        sources.append({'path': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()})\n"
        "crate_name = arguments[arguments.index('--crate-name') + 1] if '--crate-name' in arguments else None\n"
        "cap_lints = arguments[arguments.index('--cap-lints') + 1] if '--cap-lints' in arguments else None\n"
        "record = {'compiler': str(compiler), 'sources': sources, 'crate_name': crate_name, 'test': '--test' in arguments, 'cap_lints': cap_lints}\n"
        "with open(os.environ['PHASE285_RUSTC_AUDIT_LOG'], 'a', encoding='utf-8') as audit:\n"
        "    audit.write(json.dumps(record, sort_keys=True) + '\\n')\n"
        "os.execv(str(pinned), [str(pinned), *arguments])\n"
    )
    RUSTC_AUDIT_WRAPPER.write_text(
        "#!/bin/sh\n"
        f"exec {json.dumps(sys.executable)} -I {json.dumps(str(RUSTC_AUDIT_PROGRAM))} \"$@\"\n"
    )
    RUSTC_AUDIT_WRAPPER.chmod(0o755)
    RUSTC_AUDIT_ARTIFACT_DIGESTS = {
        path: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (RUSTC_AUDIT_PROGRAM, RUSTC_AUDIT_WRAPPER)
    }


def sanitized_cargo_environment(
    *, target_dir=None, extra=None, audit=True, source_environment=None,
):
    if SANITIZED_CARGO_HOME is None or PINNED_RUSTC is None:
        raise RuntimeError("sanitized Cargo boundary is not configured")
    environment = dict(os.environ if source_environment is None else source_environment)
    for name in list(environment):
        if (
            name in cargo_override_names(
                {name: environment[name]}, active_target_only=False,
            )
            or name in {
                "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP_TOOLCHAIN",
                "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT",
            }
            or name in BOOTSTRAP_ENVIRONMENT_NAMES
            or name in WORKFLOW_LOADER_ENVIRONMENT_NAMES
            or name.startswith("BASH_FUNC_")
            or name.startswith("LD_")
            or name.startswith("DYLD_")
        ):
            environment.pop(name, None)
    environment.update({
        "HOME": pwd.getpwuid(os.getuid()).pw_dir,
        "CARGO_HOME": str(SANITIZED_CARGO_HOME),
        "CARGO_TARGET_DIR": str(
            pathlib.Path(target_dir).resolve()
            if target_dir is not None
            else (REPO_ROOT / "target/phase285-negative-registry/build").resolve()
        ),
        "RUSTUP_TOOLCHAIN": PINNED_RUST_VERSION,
        "RUSTC": str(PINNED_RUSTC),
        "PATH": ":".join((str(PINNED_RUSTC.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
    })
    if audit:
        environment.update({
            "RUSTC_WRAPPER": str(RUSTC_AUDIT_WRAPPER),
            "PHASE285_RUSTC_AUDIT_LOG": str(RUSTC_AUDIT_LOG),
        })
    if extra:
        environment.update(extra)
    return environment


def sanitized_runtime_environment(*, source_environment=None):
    environment = dict(os.environ if source_environment is None else source_environment)
    for name in list(environment):
        if (
            name in cargo_override_names(
                {name: environment[name]}, active_target_only=False,
            )
            or name.startswith("CARGO_")
            or name.startswith("RUSTUP_")
            or name in {
                "PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT",
            }
            or name in BOOTSTRAP_ENVIRONMENT_NAMES
            or name in WORKFLOW_LOADER_ENVIRONMENT_NAMES
            or name.startswith("BASH_FUNC_")
            or name.startswith("LD_")
            or name.startswith("DYLD_")
        ):
            environment.pop(name, None)
    environment.update({
        "HOME": pwd.getpwuid(os.getuid()).pw_dir,
        "PATH": ":".join((str(PINNED_RUSTC.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")),
    })
    return environment


def run_cargo(arguments, *, cwd, target_dir=None, extra_environment=None, audit=True, **kwargs):
    arguments = list(arguments)
    command = arguments[0] if arguments else ""
    dependency_commands = {"build", "check", "metadata", "run", "rustc", "test"}
    if command in dependency_commands:
        if not DEPENDENCY_CACHE_HYDRATED:
            return subprocess.CompletedProcess(
                [str(PINNED_CARGO), *arguments], 125, stdout="",
                stderr="refused dependency-resolving Cargo before controlled cache hydration",
            )
        if "--locked" not in arguments:
            arguments.insert(1, "--locked")
        if "--offline" not in arguments:
            arguments.insert(2, "--offline")
    elif command == "generate-lockfile":
        if not DEPENDENCY_CACHE_HYDRATED:
            return subprocess.CompletedProcess(
                [str(PINNED_CARGO), *arguments], 125, stdout="",
                stderr="refused lock generation before controlled cache hydration",
            )
        if "--offline" not in arguments:
            arguments.insert(1, "--offline")
    elif command == "fetch":
        if "--locked" not in arguments:
            return subprocess.CompletedProcess(
                [str(PINNED_CARGO), *arguments], 125, stdout="",
                stderr="refused Cargo fetch without --locked",
            )
        if not DEPENDENCY_FETCH_ACTIVE and "--offline" not in arguments:
            return subprocess.CompletedProcess(
                [str(PINNED_CARGO), *arguments], 125, stdout="",
                stderr="refused any network-capable Cargo fetch outside controlled hydration",
            )
    config_sources = cargo_config_sources(pathlib.Path(cwd))
    if config_sources:
        return subprocess.CompletedProcess(
            [str(PINNED_CARGO), *arguments],
            125,
            stdout="",
            stderr=f"refused Cargo config sources: {[str(path) for path in config_sources]}",
        )
    if audit:
        changed = audit_artifact_changes()
        if changed:
            return subprocess.CompletedProcess(
                [str(PINNED_CARGO), *arguments], 125, stdout="",
                stderr=f"refused modified compiler-audit artifacts before Cargo: {changed}",
            )
    result = subprocess.run(
        [str(PINNED_CARGO), *arguments],
        cwd=cwd,
        env=sanitized_cargo_environment(
            target_dir=target_dir,
            extra=extra_environment,
            audit=audit,
        ),
        **kwargs,
    )
    if audit:
        changed = audit_artifact_changes()
        if changed:
            stderr = result.stderr or ""
            return subprocess.CompletedProcess(
                result.args, 125, stdout=result.stdout,
                stderr=f"{stderr}\ncompiler-audit artifacts changed during Cargo: {changed}",
            )
    return result


def hydrate_locked_workspace_cache(report):
    global DEPENDENCY_CACHE_HYDRATED, DEPENDENCY_FETCH_ACTIVE
    dependency_domains = (
        (REPO_ROOT / "Cargo.toml", REPO_ROOT / "Cargo.lock"),
        (
            REPO_ROOT / "tools/negative-registry-ast/Cargo.toml",
            REPO_ROOT / "tools/negative-registry-ast/Cargo.lock",
        ),
    )
    lock_digests = {
        lock_path: hashlib.sha256(lock_path.read_bytes()).hexdigest()
        for _manifest_path, lock_path in dependency_domains
    }
    registered = registry_document(REPO_ROOT, report).get("entry", [])
    input_snapshot = execution_input_snapshot(REPO_ROOT, registered)
    invalid_sources = []
    for _manifest_path, lock_path in dependency_domains:
        relative_lock = str(lock_path.relative_to(REPO_ROOT))
        lock = parse_toml(lock_path, report, "dependency-lock-read")
        for package in lock.get("package", []):
            source = package.get("source")
            if source is None:
                continue
            checksum = package.get("checksum")
            if source != CRATES_IO_SOURCE or not isinstance(checksum, str) \
                    or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
                invalid_sources.append((
                    relative_lock,
                    package.get("name"),
                    package.get("version"),
                    source,
                    checksum,
                ))
    if invalid_sources:
        report.violation(
            "dependency-cache-source-unpinned",
            "a tracked dependency lock contains non-registry or non-checksummed "
            f"sources: {invalid_sources}",
        )
        return
    fetch_failures = []
    DEPENDENCY_FETCH_ACTIVE = True
    try:
        for manifest_path, _lock_path in dependency_domains:
            fetched = run_cargo(
                [
                    "fetch", "--locked",
                    "--manifest-path", str(manifest_path),
                ],
                cwd=REPO_ROOT,
                audit=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if fetched.returncode:
                fetch_failures.append((
                    str(manifest_path.relative_to(REPO_ROOT)),
                    fetched.stderr[-4000:],
                ))
    finally:
        DEPENDENCY_FETCH_ACTIVE = False
    if fetch_failures:
        report.violation(
            "dependency-cache-hydration-failed",
            "could not hydrate the empty gate-owned Cargo cache exclusively from "
            f"the tracked locked/checksummed resolutions: {fetch_failures}",
        )
    for _manifest_path, lock_path in dependency_domains:
        current_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        if current_digest != lock_digests[lock_path]:
            report.violation(
                "dependency-cache-lock-mutated",
                f"Cargo fetch changed {lock_path.relative_to(REPO_ROOT)} from "
                f"{lock_digests[lock_path]} to {current_digest}",
            )
    current_snapshot = execution_input_snapshot(REPO_ROOT, registered)
    if current_snapshot != input_snapshot:
        report.violation(
            "dependency-cache-input-mutated",
            "Cargo fetch changed the exact protected execution-input snapshot",
        )
    if not report.violations:
        DEPENDENCY_CACHE_HYDRATED = True


def audit_artifact_changes():
    changed = []
    for path, expected in RUSTC_AUDIT_ARTIFACT_DIGESTS.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        if actual != expected:
            changed.append(str(path))
    return changed


def root_execution_manifest(document):
    return {
        name: document[name]
        for name in ("workspace", "profile", "target", "patch", "replace")
        if name in document
    }


def validate_manifest_semantic_identity(relative, document, report):
    expected = EXPECTED_CRATE_MANIFEST_DIGESTS.get(relative)
    if expected is None:
        report.violation(
            "dependency-manifest-semantic-baseline-missing",
            f"{relative} has no checker-owned semantic baseline",
        )
        return
    actual = canonical_toml_digest(document)
    if actual != expected:
        report.violation(
            "dependency-manifest-semantic-drift",
            f"{relative} semantic digest is {actual}, expected {expected}",
        )


def validate_root_manifest_semantic_identity(document, report):
    actual = canonical_toml_digest(root_execution_manifest(document))
    if actual != EXPECTED_ROOT_EXECUTION_MANIFEST_DIGEST:
        report.violation(
            "dependency-root-manifest-semantic-drift",
            f"Cargo.toml execution semantic digest is {actual}, expected {EXPECTED_ROOT_EXECUTION_MANIFEST_DIGEST}",
        )


def validate_registered_manifest_test_shape(relative, document, report):
    package_table = document.get("package", {})
    if package_table.get("version") != {"workspace": True} or package_table.get("edition") != {"workspace": True}:
        report.violation(
            "dependency-manifest-identity",
            f"{relative} must inherit package version and edition from the workspace",
        )
    if package_table.get("autotests") is False:
        report.violation(
            "dependency-manifest-autotests-disabled",
            f"{relative} disables automatic integration-test discovery",
        )
    if document.get("test") is not None:
        report.violation(
            "dependency-manifest-explicit-test",
            f"{relative} defines explicit [[test]] targets; registered tests must use canonical auto-discovery",
        )
    if package_table.get("build") is not None or document.get("build-dependencies") is not None:
        report.violation(
            "dependency-manifest-build-script",
            f"{relative} adds a build script or build dependencies to a registered target crate",
        )
    if document.get("lib") is not None:
        report.violation(
            "dependency-manifest-library-override",
            f"{relative} overrides the canonical auto-discovered library target",
        )


def validate_registered_build_script_path(root, relative, report):
    build_script = (root / relative).parent / "build.rs"
    if build_script.exists():
        report.violation(
            "dependency-manifest-build-script",
            f"{relative} has an auto-discovered build.rs",
        )


def validate_governance_assurance_identity(root, report):
    for relative, expected in GOVERNANCE_ASSURANCE_INPUT_DIGESTS.items():
        path = root / relative
        if path.is_symlink() or not path.is_file():
            report.violation(
                "governance-assurance-input-identity",
                f"{relative} must be the exact regular-file governance assurance input",
            )
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            report.violation(
                "governance-assurance-input-drift",
                f"{relative} digest is {actual}, expected {expected}",
            )
    for crate_name, expected in GOVERNANCE_ASSURANCE_PACKAGE_FILE_INVENTORY.items():
        crate_root = root / "crates" / crate_name
        entries = sorted(crate_root.rglob("*")) if crate_root.is_dir() else []
        symlinks = [path for path in entries if path.is_symlink()]
        files = [path for path in entries if path.is_file() and not path.is_symlink()]
        inventory = "".join(
            f"{path.relative_to(root)}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n"
            for path in files
        )
        actual = (len(files), hashlib.sha256(inventory.encode()).hexdigest())
        if symlinks or actual != expected:
            report.violation(
                "governance-assurance-package-input-drift",
                f"{crate_name} complete regular-file identity is {actual}, expected "
                f"{expected}; symlinks="
                f"{sorted(str(path.relative_to(root)) for path in symlinks)}",
            )
    validate_registered_build_script_path(
        root,
        "crates/swarm-governance/Cargo.toml",
        report,
    )


def execute_single_governor_gate(
    root, report, *, mutation_probe=False, cache_source=None,
):
    gate = (root / SINGLE_GOVERNOR_GATE_REL).resolve()
    environment = sanitized_runtime_environment()
    environment["SWARM_NEGATIVE_REGISTRY_PROTECTED"] = "1"
    environment["SWARM_SINGLE_GOVERNOR_CACHE_SOURCE"] = str(
        SANITIZED_CARGO_HOME if cache_source is None else cache_source
    )
    if mutation_probe:
        environment["SWARM_SINGLE_GOVERNOR_MUTATION_PROBE"] = "1"
    try:
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", str(gate)],
            cwd=root,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120 if mutation_probe else 600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        report.violation("governance-assurance-gate-failed", str(error))
        return None
    if result.returncode or result.stdout.strip() != SINGLE_GOVERNOR_GATE_OUTPUT:
        report.violation(
            "governance-assurance-gate-failed",
            "the exact single-governor gate did not produce its pinned semantic verdict: "
            f"exit={result.returncode}, stdout={result.stdout[-2000:]!r}, "
            f"stderr={result.stderr[-2000:]!r}",
        )
    return result


def validate_dependency_manifests(root, report):
    root_manifest = parse_toml(root / "Cargo.toml", report, "dependency-manifest-read")
    validate_root_manifest_semantic_identity(root_manifest, report)
    if "patch" in root_manifest or "replace" in root_manifest:
        report.violation("dependency-manifest-substitution", "root Cargo.toml may not define [patch] or [replace]")
    workspace = root_manifest.get("workspace", {})
    dependencies = workspace.get("dependencies", {}) if isinstance(workspace, dict) else {}
    expected_workspace = {
        "async-trait": "0.1",
        "serde": {"version": "1", "features": ["derive"]},
        "serde_json": "1",
        "tokio": {"version": "1", "features": ["full"]},
    }
    for name, expected in expected_workspace.items():
        if dependencies.get(name) != expected:
            report.violation(
                "dependency-manifest-identity",
                f"workspace dependency `{name}` is {dependencies.get(name)!r}, expected {expected!r}",
            )

    required_by_crate = {
        "swarm-governance": {
            "dependencies": {"async-trait", "serde", "serde_json"},
            "dev-dependencies": {"tokio"},
        },
        "swarm-policy": {"dependencies": {"serde", "serde_json"}, "dev-dependencies": {"serde_json"}},
        "swarm-response": {"dependencies": {"async-trait", "serde", "serde_json", "tokio"}},
        "swarm-runtime": {"dependencies": {"async-trait", "serde", "serde_json", "tokio"}},
        "swarm-spine": {"dependencies": {"serde", "serde_json", "tokio"}},
    }
    for package, sections in required_by_crate.items():
        relative, _ = PRODUCTION_PACKAGES[package]
        document = parse_toml(root / relative, report, "dependency-manifest-read")
        if "patch" in document or "replace" in document:
            report.violation("dependency-manifest-substitution", f"{relative} may not define [patch] or [replace]")
        if document.get("package", {}).get("name") != package:
            report.violation("dependency-manifest-identity", f"{relative} package name is not `{package}`")
        validate_manifest_semantic_identity(relative, document, report)
        validate_registered_manifest_test_shape(relative, document, report)
        validate_registered_build_script_path(root, relative, report)
        for section, names in sections.items():
            values = document.get(section, {})
            for name in names:
                if values.get(name) != {"workspace": True}:
                    report.violation(
                        "dependency-manifest-identity",
                        f"{relative} {section}.{name} is {values.get(name)!r}, expected workspace = true",
                    )


def validate_cargo_execution_boundary(root, report, *, check_environment=True, environment=None):
    for source in cargo_config_sources(root):
        report.violation(
            "dependency-cargo-config",
            f"Cargo config source {source} may alter compiler or runner identity",
        )
    if check_environment:
        environment = os.environ if environment is None else environment
        configured = cargo_override_names(environment)
        configured.extend(bootstrap_override_names(environment))
        configured = sorted(set(configured))
        if configured:
            report.violation(
                "dependency-execution-environment",
                f"compiler, target, flags, or runner override environment is set: {configured}",
            )


def validate_production_metadata_targets(
    root,
    metadata_packages,
    resolved_ids,
    report,
    production_packages=PRODUCTION_PACKAGES,
):
    for name, (relative, lib_name) in production_packages.items():
        package_root = (root / relative).parent.resolve()
        expected_manifest = str((root / relative).resolve())
        expected_id = f"path+{package_root.as_uri()}#0.1.0"
        matching = [package for package in metadata_packages if package.get("name") == name]
        actual = [
            (
                package.get("version"),
                package.get("source"),
                package.get("manifest_path"),
                package.get("id"),
            )
            for package in matching
        ]
        expected_package = [("0.1.0", None, expected_manifest, expected_id)]
        if actual != expected_package or matching[0].get("id") not in resolved_ids:
            report.violation(
                "dependency-production-package-identity",
                f"resolved `{name}` identity is {actual!r}, expected {expected_package!r}",
            )
            continue

        targets = matching[0].get("targets", [])
        library_targets = [target for target in targets if "lib" in target.get("kind", [])]
        expected_library = {
            "name": lib_name,
            "kind": ["lib"],
            "crate_types": ["lib"],
            "src_path": str((package_root / "src/lib.rs").resolve()),
            "edition": "2024",
            "doc": True,
            "doctest": True,
            "test": True,
        }
        actual_library = [] if len(library_targets) != 1 else [
            {field: library_targets[0].get(field) for field in expected_library}
        ]
        if actual_library != [expected_library]:
            report.violation(
                "dependency-production-target-identity",
                f"resolved `{name}/{lib_name}` library target is {actual_library!r}, expected {[expected_library]!r}",
            )
        custom_builds = [
            target.get("name") for target in targets
            if "custom-build" in target.get("kind", [])
        ]
        if custom_builds:
            report.violation(
                "dependency-custom-build-target",
                f"resolved `{name}` has unexpected custom-build targets {custom_builds!r}",
            )


def validate_local_custom_build_targets(root, metadata_packages, report):
    observed = set()
    for package in metadata_packages:
        if package.get("source") is not None:
            continue
        custom_targets = [
            target for target in package.get("targets", [])
            if "custom-build" in target.get("kind", [])
        ]
        if not custom_targets:
            continue
        name = package.get("name")
        expected = ALLOWED_LOCAL_CUSTOM_BUILD.get(name)
        if expected is None:
            report.violation(
                "dependency-local-custom-build-target",
                f"resolved local package `{name}` has an unreviewed custom-build target",
            )
            continue
        observed.add(name)
        manifest = (root / expected["manifest"]).resolve()
        script = (root / expected["script"]).resolve()
        expected_target = {
            "name": "build-script-build",
            "kind": ["custom-build"],
            "crate_types": ["bin"],
            "src_path": str(script),
            "edition": "2024",
            "doc": False,
            "doctest": False,
            "test": False,
        }
        actual_targets = [
            {field: target.get(field) for field in expected_target}
            for target in custom_targets
        ]
        manifest_digest = (
            canonical_toml_digest(parse_toml(
                manifest, report, "dependency-local-custom-build-manifest-read",
            ))
            if manifest.is_file() else None
        )
        script_digest = (
            hashlib.sha256(script.read_bytes()).hexdigest() if script.is_file() else None
        )
        if (
            pathlib.Path(package.get("manifest_path", "")).resolve() != manifest
            or actual_targets != [expected_target]
            or manifest_digest != expected["manifest_digest"]
            or script_digest != expected["script_digest"]
        ):
            report.violation(
                "dependency-local-custom-build-identity",
                f"resolved local custom build `{name}` does not match its reviewed manifest, target, and script digests",
            )
    missing = set(ALLOWED_LOCAL_CUSTOM_BUILD) - observed
    if missing:
        report.violation(
            "dependency-local-custom-build-missing",
            f"reviewed local custom builds are absent from metadata: {sorted(missing)}",
        )


def validate_lock_resolution_identity(root, report, expected=PINNED_RESOLUTION):
    lock = parse_toml(root / "Cargo.lock", report, "dependency-lock-read")
    packages = lock.get("package", [])
    for name, identity in expected.items():
        matching = [package for package in packages if package.get("name") == name]
        actual = [(item.get("version"), item.get("source"), item.get("checksum")) for item in matching]
        if actual != [identity]:
            report.violation("dependency-lock-identity", f"Cargo.lock `{name}` identity is {actual!r}, expected {[identity]!r}")


def validate_resolution_identity(root, report, expected=PINNED_RESOLUTION, *, production_packages=True):
    validate_lock_resolution_identity(root, report, expected)
    metadata_result = run_cargo(
        ["metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if metadata_result.returncode:
        report.violation("dependency-metadata-failed", metadata_result.stderr[-4000:])
        return
    try:
        metadata = json.loads(metadata_result.stdout)
    except json.JSONDecodeError as error:
        report.violation("dependency-metadata-invalid", str(error))
        return
    resolved_ids = {node.get("id") for node in metadata.get("resolve", {}).get("nodes", [])}
    metadata_packages = metadata.get("packages", [])
    for name, (version, source, _checksum) in expected.items():
        matching = [
            package for package in metadata_packages
            if package.get("name") == name and package.get("version") == version
        ]
        identities = [(package.get("version"), package.get("source")) for package in matching]
        if identities != [(version, source)] or matching[0].get("id") not in resolved_ids:
            report.violation(
                "dependency-metadata-identity",
                f"resolved `{name}` identity is {identities!r}, expected {[(version, source)]!r}",
            )
    if production_packages:
        validate_production_metadata_targets(root, metadata_packages, resolved_ids, report)
        validate_metadata_test_targets(root, metadata_packages, resolved_ids, report)
        validate_local_custom_build_targets(root, metadata_packages, report)


def expected_test_target(root, relative):
    return {
        "kind": ["test"],
        "crate_types": ["bin"],
        "src_path": str((root / relative).resolve()),
        "edition": "2024",
        "doc": False,
        "doctest": False,
        "test": True,
    }


def validate_metadata_test_targets(root, metadata_packages, resolved_ids, report, targets=REGISTERED_TARGETS):
    for (package_name, target_name), relative in targets.items():
        packages = [package for package in metadata_packages if package.get("name") == package_name]
        matching = [] if len(packages) != 1 else [
            target for target in packages[0].get("targets", []) if target.get("name") == target_name
        ]
        expected = expected_test_target(root, relative)
        actual = [] if len(matching) != 1 else [
            {field: matching[0].get(field) for field in expected}
        ]
        if (
            len(packages) != 1
            or packages[0].get("id") not in resolved_ids
            or (
                package_name in PRODUCTION_PACKAGES
                and packages[0].get("id")
                != f"path+{((root / PRODUCTION_PACKAGES[package_name][0]).parent.resolve()).as_uri()}#0.1.0"
            )
            or actual != [expected]
        ):
            report.violation(
                "dependency-test-target-identity",
                f"resolved `{package_name}/{target_name}` target is {actual!r}, expected {[expected]!r}",
            )


def validate_execution_dependencies(root, report):
    validate_toolchain_identity(root, report)
    validate_workflow_bootstrap(root, report)
    validate_governance_assurance_identity(root, report)
    validate_dependency_manifests(root, report)
    validate_cargo_execution_boundary(root, report)
    validate_resolution_identity(root, report)


def compiled_test_binary(root, crate, target, report, code, expected_source=None, expected_package_id=None):
    production_audit = root.resolve() == REPO_ROOT.resolve()
    if production_audit:
        RUSTC_AUDIT_LOG.unlink(missing_ok=True)
        nonce = secrets.token_hex(12)
        command = [
            "rustc", "--locked", "-p", crate, "--test", target,
            "--message-format=json", "--", "-C", f"metadata=phase285_assurance_audit_{nonce}",
        ]
    else:
        command = [
            "test", "--locked", "-p", crate, "--test", target,
            "--no-run", "--message-format=json",
        ]
    result = run_cargo(
        command,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        report.violation(code, f"{crate}/{target} compilation failed:\n{result.stderr[-4000:]}")
        return None
    expected_source = expected_source or REGISTERED_TARGETS.get((crate, target))
    if production_audit:
        source_path = (root / expected_source).resolve()
        expected_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        try:
            audit_records = [
                json.loads(line) for line in RUSTC_AUDIT_LOG.read_text().splitlines()
                if line.strip()
            ]
        except (OSError, json.JSONDecodeError) as error:
            report.violation(code, f"{crate}/{target} compiler audit is unreadable: {error}")
            return None
        expected_crate_name = target.replace("-", "_")
        matching_audits = [
            record for record in audit_records
            if record.get("compiler") == str(PINNED_RUSTC)
            and record.get("crate_name") == expected_crate_name
            and record.get("test") is True
            and record.get("sources") == [{"path": str(source_path), "sha256": expected_digest}]
        ]
        if len(matching_audits) != 1:
            report.violation(
                code,
                f"{crate}/{target} has {len(matching_audits)} exact audited test compilations; expected one",
            )
            return None
    expected_target = expected_test_target(root, expected_source) if expected_source else None
    if expected_package_id is None and crate in PRODUCTION_PACKAGES:
        package_manifest, _lib_name = PRODUCTION_PACKAGES[crate]
        package_root = (root / package_manifest).parent.resolve()
        expected_package_id = f"path+{package_root.as_uri()}#0.1.0"
    executables = []
    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        target_data = message.get("target", {})
        target_identity = None if expected_target is None else {
            field: target_data.get(field) for field in expected_target
        }
        if (
            message.get("reason") == "compiler-artifact"
            and target_data.get("name") == target
            and "test" in target_data.get("kind", [])
            and (expected_target is None or target_identity == expected_target)
            and (expected_package_id is None or message.get("package_id") == expected_package_id)
            and message.get("profile", {}).get("test") is True
            and message.get("executable")
        ):
            executables.append(pathlib.Path(message["executable"]))
    unique = sorted(set(executables))
    if len(unique) != 1 or not unique[0].is_file():
        report.violation(code, f"{crate}/{target} emitted test binaries are {unique!r}, expected one existing artifact")
        return None
    return unique[0]


def registered_source_cache(root, registered):
    cached = {}
    for relative in sorted({str(entry.get("test_file", "")) for entry in registered}):
        path = root / relative
        if path.is_file():
            raw = path.read_text(encoding="utf-8", errors="replace")
            cached[relative] = (raw, sanitize_rust(raw)[0])
    return cached


def execution_input_snapshot(root, registered):
    governance_closure_inputs = {
        str(path.relative_to(root))
        for crate_name in GOVERNANCE_ASSURANCE_CLOSURE_CRATES
        for path in (root / "crates" / crate_name).rglob("*")
        if path.is_file() or path.is_symlink()
    }
    relative_paths = {
        MAPPING_REL,
        REGISTRY_REL,
        UNIVERSE_REL,
        PROTOCOL_REL,
        CONTRACT_REL,
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        *GOVERNANCE_ASSURANCE_INPUT_DIGESTS,
        *GOVERNANCE_ASSURANCE_TARGET_ROOTS,
        *governance_closure_inputs,
        *(
            f"crates/{crate_name}/build.rs"
            for crate_name in GOVERNANCE_ASSURANCE_CLOSURE_CRATES
        ),
        *(entry["manifest"] for entry in ALLOWED_LOCAL_CUSTOM_BUILD.values()),
        *(entry["script"] for entry in ALLOWED_LOCAL_CUSTOM_BUILD.values()),
        ".cargo/config",
        ".cargo/config.toml",
        *(entry.get("test_file", "") for entry in registered),
        *(relative for relative, _lib_name in PRODUCTION_PACKAGES.values()),
        *(
            str(pathlib.PurePosixPath(relative).parent / "src/lib.rs")
            for relative, _lib_name in PRODUCTION_PACKAGES.values()
        ),
        *(
            str(pathlib.PurePosixPath(relative).parent / "build.rs")
            for relative, _lib_name in PRODUCTION_PACKAGES.values()
        ),
    }
    snapshot = {}
    for relative in sorted(relative_paths):
        path = root / relative
        snapshot[relative] = path.read_bytes() if path.is_file() else None
    return snapshot


def run_ast_checks(root, registered, report, source_cache):
    lines = []
    binding_rows = []
    for entry in registered:
        relative = str(entry.get("test_file", ""))
        cached = source_cache.get(relative)
        if cached is None:
            continue
        _raw, clean = cached
        test = test_function(clean, str(entry.get("test_fn", "")))
        if test is None:
            continue
        macro_path = "negative_protocol::assert_registered_negative_case"
        edge_validation = str(entry.get("edge_validation", ""))
        fields = [
            str(entry.get("invariant", "")),
            relative,
            str(entry.get("test_fn", "")),
            str(entry.get("case_type", "")),
            str(entry.get("real_adapter", "")),
            str(entry.get("production_fn", "")),
            str(entry.get("production_entry", "")),
            str(entry.get("broken_variant", "")),
            macro_path,
            edge_validation,
        ]
        if any("\t" in field or "\n" in field for field in fields):
            report.violation("ast-contract-field", f"entry `{fields[0]}` has a non-scalar AST contract field")
            continue
        lines.append("\t".join(fields))
        binding_rows.append("|".join([
            str(entry.get("invariant", "")),
            str(entry.get("case_type", "")),
            str(entry.get("real_adapter", "")),
            str(entry.get("production_fn", "")),
            str(entry.get("production_entry", "")),
            str(entry.get("broken_variant", "")),
            macro_path,
            edge_validation,
        ]))
    if root.resolve() == REPO_ROOT.resolve():
        try:
            universe = tomllib.loads((root / UNIVERSE_REL).read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            report.violation("universe-binding-read", str(error))
            universe = {}
        required = universe.get("required_bindings", [])
        if universe.get("schema_version") != 2:
            report.violation("universe-binding-schema", "universe must use schema_version = 2")
        if universe.get("binding_count") != len(binding_rows):
            report.violation("universe-binding-count", f"binding_count is not {len(binding_rows)}")
        if not isinstance(required, list) or len(required) != len(set(required)) or set(required) != set(binding_rows):
            report.violation("universe-binding-drift", "required_bindings is not the exact registry/source identity set")
    with tempfile.NamedTemporaryFile("w", suffix=".tsv", delete=False) as contract:
        contract.write("\n".join(lines) + "\n")
        contract_path = pathlib.Path(contract.name)
    try:
        mode = "--check" if root.resolve() == REPO_ROOT.resolve() else "--fixture"
        result = subprocess.run(
            [os.environ["NEGATIVE_REGISTRY_AST"], mode, str(contract_path)],
            cwd=root,
            env=sanitized_runtime_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        contract_path.unlink(missing_ok=True)
    if result.returncode:
        parsed = False
        for line in result.stderr.splitlines():
            match = re.fullmatch(r"\[([a-z0-9-]+)\]\s+(.*)", line)
            if match:
                parsed = True
                report.violation(match.group(1), match.group(2))
        if not parsed:
            report.violation("ast-check-failed", result.stderr[-4000:] or result.stdout[-4000:])


def run_checks(root, minimum=12, execute_tests=False):
    report = Report(); mapped = rows(root, report)
    document = registry_document(root, report); registered = document.get("entry", [])
    source_cache = registered_source_cache(root, registered)
    initial_execution_inputs = execution_input_snapshot(root, registered) if execute_tests else None
    if execute_tests and root.resolve() == REPO_ROOT.resolve():
        validate_execution_dependencies(root, report)
        execute_single_governor_gate(
            root,
            report,
            mutation_probe=bool(report.violations),
        )
    if document.get("schema_version") != 5:
        report.violation("registry-schema-version", "negative registry must use schema_version = 5")
    if not mapped: report.violation("no-rows", "mapping parsed to zero rows")
    if not registered: report.violation("no-entries", "registry parsed to zero entries")
    row_by_name = {row["invariant"]: row for row in mapped}
    seen = {}
    for entry in registered:
        invariant = entry.get("invariant", "")
        if not invariant: report.violation("entry-no-invariant", "entry has no invariant"); continue
        seen[invariant] = seen.get(invariant, 0) + 1
        row = row_by_name.get(invariant)
        if row is None:
            report.violation("entry-orphan", f"entry `{invariant}` has no mapping row"); continue
        production = entry.get("production_fn", "")
        if production != row["function"]:
            report.violation("entry-production-fn-drift", f"entry `{invariant}` production_fn `{production}` != `{row['function']}`")
        production_entry = entry.get("production_entry", "")
        for label, path_value in (("production", production), ("production-entry", production_entry)):
            if label == "production-entry" and path_value == "serde_json::from_value":
                resolved = (pathlib.Path("external/serde_json"), None)
            else:
                resolved = resolve_function(root, path_value) if path_value else "path is empty"
            if isinstance(resolved, str):
                report.violation(f"entry-{label}-path-unresolvable", f"entry `{invariant}` {label}: {resolved}")
        reachability = entry.get("entry_reachability", "")
        edge_validation = entry.get("edge_validation", "")
        reason = str(entry.get("reachability_reason", "")).strip()
        if reachability not in {"direct", "indirect"}:
            report.violation("entry-reachability-invalid", f"entry `{invariant}` reachability must be direct or indirect")
        if not reason:
            report.violation("entry-reachability-reason-empty", f"entry `{invariant}` has no reachability reason")
        if reachability == "direct" and production != production_entry:
            report.violation("entry-direct-path-drift", f"entry `{invariant}` says direct but production_fn != production_entry")
        if reachability == "indirect" and production == production_entry:
            report.violation("entry-indirect-path-vacuous", f"entry `{invariant}` says indirect but names the same internal and entry paths")
        expected_edge = "direct" if reachability == "direct" else "reviewed-boundary"
        if edge_validation != expected_edge:
            report.violation("entry-edge-validation-drift", f"entry `{invariant}` edge_validation `{edge_validation}` != `{expected_edge}`")
        if reachability == "indirect" and production_entry != "serde_json::from_value":
            report.violation("entry-indirect-unreviewed", f"entry `{invariant}` has an indirect boundary outside the explicit serde boundary")
        if edge_validation == "reviewed-boundary" and not str(entry.get("edge_review_reason", "")).strip():
            report.violation("entry-edge-review-reason-empty", f"entry `{invariant}` reviewed boundary has no reason")
        for field in ("permits", "observed_when_neutralized"):
            if not str(entry.get(field, "")).strip():
                report.violation(f"entry-empty-{field.replace('_', '-')}", f"entry `{invariant}` has empty {field}")

        relative = entry.get("test_file", "")
        if not TEST_FILE.fullmatch(relative):
            report.violation("entry-test-file-shape", f"entry `{invariant}` has invalid test_file `{relative}`"); continue
        path = root / relative
        if not path.is_file():
            report.violation("entry-test-file-absent", f"entry `{invariant}` test file missing"); continue
        _raw, clean = source_cache[relative]
        test_name = entry.get("test_fn", "")
        # Distinguish absent declarations from real functions Cargo will not run.
        from assurance_source import find_function
        declared = find_function(clean, test_name, None) if test_name else None
        test = test_function(clean, test_name) if test_name else None
        if declared is None:
            report.violation("entry-test-fn-absent", f"entry `{invariant}` test `{test_name}` has no executable function body"); continue
        if test is None:
            report.violation("entry-test-fn-not-a-test", f"entry `{invariant}` `{test_name}` lacks adjacent built-in #[test]"); continue
        attributes = function_attributes(clean, test)
        if attributes != {"test"}:
            report.violation(
                "entry-test-attribute-not-builtin",
                f"entry `{invariant}` test `{test_name}` attributes are {attributes!r}, expected only built-in #[test]",
            )
        if any(attribute.startswith("ignore") for attribute in attributes):
            report.violation("entry-test-ignored", f"entry `{invariant}` test `{test_name}` is #[ignore]")
        if function_has_conditional_owner(clean, test):
            report.violation("entry-test-cfg-disabled", f"entry `{invariant}` test `{test_name}` has disabling conditional attributes")

        broken = entry.get("broken_variant", "")
        if not broken:
            report.violation("entry-no-broken-variant", f"entry `{invariant}` has no broken_variant"); continue
        if not enum_variant_defined(clean, broken, (test.declaration_start, test.body_end + 1)):
            report.violation("entry-broken-variant-undefined", f"entry `{invariant}` mutation `{broken}` has no exact executable Enum::Variant definition outside its test")
        enum_name = broken.split("::", 1)[0]
        control_variant = f"{enum_name}::None"
        if not enum_variant_defined(clean, control_variant, (test.declaration_start, test.body_end + 1)):
            report.violation("entry-control-variant-undefined", f"entry `{invariant}` has no `{control_variant}` control")
        case_type = entry.get("case_type", "")
        expected_case = invariant.replace("-", "_")
        if case_type != expected_case:
            report.violation("entry-case-identity-drift", f"entry `{invariant}` case `{case_type}` != `{expected_case}`")
        real_adapter = entry.get("real_adapter", "")
        expected_adapter = f"{expected_case}::real"
        if real_adapter != expected_adapter:
            report.violation("entry-real-adapter-drift", f"entry `{invariant}` real_adapter `{real_adapter}` != `{expected_adapter}`")

    for invariant, count in seen.items():
        if count > 1: report.violation("entry-duplicate", f"entry `{invariant}` appears {count} times")
    for row in mapped:
        if row["invariant"] not in seen: report.violation("row-unregistered", f"row `{row['invariant']}` has no registry entry")
    if len(registered) < minimum: report.violation("coverage-entries", f"{len(registered)} entries < {minimum}")
    run_ast_checks(root, registered, report, source_cache)
    if execute_tests and not report.violations:
        targets = {}
        for entry in registered:
            relative = entry["test_file"]
            parts = pathlib.PurePosixPath(relative).parts
            crate = parts[1]
            target = pathlib.PurePosixPath(parts[-1]).stem
            targets.setdefault((crate, target), set()).add(entry["test_fn"])
        for (crate, target), names in sorted(targets.items()):
            executable = compiled_test_binary(
                root, crate, target, report, "entry-test-compile-failed"
            )
            if executable is None:
                continue
            discovery = subprocess.run(
                [str(executable), "--list"],
                env=sanitized_runtime_environment(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if discovery.returncode:
                report.violation("entry-test-list-failed", f"{crate}/{target} discovery failed:\n{discovery.stderr[-4000:]}")
                continue
            discovered = listed_tests(discovery.stdout)
            if discovered != names:
                report.violation("entry-test-list-drift", f"{crate}/{target} discovered {sorted(discovered)}, registry requires {sorted(names)}")
                continue
            result = subprocess.run(
                [str(executable)],
                env=sanitized_runtime_environment(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode:
                report.violation("entry-test-target-failed", f"{crate}/{target} failed:\n{(result.stdout + result.stderr)[-4000:]}")
                continue
            summary = run_summary(result.stdout)
            if summary is None or summary != {"passed": len(names), "failed": 0, "ignored": 0, "measured": 0, "filtered": 0}:
                report.violation("entry-test-target-summary", f"{crate}/{target} did not prove exact {len(names)} passed, 0 failed/ignored/measured/filtered: {summary}")
        executable = compiled_test_binary(
            root, CONTRACT_CRATE, CONTRACT_TARGET, report, "protocol-contract-compile-failed"
        )
        if executable is None:
            pass
        else:
            discovery = subprocess.run(
                [str(executable), "--list"],
                env=sanitized_runtime_environment(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if discovery.returncode:
                report.violation("protocol-contract-list-failed", f"protocol contract discovery failed:\n{discovery.stderr[-4000:]}")
            elif listed_tests(discovery.stdout) != CONTRACT_TESTS:
                report.violation("protocol-contract-list-drift", f"protocol contract discovered {sorted(listed_tests(discovery.stdout))}, expected {sorted(CONTRACT_TESTS)}")
            else:
                result = subprocess.run(
                    [str(executable)],
                    env=sanitized_runtime_environment(),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                summary = run_summary(result.stdout)
                expected = {"passed": len(CONTRACT_TESTS), "failed": 0, "ignored": 0, "measured": 0, "filtered": 0}
                if result.returncode or summary != expected:
                    report.violation("protocol-contract-execution-failed", f"protocol contract did not prove exact {expected}: {summary}\n{(result.stdout + result.stderr)[-4000:]}")
        final_execution_inputs = execution_input_snapshot(root, registered)
        if final_execution_inputs != initial_execution_inputs:
            changed = sorted(
                path for path in set(initial_execution_inputs) | set(final_execution_inputs)
                if initial_execution_inputs.get(path) != final_execution_inputs.get(path)
            )
            report.violation(
                "entry-execution-input-drift",
                f"registered source/manifest inputs changed across compilation and execution: {changed}",
            )
    return report


MAPPING = '''
| Invariant | Enforcing function | Assumptions | What it refuses |
| --- | --- | --- | --- |
| `FIXTURE-ONE` | `fixture_crate::gate::Gate::evaluate` | `ASSUME-X` | danger |
'''
SOURCE = '''
pub struct Gate;
impl Gate { pub fn evaluate(&self) -> bool { false } }
'''
TEST = '''
#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;

enum Mutation {
    None,
    RemoveGuard,
}
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    negative_protocol::assert_registered_negative_case! {
        case: FIXTURE_ONE,
        mutation: Mutation,
        control: Mutation::None,
        broken: Mutation::RemoveGuard,
        state: {},
        probe: bool = true,
        outcome: bool,
        real_probe: probe,
        production: fixture_crate::gate::Gate::evaluate,
        arguments: (&Gate),
        call: sync,
        normalize: |production_result| production_result,
        mirror: |_state, _probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
'''
REGISTRY = '''
schema_version=5
[[entry]]
invariant="FIXTURE-ONE"
case_type="FIXTURE_ONE"
real_adapter="FIXTURE_ONE::real"
production_fn="fixture_crate::gate::Gate::evaluate"
production_entry="fixture_crate::gate::Gate::evaluate"
entry_reachability="direct"
edge_validation="direct"
reachability_reason="The named adapter calls the public production entry."
test_file="crates/fixture-crate/tests/negative_gate.rs"
test_fn="broken_gate"
broken_variant="Mutation::RemoveGuard"
permits="danger"
observed_when_neutralized="assertion failed"
'''


def fixture(root):
    src = root / "crates/fixture-crate/src"; src.mkdir(parents=True)
    (src / "lib.rs").write_text("pub mod gate;\n"); (src / "gate.rs").write_text(SOURCE)
    tests = root / "crates/fixture-crate/tests"; tests.mkdir(parents=True)
    (tests / "negative_gate.rs").write_text(TEST)
    protocol = root / "tests"; protocol.mkdir()
    (protocol / "negative_protocol.rs").write_text("macro_rules! assert_registered_negative_case { ($($tokens:tt)*) => {} }\n")
    docs = root / "docs/assurance"; docs.mkdir(parents=True)
    (docs / "MAPPING.md").write_text(MAPPING); (docs / "negative-registry.toml").write_text(REGISTRY)
    return root


CASES = {
    "non_test_function": "entry-test-fn-not-a-test",
    "comment_only_test": "entry-test-fn-absent",
    "string_only_test": "entry-test-fn-absent",
    "nonexistent_module": "entry-production-entry-path-unresolvable",
    "nonexistent_type": "entry-production-entry-path-unresolvable",
    "comment_only_production": "entry-production-entry-path-unresolvable",
    "string_only_production": "entry-production-entry-path-unresolvable",
    "comment_only_mutation_definition": "entry-broken-variant-undefined",
    "string_only_mutation_definition": "entry-broken-variant-undefined",
    "comment_only_protocol": "ast-source-parse",
    "string_only_protocol": "ast-macro-path",
    "production_shaped_spoof": "ast-source-binding",
    "black_box_only_spoof": "ast-macro-path",
    "unrelated_assertion_spoof": "ast-macro-path",
    "protocol_import_spoof": "ast-protocol-module",
    "case_identity_drift": "ast-source-binding",
    "real_adapter_drift": "entry-real-adapter-drift",
    "real_adapter_uses_mirror": "ast-source-binding",
    "broken_variant_drift": "ast-source-binding",
    "protocol_shadow": "ast-reserved-binding",
    "sync_alias_shadow": "ast-reserved-binding",
    "proc_macro_test_attribute": "entry-test-attribute-not-builtin",
    "dead_closure": "ast-macro-placement",
    "if_false_wrapper": "ast-macro-placement",
    "normalizer_constant": "ast-invocation-parse",
    "orphan": "entry-orphan",
    "unregistered": "row-unregistered",
    "ignored_test": "entry-test-ignored",
    "cfg_disabled_test": "entry-test-cfg-disabled",
    "module_cfg_disabled_test": "entry-test-cfg-disabled",
}


def mutate(root, case):
    registry = root / "docs/assurance/negative-registry.toml"
    source = root / "crates/fixture-crate/src/gate.rs"
    test = root / "crates/fixture-crate/tests/negative_gate.rs"
    if case == "non_test_function": test.write_text(test.read_text().replace("#[test]\n", ""))
    elif case == "comment_only_test": test.write_text("/* #[test] fn broken_gate() { mirrored(Mutation::RemoveGuard); } */")
    elif case == "string_only_test": test.write_text('const X: &str = "#[test] fn broken_gate() { mirrored(Mutation::RemoveGuard); }";')
    elif case == "nonexistent_module": registry.write_text(registry.read_text().replace("production_entry=\"fixture_crate::gate::Gate", "production_entry=\"fixture_crate::ghost::Gate"))
    elif case == "nonexistent_type": registry.write_text(registry.read_text().replace("production_entry=\"fixture_crate::gate::Gate", "production_entry=\"fixture_crate::gate::Ghost"))
    elif case in {"comment_only_production", "string_only_production"}:
        registry.write_text(registry.read_text().replace("production_entry=\"fixture_crate::gate::Gate::evaluate\"", "production_entry=\"fixture_crate::gate::Gate::ghost\""))
        fake = "// pub fn ghost(&self) {}" if case.startswith("comment") else 'const X: &str = "pub fn ghost(&self) {}";'
        source.write_text(source.read_text() + "\n" + fake)
    elif case in {"comment_only_mutation_definition", "string_only_mutation_definition"}:
        test.write_text(test.read_text().replace("    RemoveGuard,", "    KeepGuard,").replace(
            "fn mirrored", ("// enum Fake { RemoveGuard }\nfn mirrored" if case.startswith("comment") else 'const X: &str = "enum Fake { RemoveGuard }";\nfn mirrored'), 1))
    elif case == "comment_only_protocol": test.write_text(test.read_text().replace("    assert_registered_negative_case! {", "    /* assert_registered_negative_case! {", 1).replace("    }\n}", "    } */\n}", 1))
    elif case == "string_only_protocol": test.write_text('#[test]\nfn broken_gate() { let _ = "assert_registered_negative_case! { case: FIXTURE_ONE }"; }\n')
    elif case == "production_shaped_spoof": test.write_text('''
#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;
enum Mutation { None, RemoveGuard }
struct Mirror;
impl Mirror { fn evaluate(&self) -> bool { true } }
fn mirrored(mutation: Mutation) -> bool { matches!(mutation, Mutation::RemoveGuard) }
#[test]
fn broken_gate() {
    negative_protocol::assert_registered_negative_case! {
        case: FIXTURE_ONE,
        mutation: Mutation,
        control: Mutation::None,
        broken: Mutation::RemoveGuard,
        state: {},
        probe: bool = true,
        outcome: bool,
        real_probe: probe,
        production: Mirror::evaluate,
        arguments: (&Mirror),
        call: sync,
        normalize: |production_result| production_result,
        mirror: |_state, _probe, mutation| mirrored(mutation),
        denied: |value| !value,
        permitted: |value| *value,
    }
}
''')
    elif case == "black_box_only_spoof": test.write_text('''
#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;
#[test]
fn broken_gate() {
    std::hint::black_box("fixture_crate::gate::Gate::evaluate mirror None RemoveGuard");
}
''')
    elif case == "unrelated_assertion_spoof": test.write_text('''
#[path = "../../../tests/negative_protocol.rs"]
mod negative_protocol;
#[test]
fn broken_gate() {
    assert!(true, "real == control denial and broken permits");
    assert_eq!(1, 1);
}
''')
    elif case == "protocol_import_spoof": test.write_text(test.read_text().replace('../../../tests/negative_protocol.rs', 'alternate_protocol.rs'))
    elif case == "case_identity_drift": test.write_text(test.read_text().replace("case: FIXTURE_ONE", "case: FIXTURE_GHOST"))
    elif case == "real_adapter_drift": registry.write_text(registry.read_text().replace('real_adapter="FIXTURE_ONE::real"', 'real_adapter="FIXTURE_ONE::mirror"'))
    elif case == "real_adapter_uses_mirror": test.write_text(test.read_text().replace("production: fixture_crate::gate::Gate::evaluate", "production: mirrored"))
    elif case == "broken_variant_drift": test.write_text(test.read_text().replace("broken: Mutation::RemoveGuard", "broken: Mutation::None"))
    elif case == "protocol_shadow": test.write_text("macro_rules! assert_registered_negative_case { ($($t:tt)*) => {} }\n" + test.read_text())
    elif case == "sync_alias_shadow": test.write_text(test.read_text().replace(
        "mod negative_protocol;",
        "mod negative_protocol;\nuse negative_protocol::assert_registered_negative_case as canonical_case;\nmacro_rules! assert_registered_negative_case { ($($tokens:tt)*) => {{ if false { canonical_case! { $($tokens)* } } }}; }",
    ).replace("negative_protocol::assert_registered_negative_case!", "assert_registered_negative_case!"))
    elif case == "proc_macro_test_attribute": test.write_text(test.read_text().replace(
        "#[test]\nfn broken_gate()", "#[tokio::test]\nasync fn broken_gate()"
    ))
    elif case == "dead_closure": test.write_text(test.read_text().replace(
        "    negative_protocol::assert_registered_negative_case! {",
        "    let _dead = || { negative_protocol::assert_registered_negative_case! {",
    ).replace("    }\n}\n", "    } };\n}\n", 1))
    elif case == "if_false_wrapper": test.write_text(test.read_text().replace(
        "    negative_protocol::assert_registered_negative_case! {",
        "    if false { negative_protocol::assert_registered_negative_case! {",
    ).replace("    }\n}\n", "    } }\n}\n", 1))
    elif case == "normalizer_constant": test.write_text(test.read_text().replace(
        "normalize: |production_result| production_result",
        "normalize: |_production_result| false",
    ))
    elif case == "orphan": registry.write_text(registry.read_text().replace("FIXTURE-ONE", "FIXTURE-GHOST"))
    elif case == "unregistered": registry.write_text("schema_version=5\n")
    elif case == "ignored_test": test.write_text(test.read_text().replace("#[test]", "#[test]\n#[ignore]"))
    elif case == "cfg_disabled_test": test.write_text(test.read_text().replace("#[test]", "#[cfg(any())]\n#[test]"))
    elif case == "module_cfg_disabled_test": test.write_text("#[cfg(any())]\nmod disabled {\n" + test.read_text() + "\n}\n")


def protocol_mutation_self_test(base):
    root = base / "actual_protocol_mutations"
    crate = root / "crates/protocol-contract"
    tests = crate / "tests"
    protocol_path = root / PROTOCOL_REL
    tests.mkdir(parents=True)
    protocol_path.parent.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/protocol-contract"]\nresolver = "2"\n'
    )
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "protocol-contract"\nversion = "0.0.0"\nedition = "2024"\n'
    )
    contract = (REPO_ROOT / CONTRACT_REL).read_text()
    protocol = (REPO_ROOT / PROTOCOL_REL).read_text()
    (tests / "negative_protocol_contract.rs").write_text(contract)

    generated = run_cargo(
        ["generate-lockfile"],
        cwd=root,
        target_dir=root / "target",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if generated.returncode:
        print(f"protocol self-test lock generation failed:\n{generated.stderr[-4000:]}", file=sys.stderr)
        return False, 0
    command = ["test", "--locked", "--test", CONTRACT_TARGET]

    def run(source, contract_source=contract):
        protocol_path.write_text(source)
        (tests / "negative_protocol_contract.rs").write_text(contract_source)
        return run_cargo(
            command,
            cwd=root,
            target_dir=root / "target",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    clean = run(protocol)
    if clean.returncode or run_summary(clean.stdout) != {
        "passed": len(CONTRACT_TESTS), "failed": 0, "ignored": 0,
        "measured": 0, "filtered": 0,
    }:
        print(f"actual protocol clean contract failed:\n{(clean.stdout + clean.stderr)[-4000:]}", file=sys.stderr)
        return False, 0

    sync_body = '''        let synchronous_wrapper =
            $crate::negative_protocol::SynchronousTestSentinel::enter();
        let (case, probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };
        let _completed_case =
            $crate::negative_protocol::execute_registered_negative_case_sync(case, probe);
        synchronous_wrapper.complete();'''
    no_op = '''        let (_case, _probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };'''
    if_false = '''        let (case, probe) = $crate::negative_protocol::define_registered_negative_case! { $($tokens)* };
        if false {
            let _completed_case =
                $crate::negative_protocol::execute_registered_negative_case_sync(case, probe);
        }'''
    equality = '''    assert_eq!(
        real, control,
        "the unmutated mirror drifted from the real denial"
    );'''
    permitted = '''    assert!(
        C::permitted(&broken),
        "removing the named guard did not permit"
    );'''
    mutations = {
        "macro_no_op": (sync_body, no_op),
        "macro_if_false": (sync_body, if_false),
        "omit_real_operation": (
            "    let real = case.real(&probe).await;",
            "    let real = case.mirror(&probe, C::CONTROL).await;",
        ),
        "omit_control_operation": (
            "    let control = case.mirror(&probe, C::CONTROL).await;",
            "    let control = case.real(&probe).await;",
        ),
        "omit_broken_operation": (
            "    let broken = case.mirror(&probe, C::BROKEN).await;",
            "    let broken = case.mirror(&probe, C::CONTROL).await;",
        ),
        "swap_control_broken_operations": (
            "    let control = case.mirror(&probe, C::CONTROL).await;\n    let broken = case.mirror(&probe, C::BROKEN).await;",
            "    let control = case.mirror(&probe, C::BROKEN).await;\n    let broken = case.mirror(&probe, C::CONTROL).await;",
        ),
        "remove_real_control_equality": (equality, ""),
        "invert_real_control_equality": (equality, equality.replace("assert_eq!", "assert_ne!")),
        "vacuous_real_control_equality": (equality, equality.replace("real, control", "real, real")),
        "remove_real_denial": (
            '    assert!(C::denied(&real), "the real operation did not deny");',
            "",
        ),
        "invert_real_denial": (
            '    assert!(C::denied(&real), "the real operation did not deny");',
            '    assert!(!C::denied(&real), "inverted real denial");',
        ),
        "remove_broken_permission": (permitted, ""),
        "invert_broken_permission": (
            permitted,
            permitted.replace("C::permitted(&broken)", "!C::permitted(&broken)"),
        ),
    }
    ok = True
    for name, (old, new) in mutations.items():
        count = protocol.count(old)
        if count != 1:
            ok = False
            print(f"actual protocol mutation {name}: replacement matched {count}, expected 1", file=sys.stderr)
            continue
        result = run(protocol.replace(old, new, 1))
        output = result.stdout + result.stderr
        if result.returncode == 0 or "test result: FAILED" not in output:
            ok = False
            print(f"actual protocol mutation {name} did not produce a compiled test failure:\n{output[-4000:]}", file=sys.stderr)

    mirror = "mirror: |state, probe, mutation| state.mirror(probe, mutation),"
    denied = "denied: |outcome| outcome == &ContractOutcome::Denied,"
    permitted = "permitted: |outcome| outcome == &ContractOutcome::Permitted,"
    contract_mutations = {
        "contract_mirror_forced_none": contract.replace(
            mirror,
            "mirror: |state, probe, _mutation| state.mirror(probe, ContractMutation::None),",
            1,
        ),
        "contract_mirror_forced_broken": contract.replace(
            mirror,
            "mirror: |state, probe, _mutation| state.mirror(probe, ContractMutation::Broken),",
            1,
        ),
        "contract_denied_constant_true": contract.replace(
            denied, "denied: |_outcome| true,", 1
        ),
        "contract_permitted_constant_true": contract.replace(
            permitted, "permitted: |_outcome| true,", 1
        ),
        "contract_predicates_swapped": contract.replace(
            denied, "denied: |outcome| outcome == &ContractOutcome::Permitted,", 1
        ).replace(
            permitted, "permitted: |outcome| outcome == &ContractOutcome::Denied,", 1
        ),
        "contract_denied_vacuous_true": contract.replace(
            denied,
            "denied: |outcome| outcome == &ContractOutcome::Denied || true,",
            1,
        ),
        "contract_permitted_vacuous_false": contract.replace(
            permitted,
            "permitted: |outcome| outcome == &ContractOutcome::Permitted && false,",
            1,
        ),
    }
    for name, mutated_contract in contract_mutations.items():
        if mutated_contract == contract:
            ok = False
            print(f"actual contract mutation {name}: replacement did not match", file=sys.stderr)
            continue
        result = run(protocol, mutated_contract)
        output = result.stdout + result.stderr
        if result.returncode == 0 or "test result: FAILED" not in output:
            ok = False
            print(f"actual contract mutation {name} did not produce a compiled test failure:\n{output[-4000:]}", file=sys.stderr)
    return ok, len(mutations) + len(contract_mutations)


def registered_source_mutation_self_test(base):
    registered = entries(REPO_ROOT, Report())
    targets = sorted({entry["test_file"] for entry in registered})
    clean_root = base / "registered_source_clean"
    for relative in targets:
        destination = clean_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / relative, destination)
    protocol_destination = clean_root / PROTOCOL_REL
    protocol_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / PROTOCOL_REL, protocol_destination)

    def contract_text(root, entry_overrides=None):
        entry_overrides = entry_overrides or {}
        lines = []
        source_cache = {}
        for original in registered:
            entry = {**original, **entry_overrides.get(original["invariant"], {})}
            relative = entry["test_file"]
            if relative not in source_cache:
                raw = (root / relative).read_text()
                source_cache[relative] = sanitize_rust(raw)[0]
            clean = source_cache[relative]
            test = test_function(clean, entry["test_fn"])
            macro_path = "negative_protocol::assert_registered_negative_case"
            edge = entry["edge_validation"]
            lines.append("\t".join([
                entry["invariant"], relative, entry["test_fn"], entry["case_type"],
                entry["real_adapter"], entry["production_fn"], entry["production_entry"],
                entry["broken_variant"], macro_path, edge,
            ]))
        return "\n".join(lines) + "\n"

    def run(root, overrides=None, binary=None):
        contract = root / "contract.tsv"
        contract.write_text(contract_text(root, overrides))
        return subprocess.run(
            [binary or os.environ["NEGATIVE_REGISTRY_AST"], "--check", str(contract)],
            cwd=root,
            env=sanitized_runtime_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    clean = run(clean_root)
    if clean.returncode:
        print(f"registered source clean AST contract failed:\n{clean.stderr[-4000:]}", file=sys.stderr)
        return False, 0

    def wrap_first(source, keyword):
        marker = "negative_protocol::assert_registered_negative_case!"
        start = source.index(marker)
        clean, _ = sanitize_rust(source)
        opening = clean.index("{", start)
        closing = matching_brace(clean, opening)
        if closing is None:
            raise AssertionError("registered macro has no closing brace")
        prefix = "if false { " if keyword == "if-false" else "let _dead = || { "
        suffix = " }" if keyword == "if-false" else " };"
        return source[:start] + prefix + source[start:closing + 1] + suffix + source[closing + 1:]

    def wrap_first_async(source):
        marker = "negative_protocol::assert_registered_negative_case!"
        start = source.index(marker)
        clean, _ = sanitize_rust(source)
        opening = clean.index("{", start)
        closing = matching_brace(clean, opening)
        if closing is None:
            raise AssertionError("registered async macro has no closing brace")
        return (
            source[:start]
            + "async { "
            + source[start:closing + 1]
            + " };"
            + source[closing + 1:]
        )

    def replace_after(source, marker, old, new):
        start = source.index(marker)
        replacement = source[start:].replace(old, new, 1)
        return source[:start] + replacement

    def mutate_deploy_decoy(source, replacements):
        case_start = source.index("case: POLICY_DEPLOY_DECOY_MIN_SEVERITY")
        start = source.rfind("negative_protocol::assert_registered_negative_case!", 0, case_start)
        clean, _ = sanitize_rust(source)
        opening = clean.index("{", start)
        closing = matching_brace(clean, opening)
        if closing is None:
            raise AssertionError("reviewer bypass macro has no closing brace")
        prefix, invocation, suffix = source[:start], source[start:closing + 1], source[closing + 1:]
        for old, new in replacements:
            if invocation.count(old) != 1:
                raise AssertionError(f"reviewer bypass replacement `{old}` is not exact")
            invocation = invocation.replace(old, new, 1)
        return prefix + invocation + suffix

    deploy_mirror = "MirroredStaticGate::from_config(config, mutation)"
    deploy_denied = 'denied: |value| value == "Deny/static.deploy_decoy_min_severity"'
    deploy_permitted = 'permitted: |value| value == "Allow/static.default_allow"'

    def deploy_decoy_full_gate_bypass(source):
        return mutate_deploy_decoy(source, (
            (deploy_mirror,
             "MirroredStaticGate::from_config(config, StaticMutation::None)"),
            (deploy_denied, "denied: |_value| true"),
            (deploy_permitted, "permitted: |_value| true"),
        ))

    def deploy_decoy_coordinated_bypass(source):
        return mutate_deploy_decoy(source, (
            (deploy_mirror,
             "MirroredStaticGate::from_config(config, { let _ = mutation; StaticMutation::None })"),
            (deploy_denied, "denied: |value| { let _ = value; true }"),
            (deploy_permitted, "permitted: |value| { let _ = value; true }"),
        ))

    def inject_protocol_executor(source, statement):
        marker = '{\n    assert!(!C::INVARIANT.is_empty(), "case invariant identity is empty");'
        if source.count(marker) != 1:
            raise AssertionError("shared protocol executor marker is not exact")
        return source.replace(marker, "{\n    " + statement + "\n    assert!(!C::INVARIANT.is_empty(), \"case invariant identity is empty\");", 1)

    policy = "crates/swarm-policy/tests/negative_policy_gates.rs"
    response = "crates/swarm-response/tests/negative_containment_and_rollback.rs"
    runtime = "crates/swarm-runtime/tests/negative_runtime_fail_closed.rs"
    spine = "crates/swarm-spine/tests/negative_envelope_and_chain.rs"

    def add_root_shadow(source, root, body=""):
        marker = "mod negative_protocol;"
        shadow = f"\nmod {root} {{ {body} }}"
        return source.replace(marker, marker + shadow, 1)

    def reviewer_policy_shadow(source):
        source = source.replace("use swarm_policy::", "use ::swarm_policy::")
        source = add_root_shadow(source, "swarm_policy", """
            pub mod static_gate {
                pub struct StaticApprovalGate;
                impl StaticApprovalGate {
                    pub fn evaluate<T, U>(_gate: &T, _request: &U) -> bool { true }
                }
            }
            pub mod configurable_gate {
                pub struct ConfigurableApprovalGate;
                impl ConfigurableApprovalGate {
                    pub fn evaluate<T, U>(_gate: &T, _request: &U) -> bool { true }
                }
            }
        """)
        return source.replace(
            "production: crate::__phase285_swarm_policy::",
            "production: swarm_policy::",
        ).replace(
            "production_each: crate::__phase285_swarm_policy::",
            "production_each: swarm_policy::",
        )

    def production_root_reexport(source):
        source = source.replace(
            "mod negative_protocol;",
            "mod negative_protocol;\npub use ::swarm_policy as phase285_policy_reexport;",
            1,
        )
        return source.replace(
            "production: crate::__phase285_swarm_policy::",
            "production: crate::phase285_policy_reexport::",
            1,
        )

    def dead_genuine_call_with_fabricated_result(source):
        helper = """
fn fabricated_policy_result() -> bool {
    let _dead_genuine_call = || {
        let _ = crate::__phase285_swarm_policy::static_gate::StaticApprovalGate::evaluate;
    };
    true
}
"""
        source = source.replace("mod negative_protocol;", "mod negative_protocol;" + helper, 1)
        return source.replace(
            "production: crate::__phase285_swarm_policy::static_gate::StaticApprovalGate::evaluate",
            "production: crate::fabricated_policy_result",
            1,
        )

    mutations = {
        "dead_closure": (policy, lambda value: wrap_first(value, "dead"), "ast-macro-placement", None),
        "if_false": (policy, lambda value: wrap_first(value, "if-false"), "ast-macro-placement", None),
        "unreachable_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    return;\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "if_true_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    if true { return; }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "match_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    match () { () => return }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "loop_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    loop { return; }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "block_return": (policy, lambda value: value.replace(
            "    negative_protocol::assert_registered_negative_case! {",
            "    { return; }\n    negative_protocol::assert_registered_negative_case! {",
            1,
        ), "ast-macro-placement", None),
        "question_mark_return": (policy, lambda value: value.replace(
            "fn broken_empty_ruleset_arm_permits_the_action_the_real_gate_fails_closed_on() {",
            "fn broken_empty_ruleset_arm_permits_the_action_the_real_gate_fails_closed_on() -> Result<(), ()> {\n    Ok::<(), ()>(())?;",
            1,
        ), "ast-macro-placement", None),
        "async_block_wrapper": (
            runtime,
            wrap_first_async,
            "ast-macro-placement",
            None,
        ),
        "protocol_identity_prefix_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if !C::INVARIANT.starts_with("PROTOCOL_") { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_explicit_production_id_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if matches!(C::INVARIANT, "POLICY_DEPLOY_DECOY_MIN_SEVERITY" | "SPINE_CHAIN_SEQ_MONOTONIC") { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_inverse_contract_set_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if C::INVARIANT != "PROTOCOL_CONTRACT" { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_type_name_bypass": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(
                value,
                'if !std::any::type_name::<C>().contains("PROTOCOL_CONTRACT") { return case; }',
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_unconditional_early_return": (
            PROTOCOL_REL,
            lambda value: inject_protocol_executor(value, "return case;"),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_real_role_skipped": (
            PROTOCOL_REL,
            lambda value: value.replace(
                "let real = case.real(&probe).await;",
                "let real = case.mirror(&probe, C::CONTROL).await;",
                1,
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_control_role_skipped": (
            PROTOCOL_REL,
            lambda value: value.replace(
                "let control = case.mirror(&probe, C::CONTROL).await;",
                "let control = case.real(&probe).await;",
                1,
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "protocol_broken_role_skipped": (
            PROTOCOL_REL,
            lambda value: value.replace(
                "let broken = case.mirror(&probe, C::BROKEN).await;",
                "let broken = case.mirror(&probe, C::CONTROL).await;",
                1,
            ),
            "ast-protocol-semantic-drift",
            None,
        ),
        "sync_alias_shadow": (policy, lambda value: value.replace(
            "mod negative_protocol;",
            "mod negative_protocol;\nuse negative_protocol::assert_registered_negative_case as canonical_case;\nmacro_rules! assert_registered_negative_case { ($($tokens:tt)*) => {{ if false { canonical_case! { $($tokens)* } } }}; }",
            1,
        ).replace("negative_protocol::assert_registered_negative_case!", "assert_registered_negative_case!", 1), "ast-reserved-binding", None),
        "proc_macro_test_attribute": (runtime, lambda value: value.replace(
            "#[test]\nfn broken_policy_error_fallback_executes_when_evaluation_failed()",
            "#[tokio::test]\nasync fn broken_policy_error_fallback_executes_when_evaluation_failed()",
            1,
        ), "ast-macro-placement", None),
        "reviewer_policy_local_crate_shadow": (
            policy,
            reviewer_policy_shadow,
            "ast-reserved-binding",
            None,
        ),
        "production_root_reexport": (
            policy,
            production_root_reexport,
            "ast-source-binding",
            None,
        ),
        "dead_genuine_call_with_fabricated_result": (
            policy,
            dead_genuine_call_with_fabricated_result,
            "ast-source-binding",
            None,
        ),
        "helper_body_drift": (
            policy,
            lambda value: value.replace(
                "mod negative_protocol;",
                "mod negative_protocol;\nfn unregistered_helper() -> bool { true }",
                1,
            ),
            "ast-source-semantic-drift",
            None,
        ),
        "import_inventory_drift": (
            spine,
            lambda value: value.replace(
                "mod negative_protocol;",
                "mod negative_protocol;\nuse std::mem as unregistered_import;",
                1,
            ),
            "ast-source-semantic-drift",
            None,
        ),
        "response_local_crate_shadow": (
            response,
            lambda value: add_root_shadow(value, "swarm_response"),
            "ast-reserved-binding",
            None,
        ),
        "runtime_local_crate_shadow": (
            runtime,
            lambda value: add_root_shadow(value, "swarm_runtime"),
            "ast-reserved-binding",
            None,
        ),
        "spine_local_crate_shadow": (
            spine,
            lambda value: add_root_shadow(value, "swarm_spine"),
            "ast-reserved-binding",
            None,
        ),
        "serde_local_crate_shadow": (
            response,
            lambda value: add_root_shadow(value, "serde_json"),
            "ast-reserved-binding",
            None,
        ),
        "policy_self_extern_alias": (
            policy,
            lambda value: value.replace(
                "extern crate swarm_policy as __phase285_swarm_policy;",
                "extern crate self as __phase285_swarm_policy;",
                1,
            ),
            "ast-crate-binding",
            None,
        ),
        "response_swapped_extern_alias": (
            response,
            lambda value: value.replace(
                "extern crate swarm_response as __phase285_swarm_response;",
                "extern crate serde_json as __phase285_swarm_response;",
                1,
            ),
            "ast-crate-binding",
            None,
        ),
        "runtime_use_crate_alias": (
            runtime,
            lambda value: value.replace(
                "extern crate swarm_runtime as __phase285_swarm_runtime;",
                "use crate as __phase285_swarm_runtime;",
                1,
            ),
            "ast-crate-binding",
            None,
        ),
        "spine_reexport_alias": (
            spine,
            lambda value: value.replace(
                "extern crate swarm_spine as __phase285_swarm_spine;",
                "pub use ::swarm_spine as __phase285_swarm_spine;",
                1,
            ),
            "ast-crate-binding",
            None,
        ),
        "policy_reserved_alias_module": (
            policy,
            lambda value: add_root_shadow(value, "__phase285_swarm_policy"),
            "ast-reserved-binding",
            None,
        ),
        "runtime_reserved_alias_module": (
            runtime,
            lambda value: add_root_shadow(value, "__phase285_swarm_runtime"),
            "ast-reserved-binding",
            None,
        ),
        "response_reserved_alias_glob": (
            response,
            lambda value: value.replace(
                "mod negative_protocol;",
                "mod negative_protocol;\nuse crate::__phase285_swarm_response::*;",
                1,
            ),
            "ast-reserved-binding",
            None,
        ),
        "wrong_protocol_path": (policy, lambda value: value.replace(
            '../../../tests/negative_protocol.rs', 'alternate_protocol.rs', 1
        ), "ast-protocol-module", None),
        "normalizer_constant": (policy, lambda value: value.replace(
            "normalize: |production_result| outcome(&production_result)",
            "normalize: |production_result| { let _ = production_result; false }",
            1,
        ), "ast-expected-binding-drift", None),
        "normalizer_helper_constant": (policy, lambda value: value.replace(
            "fn outcome(result: &Result<PolicyDecision, ApprovalError>) -> String {",
            "fn outcome(result: &Result<PolicyDecision, ApprovalError>) -> String { let _ = result; return \"Deny/fabricated\".to_string();",
            1,
        ), "ast-normalizer-helper", None),
        "reviewer_deploy_decoy_full_gate_bypass": (
            policy,
            deploy_decoy_full_gate_bypass,
            "ast-invocation-parse",
            None,
        ),
        "mirror_forced_none": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_mirror,
                "MirroredStaticGate::from_config(config, StaticMutation::None)",
            ),)),
            "ast-invocation-parse",
            None,
        ),
        "mirror_forced_broken": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_mirror,
                "MirroredStaticGate::from_config(config, StaticMutation::SkipDeployDecoyMinimum)",
            ),)),
            "ast-invocation-parse",
            None,
        ),
        "denied_predicate_constant_true": (
            policy,
            lambda value: mutate_deploy_decoy(
                value, ((deploy_denied, "denied: |_value| true"),)
            ),
            "ast-invocation-parse",
            None,
        ),
        "permitted_predicate_constant_false": (
            policy,
            lambda value: mutate_deploy_decoy(
                value, ((deploy_permitted, "permitted: |_value| false"),)
            ),
            "ast-invocation-parse",
            None,
        ),
        "predicate_input_semantically_ignored": (
            policy,
            lambda value: mutate_deploy_decoy(
                value, ((deploy_denied, "denied: |value| { let _ = value; true }"),)
            ),
            "ast-expected-binding-drift",
            None,
        ),
        "predicates_swapped": (
            policy,
            lambda value: mutate_deploy_decoy(value, (
                (deploy_denied, 'denied: |value| value == "Allow/static.default_allow"'),
                (deploy_permitted, 'permitted: |value| value == "Deny/static.deploy_decoy_min_severity"'),
            )),
            "ast-expected-binding-drift",
            None,
        ),
        "denied_predicate_vacuous_true": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_denied,
                'denied: |value| value == "Deny/static.deploy_decoy_min_severity" || true',
            ),)),
            "ast-expected-binding-drift",
            None,
        ),
        "permitted_predicate_vacuous_false": (
            policy,
            lambda value: mutate_deploy_decoy(value, ((
                deploy_permitted,
                'permitted: |value| value == "Allow/static.default_allow" && false',
            ),)),
            "ast-expected-binding-drift",
            None,
        ),
        "renamed_mirror_entry": (
            policy,
            lambda value: replace_after(
                value.replace("MirroredStaticGate", "RenamedStaticGate"),
                "case: POLICY_NULL_EVIDENCE_REFUSED",
                "production: crate::__phase285_swarm_policy::static_gate::StaticApprovalGate::evaluate",
                "production: RenamedStaticGate::evaluate",
            ),
            "ast-expected-binding-drift",
            None,
        ),
        "coordinated_production_entry_substitution": (
            policy,
            lambda value: replace_after(
                value,
                "case: POLICY_NULL_EVIDENCE_REFUSED",
                "production: crate::__phase285_swarm_policy::static_gate::StaticApprovalGate::evaluate",
                "production: MirroredStaticGate::evaluate",
            ),
            "ast-expected-binding-drift",
            {"POLICY-NULL-EVIDENCE-REFUSED": {
                "production_entry": "MirroredStaticGate::evaluate",
            }},
        ),
    }
    ok = True
    for name, (relative, mutate_source, expected_code, overrides) in mutations.items():
        root = base / f"registered_source_{name}"
        shutil.copytree(clean_root, root)
        path = root / relative
        path.write_text(mutate_source(path.read_text()))
        result = run(root, overrides)
        codes = set(re.findall(r"\[([a-z0-9-]+)\]", result.stderr))
        if result.returncode == 0 or expected_code not in codes:
            ok = False
            print(f"registered source mutation {name}: expected {expected_code}, got {sorted(codes)}\n{result.stderr[-2000:]}", file=sys.stderr)

    coordinated = base / "coordinated_baseline_mutation"
    shutil.copytree(clean_root, coordinated)
    helper = coordinated / "tools/negative-registry-ast"
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        REPO_ROOT / "tools/negative-registry-ast",
        helper,
        ignore=shutil.ignore_patterns("target"),
    )
    policy_path = coordinated / policy
    policy_path.write_text(deploy_decoy_coordinated_bypass(policy_path.read_text()))
    docs = coordinated / "docs/assurance"
    docs.mkdir(parents=True)
    shutil.copy2(REPO_ROOT / REGISTRY_REL, docs / "negative-registry.toml")
    shutil.copy2(REPO_ROOT / UNIVERSE_REL, docs / "universe.toml")
    registry_path = docs / "negative-registry.toml"
    registry_path.write_text(registry_path.read_text().replace(
        'observed_when_neutralized = "Neutralizing SkipDeployDecoyMinimum changes the broken verdict from Allow to Deny."',
        'observed_when_neutralized = "Coordinated attack claims the vacuous differential is valid."',
        1,
    ))
    universe_path = docs / "universe.toml"
    universe_path.write_text(
        universe_path.read_text() + "\n# coordinated semantic-baseline attack\n"
    )
    contract = coordinated / "contract.tsv"
    contract.write_text(contract_text(coordinated))
    cargo_command = [
        "run", "--quiet", "--locked", "--manifest-path", str(helper / "Cargo.toml"),
        "--target-dir", str(REPO_ROOT / "target/assurance-tools-selftest"), "--",
    ]
    emitted = run_cargo(
        [*cargo_command, "--emit", str(contract)],
        cwd=coordinated,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if emitted.returncode:
        print(f"coordinated semantic baseline emit failed:\n{emitted.stderr[-4000:]}", file=sys.stderr)
        return False, len(mutations) + 1
    expected_path = helper / "src/expected-bindings.tsv"
    comments = "\n".join(
        line for line in expected_path.read_text().splitlines() if line.startswith("#")
    )
    expected_path.write_text(comments + "\n" + emitted.stdout)
    result = run_cargo(
        [*cargo_command, "--check", str(contract)],
        cwd=coordinated,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0 or "[ast-expected-parse]" not in result.stderr:
        ok = False
        print(f"coordinated semantic baseline mutation bypassed pinned digest:\n{result.stderr[-4000:]}", file=sys.stderr)
    return ok, len(mutations) + 1


def cargo_config_isolation_self_test(base):
    ok = True
    root = base / "external_cargo_home_full_gate"
    hostile_home = base / "attacker-cargo-home"
    hostile_home.mkdir()
    registered = entries(REPO_ROOT, Report())
    by_target = {}
    for entry in registered:
        relative = entry["test_file"]
        package = pathlib.PurePosixPath(relative).parts[1]
        target = pathlib.PurePosixPath(relative).stem
        by_target.setdefault((package, target, relative), set()).add(entry["test_fn"])
    by_target[(CONTRACT_CRATE, CONTRACT_TARGET, CONTRACT_REL)] = set(CONTRACT_TESTS)
    packages = sorted({package for package, _target, _relative in by_target})
    (root / "Cargo.toml").parent.mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(
        "[workspace]\nresolver = \"2\"\nmembers = ["
        + ", ".join(json.dumps(f"crates/{package}") for package in packages)
        + "]\n"
    )
    substitutions = {}
    for package in packages:
        crate = root / "crates" / package
        (crate / "src").mkdir(parents=True)
        (crate / "src/lib.rs").write_text("")
        (crate / "Cargo.toml").write_text(
            f'[package]\nname = "{package}"\nversion = "0.0.0"\nedition = "2024"\n'
        )
    for (_package, target, relative), names in sorted(by_target.items()):
        canonical = root / relative
        canonical.parent.mkdir(parents=True, exist_ok=True)
        canonical.write_text(
            "\n".join(
                f'#[test]\nfn {name}() {{ panic!("canonical body must execute"); }}'
                for name in sorted(names)
            ) + "\n"
        )
        fabricated = canonical.with_name(f"{target}_fabricated.rs")
        fabricated.write_text(
            "\n".join(f"#[test]\nfn {name}() {{}}" for name in sorted(names)) + "\n"
        )
        substitutions[str(canonical.resolve())] = str(fabricated.resolve())

    wrapper = root / "fake-rustc-wrapper.py"
    wrapper.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, shutil, sys\n"
        f"substitutions = {substitutions!r}\n"
        "compiler_value = sys.argv[1]\n"
        "compiler = str(pathlib.Path(compiler_value).resolve()) if '/' in compiler_value else shutil.which(compiler_value)\n"
        "if not compiler:\n"
        "    raise SystemExit(f'compiler not found: {compiler_value}')\n"
        "arguments = []\n"
        "for value in sys.argv[2:]:\n"
        "    candidate = pathlib.Path(value)\n"
        "    resolved = str(candidate.resolve()) if value.endswith('.rs') and candidate.is_file() else value\n"
        "    arguments.append(substitutions.get(resolved, value))\n"
        "os.execv(compiler, [compiler, *arguments])\n"
    )
    wrapper.chmod(0o755)
    (hostile_home / "config.toml").write_text(
        "[build]\nrustc-wrapper = " + json.dumps(str(wrapper.resolve())) + "\n"
    )
    raw_target = REPO_ROOT / "target/assurance-external-cargo-home-red"
    raw_environment = sanitized_cargo_environment(target_dir=raw_target, audit=False)
    raw_environment["CARGO_HOME"] = str(hostile_home)
    lock = subprocess.run(
        [str(PINNED_CARGO), "generate-lockfile"], cwd=root, env=raw_environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if lock.returncode:
        ok = False
        print(f"external CARGO_HOME exact red lock failed:\n{lock.stderr[-4000:]}", file=sys.stderr)
    else:
        for (package, target, _relative), names in sorted(by_target.items()):
            bypass = subprocess.run(
                [str(PINNED_CARGO), "test", "--locked", "-p", package, "--test", target],
                cwd=root, env=raw_environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            expected = {
                "passed": len(names), "failed": 0, "ignored": 0,
                "measured": 0, "filtered": 0,
            }
            if bypass.returncode or run_summary(bypass.stdout) != expected:
                ok = False
                print(
                    f"external CARGO_HOME exact red did not fabricate {package}/{target}:\n"
                    f"{(bypass.stdout + bypass.stderr)[-4000:]}",
                    file=sys.stderr,
                )

    safe_target = REPO_ROOT / "target/assurance-external-cargo-home-safe"
    for package, target, _relative in sorted(by_target):
        protected = run_cargo(
            ["test", "--locked", "-p", package, "--test", target],
            cwd=root, target_dir=safe_target, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if protected.returncode == 0:
            ok = False
            print(f"sanitized CARGO_HOME accepted substituted {package}/{target}", file=sys.stderr)

    # A relative wrapper is resolved from the build cwd and is equally hostile.
    relative_home = base / "relative-attacker-cargo-home"
    relative_home.mkdir()
    relative_wrapper = relative_home / "relative-wrapper.py"
    shutil.copy2(wrapper, relative_wrapper)
    relative_wrapper.chmod(0o755)
    (relative_home / "config.toml").write_text('[build]\nrustc-wrapper = "relative-wrapper.py"\n')
    relative_environment = sanitized_cargo_environment(
        target_dir=REPO_ROOT / "target/assurance-relative-cargo-home-red", audit=False,
    )
    relative_environment["CARGO_HOME"] = str(relative_home)
    relative_environment["PATH"] = f"{relative_home}:{relative_environment['PATH']}"
    package, target, _relative = sorted(by_target)[0]
    relative = subprocess.run(
        [str(PINNED_CARGO), "test", "--locked", "-p", package, "--test", target],
        cwd=root, env=relative_environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    relative_names = by_target[(package, target, REGISTERED_TARGETS[(package, target)])]
    relative_expected = {
        "passed": len(relative_names), "failed": 0, "ignored": 0,
        "measured": 0, "filtered": 0,
    }
    if relative.returncode or run_summary(relative.stdout) != relative_expected:
        ok = False
        print(
            f"relative CARGO_HOME wrapper red did not fabricate a pass:\n"
            f"{(relative.stdout + relative.stderr)[-4000:]}",
            file=sys.stderr,
        )

    def external_config_run(name, config, run_target, *, expect_pass):
        config_home = base / f"executable-attacker-home-{name}"
        config_home.mkdir()
        (config_home / "config.toml").write_text(config)
        environment = sanitized_cargo_environment(
            target_dir=REPO_ROOT / f"target/assurance-cargo-config-{name}-red",
            audit=False,
        )
        environment["CARGO_HOME"] = str(config_home)
        environment.pop("RUSTC", None)
        result = subprocess.run(
            [str(PINNED_CARGO), "test", "--locked", "-p", package, "--test", run_target],
            cwd=root, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if expect_pass and result.returncode:
            print(
                f"external CARGO_HOME {name} red did not fabricate/alter execution:\n"
                f"{(result.stdout + result.stderr)[-4000:]}",
                file=sys.stderr,
            )
            return False
        return True

    direct_rustc = root / "fake-build-rustc.py"
    direct_rustc.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        f"substitutions = {substitutions!r}\n"
        "arguments = []\n"
        "for value in sys.argv[1:]:\n"
        "    candidate = pathlib.Path(value)\n"
        "    resolved = str(candidate.resolve()) if value.endswith('.rs') and candidate.is_file() else value\n"
        "    arguments.append(substitutions.get(resolved, value))\n"
        f"compiler = {str(PINNED_RUSTC)!r}\n"
        "os.execv(compiler, [compiler, *arguments])\n"
    )
    direct_rustc.chmod(0o755)
    if not external_config_run(
        "build-rustc",
        f'[build]\nrustc = {json.dumps(str(direct_rustc.resolve()))}\n',
        target,
        expect_pass=True,
    ):
        ok = False

    if not external_config_run(
        "workspace-wrapper",
        f'[build]\nrustc-workspace-wrapper = {json.dumps(str(wrapper.resolve()))}\n',
        target,
        expect_pass=True,
    ):
        ok = False

    flags_target = "cargo_config_rustflags_probe"
    flags_source = root / f"crates/{package}/tests/{flags_target}.rs"
    flags_source.write_text('''
#[cfg(not(phase285_erase_registered))]
#[test]
fn body_must_run() { panic!("rustflags must not select an alternate body"); }

#[cfg(phase285_erase_registered)]
#[test]
fn body_must_run() {}
''')
    if not external_config_run(
        "rustflags",
        '[build]\nrustflags = ["--cfg", "phase285_erase_registered"]\n'
        'rustdocflags = ["--cfg", "phase285_erase_registered"]\n',
        flags_target,
        expect_pass=True,
    ):
        ok = False

    runner = root / "fake-config-runner.py"
    runner.write_text(
        "print('running 1 test')\n"
        "print('test body_must_run ... ok')\n"
        "print()\n"
        "print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;')\n"
    )
    if not external_config_run(
        "target-runner",
        f"[target.'cfg(all())']\nrunner = [{json.dumps(sys.executable)}, {json.dumps(str(runner.resolve()))}]\n",
        flags_target,
        expect_pass=True,
    ):
        ok = False

    linker_target = "cargo_config_linker_probe"
    (root / f"crates/{package}/tests/{linker_target}.rs").write_text(
        "#[test]\nfn linker_probe() {}\n"
    )
    linker_marker = root / "attacker-linker-executed"
    linker = root / "fake-linker.py"
    linker.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        f"pathlib.Path({str(linker_marker)!r}).write_text('executed')\n"
        "os.execv('/usr/bin/cc', ['/usr/bin/cc', *sys.argv[1:]])\n"
    )
    linker.chmod(0o755)
    if not external_config_run(
        "target-linker",
        f"[target.'cfg(all())']\nlinker = {json.dumps(str(linker.resolve()))}\n",
        linker_target,
        expect_pass=True,
    ) or not linker_marker.is_file():
        ok = False
        print("external CARGO_HOME target linker red did not execute", file=sys.stderr)

    # The same sources must behave canonically through the gate-owned home.
    for name, run_target, should_fail in (
        ("build-rustc", target, True),
        ("workspace-wrapper", target, True),
        ("rustflags", flags_target, True),
        ("target-runner", flags_target, True),
        ("target-linker", linker_target, False),
    ):
        if name == "target-linker":
            linker_marker.unlink(missing_ok=True)
        result = run_cargo(
            ["test", "--locked", "-p", package, "--test", run_target],
            cwd=root,
            target_dir=REPO_ROOT / f"target/assurance-cargo-config-{name}-safe",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if (should_fail and result.returncode == 0) or (not should_fail and result.returncode != 0):
            ok = False
            print(f"sanitized CARGO_HOME did not restore canonical {name} behavior", file=sys.stderr)
        if name == "target-linker" and linker_marker.exists():
            ok = False
            print("sanitized CARGO_HOME still executed the attacker linker", file=sys.stderr)

    # Every compiler/process-bearing Cargo config family is excluded because none
    # of the attacker home is copied into the internally created Cargo home.
    config_variants = {
        "build-rustc": f'[build]\nrustc = {json.dumps(str(wrapper.resolve()))}\n',
        "workspace-wrapper": f'[build]\nrustc-workspace-wrapper = {json.dumps(str(wrapper.resolve()))}\n',
        "rustflags": '[build]\nrustflags = ["--cfg", "phase285_erase_registered"]\nrustdocflags = ["--cfg", "phase285_erase_registered"]\n',
        "target-linker": f'[target.\'cfg(all())\']\nlinker = {json.dumps(str(wrapper.resolve()))}\n',
        "target-runner": f'[target.\'cfg(all())\']\nrunner = ["{sys.executable}", {json.dumps(str(wrapper.resolve()))}]\n',
        "credentials": '[registry]\nglobal-credential-providers = ["cargo:token-from-stdout echo attacker"]\n',
    }
    for name, contents in config_variants.items():
        variant_home = base / f"attacker-home-{name}"
        variant_home.mkdir()
        (variant_home / "config.toml").write_text(contents)
        hostile_environment = dict(os.environ)
        hostile_environment.update({
            "HOME": str(variant_home),
            "PATH": str(variant_home),
            "CARGO_HOME": str(variant_home),
        })
        protected_environment = sanitized_cargo_environment()
        if (
            protected_environment["CARGO_HOME"] == str(variant_home)
            or protected_environment["HOME"] == str(variant_home)
            or protected_environment["PATH"] == str(variant_home)
            or (SANITIZED_CARGO_HOME / "config.toml").exists()
            or (SANITIZED_CARGO_HOME / "config").exists()
        ):
            ok = False
            print(f"sanitized boundary retained hostile {name} config/environment", file=sys.stderr)

    ancestor = base / "ancestor-config" / "nested" / "workspace"
    ancestor.mkdir(parents=True)
    (ancestor.parent.parent / ".cargo").mkdir()
    (ancestor.parent.parent / ".cargo/config.toml").write_text("[build]\nrustflags = []\n")
    ancestor_report = Report()
    validate_cargo_execution_boundary(ancestor, ancestor_report, check_environment=False)
    refused = run_cargo(
        ["metadata", "--format-version", "1"], cwd=ancestor,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if "dependency-cargo-config" not in ancestor_report.codes() or refused.returncode != 125:
        ok = False
        print("ancestor Cargo config source was not refused", file=sys.stderr)

    toolchain_root = base / "toolchain-redirection"
    toolchain_root.mkdir()
    (toolchain_root / "rust-toolchain.toml").write_text('[toolchain]\npath = "attacker-toolchain"\n')
    toolchain_report = Report()
    validate_toolchain_identity(toolchain_root, toolchain_report)
    if "dependency-toolchain-drift" not in toolchain_report.codes():
        ok = False
        print("rust-toolchain path redirection was not rejected", file=sys.stderr)
    return ok, 15


def python_isolation_self_test(base):
    ok = True
    shadow_root = base / "python-module-shadow"
    python_path = base / "pythonpath-shadow"
    shadow_root.mkdir()
    python_path.mkdir()
    (shadow_root / "hashlib.py").write_text("raise SystemExit(73)\n")
    (python_path / "tomllib.py").write_text("raise SystemExit(74)\n")

    raw_root = subprocess.run(
        [sys.executable, "-c", "import hashlib"],
        cwd=shadow_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    isolated_root = subprocess.run(
        [sys.executable, "-I", "-c", "import hashlib; hashlib.sha256(b'x').hexdigest()"],
        cwd=shadow_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if raw_root.returncode != 73 or isolated_root.returncode:
        ok = False
        print("isolated Python did not defeat a cwd stdlib-module shadow", file=sys.stderr)

    raw_path_environment = dict(os.environ)
    raw_path_environment["PYTHONPATH"] = str(python_path)
    raw_path = subprocess.run(
        [sys.executable, "-c", "import tomllib"],
        env=raw_path_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    isolated_path = subprocess.run(
        [sys.executable, "-I", "-c", "import tomllib; tomllib.loads('x = 1')"],
        env=raw_path_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if raw_path.returncode != 74 or isolated_path.returncode:
        ok = False
        print("isolated Python did not defeat a PYTHONPATH stdlib-module shadow", file=sys.stderr)

    RUSTC_AUDIT_LOG.unlink(missing_ok=True)
    wrapper_environment = sanitized_cargo_environment(audit=True)
    wrapper_environment["PYTHONPATH"] = str(python_path)
    wrapper = subprocess.run(
        [str(RUSTC_AUDIT_WRAPPER), str(PINNED_RUSTC), "-vV"],
        cwd=shadow_root,
        env=wrapper_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if wrapper.returncode or f"release: {PINNED_RUST_VERSION}" not in wrapper.stdout:
        ok = False
        print(f"isolated rustc audit wrapper was shadowed:\n{wrapper.stderr[-4000:]}", file=sys.stderr)

    attacker_path = base / "attacker-python-path"
    attacker_path.mkdir()
    marker = attacker_path / "python3-was-invoked"
    fake_python = attacker_path / "python3"
    fake_python.write_text(
        "#!/bin/sh\n"
        f": > {json.dumps(str(marker))}\n"
        "echo 'check-negative-registry OK: 59 executable tests + 5 protocol-contract tests; 179 self-tests passed (3 clean controls, 176 adversarial)'\n"
    )
    fake_python.chmod(0o755)
    hostile_path_environment = dict(os.environ)
    hostile_path_environment["PATH"] = str(attacker_path)
    old_boundary = subprocess.run(
        ["python3", "-I", "-c", "raise SystemExit(99)"],
        env=hostile_path_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if old_boundary.returncode or "check-negative-registry OK:" not in old_boundary.stdout or not marker.is_file():
        ok = False
        print("PATH-resolved Python red fixture did not fabricate the gate result", file=sys.stderr)
    marker.unlink(missing_ok=True)
    protected = subprocess.run(
        [str(TRUSTED_PYTHON), "-I", "-c", "print('trusted Python executed')"],
        env=hostile_path_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if protected.returncode or protected.stdout.strip() != "trusted Python executed" or marker.exists():
        ok = False
        print("absolute trusted Python execution was replaced through PATH", file=sys.stderr)
    return ok, 4


def bootstrap_boundary_self_test(base):
    ok = True
    exact_gate = REPO_ROOT / "tools/check-negative-registry.sh"
    fake_result = (
        "check-negative-registry OK: 59 executable tests + 5 protocol-contract tests; "
        "179 self-tests passed (3 clean controls, 176 adversarial)"
    )

    def startup_payload(name):
        marker = base / f"{name}-executed"
        payload = base / f"{name}.sh"
        payload.write_text(
            f": > {json.dumps(str(marker))}\n"
            f"printf '%s\\n' {json.dumps(fake_result)}\n"
            "exit 0\n"
        )
        return payload, marker

    bash_payload, bash_marker = startup_payload("bash-env")
    bash_environment = sanitized_runtime_environment()
    bash_environment["BASH_ENV"] = str(bash_payload)
    bash_attack = subprocess.run(
        ["/bin/bash", str(exact_gate)],
        cwd=REPO_ROOT,
        env=bash_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if (
        bash_attack.returncode
        or bash_attack.stdout.strip() != fake_result
        or not bash_marker.is_file()
    ):
        ok = False
        print(
            f"BASH_ENV exact-gate red fixture did not false-green before line one:\n"
            f"{(bash_attack.stdout + bash_attack.stderr)[-4000:]}",
            file=sys.stderr,
        )

    env_payload, env_marker = startup_payload("env")
    env_environment = sanitized_runtime_environment()
    env_environment.update({"ENV": str(env_payload), "TERM": "dumb"})
    env_attack = subprocess.run(
        ["/bin/sh", "-i", "-c", "printf 'shell body unexpectedly executed\\n'"],
        cwd=REPO_ROOT,
        env=env_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if (
        env_attack.returncode
        or fake_result not in env_attack.stdout
        or not env_marker.is_file()
    ):
        ok = False
        print(
            f"ENV exact-gate red fixture did not false-green before line one:\n"
            f"{(env_attack.stdout + env_attack.stderr)[-4000:]}",
            file=sys.stderr,
        )

    completion_token = f"phase285-bootstrap-complete-{secrets.token_hex(12)}"
    completion_marker = base / "supported-boundary-completed"
    probe = base / "supported-boundary-probe.sh"
    probe.write_text(
        "#!/bin/bash\n"
        "if [[ $- == *n* ]] || shopt -q extdebug; then exit 71; fi\n"
        "if declare -F env >/dev/null || declare -F bash >/dev/null; then exit 72; fi\n"
        "if [[ -n ${BASH_ENV-} || -n ${ENV-} ]]; then exit 73; fi\n"
        f": > {json.dumps(str(completion_marker))}\n"
        f"printf '%s\\n' {json.dumps(completion_token)}\n"
    )

    old_noexec_environment = sanitized_runtime_environment()
    old_noexec_environment["SHELLOPTS"] = "noexec"
    completion_marker.unlink(missing_ok=True)
    old_noexec = subprocess.run(
        [
            "/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c",
            "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin "
            f"/bin/bash --noprofile --norc -e -o pipefail {probe}",
        ],
        env=old_noexec_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if old_noexec.returncode or old_noexec.stdout or completion_marker.exists():
        ok = False
        print("old in-run env-i boundary did not reproduce the SHELLOPTS=noexec false green", file=sys.stderr)

    loader_noexec_attacks = {}
    if sys.platform.startswith("linux"):
        loader_noexec_attacks = {
            "LD_TRACE_LOADED_OBJECTS": "1",
            "LD_DEBUG": "help",
        }
    for variable, value in loader_noexec_attacks.items():
        completion_marker.unlink(missing_ok=True)
        hostile_environment = sanitized_runtime_environment()
        hostile_environment[variable] = value
        loader_noexec = subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                "/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail",
                str(probe),
            ],
            env=hostile_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if (
            loader_noexec.returncode
            or completion_token in loader_noexec.stdout
            or completion_marker.exists()
        ):
            ok = False
            print(
                f"{variable} did not reproduce a zero-exit before /usr/bin/env entered:\n"
                f"{(loader_noexec.stdout + loader_noexec.stderr)[-4000:]}",
            file=sys.stderr,
        )

    fake_bash_root = base / "github-path-fake-bash"
    fake_bash_root.mkdir()
    fake_bash_marker = fake_bash_root / "invoked"
    fake_bash = fake_bash_root / "bash"
    fake_bash.write_text(
        "#!/bin/sh\n"
        f": > {json.dumps(str(fake_bash_marker))}\n"
        f"printf '%s\\n' {json.dumps(fake_result)}\n"
        "exit 0\n"
    )
    fake_bash.chmod(0o755)
    github_path_environment = sanitized_runtime_environment()
    github_path_environment["PATH"] = f"{fake_bash_root}:/usr/bin:/bin:/usr/sbin:/sbin"
    default_bash_attack = subprocess.run(
        ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", str(probe)],
        env=github_path_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if (
        default_bash_attack.returncode
        or default_bash_attack.stdout.strip() != fake_result
        or not fake_bash_marker.is_file()
        or completion_marker.exists()
    ):
        ok = False
        print("GITHUB_PATH fake default Bash did not reproduce the pre-launch false green", file=sys.stderr)

    supported_attacks = {
        "clean-fresh-runner": {},
        "shellopts-noexec": {"SHELLOPTS": "noexec"},
        "bashopts-extdebug": {"BASHOPTS": "extdebug"},
        "imported-functions": {
            "BASH_FUNC_env%%": "() { printf 'fake env\\n'; exit 0; }",
            "BASH_FUNC_bash%%": "() { printf 'fake bash\\n'; exit 0; }",
        },
        "startup-files": {"BASH_ENV": str(bash_payload), "ENV": str(env_payload)},
        "github-path-fake-bash": {
            "PATH": f"{fake_bash_root}:/usr/bin:/bin:/usr/sbin:/sbin",
        },
    }
    for name, hostile in supported_attacks.items():
        completion_marker.unlink(missing_ok=True)
        launcher_environment = sanitized_runtime_environment()
        launcher_environment.update(hostile)
        supported = subprocess.run(
            [
                "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                "/bin/bash", "--noprofile", "--norc", "-e", "-o", "pipefail",
                str(probe),
            ],
            env=launcher_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if (
            supported.returncode
            or supported.stdout.strip() != completion_token
            or not completion_marker.is_file()
        ):
            ok = False
            print(
                f"supported custom-shell boundary failed {name} without exact completion:\n"
                f"{(supported.stdout + supported.stderr)[-4000:]}",
                file=sys.stderr,
            )

    loader_root = base / "loader-prebootstrap"
    loader_root.mkdir()
    loader_marker = loader_root / "constructor-executed"
    loader_source = loader_root / "stop-before-entry.c"
    loader_source.write_text(
        "#include <fcntl.h>\n"
        "#include <unistd.h>\n"
        "static void phase285_stop(void) {\n"
        f"  int fd = open({json.dumps(str(loader_marker))}, O_CREAT | O_WRONLY, 0600);\n"
        "  if (fd >= 0) close(fd);\n"
        "  _exit(0);\n"
        "}\n"
        "__attribute__((constructor)) static void phase285_constructor(void) { phase285_stop(); }\n"
        "unsigned int la_version(unsigned int version) { phase285_stop(); return version; }\n"
    )
    if sys.platform == "darwin":
        loader = loader_root / "libphase285-stop.dylib"
        compile_loader = subprocess.run(
            ["/usr/bin/cc", "-dynamiclib", "-o", str(loader), str(loader_source)],
            env=sanitized_runtime_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        loader_variables = ("DYLD_INSERT_LIBRARIES",)
    elif sys.platform.startswith("linux"):
        loader = loader_root / "libphase285-stop.so"
        compile_loader = subprocess.run(
            ["/usr/bin/cc", "-shared", "-fPIC", "-o", str(loader), str(loader_source)],
            env=sanitized_runtime_environment(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        loader_variables = ("LD_PRELOAD", "LD_AUDIT")
    else:
        loader = None
        compile_loader = None
        loader_variables = ()
    if compile_loader is not None and compile_loader.returncode:
        ok = False
        print(f"loader red fixture did not compile:\n{compile_loader.stderr[-4000:]}", file=sys.stderr)
    elif loader is not None:
        for variable in loader_variables:
            loader_marker.unlink(missing_ok=True)
            loader_environment = sanitized_runtime_environment()
            loader_environment[variable] = str(loader)
            loader_attack = subprocess.run(
                [str(TRUSTED_PYTHON), "-I", "-c", "print('Python bootstrap entered')"],
                cwd=REPO_ROOT,
                env=loader_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            if (
                loader_attack.returncode
                or not loader_marker.is_file()
                or "check-negative-registry OK:" in loader_attack.stdout
            ):
                ok = False
                print(
                    f"{variable} Python-bootstrap red fixture did not exit before bootstrap:\n"
                    f"{(loader_attack.stdout + loader_attack.stderr)[-4000:]}",
                    file=sys.stderr,
                )

    hostile_loader_environment = {
        **{name: "/attacker/value" for name in BOOTSTRAP_ENVIRONMENT_NAMES},
        **{name: "/attacker/value" for name in WORKFLOW_LOADER_ENVIRONMENT_NAMES},
        "LD_PHASE285_FUTURE_CHANNEL": "/attacker/value",
        "DYLD_PHASE285_FUTURE_CHANNEL": "/attacker/value",
    }
    if (
        bootstrap_override_names(hostile_loader_environment)
        != sorted(hostile_loader_environment)
        or any(
            name in sanitized_cargo_environment(source_environment=hostile_loader_environment)
            for name in hostile_loader_environment
        )
        or any(
            name in sanitized_runtime_environment(source_environment=hostile_loader_environment)
            for name in hostile_loader_environment
        )
    ):
        ok = False
        print("shell/LD/DYLD environment family was not completely refused and stripped", file=sys.stderr)

    workflow_root = base / "workflow-bootstrap-contract"
    workflow_path = workflow_root / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_text = (REPO_ROOT / ".github/workflows/ci.yml").read_text()
    workflow_path.write_text(workflow_text)
    clean_report = Report()
    validate_workflow_bootstrap(workflow_root, clean_report)
    if clean_report.violations:
        ok = False
        print(f"workflow bootstrap clean fixture failed: {clean_report.violations}", file=sys.stderr)

    def mutate_workflow_job(job, old, new):
        start = workflow_text.index(f"  {job}:\n")
        boundary = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", workflow_text[start + 1:])
        end = len(workflow_text) if boundary is None else start + 1 + boundary.start()
        block = workflow_text[start:end]
        if old not in block:
            raise AssertionError(f"workflow mutation input missing from {job}: {old!r}")
        return workflow_text[:start] + block.replace(old, new, 1) + workflow_text[end:]

    workflow_mutations = {
        "default-bash-before-env": workflow_text.replace(
            f"        shell: {WORKFLOW_BOOTSTRAP_SHELL}",
            "        shell: /bin/bash -e {0}",
            1,
        ),
        "unpinned-checkout": workflow_text.replace(
            f"uses: {PINNED_CHECKOUT}",
            "uses: actions/checkout@v4",
            1,
        ),
        "prior-github-path-writer": workflow_text.replace(
            "    steps:\n      - name: Checkout the candidate without persisted credentials",
            "    steps:\n      - name: Candidate-controlled PATH writer\n"
            "        run: echo attacker >> $GITHUB_PATH\n\n"
            "      - name: Checkout the candidate without persisted credentials",
            1,
        ),
        "workflow-environment": workflow_text.replace(
            "jobs:\n", "env:\n  BASH_ENV: attacker\n\njobs:\n", 1,
        ),
        "job-environment": workflow_text.replace(
            "  negative-registry-contract:\n",
            "  negative-registry-contract:\n    env:\n      LD_PRELOAD: attacker\n",
            1,
        ),
        "step-environment": workflow_text.replace(
            "      - name: Check every mapped invariant has a falsifying negative test\n",
            "      - name: Check every mapped invariant has a falsifying negative test\n"
            "        env:\n          BASH_ENV: attacker\n",
            1,
        ),
        "negative-default-bash": mutate_workflow_job(
            "negative-registry-contract",
            f"        shell: {WORKFLOW_BOOTSTRAP_SHELL}",
            "        shell: /bin/bash -e {0}",
        ),
        "negative-prior-github-path-writer": mutate_workflow_job(
            "negative-registry-contract",
            "    steps:\n",
            "    steps:\n      - name: Candidate-controlled PATH writer\n"
            "        run: echo attacker >> $GITHUB_PATH\n\n",
        ),
        "mapping-display-name-removed": mutate_workflow_job(
            "mapping-contract",
            "    name: mapping-contract (${{ github.sha }})\n",
            "",
        ),
        "mapping-display-name-expression-drift": mutate_workflow_job(
            "mapping-contract",
            "    name: mapping-contract (${{ github.sha }})",
            "    name: mapping-contract (${{ github.event.pull_request.head.sha }})",
        ),
        "negative-display-name-removed": mutate_workflow_job(
            "negative-registry-contract",
            "    name: negative-registry-contract (${{ github.sha }})\n",
            "",
        ),
        "negative-display-name-expression-drift": mutate_workflow_job(
            "negative-registry-contract",
            "    name: negative-registry-contract (${{ github.sha }})",
            "    name: negative-registry-contract (${{ github.event.pull_request.head.sha }})",
        ),
    }
    for name, mutation in workflow_mutations.items():
        workflow_path.write_text(mutation)
        drift_report = Report()
        validate_workflow_bootstrap(workflow_root, drift_report)
        if "dependency-bootstrap-workflow-drift" not in drift_report.codes():
            ok = False
            print(f"workflow bootstrap mutation {name} was not rejected", file=sys.stderr)
    return ok, 21 + len(loader_noexec_attacks)


def target_environment_scope_self_test():
    ok = True
    inactive_target = (
        "x86_64-unknown-linux-gnu"
        if PINNED_HOST != "x86_64-unknown-linux-gnu"
        else "aarch64-apple-darwin"
    )
    inactive_name = f"CARGO_TARGET_{cargo_target_environment_name(inactive_target)}_LINKER"
    inactive_environment = {inactive_name: "/attacker/inactive-linker"}
    inactive_report = Report()
    validate_cargo_execution_boundary(
        REPO_ROOT, inactive_report, environment=inactive_environment,
    )
    sanitized = sanitized_cargo_environment(source_environment=inactive_environment)
    if "dependency-execution-environment" in inactive_report.codes() or inactive_name in sanitized:
        ok = False
        print("inactive target linker override was not accepted then sanitized", file=sys.stderr)

    active_name = f"CARGO_TARGET_{cargo_target_environment_name(PINNED_HOST)}_LINKER"
    active_environment = {active_name: "/attacker/active-linker"}
    active_report = Report()
    validate_cargo_execution_boundary(
        REPO_ROOT, active_report, environment=active_environment,
    )
    if (
        "dependency-execution-environment" not in active_report.codes()
        or active_name in sanitized_cargo_environment(source_environment=active_environment)
    ):
        ok = False
        print("active target linker override was not refused and sanitized", file=sys.stderr)
    return ok, 2


def transitive_build_script_self_test(base):
    ok = True
    root = base / "transitive-build-script-audit-overwrite"
    core = root / "swarm-core"
    victim = root / "victim"
    (core / "src").mkdir(parents=True)
    (victim / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "2"\nmembers = ["swarm-core", "victim"]\n'
    )
    (core / "Cargo.toml").write_text(
        '[package]\nname = "swarm-core"\nversion = "0.0.0"\nedition = "2024"\n'
        'build = "build.rs"\n'
    )
    (core / "src/lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    fabricated = victim / "src/fabricated.rs"
    fabricated.write_text("pub fn value() -> u8 { 1 }\n")
    attacker_program = (
        "import os, pathlib, sys\n"
        "compiler = sys.argv[1]\n"
        f"victim = {str((victim / 'src/lib.rs').resolve())!r}\n"
        f"fabricated = {str(fabricated.resolve())!r}\n"
        "arguments = [fabricated if value.endswith('.rs') and str(pathlib.Path(value).resolve()) == victim else value for value in sys.argv[2:]]\n"
        "os.execv(compiler, [compiler, *arguments])\n"
    )
    (core / "build.rs").write_text(
        "fn main() {\n"
        "    let log = std::path::PathBuf::from(std::env::var(\"PHASE285_RUSTC_AUDIT_LOG\").unwrap());\n"
        "    let program = log.parent().unwrap().parent().unwrap().join(\"rustc-audit.py\");\n"
        f"    std::fs::write(program, {json.dumps(attacker_program)}).unwrap();\n"
        "}\n"
    )
    (victim / "Cargo.toml").write_text(
        '[package]\nname = "victim"\nversion = "0.0.0"\nedition = "2024"\n'
        '[dependencies]\nswarm-core = { path = "../swarm-core" }\n'
    )
    (victim / "src/lib.rs").write_text(
        'compile_error!("the transitive build script must not replace this source");\n'
    )
    lock = run_cargo(
        ["generate-lockfile"], cwd=root,
        target_dir=REPO_ROOT / "target/assurance-transitive-build-script",
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    original_program = RUSTC_AUDIT_PROGRAM.read_bytes()
    raw_environment = sanitized_cargo_environment(
        target_dir=REPO_ROOT / "target/assurance-transitive-build-script-red",
    )
    try:
        unprotected = subprocess.run(
            [str(PINNED_CARGO), "check", "--locked", "-p", "victim"],
            cwd=root, env=raw_environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) if lock.returncode == 0 else lock
    finally:
        RUSTC_AUDIT_PROGRAM.write_bytes(original_program)
    if unprotected.returncode:
        ok = False
        print(
            f"transitive build-script red fixture did not substitute the victim source:\n"
            f"{(unprotected.stdout + unprotected.stderr)[-4000:]}",
            file=sys.stderr,
        )

    try:
        attack = run_cargo(
            ["check", "--locked", "-p", "victim"], cwd=root,
            target_dir=REPO_ROOT / "target/assurance-transitive-build-script-protected",
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) if lock.returncode == 0 else lock
    finally:
        RUSTC_AUDIT_PROGRAM.write_bytes(original_program)
    if attack.returncode != 125 or "compiler-audit artifacts changed during Cargo" not in attack.stderr:
        ok = False
        print(
            f"transitive build-script audit overwrite was not rejected:\n{(attack.stdout + attack.stderr)[-4000:]}",
            file=sys.stderr,
        )

    metadata = run_cargo(
        ["metadata", "--locked", "--format-version", "1"], cwd=root,
        target_dir=REPO_ROOT / "target/assurance-transitive-build-script-metadata",
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    metadata_report = Report()
    if metadata.returncode:
        metadata_report.violation("dependency-metadata-failed", metadata.stderr[-4000:])
    else:
        validate_local_custom_build_targets(
            root, json.loads(metadata.stdout).get("packages", []), metadata_report,
        )
    if "dependency-local-custom-build-target" not in metadata_report.codes():
        ok = False
        print(f"transitive swarm-core custom build was not rejected: {metadata_report.violations}", file=sys.stderr)
    return ok, 2


def governance_assurance_contract_self_test(base):
    ok = True

    def copy_fixture(name):
        root = base / name
        root.mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "Cargo.toml", root / "Cargo.toml")
        shutil.copy2(REPO_ROOT / "Cargo.lock", root / "Cargo.lock")
        shutil.copytree(REPO_ROOT / "rulesets", root / "rulesets")
        for source in sorted((REPO_ROOT / "crates").iterdir()):
            if source.is_dir() and (source / "Cargo.toml").is_file():
                shutil.copytree(source, root / "crates" / source.name)
        gate = root / SINGLE_GOVERNOR_GATE_REL
        gate.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / SINGLE_GOVERNOR_GATE_REL, gate)
        for relative in GOVERNANCE_ASSURANCE_INPUT_DIGESTS:
            source = REPO_ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        return root

    def contract_report(root):
        report = Report()
        validate_governance_assurance_identity(root, report)
        relative = "crates/swarm-governance/Cargo.toml"
        document = parse_toml(root / relative, report, "dependency-manifest-read")
        if document.get("package", {}).get("name") != "swarm-governance":
            report.violation(
                "dependency-manifest-identity",
                f"{relative} package name is not `swarm-governance`",
            )
        validate_manifest_semantic_identity(relative, document, report)
        validate_registered_manifest_test_shape(relative, document, report)
        execute_single_governor_gate(
            root,
            report,
            mutation_probe=bool(report.violations),
        )
        return report

    def add_workspace_alias_escape(root):
        manifest = root / "Cargo.toml"
        source = manifest.read_text()
        member_marker = '    "crates/swarm-crypto",\n]'
        dependency_marker = "# Internal crates\n"
        if source.count(member_marker) != 1 or source.count(dependency_marker) != 1:
            raise RuntimeError("workspace alias mutation lost its exact root markers")
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
        crate_root = root / "crates/swarm-closure-escape"
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

    clean = copy_fixture("governance-assurance-clean")
    clean_report = contract_report(clean)
    if clean_report.violations:
        ok = False
        print(
            f"governance assurance clean contract failed: {clean_report.violations}",
            file=sys.stderr,
        )

    cold = copy_fixture("governance-assurance-empty-cargo-cache")
    cold_cache = base / "governance-assurance-empty-cargo-home"
    (cold_cache / "registry").mkdir(parents=True)
    (cold_cache / "git").mkdir()
    cold_report = Report()
    cold_result = execute_single_governor_gate(
        cold,
        cold_report,
        mutation_probe=True,
        cache_source=cold_cache,
    )
    cold_output = "" if cold_result is None else cold_result.stdout + cold_result.stderr
    if (
        cold_result is None
        or cold_result.returncode == 0
        or "controlled primary-package compile failed" not in cold_output
        or "offline mode" not in cold_output
        or "governance-assurance-gate-failed" not in cold_report.codes()
    ):
        ok = False
        print(
            "an empty unhydrated Cargo cache did not fail closed before the protected "
            f"compiler proof: result={cold_result}; report={cold_report.violations}",
            file=sys.stderr,
        )

    unchecked = copy_fixture("governance-assurance-unchecked-constructor")
    authority_source = unchecked / "crates/swarm-governance/src/lib.rs"
    source = authority_source.read_text()
    marker = "impl GovernanceAuthority {\n"
    if source.count(marker) != 1:
        ok = False
        print("unchecked constructor mutation lost its exact impl marker", file=sys.stderr)
    else:
        authority_source.write_text(source.replace(
            marker,
            marker
            + "    pub fn unchecked(policy: Arc<GovernancePolicy>) -> Self { Self { policy } }\n",
            1,
        ))
        report = contract_report(unchecked)
        direct_gate_report = Report()
        execute_single_governor_gate(unchecked, direct_gate_report, mutation_probe=True)
        if (
            "governance-assurance-input-drift" not in report.codes()
            or "governance-assurance-gate-failed" not in direct_gate_report.codes()
        ):
            ok = False
            print(
                "unchecked constructor did not fail both protected input identity "
                f"and the exact authority gate: {report.violations}; "
                f"{direct_gate_report.violations}",
                file=sys.stderr,
            )

    trait_forge = copy_fixture("governance-assurance-trait-forge")
    authority_source = trait_forge / "crates/swarm-governance/src/lib.rs"
    authority_source.write_text(
        authority_source.read_text()
        + """
pub trait ForgeAuthority {
    fn forge_authority(self) -> GovernanceAuthority;
}

impl ForgeAuthority for Arc<GovernancePolicy> {
    fn forge_authority(self) -> GovernanceAuthority {
        unsafe { std::mem::transmute(self) }
    }
}
"""
    )
    trait_report = contract_report(trait_forge)
    trait_gate_report = Report()
    execute_single_governor_gate(trait_forge, trait_gate_report, mutation_probe=True)
    if (
        "governance-assurance-input-drift" not in trait_report.codes()
        or "governance-assurance-gate-failed" not in trait_gate_report.codes()
    ):
        ok = False
        print(
            "trait transmute forge did not fail both protected input identity "
            f"and the exact authority gate: {trait_report.violations}; "
            f"{trait_gate_report.violations}",
            file=sys.stderr,
        )

    alias_forge = copy_fixture("governance-assurance-generic-alias-forge")
    authority_source = alias_forge / "crates/swarm-governance/src/lib.rs"
    authority_source.write_text(
        authority_source.read_text()
        + """
pub type AlternateAuthority<T = GovernanceAuthority> = T;

pub fn mint_alternate(policy: Arc<GovernancePolicy>) -> AlternateAuthority {
    GovernanceAuthority { policy }
}
"""
    )
    alias_report = contract_report(alias_forge)
    alias_gate_report = Report()
    execute_single_governor_gate(alias_forge, alias_gate_report, mutation_probe=True)
    if (
        "governance-assurance-input-drift" not in alias_report.codes()
        or "governance-assurance-gate-failed" not in alias_gate_report.codes()
    ):
        ok = False
        print(
            "safe generic-alias forge did not fail both protected input identity "
            f"and the exact authority gate: {alias_report.violations}; "
            f"{alias_gate_report.violations}",
            file=sys.stderr,
        )

    inferred_forge = copy_fixture("governance-assurance-inferred-runtime-forge")
    runtime_root = inferred_forge / "crates/swarm-runtime/src"
    runtime_lib = runtime_root / "lib.rs"
    runtime_lib.write_text(runtime_lib.read_text() + "\npub(crate) mod inferred_authority_forge;\n")
    (runtime_root / "inferred_authority_forge.rs").write_text("""
use std::sync::Arc;

use swarm_governance::GovernancePolicy;

use crate::containment::ContainmentSweep;

pub fn install(policy: Arc<GovernancePolicy>, sweep: ContainmentSweep) -> ContainmentSweep {
    let value = unsafe { std::mem::transmute_copy(&policy) };
    std::mem::forget(policy);
    sweep.with_governance_authority(value)
}
""")
    inferred_report = contract_report(inferred_forge)
    if "governance-assurance-gate-failed" not in inferred_report.codes():
        ok = False
        print(
            "type-inferred downstream transmute_copy did not fail the full protected gate: "
            f"{inferred_report.violations}",
            file=sys.stderr,
        )

    erased_getter = copy_fixture("governance-assurance-erased-any-getter")
    containment_source = erased_getter / "crates/swarm-runtime/src/containment.rs"
    containment_source.write_text(containment_source.read_text() + """

pub trait ExposeErasedAuthority {
    fn authority_any(&self) -> Option<&dyn std::any::Any>;
}

impl ExposeErasedAuthority for ContainmentSweep {
    fn authority_any(&self) -> Option<&dyn std::any::Any> {
        self.governance
            .as_ref()
            .map(|value| value as &dyn std::any::Any)
    }
}
""")
    erased_report = contract_report(erased_getter)
    erased_gate_report = Report()
    execute_single_governor_gate(erased_getter, erased_gate_report, mutation_probe=True)
    if (
        "governance-assurance-input-drift" not in erased_report.codes()
        or "governance-assurance-gate-failed" not in erased_gate_report.codes()
    ):
        ok = False
        print(
            "safe Any getter did not fail both protected field-owner identity and the exact gate: "
            f"{erased_report.violations}; {erased_gate_report.violations}",
            file=sys.stderr,
        )

    descendant_getter = copy_fixture("governance-assurance-descendant-any-getter")
    descendant_source = (
        descendant_getter
        / "crates/swarm-ingest-runtime/src/ingest/governance_resume.rs"
    )
    descendant_source.write_text(descendant_source.read_text() + """

fn x(state: &IngestState) -> Option<&dyn std::any::Any> {
    state
        .governance_authority
        .as_ref()
        .map(|value| value as &dyn std::any::Any)
}

impl IngestState {
    pub fn erased(&self) -> Option<&dyn std::any::Any> { x(self) }
}
""")
    descendant_report = contract_report(descendant_getter)
    descendant_gate_report = Report()
    execute_single_governor_gate(descendant_getter, descendant_gate_report, mutation_probe=True)
    if (
        "governance-assurance-input-drift" not in descendant_report.codes()
        or "governance-assurance-gate-failed" not in descendant_gate_report.codes()
    ):
        ok = False
        print(
            "descendant split-helper Any leak did not fail both protected privacy identity "
            f"and the exact gate: {descendant_report.violations}; "
            f"{descendant_gate_report.violations}",
            file=sys.stderr,
        )

    workspace_alias = copy_fixture("governance-assurance-workspace-alias-closure")
    try:
        add_workspace_alias_escape(workspace_alias)
    except RuntimeError as error:
        ok = False
        print(str(error), file=sys.stderr)
    else:
        compiled = run_cargo(
            ["check", "--locked", "--offline", "-p", "swarm-closure-escape"],
            cwd=workspace_alias,
            target_dir=REPO_ROOT / "target/assurance-governance-alias-closure",
            audit=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        alias_report = contract_report(workspace_alias)
        alias_gate_report = Report()
        execute_single_governor_gate(workspace_alias, alias_gate_report, mutation_probe=True)
        if (
            compiled.returncode
            or "governance-assurance-input-drift" not in alias_report.codes()
            or "governance-assurance-gate-failed" not in alias_gate_report.codes()
            or "resolved normal reverse dependency closure drifted"
                not in " ".join(message for _code, message in alias_gate_report.violations)
        ):
            ok = False
            print(
                "valid renamed workspace dependency escape did not fail the protected "
                "root identity and resolved metadata closure: "
                f"compile={compiled.returncode}:{compiled.stderr[-2000:]}; "
                f"protected={alias_report.violations}; gate={alias_gate_report.violations}",
                file=sys.stderr,
            )

    trait_default = copy_fixture("governance-assurance-trait-default-clone")
    containment_source = trait_default / "crates/swarm-runtime/src/containment.rs"
    containment_source.write_text(containment_source.read_text() + """

pub trait ReleaseAuthorityLeak {
    fn release_authority(sweep: &ContainmentSweep) -> Option<GovernanceAuthority> {
        sweep.governance.clone()
    }
}

impl ReleaseAuthorityLeak for () {}
""")
    trait_default_report = contract_report(trait_default)
    trait_default_gate_report = Report()
    execute_single_governor_gate(trait_default, trait_default_gate_report, mutation_probe=True)
    if (
        "governance-assurance-input-drift" not in trait_default_report.codes()
        or "governance-assurance-gate-failed" not in trait_default_gate_report.codes()
    ):
        ok = False
        print(
            "public trait default authority clone did not fail both protected identity and gate: "
            f"{trait_default_report.violations}; {trait_default_gate_report.violations}",
            file=sys.stderr,
        )

    extern_clone = copy_fixture("governance-assurance-extern-clone")
    containment_source = extern_clone / "crates/swarm-runtime/src/containment.rs"
    containment_source.write_text(containment_source.read_text() + """

pub extern "Rust" fn release_authority_extern(
    sweep: &ContainmentSweep,
) -> Option<GovernanceAuthority> {
    sweep.governance.clone()
}
""")
    extern_report = contract_report(extern_clone)
    extern_gate_report = Report()
    execute_single_governor_gate(extern_clone, extern_gate_report, mutation_probe=True)
    if (
        "governance-assurance-input-drift" not in extern_report.codes()
        or "governance-assurance-gate-failed" not in extern_gate_report.codes()
    ):
        ok = False
        print(
            "extern Rust authority clone did not fail both protected identity and gate: "
            f"{extern_report.violations}; {extern_gate_report.violations}",
            file=sys.stderr,
        )

    git_dependency_escape = copy_fixture(
        "governance-assurance-git-dependency-macro-include"
    )
    workbench_root = git_dependency_escape / "crates/swarm-runtime-workbench"
    capability_forge = """
use std::sync::Arc;
use swarm_runtime::containment::ContainmentSweep;

#[cfg(not(debug_assertions))]
pub fn install_assurance_escape(
    raw: Arc<()>,
    sweep: ContainmentSweep,
) -> ContainmentSweep {
    let authority = unsafe { std::mem::transmute_copy(&raw) };
    std::mem::forget(raw);
    sweep.with_governance_authority(authority)
}
"""
    macro_loader = """

macro_rules! load_assurance_escape {
    ($loader:ident, $path:literal) => { $loader!($path); };
}
load_assurance_escape!(include, "../capability_forge.txt");
"""
    (workbench_root / "capability_forge.txt").write_text(capability_forge)
    workbench_lib = workbench_root / "src/lib.rs"
    workbench_lib.write_text(workbench_lib.read_text() + macro_loader)

    compiler_repo = base / "governance-assurance-git-compiler-control"
    runtime_stub = compiler_repo / "crates/swarm-runtime"
    workbench_stub = compiler_repo / "crates/swarm-runtime-workbench"
    (runtime_stub / "src").mkdir(parents=True)
    (workbench_stub / "src").mkdir(parents=True)
    (compiler_repo / "Cargo.toml").write_text("""
[workspace]
members = ["crates/swarm-runtime", "crates/swarm-runtime-workbench"]
resolver = "2"
""")
    (runtime_stub / "Cargo.toml").write_text("""
[package]
name = "swarm-runtime"
version = "0.1.0"
edition = "2024"
""")
    (runtime_stub / "src/lib.rs").write_text("""
pub mod containment {
    pub struct GovernanceAuthority {
        _policy: std::sync::Arc<()>,
    }

    pub struct ContainmentSweep;

    impl ContainmentSweep {
        pub fn with_governance_authority(self, _authority: GovernanceAuthority) -> Self {
            self
        }
    }
}
""")
    (workbench_stub / "Cargo.toml").write_text("""
[package]
name = "swarm-runtime-workbench"
version = "0.1.0"
edition = "2024"

[dependencies]
swarm-runtime = { path = "../swarm-runtime" }
""")
    (workbench_stub / "capability_forge.txt").write_text(capability_forge)
    (workbench_stub / "src/lib.rs").write_text(
        "#![forbid(unsafe_code)]\n" + macro_loader
    )
    git_environment = sanitized_runtime_environment()
    git_commands = (
        ["/usr/bin/git", "init", "--quiet"],
        ["/usr/bin/git", "add", "--all"],
        [
            "/usr/bin/git",
            "-c", "user.name=phase285-assurance",
            "-c", "user.email=phase285-assurance@example.invalid",
            "commit", "--quiet", "-m", "compiler-input escape fixture",
        ],
    )
    git_result = None
    for command in git_commands:
        git_result = subprocess.run(
            command,
            cwd=compiler_repo,
            env=git_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if git_result.returncode:
            break
    revision = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=compiler_repo,
        env=git_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) if git_result is not None and git_result.returncode == 0 else git_result
    consumer = base / "governance-assurance-external-git-consumer"
    (consumer / "src").mkdir(parents=True)
    if revision is not None and revision.returncode == 0:
        git_url = compiler_repo.resolve().as_uri()
        rev = revision.stdout.strip()
        (consumer / "Cargo.toml").write_text(f"""
[package]
name = "governance-assurance-external-consumer"
version = "0.0.0"
edition = "2024"

[dependencies]
swarm-runtime = {{ git = {json.dumps(git_url)}, rev = {json.dumps(rev)} }}
swarm-runtime-workbench = {{ git = {json.dumps(git_url)}, rev = {json.dumps(rev)} }}
""")
        (consumer / "src/lib.rs").write_text("""
use std::sync::Arc;
use swarm_runtime::containment::ContainmentSweep;
use swarm_runtime_workbench::install_assurance_escape;

pub fn install_from_dependency(
    raw: Arc<()>,
    sweep: ContainmentSweep,
) -> ContainmentSweep {
    install_assurance_escape(raw, sweep)
}
""")
        # Cargo's offline mode refuses even a file:// Git checkout that was
        # created moments ago. Resolve this compiler-control fixture through a
        # dedicated empty Cargo home, then prove the resulting lock contains
        # only the exact local repository and revision before any protected
        # compile. No registry or remote Git source is present in this manifest.
        local_git_cargo_home = base / "governance-assurance-git-cargo-home"
        local_git_cargo_home.mkdir()
        local_git_environment = sanitized_cargo_environment(
            target_dir=REPO_ROOT / "target/assurance-governance-git-consumer",
            audit=False,
        )
        local_git_environment["CARGO_HOME"] = str(local_git_cargo_home)
        local_git_config_sources = cargo_config_sources(consumer)
        if local_git_config_sources:
            lock = subprocess.CompletedProcess(
                [str(PINNED_CARGO), "generate-lockfile"],
                125,
                stdout="",
                stderr=f"refused Cargo config sources: {local_git_config_sources}",
            )
        else:
            lock = subprocess.run(
                [str(PINNED_CARGO), "generate-lockfile"],
                cwd=consumer,
                env=local_git_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        lock_document = (
            tomllib.loads((consumer / "Cargo.lock").read_text())
            if lock.returncode == 0 else {}
        )
        expected_git_suffix = f"#{rev}"
        lock_sources_are_exact = all(
            package.get("source", "").startswith(f"git+{git_url}?rev={rev}")
            and package.get("source", "").endswith(expected_git_suffix)
            and "checksum" not in package
            for package in lock_document.get("package", [])
            if package.get("name") != "governance-assurance-external-consumer"
        ) and {
            package.get("name") for package in lock_document.get("package", [])
        } == {
            "governance-assurance-external-consumer",
            "swarm-runtime",
            "swarm-runtime-workbench",
        }
        lock_digest = (
            hashlib.sha256((consumer / "Cargo.lock").read_bytes()).hexdigest()
            if lock.returncode == 0 else None
        )
        fetched = run_cargo(
            ["fetch", "--locked", "--offline"],
            cwd=consumer,
            target_dir=REPO_ROOT / "target/assurance-governance-git-consumer",
            extra_environment={"CARGO_HOME": str(local_git_cargo_home)},
            audit=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) if lock.returncode == 0 and lock_sources_are_exact else lock
        lock_stayed_exact = (
            lock_digest is not None
            and hashlib.sha256((consumer / "Cargo.lock").read_bytes()).hexdigest()
                == lock_digest
        )
        RUSTC_AUDIT_LOG.unlink(missing_ok=True)
        compiled = run_cargo(
            ["check", "--locked", "--offline", "--release"],
            cwd=consumer,
            target_dir=REPO_ROOT / "target/assurance-governance-git-consumer",
            extra_environment={"CARGO_HOME": str(local_git_cargo_home)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) if fetched.returncode == 0 and lock_stayed_exact else fetched
    else:
        lock = revision
        fetched = revision
        compiled = revision
        lock_sources_are_exact = False
        lock_stayed_exact = False
    audit_records = []
    if RUSTC_AUDIT_LOG.is_file():
        for line in RUSTC_AUDIT_LOG.read_text().splitlines():
            try:
                audit_records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    workbench_was_dependency_capped = any(
        record.get("crate_name") == "swarm_runtime_workbench"
        and record.get("cap_lints") == "allow"
        for record in audit_records
    )
    git_dependency_report = contract_report(git_dependency_escape)
    git_dependency_gate_report = Report()
    execute_single_governor_gate(
        git_dependency_escape,
        git_dependency_gate_report,
        mutation_probe=True,
    )
    if (
        revision is None
        or revision.returncode
        or lock is None
        or lock.returncode
        or fetched is None
        or fetched.returncode
        or not lock_sources_are_exact
        or not lock_stayed_exact
        or compiled is None
        or compiled.returncode
        or not workbench_was_dependency_capped
        or "governance-assurance-package-input-drift"
            not in git_dependency_report.codes()
        or "governance-assurance-gate-failed"
            not in git_dependency_gate_report.codes()
    ):
        ok = False
        print(
            "release-mode external git dependency macro/include escape was not both "
            "compiler-valid under dependency cap-lints and refused by the protected "
            "regular-file/direct-gate boundary: "
            f"git={None if revision is None else revision.returncode}; "
            f"lock={None if lock is None else lock.returncode}; "
            f"fetch={None if fetched is None else fetched.returncode}; "
            f"compile={None if compiled is None else compiled.returncode}:"
            f"{'' if compiled is None else compiled.stderr[-3000:]}; "
            f"cap_lints={workbench_was_dependency_capped}; "
            f"protected={git_dependency_report.violations}; "
            f"gate={git_dependency_gate_report.violations}",
            file=sys.stderr,
        )

    weakened = copy_fixture("governance-assurance-weakened-script")
    weakened_gate = weakened / SINGLE_GOVERNOR_GATE_REL
    weakened_gate.write_text(
        "#!/usr/bin/env bash\n"
        + f"printf '%s\\n' {json.dumps(SINGLE_GOVERNOR_GATE_OUTPUT)}\n"
    )
    weakened_report = contract_report(weakened)
    fabricated_verdict = Report()
    execute_single_governor_gate(weakened, fabricated_verdict)
    if (
        "governance-assurance-input-drift" not in weakened_report.codes()
        or fabricated_verdict.violations
    ):
        ok = False
        print(
            "coherently weakened single-governor script was not rejected by its "
            f"protected identity: {weakened_report.violations}; "
            f"fabricated verdict={fabricated_verdict.violations}",
            file=sys.stderr,
        )

    redirected = copy_fixture("governance-assurance-source-redirect")
    redirected_manifest = redirected / "crates/swarm-governance/Cargo.toml"
    redirected_manifest.write_text(
        redirected_manifest.read_text()
        + '\n[lib]\npath = "src/redirected.rs"\n'
    )
    (redirected / "crates/swarm-governance/src/redirected.rs").write_text("")
    redirected_report = contract_report(redirected)
    required_redirect_codes = {
        "governance-assurance-input-drift",
        "dependency-manifest-semantic-drift",
        "dependency-manifest-library-override",
    }
    if not required_redirect_codes.issubset(redirected_report.codes()):
        ok = False
        print(
            f"governance source redirect was not rejected: {redirected_report.violations}",
            file=sys.stderr,
        )

    build_escape = copy_fixture("governance-assurance-build-script")
    (build_escape / "crates/swarm-governance/build.rs").write_text("fn main() {}\n")
    build_report = contract_report(build_escape)
    if "dependency-manifest-build-script" not in build_report.codes():
        ok = False
        print(
            f"governance build.rs escape was not rejected: {build_report.violations}",
            file=sys.stderr,
        )

    return ok, 14


def dependency_execution_self_test(base):
    ok = True
    target_dir = REPO_ROOT / "target/assurance-dependency-selftest"

    fake_root = base / "fake_tokio_macros"
    fake_macro = fake_root / "fake-tokio-macros"
    victim = fake_root / "victim"
    (fake_macro / "src").mkdir(parents=True)
    (victim / "tests").mkdir(parents=True)
    (fake_root / "Cargo.toml").write_text('''
[workspace]
members = ["fake-tokio-macros", "victim"]
resolver = "2"

[patch.crates-io]
tokio-macros = { path = "fake-tokio-macros" }
''')
    (fake_macro / "Cargo.toml").write_text('''
[package]
name = "tokio-macros"
version = "2.7.0"
edition = "2021"

[lib]
proc-macro = true
''')
    (fake_macro / "src/lib.rs").write_text(r'''
extern crate proc_macro;
use proc_macro::TokenStream;

fn erase_test_body(item: TokenStream) -> TokenStream {
    let source = item.to_string();
    let name = source
        .split_whitespace()
        .skip_while(|token| *token != "fn")
        .nth(1)
        .and_then(|token| token.split('(').next())
        .expect("test function name");
    format!("#[test] fn {name}() {{}}").parse().expect("empty test")
}

#[proc_macro_attribute]
pub fn test(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    erase_test_body(item)
}

#[proc_macro_attribute]
pub fn main(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    erase_test_body(item)
}

#[proc_macro_attribute]
pub fn test_rt(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    erase_test_body(item)
}

#[proc_macro_attribute]
pub fn main_rt(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    erase_test_body(item)
}

#[proc_macro_attribute]
pub fn test_fail(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    erase_test_body(item)
}

#[proc_macro_attribute]
pub fn main_fail(_attribute: TokenStream, item: TokenStream) -> TokenStream {
    erase_test_body(item)
}

#[proc_macro]
pub fn select_priv_declare_output_enum(input: TokenStream) -> TokenStream {
    input
}

#[proc_macro]
pub fn select_priv_clean_pattern(input: TokenStream) -> TokenStream {
    input
}
''')
    (victim / "Cargo.toml").write_text('''
[package]
name = "victim"
version = "0.0.0"
edition = "2021"

[dev-dependencies]
tokio = { version = "=1.52.3", features = ["macros", "rt"] }
''')
    (victim / "tests/registered.rs").write_text('''
#[tokio::test]
async fn erased_async_body() {
    panic!("the registered body must execute");
}
''')
    lock = run_cargo(
        ["generate-lockfile"], cwd=fake_root, target_dir=target_dir,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    bypass = run_cargo(
        ["test", "--locked", "-p", "victim", "--test", "registered"],
        cwd=fake_root, target_dir=target_dir, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) if lock.returncode == 0 else lock
    if bypass.returncode or run_summary(bypass.stdout) != {
        "passed": 1, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0,
    }:
        ok = False
        print(f"fake tokio-macros red fixture did not erase the async body:\n{(bypass.stdout + bypass.stderr)[-4000:]}", file=sys.stderr)
    resolution_report = Report()
    validate_resolution_identity(
        fake_root,
        resolution_report,
        {"tokio-macros": PINNED_RESOLUTION["tokio-macros"]},
        production_packages=False,
    )
    if "dependency-lock-identity" not in resolution_report.codes():
        ok = False
        print(f"fake tokio-macros resolution was not rejected: {resolution_report.violations}", file=sys.stderr)

    runner_root = base / "cargo_runner_spoof"
    runner_victim = runner_root / "victim"
    (runner_victim / "tests").mkdir(parents=True)
    (runner_root / ".cargo").mkdir()
    (runner_root / "Cargo.toml").write_text('''
[workspace]
members = ["victim"]
resolver = "2"
''')
    (runner_victim / "Cargo.toml").write_text('''
[package]
name = "victim"
version = "0.0.0"
edition = "2021"
''')
    (runner_victim / "tests/registered.rs").write_text('''
#[test]
fn body_must_run() {
    panic!("the runner must not replace this binary");
}
''')
    runner = runner_root / "fake_runner.py"
    runner.write_text('''
import sys
if "--list" in sys.argv:
    print("body_must_run: test")
else:
    print("running 1 test")
    print("test body_must_run ... ok")
    print()
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
''')
    (runner_root / ".cargo/config.toml").write_text(
        "[target.'cfg(all())']\nrunner = [\"python3\", " + json.dumps(str(runner)) + "]\n"
    )
    runner_environment = sanitized_cargo_environment(target_dir=target_dir, audit=False)
    lock = subprocess.run(
        [str(PINNED_CARGO), "generate-lockfile"], cwd=runner_root, env=runner_environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    spoof = subprocess.run(
        [str(PINNED_CARGO), "test", "--locked", "-p", "victim", "--test", "registered"],
        cwd=runner_root, env=runner_environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) if lock.returncode == 0 else lock
    if spoof.returncode or run_summary(spoof.stdout) != {
        "passed": 1, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0,
    }:
        ok = False
        print(f"Cargo runner red fixture did not fabricate a passing summary:\n{(spoof.stdout + spoof.stderr)[-4000:]}", file=sys.stderr)
    config_report = Report()
    validate_cargo_execution_boundary(runner_root, config_report, check_environment=False)
    if "dependency-cargo-config" not in config_report.codes():
        ok = False
        print(f"Cargo runner config was not rejected: {config_report.violations}", file=sys.stderr)
    direct_report = Report()
    executable = compiled_test_binary(
        runner_root, "victim", "registered", direct_report, "runner-fixture-compile"
    )
    direct = subprocess.run(
        [str(executable)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) if executable is not None else None
    if (
        "runner-fixture-compile" not in direct_report.codes()
        or executable is not None
        or direct is not None
    ):
        ok = False
        print(
            f"sanitized compiler did not refuse the discovered runner config: "
            f"{direct_report.violations} {'' if direct is None else (direct.stdout + direct.stderr)[-4000:]}",
            file=sys.stderr,
        )

    rustc_root = base / "rustc_source_substitution"
    rustc_victim = rustc_root / "victim"
    (rustc_victim / "tests").mkdir(parents=True)
    (rustc_root / "Cargo.toml").write_text('''
[workspace]
members = ["victim"]
resolver = "2"
''')
    (rustc_victim / "Cargo.toml").write_text('''
[package]
name = "rustc-source-substitution-victim"
version = "0.0.0"
edition = "2021"
''')
    (rustc_victim / "tests/registered.rs").write_text('''
#[test]
fn body_must_run() {
    panic!("the registered source must reach rustc");
}
''')
    fabricated_source = rustc_victim / "tests/fabricated.rs"
    fabricated_source.write_text('''
#[test]
fn body_must_run() {}
''')
    real_rustc = str(PINNED_RUSTC)
    fake_rustc = rustc_root / "fake-rustc.py"
    fake_rustc.write_text(
        "#!/usr/bin/env python3\n"
        "import os\n"
        "import sys\n"
        "arguments = list(sys.argv[1:])\n"
        f"fabricated = {str(fabricated_source)!r}\n"
        "arguments = [fabricated if value.endswith('tests/registered.rs') else value for value in arguments]\n"
        f"real_rustc = {real_rustc!r}\n"
        "os.execv(real_rustc, [real_rustc, *arguments])\n"
    )
    fake_rustc.chmod(0o755)
    rustc_environment = {
        **sanitized_cargo_environment(
            target_dir=REPO_ROOT / "target/assurance-rustc-env-selftest",
            audit=False,
        ),
        "RUSTC": str(fake_rustc),
    }
    lock = subprocess.run(
        [str(PINNED_CARGO), "generate-lockfile"], cwd=rustc_root, env=rustc_environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    bypass = subprocess.run(
        [str(PINNED_CARGO), "test", "--locked", "-p", "rustc-source-substitution-victim", "--test", "registered"],
        cwd=rustc_root, env=rustc_environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) if lock.returncode == 0 else lock
    expected_summary = {"passed": 1, "failed": 0, "ignored": 0, "measured": 0, "filtered": 0}
    if bypass.returncode or run_summary(bypass.stdout) != expected_summary:
        ok = False
        print(f"fake RUSTC red fixture did not substitute the registered source:\n{(bypass.stdout + bypass.stderr)[-4000:]}", file=sys.stderr)
    rustc_report = Report()
    validate_cargo_execution_boundary(
        rustc_root,
        rustc_report,
        environment={"RUSTC": str(fake_rustc)},
    )
    if "dependency-execution-environment" not in rustc_report.codes():
        ok = False
        print(f"fake RUSTC environment was not rejected: {rustc_report.violations}", file=sys.stderr)

    flags_root = base / "encoded_rustflags_cfg_substitution"
    flags_victim = flags_root / "victim"
    (flags_victim / "tests").mkdir(parents=True)
    (flags_root / "Cargo.toml").write_text('''
[workspace]
members = ["victim"]
resolver = "2"
''')
    (flags_victim / "Cargo.toml").write_text('''
[package]
name = "encoded-rustflags-victim"
version = "0.0.0"
edition = "2021"
''')
    (flags_victim / "tests/registered.rs").write_text('''
#[cfg(not(phase285_erase_registered))]
#[test]
fn body_must_run() {
    panic!("the unmodified cfg must execute this body");
}

#[cfg(phase285_erase_registered)]
#[test]
fn body_must_run() {}
''')
    flags_environment = {
        **sanitized_cargo_environment(
            target_dir=REPO_ROOT / "target/assurance-rustflags-env-selftest",
            audit=False,
        ),
        "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fphase285_erase_registered",
    }
    lock = subprocess.run(
        [str(PINNED_CARGO), "generate-lockfile"], cwd=flags_root, env=flags_environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    bypass = subprocess.run(
        [str(PINNED_CARGO), "test", "--locked", "-p", "encoded-rustflags-victim", "--test", "registered"],
        cwd=flags_root, env=flags_environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) if lock.returncode == 0 else lock
    if bypass.returncode or run_summary(bypass.stdout) != expected_summary:
        ok = False
        print(f"encoded rustflags red fixture did not select the empty cfg body:\n{(bypass.stdout + bypass.stderr)[-4000:]}", file=sys.stderr)
    flags_report = Report()
    validate_cargo_execution_boundary(
        flags_root,
        flags_report,
        environment={"CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fphase285_erase_registered"},
    )
    if "dependency-execution-environment" not in flags_report.codes():
        ok = False
        print(f"encoded rustflags environment was not rejected: {flags_report.violations}", file=sys.stderr)
    isolation_ok, isolation_mutations = cargo_config_isolation_self_test(base)
    python_ok, python_mutations = python_isolation_self_test(base)
    bootstrap_ok, bootstrap_mutations = bootstrap_boundary_self_test(base)
    target_environment_ok, target_environment_mutations = target_environment_scope_self_test()
    transitive_ok, transitive_mutations = transitive_build_script_self_test(base)
    governance_ok, governance_mutations = governance_assurance_contract_self_test(base)
    return (
        ok and isolation_ok and python_ok and bootstrap_ok
        and target_environment_ok and transitive_ok and governance_ok,
        4 + isolation_mutations + python_mutations
        + bootstrap_mutations + target_environment_mutations + transitive_mutations
        + governance_mutations,
    )


def target_override_self_test(base):
    ok = True
    target_dir = REPO_ROOT / "target/assurance-target-override-selftest"
    registered = entries(REPO_ROOT, Report())
    target_names = {
        (pathlib.PurePosixPath(entry["test_file"]).parts[1], pathlib.PurePosixPath(entry["test_file"]).stem)
        for entry in registered
    }

    for package, target in sorted(target_names):
        root = base / f"manifest_override_{package}"
        relative, _lib_name = PRODUCTION_PACKAGES[package]
        manifest = root / relative
        manifest.parent.mkdir(parents=True)
        source = (REPO_ROOT / relative).read_text()
        source = source.replace(
            f'name = "{package}"',
            f'name = "{package}"\nautotests = false',
            1,
        ) + f'\n[[test]]\nname = "{target}"\npath = "tests/fabricated.rs"\nharness = false\n'
        manifest.write_text(source)
        report = Report()
        validate_registered_manifest_test_shape(relative, tomllib.loads(source), report)
        required = {"dependency-manifest-autotests-disabled", "dependency-manifest-explicit-test"}
        if not required.issubset(report.codes()):
            ok = False
            print(f"{package} target-override manifest was not rejected: {report.violations}", file=sys.stderr)

    runtime_relative, runtime_lib_name = PRODUCTION_PACKAGES["swarm-runtime"]
    runtime_manifest_source = (REPO_ROOT / runtime_relative).read_text()

    harness_source = runtime_manifest_source + '''
[[test]]
name = "negative_runtime_fail_closed"
path = "tests/fabricated.rs"
harness = false
'''
    harness_report = Report()
    validate_registered_manifest_test_shape(
        runtime_relative,
        tomllib.loads(harness_source),
        harness_report,
    )
    if "dependency-manifest-explicit-test" not in harness_report.codes():
        ok = False
        print(f"harness=false target was not rejected: {harness_report.violations}", file=sys.stderr)

    path_dependency_source = runtime_manifest_source + '''
[dev-dependencies.phase285-build-hook]
path = "../../phase285-build-hook"
'''
    path_dependency_report = Report()
    validate_manifest_semantic_identity(
        runtime_relative,
        tomllib.loads(path_dependency_source),
        path_dependency_report,
    )
    if "dependency-manifest-semantic-drift" not in path_dependency_report.codes():
        ok = False
        print(f"extra path dev-dependency was not rejected: {path_dependency_report.violations}", file=sys.stderr)

    build_hook_root = base / "path_dev_dependency_build_hook"
    build_hook_victim = build_hook_root / "victim"
    build_hook = build_hook_root / "build-hook"
    (build_hook_victim / "tests").mkdir(parents=True)
    (build_hook / "src").mkdir(parents=True)
    (build_hook_root / "Cargo.toml").write_text('''
[workspace]
members = ["victim", "build-hook"]
resolver = "2"
''')
    (build_hook_victim / "Cargo.toml").write_text('''
[package]
name = "path-dev-dependency-victim"
version = "0.0.0"
edition = "2021"

[dev-dependencies]
phase285-build-hook = { path = "../build-hook" }
''')
    (build_hook_victim / "tests/registered.rs").write_text('''
#[test]
fn registered_test() {}
''')
    (build_hook / "Cargo.toml").write_text('''
[package]
name = "phase285-build-hook"
version = "0.0.0"
edition = "2021"
''')
    (build_hook / "src/lib.rs").write_text("")
    (build_hook / "build.rs").write_text('''
fn main() {
    let marker = std::env::var("PHASE285_BUILD_MARKER").expect("marker path");
    std::fs::write(marker, "executed").expect("write build marker");
}
''')
    build_marker = build_hook_root / "build-script-executed"
    build_marker.unlink(missing_ok=True)
    build_target = REPO_ROOT / "target/assurance-manifest-env-selftest"
    lock = run_cargo(
        ["generate-lockfile"], cwd=build_hook_root, target_dir=build_target,
        extra_environment={"PHASE285_BUILD_MARKER": str(build_marker)},
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    bypass = run_cargo(
        ["test", "--locked", "-p", "path-dev-dependency-victim", "--test", "registered"],
        cwd=build_hook_root, target_dir=build_target,
        extra_environment={"PHASE285_BUILD_MARKER": str(build_marker)}, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ) if lock.returncode == 0 else lock
    if bypass.returncode or not build_marker.is_file():
        ok = False
        print(f"path dev-dependency red fixture did not execute its build script:\n{(bypass.stdout + bypass.stderr)[-4000:]}", file=sys.stderr)

    feature_source = runtime_manifest_source.replace(
        "default = []",
        'default = ["z3"]',
        1,
    )
    feature_report = Report()
    validate_manifest_semantic_identity(
        runtime_relative,
        tomllib.loads(feature_source),
        feature_report,
    )
    if feature_source == runtime_manifest_source or "dependency-manifest-semantic-drift" not in feature_report.codes():
        ok = False
        print(f"default-feature drift was not rejected: {feature_report.violations}", file=sys.stderr)

    root_manifest_source = (REPO_ROOT / "Cargo.toml").read_text()
    root_profile_source = root_manifest_source.replace(
        'panic = "abort"',
        'panic = "unwind"',
        1,
    )
    root_profile_report = Report()
    validate_root_manifest_semantic_identity(
        tomllib.loads(root_profile_source),
        root_profile_report,
    )
    if (
        root_profile_source == root_manifest_source
        or "dependency-root-manifest-semantic-drift" not in root_profile_report.codes()
    ):
        ok = False
        print(f"root execution-profile drift was not rejected: {root_profile_report.violations}", file=sys.stderr)

    def metadata_for_manifest(fixture_name, manifest_source, extra_files):
        fixture_root = base / fixture_name
        fixture_crate = fixture_root / "crates/swarm-runtime"
        (fixture_crate / "src").mkdir(parents=True)
        (fixture_root / "Cargo.toml").write_text('''
[workspace]
members = ["crates/swarm-runtime"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
''')
        (fixture_crate / "Cargo.toml").write_text(manifest_source)
        (fixture_crate / "src/lib.rs").write_text("")
        for relative, contents in extra_files.items():
            destination = fixture_crate / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(contents)
        locked = run_cargo(
            ["generate-lockfile"],
            cwd=fixture_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if locked.returncode:
            return fixture_root, None, locked.stderr
        result = run_cargo(
            ["metadata", "--format-version", "1"],
            cwd=fixture_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode:
            return fixture_root, None, result.stderr
        return fixture_root, json.loads(result.stdout), ""

    canonical_runtime_manifest = '''
[package]
name = "swarm-runtime"
version.workspace = true
edition.workspace = true
'''
    library_root, library_metadata, library_error = metadata_for_manifest(
        "production_library_override",
        canonical_runtime_manifest + '''
[lib]
path = "src/fabricated.rs"
crate-type = ["rlib"]
''',
        {"src/fabricated.rs": ""},
    )
    library_report = Report()
    if library_metadata is None:
        ok = False
        print(f"production library override metadata failed:\n{library_error[-4000:]}", file=sys.stderr)
    else:
        validate_registered_manifest_test_shape(
            runtime_relative,
            tomllib.loads((library_root / runtime_relative).read_text()),
            library_report,
        )
        validate_production_metadata_targets(
            library_root,
            library_metadata["packages"],
            {node["id"] for node in library_metadata["resolve"]["nodes"]},
            library_report,
            {"swarm-runtime": (runtime_relative, runtime_lib_name)},
        )
        required = {
            "dependency-manifest-library-override",
            "dependency-production-target-identity",
        }
        if not required.issubset(library_report.codes()):
            ok = False
            print(f"production library redirect/crate-type was not rejected: {library_report.violations}", file=sys.stderr)

    build_root, build_metadata, build_error = metadata_for_manifest(
        "production_custom_build",
        canonical_runtime_manifest.replace(
            'edition.workspace = true',
            'edition.workspace = true\nbuild = "build.rs"',
        ) + '''
[build-dependencies]
''',
        {"build.rs": "fn main() {}\n"},
    )
    build_report = Report()
    if build_metadata is None:
        ok = False
        print(f"production custom-build metadata failed:\n{build_error[-4000:]}", file=sys.stderr)
    else:
        validate_registered_manifest_test_shape(
            runtime_relative,
            tomllib.loads((build_root / runtime_relative).read_text()),
            build_report,
        )
        validate_registered_build_script_path(build_root, runtime_relative, build_report)
        validate_production_metadata_targets(
            build_root,
            build_metadata["packages"],
            {node["id"] for node in build_metadata["resolve"]["nodes"]},
            build_report,
            {"swarm-runtime": (runtime_relative, runtime_lib_name)},
        )
        required = {"dependency-manifest-build-script", "dependency-custom-build-target"}
        if not required.issubset(build_report.codes()):
            ok = False
            print(f"production custom-build was not rejected: {build_report.violations}", file=sys.stderr)

    for package, target in sorted(target_names):
        root = base / f"full_target_override_{package}"
        relative, _lib_name = PRODUCTION_PACKAGES[package]
        crate = (root / relative).parent
        (crate / "src").mkdir(parents=True)
        (crate / "tests").mkdir()
        (root / "Cargo.toml").write_text(f'''
[workspace]
members = ["{pathlib.PurePosixPath(relative).parent}"]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2024"
''')
        (crate / "Cargo.toml").write_text(f'''
[package]
name = "{package}"
version.workspace = true
edition.workspace = true
autotests = false

[[test]]
name = "{target}"
path = "tests/fabricated.rs"
''')
        (crate / "src/lib.rs").write_text("")
        registered_names = sorted(
            entry["test_fn"]
            for entry in registered
            if entry["test_file"] == REGISTERED_TARGETS[(package, target)]
        )
        (crate / "tests/fabricated.rs").write_text(
            "\n".join(f"#[test]\nfn {name}() {{}}" for name in registered_names) + "\n"
        )
        original = root / REGISTERED_TARGETS[(package, target)]
        original.write_text("compile_error!(\"the canonical registered source was not selected\");\n")
        lock = run_cargo(
            ["generate-lockfile"], cwd=root, target_dir=target_dir,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        bypass = run_cargo(
            ["test", "--locked", "-p", package, "--test", target],
            cwd=root, target_dir=target_dir, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) if lock.returncode == 0 else lock
        expected_summary = {
            "passed": len(registered_names), "failed": 0, "ignored": 0,
            "measured": 0, "filtered": 0,
        }
        if not registered_names or bypass.returncode or run_summary(bypass.stdout) != expected_summary:
            ok = False
            print(
                f"{package} target-override red fixture did not fabricate "
                f"{len(registered_names)} passes:\n{(bypass.stdout + bypass.stderr)[-4000:]}",
                file=sys.stderr,
            )

        metadata = run_cargo(
            ["metadata", "--locked", "--format-version", "1"],
            cwd=root, target_dir=target_dir, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        metadata_report = Report()
        if metadata.returncode:
            ok = False
            print(f"{package} target-override metadata failed:\n{metadata.stderr[-4000:]}", file=sys.stderr)
        else:
            document = json.loads(metadata.stdout)
            validate_metadata_test_targets(
                root,
                document["packages"],
                {node["id"] for node in document["resolve"]["nodes"]},
                metadata_report,
                {(package, target): REGISTERED_TARGETS[(package, target)]},
            )
            if "dependency-test-target-identity" not in metadata_report.codes():
                ok = False
                print(f"{package} target-override metadata was accepted: {metadata_report.violations}", file=sys.stderr)

        artifact_report = Report()
        executable = compiled_test_binary(
            root,
            package,
            target,
            artifact_report,
            "target-override-artifact-identity",
            expected_source=REGISTERED_TARGETS[(package, target)],
            expected_package_id=f"path+{crate.resolve().as_uri()}#0.1.0",
        )
        if executable is not None or "target-override-artifact-identity" not in artifact_report.codes():
            ok = False
            print(f"{package} target-override artifact was accepted: {artifact_report.violations}", file=sys.stderr)
    return ok, len(target_names) * 2 + 6


def dependency_hydration_boundary_self_test(base):
    global PINNED_CARGO, DEPENDENCY_CACHE_HYDRATED, DEPENDENCY_FETCH_ACTIVE

    ok = True
    original_cargo = PINNED_CARGO
    original_hydrated = DEPENDENCY_CACHE_HYDRATED
    original_fetch_active = DEPENDENCY_FETCH_ACTIVE
    root = base / "dependency-hydration-boundary"
    root.mkdir()
    fake_cargo = root / "cargo"
    marker = root / "cargo-arguments"
    fake_cargo.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        ": \"${PHASE285_FAKE_CARGO_LOG:?}\"\n"
        "printf '%s\\n' \"$@\" >\"$PHASE285_FAKE_CARGO_LOG\"\n"
    )
    fake_cargo.chmod(0o755)
    execution = {
        "audit": False,
        "text": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "extra_environment": {"PHASE285_FAKE_CARGO_LOG": str(marker)},
    }

    def marker_arguments():
        return marker.read_text().splitlines() if marker.is_file() else []

    try:
        PINNED_CARGO = fake_cargo
        DEPENDENCY_CACHE_HYDRATED = False
        DEPENDENCY_FETCH_ACTIVE = False

        raw = subprocess.run(
            [str(fake_cargo), "metadata", "--format-version", "1"],
            cwd=root,
            env={"PHASE285_FAKE_CARGO_LOG": str(marker)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        raw_arguments = marker_arguments()
        marker.unlink(missing_ok=True)
        refused_metadata = run_cargo(
            ["metadata", "--format-version", "1"], cwd=root, **execution,
        )
        if (
            raw.returncode
            or raw_arguments != ["metadata", "--format-version", "1"]
            or refused_metadata.returncode != 125
            or "before controlled cache hydration" not in refused_metadata.stderr
            or marker.exists()
        ):
            ok = False
            print(
                "dependency hydration differential did not prove raw metadata reachable "
                "and guarded metadata refused before hydration",
                file=sys.stderr,
            )

        unlocked_fetch = run_cargo(["fetch"], cwd=root, **execution)
        if (
            unlocked_fetch.returncode != 125
            or "without --locked" not in unlocked_fetch.stderr
            or marker.exists()
        ):
            ok = False
            print("dependency hydration boundary accepted an unlocked fetch", file=sys.stderr)

        uncontrolled_fetch = run_cargo(["fetch", "--locked"], cwd=root, **execution)
        if (
            uncontrolled_fetch.returncode != 125
            or "outside controlled hydration" not in uncontrolled_fetch.stderr
            or marker.exists()
        ):
            ok = False
            print("dependency hydration boundary accepted an uncontrolled online fetch", file=sys.stderr)

        DEPENDENCY_FETCH_ACTIVE = True
        controlled_fetch = run_cargo(["fetch", "--locked"], cwd=root, **execution)
        if controlled_fetch.returncode or marker_arguments() != ["fetch", "--locked"]:
            ok = False
            print("dependency hydration boundary rejected its single controlled fetch", file=sys.stderr)
        marker.unlink(missing_ok=True)

        DEPENDENCY_FETCH_ACTIVE = False
        DEPENDENCY_CACHE_HYDRATED = True
        offline_metadata = run_cargo(
            ["metadata", "--format-version", "1"], cwd=root, **execution,
        )
        if offline_metadata.returncode or marker_arguments() != [
            "metadata", "--locked", "--offline", "--format-version", "1",
        ]:
            ok = False
            print("post-hydration metadata was not forced locked and offline", file=sys.stderr)
        marker.unlink(missing_ok=True)

        offline_lock = run_cargo(["generate-lockfile"], cwd=root, **execution)
        if offline_lock.returncode or marker_arguments() != ["generate-lockfile", "--offline"]:
            ok = False
            print("post-hydration lock generation was not forced offline", file=sys.stderr)
        marker.unlink(missing_ok=True)

        offline_fetch = run_cargo(["fetch", "--locked", "--offline"], cwd=root, **execution)
        if offline_fetch.returncode or marker_arguments() != ["fetch", "--locked", "--offline"]:
            ok = False
            print("post-hydration explicit offline fetch was not preserved", file=sys.stderr)
    finally:
        PINNED_CARGO = original_cargo
        DEPENDENCY_CACHE_HYDRATED = original_hydrated
        DEPENDENCY_FETCH_ACTIVE = original_fetch_active

    return ok, 3


def self_test():
    ok = True
    protocol_mutations = 0
    with tempfile.TemporaryDirectory() as raw:
        base = pathlib.Path(raw)
        clean = fixture(base / "clean"); report = run_checks(clean, 1)
        if report.violations: ok = False; print(f"negative self-test clean failed: {report.violations}", file=sys.stderr)
        for case, expected in CASES.items():
            root = fixture(base / case); mutate(root, case); codes = run_checks(root, 1).codes()
            if expected not in codes:
                ok = False; print(f"negative self-test {case}: expected {expected}, got {sorted(codes)}", file=sys.stderr)
        spoofed_output = "\n".join((
            "test broken_gate ... ok",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
        ))
        if listed_tests(spoofed_output) or run_summary(spoofed_output) is not None:
            ok = False
            print("negative self-test stdout spoof was accepted as Cargo discovery/execution evidence", file=sys.stderr)
        protocol_ok, protocol_mutations = protocol_mutation_self_test(base)
        source_ok, source_mutations = registered_source_mutation_self_test(base)
        dependency_ok, dependency_mutations = dependency_execution_self_test(base)
        target_ok, target_mutations = target_override_self_test(base)
        hydration_ok, hydration_mutations = dependency_hydration_boundary_self_test(base)
        ok = (
            ok and protocol_ok and source_ok and dependency_ok and target_ok
            and hydration_ok
        )
    return (
        ok,
        protocol_mutations + source_mutations + dependency_mutations
        + target_mutations + hydration_mutations,
    )


preflight = Report()
validate_toolchain_identity(REPO_ROOT, preflight)
configure_sanitized_cargo_boundary(preflight)
validate_cargo_execution_boundary(REPO_ROOT, preflight)
validate_governance_assurance_identity(REPO_ROOT, preflight)
validate_dependency_manifests(REPO_ROOT, preflight)
validate_lock_resolution_identity(REPO_ROOT, preflight)
if preflight.violations:
    for code, message in preflight.violations:
        print(f"[{code}] {message}", file=sys.stderr)
    raise SystemExit("check-negative-registry refused compiler-affecting execution overrides before building its checker")
hydrate_locked_workspace_cache(preflight)
if preflight.violations:
    for code, message in preflight.violations:
        print(f"[{code}] {message}", file=sys.stderr)
    raise SystemExit(
        "check-negative-registry could not hydrate its empty Cargo cache from the "
        "exact tracked locked/checksummed resolution"
    )
validate_resolution_identity(REPO_ROOT, preflight)
if preflight.violations:
    for code, message in preflight.violations:
        print(f"[{code}] {message}", file=sys.stderr)
    raise SystemExit(
        "check-negative-registry could not resolve exact metadata from its "
        "hydrated offline Cargo cache"
    )
ast_target_dir = REPO_ROOT / "target/assurance-tools"
ast_build = run_cargo(
    [
        "build", "--quiet", "--locked", "--offline",
        "--manifest-path", str(REPO_ROOT / "tools/negative-registry-ast/Cargo.toml"),
        "--target-dir", str(ast_target_dir),
    ],
    cwd=REPO_ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if ast_build.returncode:
    raise SystemExit(f"negative registry AST checker build failed:\n{ast_build.stderr[-4000:]}")
os.environ["NEGATIVE_REGISTRY_AST"] = str(ast_target_dir / "debug/negative-registry-ast")

self_test_ok, protocol_mutations = self_test()
if not self_test_ok: raise SystemExit("check-negative-registry self-test failed")
report = run_checks(REPO_ROOT, execute_tests=True)
if report.violations:
    print(f"check-negative-registry: {len(report.violations)} violation(s)", file=sys.stderr)
    for code, message in report.violations: print(f"  [{code}] {message}", file=sys.stderr)
    raise SystemExit(1)
registered = entries(REPO_ROOT, Report())
print(f"check-negative-registry OK: {len(registered)} executable tests + {len(CONTRACT_TESTS)} protocol-contract tests; {len(CASES)+3+protocol_mutations} self-tests passed ({3} clean controls, {len(CASES)+protocol_mutations} adversarial)")
PY
