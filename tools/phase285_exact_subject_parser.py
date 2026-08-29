#!/usr/bin/env python3
"""Fail-closed extractor for the Phase 285 exact-subject CI monolith."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import sys

STEP_NAME = "Run the isolated Phase 285 assurance monolith as the final candidate step"
STEP_LINE = f"      - name: {STEP_NAME}\n"
RUN_LINE = "        run: |\n"
SCRIPT_INDENT = "          "
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024


class ContractError(ValueError):
    """The checked input does not satisfy the exact-subject contract."""


def _read_regular_file(path: pathlib.Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ContractError(f"cannot open regular file without following links: {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"input is not a regular file: {path}")
        if before.st_size <= 0 or before.st_size > MAX_WORKFLOW_BYTES:
            raise ContractError(f"input size is outside 1..{MAX_WORKFLOW_BYTES}: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 131_072))
            if not chunk:
                raise ContractError(f"input ended before its recorded size: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ContractError(f"input grew while it was read: {path}")
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_size)
        identity_after = (after.st_dev, after.st_ino, after.st_mode, after.st_size)
        if identity_before != identity_after:
            raise ContractError(f"input identity changed while it was read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_text(raw: bytes, label: str) -> str:
    if b"\x00" in raw or b"\r" in raw:
        raise ContractError(f"{label} contains NUL or carriage-return bytes")
    if not raw.endswith(b"\n"):
        raise ContractError(f"{label} must end with one or more LF-delimited lines")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} is not strict UTF-8") from error


def extract_monolith(raw: bytes) -> bytes:
    """Extract exactly one named YAML literal block without parsing other YAML."""

    text = _decode_text(raw, "subject workflow")
    if text.count(STEP_NAME) != 1:
        raise ContractError("subject workflow must contain the literal monolith name exactly once")
    lines = text.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line == STEP_LINE]
    if len(starts) != 1:
        raise ContractError("monolith step name is missing or has malformed indentation")
    start = starts[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.startswith("        "):
            end = index
            break
    step_lines = lines[start + 1 : end]
    run_keys = [index for index, line in enumerate(step_lines) if re.match(r"^ {8}run\s*:", line)]
    if len(run_keys) != 1 or step_lines[run_keys[0]] != RUN_LINE:
        raise ContractError("monolith step must contain exactly one literal run: | key")
    run_index = run_keys[0]
    script_lines = step_lines[run_index + 1 :]
    while script_lines and not script_lines[-1].strip():
        script_lines.pop()
    if not script_lines:
        raise ContractError("monolith run block is empty")
    extracted: list[str] = []
    for line in script_lines:
        if not line.strip():
            extracted.append("\n")
            continue
        if "\t" in line or not line.startswith(SCRIPT_INDENT):
            raise ContractError("monolith run block has malformed indentation or a tab")
        extracted.append(line[len(SCRIPT_INDENT) :])
    script = "".join(extracted)
    if "${{" in script:
        raise ContractError("monolith run block contains a GitHub expression")
    if not script.endswith("\n"):
        raise ContractError("monolith run block is not LF terminated")
    return script.encode("utf-8")


def _write_new_regular_file(path: pathlib.Path, payload: bytes) -> None:
    if not path.is_absolute():
        raise ContractError("output path must be absolute")
    parent = path.parent
    parent_metadata = parent.stat()
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
        raise ContractError("output parent must be a real directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ContractError("short write while creating extracted script")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ContractError("extracted script type or mode differs")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _valid_fixture() -> bytes:
    return (
        "name: fixture\n"
        "jobs:\n"
        "  exact:\n"
        "    steps:\n"
        f"{STEP_LINE}"
        "        env:\n"
        "          SAFE: yes\n"
        f"{RUN_LINE}"
        "          set -euo pipefail\n"
        "          echo exact\n"
        "\n"
        "  next: {}\n"
    ).encode()


def run_self_test() -> None:
    valid = _valid_fixture()
    expected = b"set -euo pipefail\necho exact\n"
    if extract_monolith(valid) != expected:
        raise ContractError("valid fixture extraction differs")
    mutations = {
        "missing-name": valid.replace(STEP_NAME.encode(), b"different step"),
        "duplicate-name": valid.replace(b"  next: {}\n", STEP_LINE.encode() + b"  next: {}\n"),
        "name-indent": valid.replace(
            STEP_LINE.encode(), b"     - name: " + STEP_NAME.encode() + b"\n"
        ),
        "folded-run": valid.replace(RUN_LINE.encode(), b"        run: >\n"),
        "duplicate-run": valid.replace(RUN_LINE.encode(), RUN_LINE.encode() + b"        run : |\n"),
        "script-indent": valid.replace(b"          echo exact\n", b"         echo exact\n"),
        "expression": valid.replace(b"echo exact", b"echo ${{ inputs.subject_sha }}"),
        "carriage-return": valid.replace(b"\n", b"\r\n", 1),
        "unterminated": valid[:-1],
    }
    survived: list[str] = []
    for name, mutation in mutations.items():
        try:
            extract_monolith(mutation)
        except ContractError:
            continue
        survived.append(name)
    if survived:
        raise ContractError(f"parser mutations survived: {','.join(survived)}")
    print(f"phase285_exact_subject_parser self_test={len(mutations)} passed=1")


R1D_REF = "refs/heads/work/v179-phase285-convergence"
R1D_SHA = "d229f90c4984fd882d4401fdb7923549fa7b0dbe"
R1D_TREE = "15dce0b2e157c7bfb9e71fee94d3818851a5751a"
CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
RUST_TOOLCHAIN = "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4"
RUST_VERSION = "1.97.1"
RUSTC_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
CARGO_COMMIT = "c980f4866141969fab6254a680546a277789d6f0"
ACTIONLINT_ARCHIVE_SHA256 = "023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
RUNNER_WORKFLOW_SHA256 = "5b2ea171a9194c0d31eb69ac8593e6dfafe35e2f352e46dfd6fb857fc98f4f71"
ROOT_PREFIX_SHA256 = "f7349131b3c47915a5d9d2ec3168e16ef14fa42b16efa53ff0cf96369bfacbbf"
JOB_SHA256 = {
    "validate-subject": "dbf9585a06fa2e512804b44542dcf03f7f770f7d74cef68ba97695c02d15754f",
    "validate-runner": "e1c0156e8675a9e27a3db2d3e19ea12f1f8e5c31708cfdbfd3c9043600baa74e",
    "subject-workflow-preflight": (
        "4254e49cecc03272168d3b5f0bdb6488ea046ae3bae165281225d08b57a43ffa"
    ),
    "workspace-tests": "cff1d5ad0f6cb5aff73e4d3758565b105bec61264143f16e272c68474e55636a",
    "assurance-monolith": ("7d2de01a84273aa3078fa1a9e5b548abd30f8d8b5e9ad4a314c0315c0e365c8d"),
}
BOUNDARY_BLOCK = """# Receipt boundary inherited from the reviewed R1d CI: this runs only the exact
# pre-reviewed subject. Deliberate same-UID subject/tool tampering, Docker-daemon
# abuse, transient replace-and-restore, and compromised GitHub-hosted
# infrastructure are outside this narrow receipt. Pre/post inventories show
# observed terminal stability, not continuous custody. This is not arbitrary
# untrusted-candidate isolation, artifact attestation, native subject head_sha,
# final Phase 285 closure, or external enforcement.
"""
PREFLIGHT_RUN_SHA256 = {
    "Verify runner infrastructure and parser self-test": (
        "e166920ac7fde8bf7030c65f9ffca8c4315b7dbadc2d3ffafab1544575db3ddd"
    ),
    "Bind the detached checkout to the exact commit and tree": (
        "461569b4cba6857590aa5759ac3d7d63b029855a2037fae61c31788b859f3245"
    ),
    "Extract the exact subject monolith without executing it": (
        "11077609e652b2ddcdc07570bceb714351483cc834a1b1f6ad1197cba648433a"
    ),
    "Provision digest-bound actionlint and lint the exact subject workflow": (
        "f75fe84b1dbf413598866279f589de52ce33a0d6b1d94ba1b78eef8a524989e1"
    ),
}
PREFLIGHT_JOB_SHA256 = "4254e49cecc03272168d3b5f0bdb6488ea046ae3bae165281225d08b57a43ffa"
PREFLIGHT_STEP_SHA256 = {
    "Checkout immutable runner infrastructure": (
        "153e6b3a9c9385f243d59b4d77c4dd56901c36e3f362a5aa9d2af6a445a10cbb"
    ),
    "Verify runner infrastructure and parser self-test": (
        "90cedcc5bd66649cad00fb71982ff841759e4a15f5f7d972f325d9d3c45b94ea"
    ),
    "Checkout the exact subject ref without persisted credentials": (
        "632c581327d04c2f01d93d6d9316e410a766c506dd161488cb638ec1adc28517"
    ),
    "Bind the detached checkout to the exact commit and tree": (
        "9738604ca9836e6e028655823b92c960180eeff61b2eee09eed01f3bae5df250"
    ),
    "Extract the exact subject monolith without executing it": (
        "50172d851fb0831f2c7daf07d3986c8a1a043b0264c33c7c0b89378b6c1dc772"
    ),
    "Provision digest-bound actionlint and lint the exact subject workflow": (
        "484cbd31306c3140df3eb117e7776a8f2934b3187dacbe1445f2a0a42917a549"
    ),
}
PREFLIGHT_STEP_SCHEMA: dict[str, dict[str, list[tuple[str, str | None]]]] = {
    "Checkout immutable runner infrastructure": {
        "fields": [("uses", CHECKOUT), ("with", None)],
        "with": [
            ("ref", "${{ github.sha }}"),
            ("fetch-depth", "1"),
            ("persist-credentials", "false"),
            ("path", "control"),
            ("clean", "true"),
            ("lfs", "false"),
            ("submodules", "false"),
        ],
    },
    "Verify runner infrastructure and parser self-test": {
        "fields": [
            ("working-directory", "control"),
            ("shell", "/bin/bash --noprofile --norc -e -o pipefail {0}"),
            ("env", None),
            ("run", "|"),
        ],
        "env": [
            ("BASH_ENV", "/dev/null"),
            ("ENV", "/dev/null"),
            ("CDPATH", '""'),
            ("PHASE285_CONTROL_SHA", "${{ github.sha }}"),
        ],
    },
    "Checkout the exact subject ref without persisted credentials": {
        "fields": [("uses", CHECKOUT), ("with", None)],
        "with": [
            ("ref", R1D_REF),
            ("fetch-depth", "1"),
            ("persist-credentials", "false"),
            ("path", "subject"),
            ("clean", "true"),
            ("lfs", "false"),
            ("submodules", "false"),
        ],
    },
    "Bind the detached checkout to the exact commit and tree": {
        "fields": [
            ("working-directory", "subject"),
            ("shell", "/bin/bash --noprofile --norc -e -o pipefail {0}"),
            ("env", None),
            ("run", "|"),
        ],
        "env": [
            ("BASH_ENV", "/dev/null"),
            ("ENV", "/dev/null"),
            ("CDPATH", '""'),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", '"1"'),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_NO_REPLACE_OBJECTS", '"1"'),
        ],
    },
    "Extract the exact subject monolith without executing it": {
        "fields": [
            ("working-directory", "subject"),
            ("shell", "/bin/bash --noprofile --norc -e -o pipefail {0}"),
            ("env", None),
            ("run", "|"),
        ],
        "env": [
            ("BASH_ENV", "/dev/null"),
            ("ENV", "/dev/null"),
            ("CDPATH", '""'),
            (
                "PHASE285_PREFLIGHT_EXTRACTED_SCRIPT",
                "${{ runner.temp }}/phase285-preflight-monolith.sh",
            ),
        ],
    },
    "Provision digest-bound actionlint and lint the exact subject workflow": {
        "fields": [
            ("working-directory", "subject"),
            ("shell", "/bin/bash --noprofile --norc -e -o pipefail {0}"),
            ("env", None),
            ("run", "|"),
        ],
        "env": [
            ("BASH_ENV", "/dev/null"),
            ("ENV", "/dev/null"),
            ("CDPATH", '""'),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_NOSYSTEM", '"1"'),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_NO_REPLACE_OBJECTS", '"1"'),
            ("GIT_OPTIONAL_LOCKS", '"0"'),
            ("GOPATH", "${{ runner.temp }}/phase285-preflight-actionlint-gopath"),
            (
                "PHASE285_ACTIONLINT_ARCHIVE",
                "${{ runner.temp }}/phase285-preflight-actionlint-1.7.7-linux-amd64.tar.gz",
            ),
        ],
    },
}


def _job_block(text: str, job_name: str) -> str:
    marker = f"  {job_name}:\n"
    if text.count(marker) != 1:
        raise ContractError(f"runner job is missing or duplicated: {job_name}")
    start = text.index(marker)
    match = re.search(r"(?m)^  [a-z0-9][a-z0-9-]*:\n", text[start + len(marker) :])
    end = len(text) if match is None else start + len(marker) + match.start()
    return text[start:end]


def _step_block(job_block: str, step_name: str) -> str:
    marker = f"      - name: {step_name}\n"
    if job_block.count(marker) != 1:
        raise ContractError(f"runner step is missing or duplicated: {step_name}")
    start = job_block.index(marker)
    following = job_block[start + len(marker) :]
    next_step = re.search(r"(?m)^      - name: .+$", following)
    end = len(job_block) if next_step is None else start + len(marker) + next_step.start()
    return job_block[start:end]


def _canonical_mapping_entries(block: str, indentation: int) -> list[tuple[str, str | None]]:
    prefix = " " * indentation
    pattern = re.compile(rf"^{prefix}([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?$")
    entries: list[tuple[str, str | None]] = []
    for line in block.splitlines():
        match = pattern.match(line)
        if match:
            entries.append((match.group(1), match.group(2)))
    keys = [key for key, _ in entries]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise ContractError(f"runner canonical mapping contains duplicate keys: {duplicates}")
    return entries


def _nested_mapping_entries(step_block: str, parent_key: str) -> list[tuple[str, str | None]]:
    marker = f"        {parent_key}:\n"
    if step_block.count(marker) != 1:
        raise ContractError(f"runner step nested mapping differs: {parent_key}")
    start = step_block.index(marker) + len(marker)
    following = step_block[start:]
    next_field = re.search(r"(?m)^        [A-Za-z_][A-Za-z0-9_-]*:", following)
    end = len(step_block) if next_field is None else start + next_field.start()
    return _canonical_mapping_entries(step_block[start:end], 10)


def _root_child_mapping_entries(text: str, parent_key: str) -> list[tuple[str, str | None]]:
    marker = f"{parent_key}:\n"
    matches = list(re.finditer(rf"(?m)^{re.escape(marker)}", text))
    if len(matches) != 1:
        raise ContractError(f"runner root mapping differs: {parent_key}")
    start = matches[0].start() + len(marker)
    following = text[start:]
    next_root_key = re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_-]*:", following)
    end = len(text) if next_root_key is None else start + next_root_key.start()
    return _canonical_mapping_entries(text[start:end], 2)


def _reject_global_duplicate_mapping_keys(text: str) -> None:
    contexts: list[tuple[int, tuple[str, ...]]] = [(0, ("root",))]
    seen: dict[tuple[str, ...], set[str]] = {}
    sequence_indexes: dict[tuple[str, ...], int] = {}
    literal_indent: int | None = None
    key_pattern = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):(?: (.*))?$")
    for line_number, line in enumerate(text.splitlines(), 1):
        indentation = len(line) - len(line.lstrip(" "))
        if literal_indent is not None:
            if not line.strip() or indentation > literal_indent:
                continue
            literal_indent = None
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        while len(contexts) > 1 and indentation < contexts[-1][0]:
            contexts.pop()
        content = line[indentation:]
        is_sequence_item = content.startswith("- ")
        if is_sequence_item:
            if contexts[-1][0] != indentation:
                continue
            sequence_path = contexts[-1][1]
            item_index = sequence_indexes.get(sequence_path, 0)
            sequence_indexes[sequence_path] = item_index + 1
            item_path = sequence_path + (f"[{item_index}]",)
            contexts.append((indentation + 2, item_path))
            content = content[2:]
            match = key_pattern.match(content)
            if match is None:
                continue
            key, value = match.groups()
            scope = item_path
            effective_indentation = indentation + 2
        else:
            if contexts[-1][0] != indentation:
                continue
            match = key_pattern.match(content)
            if match is None:
                continue
            key, value = match.groups()
            scope = contexts[-1][1]
            effective_indentation = indentation
        keys = seen.setdefault(scope, set())
        if key in keys:
            raise ContractError(
                f"runner YAML contains duplicate mapping key at line {line_number}: {key}"
            )
        keys.add(key)
        if value is None:
            contexts.append((effective_indentation + 2, scope + (key,)))
        elif value.startswith(("|", ">")):
            literal_indent = effective_indentation


def _literal_run_scalar(job_block: str, step_name: str) -> str:
    step_block = _step_block(job_block, step_name)
    run_marker = "        run: |\n"
    if step_block.count(run_marker) != 1:
        raise ContractError(f"runner step literal run scalar differs: {step_name}")
    scalar_lines = step_block.split(run_marker, 1)[1].splitlines(keepends=True)
    normalized: list[str] = []
    for line in scalar_lines:
        if line == "\n":
            normalized.append(line)
        elif line.startswith("          "):
            normalized.append(line[10:])
        else:
            raise ContractError(f"runner step contains data after its run scalar: {step_name}")
    return "".join(normalized).rstrip("\n") + "\n"


def _validate_runner_workflow(
    runner_raw: bytes, *, expected_digest: str = RUNNER_WORKFLOW_SHA256
) -> int:
    text = _decode_text(runner_raw, "runner workflow")
    _reject_global_duplicate_mapping_keys(text)
    if_key_patterns = (
        r"(?m)^[ ]*(?:-[ ]+)?(?:if|['\"]if['\"]|\"\\x69f\"|\"\\u0069f\")[ ]*:",
        r"(?m)^[ ]*\?[ ]*(?:if|['\"]if['\"])[ ]*$",
        r"(?m)(?:\{|,)[ ]*(?:if|['\"]if['\"]|\"\\x69f\"|\"\\u0069f\")[ ]*:",
    )
    if any(re.search(pattern, text) for pattern in if_key_patterns):
        raise ContractError("runner workflow must not contain an if mapping key")
    if text.count(BOUNDARY_BLOCK) != 1:
        raise ContractError("runner receipt boundary is missing, duplicated, or changed")
    claims_surface = text.replace(BOUNDARY_BLOCK, "", 1)
    forbidden_claims = (
        "arbitrary untrusted-candidate isolation",
        "artifact attestation",
        "native subject head_sha",
        "final Phase 285 closure",
        "external enforcement",
        "continuous custody",
        "continuous_custody=1",
        "terminal_stability=0",
        "attested=1",
        "isolated=1",
        "head_sha=",
    )
    claimed = [value for value in forbidden_claims if value in claims_surface]
    if claimed:
        raise ContractError(f"runner exceeds the narrow receipt boundary: {claimed}")
    expected_root_fields = [
        ("name", "Phase 285 Exact Subject"),
        ("on", None),
        ("permissions", None),
        ("env", None),
        ("jobs", None),
    ]
    observed_root_fields = _canonical_mapping_entries(text, 0)
    if observed_root_fields != expected_root_fields:
        raise ContractError(f"runner root fields differ: {observed_root_fields}")
    expected_root_children = {
        "on": [("workflow_dispatch", None)],
        "permissions": [("contents", "read")],
        "env": [
            ("PHASE285_SUBJECT_REF", R1D_REF),
            ("PHASE285_SUBJECT_SHA", R1D_SHA),
            ("PHASE285_SUBJECT_TREE", R1D_TREE),
            ("PHASE285_ACTIONLINT_ARCHIVE_SHA256", ACTIONLINT_ARCHIVE_SHA256),
        ],
        "jobs": [(name, None) for name in JOB_SHA256],
    }
    for root_key, expected_children in expected_root_children.items():
        observed_children = _root_child_mapping_entries(text, root_key)
        if observed_children != expected_children:
            raise ContractError(f"runner root {root_key} mapping differs: {observed_children}")
    root_prefix = text[: text.index("jobs:\n")]
    observed_root_prefix_digest = hashlib.sha256(root_prefix.encode()).hexdigest()
    if observed_root_prefix_digest != ROOT_PREFIX_SHA256:
        raise ContractError(f"runner canonical root prefix differs: {observed_root_prefix_digest}")
    forbidden = (
        "pull_request_target",
        "\n  push:\n",
        "\n  pull_request:\n",
        "\n  schedule:\n",
        "secrets.",
        "contents: write",
        "id-token: write",
        "attestations: write",
        "actions/cache",
        "restore-keys:",
        "actions/upload-artifact",
        "continue-on-error:",
        "protected-required",
        "GitHub App",
        "${{ inputs.",
        "\n  inputs:\n",
        "go install ",
        "cargo install ",
        "rustup update",
        "toolchain: stable",
        "- name: Provision the digest-bound actionlint release",
        "- name: Execute the exact extracted monolith",
        "phase285_bound_binary_terminal",
    )
    present = [value for value in forbidden if value in text]
    if present:
        raise ContractError(f"runner workflow contains forbidden authority or input: {present}")
    if text.count("permissions:\n  contents: read\n") != 1 or text.count("permissions:") != 1:
        raise ContractError("runner permissions must be the unique canonical contents-read block")
    required_counts = {
        "on:\n  workflow_dispatch:\n": 1,
        f"  PHASE285_SUBJECT_REF: {R1D_REF}\n": 1,
        f"  PHASE285_SUBJECT_SHA: {R1D_SHA}\n": 1,
        f"  PHASE285_SUBJECT_TREE: {R1D_TREE}\n": 1,
        f"          ref: {R1D_REF}\n": 3,
        "          persist-credentials: false\n": 6,
        "    runs-on: ubuntu-24.04\n": 5,
        "          CARGO_HOME: ${{ runner.temp }}/phase285-workspace-cargo-home\n": 3,
        "          CARGO_HOME: ${{ runner.temp }}/phase285-monolith-cargo-home\n": 3,
        f"          toolchain: {RUST_VERSION}\n": 2,
        f" = {RUSTC_COMMIT}\n": 2,
        f" = {CARGO_COMMIT}\n": 2,
        "        run: cargo fetch --locked\n": 2,
        "        run: cargo test --workspace --locked --offline\n": 1,
        f"  PHASE285_ACTIONLINT_ARCHIVE_SHA256: {ACTIONLINT_ARCHIVE_SHA256}\n": 1,
        "          GOPATH: ${{ runner.temp }}/phase285-actionlint-gopath\n": 1,
        "          GOPATH: ${{ runner.temp }}/phase285-preflight-actionlint-gopath\n": 1,
        "          PHASE285_ACTIONLINT_ARCHIVE: ${{ runner.temp }}/phase285-actionlint-1.7.7-linux-amd64.tar.gz\n": 1,
        "          PHASE285_ACTIONLINT_ARCHIVE: ${{ runner.temp }}/phase285-preflight-actionlint-1.7.7-linux-amd64.tar.gz\n": 1,
        "          PHASE285_PREFLIGHT_EXTRACTED_SCRIPT: ${{ runner.temp }}/phase285-preflight-monolith.sh\n": 1,
        f" = {ACTIONLINT_ARCHIVE_SHA256}\n": 2,
        "https://github.com/rhysd/actionlint/releases/download/v1.7.7/actionlint_1.7.7_linux_amd64.tar.gz\n": 2,
        "          /usr/bin/curl --fail --silent --show-error --location \\\n": 2,
        "            --proto '=https' --proto-redir '=https' --tlsv1.2 \\\n": 2,
        '          /usr/bin/tar --extract --gzip --file "$PHASE285_ACTIONLINT_ARCHIVE" \\\n': 2,
        '          actionlint_archive_provisioned="$(/usr/bin/sha256sum "$PHASE285_ACTIONLINT_ARCHIVE" | /usr/bin/awk \'{print $1}\')"\n': 2,
        '          test "$actionlint_archive_provisioned" = "$PHASE285_ACTIONLINT_ARCHIVE_SHA256"\n': 2,
        '          actionlint_binary_provisioned="$(/usr/bin/sha256sum "$GOPATH/bin/actionlint" | /usr/bin/awk \'{print $1}\')"\n': 2,
        "          readonly actionlint_archive_provisioned actionlint_binary_provisioned\n": 2,
        "          verify_actionlint_files() {\n": 1,
        "          verify_actionlint_binding() {\n": 1,
        "          verify_terminal_subject() {\n": 1,
        "          readonly -f verify_actionlint_files verify_actionlint_binding verify_terminal_subject\n": 1,
        "          verify_actionlint_files\n": 2,
        "          verify_actionlint_binding\n": 2,
        "          verify_terminal_subject\n": 1,
        "      - name: Provision digest-bound actionlint and execute the exact monolith\n": 1,
        '            test "$RUNNER_TEMP" = "$(/usr/bin/realpath -e "$RUNNER_TEMP")"\n': 2,
        '            test "$(/usr/bin/dirname "$GOPATH")" = "$RUNNER_TEMP"\n': 2,
        '            test "$(/usr/bin/realpath -e "$GOPATH")" = "$GOPATH"\n': 2,
        '            test -d "$GOPATH"\n': 2,
        '            test ! -L "$GOPATH"\n': 2,
        '            test "$(/usr/bin/stat -c \'%a\' "$GOPATH")" = 700\n': 2,
        '            test "$(/usr/bin/dirname "$GOPATH/bin")" = "$GOPATH"\n': 2,
        '            test "$(/usr/bin/realpath -e "$GOPATH/bin")" = "$GOPATH/bin"\n': 2,
        '            test -d "$GOPATH/bin"\n': 2,
        '            test ! -L "$GOPATH/bin"\n': 2,
        '            test "$(/usr/bin/stat -c \'%a\' "$GOPATH/bin")" = 700\n': 2,
        '            test "$(/usr/bin/dirname "$PHASE285_ACTIONLINT_ARCHIVE")" = "$RUNNER_TEMP"\n': 2,
        '            test "$(/usr/bin/realpath -e "$PHASE285_ACTIONLINT_ARCHIVE")" = "$PHASE285_ACTIONLINT_ARCHIVE"\n': 2,
        '            test -f "$PHASE285_ACTIONLINT_ARCHIVE"\n': 2,
        '            test ! -L "$PHASE285_ACTIONLINT_ARCHIVE"\n': 2,
        '            test "$(/usr/bin/stat -c \'%a\' "$PHASE285_ACTIONLINT_ARCHIVE")" = 600\n': 2,
        '            test "$observed_archive_sha" = "$PHASE285_ACTIONLINT_ARCHIVE_SHA256"\n': 2,
        '            test "$observed_archive_sha" = "$actionlint_archive_provisioned"\n': 2,
        '            test -f "$GOPATH/bin/actionlint"\n': 2,
        '            test ! -L "$GOPATH/bin/actionlint"\n': 2,
        '            test -x "$GOPATH/bin/actionlint"\n': 2,
        '            test "$(/usr/bin/dirname "$GOPATH/bin/actionlint")" = "$GOPATH/bin"\n': 2,
        '            test "$(/usr/bin/realpath -e "$GOPATH/bin/actionlint")" = "$GOPATH/bin/actionlint"\n': 2,
        '            test "$(/usr/bin/stat -c \'%a\' "$GOPATH/bin/actionlint")" = 500\n': 2,
        '            test "$observed_binary_sha" = "$actionlint_binary_provisioned"\n': 2,
        '            test "$(go env GOPATH)/bin/actionlint" = "$GOPATH/bin/actionlint"\n': 1,
        '            test "$(command -v "$GOPATH/bin/actionlint")" = "$GOPATH/bin/actionlint"\n': 2,
        '            test "$("$GOPATH/bin/actionlint" -version | /usr/bin/sed -n \'1p\')" = 1.7.7\n': 2,
        "      - name: Provision digest-bound actionlint and lint the exact subject workflow\n": 1,
        '          "$GOPATH/bin/actionlint" -shellcheck= "$subject_workflow_path"\n': 1,
        "          verify_preflight_inventory() {\n": 1,
        "          verify_preflight_binding() {\n": 1,
        "          readonly -f verify_preflight_inventory verify_preflight_binding\n": 1,
        "            verify_preflight_inventory\n": 2,
        "          verify_preflight_binding\n": 2,
        '            test "$(/usr/bin/stat -c \'%a\' "$subject_workflow_path")" = 644\n': 1,
        '            test "$(/usr/bin/git ls-tree "$PHASE285_SUBJECT_SHA" -- .github/workflows/ci.yml | /usr/bin/awk \'{print $1}\')" = 100644\n': 1,
        '            test "$(/usr/bin/git hash-object "$subject_workflow_path")" = "$subject_workflow_blob"\n': 1,
        '            test "$(/usr/bin/git rev-parse "$PHASE285_SUBJECT_SHA:.github/workflows/ci.yml")" = "$subject_workflow_blob"\n': 1,
        "      - name: Audit terminal workspace subject identity and cleanliness\n": 1,
        "          printf 'phase285_workspace_terminal_inventory sha=%s tree=%s detached=1 clean=1 continuous_custody=0 passed=1\\n' \\\n": 1,
        "          printf 'phase285_monolith_terminal_inventory archive_sha256=%s binary_sha256=%s sha=%s tree=%s clean=1 continuous_custody=0 passed=1\\n' \\\n": 1,
        "          printf 'phase285_subject_workflow_preflight archive_sha256=%s binary_sha256=%s workflow_blob=%s workflow_sha256=%s terminal_stability=1 continuous_custody=0 passed=1\\n' \\\n": 1,
        '          export GITHUB_SHA="$PHASE285_SUBJECT_SHA"\n': 1,
        "../control/tools/phase285_exact_subject_parser.py extract \\\n": 2,
        "check-runner-workflow .github/workflows/phase285-exact-subject.yml\n": 3,
    }
    for value, expected in required_counts.items():
        if text.count(value) != expected:
            raise ContractError(f"runner canonical surface count differs: {value.rstrip()}")
    expected_jobs = {
        "validate-subject": None,
        "validate-runner": "validate-subject",
        "subject-workflow-preflight": "validate-runner",
        "workspace-tests": "subject-workflow-preflight",
        "assurance-monolith": "subject-workflow-preflight",
    }
    jobs_tail = text.split("jobs:\n", 1)
    if len(jobs_tail) != 2 or text.count("jobs:\n") != 1:
        raise ContractError("runner jobs mapping is missing or duplicated")
    observed_jobs = set(re.findall(r"(?m)^  ([a-z0-9][a-z0-9-]*):$", jobs_tail[1]))
    if observed_jobs != set(expected_jobs):
        raise ContractError(f"runner job inventory differs: {sorted(observed_jobs)}")
    for job_name, dependency in expected_jobs.items():
        block = _job_block(text, job_name)
        observed_needs = re.findall(r"(?m)^    needs: ([a-z0-9-]+)$", block)
        expected_needs = [] if dependency is None else [dependency]
        if observed_needs != expected_needs:
            raise ContractError(f"runner dependency differs for {job_name}: {observed_needs}")
        observed_job_digest = hashlib.sha256(block.encode()).hexdigest()
        if observed_job_digest != JOB_SHA256[job_name]:
            raise ContractError(
                f"runner canonical job differs for {job_name}: {observed_job_digest}"
            )
    checker_command = (
        "            check-runner-workflow .github/workflows/phase285-exact-subject.yml\n"
    )
    for job_name in ("validate-runner", "subject-workflow-preflight", "assurance-monolith"):
        if _job_block(text, job_name).count(checker_command) != 1:
            raise ContractError(f"runner checker invocation differs for {job_name}")
    preflight_block = _job_block(text, "subject-workflow-preflight")
    expected_preflight_job_fields = [
        ("name", "lint the exact subject workflow before subject execution"),
        ("needs", "validate-runner"),
        ("runs-on", "ubuntu-24.04"),
        ("steps", None),
    ]
    observed_preflight_job_fields = _canonical_mapping_entries(preflight_block, 4)
    if observed_preflight_job_fields != expected_preflight_job_fields:
        raise ContractError(
            f"subject workflow preflight job fields differ: {observed_preflight_job_fields}"
        )
    expected_preflight_steps = [
        "Checkout immutable runner infrastructure",
        "Verify runner infrastructure and parser self-test",
        "Checkout the exact subject ref without persisted credentials",
        "Bind the detached checkout to the exact commit and tree",
        "Extract the exact subject monolith without executing it",
        "Provision digest-bound actionlint and lint the exact subject workflow",
    ]
    observed_preflight_steps = re.findall(r"(?m)^      - name: (.+)$", preflight_block)
    if observed_preflight_steps != expected_preflight_steps:
        raise ContractError(
            f"subject workflow preflight step inventory differs: {observed_preflight_steps}"
        )
    if list(PREFLIGHT_STEP_SHA256) != expected_preflight_steps:
        raise ContractError("subject workflow preflight step digest inventory differs")
    if list(PREFLIGHT_STEP_SCHEMA) != expected_preflight_steps:
        raise ContractError("subject workflow preflight step schema inventory differs")
    for step_name in expected_preflight_steps:
        step_block = _step_block(preflight_block, step_name)
        schema = PREFLIGHT_STEP_SCHEMA[step_name]
        observed_fields = _canonical_mapping_entries(step_block, 8)
        if observed_fields != schema["fields"]:
            raise ContractError(
                f"subject workflow preflight step fields differ: {step_name} {observed_fields}"
            )
        for nested_key in ("with", "env"):
            expected_nested = schema.get(nested_key)
            if expected_nested is None:
                if f"        {nested_key}:\n" in step_block:
                    raise ContractError(
                        f"subject workflow preflight step has unexpected {nested_key}: {step_name}"
                    )
                continue
            observed_nested = _nested_mapping_entries(step_block, nested_key)
            if observed_nested != expected_nested:
                raise ContractError(
                    f"subject workflow preflight {nested_key} differs: {step_name} "
                    f"{observed_nested}"
                )
        observed_step_digest = hashlib.sha256(step_block.encode()).hexdigest()
        if observed_step_digest != PREFLIGHT_STEP_SHA256[step_name]:
            raise ContractError(
                f"subject workflow preflight step object differs: {step_name} "
                f"{observed_step_digest}"
            )
    observed_preflight_job_digest = hashlib.sha256(preflight_block.encode()).hexdigest()
    if observed_preflight_job_digest != PREFLIGHT_JOB_SHA256:
        raise ContractError(
            f"subject workflow preflight job object differs: {observed_preflight_job_digest}"
        )
    for step_name, expected_run_digest in PREFLIGHT_RUN_SHA256.items():
        run_scalar = _literal_run_scalar(preflight_block, step_name)
        observed_run_digest = hashlib.sha256(run_scalar.encode()).hexdigest()
        if observed_run_digest != expected_run_digest:
            raise ContractError(
                f"subject workflow preflight run scalar differs: {step_name} {observed_run_digest}"
            )
    extract_command = "          /usr/bin/python3 -I ../control/tools/phase285_exact_subject_parser.py extract \\\n"
    provision_marker = (
        "      - name: Provision digest-bound actionlint and lint the exact subject workflow\n"
    )
    lint_command = '          "$GOPATH/bin/actionlint" -shellcheck= "$subject_workflow_path"\n'
    for value in (extract_command, provision_marker, lint_command):
        if preflight_block.count(value) != 1:
            raise ContractError(f"subject workflow preflight command differs: {value.rstrip()}")
    if not (
        preflight_block.index(extract_command)
        < preflight_block.index(provision_marker)
        < preflight_block.index(lint_command)
    ):
        raise ContractError("subject workflow extraction, provisioning, and lint order differs")
    workspace_block = _job_block(text, "workspace-tests")
    if (
        workspace_block.count(
            "      - name: Audit terminal workspace subject identity and cleanliness\n"
        )
        != 1
    ):
        raise ContractError("workspace terminal cleanliness audit differs")
    monolith_block = _job_block(text, "assurance-monolith")
    if (
        monolith_block.count(
            "      - name: Provision digest-bound actionlint and execute the exact monolith\n"
        )
        != 1
    ):
        raise ContractError("actionlint provision and monolith execution are split")
    execution_sequence = (
        "          verify_actionlint_binding\n"
        '          /bin/bash --noprofile --norc -e -o pipefail "$PHASE285_EXTRACTED_SCRIPT"\n'
        "          verify_actionlint_binding\n"
        "          verify_terminal_subject\n"
    )
    if monolith_block.count(execution_sequence) != 1:
        raise ContractError("monolith pre/post tool binding sequence differs")

    allowed_single_run = {
        "cargo fetch --locked",
        "cargo test --workspace --locked --offline",
    }
    allowed_expressions = {
        "PHASE285_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
        "PHASE285_DISPATCH_REF: ${{ github.ref }}",
        "PHASE285_CONTROL_SHA: ${{ github.sha }}",
        "ref: ${{ github.sha }}",
        "CARGO_HOME: ${{ runner.temp }}/phase285-workspace-cargo-home",
        "CARGO_HOME: ${{ runner.temp }}/phase285-monolith-cargo-home",
        "CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-exact-workspace-target",
        "CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-assurance-target",
        "PHASE285_EXTRACTED_SCRIPT: ${{ runner.temp }}/phase285-exact-subject-monolith.sh",
        "PHASE285_PREFLIGHT_EXTRACTED_SCRIPT: ${{ runner.temp }}/phase285-preflight-monolith.sh",
        "GOPATH: ${{ runner.temp }}/phase285-actionlint-gopath",
        "GOPATH: ${{ runner.temp }}/phase285-preflight-actionlint-gopath",
        "PHASE285_ACTIONLINT_ARCHIVE: ${{ runner.temp }}/phase285-actionlint-1.7.7-linux-amd64.tar.gz",
        "PHASE285_ACTIONLINT_ARCHIVE: ${{ runner.temp }}/phase285-preflight-actionlint-1.7.7-linux-amd64.tar.gz",
    }
    uses: list[str] = []
    run_indent: int | None = None
    for line in text.splitlines():
        indentation = len(line) - len(line.lstrip(" "))
        if run_indent is not None:
            if not line.strip() or indentation > run_indent:
                if "${{" in line:
                    raise ContractError("runner literal run block contains a GitHub expression")
                continue
            run_indent = None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line:
            raise ContractError("runner workflow contains a tab")
        if re.match(r"^ *(?:- +)?(?:[A-Za-z_][A-Za-z0-9_-]*|['\"][^'\"]+['\"])[ ]+:", line):
            raise ContractError(
                f"runner mapping key has noncanonical colon spacing: {line.strip()}"
            )
        if (
            re.match(r"^ *(?:- +)?['\"]", line)
            or line.lstrip().startswith(("- {", "{", "? ", "- ? "))
            or ": {" in line
            or ": [" in line
            or "<<:" in line
        ):
            raise ContractError(
                f"runner workflow uses a quoted, flow, or merged mapping: {line.strip()}"
            )
        if re.search(r"(?:^|[ :])(?:&|\*|!!|!<)", line):
            raise ContractError(
                f"runner workflow uses a YAML anchor, alias, or tag: {line.strip()}"
            )
        run_match = re.match(r"^( *)(?:run):(?: (.*))?$", line)
        if run_match:
            value = run_match.group(2)
            if value == "|":
                run_indent = len(run_match.group(1))
            elif value not in allowed_single_run:
                raise ContractError(f"runner single-line run scalar is not closed: {value}")
        elif re.match(r"^ *['\"]?run['\"]? *:", line):
            raise ContractError(f"runner run key is not canonical: {line.strip()}")
        uses_match = re.match(r"^        uses: (\S+)$", line)
        if uses_match:
            uses.append(uses_match.group(1))
        elif re.match(r"^ *['\"]?uses['\"]? *:", line):
            raise ContractError(f"runner uses key is not canonical: {line.strip()}")
        if "${{" in line and line.strip() not in allowed_expressions:
            raise ContractError(f"runner expression surface is not closed: {line.strip()}")
    if uses.count(CHECKOUT) != 6 or uses.count(RUST_TOOLCHAIN) != 2 or len(uses) != 8:
        raise ContractError(f"runner pinned action inventory differs: {uses}")
    observed_digest = hashlib.sha256(runner_raw).hexdigest()
    if observed_digest != expected_digest:
        raise ContractError(f"runner reviewed-byte digest differs: {observed_digest}")
    return len(uses)


def _replace_once(raw: bytes, old: bytes, new: bytes, *, expected_count: int | None = 1) -> bytes:
    observed_count = raw.count(old)
    if observed_count < 1 or (expected_count is not None and observed_count != expected_count):
        raise ContractError(f"runner mutation source cardinality differs: {old!r}")
    mutation = raw.replace(old, new, 1)
    if mutation == raw:
        raise ContractError(f"runner mutation made no change: {old!r}")
    return mutation


def _runner_mutations(runner_raw: bytes) -> dict[str, bytes]:
    checkout_line = f"        uses: {CHECKOUT}\n".encode()
    execution_line = (
        b'          /bin/bash --noprofile --norc -e -o pipefail "$PHASE285_EXTRACTED_SCRIPT"\n'
    )
    split_step = _replace_once(
        runner_raw,
        b"          verify_actionlint_binding\n" + execution_line,
        b"      - name: Execute the monolith in a split step\n"
        b"        working-directory: subject\n"
        b"        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n"
        b"        run: |\n" + execution_line,
    )
    untrusted_rebaseline = _replace_once(
        runner_raw,
        b"          readonly actionlint_archive_provisioned actionlint_binary_provisioned\n\n"
        b"          verify_actionlint_files() {\n",
        b"\n          verify_actionlint_files() {\n",
    )
    untrusted_rebaseline = _replace_once(
        untrusted_rebaseline,
        execution_line + b"          verify_actionlint_binding\n",
        execution_line + b'          actionlint_binary_provisioned="$(/usr/bin/sha256sum '
        b'"$GOPATH/bin/actionlint" | /usr/bin/awk \'{print $1}\')"\n'
        + b"          verify_actionlint_binding\n",
    )
    workspace_step_start = (
        b"      - name: Audit terminal workspace subject identity and cleanliness\n"
    )
    workspace_step_end = b"\n  assurance-monolith:\n"
    if runner_raw.count(workspace_step_start) != 1 or runner_raw.count(workspace_step_end) != 1:
        raise ContractError("workspace terminal mutation boundaries differ")
    workspace_start = runner_raw.index(workspace_step_start)
    workspace_end = runner_raw.index(workspace_step_end, workspace_start)
    workspace_terminal_omission = runner_raw[:workspace_start] + runner_raw[workspace_end + 1 :]
    preflight_lint_line = (
        b'          "$GOPATH/bin/actionlint" -shellcheck= "$subject_workflow_path"\n'
    )
    preflight_extract_line = b"          /usr/bin/python3 -I ../control/tools/phase285_exact_subject_parser.py extract \\\n"
    preflight_lint_reordered = _replace_once(runner_raw, preflight_lint_line, b"")
    preflight_lint_reordered = _replace_once(
        preflight_lint_reordered,
        preflight_extract_line,
        preflight_lint_line + preflight_extract_line,
        expected_count=2,
    )

    def insert_before_preflight_lint(command: bytes) -> bytes:
        return _replace_once(runner_raw, preflight_lint_line, command + preflight_lint_line)

    workspace_job_header = (
        b"  workspace-tests:\n"
        b"    name: exact-subject workspace tests\n"
        b"    needs: subject-workflow-preflight\n"
    )
    monolith_job_header = (
        b"  assurance-monolith:\n"
        b"    name: exact-subject assurance monolith\n"
        b"    needs: subject-workflow-preflight\n"
    )
    workspace_test_step = b"      - name: Run locked workspace tests\n"
    preflight_job_header = (
        b"  subject-workflow-preflight:\n"
        b"    name: lint the exact subject workflow before subject execution\n"
        b"    needs: validate-runner\n"
        b"    runs-on: ubuntu-24.04\n"
    )
    preflight_provision_header = (
        b"      - name: Provision digest-bound actionlint and lint the exact subject workflow\n"
        b"        working-directory: subject\n"
        b"        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n"
    )
    preflight_provision_env = preflight_provision_header + b"        env:\n"

    def mutate_preflight_job(old: bytes, new: bytes, *, expected_count: int = 1) -> bytes:
        start_marker = b"  subject-workflow-preflight:\n"
        end_marker = b"\n  workspace-tests:\n"
        if runner_raw.count(start_marker) != 1 or runner_raw.count(end_marker) != 1:
            raise ContractError("preflight mutation boundaries differ")
        start = runner_raw.index(start_marker)
        end = runner_raw.index(end_marker, start)
        job = runner_raw[start:end]
        mutated_job = _replace_once(job, old, new, expected_count=expected_count)
        return runner_raw[:start] + mutated_job + runner_raw[end:]

    def mutate_root_prefix(old: bytes, new: bytes, *, expected_count: int = 1) -> bytes:
        end_marker = b"jobs:\n"
        if runner_raw.count(end_marker) != 1:
            raise ContractError("root mutation boundary differs")
        end = runner_raw.index(end_marker) + len(end_marker)
        prefix = runner_raw[:end]
        mutated_prefix = _replace_once(prefix, old, new, expected_count=expected_count)
        return mutated_prefix + runner_raw[end:]

    root_env_header = b"env:\n  PHASE285_SUBJECT_REF: refs/heads/work/v179-phase285-convergence\n"
    root_env_block = (
        root_env_header
        + b"  PHASE285_SUBJECT_SHA: d229f90c4984fd882d4401fdb7923549fa7b0dbe\n"
        + b"  PHASE285_SUBJECT_TREE: 15dce0b2e157c7bfb9e71fee94d3818851a5751a\n"
        + b"  # Official v1.7.7 checksums.txt digest for the linux_amd64 release archive.\n"
        + b"  PHASE285_ACTIONLINT_ARCHIVE_SHA256: 023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757\n"
    )
    root_permissions = b"permissions:\n  contents: read\n"
    preflight_startup_env = (
        b'          BASH_ENV: /dev/null\n          ENV: /dev/null\n          CDPATH: ""\n'
    )

    return {
        "root-env-bash-env": mutate_root_prefix(
            root_env_header,
            root_env_header + b"  BASH_ENV: ../subject/tools/fixture-inventory.sh\n",
        ),
        "root-env-env": mutate_root_prefix(
            root_env_header,
            root_env_header + b"  ENV: ../subject/tools/fixture-inventory.sh\n",
        ),
        "root-env-shellopts": mutate_root_prefix(
            root_env_header, root_env_header + b"  SHELLOPTS: sourcepath\n"
        ),
        "root-env-bashopts": mutate_root_prefix(
            root_env_header, root_env_header + b"  BASHOPTS: sourcepath\n"
        ),
        "root-env-path": mutate_root_prefix(
            root_env_header, root_env_header + b"  PATH: ../subject/tools:/usr/bin:/bin\n"
        ),
        "root-env-git-config-count": mutate_root_prefix(
            root_env_header,
            root_env_header
            + b"  GIT_CONFIG_COUNT: 1\n"
            + b"  GIT_CONFIG_KEY_0: core.fsmonitor\n"
            + b"  GIT_CONFIG_VALUE_0: ../subject/tools/fixture-inventory.sh\n",
        ),
        "root-env-git-config-global": mutate_root_prefix(
            root_env_header,
            root_env_header + b"  GIT_CONFIG_GLOBAL: ../subject/.gitconfig\n",
        ),
        "root-env-git-config-system": mutate_root_prefix(
            root_env_header,
            root_env_header + b"  GIT_CONFIG_SYSTEM: ../subject/.gitconfig\n",
        ),
        "root-env-git-config-nosystem": mutate_root_prefix(
            root_env_header, root_env_header + b"  GIT_CONFIG_NOSYSTEM: 0\n"
        ),
        "root-env-pythonpath": mutate_root_prefix(
            root_env_header, root_env_header + b"  PYTHONPATH: ../subject/tools\n"
        ),
        "root-env-home": mutate_root_prefix(
            root_env_header, root_env_header + b"  HOME: ../subject\n"
        ),
        "root-env-ld-preload": mutate_root_prefix(
            root_env_header, root_env_header + b"  LD_PRELOAD: ../subject/libsubject.so\n"
        ),
        "root-env-action": mutate_root_prefix(
            root_env_header, root_env_header + b"  ACTIONS_STEP_DEBUG: true\n"
        ),
        "root-defaults-shell": mutate_root_prefix(
            b"jobs:\n",
            b"defaults:\n  run:\n    shell: /bin/sh {0}\n\njobs:\n",
        ),
        "root-defaults-working-directory": mutate_root_prefix(
            b"jobs:\n",
            b"defaults:\n  run:\n    working-directory: subject\n\njobs:\n",
        ),
        "root-concurrency": mutate_root_prefix(
            b"jobs:\n",
            b"concurrency:\n  group: phase285-bypass\n  cancel-in-progress: false\n\njobs:\n",
        ),
        "root-run-name": mutate_root_prefix(
            b"name: Phase 285 Exact Subject\n",
            b"name: Phase 285 Exact Subject\nrun-name: subject-bypass\n",
        ),
        "root-permission-contents-write": mutate_root_prefix(
            root_permissions, b"permissions:\n  contents: write\n"
        ),
        "root-permission-id-token": mutate_root_prefix(
            root_permissions,
            b"permissions:\n  contents: read\n  id-token: write\n",
        ),
        "root-env-alias": mutate_root_prefix(
            root_env_header,
            b"env:\n"
            + b"  PHASE285_SUBJECT_REF: &subject_path refs/heads/work/v179-phase285-convergence\n"
            + b"  BASH_ENV: *subject_path\n",
        ),
        "root-env-merge": mutate_root_prefix(
            root_env_block,
            b"subject-env: &subject_env\n"
            + b"  BASH_ENV: ../subject/tools/fixture-inventory.sh\n"
            + root_env_block.replace(b"env:\n", b"env:\n  <<: *subject_env\n", 1),
        ),
        "root-env-quoted-key": mutate_root_prefix(
            root_env_header,
            b'env:\n  "PHASE285_SUBJECT_REF": refs/heads/work/v179-phase285-convergence\n',
        ),
        "root-env-flow-map": mutate_root_prefix(
            root_env_block,
            b"env: {PHASE285_SUBJECT_REF: refs/heads/work/v179-phase285-convergence, PHASE285_SUBJECT_SHA: d229f90c4984fd882d4401fdb7923549fa7b0dbe, PHASE285_SUBJECT_TREE: 15dce0b2e157c7bfb9e71fee94d3818851a5751a, PHASE285_ACTIONLINT_ARCHIVE_SHA256: 023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757}\n",
        ),
        "root-duplicate-key": mutate_root_prefix(
            root_permissions,
            root_permissions + b"permissions:\n  contents: read\n",
        ),
        "root-duplicate-concurrency-map": mutate_root_prefix(
            b"jobs:\n",
            b"concurrency:\n"
            + b"  group: first\n"
            + b"  group: second\n"
            + b"  cancel-in-progress: false\n\n"
            + b"jobs:\n",
        ),
        "root-env-duplicate-key": mutate_root_prefix(
            root_env_header,
            root_env_header + b"  PHASE285_SUBJECT_REF: refs/heads/work/v179-phase285-other\n",
        ),
        "global-duplicate-workspace-job-key": _replace_once(
            runner_raw,
            workspace_job_header,
            workspace_job_header + b"    needs: validate-runner\n",
        ),
        "global-duplicate-checkout-with-key": _replace_once(
            runner_raw,
            b"          fetch-depth: 1\n",
            b"          fetch-depth: 1\n          fetch-depth: 0\n",
            expected_count=6,
        ),
        "global-duplicate-step-env-key": _replace_once(
            runner_raw,
            b"          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-exact-workspace-target\n",
            b"          CARGO_TARGET_DIR: ${{ runner.temp }}/phase285-exact-workspace-target\n"
            + b"          CARGO_TARGET_DIR: /tmp/duplicate-target\n",
        ),
        "root-extra-key": mutate_root_prefix(b"jobs:\n", b"timeout-minutes: 1\n\njobs:\n"),
        "root-env-subject-sha-replaced": mutate_root_prefix(
            b"  PHASE285_SUBJECT_SHA: d229f90c4984fd882d4401fdb7923549fa7b0dbe\n",
            b"  PHASE285_SUBJECT_SHA: 0000000000000000000000000000000000000000\n",
        ),
        "root-env-subject-tree-deleted": mutate_root_prefix(
            b"  PHASE285_SUBJECT_TREE: 15dce0b2e157c7bfb9e71fee94d3818851a5751a\n",
            b"",
        ),
        "root-env-actionlint-digest-deleted": mutate_root_prefix(
            b"  PHASE285_ACTIONLINT_ARCHIVE_SHA256: 023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757\n",
            b"",
        ),
        "root-trigger-replaced": mutate_root_prefix(
            b"on:\n  workflow_dispatch:\n", b"on:\n  push:\n"
        ),
        "root-trigger-inputs": mutate_root_prefix(
            b"on:\n  workflow_dispatch:\n",
            b"on:\n  workflow_dispatch:\n    inputs:\n      bypass:\n        required: false\n",
        ),
        "root-permissions-deleted": mutate_root_prefix(root_permissions, b""),
        "preflight-step-bash-env-omission": mutate_preflight_job(
            preflight_startup_env,
            b"          ENV: /dev/null\n" + b'          CDPATH: ""\n',
            expected_count=4,
        ),
        "preflight-step-bash-env-substitution": mutate_preflight_job(
            preflight_startup_env,
            b"          BASH_ENV: ../subject/tools/fixture-inventory.sh\n"
            + b"          ENV: /dev/null\n"
            + b'          CDPATH: ""\n',
            expected_count=4,
        ),
        "preflight-step-env-omission": mutate_preflight_job(
            preflight_startup_env,
            b"          BASH_ENV: /dev/null\n" + b'          CDPATH: ""\n',
            expected_count=4,
        ),
        "preflight-step-cdpath-substitution": mutate_preflight_job(
            preflight_startup_env,
            b"          BASH_ENV: /dev/null\n"
            + b"          ENV: /dev/null\n"
            + b"          CDPATH: ../subject/tools\n",
            expected_count=4,
        ),
        "receipt-boundary-omission": _replace_once(runner_raw, BOUNDARY_BLOCK.encode(), b""),
        "receipt-boundary-continuous-custody-claim": _replace_once(
            runner_raw, b"continuous_custody=0", b"continuous_custody=1", expected_count=3
        ),
        "preflight-actionlint-omission": _replace_once(runner_raw, preflight_lint_line, b""),
        "preflight-actionlint-reordering": preflight_lint_reordered,
        "preflight-subject-execution-before-lint": _replace_once(
            runner_raw,
            preflight_lint_line,
            b'          /bin/bash --noprofile --norc -e -o pipefail "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
            + preflight_lint_line,
        ),
        "job-if-always": _replace_once(
            runner_raw, workspace_job_header, workspace_job_header + b"    if: always()\n"
        ),
        "job-if-success": _replace_once(
            runner_raw, monolith_job_header, monolith_job_header + b"    if: success()\n"
        ),
        "job-if-failure": _replace_once(
            runner_raw, workspace_job_header, workspace_job_header + b"    if: failure()\n"
        ),
        "job-if-cancelled": _replace_once(
            runner_raw, monolith_job_header, monolith_job_header + b"    if: cancelled()\n"
        ),
        "job-if-expression": _replace_once(
            runner_raw,
            workspace_job_header,
            workspace_job_header + b"    if: ${{ always() }}\n",
        ),
        "job-if-key-spacing": _replace_once(
            runner_raw, workspace_job_header, workspace_job_header + b"    if : always()\n"
        ),
        "job-if-quoted-key": _replace_once(
            runner_raw, workspace_job_header, workspace_job_header + b"    'if': always()\n"
        ),
        "job-if-double-quoted-key": _replace_once(
            runner_raw, workspace_job_header, workspace_job_header + b'    "if": always()\n'
        ),
        "job-if-escaped-key": _replace_once(
            runner_raw,
            workspace_job_header,
            workspace_job_header + b'    "\\x69f": always()\n',
        ),
        "job-if-explicit-key": _replace_once(
            runner_raw,
            workspace_job_header,
            workspace_job_header + b"    ? if\n    : always()\n",
        ),
        "step-if-always": _replace_once(
            runner_raw, workspace_test_step, workspace_test_step + b"        if: always()\n"
        ),
        "step-if-success": _replace_once(
            runner_raw, workspace_test_step, workspace_test_step + b"        if: success()\n"
        ),
        "step-if-failure": _replace_once(
            runner_raw, workspace_test_step, workspace_test_step + b"        if: failure()\n"
        ),
        "step-if-cancelled": _replace_once(
            runner_raw, workspace_test_step, workspace_test_step + b"        if: cancelled()\n"
        ),
        "step-if-expression": _replace_once(
            runner_raw,
            workspace_test_step,
            workspace_test_step + b"        if: ${{ !cancelled() }}\n",
        ),
        "step-if-flow-mapping": _replace_once(
            runner_raw,
            workspace_test_step,
            b"      - {name: Conditional bypass, if: always(), run: echo bypass}\n"
            + workspace_test_step,
        ),
        "preflight-escape-env-bash": insert_before_preflight_lint(
            b'          /usr/bin/env /bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-source": insert_before_preflight_lint(
            b'          source "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-dot-source": insert_before_preflight_lint(
            b'          . "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-env-cargo": insert_before_preflight_lint(
            b"          /usr/bin/env cargo test\n"
        ),
        "preflight-escape-command-cargo": insert_before_preflight_lint(
            b"          command cargo test\n"
        ),
        "preflight-escape-sh-c": insert_before_preflight_lint(
            b"          /bin/sh -c '/bin/bash \"$RUNNER_TEMP/phase285-preflight-monolith.sh\"'\n"
        ),
        "preflight-escape-whitespace": insert_before_preflight_lint(
            b'          /bin/bash    "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-quoted-command": insert_before_preflight_lint(
            b'          "/bin/bash" "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-env-assignment": insert_before_preflight_lint(
            b'          /usr/bin/env SUBJECT_SCRIPT="$RUNNER_TEMP/phase285-preflight-monolith.sh" /bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-command-builtin": insert_before_preflight_lint(
            b'          command /bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-subshell": insert_before_preflight_lint(
            b'          ( /bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh" )\n'
        ),
        "preflight-escape-command-substitution": insert_before_preflight_lint(
            b'          $(/bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh")\n'
        ),
        "preflight-escape-eval": insert_before_preflight_lint(
            b"          eval '/bin/bash \"$RUNNER_TEMP/phase285-preflight-monolith.sh\"'\n"
        ),
        "preflight-escape-function": insert_before_preflight_lint(
            b'          run_subject() { /bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh"; }; run_subject\n'
        ),
        "preflight-escape-redirection": insert_before_preflight_lint(
            b'          /bin/bash < "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-escape-continuation": insert_before_preflight_lint(
            b'          /bin/\\\n          bash "$RUNNER_TEMP/phase285-preflight-monolith.sh"\n'
        ),
        "preflight-envelope-shell": _replace_once(
            runner_raw,
            preflight_provision_header,
            preflight_provision_header.replace(
                b"        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n",
                b'        shell: /bin/bash "$RUNNER_TEMP/phase285-preflight-monolith.sh" {0}\n',
            ),
        ),
        "preflight-envelope-bash-env": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header
            + b"    env:\n"
            + b"      BASH_ENV: /tmp/phase285-preflight-monolith.sh\n",
        ),
        "preflight-envelope-env-startup": _replace_once(
            runner_raw,
            preflight_provision_env,
            preflight_provision_env + b"          ENV: /tmp/phase285-preflight-monolith.sh\n",
        ),
        "preflight-envelope-working-directory": _replace_once(
            runner_raw,
            preflight_provision_header,
            preflight_provision_header.replace(
                b"        working-directory: subject\n",
                b"        working-directory: control\n",
            ),
        ),
        "preflight-envelope-env-injection": _replace_once(
            runner_raw,
            preflight_provision_env,
            preflight_provision_env + b"          PRELOAD_SUBJECT: subject-controlled\n",
        ),
        "preflight-envelope-continue-on-error": _replace_once(
            runner_raw,
            preflight_provision_header,
            preflight_provision_header + b"        continue-on-error: true\n",
        ),
        "preflight-envelope-step-timeout": _replace_once(
            runner_raw,
            preflight_provision_header,
            preflight_provision_header + b"        timeout-minutes: 1\n",
        ),
        "preflight-envelope-job-timeout": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header + b"    timeout-minutes: 1\n",
        ),
        "preflight-envelope-strategy": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header
            + b"    strategy:\n"
            + b"      fail-fast: false\n"
            + b"      matrix:\n"
            + b"        lane:\n"
            + b"          - preflight\n",
        ),
        "preflight-envelope-container": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header + b"    container: ubuntu:24.04\n",
        ),
        "preflight-envelope-services": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header
            + b"    services:\n"
            + b"      redis:\n"
            + b"        image: redis:7\n",
        ),
        "preflight-envelope-job-defaults": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header
            + b"    defaults:\n"
            + b"      run:\n"
            + b"        shell: /bin/sh {0}\n",
        ),
        "preflight-envelope-workflow-defaults": _replace_once(
            runner_raw,
            b"jobs:\n",
            b"defaults:\n  run:\n    shell: /bin/sh {0}\n\njobs:\n",
        ),
        "preflight-envelope-job-permissions": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header + b"    permissions:\n      contents: read\n",
        ),
        "preflight-envelope-extra-job-key": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header + b"    environment: production\n",
        ),
        "preflight-envelope-extra-step-key": _replace_once(
            runner_raw,
            preflight_provision_header,
            preflight_provision_header + b"        id: preflight-bypass\n",
        ),
        "preflight-envelope-extra-step": _replace_once(
            runner_raw,
            b"      - name: Provision digest-bound actionlint and lint the exact subject workflow\n",
            b"      - name: Execute subject before lint\n"
            + b"        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n"
            + b"        run: echo subject-bypass\n\n"
            + b"      - name: Provision digest-bound actionlint and lint the exact subject workflow\n",
        ),
        "preflight-envelope-checkout-uses": mutate_preflight_job(
            b"      - name: Checkout immutable runner infrastructure\n"
            + f"        uses: {CHECKOUT}\n".encode(),
            b"      - name: Checkout immutable runner infrastructure\n"
            + b"        uses: actions/checkout@v4\n",
        ),
        "preflight-envelope-checkout-with": mutate_preflight_job(
            b"          persist-credentials: false\n",
            b"          persist-credentials: true\n",
            expected_count=2,
        ),
        "preflight-envelope-duplicate-job-key": _replace_once(
            runner_raw,
            preflight_job_header,
            preflight_job_header + b"    needs: validate-subject\n",
        ),
        "preflight-envelope-duplicate-step-key": _replace_once(
            runner_raw,
            preflight_provision_header,
            preflight_provision_header
            + b"        shell: /bin/bash --noprofile --norc -e -o pipefail {0}\n",
        ),
        "permission-flow-key-spacing": _replace_once(
            runner_raw,
            b"permissions:\n  contents: read\n",
            b'permissions : {"contents": write,"id-token": write}\n',
        ),
        "mutable-uses-key-spacing": _replace_once(
            runner_raw,
            checkout_line,
            b"        uses : actions/checkout@v4\n",
            expected_count=6,
        ),
        "quoted-run-escaped-expression": _replace_once(
            runner_raw,
            b"        run: cargo test --workspace --locked --offline\n",
            b'        run: "echo \\x24{{ inputs.subject_ref }}"\n',
        ),
        "folded-run": _replace_once(
            runner_raw,
            b"        run: |\n",
            b"        run: >-\n",
            expected_count=None,
        ),
        "chomped-indented-run": _replace_once(
            runner_raw,
            b"        run: |\n",
            b"        run: |2-\n",
            expected_count=None,
        ),
        "workspace-command-omission": _replace_once(
            runner_raw, b"        run: cargo test --workspace --locked --offline\n", b""
        ),
        "checkout-duplication": _replace_once(
            runner_raw,
            checkout_line,
            checkout_line + checkout_line,
            expected_count=6,
        ),
        "subject-substitution": _replace_once(
            runner_raw,
            f"  PHASE285_SUBJECT_SHA: {R1D_SHA}\n".encode(),
            b"  PHASE285_SUBJECT_SHA: 0000000000000000000000000000000000000000\n",
        ),
        "workspace-dependency-bypass": _replace_once(
            runner_raw,
            b"  workspace-tests:\n    name: exact-subject workspace tests\n    needs: subject-workflow-preflight\n",
            b"  workspace-tests:\n    name: exact-subject workspace tests\n    needs: validate-subject\n",
        ),
        "monolith-dependency-bypass": _replace_once(
            runner_raw,
            b"  assurance-monolith:\n    name: exact-subject assurance monolith\n    needs: subject-workflow-preflight\n",
            b"  assurance-monolith:\n    name: exact-subject assurance monolith\n    needs: validate-subject\n",
        ),
        "preflight-runner-dependency-bypass": _replace_once(
            runner_raw,
            b"  subject-workflow-preflight:\n    name: lint the exact subject workflow before subject execution\n    needs: validate-runner\n",
            b"  subject-workflow-preflight:\n    name: lint the exact subject workflow before subject execution\n    needs: validate-subject\n",
        ),
        "runner-check-omission": _replace_once(
            runner_raw,
            b"            check-runner-workflow .github/workflows/phase285-exact-subject.yml\n",
            b"            --self-test\n",
            expected_count=3,
        ),
        "floating-rust-toolchain": _replace_once(
            runner_raw,
            f"          toolchain: {RUST_VERSION}\n".encode(),
            b"          toolchain: stable\n",
            expected_count=2,
        ),
        "rustc-source-substitution": _replace_once(
            runner_raw,
            f" = {RUSTC_COMMIT}\n".encode(),
            b" = 0000000000000000000000000000000000000000\n",
            expected_count=2,
        ),
        "mutable-actionlint-install": _replace_once(
            runner_raw,
            b"        run: cargo fetch --locked\n",
            b"        run: go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7\n",
            expected_count=2,
        ),
        "actionlint-digest-substitution": _replace_once(
            runner_raw,
            f"  PHASE285_ACTIONLINT_ARCHIVE_SHA256: {ACTIONLINT_ARCHIVE_SHA256}\n".encode(),
            b"  PHASE285_ACTIONLINT_ARCHIVE_SHA256: 0000000000000000000000000000000000000000000000000000000000000000\n",
        ),
        "actionlint-archive-check-omission": _replace_once(
            runner_raw,
            b'            test "$observed_archive_sha" = "$PHASE285_ACTIONLINT_ARCHIVE_SHA256"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-pre-bind-omission": _replace_once(
            runner_raw,
            b"          verify_actionlint_binding\n",
            b"",
            expected_count=2,
        ),
        "actionlint-post-bind-omission": _replace_once(
            runner_raw,
            execution_line + b"          verify_actionlint_binding\n",
            execution_line,
        ),
        "actionlint-step-split": split_step,
        "actionlint-untrusted-rebaseline": untrusted_rebaseline,
        "actionlint-ancestry-check-omission": _replace_once(
            runner_raw,
            b'            test "$(/usr/bin/dirname "$GOPATH")" = "$RUNNER_TEMP"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-directory-type-omission": _replace_once(
            runner_raw, b'            test -d "$GOPATH/bin"\n', b"", expected_count=2
        ),
        "actionlint-directory-mode-omission": _replace_once(
            runner_raw,
            b'            test "$(/usr/bin/stat -c \'%a\' "$GOPATH/bin")" = 700\n',
            b"",
            expected_count=2,
        ),
        "actionlint-archive-type-omission": _replace_once(
            runner_raw,
            b'            test -f "$PHASE285_ACTIONLINT_ARCHIVE"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-archive-mode-omission": _replace_once(
            runner_raw,
            b'            test "$(/usr/bin/stat -c \'%a\' "$PHASE285_ACTIONLINT_ARCHIVE")" = 600\n',
            b"",
            expected_count=2,
        ),
        "actionlint-binary-type-omission": _replace_once(
            runner_raw,
            b'            test -f "$GOPATH/bin/actionlint"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-binary-mode-omission": _replace_once(
            runner_raw,
            b'            test "$(/usr/bin/stat -c \'%a\' "$GOPATH/bin/actionlint")" = 500\n',
            b"",
            expected_count=2,
        ),
        "actionlint-binary-hash-omission": _replace_once(
            runner_raw,
            b'            test "$observed_binary_sha" = "$actionlint_binary_provisioned"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-canonical-path-omission": _replace_once(
            runner_raw,
            b'            test "$(/usr/bin/realpath -e "$GOPATH/bin/actionlint")" = "$GOPATH/bin/actionlint"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-resolution-omission": _replace_once(
            runner_raw,
            b'            test "$(command -v "$GOPATH/bin/actionlint")" = "$GOPATH/bin/actionlint"\n',
            b"",
            expected_count=2,
        ),
        "actionlint-version-omission": _replace_once(
            runner_raw,
            b'            test "$("$GOPATH/bin/actionlint" -version | /usr/bin/sed -n \'1p\')" = 1.7.7\n',
            b"",
            expected_count=2,
        ),
        "preflight-workflow-identity-omission": _replace_once(
            runner_raw,
            b'            test "$(/usr/bin/git hash-object "$subject_workflow_path")" = "$subject_workflow_blob"\n',
            b"",
        ),
        "workspace-terminal-audit-omission": workspace_terminal_omission,
        "monolith-terminal-audit-omission": _replace_once(
            runner_raw, b"          verify_terminal_subject\n", b""
        ),
        "cargo-fetch-unlocked": _replace_once(
            runner_raw,
            b"        run: cargo fetch --locked\n",
            b"        run: cargo fetch\n",
            expected_count=2,
        ),
        "cache-insertion": _replace_once(
            runner_raw,
            checkout_line,
            checkout_line + b"        uses: actions/cache@v4\n",
            expected_count=6,
        ),
    }


def check_runner_workflow(path: pathlib.Path) -> None:
    runner_raw = _read_regular_file(path)
    uses = _validate_runner_workflow(runner_raw)
    survived: list[str] = []
    mutations = _runner_mutations(runner_raw)
    for name, mutation in mutations.items():
        try:
            _validate_runner_workflow(
                mutation, expected_digest=hashlib.sha256(mutation).hexdigest()
            )
        except ContractError:
            continue
        survived.append(name)
    if survived:
        raise ContractError(f"runner workflow mutations survived: {','.join(survived)}")
    source_raw = _read_regular_file(pathlib.Path(__file__))
    print(
        "phase285_exact_subject_workflow "
        f"parser_sha256={hashlib.sha256(source_raw).hexdigest()} "
        f"workflow_sha256={hashlib.sha256(runner_raw).hexdigest()} "
        f"uses={uses} mutations={len(mutations)} "
        f"digest_rebased_mutations={len(mutations)} passed=1"
    )


def _usage() -> str:
    return (
        "usage: phase285_exact_subject_parser.py --self-test | "
        "extract WORKFLOW OUTPUT | check-runner-workflow WORKFLOW"
    )


def main(arguments: list[str]) -> int:
    try:
        if arguments == ["--self-test"]:
            run_self_test()
            return 0
        if len(arguments) == 3 and arguments[0] == "extract":
            run_self_test()
            script = extract_monolith(_read_regular_file(pathlib.Path(arguments[1])))
            output = pathlib.Path(arguments[2])
            _write_new_regular_file(output, script)
            print(
                "phase285_exact_subject_monolith "
                f"sha256={hashlib.sha256(script).hexdigest()} bytes={len(script)} passed=1"
            )
            return 0
        if len(arguments) == 2 and arguments[0] == "check-runner-workflow":
            run_self_test()
            check_runner_workflow(pathlib.Path(arguments[1]))
            return 0
        raise ContractError(_usage())
    except (ContractError, OSError) as error:
        print(f"phase285_exact_subject_parser: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
