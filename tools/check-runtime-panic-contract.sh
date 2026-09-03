#!/usr/bin/env bash
#
# Runtime panic contract scanner.
#
# WHAT IS COVERED
#   Production (non-cfg(test)) code in every engine crate (`crates/*/src`) and in
#   every ENROLLED chat-workspace crate (the `ENROLLED_WORKSPACE_CRATE_SRCS`
#   list below; today `workspace/crates/ambush-ws-client/src`, the NIP-42 client
#   the swarm bridge links in -- 00-DECISIONS W3-6, ADR 0015 C6), both `.rs` and
#   `.inc` files. A crate the daemon links runs under its `panic = "abort"`, so
#   its production code is held to the same contract. An enrolled root that does
#   not exist is a failure, not an empty scan. String literals, char literals,
#   raw strings and comments are stripped before matching, so `"...unwrap(..."`
#   in a message does not count.
#
# WHAT IS NOT COVERED (deliberately)
#   - `crates/*/tests/` integration test crates, `benches/`, `examples/`,
#     `build.rs` and `vendor/reference/`. Those are not the live-response lane.
#   - Macro-generated code. The scan is textual; a panic introduced by a macro
#     expansion is invisible to it.
#   - `panic!`, `todo!`, `unimplemented!`, `unreachable!`, `assert*!`, slice
#     indexing (`v[i]`), integer division and arithmetic overflow. The scanner
#     matches ONLY `.unwrap(` and `.expect(`. Those other panic sources are the
#     job of review and of clippy, not of this script.
#
# HOW TEST CODE IS IDENTIFIED
#   Two structural signals, no filename heuristics:
#     1. A file declared by a `cfg(test)`-gated `mod NAME;` (honouring an
#        intervening `#[path = "..."]`), and
#     2. A file named by an `include!("...")` whose OWN offset falls inside a
#        `cfg(test)` item span that the sanitizer blanked.
#   Everything else is treated as production code and IS scanned.
#
#   Signal 2 must NOT be implemented by re-matching `include!("...")` against the
#   sanitized text. The sanitizer blanks EVERY string literal unconditionally, so
#   `include!("x.rs")` sanitizes to `include!(       )` in production code exactly
#   as in test code: the path literal is gone either way, the re-match never
#   succeeds, and the classifier calls every include in the tree test-only. That
#   is a silent-unscan, and it is what the first phase-280 cut of this script did.
#   Classification is therefore driven by the recorded `cfg(test)` item spans, and
#   the self-test below covers BOTH directions.
#
# SELF-TEST
#   Every invocation first runs `run_self_test()` against synthetic crate trees in
#   a temp dir. Each case is the SAME `.unwrap()` moved between contexts, so a
#   classifier that ignores context cannot pass all of them. If any case fails the
#   script exits 1 without scanning: a broken classifier is a broken gate, not a
#   green one.
#
#   This replaced a `path.name != "tests.rs"` filename heuristic that reported
#   428 false positives, because `crates/swarm-runtime/src/mutation.rs` gates its
#   test modules from the PARENT (`#[cfg(test)] #[path = "..."] mod X;`) and
#   `crates/swarm-runtime/src/service/mod.rs` pulls its test files in via
#   `include!()` from inside a `#[cfg(test)] mod tests` block. A file wrongly
#   classified as test-only is SILENTLY UNSCANNED, so this classification is the
#   most safety-critical part of the script; see the three mutation checks in the
#   phase 280 commit message for how it is falsified.
#
# CFG PREDICATES
#   `test` is recognised anywhere it appears as a bare predicate inside `cfg(..)`
#   -- `#[cfg(test)]`, `#[cfg(all(test, feature = "nats"))]`, `#[cfg(any(test,
#   ...))]`. `not(...)` groups are stripped first, so `#[cfg(not(test))]` marks
#   PRODUCTION code and is still scanned.
#
# EXCEPTION MARKER
#   A production `.unwrap(`/`.expect(` may be kept by putting
#       // SAFETY: runtime panic contract exception -- <why it cannot fail>
#   on the line above it (blank lines are skipped, up to 3 lines back). The marker
#   must be the NEAREST non-blank line above the call, so put the justification on
#   the marker line itself or on lines above it, not between it and the call. The
#   marker means "a human established this cannot fail"; it is not a mute button.
#   Exceptions are counted and reported on the OK line.
#
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from __future__ import annotations

import pathlib
import re
import sys
import tempfile

ALLOWED_MARKER = "SAFETY: runtime panic contract exception"
PANIC_CALL = re.compile(r"\.(unwrap|expect)\s*\(")
CFG_ATTR_START = re.compile(r"#\s*\[\s*cfg\s*\(", re.S)
NOT_GROUP = re.compile(r"\bnot\s*\(")
BARE_TEST = re.compile(r"(?:^|[(,\s])test\s*(?:[,)]|$)")
MOD_DECL = re.compile(
    r"(?P<attrs>(?:#\s*\[[^\]]*\]\s*)*)\b(?:pub\s*(?:\([^)]*\)\s*)?)?mod\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
    re.S,
)
INCLUDE_MACRO = re.compile(r"include!\s*\(\s*\"(?P<path>[^\"]+)\"\s*,?\s*\)")
PATH_ATTR = re.compile(r"#\s*\[\s*path\s*=\s*\"(?P<path>[^\"]+)\"\s*\]", re.S)


def _strip_not_groups(text: str) -> str:
    """Remove balanced `not(...)` groups so `cfg(not(test))` is not seen as test."""
    while True:
        match = NOT_GROUP.search(text)
        if not match:
            return text
        depth = 1
        index = match.end()
        while index < len(text) and depth:
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
            index += 1
        text = text[: match.start()] + " " + text[index:]


def match_cfg_test_attr(text: str, index: int):
    """Match `#[cfg(..)]` at `index` when `test` is a bare predicate inside it.

    Returns the end offset of the attribute, or None.
    """
    match = CFG_ATTR_START.match(text, index)
    if not match:
        return None
    depth = 1
    cursor = match.end()
    while cursor < len(text) and depth:
        if text[cursor] == "(":
            depth += 1
        elif text[cursor] == ")":
            depth -= 1
        cursor += 1
    if depth:
        return None
    predicate = text[match.end() : cursor - 1]
    close = cursor
    while close < len(text) and text[close].isspace():
        close += 1
    if close >= len(text) or text[close] != "]":
        return None
    if not BARE_TEST.search(_strip_not_groups(predicate)):
        return None
    return close + 1


def blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] != "\n":
            chars[index] = " "


def consume_line_comment(text: str, start: int) -> int:
    index = start + 2
    while index < len(text) and text[index] != "\n":
        index += 1
    return index


def consume_block_comment(text: str, start: int) -> int:
    depth = 1
    index = start + 2
    while index < len(text) and depth > 0:
        if text.startswith("/*", index):
            depth += 1
            index += 2
        elif text.startswith("*/", index):
            depth -= 1
            index += 2
        else:
            index += 1
    return index


def consume_quoted(text: str, start: int, quote: str) -> int:
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index + 1
        index += 1
    return index


def consume_char_literal(text: str, start: int) -> int | None:
    if text[start] != "'":
        return None

    index = start + 1
    if index >= len(text) or text[index] in {"\n", "\r", "'"}:
        return None

    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "'":
            return index + 1
        elif char in {"\n", "\r"}:
            return None
        index += 1

    return None


def consume_raw_string(text: str, start: int) -> int | None:
    prefix_len = 0
    if text.startswith("br", start):
        prefix_len = 2
    elif text.startswith("r", start):
        prefix_len = 1
    else:
        return None

    index = start + prefix_len
    while index < len(text) and text[index] == "#":
        index += 1
    if index >= len(text) or text[index] != '"':
        return None

    hashes = index - (start + prefix_len)
    terminator = '"' + ("#" * hashes)
    end = text.find(terminator, index + 1)
    if end == -1:
        return len(text)
    return end + len(terminator)


def skip_whitespace_and_comments(text: str, start: int) -> int:
    index = start
    while index < len(text):
        if text[index].isspace():
            index += 1
        elif text.startswith("//", index):
            index = consume_line_comment(text, index)
        elif text.startswith("/*", index):
            index = consume_block_comment(text, index)
        else:
            return index
    return index


def skip_cfg_test_item(text: str, start: int) -> int:
    index = skip_whitespace_and_comments(text, start)
    paren_depth = 0
    bracket_depth = 0
    angle_depth = 0
    brace_depth = 0
    saw_body = False

    while index < len(text):
        raw_end = consume_raw_string(text, index)
        if raw_end is not None:
            index = raw_end
            continue
        if text.startswith("//", index):
            index = consume_line_comment(text, index)
            continue
        if text.startswith("/*", index):
            index = consume_block_comment(text, index)
            continue
        if text.startswith('b"', index):
            index = consume_quoted(text, index + 1, '"')
            continue
        if text.startswith("b'", index):
            char_end = consume_char_literal(text, index + 1)
            if char_end is not None:
                index = char_end
                continue
        if text[index] == '"':
            index = consume_quoted(text, index, '"')
            continue
        char_end = consume_char_literal(text, index)
        if char_end is not None:
            index = char_end
            continue

        char = text[index]
        if not saw_body:
            if char == "(":
                paren_depth += 1
            elif char == ")" and paren_depth > 0:
                paren_depth -= 1
            elif char == "[":
                bracket_depth += 1
            elif char == "]" and bracket_depth > 0:
                bracket_depth -= 1
            elif char == "<":
                angle_depth += 1
            elif char == ">" and angle_depth > 0:
                angle_depth -= 1
            elif char == "{" and paren_depth == 0 and bracket_depth == 0 and angle_depth == 0:
                saw_body = True
                brace_depth = 1
            elif (
                char in ";,"
                and paren_depth == 0
                and bracket_depth == 0
                and angle_depth == 0
            ):
                return index + 1
            index += 1
            continue

        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            index += 1
            if brace_depth == 0:
                return index
            continue
        index += 1

    return index


def scan_runtime_source(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Blank comments, literals and `cfg(test)` items.

    Returns the sanitized text AND the half-open offset span of every `cfg(test)`
    item that was blanked. The spans are what classifies an `include!`; the
    sanitized TEXT cannot, because string literals are blanked unconditionally
    and so an include's path literal disappears whether or not it was test-gated.
    """
    chars = list(text)
    cfg_test_spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        cfg_end = match_cfg_test_attr(text, index)
        if cfg_end is not None:
            blank(chars, index, cfg_end)
            item_end = skip_cfg_test_item(text, cfg_end)
            blank(chars, cfg_end, item_end)
            cfg_test_spans.append((index, item_end))
            index = item_end
            continue

        raw_end = consume_raw_string(text, index)
        if raw_end is not None:
            blank(chars, index, raw_end)
            index = raw_end
            continue
        if text.startswith("//", index):
            end = consume_line_comment(text, index)
            blank(chars, index, end)
            index = end
            continue
        if text.startswith("/*", index):
            end = consume_block_comment(text, index)
            blank(chars, index, end)
            index = end
            continue
        if text.startswith('b"', index):
            end = consume_quoted(text, index + 1, '"')
            blank(chars, index, end)
            index = end
            continue
        if text.startswith("b'", index):
            end = consume_char_literal(text, index + 1)
            if end is not None:
                blank(chars, index, end)
                index = end
                continue
        if text[index] == '"':
            end = consume_quoted(text, index, '"')
            blank(chars, index, end)
            index = end
            continue
        end = consume_char_literal(text, index)
        if end is not None:
            blank(chars, index, end)
            index = end
            continue

        index += 1

    return "".join(chars), cfg_test_spans


def sanitize_runtime_source(text: str) -> str:
    return scan_runtime_source(text)[0]


def has_allowed_marker(lines: list[str], line_number: int) -> bool:
    """True when the marker is the nearest non-blank line ABOVE the call site.

    `line_number` is 1-based and `lines` is 0-based, so the call site itself is
    `lines[line_number - 1]` and the line above it is `lines[line_number - 2]`.
    Starting the walk at `line_number - 1` inspected the CALL LINE first; a line
    holding a `.unwrap(`/`.expect(` is never blank, so the loop returned on its
    first iteration and this function could never return True. The marker was
    unimplementable and the `allowed` reporting branch was dead code.
    """
    for index in range(line_number - 2, max(-1, line_number - 5), -1):
        stripped = lines[index].strip()
        if not stripped:
            continue
        return stripped.startswith(f"// {ALLOWED_MARKER}")
    return False


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def module_file_candidates(declaring: pathlib.Path, name: str) -> list[pathlib.Path]:
    """Resolve a plain `mod NAME;` the way rustc would, from `declaring`."""
    if declaring.name in {"lib.rs", "main.rs", "mod.rs"}:
        base = declaring.parent
    else:
        base = declaring.parent / declaring.stem
    return [base / f"{name}.rs", base / name / "mod.rs"]


def test_only_files(files: list[pathlib.Path]) -> set[pathlib.Path]:
    """Files that only exist under `cfg(test)`, found structurally.

    Signal 1: declared by a `cfg(test)`-gated `mod NAME;` (honouring `#[path]`).
    Signal 2: named by an `include!("...")` whose own offset lies inside one of
              the `cfg(test)` item spans the sanitizer blanked.

    A file wrongly listed here is silently unscanned, so both signals are
    structural: neither looks at the file's name.
    """
    resolved: set[pathlib.Path] = set()
    for path in files:
        source = path.read_text(encoding="utf-8")
        sanitized, cfg_test_spans = scan_runtime_source(source)

        for match in MOD_DECL.finditer(source):
            attrs = match.group("attrs")
            if match_cfg_test_attr(attrs.strip(), 0) is None and not any(
                match_cfg_test_attr(attrs, offset) is not None
                for offset in range(len(attrs))
            ):
                continue
            path_attr = PATH_ATTR.search(attrs)
            if path_attr:
                candidates = [path.parent / path_attr.group("path")]
            else:
                candidates = module_file_candidates(path, match.group("name"))
            for candidate in candidates:
                if candidate.is_file():
                    resolved.add(candidate.resolve())

        for match in INCLUDE_MACRO.finditer(source):
            # Classify on the ENCLOSING ITEM, never on the sanitized slice: the
            # sanitizer blanks all string literals, so the path literal is gone
            # from `sanitized[match.start():match.end()]` for production includes
            # too, and any slice-based test calls every include test-only.
            if not any(start <= match.start() < end for start, end in cfg_test_spans):
                continue  # not inside a cfg(test) item => production include
            candidate = path.parent / match.group("path")
            if candidate.is_file():
                resolved.add(candidate.resolve())

    return resolved


SKIPPED_DIR_NAMES = {"tests", "benches", "examples"}
Record = tuple[str, int, str]

# Chat-workspace crate `src` roots enrolled in this contract one by one
# (00-DECISIONS W3-6). The engine's own crates are found by glob; a workspace
# crate joins by being named here, on the commit that removes its last panic
# site. Each root must exist -- a missing one is a failed gate, never a silent
# no-op scan (see REFUSING TO PASS SILENTLY in check-gates-wired.sh).
ENROLLED_WORKSPACE_CRATE_SRCS: list[pathlib.Path] = [
    pathlib.Path("workspace/crates/ambush-ws-client/src"),
]


def crate_src_files(crate_src: pathlib.Path) -> list[pathlib.Path]:
    """Every `.rs`/`.inc` under one crate `src` root, minus the skipped dirs."""
    found: list[pathlib.Path] = []
    for path in crate_src.rglob("*"):
        if not path.is_file() or path.suffix not in {".rs", ".inc"}:
            continue
        if SKIPPED_DIR_NAMES & set(path.relative_to(crate_src).parts):
            continue
        found.append(path)
    return found


def production_files(
    crates_root: pathlib.Path,
    enrolled_srcs: list[pathlib.Path] = (),
) -> list[pathlib.Path]:
    """Every `.rs`/`.inc` under `<crates_root>/*/src` plus each enrolled root."""
    found: list[pathlib.Path] = []
    for crate_src in sorted(crates_root.glob("*/src")):
        found.extend(crate_src_files(crate_src))
    for crate_src in enrolled_srcs:
        if not crate_src.is_dir():
            print(
                f"runtime panic contract: enrolled crate root {crate_src} does not "
                "exist; refusing to pass silently",
                file=sys.stderr,
            )
            sys.exit(1)
        found.extend(crate_src_files(crate_src))
    return sorted(found)


def collect(files: list[pathlib.Path]) -> tuple[list[Record], list[Record]]:
    """Split every production `.unwrap(`/`.expect(` into (violations, allowed)."""
    violations: list[Record] = []
    allowed: list[Record] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        sanitized = sanitize_runtime_source(source)
        lines = source.splitlines()
        for match in PANIC_CALL.finditer(sanitized):
            line_number = line_number_for_offset(source, match.start())
            call = f".{match.group(1)}("
            record = (path.as_posix(), line_number, call)
            if has_allowed_marker(lines, line_number):
                allowed.append(record)
            else:
                violations.append(record)
    return violations, allowed


def scan_tree(crates_root: pathlib.Path, enrolled_srcs: list[pathlib.Path] = ()):
    """Classify, exclude, then scan. Returns (scanned, excluded, viol, allowed)."""
    files = production_files(crates_root, enrolled_srcs)
    excluded = test_only_files(files)
    scanned = [path for path in files if path.resolve() not in excluded]
    violations, allowed = collect(scanned)
    return scanned, excluded, violations, allowed


PANIC_BODY = "pub fn probe() -> u32 {\n    Some(1u32).unwrap()\n}\n"

# Each case is the SAME `.unwrap()` moved between contexts. `expect` counts are
# (scanned files, excluded files, violations, allowed).
SELF_TEST_CASES: list[tuple[str, dict[str, str], tuple[int, int, int, int]]] = [
    (
        "include! from PRODUCTION lib.rs is scanned",
        {
            "crates/probe/src/lib.rs": 'include!("probe.rs");\n',
            "crates/probe/src/probe.rs": PANIC_BODY,
        },
        (2, 0, 1, 0),
    ),
    (
        "include! from inside `#[cfg(test)] mod tests` is excluded",
        {
            "crates/probe/src/lib.rs": (
                "#[cfg(test)]\nmod tests {\n    include!(\"probe.rs\");\n}\n"
            ),
            "crates/probe/src/probe.rs": PANIC_BODY,
        },
        (1, 1, 0, 0),
    ),
    (
        "`#[cfg(test)] #[path] mod` is excluded",
        {
            "crates/probe/src/lib.rs": (
                '#[cfg(test)]\n#[path = "probe.rs"]\nmod probe_tests;\n'
            ),
            "crates/probe/src/probe.rs": PANIC_BODY,
        },
        (1, 1, 0, 0),
    ),
    (
        "`#[cfg(not(test))]` is production and is scanned",
        {
            "crates/probe/src/lib.rs": "#[cfg(not(test))]\n" + PANIC_BODY,
        },
        (1, 0, 1, 0),
    ),
    (
        "marker on the line directly above is an allowed exception",
        {
            "crates/probe/src/lib.rs": (
                "pub fn probe() -> u32 {\n"
                f"    // {ALLOWED_MARKER} -- literal Some, cannot be None\n"
                "    Some(1u32).unwrap()\n"
                "}\n"
            ),
        },
        (1, 0, 0, 1),
    ),
    (
        "marker still counts across a blank line",
        {
            "crates/probe/src/lib.rs": (
                "pub fn probe() -> u32 {\n"
                f"    // {ALLOWED_MARKER} -- literal Some, cannot be None\n"
                "\n"
                "    Some(1u32).unwrap()\n"
                "}\n"
            ),
        },
        (1, 0, 0, 1),
    ),
    (
        "a non-marker comment above the call does NOT excuse it",
        {
            "crates/probe/src/lib.rs": (
                "pub fn probe() -> u32 {\n"
                "    // this is fine, trust me\n"
                "    Some(1u32).unwrap()\n"
                "}\n"
            ),
        },
        (1, 0, 1, 0),
    ),
    (
        "marker further than 3 lines back does NOT excuse the call",
        {
            "crates/probe/src/lib.rs": (
                "pub fn probe() -> u32 {\n"
                f"    // {ALLOWED_MARKER} -- stale, four lines up\n"
                "    let a = 1u32;\n"
                "    let b = a;\n"
                "    let c = Some(b);\n"
                "    c.unwrap()\n"
                "}\n"
            ),
        },
        (1, 0, 1, 0),
    ),
]


def run_self_test() -> None:
    for name, tree, expected in SELF_TEST_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for relative, body in tree.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")
            scanned, excluded, violations, allowed = scan_tree(root / "crates")
            actual = (len(scanned), len(excluded), len(violations), len(allowed))
        if actual != expected:
            print(
                f"runtime panic contract SELF-TEST FAILED: {name}\n"
                f"  expected (scanned, excluded, violations, allowed) = {expected}\n"
                f"  actual   (scanned, excluded, violations, allowed) = {actual}",
                file=sys.stderr,
            )
            sys.exit(1)


run_self_test()

files, excluded, violations, allowed = scan_tree(
    pathlib.Path("crates"), ENROLLED_WORKSPACE_CRATE_SRCS
)

if violations:
    print("runtime panic contract violation(s) detected:", file=sys.stderr)
    for path, line_number, call in violations:
        print(f"- {path}:{line_number} uses {call}", file=sys.stderr)
    print(
        f"Allowed exception marker: // {ALLOWED_MARKER}",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"runtime panic contract self-test: {len(SELF_TEST_CASES)} case(s) passed")

enrolled = ", ".join(root.as_posix() for root in ENROLLED_WORKSPACE_CRATE_SRCS)
scanned = f"{len(files)} production file(s) across crates/*/src + {enrolled}"
if allowed:
    print(
        f"runtime panic contract OK: 0 live violations, "
        f"{len(allowed)} explicit exception(s); scanned {scanned}, "
        f"{len(excluded)} test-only module file(s) excluded"
    )
else:
    print(
        f"runtime panic contract OK: 0 live unwrap()/expect() sites; "
        f"scanned {scanned}, {len(excluded)} test-only module file(s) excluded"
    )
PY
