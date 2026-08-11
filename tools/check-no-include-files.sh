#!/usr/bin/env bash
#
# Non-.rs Rust source scanner (INCFIX-03).
#
# WHY THIS EXISTS
#   `#[path = "core.inc"] mod core;` pulls a file of real Rust into the crate.
#   rustc, clippy AND rustfmt all follow `#[path]`, so a `.inc` file is compiled,
#   linted, and formatted like any other source. What skips it is every tool that
#   finds code by globbing `*.rs`: rust-analyzer (no editor support -- no
#   go-to-definition, no rename, no inline diagnostics) and every LOC/complexity
#   tool (tokei, scc), which is how one grew to 5,394 lines without appearing in
#   any size measurement. Two tools of four, not three.
#
#   Phase 281's commit messages and an earlier version of this header claimed
#   `.inc` files were "permanently unformatted". That was WRONG and was disproved
#   by a two-sided control: appending a formatting violation to a still-`.inc`
#   file makes `cargo fmt --all -- --check` exit 1, and `rustfmt --check` on the
#   pristine core.inc files exits 0 -- they were already formatted. Recorded here
#   so phases 282 and 283 do not inherit the claim. The gate is worth keeping on
#   the rust-analyzer and LOC-visibility grounds alone.
#
# WHAT IS COVERED
#   Every `.rs` and `.inc` file under `crates/` (any depth: `src/`, `tests/`,
#   `benches/`, `examples/`, `build.rs`), plus a filesystem sweep of `crates/`.
#   Three signals:
#     1. `#[path = "..."]` whose target does not end in `.rs`
#     2. `#[cfg_attr(..., path = "...")]` whose target does not end in `.rs`
#     3. `include!("...")` whose target does not end in `.rs`
#        (`include_str!`/`include_bytes!` are NOT matched: they pull in data,
#        not Rust, and a `.json`/`.txt` payload is not this gate's business.)
#     4. any file under `crates/` named `*.inc` or `*.rs.in`, even when no
#        directive references it -- a file can be committed a commit before the
#        directive that includes it, and signals 1-3 would miss it until then.
#   Targets are resolved relative to the declaring file, so the two directives
#   that name `crates/swarm-cli/src/core.inc` -- one as `"core.inc"`, one as
#   `"../../../swarm-cli/src/core.inc"` -- resolve to the same repo-relative
#   path and are matched against the same single allowlist entry.
#
# WHAT IS NOT COVERED (deliberately)
#   - Rust source outside `crates/`: `vendor/reference/` (archive, not built),
#     `tools/`, and any build script living above the crate roots.
#   - `#[path]` or `include!` produced by a macro expansion. The scan is
#     textual; anything only visible after expansion is invisible to it.
#   - Whether an included file is GOOD Rust. This gate is about the file's name
#     and nothing else -- `cargo clippy` and review own the contents.
#   - A `.rs` file that is included rather than declared (`include!("x.rs")`).
#     That is legal, formattable and analyzable, so it is not a defect here.
#
# STRING AND COMMENT HANDLING
#   Comments are blanked before matching, so `// #[path = "x.inc"]` in a doc
#   block is not a violation. String literals are NOT blanked -- the target path
#   IS a string literal, and blanking it would delete the very thing being
#   checked (the phase-280 panic-contract script shipped exactly that bug once).
#   Instead the scanner RECORDS every string span and discards any directive
#   whose `#[`/`include!` start offset falls inside one, so a directive quoted
#   inside a raw string does not count. Classify on spans, never on a re-match
#   of sanitized text.
#
# DEFERRED EXCEPTION
#   `crates/swarm-cli/src/core.inc` is allowlisted by exact path, once, below.
#   It is NOT a pattern: a new `.inc` anywhere -- including a
#   `crates/swarm-cli/src/other.inc` right beside it -- still fails. The entry
#   is dated and must be deleted when phase 282 lands. A stale entry (the file
#   no longer exists) is itself a failure, so the allowlist cannot outlive the
#   exception it documents.
#
# SELF-TEST
#   Every invocation first runs `run_self_test()` over synthetic trees in a temp
#   dir, covering both directions: a new `.inc` must fail, an allowlisted one
#   must pass, a commented-out or string-quoted directive must not fire, and a
#   stale allowlist entry must fail. If any case fails the script exits 1
#   without scanning: a broken gate is not a green gate.
#
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 - <<'PY'
from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile

# ---------------------------------------------------------------------------
# Allowlist: EXACT repo-relative paths, never patterns.
#
# 2026-08-11 -- phase 281 / INCFIX-03. crates/swarm-cli/src/core.inc is 5,394
# lines of Rust included by TWO crates (crates/swarm-cli/src/lib.rs:79 and
# crates/swarm-runtime/src/cli/mod.rs:1, the latter reaching across the
# workspace with `../../../`). Splitting a file with two owners is a different
# and larger change than the three single-owner files phase 281 converted, so
# the human scoped it out to phase 282.
#
# DELETE THIS ENTRY WHEN PHASE 282 LANDS. It is not "the .inc exception", it is
# "this one file, until this one ticket"; the stale-entry check below fails the
# build if the file disappears and the entry stays.
# ---------------------------------------------------------------------------
DEFERRED_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "crates/swarm-cli/src/core.inc",
    }
)

# Names that mean "Rust source wearing a non-.rs extension".
NON_RS_SOURCE_SUFFIXES = (".inc", ".rs.in")

SCANNED_SUFFIXES = (".rs", ".inc")
SKIPPED_DIR_NAMES = {"target", ".git"}

PATH_ATTR = re.compile(r"#\s*\[\s*path\s*=\s*\"(?P<path>[^\"]*)\"\s*\]", re.S)
CFG_ATTR = re.compile(r"#\s*\[\s*cfg_attr\s*\(", re.S)
CFG_ATTR_PATH = re.compile(r"\bpath\s*=\s*\"(?P<path>[^\"]*)\"", re.S)
# `include!` only. `include_str!`/`include_bytes!` cannot match: the `!` must
# follow "include" immediately.
INCLUDE_MACRO = re.compile(r"\binclude!\s*\(\s*\"(?P<path>[^\"]*)\"\s*,?\s*\)", re.S)


def _consume_line_comment(text: str, start: int) -> int:
    index = start + 2
    while index < len(text) and text[index] != "\n":
        index += 1
    return index


def _consume_block_comment(text: str, start: int) -> int:
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


def _consume_quoted(text: str, start: int) -> int:
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index + 1
        index += 1
    return index


def _consume_raw_string(text: str, start: int) -> int | None:
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


def _consume_char_literal(text: str, start: int) -> int | None:
    """Consume `'x'`. Returns None for a lifetime (`'a`), which never closes."""
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


def strip_comments(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Blank comments; keep string literals and record their spans.

    Offsets and line numbers are preserved: blanked characters become spaces and
    newlines survive. String CONTENT survives because the directive target being
    checked lives inside a string literal -- blanking it would erase the check.
    The returned spans are how a directive quoted inside a raw string is
    discarded, since a re-match against the returned text cannot tell the two
    apart.
    """
    chars = list(text)
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(text):
        raw_end = _consume_raw_string(text, index)
        if raw_end is not None:
            spans.append((index, raw_end))
            index = raw_end
            continue
        if text.startswith("//", index):
            end = _consume_line_comment(text, index)
            for offset in range(index, end):
                chars[offset] = " "
            index = end
            continue
        if text.startswith("/*", index):
            end = _consume_block_comment(text, index)
            for offset in range(index, end):
                if chars[offset] != "\n":
                    chars[offset] = " "
            index = end
            continue
        if text.startswith('b"', index):
            end = _consume_quoted(text, index + 1)
            spans.append((index, end))
            index = end
            continue
        if text[index] == '"':
            end = _consume_quoted(text, index)
            spans.append((index, end))
            index = end
            continue
        char_end = _consume_char_literal(text, index)
        if char_end is not None:
            spans.append((index, char_end))
            index = char_end
            continue
        index += 1
    return "".join(chars), spans


def inside_any(spans: list[tuple[int, int]], offset: int) -> bool:
    return any(start <= offset < end for start, end in spans)


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def source_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every `.rs`/`.inc` under `crates/`, at any depth."""
    crates = root / "crates"
    if not crates.is_dir():
        return []
    found: list[pathlib.Path] = []
    for path in crates.rglob("*"):
        if not path.is_file():
            continue
        if SKIPPED_DIR_NAMES & set(path.relative_to(crates).parts):
            continue
        if path.name.endswith(SCANNED_SUFFIXES):
            found.append(path)
    return sorted(found)


def non_rs_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every file under `crates/` wearing a non-.rs Rust-source name."""
    crates = root / "crates"
    if not crates.is_dir():
        return []
    found: list[pathlib.Path] = []
    for path in crates.rglob("*"):
        if not path.is_file():
            continue
        if SKIPPED_DIR_NAMES & set(path.relative_to(crates).parts):
            continue
        if path.name.endswith(NON_RS_SOURCE_SUFFIXES):
            found.append(path)
    return sorted(found)


def resolve_target(root: pathlib.Path, declaring: pathlib.Path, target: str) -> str:
    """Repo-relative POSIX path of `target` as rustc would resolve it."""
    joined = (declaring.parent / target).as_posix()
    normalized = pathlib.Path(os.path.normpath(joined))
    try:
        return normalized.relative_to(root).as_posix()
    except ValueError:
        return normalized.as_posix()


def directives(text: str, spans: list[tuple[int, int]]):
    """Yield `(offset, rendered_directive, target)` for each include directive."""
    for match in PATH_ATTR.finditer(text):
        if inside_any(spans, match.start()):
            continue
        yield match.start(), f'#[path = "{match.group("path")}"]', match.group("path")

    for match in CFG_ATTR.finditer(text):
        if inside_any(spans, match.start()):
            continue
        depth = 1
        cursor = match.end()
        while cursor < len(text) and depth:
            if text[cursor] == "(":
                depth += 1
            elif text[cursor] == ")":
                depth -= 1
            cursor += 1
        for inner in CFG_ATTR_PATH.finditer(text[match.end() : cursor]):
            yield (
                match.start(),
                f'#[cfg_attr(..., path = "{inner.group("path")}")]',
                inner.group("path"),
            )

    for match in INCLUDE_MACRO.finditer(text):
        if inside_any(spans, match.start()):
            continue
        yield match.start(), f'include!("{match.group("path")}")', match.group("path")


Violation = tuple[str, str]


def scan_tree(root: pathlib.Path, allowlist: frozenset[str]):
    """Returns (violations, scanned_count, directive_count, stale_exceptions)."""
    violations: list[Violation] = []
    named_by_directive: set[str] = set()
    directive_count = 0

    files = source_files(root)
    for path in files:
        source = path.read_text(encoding="utf-8", errors="replace")
        stripped, spans = strip_comments(source)
        relative = path.relative_to(root).as_posix()
        for offset, rendered, target in directives(stripped, spans):
            directive_count += 1
            if target.endswith(".rs"):
                continue
            resolved = resolve_target(root, path.relative_to(root), target)
            if resolved in allowlist:
                continue
            line = line_number_for_offset(source, offset)
            named_by_directive.add(resolved)
            violations.append(
                (
                    resolved,
                    f"{relative}:{line}: {rendered} includes Rust source that is "
                    f"not a .rs file ({resolved})",
                )
            )

    for path in non_rs_files(root):
        relative = path.relative_to(root).as_posix()
        if relative in allowlist or relative in named_by_directive:
            continue
        violations.append(
            (
                relative,
                f"{relative}: non-.rs Rust source file committed under crates/ "
                f"(no #[path]/include! directive references it yet)",
            )
        )

    stale = sorted(entry for entry in allowlist if not (root / entry).is_file())
    return violations, len(files), directive_count, stale


# ---------------------------------------------------------------------------
# Self-test. Each case is the same `.inc` moved between contexts, so a scanner
# that ignores context cannot pass all of them.
# Expected tuple is (violation count, scanned files, directives, stale entries).
# ---------------------------------------------------------------------------
SelfTestCase = tuple[str, dict[str, str], frozenset[str], tuple[int, int, int, int]]

SELF_TEST_CASES: list[SelfTestCase] = [
    (
        "a plain .rs module tree is clean",
        {
            "crates/probe/src/lib.rs": '#[path = "sub.rs"]\nmod sub;\n',
            "crates/probe/src/sub.rs": "pub fn probe() {}\n",
        },
        frozenset(),
        (0, 2, 1, 0),
    ),
    (
        "a NEW .inc plus its #[path] directive fails",
        {
            "crates/probe/src/lib.rs": '#[path = "core.inc"]\nmod core;\n',
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
        },
        frozenset(),
        (1, 2, 1, 0),
    ),
    (
        "the same .inc passes when allowlisted by exact path",
        {
            "crates/probe/src/lib.rs": '#[path = "core.inc"]\nmod core;\n',
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
        },
        frozenset({"crates/probe/src/core.inc"}),
        (0, 2, 1, 0),
    ),
    (
        "allowlisting one .inc does NOT allow a sibling .inc",
        {
            "crates/probe/src/lib.rs": (
                '#[path = "core.inc"]\nmod core;\n#[path = "other.inc"]\nmod other;\n'
            ),
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
            "crates/probe/src/other.inc": "pub fn other() {}\n",
        },
        frozenset({"crates/probe/src/core.inc"}),
        # 3 scanned: lib.rs plus BOTH .inc files (a .inc can itself hold a
        # directive, so the scanner reads them too).
        (1, 3, 2, 0),
    ),
    (
        "a .inc reached through ../ resolves to the same allowlist entry",
        {
            "crates/probe/src/lib.rs": "pub fn probe() {}\n",
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
            "crates/other/src/lib.rs": (
                '#[path = "../../probe/src/core.inc"]\nmod core;\n'
            ),
        },
        frozenset({"crates/probe/src/core.inc"}),
        (0, 3, 1, 0),
    ),
    (
        "include!(\"x.inc\") fails just like #[path]",
        {
            "crates/probe/src/lib.rs": 'include!("core.inc");\n',
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
        },
        frozenset(),
        (1, 2, 1, 0),
    ),
    (
        "cfg_attr(..., path = \"x.inc\") fails too",
        {
            "crates/probe/src/lib.rs": (
                '#[cfg_attr(test, path = "core.inc")]\nmod core;\n'
            ),
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
        },
        frozenset(),
        (1, 2, 1, 0),
    ),
    (
        "an orphan .inc with no directive at all is still caught",
        {
            "crates/probe/src/lib.rs": "pub fn probe() {}\n",
            "crates/probe/src/core.inc": "pub fn probe() {}\n",
        },
        frozenset(),
        (1, 2, 0, 0),
    ),
    (
        "a commented-out directive is not a violation",
        {
            "crates/probe/src/lib.rs": (
                '// historical: #[path = "core.inc"] mod core;\npub fn probe() {}\n'
            ),
        },
        frozenset(),
        (0, 1, 0, 0),
    ),
    (
        "a directive quoted inside a raw string is not a violation",
        {
            "crates/probe/src/lib.rs": (
                'pub const DOC: &str = r##"#[path = "core.inc"]"##;\n'
            ),
        },
        frozenset(),
        (0, 1, 0, 0),
    ),
    (
        "include_str! of a data file is not a violation",
        {
            "crates/probe/src/lib.rs": (
                'pub const DATA: &str = include_str!("fixture.json");\n'
            ),
            "crates/probe/src/fixture.json": "{}\n",
        },
        frozenset(),
        (0, 1, 0, 0),
    ),
    (
        "a stale allowlist entry (file gone) is itself a failure",
        {
            "crates/probe/src/lib.rs": "pub fn probe() {}\n",
        },
        frozenset({"crates/probe/src/core.inc"}),
        (0, 1, 0, 1),
    ),
]


def run_self_test() -> None:
    for name, tree, allowlist, expected in SELF_TEST_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for relative, body in tree.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(body, encoding="utf-8")
            violations, scanned, directive_count, stale = scan_tree(root, allowlist)
            actual = (len(violations), scanned, directive_count, len(stale))
        if actual != expected:
            print(
                f"include-file gate SELF-TEST FAILED: {name}\n"
                f"  expected (violations, scanned, directives, stale) = {expected}\n"
                f"  actual   (violations, scanned, directives, stale) = {actual}",
                file=sys.stderr,
            )
            sys.exit(1)


run_self_test()

root = pathlib.Path.cwd()
violations, scanned, directive_count, stale = scan_tree(root, DEFERRED_EXCEPTIONS)

if stale:
    print("stale include-file exception(s) in tools/check-no-include-files.sh:", file=sys.stderr)
    for entry in stale:
        print(f"- {entry}: allowlisted, but the file no longer exists", file=sys.stderr)
    print(
        "\nThe exception outlived the file it documents. Delete the entry from "
        "DEFERRED_EXCEPTIONS -- an allowlist nobody prunes is how the next .inc "
        "gets in.",
        file=sys.stderr,
    )
    sys.exit(1)

if violations:
    print("non-.rs Rust source detected under crates/:", file=sys.stderr)
    for _, message in sorted(violations):
        print(f"- {message}", file=sys.stderr)
    print(
        "\nRust source must live in a `.rs` file. rustc, clippy and rustfmt all "
        "follow `#[path]`, but rust-analyzer and every LOC/complexity tool find "
        "code by globbing `*.rs`, so a `.inc` file has no editor support and is "
        "invisible to size and complexity metrics.\n"
        "\nFix: rename the file to `.rs` and either drop the `#[path]` (a plain "
        "`mod name;` next to `name.rs`) or point it at the `.rs` name. Then run "
        "`cargo fmt --all` -- the file has never been formatted, so expect a diff.\n"
        "\nThere is exactly one allowlisted exception "
        "(crates/swarm-cli/src/core.inc, deferred to phase 282). Do not add a "
        "second one without a ticket and a date.",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"include-file gate self-test: {len(SELF_TEST_CASES)} case(s) passed")
print(
    f"no non-.rs Rust source: scanned {scanned} file(s) and {directive_count} "
    f"#[path]/include! directive(s) under crates/, "
    f"{len(DEFERRED_EXCEPTIONS)} dated exception(s) allowlisted "
    f"({', '.join(sorted(DEFERRED_EXCEPTIONS))})"
)
PY
