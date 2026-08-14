"""Small Rust lexical helpers for the phase-285 assurance gates.

This is deliberately not a Rust parser.  It performs the one job the gates need:
remove comments and literals without changing byte offsets, then resolve concrete
function bodies and executable identifier uses from the remaining token stream.
Raw grep cannot make those distinctions and therefore cannot police evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import pathlib
import re


@dataclass(frozen=True)
class LineComment:
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    type_name: str | None
    declaration_start: int
    body_start: int
    body_end: int


def _blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "


def sanitize_rust(text: str) -> tuple[str, list[LineComment]]:
    """Blank comments and string/character literals while preserving offsets."""

    chars = list(text)
    comments: list[LineComment] = []
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            comments.append(LineComment(index, end, text[index + 2 : end]))
            _blank(chars, index, end)
            index = end
            continue

        if text.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth += 1
                    end += 2
                elif text.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            _blank(chars, index, end)
            index = end
            continue

        raw = re.match(r"(?:br|rb|r)(?P<hashes>#{0,255})\"", text[index:])
        if raw:
            terminator = '"' + raw.group("hashes")
            content_start = index + raw.end()
            found = text.find(terminator, content_start)
            end = length if found < 0 else found + len(terminator)
            _blank(chars, index, end)
            index = end
            continue

        prefix = 1 if text.startswith('b"', index) else 0
        if index + prefix < length and text[index + prefix] == '"':
            end = index + prefix + 1
            escaped = False
            while end < length:
                char = text[end]
                end += 1
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    break
            _blank(chars, index, end)
            index = end
            continue

        # Do not erase lifetimes.  A Rust character literal has either one
        # codepoint followed by a quote or an escape followed by a quote.
        if text[index] == "'":
            if index + 2 < length and text[index + 2] == "'":
                end = index + 3
                _blank(chars, index, end)
                index = end
                continue
            if index + 3 < length and text[index + 1] == "\\":
                end_quote = text.find("'", index + 2)
                if end_quote >= 0:
                    end = end_quote + 1
                    _blank(chars, index, end)
                    index = end
                    continue

        index += 1

    return "".join(chars), comments


def matching_brace(text: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _cfg_test_ranges(clean: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    pattern = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")
    for match in pattern.finditer(clean):
        cursor = match.end()
        # Permit additional attributes between cfg(test) and its item.
        while True:
            attribute = re.match(r"\s*#\s*\[[^\]]*\]", clean[cursor:])
            if not attribute:
                break
            cursor += attribute.end()
        opening = clean.find("{", cursor)
        semicolon = clean.find(";", cursor)
        if semicolon >= 0 and (opening < 0 or semicolon < opening):
            ranges.append((match.start(), semicolon + 1))
            continue
        if opening >= 0:
            closing = matching_brace(clean, opening)
            if closing is not None:
                ranges.append((match.start(), closing + 1))
    return ranges


def production_sanitized(text: str) -> tuple[str, list[LineComment]]:
    clean, comments = sanitize_rust(text)
    chars = list(clean)
    excluded = _cfg_test_ranges(clean)
    for start, end in excluded:
        _blank(chars, start, end)
    kept_comments = [
        comment
        for comment in comments
        if not any(start <= comment.start < end for start, end in excluded)
    ]
    return "".join(chars), kept_comments


def _impl_type(header: str) -> str | None:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[<>]", header)
    if not tokens or tokens[0] != "impl":
        return None
    cursor = 1
    if cursor < len(tokens) and tokens[cursor] == "<":
        depth = 1
        cursor += 1
        while cursor < len(tokens) and depth:
            depth += tokens[cursor] == "<"
            depth -= tokens[cursor] == ">"
            cursor += 1
    remainder = tokens[cursor:]
    if "for" in remainder:
        cursor = remainder.index("for") + 1
        remainder = remainder[cursor:]
    for token in remainder:
        if token[:1].isupper():
            return token
    return None


def impl_spans(clean: str) -> list[tuple[int, int, str | None]]:
    spans: list[tuple[int, int, str | None]] = []
    for match in re.finditer(r"\bimpl\b", clean):
        opening = clean.find("{", match.end())
        if opening < 0:
            continue
        closing = matching_brace(clean, opening)
        if closing is None:
            continue
        spans.append((opening, closing, _impl_type(clean[match.start() : opening])))
    return spans


def function_spans(clean: str) -> list[FunctionSpan]:
    implementations = impl_spans(clean)
    spans: list[FunctionSpan] = []
    for match in re.finditer(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^{};]*>)?\s*\(", clean):
        opening = clean.find("{", match.end())
        semicolon = clean.find(";", match.end())
        if opening < 0 or (semicolon >= 0 and semicolon < opening):
            continue
        closing = matching_brace(clean, opening)
        if closing is None:
            continue
        enclosing = [span for span in implementations if span[0] < match.start() < span[1]]
        type_name = min(enclosing, key=lambda span: span[1] - span[0])[2] if enclosing else None
        line_start = clean.rfind("\n", 0, match.start()) + 1
        spans.append(
            FunctionSpan(
                match.group("name"),
                type_name,
                line_start,
                opening,
                closing,
            )
        )
    return spans


def find_function(clean: str, name: str, type_name: str | None) -> FunctionSpan | None:
    candidates = [span for span in function_spans(clean) if span.name == name]
    if type_name is None:
        candidates = [span for span in candidates if span.type_name is None]
    else:
        candidates = [span for span in candidates if span.type_name == type_name]
    return candidates[0] if len(candidates) == 1 else None


def resolve_function(root: pathlib.Path, path_str: str) -> tuple[pathlib.Path, FunctionSpan] | str:
    """Resolve an exact crate::module::[Type::]function path or return a reason."""

    segments = path_str.split("::")
    if len(segments) < 2:
        return f"`{path_str}` is not a crate function path"
    crate_dir = root / "crates" / segments[0].replace("_", "-") / "src"
    if not crate_dir.is_dir():
        return f"crate `{segments[0]}` has no source directory"

    rest = segments[1:]
    module_file: pathlib.Path | None = None
    current = crate_dir
    cursor = 0
    while cursor < len(rest):
        segment = rest[cursor]
        if not (segment[:1].islower() or segment.startswith("_")):
            break
        directory = current / segment
        source = current / f"{segment}.rs"
        if directory.is_dir():
            current = directory
            cursor += 1
            continue
        if source.is_file():
            module_file = source
            cursor += 1
        break
    if module_file is None:
        module_file = current / ("mod.rs" if current != crate_dir else "lib.rs")
    if not module_file.is_file():
        return f"`{path_str}` resolves to missing `{module_file.relative_to(root)}`"

    remaining = rest[cursor:]
    if len(remaining) == 1:
        type_name, fn_name = None, remaining[0]
    elif len(remaining) == 2 and remaining[0][:1].isupper():
        type_name, fn_name = remaining
    else:
        return f"`{path_str}` does not end in function or Type::function"

    source_text = module_file.read_text(encoding="utf-8", errors="replace")
    clean, _ = production_sanitized(source_text)
    span = find_function(clean, fn_name, type_name)
    if span is None:
        target = f"{type_name}::{fn_name}" if type_name else fn_name
        return f"`{module_file.relative_to(root)}` declares no unique production `{target}` body"
    return module_file, span


def test_function(clean: str, name: str) -> FunctionSpan | None:
    span = find_function(clean, name, None)
    if span is None:
        return None
    lines = clean[: span.declaration_start].splitlines()
    adjacent: list[str] = []
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped and not adjacent:
            continue
        if re.fullmatch(r"#\s*\[[^\]]+\]", stripped):
            adjacent.append(stripped)
            continue
        break
    attributes = re.findall(r"#\s*\[\s*([^\]]+)\]", "\n".join(adjacent))
    normalized = {re.sub(r"\s+", "", attribute) for attribute in attributes}
    if not any(value == "test" or value.startswith("tokio::test") for value in normalized):
        return None
    return span


def identifier_defined(clean: str, name: str, excluded: tuple[int, int] | None = None) -> bool:
    chars = list(clean)
    if excluded is not None:
        _blank(chars, excluded[0], excluded[1])
    outside = "".join(chars)
    if re.search(
        r"\b(?:fn|struct|enum|union|trait|type|const|static)\s+" + re.escape(name) + r"\b",
        outside,
    ):
        return True
    # Enum variants: an identifier at the start of a source line followed by a
    # tuple/body/comma/discriminant.  Requiring a real token stream keeps a
    # comment or string from fabricating this evidence.
    return bool(
        re.search(
            r"(?m)^\s*" + re.escape(name) + r"\s*(?:[,({=])",
            outside,
        )
    )


def identifier_used(clean: str, name: str, span: FunctionSpan) -> bool:
    body = clean[span.body_start : span.body_end + 1]
    return bool(re.search(r"\b" + re.escape(name) + r"\b", body))


def enum_variant_defined(
    clean: str,
    evidence: str,
    excluded: tuple[int, int] | None = None,
) -> bool:
    """Resolve exact `Enum::Variant` evidence outside the attributed test."""

    match = re.fullmatch(
        r"(?P<enum>[A-Za-z_][A-Za-z0-9_]*)::(?P<variant>[A-Za-z_][A-Za-z0-9_]*)",
        evidence,
    )
    if match is None:
        return False
    chars = list(clean)
    if excluded is not None:
        _blank(chars, excluded[0], excluded[1])
    outside = "".join(chars)
    declarations = list(
        re.finditer(r"\benum\s+" + re.escape(match.group("enum")) + r"\s*\{", outside)
    )
    if len(declarations) != 1:
        return False
    opening = outside.find("{", declarations[0].start())
    closing = matching_brace(outside, opening)
    if closing is None:
        return False
    body = outside[opening + 1 : closing]
    return bool(
        re.search(
            r"(?m)^\s*" + re.escape(match.group("variant")) + r"\s*(?:[,({=])",
            body,
        )
    )


def mutation_used(clean: str, evidence: str, span: FunctionSpan) -> bool:
    """Require exact enum evidence as an argument to a non-assertion call.

    A bare `let _ = Mutation::RemoveGuard`, or the same path pasted into an
    assertion, is decorative evidence: it does not drive a mirror. Requiring a
    surrounding call/construction is still intentionally lexical, but closes
    the token-presence evasion the assurance review demonstrated.
    """

    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*", evidence
    ):
        return False
    body = clean[span.body_start : span.body_end + 1]
    assertion_calls = {
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
        "matches",
    }
    for occurrence in re.finditer(r"\b" + re.escape(evidence) + r"\b", body):
        stack: list[tuple[int, str | None]] = []
        for index, char in enumerate(body[: occurrence.start()]):
            if char == "(":
                prefix = body[:index]
                caller = re.search(
                    r"(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)!?\s*$",
                    prefix,
                )
                stack.append((index, caller.group(1) if caller else None))
            elif char == ")" and stack:
                stack.pop()
        for _, caller in reversed(stack):
            if caller is not None and caller not in assertion_calls:
                return True
    return False


def next_code_line(clean: str, position: int) -> tuple[int, str] | None:
    cursor = clean.find("\n", position)
    cursor = len(clean) if cursor < 0 else cursor + 1
    while cursor < len(clean):
        end = clean.find("\n", cursor)
        end = len(clean) if end < 0 else end
        line = clean[cursor:end]
        if line.strip():
            statement = line.strip()
            if statement.startswith("let ") and ";" not in statement and "else" not in statement:
                continuation = end + 1
                while continuation < len(clean):
                    next_end = clean.find("\n", continuation)
                    next_end = len(clean) if next_end < 0 else next_end
                    fragment = clean[continuation:next_end].strip()
                    if fragment:
                        statement += " " + fragment
                    if ";" in fragment or "else" in fragment:
                        break
                    continuation = next_end + 1
            return cursor, statement
        cursor = end + 1
    return None


def looks_like_executable_guard(line: str) -> bool:
    """Recognize the decision forms to which an INVARIANT marker may attach."""

    stripped = line.lstrip("}").strip()
    if re.match(r"(?:else\s+)?if\b|else\b|match\b", stripped):
        return True
    if "=>" in stripped:
        return True
    if re.match(r"let\b", stripped) and ("else" in stripped or "?" in stripped):
        return True
    if re.match(r"(?:return\s+)?(?:Err|Ok)\s*\(", stripped):
        return True
    # A Result-propagating call is an executable refusal decision even though
    # Rust spells it with `?` rather than an `if`.
    return "?" in stripped
