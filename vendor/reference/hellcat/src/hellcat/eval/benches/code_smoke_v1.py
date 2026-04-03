"""
Code Smoke Bench v1.

Small, fast unit-level tasks intended to exercise the full Hellcat loop:
issue -> workcell -> adapter -> gates -> rollout -> archive.
"""

from __future__ import annotations

from typing import Any


def _case(
    *,
    case_id: str,
    title: str,
    test_k: str,
    description: str,
    estimated_tokens: int = 2500,
) -> dict[str, Any]:
    return {
        "id": case_id,
        "title": title,
        "description": description.strip() + "\n",
        "acceptance_criteria": [
            f"Tests pass: `pytest kernel/benchmarks/code_smoke_v1/tests -q -k {test_k}`",
        ],
        "context_files": [
            "kernel/benchmarks/code_smoke_v1/tasks.py",
            "kernel/benchmarks/code_smoke_v1/tests/test_cases.py",
        ],
        "tags": ["bench", "bench:code_smoke_v1"],
        "dk_estimated_tokens": estimated_tokens,
        "dk_max_attempts": 1,
        "dk_apply_patch": False,
        "quality_gates": {
            "test": f"pytest kernel/benchmarks/code_smoke_v1/tests -q -k {test_k}",
        },
    }


BENCH: dict[str, Any] = {
    "schema_version": "hellcat.bench.v1",
    "name": "code_smoke_v1",
    "domain": "code",
    "cases": [
        _case(
            case_id="cs01",
            title="code_smoke_v1: add_ints",
            test_k="test_case_01_add_ints",
            description="""
Implement `add_ints(a: int, b: int) -> int` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Keep it simple and pure (no I/O).
""",
        ),
        _case(
            case_id="cs02",
            title="code_smoke_v1: clamp_int",
            test_k="test_case_02_clamp_int",
            description="""
Implement `clamp_int(value: int, low: int, high: int) -> int` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
If `low > high`, raise `ValueError`.
""",
        ),
        _case(
            case_id="cs03",
            title="code_smoke_v1: normalize_whitespace",
            test_k="test_case_03_normalize_whitespace",
            description="""
Implement `normalize_whitespace(text: str) -> str` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Collapse all whitespace runs to a single space and strip leading/trailing whitespace.
""",
        ),
        _case(
            case_id="cs04",
            title="code_smoke_v1: slugify",
            test_k="test_case_04_slugify",
            description="""
Implement `slugify(text: str) -> str` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Lowercase, replace runs of non-alphanumerics with `-`, and strip `-` at ends.
""",
        ),
        _case(
            case_id="cs05",
            title="code_smoke_v1: parse_kv_pairs",
            test_k="test_case_05_parse_kv_pairs",
            description="""
Implement `parse_kv_pairs(text: str) -> dict[str, str]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Accept comma-separated `k=v` pairs; ignore empty segments; strip whitespace.
Raise `ValueError` for malformed segments (missing `=`).
""",
        ),
        _case(
            case_id="cs06",
            title="code_smoke_v1: safe_divide",
            test_k="test_case_06_safe_divide",
            description="""
Implement `safe_divide(a: float, b: float) -> float | None` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Return `None` when dividing by zero.
""",
        ),
        _case(
            case_id="cs07",
            title="code_smoke_v1: chunk_list",
            test_k="test_case_07_chunk_list",
            description="""
Implement `chunk_list(items: list[int], size: int) -> list[list[int]]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
`size` must be positive (raise `ValueError` otherwise).
""",
        ),
        _case(
            case_id="cs08",
            title="code_smoke_v1: unique_preserve_order",
            test_k="test_case_08_unique_preserve_order",
            description="""
Implement `unique_preserve_order(items: list[str]) -> list[str]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Keep first occurrences, preserve original order.
""",
        ),
        _case(
            case_id="cs09",
            title="code_smoke_v1: is_valid_email_basic",
            test_k="test_case_09_is_valid_email_basic",
            description="""
Implement `is_valid_email_basic(email: str) -> bool` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Basic validation only (no RFC): exactly one `@`, non-empty local/domain, and domain contains a dot.
""",
        ),
        _case(
            case_id="cs10",
            title="code_smoke_v1: format_bytes",
            test_k="test_case_10_format_bytes",
            description="""
Implement `format_bytes(num_bytes: int) -> str` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Use binary units (KiB, MiB, GiB). Round to 1 decimal, but show no decimals for exact values.
""",
        ),
        _case(
            case_id="cs11",
            title="code_smoke_v1: parse_csv_line",
            test_k="test_case_11_parse_csv_line",
            description="""
Implement `parse_csv_line(line: str) -> list[str]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Support simple CSV with commas and double-quote escaping of commas/quotes ("" -> ").
""",
        ),
        _case(
            case_id="cs12",
            title="code_smoke_v1: median_ints",
            test_k="test_case_12_median_ints",
            description="""
Implement `median_ints(values: list[int]) -> float` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Raise `ValueError` for empty input.
""",
        ),
        _case(
            case_id="cs13",
            title="code_smoke_v1: rolling_sum",
            test_k="test_case_13_rolling_sum",
            description="""
Implement `rolling_sum(values: list[int]) -> list[int]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Return prefix sums of the list.
""",
        ),
        _case(
            case_id="cs14",
            title="code_smoke_v1: coalesce",
            test_k="test_case_14_coalesce",
            description="""
Implement `coalesce(*values: object) -> object | None` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Return the first value that is not `None`, else `None`.
""",
        ),
        _case(
            case_id="cs15",
            title="code_smoke_v1: invert_dict_unique",
            test_k="test_case_15_invert_dict_unique",
            description="""
Implement `invert_dict_unique(mapping: dict[str, str]) -> dict[str, str]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Invert key/value pairs, but raise `ValueError` if values are not unique.
""",
        ),
        _case(
            case_id="cs16",
            title="code_smoke_v1: json_pointer_get",
            test_k="test_case_16_json_pointer_get",
            description="""
Implement `json_pointer_get(obj: object, pointer: str) -> object` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Support a minimal JSON Pointer: `/a/b/0`. Raise `KeyError` on missing path.
""",
        ),
        _case(
            case_id="cs17",
            title="code_smoke_v1: stable_sort_by_key",
            test_k="test_case_17_stable_sort_by_key",
            description="""
Implement `stable_sort_by_key(items: list[dict[str, int]], key: str) -> list[dict[str, int]]` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Stable sort ascending by the given key; raise `KeyError` if any item lacks the key.
""",
        ),
        _case(
            case_id="cs18",
            title="code_smoke_v1: parse_duration_seconds",
            test_k="test_case_18_parse_duration_seconds",
            description="""
Implement `parse_duration_seconds(text: str) -> int` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Accept forms like `10s`, `5m`, `2h` and return seconds. Raise `ValueError` otherwise.
""",
        ),
        _case(
            case_id="cs19",
            title="code_smoke_v1: redact_secrets",
            test_k="test_case_19_redact_secrets",
            description="""
Implement `redact_secrets(text: str, secrets: list[str]) -> str` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Replace exact secret substrings with `***` (if secret is empty, ignore it).
""",
        ),
        _case(
            case_id="cs20",
            title="code_smoke_v1: longest_common_prefix",
            test_k="test_case_20_longest_common_prefix",
            description="""
Implement `longest_common_prefix(values: list[str]) -> str` in `kernel/benchmarks/code_smoke_v1/tasks.py`.
Return empty string for empty input.
""",
        ),
    ],
}


def get_bench() -> dict[str, Any]:
    return BENCH
