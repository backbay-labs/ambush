"""Canonical JSON for hashing/signatures (CCJ v1 / RFC 8785 JCS).

This module implements CCJ v1 (RFC 8785 JSON Canonicalization Scheme) for the
subset of Python values that map cleanly to JSON:

- dict (string keys), list/tuple
- str, int, float, bool, None

It matches ECMAScript `JSON.stringify()` number formatting and string escaping,
so hashes and Ed25519 signatures can verify across Python/Rust/TypeScript.
"""

from __future__ import annotations

import math
from typing import Any


class CanonicalJsonError(ValueError):
    pass


def canonicalize(value: Any) -> str:
    """Return CCJ v1 canonical JSON for `value`."""
    return _canon(value)


def _canon(value: Any) -> str:
    if value is None:
        return "null"

    # bool is a subclass of int in Python; check it first.
    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        return _js_number_string(value)

    if isinstance(value, str):
        return '"' + _escape_json_string(value) + '"'

    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon(v) for v in value) + "]"

    if isinstance(value, dict):
        items: list[str] = []
        for k in sorted(value.keys()):
            if not isinstance(k, str):
                raise CanonicalJsonError("JSON object keys must be strings")
            items.append('"' + _escape_json_string(k) + '":' + _canon(value[k]))
        return "{" + ",".join(items) + "}"

    raise CanonicalJsonError(f"Unsupported type for canonical JSON: {type(value)!r}")


def _escape_json_string(s: str) -> str:
    # JCS aligns with ECMAScript `JSON.stringify()` escaping.
    out: list[str] = []
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x0C:
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code <= 0x1F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _js_number_string(x: float) -> str:
    """ECMAScript `JSON.stringify()` number string for finite doubles."""
    if not math.isfinite(x):
        raise CanonicalJsonError("Non-finite numbers are not valid JSON")

    if x == 0.0:
        # Normalize -0 to 0.
        return "0"

    sign = "-" if math.copysign(1.0, x) < 0 else ""
    x_abs = abs(x)

    use_exp = x_abs >= 1e21 or x_abs < 1e-6

    digits, sci_exp = _scientific_parts_from_repr(repr(x_abs))

    if not use_exp:
        rendered = _render_decimal(digits, sci_exp)
        return sign + rendered

    if len(digits) == 1:
        mantissa = digits
    else:
        mantissa = digits[0] + "." + digits[1:]

    exp_sign = "+" if sci_exp >= 0 else ""
    return f"{sign}{mantissa}e{exp_sign}{sci_exp}"


def _scientific_parts_from_repr(s: str) -> tuple[str, int]:
    """Parse Python's float `repr()` into (digits, scientific_exponent).

    Output:
    - digits: base-10 digits, no leading/trailing zeros (except "0")
    - scientific_exponent: exponent for `d.ddd * 10^e`
    """
    s = s.strip().lower()
    if "e" in s:
        mantissa, exp_str = s.split("e", 1)
        exp = int(exp_str)
        if "." in mantissa:
            a, b = mantissa.split(".", 1)
            digits = a + b
        else:
            digits = mantissa
        digits = digits.lstrip("0") or "0"
        digits = digits.rstrip("0") or "0"
        # Python repr uses normalized mantissa (one digit before '.').
        return digits, exp

    # Decimal form.
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""

    frac_part = frac_part.rstrip("0")
    int_stripped = int_part.lstrip("0")

    if int_stripped:
        digits = int_stripped + frac_part
        sci_exp = len(int_stripped) - 1
    else:
        # number < 1
        leading_zeros = 0
        while leading_zeros < len(frac_part) and frac_part[leading_zeros] == "0":
            leading_zeros += 1
        digits = frac_part[leading_zeros:]
        sci_exp = -(leading_zeros + 1)

    digits = digits.lstrip("0") or "0"
    digits = digits.rstrip("0") or "0"
    return digits, sci_exp


def _render_decimal(digits: str, sci_exp: int) -> str:
    digits_len = len(digits)
    shift = sci_exp - (digits_len - 1)

    if shift >= 0:
        return digits + ("0" * shift)

    pos = digits_len + shift
    if pos > 0:
        out = digits[:pos] + "." + digits[pos:]
    else:
        out = "0." + ("0" * (-pos)) + digits

    if "." in out:
        out = out.rstrip("0").rstrip(".")
    return out


__all__ = ["CanonicalJsonError", "canonicalize"]

