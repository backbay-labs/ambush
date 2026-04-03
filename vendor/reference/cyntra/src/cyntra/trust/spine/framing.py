"""Transport framing helpers shared across Spine planes.

Currently supported frames:
- `Z1` prefix: zlib-compressed UTF-8 JSON bytes

Receivers must bound decompression output sizes to avoid zip-bomb style DoS.
"""

from __future__ import annotations

import zlib

_ZLIB_MAGIC = b"Z1"


def _bounded_zlib_decompress(data: bytes, *, max_output_bytes: int) -> bytes | None:
    """Decompress zlib data, returning None if output exceeds `max_output_bytes`."""
    try:
        limit = int(max_output_bytes)
        if limit < 0:
            return None

        d = zlib.decompressobj()
        remaining = limit + 1  # allow a 1-byte overflow sentinel
        parts: list[bytes] = []

        chunk = d.decompress(data, remaining)
        parts.append(chunk)
        total = len(chunk)
        remaining -= len(chunk)
        if remaining <= 0:
            return None

        # If output is larger than max_length, zlib may leave unconsumed tail.
        while d.unconsumed_tail:
            chunk = d.decompress(d.unconsumed_tail, remaining)
            parts.append(chunk)
            total += len(chunk)
            remaining -= len(chunk)
            if remaining <= 0:
                return None

        chunk = d.flush(remaining)
        parts.append(chunk)
        total += len(chunk)
        if total > limit:
            return None
        return b"".join(parts)
    except Exception:
        return None


def decode_maybe_zlib_framed(payload: bytes, *, max_decompressed_bytes: int) -> bytes | None:
    """Decode an optional `Z1` zlib frame; returns None on decode failure."""
    if payload.startswith(_ZLIB_MAGIC):
        return _bounded_zlib_decompress(payload[2:], max_output_bytes=max_decompressed_bytes)
    return payload
