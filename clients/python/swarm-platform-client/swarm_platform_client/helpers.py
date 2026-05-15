"""Hand-maintained convenience layer over the generated client.

The OpenAPI generator only emits boilerplate for the bearer auth scheme,
so the generated `AuthenticatedClient` does not know about the platform
`x-api-key` header that every `/v2/api/*` route requires alongside the
bearer token. The generator also emits a synchronous wrapper for the
SSE `/v2/api/stream/findings` route that buffers the full response — it
never yields findings against a live server. This module wraps both
gaps with thin helpers.
"""

from collections.abc import Iterator
from typing import Any

import httpx

from .client import AuthenticatedClient


def make_platform_client(
    base_url: str,
    *,
    bearer_token: str,
    platform_api_key: str,
    timeout: httpx.Timeout | None = None,
    verify_ssl: bool = True,
) -> AuthenticatedClient:
    """Construct an `AuthenticatedClient` with both the bearer token AND the
    `x-api-key` header set, matching the server's combined-auth requirement.
    """
    headers: dict[str, str] = {"x-api-key": platform_api_key}
    return AuthenticatedClient(
        base_url=base_url,
        token=bearer_token,
        headers=headers,
        timeout=timeout if timeout is not None else httpx.Timeout(5.0),
        verify_ssl=verify_ssl,
    )


def iter_findings_sse(
    client: AuthenticatedClient,
    *,
    threat_class: str | None = None,
    severity: str | None = None,
    timeout: httpx.Timeout | None = None,
) -> Iterator[dict[str, Any]]:
    """Stream Server-Sent Events from `/v2/api/stream/findings`.

    Yields one parsed event payload per SSE `data:` line. The generated
    `stream_findings` helper does a buffered request and never returns
    against the open-ended live stream; this iterates over the response
    body line-by-line and parses JSON `data:` payloads as they arrive.
    """
    import json

    params: dict[str, str] = {}
    if threat_class is not None:
        params["threat_class"] = threat_class
    if severity is not None:
        params["severity"] = severity

    httpx_client = client.get_httpx_client()
    request = httpx_client.build_request(
        "GET",
        "/v2/api/stream/findings",
        params=params,
        headers={"accept": "text/event-stream"},
        timeout=timeout if timeout is not None else httpx.Timeout(None, connect=5.0),
    )
    with httpx_client.send(request, stream=True) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            payload = line[len("data:") :].strip()
            if not payload:
                continue
            try:
                yield json.loads(payload)
            except json.JSONDecodeError:
                continue
