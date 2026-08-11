from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_response import ErrorResponse
from ...models.stream_findings_severity import StreamFindingsSeverity
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    host_id: str | Unset = UNSET,
    strategy_id: str | Unset = UNSET,
    threat_class: str | Unset = UNSET,
    severity: StreamFindingsSeverity | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_swarm_schema_version, Unset):
        headers["x-swarm-schema-version"] = str(x_swarm_schema_version)

    params: dict[str, Any] = {}

    params["host_id"] = host_id

    params["strategy_id"] = strategy_id

    params["threat_class"] = threat_class

    json_severity: str | Unset = UNSET
    if not isinstance(severity, Unset):
        json_severity = severity.value

    params["severity"] = json_severity

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v2/api/stream/findings",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> ErrorResponse | str | None:
    if response.status_code == 200:
        response_200 = response.text
        return response_200

    if response.status_code == 400:
        response_400 = ErrorResponse.from_dict(response.json())

        return response_400

    if response.status_code == 401:
        response_401 = ErrorResponse.from_dict(response.json())

        return response_401

    if response.status_code == 403:
        response_403 = ErrorResponse.from_dict(response.json())

        return response_403

    if response.status_code == 429:
        response_429 = ErrorResponse.from_dict(response.json())

        return response_429

    if response.status_code == 503:
        response_503 = ErrorResponse.from_dict(response.json())

        return response_503

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[ErrorResponse | str]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    host_id: str | Unset = UNSET,
    strategy_id: str | Unset = UNSET,
    threat_class: str | Unset = UNSET,
    severity: StreamFindingsSeverity | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> Response[ErrorResponse | str]:
    """Stream live findings

     Streams live finding events as server-sent events. Generated clients should treat this as a raw
    text/event-stream response.

    Args:
        host_id (str | Unset):
        strategy_id (str | Unset):
        threat_class (str | Unset):
        severity (StreamFindingsSeverity | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | str]
    """

    kwargs = _get_kwargs(
        host_id=host_id,
        strategy_id=strategy_id,
        threat_class=threat_class,
        severity=severity,
        x_swarm_schema_version=x_swarm_schema_version,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    host_id: str | Unset = UNSET,
    strategy_id: str | Unset = UNSET,
    threat_class: str | Unset = UNSET,
    severity: StreamFindingsSeverity | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> ErrorResponse | str | None:
    """Stream live findings

     Streams live finding events as server-sent events. Generated clients should treat this as a raw
    text/event-stream response.

    Args:
        host_id (str | Unset):
        strategy_id (str | Unset):
        threat_class (str | Unset):
        severity (StreamFindingsSeverity | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | str
    """

    return sync_detailed(
        client=client,
        host_id=host_id,
        strategy_id=strategy_id,
        threat_class=threat_class,
        severity=severity,
        x_swarm_schema_version=x_swarm_schema_version,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    host_id: str | Unset = UNSET,
    strategy_id: str | Unset = UNSET,
    threat_class: str | Unset = UNSET,
    severity: StreamFindingsSeverity | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> Response[ErrorResponse | str]:
    """Stream live findings

     Streams live finding events as server-sent events. Generated clients should treat this as a raw
    text/event-stream response.

    Args:
        host_id (str | Unset):
        strategy_id (str | Unset):
        threat_class (str | Unset):
        severity (StreamFindingsSeverity | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | str]
    """

    kwargs = _get_kwargs(
        host_id=host_id,
        strategy_id=strategy_id,
        threat_class=threat_class,
        severity=severity,
        x_swarm_schema_version=x_swarm_schema_version,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    host_id: str | Unset = UNSET,
    strategy_id: str | Unset = UNSET,
    threat_class: str | Unset = UNSET,
    severity: StreamFindingsSeverity | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> ErrorResponse | str | None:
    """Stream live findings

     Streams live finding events as server-sent events. Generated clients should treat this as a raw
    text/event-stream response.

    Args:
        host_id (str | Unset):
        strategy_id (str | Unset):
        threat_class (str | Unset):
        severity (StreamFindingsSeverity | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | str
    """

    return (
        await asyncio_detailed(
            client=client,
            host_id=host_id,
            strategy_id=strategy_id,
            threat_class=threat_class,
            severity=severity,
            x_swarm_schema_version=x_swarm_schema_version,
        )
    ).parsed
