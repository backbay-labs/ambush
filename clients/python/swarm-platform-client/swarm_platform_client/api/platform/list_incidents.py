from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_response import ErrorResponse
from ...models.platform_incidents_page import PlatformIncidentsPage
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    cursor: str | Unset = UNSET,
    page_size: int | Unset = UNSET,
    incident_id: str | Unset = UNSET,
    hunt_id: str | Unset = UNSET,
    receipt_id: str | Unset = UNSET,
    correlation_key: str | Unset = UNSET,
    context_token: str | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_swarm_schema_version, Unset):
        headers["x-swarm-schema-version"] = str(x_swarm_schema_version)

    params: dict[str, Any] = {}

    params["cursor"] = cursor

    params["page_size"] = page_size

    params["incident_id"] = incident_id

    params["hunt_id"] = hunt_id

    params["receipt_id"] = receipt_id

    params["correlation_key"] = correlation_key

    params["context_token"] = context_token

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v2/api/incidents",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorResponse | PlatformIncidentsPage | None:
    if response.status_code == 200:
        response_200 = PlatformIncidentsPage.from_dict(response.json())

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


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ErrorResponse | PlatformIncidentsPage]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
    cursor: str | Unset = UNSET,
    page_size: int | Unset = UNSET,
    incident_id: str | Unset = UNSET,
    hunt_id: str | Unset = UNSET,
    receipt_id: str | Unset = UNSET,
    correlation_key: str | Unset = UNSET,
    context_token: str | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> Response[ErrorResponse | PlatformIncidentsPage]:
    """List incidents

     Returns cursor-paginated correlated incident summaries from the incident store.

    Args:
        cursor (str | Unset):
        page_size (int | Unset):
        incident_id (str | Unset):
        hunt_id (str | Unset):
        receipt_id (str | Unset):
        correlation_key (str | Unset):
        context_token (str | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | PlatformIncidentsPage]
    """

    kwargs = _get_kwargs(
        cursor=cursor,
        page_size=page_size,
        incident_id=incident_id,
        hunt_id=hunt_id,
        receipt_id=receipt_id,
        correlation_key=correlation_key,
        context_token=context_token,
        x_swarm_schema_version=x_swarm_schema_version,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
    cursor: str | Unset = UNSET,
    page_size: int | Unset = UNSET,
    incident_id: str | Unset = UNSET,
    hunt_id: str | Unset = UNSET,
    receipt_id: str | Unset = UNSET,
    correlation_key: str | Unset = UNSET,
    context_token: str | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> ErrorResponse | PlatformIncidentsPage | None:
    """List incidents

     Returns cursor-paginated correlated incident summaries from the incident store.

    Args:
        cursor (str | Unset):
        page_size (int | Unset):
        incident_id (str | Unset):
        hunt_id (str | Unset):
        receipt_id (str | Unset):
        correlation_key (str | Unset):
        context_token (str | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | PlatformIncidentsPage
    """

    return sync_detailed(
        client=client,
        cursor=cursor,
        page_size=page_size,
        incident_id=incident_id,
        hunt_id=hunt_id,
        receipt_id=receipt_id,
        correlation_key=correlation_key,
        context_token=context_token,
        x_swarm_schema_version=x_swarm_schema_version,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
    cursor: str | Unset = UNSET,
    page_size: int | Unset = UNSET,
    incident_id: str | Unset = UNSET,
    hunt_id: str | Unset = UNSET,
    receipt_id: str | Unset = UNSET,
    correlation_key: str | Unset = UNSET,
    context_token: str | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> Response[ErrorResponse | PlatformIncidentsPage]:
    """List incidents

     Returns cursor-paginated correlated incident summaries from the incident store.

    Args:
        cursor (str | Unset):
        page_size (int | Unset):
        incident_id (str | Unset):
        hunt_id (str | Unset):
        receipt_id (str | Unset):
        correlation_key (str | Unset):
        context_token (str | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | PlatformIncidentsPage]
    """

    kwargs = _get_kwargs(
        cursor=cursor,
        page_size=page_size,
        incident_id=incident_id,
        hunt_id=hunt_id,
        receipt_id=receipt_id,
        correlation_key=correlation_key,
        context_token=context_token,
        x_swarm_schema_version=x_swarm_schema_version,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
    cursor: str | Unset = UNSET,
    page_size: int | Unset = UNSET,
    incident_id: str | Unset = UNSET,
    hunt_id: str | Unset = UNSET,
    receipt_id: str | Unset = UNSET,
    correlation_key: str | Unset = UNSET,
    context_token: str | Unset = UNSET,
    x_swarm_schema_version: int | Unset = UNSET,
) -> ErrorResponse | PlatformIncidentsPage | None:
    """List incidents

     Returns cursor-paginated correlated incident summaries from the incident store.

    Args:
        cursor (str | Unset):
        page_size (int | Unset):
        incident_id (str | Unset):
        hunt_id (str | Unset):
        receipt_id (str | Unset):
        correlation_key (str | Unset):
        context_token (str | Unset):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | PlatformIncidentsPage
    """

    return (
        await asyncio_detailed(
            client=client,
            cursor=cursor,
            page_size=page_size,
            incident_id=incident_id,
            hunt_id=hunt_id,
            receipt_id=receipt_id,
            correlation_key=correlation_key,
            context_token=context_token,
            x_swarm_schema_version=x_swarm_schema_version,
        )
    ).parsed
