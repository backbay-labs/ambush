from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.error_response import ErrorResponse
from ...models.platform_asset_posture_page import PlatformAssetPosturePage
from ...types import UNSET, Response, Unset


def _get_kwargs(
    host_id: str,
    *,
    x_swarm_schema_version: int | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_swarm_schema_version, Unset):
        headers["x-swarm-schema-version"] = str(x_swarm_schema_version)

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/v2/api/assets/{host_id}/posture".format(
            host_id=quote(str(host_id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ErrorResponse | PlatformAssetPosturePage | None:
    if response.status_code == 200:
        response_200 = PlatformAssetPosturePage.from_dict(response.json())

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
) -> Response[ErrorResponse | PlatformAssetPosturePage]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    host_id: str,
    *,
    client: AuthenticatedClient | Client,
    x_swarm_schema_version: int | Unset = UNSET,
) -> Response[ErrorResponse | PlatformAssetPosturePage]:
    """Read asset posture

     Returns threat concentration, active investigations, and recent findings for one host.

    Args:
        host_id (str):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | PlatformAssetPosturePage]
    """

    kwargs = _get_kwargs(
        host_id=host_id,
        x_swarm_schema_version=x_swarm_schema_version,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    host_id: str,
    *,
    client: AuthenticatedClient | Client,
    x_swarm_schema_version: int | Unset = UNSET,
) -> ErrorResponse | PlatformAssetPosturePage | None:
    """Read asset posture

     Returns threat concentration, active investigations, and recent findings for one host.

    Args:
        host_id (str):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | PlatformAssetPosturePage
    """

    return sync_detailed(
        host_id=host_id,
        client=client,
        x_swarm_schema_version=x_swarm_schema_version,
    ).parsed


async def asyncio_detailed(
    host_id: str,
    *,
    client: AuthenticatedClient | Client,
    x_swarm_schema_version: int | Unset = UNSET,
) -> Response[ErrorResponse | PlatformAssetPosturePage]:
    """Read asset posture

     Returns threat concentration, active investigations, and recent findings for one host.

    Args:
        host_id (str):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ErrorResponse | PlatformAssetPosturePage]
    """

    kwargs = _get_kwargs(
        host_id=host_id,
        x_swarm_schema_version=x_swarm_schema_version,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    host_id: str,
    *,
    client: AuthenticatedClient | Client,
    x_swarm_schema_version: int | Unset = UNSET,
) -> ErrorResponse | PlatformAssetPosturePage | None:
    """Read asset posture

     Returns threat concentration, active investigations, and recent findings for one host.

    Args:
        host_id (str):
        x_swarm_schema_version (int | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ErrorResponse | PlatformAssetPosturePage
    """

    return (
        await asyncio_detailed(
            host_id=host_id,
            client=client,
            x_swarm_schema_version=x_swarm_schema_version,
        )
    ).parsed
